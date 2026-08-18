package clientauth

import (
	"context"
	"crypto/sha256"
	"crypto/x509"
	"errors"
	"log/slog"
	"path/filepath"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	"github.com/RafPe/goweb-https/internal/certreload"
)

// Bundle tracks a client CA trust bundle on disk and republishes it as it
// rotates.
//
// In Kubernetes the configured file is typically a projected volume - a
// ConfigMap, a Secret, or a ClusterTrustBundle - which is updated in place, so
// a restart is not an acceptable way to pick up a rotated bundle.
//
// Two invariants govern everything Bundle does, because the failure mode of
// getting them wrong is silent and opens the door rather than closing it:
//
//  1. A reload never publishes a nil or empty pool. crypto/x509 substitutes the
//     system root pool when VerifyOptions.Roots is nil, so a nil ClientCAs
//     under tls.VerifyClientCertIfGiven would turn every publicly issued client
//     certificate into a verified identity. Any failed reload therefore retains
//     the last known good pool - see [Bundle.Reconcile].
//  2. A bundle that parses is published even when it holds fewer CAs than
//     before. Removing a CA is revocation and must take effect; a rule that
//     only ever grew the pool would make revocation impossible.
//
// The read path is lock free: [Bundle.Pool] loads an immutable snapshot through
// an atomic pointer. All discovery happens on the goroutine running
// [Bundle.Watch].
type Bundle struct {
	path string

	logger            *slog.Logger
	now               func() time.Time
	debounce          time.Duration
	reconcileInterval time.Duration
	retryDelay        time.Duration

	// current holds the published snapshot. Readers load it without locking;
	// writers replace it wholesale under reloadMu.
	current atomic.Pointer[bundleSnapshot]

	// reloadMu serializes reconciliation so that a burst of filesystem events
	// cannot produce concurrent reads of half-written material.
	reloadMu sync.Mutex

	healthMu sync.RWMutex
	health   bundleHealth

	callbackMu sync.RWMutex
	callbacks  []func(*x509.CertPool)
}

// bundleSnapshot is an immutable view of a published trust bundle. A snapshot
// is fully built before it is stored, and is never mutated afterwards.
type bundleSnapshot struct {
	store    *TrustStore
	loadedAt time.Time

	// digest identifies the set of trusted anchors; see anchorDigest.
	digest [sha256.Size]byte
}

// bundleHealth records how well the bundle is tracking its source. Staleness is
// reported rather than enforced: unlike the served certificate, a stale trust
// bundle does not stop the process serving correctly, so it must not fail
// readiness and pull a working pod out of service.
type bundleHealth struct {
	lastSuccess time.Time
	lastError   string
}

// BundleStatus describes the bundle for the diagnostic endpoint.
//
// Anchors carry fingerprints and not just subjects because a rotation commonly
// replaces a CA with one holding the same subject DN: a suite asserting that a
// rotation landed cannot tell the new CA from the old one by subject alone.
type BundleStatus struct {
	// FilePath is the configured bundle location.
	FilePath string

	// Anchors describes the CAs currently trusted.
	Anchors []Anchor

	// LoadedAt is when the published pool was read. It is what distinguishes
	// "rotated a moment ago" from "loaded at boot and never refreshed".
	LoadedAt time.Time

	// LastSuccess is when the source was last read successfully, whether or not
	// its content had changed. It stops advancing while reloads are failing,
	// which is what makes staleness measurable.
	LastSuccess time.Time

	// LastError describes the most recent reload failure, and is empty once a
	// reload succeeds again.
	LastError string
}

// BundleOption configures a Bundle.
type BundleOption func(*Bundle)

// WithLogger sets the logger. Defaults to slog.Default.
func WithLogger(logger *slog.Logger) BundleOption {
	return func(b *Bundle) {
		if logger != nil {
			b.logger = logger
		}
	}
}

// WithClock replaces the time source. Intended for tests.
func WithClock(now func() time.Time) BundleOption {
	return func(b *Bundle) {
		if now != nil {
			b.now = now
		}
	}
}

// WithDebounce sets the quiet period observed after a filesystem event before
// the bundle is re-read.
func WithDebounce(d time.Duration) BundleOption {
	return func(b *Bundle) {
		if d > 0 {
			b.debounce = d
		}
	}
}

// WithReconcileInterval sets how often the bundle is reconciled against disk
// irrespective of filesystem events.
func WithReconcileInterval(d time.Duration) BundleOption {
	return func(b *Bundle) {
		if d > 0 {
			b.reconcileInterval = d
		}
	}
}

// WithRetryDelay sets the base delay between retries of a failed reload.
func WithRetryDelay(d time.Duration) BundleOption {
	return func(b *Bundle) {
		if d > 0 {
			b.retryDelay = d
		}
	}
}

// Defaults applied when the corresponding option is not supplied. They match
// certreload's, because the two sources are reloaded by the same loop on the
// same operator-configured knobs.
const (
	defaultBundleDebounce          = 500 * time.Millisecond
	defaultBundleReconcileInterval = 30 * time.Second
	defaultBundleRetryDelay        = time.Second
)

// NewBundle loads path once, through [LoadTrustStore], and returns a Bundle
// ready to watch it.
//
// Every failure LoadTrustStore reports is a startup failure: a trust store that
// trusts nothing, or one holding an anchor that is not a usable CA, is an
// operator mistake - and a nil pool is not a safe fallback but the widest
// possible one. Returning an error rather than a partially initialised Bundle
// means there is no window in which [Bundle.Pool] returns nil.
func NewBundle(path string, opts ...BundleOption) (*Bundle, error) {
	if path == "" {
		return nil, errors.New("clientauth: client CA file path must not be empty")
	}

	b := &Bundle{
		path:              path,
		logger:            slog.Default(),
		now:               time.Now,
		debounce:          defaultBundleDebounce,
		reconcileInterval: defaultBundleReconcileInterval,
		retryDelay:        defaultBundleRetryDelay,
	}
	for _, opt := range opts {
		opt(b)
	}

	store, err := LoadTrustStore(path)
	if err != nil {
		return nil, err
	}

	b.publish(store)
	b.recordSuccess()

	return b, nil
}

// Pool returns the currently published trust pool, for use as
// tls.Config.ClientCAs. It is never nil.
func (b *Bundle) Pool() *x509.CertPool {
	return b.current.Load().store.Pool()
}

// Anchors describes the currently trusted CAs.
func (b *Bundle) Anchors() []Anchor {
	return b.current.Load().store.Anchors()
}

// Status describes the bundle for the diagnostic endpoint.
func (b *Bundle) Status() BundleStatus {
	snap := b.current.Load()

	b.healthMu.RLock()
	defer b.healthMu.RUnlock()

	return BundleStatus{
		FilePath:    b.path,
		Anchors:     snap.store.Anchors(),
		LoadedAt:    snap.loadedAt,
		LastSuccess: b.health.lastSuccess,
		LastError:   b.health.lastError,
	}
}

// OnChange registers a callback invoked after a successful change, with the
// newly published pool. The server uses it to rebuild its derived tls.Config.
//
// Callbacks run synchronously on the goroutine that reconciled, before
// [Bundle.Reconcile] returns, so a callback must neither block nor re-enter the
// Bundle. Registering after construction is deliberate: the pool a callback
// would have been handed at startup is the one [Bundle.Pool] already returns.
func (b *Bundle) OnChange(fn func(*x509.CertPool)) {
	if fn == nil {
		return
	}
	b.callbackMu.Lock()
	defer b.callbackMu.Unlock()
	b.callbacks = append(b.callbacks, fn)
}

// Reconcile re-reads the bundle and publishes it when the set of trusted
// anchors differs from what is currently published. It reports whether the
// published pool changed.
//
// On any error the previously published pool is retained and the error is
// returned. That is invariant 1, and it is enforced by structure rather than by
// a check: nothing is stored until [LoadTrustStore] has returned a validated,
// non-empty store, so there is no path on which a failure can publish anything
// at all.
//
// A bundle that parses is published even when it holds fewer anchors than
// before. That is invariant 2: removing a CA is how revocation is expressed
// here, and delaying it - by requiring the smaller bundle to be seen twice, say
// - would delay every genuine revocation by up to one reconcile interval. It
// relies on the bundle being replaced atomically, as projected volumes,
// ConfigMaps, Secrets and ClusterTrustBundles all are; a writer that rewrites
// the file in place can be read mid-write, and a partial bundle that still
// parses is indistinguishable from a deliberate revocation.
func (b *Bundle) Reconcile() (bool, error) {
	b.reloadMu.Lock()
	defer b.reloadMu.Unlock()

	store, err := LoadTrustStore(b.path)
	if err != nil {
		b.recordFailure(err)
		return false, err
	}

	digest := anchorDigest(store.anchors)
	if current := b.current.Load(); current != nil && current.digest == digest {
		// The same anchors: record the successful read so that staleness
		// tracking stays accurate, but do not republish.
		b.recordSuccess()
		return false, nil
	}

	b.publish(store)
	b.recordSuccess()

	b.logger.Info("client CA trust bundle reloaded",
		"client_ca_file", b.path,
		"anchors", AnchorLogFields(store.anchors),
	)

	b.notify(store.Pool())

	return true, nil
}

// Watch observes the bundle's directory and republishes as it rotates. It
// blocks until ctx is cancelled, returning nil, or until the filesystem watcher
// fails terminally.
//
// It shares [certreload.RunWatch] with the served certificate rather than
// carrying its own loop: the debounce, the bounded retries and the periodic
// reconcile that makes convergence guaranteed rather than best effort are all
// behaviour that two copies would drift on.
func (b *Bundle) Watch(ctx context.Context) error {
	return certreload.RunWatch(ctx, certreload.WatchSource{
		Directories:        []string{filepath.Dir(b.path)},
		Reconcile:          b.Reconcile,
		RecordWatcherError: b.recordWatcherError,
		Label:              "client CA trust bundle",
		RetainedNote:       "continuing to trust the last valid bundle",
		LogKey:             "client_ca_file",
		LogValue:           b.path,
	}, certreload.WatchTiming{
		Debounce:          b.debounce,
		ReconcileInterval: b.reconcileInterval,
		RetryDelay:        b.retryDelay,
	}, b.logger, b.now)
}

func (b *Bundle) publish(store *TrustStore) {
	b.current.Store(&bundleSnapshot{
		store:    store,
		loadedAt: b.now(),
		digest:   anchorDigest(store.anchors),
	})
}

// notify runs the registered callbacks with the newly published pool.
func (b *Bundle) notify(pool *x509.CertPool) {
	b.callbackMu.RLock()
	defer b.callbackMu.RUnlock()
	for _, fn := range b.callbacks {
		fn(pool)
	}
}

func (b *Bundle) recordSuccess() {
	b.healthMu.Lock()
	defer b.healthMu.Unlock()
	b.health.lastSuccess = b.now()
	b.health.lastError = ""
}

func (b *Bundle) recordFailure(err error) {
	b.healthMu.Lock()
	defer b.healthMu.Unlock()
	b.health.lastError = err.Error()
}

// recordWatcherError reports a terminal watcher failure.
//
// It logs rather than recording state because the bundle's watcher shares the
// process lifecycle: cmd runs it alongside the server, so a terminated watcher
// brings the process down and there is no window in which a stored flag could
// be scraped. It is called with nil once the watches are registered, which is
// not a condition worth reporting.
func (b *Bundle) recordWatcherError(err error) {
	if err == nil {
		return
	}
	b.logger.Error("client CA trust bundle watcher stopped",
		"err", err,
		"client_ca_file", b.path,
	)
}

// anchorDigest identifies a set of trust anchors by content.
//
// The fingerprints are sorted before hashing, so a bundle rewritten with the
// same CAs in a different order is recognised as unchanged: trust is a set, and
// republishing on a reordering would churn every derived tls.Config for a
// difference no client can observe. Identity comes from the certificates
// themselves and never from file metadata such as modification time, so a
// rotation that preserves the timestamp is still seen.
func anchorDigest(anchors []Anchor) [sha256.Size]byte {
	fingerprints := make([]string, 0, len(anchors))
	for _, anchor := range anchors {
		fingerprints = append(fingerprints, anchor.FingerprintSHA256)
	}
	slices.Sort(fingerprints)

	digest := sha256.New()
	for _, fingerprint := range fingerprints {
		// The separator keeps the concatenation unambiguous, so two different
		// sets cannot hash the same input.
		digest.Write([]byte(fingerprint))
		digest.Write([]byte{'\n'})
	}

	return [sha256.Size]byte(digest.Sum(nil))
}

// AnchorLogField is the shape one trust anchor takes in a log line: enough to
// tell an operator which CA is live, and no more.
//
// Subject alone is not enough, since a replacement CA commonly reuses the
// subject DN of the CA it replaces; the fingerprint is what lets a reader
// confirm which certificate is actually trusted.
type AnchorLogField struct {
	Subject     string `json:"subject"`
	Fingerprint string `json:"fingerprint_sha256"`
}

// AnchorLogFields projects trust anchors down to what a log line needs, so
// logging them costs nothing beyond the fields a reader actually uses to tell
// one CA from another. It is shared by the startup log and the reload log so
// the two cannot drift.
func AnchorLogFields(anchors []Anchor) []AnchorLogField {
	fields := make([]AnchorLogField, len(anchors))
	for i, anchor := range anchors {
		fields[i] = AnchorLogField{Subject: anchor.Subject, Fingerprint: anchor.FingerprintSHA256}
	}
	return fields
}
