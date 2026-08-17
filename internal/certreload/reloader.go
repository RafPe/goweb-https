package certreload

import (
	"crypto/tls"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"
)

// Reloader serves a TLS certificate and keeps it current as the backing files
// are rotated.
//
// A Reloader returned by [New] is immediately usable: the initial key pair has
// been loaded and validated, so [Reloader.GetCertificate] never observes an
// unpopulated state. The zero value is not usable.
type Reloader struct {
	certFile string
	keyFile  string

	logger             *slog.Logger
	now                func() time.Time
	debounce           time.Duration
	reconcileInterval  time.Duration
	retryDelay         time.Duration
	maximumStalePeriod time.Duration
	allowExpired       bool

	// current holds the published snapshot. Readers load it without locking;
	// writers replace it wholesale under reloadMu.
	current atomic.Pointer[snapshot]

	// reloadMu serializes reconciliation so that a burst of filesystem events
	// cannot produce concurrent reads of half-written material.
	reloadMu sync.Mutex

	healthMu sync.RWMutex
	health   Health
}

// Health describes the reloader's ability to track the certificate source.
type Health struct {
	// LastSuccess is when the certificate was last successfully read, whether
	// or not its content had changed.
	LastSuccess time.Time

	// LastFailure and LastError describe the most recent read failure.
	LastFailure time.Time
	LastError   string

	// ConsecutiveFailures counts read failures since the last success.
	ConsecutiveFailures int

	// WatcherError is set when the filesystem watcher terminated. Rotation can
	// no longer be observed promptly; only periodic reconciliation remains.
	WatcherError string
}

// Option configures a Reloader.
type Option func(*Reloader)

// WithLogger sets the logger. Defaults to slog.Default.
func WithLogger(logger *slog.Logger) Option {
	return func(r *Reloader) {
		if logger != nil {
			r.logger = logger
		}
	}
}

// WithClock replaces the time source. Intended for tests.
func WithClock(now func() time.Time) Option {
	return func(r *Reloader) {
		if now != nil {
			r.now = now
		}
	}
}

// WithDebounce sets the quiet period observed after a filesystem event before
// the certificate is re-read.
func WithDebounce(d time.Duration) Option {
	return func(r *Reloader) {
		if d > 0 {
			r.debounce = d
		}
	}
}

// WithReconcileInterval sets how often the certificate is reconciled against
// disk irrespective of filesystem events.
func WithReconcileInterval(d time.Duration) Option {
	return func(r *Reloader) {
		if d > 0 {
			r.reconcileInterval = d
		}
	}
}

// WithRetryDelay sets the base delay between retries of a failed reload.
func WithRetryDelay(d time.Duration) Option {
	return func(r *Reloader) {
		if d > 0 {
			r.retryDelay = d
		}
	}
}

// WithMaximumStalePeriod sets how long the reloader may fail to read the
// certificate source before [Reloader.Ready] reports an error.
func WithMaximumStalePeriod(d time.Duration) Option {
	return func(r *Reloader) {
		if d > 0 {
			r.maximumStalePeriod = d
		}
	}
}

// AllowExpired permits construction with an already-expired certificate.
//
// The certificate is then loaded, served, and reported as expired rather than
// causing startup to fail. Validity is a property the reloader reports; whether
// it is fatal is the caller's policy.
func AllowExpired(allow bool) Option {
	return func(r *Reloader) { r.allowExpired = allow }
}

// Defaults applied when the corresponding option is not supplied.
const (
	defaultDebounce           = 500 * time.Millisecond
	defaultReconcileInterval  = 30 * time.Second
	defaultRetryDelay         = time.Second
	defaultMaximumStalePeriod = 15 * time.Minute
	maximumDebounceWait       = 5 * time.Second
	maximumReloadRetries      = 3
)

// New loads and validates the key pair at the supplied paths and returns a
// ready-to-use Reloader.
//
// It returns an error rather than a partially initialised object: there is no
// second initialisation step and therefore no window in which the returned
// value would serve no certificate.
func New(certFile, keyFile string, opts ...Option) (*Reloader, error) {
	if certFile == "" {
		return nil, errors.New("certificate file path must not be empty")
	}
	if keyFile == "" {
		return nil, errors.New("key file path must not be empty")
	}

	r := &Reloader{
		certFile:           certFile,
		keyFile:            keyFile,
		logger:             slog.Default(),
		now:                time.Now,
		debounce:           defaultDebounce,
		reconcileInterval:  defaultReconcileInterval,
		retryDelay:         defaultRetryDelay,
		maximumStalePeriod: defaultMaximumStalePeriod,
	}
	for _, opt := range opts {
		opt(r)
	}

	snap, err := loadKeyPair(certFile, keyFile, r.now())
	if err != nil {
		return nil, err
	}

	// Startup policy: refuse to start on material that is already outside its
	// validity period unless the operator opted in. Once running, the same
	// condition is reported rather than fatal - see Reconcile.
	if state, since := snap.info.State(r.now()); state != ValidityValid && !r.allowExpired {
		switch state {
		case ValidityExpired:
			return nil, fmt.Errorf("%s expired %s ago: %w",
				certFile, since.Truncate(time.Second), ErrCertificateExpired)
		case ValidityNotYetValid:
			return nil, fmt.Errorf("%s becomes valid in %s: %w",
				certFile, since.Truncate(time.Second), ErrCertificateNotYetValid)
		}
	}

	r.publish(snap)
	r.recordSuccess()

	if warning := serverAuthWarning(certFile, snap.certificate.Leaf); warning != "" {
		r.logger.Warn(warning)
	}

	return r, nil
}

// GetCertificate implements the tls.Config.GetCertificate callback.
//
// It performs an atomic load and nothing else: no filesystem access, parsing,
// locking, logging, or retrying happens on the handshake path.
func (r *Reloader) GetCertificate(_ *tls.ClientHelloInfo) (*tls.Certificate, error) {
	snap := r.current.Load()
	if snap == nil {
		return nil, ErrCertificateUnavailable
	}
	return snap.certificate, nil
}

// CertificateInfo returns a description of the currently served certificate.
// The boolean reports whether a certificate has been published.
func (r *Reloader) CertificateInfo() (Info, bool) {
	snap := r.current.Load()
	if snap == nil {
		return Info{}, false
	}
	// Clone so that a caller cannot mutate slices reachable from the published
	// snapshot, which every concurrent reader shares.
	return snap.info.clone(), true
}

// Health returns a copy of the current reload health.
func (r *Reloader) Health() Health {
	r.healthMu.RLock()
	defer r.healthMu.RUnlock()
	return r.health
}

// Ready reports whether the reloader is able to serve traffic.
//
// It fails when no certificate has been published, when the served certificate
// is outside its validity period, or when the source has been unreadable for
// longer than the configured maximum stale period. A transient failure is
// deliberately not enough: last-good material keeps being served and readiness
// only degrades once the failure persists.
func (r *Reloader) Ready() error {
	info, ok := r.CertificateInfo()
	if !ok {
		return ErrCertificateUnavailable
	}

	now := r.now()
	if state, since := info.State(now); state != ValidityValid {
		switch state {
		case ValidityExpired:
			return fmt.Errorf("%s expired %s ago: %w",
				info.FilePath, since.Truncate(time.Second), ErrCertificateExpired)
		case ValidityNotYetValid:
			return fmt.Errorf("%s becomes valid in %s: %w",
				info.FilePath, since.Truncate(time.Second), ErrCertificateNotYetValid)
		}
	}

	health := r.Health()
	if health.WatcherError != "" {
		return fmt.Errorf("certificate watcher stopped: %s", health.WatcherError)
	}
	if health.ConsecutiveFailures > 0 && !health.LastSuccess.IsZero() {
		if stale := now.Sub(health.LastSuccess); stale > r.maximumStalePeriod {
			return fmt.Errorf("certificate source unreadable for %s (last error: %s)",
				stale.Truncate(time.Second), health.LastError)
		}
	}

	return nil
}

// Reconcile reads the certificate source and publishes it when its content
// differs from what is currently served. It reports whether a new snapshot was
// published.
//
// Change detection compares a SHA-256 fingerprint of the leaf certificate, not
// file metadata. A rotation that preserves or lowers the modification time, or
// one that lands within a single filesystem timestamp tick, is still observed;
// a duplicate filesystem event for unchanged content is still suppressed.
func (r *Reloader) Reconcile() (bool, error) {
	r.reloadMu.Lock()
	defer r.reloadMu.Unlock()

	snap, err := loadKeyPair(r.certFile, r.keyFile, r.now())
	if err != nil {
		r.recordFailure(err)
		return false, err
	}

	if current := r.current.Load(); current != nil && current.fingerprint == snap.fingerprint {
		// Same certificate: record the successful read so that staleness
		// tracking stays accurate, but do not republish.
		r.recordSuccess()
		return false, nil
	}

	// Report validity, do not enforce it. Refusing to publish a newly rotated
	// certificate because it is expired would strand the process on material
	// that is also expired, and would hide the condition from the status
	// endpoint whose purpose is to surface exactly this.
	if state, since := snap.info.State(r.now()); state != ValidityValid {
		r.logger.Warn("published certificate is outside its validity period",
			"certificate_file", r.certFile,
			"state", state.String(),
			"duration", since.Truncate(time.Second),
		)
	}

	r.publish(snap)
	r.recordSuccess()

	r.logger.Info("certificate reloaded",
		"certificate_file", r.certFile,
		"subject", snap.info.Subject,
		"fingerprint", snap.info.Fingerprint,
		"not_after", snap.info.NotAfter,
	)

	return true, nil
}

func (r *Reloader) publish(snap *snapshot) {
	r.current.Store(snap)
}

func (r *Reloader) recordSuccess() {
	r.healthMu.Lock()
	defer r.healthMu.Unlock()
	r.health.LastSuccess = r.now()
	r.health.ConsecutiveFailures = 0
	r.health.LastError = ""
}

func (r *Reloader) recordFailure(err error) {
	r.healthMu.Lock()
	defer r.healthMu.Unlock()
	r.health.LastFailure = r.now()
	r.health.LastError = err.Error()
	r.health.ConsecutiveFailures++
}

func (r *Reloader) recordWatcherError(err error) {
	r.healthMu.Lock()
	defer r.healthMu.Unlock()
	if err == nil {
		r.health.WatcherError = ""
		return
	}
	r.health.WatcherError = err.Error()
}
