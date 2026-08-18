package certreload

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"slices"
	"time"

	"github.com/fsnotify/fsnotify"
)

// WatchSource is what the shared watch loop needs to know about the thing it is
// watching.
//
// It exists so that a second rotating source - the client CA trust bundle in
// internal/clientauth - can reuse [RunWatch] rather than grow a second copy of
// its debounce, retry and reconcile behaviour. Those three took work to get
// right, and two copies of them drift.
//
// It is exported for that reuse and for no other reason: nothing outside this
// module is expected to construct one.
type WatchSource struct {
	// Directories to watch. Directories rather than files, for the reason
	// [RunWatch] documents.
	Directories []string

	// Reconcile re-reads the source. The boolean reports whether the published
	// value changed.
	Reconcile func() (bool, error)

	// RecordWatcherError records a terminal watcher failure for health
	// reporting. It is called with nil once the watches are registered, which
	// clears any error recorded by a previous run.
	RecordWatcherError func(error)

	// Label names the source in log messages, e.g. "certificate" or
	// "trust bundle".
	Label string

	// RetainedNote completes the failure log lines by naming what the source
	// keeps using when a reload fails, e.g. "continuing to serve the last valid
	// certificate". Each source phrases this itself because "serve" is right
	// for a served certificate and wrong for a trust store.
	RetainedNote string

	// LogKey and LogValue add the source's path to log lines, e.g.
	// "certificate_file" and the path.
	LogKey   string
	LogValue string
}

// WatchTiming carries the loop's timing knobs. Each source keeps its own
// configuration and passes the resolved values in.
type WatchTiming struct {
	// Debounce is the quiet period observed after a filesystem event before the
	// source is re-read.
	Debounce time.Duration

	// ReconcileInterval is how often the source is reconciled irrespective of
	// filesystem events.
	ReconcileInterval time.Duration

	// RetryDelay is the base delay between retries of a failed reload.
	RetryDelay time.Duration
}

// RunWatch observes src and reconciles it as it changes. It blocks until ctx is
// cancelled, returning nil, or until the filesystem watcher fails terminally,
// returning an error wrapping [ErrWatcherClosed].
//
// The watcher must not be left running unattended: a terminated watcher means
// rotation is no longer observed promptly, which the caller needs to act on.
//
// Directories are watched rather than files. Kubernetes rotates projected
// volumes and mounted secrets by writing a new timestamped directory and
// atomically swapping the `..data` symlink, so events never name the watched
// path itself and a watch registered on the file would observe nothing.
func RunWatch(ctx context.Context, src WatchSource, timing WatchTiming, logger *slog.Logger, now func() time.Time) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("create filesystem watcher: %w", err)
	}
	defer func() { _ = watcher.Close() }()

	for _, dir := range src.Directories {
		if err := watcher.Add(dir); err != nil {
			return fmt.Errorf("watch directory %s: %w", dir, err)
		}
	}
	src.RecordWatcherError(nil)

	// Reconcile once now that the watches are registered. A rotation that
	// landed between the initial load in New and this point produced no event
	// we could have seen, and would otherwise go unnoticed until the first
	// periodic reconciliation.
	reconcileAndLog(src, logger, "startup reconciliation")

	ticker := time.NewTicker(timing.ReconcileInterval)
	defer ticker.Stop()

	// A stopped timer with a drained channel: armed only while a reload is pending.
	debounce := time.NewTimer(time.Hour)
	stopTimer(debounce)
	defer debounce.Stop()

	var (
		pending  bool
		deadline time.Time
		attempt  int
	)

	for {
		select {
		case <-ctx.Done():
			return nil

		case event, ok := <-watcher.Events:
			if !ok {
				err := fmt.Errorf("event channel closed: %w", ErrWatcherClosed)
				src.RecordWatcherError(err)
				return err
			}
			if !isRelevant(event) {
				continue
			}

			if !pending {
				pending = true
				// Bound the total wait so a continuously churning directory
				// cannot postpone the reload indefinitely.
				deadline = now().Add(maximumDebounceWait)
			}
			// A true debounce: every new event restarts the quiet period, so
			// the reload happens once the burst has settled rather than a fixed
			// interval after the first event.
			resetTimer(debounce, quietPeriod(timing.Debounce, deadline, now))

		case err, ok := <-watcher.Errors:
			if !ok {
				err := fmt.Errorf("error channel closed: %w", ErrWatcherClosed)
				src.RecordWatcherError(err)
				return err
			}
			logger.Warn("filesystem watcher reported an error", "err", err)

		case <-debounce.C:
			pending = false
			if _, err := src.Reconcile(); err != nil {
				// Mid-rotation the material can briefly disagree with itself, or
				// only part of it may have been written. Retry a bounded number
				// of times before falling back to the periodic ticker.
				if attempt < maximumReloadRetries {
					attempt++
					delay := timing.RetryDelay * time.Duration(attempt)
					logger.Warn(src.Label+" reload failed; retrying",
						"err", err,
						"attempt", attempt,
						"retry_in", delay,
						src.LogKey, src.LogValue,
					)
					pending = true
					deadline = now().Add(maximumDebounceWait)
					resetTimer(debounce, delay)
					continue
				}
				logger.Error(src.Label+" reload failed; retries exhausted, "+src.RetainedNote,
					"err", err,
					src.LogKey, src.LogValue,
				)
			}
			attempt = 0

		case <-ticker.C:
			// fsnotify is not a durable event log: watches can be dropped, the
			// kernel queue can overflow, and container filesystems vary. This
			// periodic pass is what makes eventual convergence guaranteed
			// rather than best effort.
			reconcileAndLog(src, logger, "periodic reconciliation")
		}
	}
}

// Watch observes the certificate source and reloads it as it changes. It blocks
// until ctx is cancelled, returning nil, or until the filesystem watcher fails
// terminally, returning an error wrapping [ErrWatcherClosed].
//
// It is a thin call into [RunWatch], which carries the loop shared with the
// client CA trust bundle; see there for what the loop guarantees.
func (r *Reloader) Watch(ctx context.Context) error {
	return RunWatch(ctx, WatchSource{
		Directories:        r.watchDirectories(),
		Reconcile:          r.Reconcile,
		RecordWatcherError: r.recordWatcherError,
		Label:              "certificate",
		RetainedNote:       "continuing to serve the last valid certificate",
		LogKey:             "certificate_file",
		LogValue:           r.certFile,
	}, WatchTiming{
		Debounce:          r.debounce,
		ReconcileInterval: r.reconcileInterval,
		RetryDelay:        r.retryDelay,
	}, r.logger, r.now)
}

// quietPeriod returns how long to wait for the event burst to settle, clamped
// so the wait never extends past deadline.
func quietPeriod(debounce time.Duration, deadline time.Time, now func() time.Time) time.Duration {
	wait := debounce
	if remaining := deadline.Sub(now()); remaining < wait {
		wait = remaining
	}
	if wait < 0 {
		wait = 0
	}
	return wait
}

// watchDirectories returns the deduplicated parent directories of the
// certificate and key files.
func (r *Reloader) watchDirectories() []string {
	dirs := []string{filepath.Dir(r.certFile)}
	if keyDir := filepath.Dir(r.keyFile); !slices.Contains(dirs, keyDir) {
		dirs = append(dirs, keyDir)
	}
	return dirs
}

// isRelevant reports whether an event could indicate rotated material.
//
// The event name is deliberately not matched against the watched path. Under an
// atomic-writer layout the interesting event is a Create or Rename of `..data`,
// whose name bears no relation to the configured filename; filtering on the
// filename would discard exactly the events that matter.
func isRelevant(event fsnotify.Event) bool {
	return event.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Rename|fsnotify.Remove) != 0
}

func reconcileAndLog(src WatchSource, logger *slog.Logger, cause string) {
	changed, err := src.Reconcile()
	switch {
	case err != nil:
		logger.Warn(src.Label+" reconciliation failed; "+src.RetainedNote,
			"err", err,
			"cause", cause,
			src.LogKey, src.LogValue,
		)
	case changed:
		logger.Info(src.Label+" changed", "cause", cause)
	}
}

// stopTimer stops t and drains its channel if it had already fired.
func stopTimer(t *time.Timer) {
	if !t.Stop() {
		select {
		case <-t.C:
		default:
		}
	}
}

func resetTimer(t *time.Timer, d time.Duration) {
	stopTimer(t)
	t.Reset(d)
}
