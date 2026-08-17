package certreload

import (
	"context"
	"fmt"
	"path/filepath"
	"slices"
	"time"

	"github.com/fsnotify/fsnotify"
)

// Watch observes the certificate source and reloads it as it changes. It blocks
// until ctx is cancelled, returning nil, or until the filesystem watcher fails
// terminally, returning an error wrapping [ErrWatcherClosed].
//
// The watcher must not be left running unattended: a terminated watcher means
// rotation is no longer observed promptly, which the caller needs to act on.
//
// Directories are watched rather than files. Kubernetes rotates projected
// volumes and mounted secrets by writing a new timestamped directory and
// atomically swapping the `..data` symlink, so events never name the
// certificate path itself and a watch registered on the file would observe
// nothing.
func (r *Reloader) Watch(ctx context.Context) error {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		return fmt.Errorf("create filesystem watcher: %w", err)
	}
	defer func() { _ = watcher.Close() }()

	for _, dir := range r.watchDirectories() {
		if err := watcher.Add(dir); err != nil {
			return fmt.Errorf("watch directory %s: %w", dir, err)
		}
	}
	r.recordWatcherError(nil)

	// Reconcile once now that the watches are registered. A rotation that
	// landed between the initial load in New and this point produced no event
	// we could have seen, and would otherwise go unnoticed until the first
	// periodic reconciliation.
	r.reconcileAndLog("startup reconciliation")

	ticker := time.NewTicker(r.reconcileInterval)
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
				r.recordWatcherError(err)
				return err
			}
			if !isRelevant(event) {
				continue
			}

			if !pending {
				pending = true
				// Bound the total wait so a continuously churning directory
				// cannot postpone the reload indefinitely.
				deadline = r.now().Add(maximumDebounceWait)
			}
			// A true debounce: every new event restarts the quiet period, so
			// the reload happens once the burst has settled rather than a fixed
			// interval after the first event.
			resetTimer(debounce, r.quietPeriod(deadline))

		case err, ok := <-watcher.Errors:
			if !ok {
				err := fmt.Errorf("error channel closed: %w", ErrWatcherClosed)
				r.recordWatcherError(err)
				return err
			}
			r.logger.Warn("filesystem watcher reported an error", "err", err)

		case <-debounce.C:
			pending = false
			if _, err := r.Reconcile(); err != nil {
				// Mid-rotation the certificate and key can briefly disagree, or
				// only one of the two may have been written. Retry a bounded
				// number of times before falling back to the periodic ticker.
				if attempt < maximumReloadRetries {
					attempt++
					delay := r.retryDelay * time.Duration(attempt)
					r.logger.Warn("certificate reload failed; retrying",
						"err", err,
						"attempt", attempt,
						"retry_in", delay,
						"certificate_file", r.certFile,
					)
					pending = true
					deadline = r.now().Add(maximumDebounceWait)
					resetTimer(debounce, delay)
					continue
				}
				r.logger.Error("certificate reload failed; retries exhausted, continuing to serve the last valid certificate",
					"err", err,
					"certificate_file", r.certFile,
				)
			}
			attempt = 0

		case <-ticker.C:
			// fsnotify is not a durable event log: watches can be dropped, the
			// kernel queue can overflow, and container filesystems vary. This
			// periodic pass is what makes eventual convergence guaranteed
			// rather than best effort.
			r.reconcileAndLog("periodic reconciliation")
		}
	}
}

// quietPeriod returns how long to wait for the event burst to settle, clamped
// so the wait never extends past deadline.
func (r *Reloader) quietPeriod(deadline time.Time) time.Duration {
	wait := r.debounce
	if remaining := deadline.Sub(r.now()); remaining < wait {
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
// The event name is deliberately not matched against the certificate path.
// Under an atomic-writer layout the interesting event is a Create or Rename of
// `..data`, whose name bears no relation to the configured filename; filtering
// on the filename would discard exactly the events that matter.
func isRelevant(event fsnotify.Event) bool {
	return event.Op&(fsnotify.Create|fsnotify.Write|fsnotify.Rename|fsnotify.Remove) != 0
}

func (r *Reloader) reconcileAndLog(cause string) {
	changed, err := r.Reconcile()
	switch {
	case err != nil:
		r.logger.Warn("certificate reconciliation failed; continuing to serve the last valid certificate",
			"err", err,
			"cause", cause,
			"certificate_file", r.certFile,
		)
	case changed:
		r.logger.Info("certificate changed", "cause", cause)
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
