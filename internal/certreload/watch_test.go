package certreload

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// waitForFingerprintChange polls until the served certificate differs from
// original, or the deadline passes.
func waitForFingerprintChange(t *testing.T, r *Reloader, original string, within time.Duration) string {
	t.Helper()

	deadline := time.Now().Add(within)
	for time.Now().Before(deadline) {
		if current := fingerprintOf(t, r); current != original {
			return current
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("certificate did not change within %s", within)
	return ""
}

// runWatch starts Watch on a cancellable context and returns a stop function
// that cancels it and reports the error Watch returned.
func runWatch(t *testing.T, r *Reloader) (stop func() error) {
	t.Helper()

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- r.Watch(ctx) }()

	stopped := false
	stop = func() error {
		if stopped {
			return nil
		}
		stopped = true
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(5 * time.Second):
			return errors.New("Watch did not return within 5s of cancellation")
		}
	}
	t.Cleanup(func() { _ = stop() })
	return stop
}

// TestWatch_ObservesRotation covers the filesystem-event path end to end. It is
// the only test that depends on fsnotify; the reconciliation logic itself is
// covered directly in reloader_test.go, which keeps the suite deterministic.
func TestWatch_ObservesRotation(t *testing.T) {
	t.Parallel()

	f := newFixture(t, certOptions{commonName: "watch-before.example.com"})
	r := newTestReloader(t, f,
		WithDebounce(20*time.Millisecond),
		// Long enough that a pass cannot fire during the test: this asserts the
		// event path, not the ticker.
		WithReconcileInterval(time.Hour),
	)
	original := fingerprintOf(t, r)

	runWatch(t, r)
	// Give the watcher a moment to register before rotating.
	time.Sleep(50 * time.Millisecond)

	f.write(t, certOptions{commonName: "watch-after.example.com"})
	waitForFingerprintChange(t, r, original, 5*time.Second)

	info, _ := r.CertificateInfo()
	if info.Subject != "CN=watch-after.example.com" {
		t.Errorf("subject = %q, want the rotated certificate", info.Subject)
	}
}

// TestWatch_PeriodicReconciliationRecoversLostEvents proves the correctness
// guarantee does not rest on fsnotify. The reconcile interval alone must
// converge even when no usable event is ever delivered.
func TestWatch_PeriodicReconciliationRecoversLostEvents(t *testing.T) {
	t.Parallel()

	f := newFixture(t, certOptions{commonName: "ticker-before.example.com"})
	r := newTestReloader(t, f,
		// A debounce far longer than the test disables the event path: any
		// filesystem event that arrives will not elapse its quiet period, so
		// only the periodic pass can publish the replacement.
		WithDebounce(time.Hour),
		WithReconcileInterval(50*time.Millisecond),
	)
	original := fingerprintOf(t, r)

	runWatch(t, r)
	// Let the startup reconciliation complete so it cannot be what succeeds.
	time.Sleep(100 * time.Millisecond)

	f.write(t, certOptions{commonName: "ticker-after.example.com"})

	waitForFingerprintChange(t, r, original, 5*time.Second)
}

// TestWatch_ReconcilesAtStartup covers the race between the initial load in New
// and watch registration: material rotated in that window produces no event.
func TestWatch_ReconcilesAtStartup(t *testing.T) {
	t.Parallel()

	f := newFixture(t, certOptions{commonName: "startup-before.example.com"})
	r := newTestReloader(t, f,
		WithDebounce(10*time.Millisecond),
		// No ticker may fire: only the startup reconciliation can succeed here.
		WithReconcileInterval(time.Hour),
	)
	original := fingerprintOf(t, r)

	f.write(t, certOptions{commonName: "startup-after.example.com"})

	runWatch(t, r)

	waitForFingerprintChange(t, r, original, 5*time.Second)
}

func TestWatch_StopsPromptlyOnCancellation(t *testing.T) {
	t.Parallel()

	f := newFixture(t, certOptions{})
	r := newTestReloader(t, f,
		WithDebounce(10*time.Millisecond),
		WithReconcileInterval(20*time.Millisecond),
		WithRetryDelay(10*time.Millisecond),
	)

	// Break the source so the retry path is active when cancellation arrives.
	f.remove(t)

	stop := runWatch(t, r)
	time.Sleep(100 * time.Millisecond)

	start := time.Now()
	if err := stop(); err != nil {
		t.Fatalf("Watch returned %v, want nil on cancellation", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("Watch took %s to stop after cancellation", elapsed)
	}
}

func TestWatch_FailsOnUnwatchableDirectory(t *testing.T) {
	t.Parallel()

	f := newFixture(t, certOptions{})
	r := newTestReloader(t, f)

	// Remove the directory out from under the watcher so registration fails.
	if err := os.RemoveAll(f.dir); err != nil {
		t.Fatalf("remove %s: %v", f.dir, err)
	}

	err := r.Watch(t.Context())
	if err == nil {
		t.Fatal("expected Watch to fail when the directory cannot be watched")
	}
}

func TestWatchDirectories_DeduplicatesSharedParent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()

	shared := &Reloader{
		certFile: filepath.Join(dir, "tls.crt"),
		keyFile:  filepath.Join(dir, "tls.key"),
	}
	if got := shared.watchDirectories(); len(got) != 1 {
		t.Errorf("watch directories = %v, want a single entry for a shared parent", got)
	}

	split := &Reloader{
		certFile: filepath.Join(dir, "certs", "tls.crt"),
		keyFile:  filepath.Join(dir, "keys", "tls.key"),
	}
	if got := split.watchDirectories(); len(got) != 2 {
		t.Errorf("watch directories = %v, want both parents", got)
	}
}

// TestWatch_SurvivesAtomicSymlinkRotation reproduces the Kubernetes
// projected-volume layout: the served paths are symlinks into a `..data`
// directory which is replaced by an atomic rename. Events name `..data`, never
// the certificate, so a watch on the file itself would observe nothing.
func TestWatch_SurvivesAtomicSymlinkRotation(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	certLink := filepath.Join(root, "tls.crt")
	keyLink := filepath.Join(root, "tls.key")

	writeGeneration := func(name, commonName string) string {
		dir := filepath.Join(root, name)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
		certPEM, keyPEM := generateCert(t, certOptions{commonName: commonName})
		writeFile(t, filepath.Join(dir, "tls.crt"), certPEM)
		writeFile(t, filepath.Join(dir, "tls.key"), keyPEM)
		return dir
	}

	first := writeGeneration("..data_1", "symlink-before.example.com")
	symlink(t, first, filepath.Join(root, "..data"))
	symlink(t, filepath.Join(root, "..data", "tls.crt"), certLink)
	symlink(t, filepath.Join(root, "..data", "tls.key"), keyLink)

	r, err := New(certLink, keyLink,
		WithLogger(quietLogger()),
		WithDebounce(20*time.Millisecond),
		WithReconcileInterval(time.Hour),
	)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	original := fingerprintOf(t, r)

	runWatch(t, r)
	time.Sleep(50 * time.Millisecond)

	// Atomic swap: a new ..data symlink is renamed over the old one.
	second := writeGeneration("..data_2", "symlink-after.example.com")
	staging := filepath.Join(root, "..data_tmp")
	symlink(t, second, staging)
	if err := os.Rename(staging, filepath.Join(root, "..data")); err != nil {
		t.Fatalf("rename %s: %v", staging, err)
	}

	waitForFingerprintChange(t, r, original, 5*time.Second)

	info, _ := r.CertificateInfo()
	if info.Subject != "CN=symlink-after.example.com" {
		t.Errorf("subject = %q, want the rotated certificate", info.Subject)
	}
}

func symlink(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink %s -> %s: %v", link, target, err)
	}
}
