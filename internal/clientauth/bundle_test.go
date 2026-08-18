package clientauth

import (
	"bytes"
	"context"
	"crypto/x509"
	"io"
	"log/slog"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// bundleFixture is a client CA bundle written to a temporary directory, which
// tests rewrite in place to simulate a rotation.
type bundleFixture struct {
	dir  string
	path string
}

func newBundleFixture(t *testing.T, commonNames ...string) *bundleFixture {
	t.Helper()

	dir := t.TempDir()
	f := &bundleFixture{dir: dir, path: filepath.Join(dir, "client-ca.pem")}
	f.write(t, commonNames...)
	return f
}

// write replaces the bundle with freshly generated CAs, one per common name.
func (f *bundleFixture) write(t *testing.T, commonNames ...string) {
	t.Helper()

	var content []byte
	for _, name := range commonNames {
		content = append(content, caCertPEM(t, name)...)
	}
	f.writeRaw(t, content)
}

// writeRaw replaces the bundle with arbitrary bytes, so a test can simulate
// material that is truncated, corrupt, or empty.
func (f *bundleFixture) writeRaw(t *testing.T, content []byte) {
	t.Helper()
	if err := os.WriteFile(f.path, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", f.path, err)
	}
}

func (f *bundleFixture) remove(t *testing.T) {
	t.Helper()
	if err := os.Remove(f.path); err != nil {
		t.Fatalf("remove %s: %v", f.path, err)
	}
}

// newTestBundle builds a Bundle over f with logging silenced.
func newTestBundle(t *testing.T, f *bundleFixture, opts ...BundleOption) *Bundle {
	t.Helper()

	b, err := NewBundle(f.path, append([]BundleOption{WithLogger(quietLogger())}, opts...)...)
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}
	return b
}

// subjectsOf returns the subjects the bundle currently trusts, sorted so that
// comparisons do not depend on the order the CAs appear in the file.
func subjectsOf(b *Bundle) []string {
	var subjects []string
	for _, anchor := range b.Anchors() {
		subjects = append(subjects, anchor.Subject)
	}
	slices.Sort(subjects)
	return subjects
}

func TestNewBundle(t *testing.T) {
	t.Parallel()

	t.Run("publishes the loaded anchors", func(t *testing.T) {
		t.Parallel()

		f := newBundleFixture(t, "first-ca", "second-ca")
		b := newTestBundle(t, f)

		if b.Pool() == nil {
			t.Fatal("Pool is nil; a nil pool makes crypto/x509 fall back to the system roots")
		}
		if got, want := subjectsOf(b), []string{"CN=first-ca", "CN=second-ca"}; !slices.Equal(got, want) {
			t.Errorf("anchors = %v, want %v", got, want)
		}
	})

	// Every LoadTrustStore failure is a startup failure. There is no safe
	// fallback: an empty pool refuses every client, and a nil one trusts the
	// whole public web.
	t.Run("fails rather than starting without a usable bundle", func(t *testing.T) {
		t.Parallel()

		tests := map[string]func(t *testing.T) string{
			"missing file": func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "absent.pem")
			},
			"no certificate": func(t *testing.T) string {
				return newBundleFixture(t).path
			},
			"corrupt armour": func(t *testing.T) string {
				f := newBundleFixture(t)
				f.writeRaw(t, corruptArmourCertificateBlock())
				return f.path
			},
		}

		for name, path := range tests {
			t.Run(name, func(t *testing.T) {
				t.Parallel()

				if _, err := NewBundle(path(t), WithLogger(quietLogger())); err == nil {
					t.Fatal("NewBundle returned no error, want a startup failure")
				}
			})
		}
	})

	t.Run("rejects an empty path", func(t *testing.T) {
		t.Parallel()

		if _, err := NewBundle(""); err == nil {
			t.Fatal("NewBundle(\"\") returned no error")
		}
	})
}

// TestBundle_FailedReloadRetainsLastKnownGood is the test for invariant 1: a
// reload that fails for any reason leaves the previously published pool in
// place, and never publishes nil or empty.
//
// The consequence of getting this wrong is not a degraded service but a silent
// escalation of trust: crypto/x509 substitutes the system root pool when
// Roots is nil, so a nil ClientCAs under VerifyClientCertIfGiven turns every
// publicly issued client certificate into a verified identity.
func TestBundle_FailedReloadRetainsLastKnownGood(t *testing.T) {
	t.Parallel()

	breakages := map[string]func(t *testing.T, f *bundleFixture){
		"unreadable": func(t *testing.T, f *bundleFixture) { f.remove(t) },
		"empty": func(t *testing.T, f *bundleFixture) {
			f.writeRaw(t, nil)
		},
		"truncated mid-block": func(t *testing.T, f *bundleFixture) {
			pem := caCertPEM(t, "truncated-ca")
			f.writeRaw(t, pem[:len(pem)/2])
		},
		"corrupt armour beside a valid CA": func(t *testing.T, f *bundleFixture) {
			f.writeRaw(t, append(caCertPEM(t, "surviving-ca"), corruptArmourCertificateBlock()...))
		},
		"not a CA": func(t *testing.T, f *bundleFixture) {
			template := caTemplate("leaf-not-ca")
			template.IsCA = false
			f.writeRaw(t, certPEM(t, template))
		},
	}

	for name, breakIt := range breakages {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := newBundleFixture(t, "trusted-ca")
			b := newTestBundle(t, f)
			before := b.Pool()

			breakIt(t, f)

			changed, err := b.Reconcile()
			if err == nil {
				t.Fatal("Reconcile returned no error, want the broken bundle refused")
			}
			if changed {
				t.Error("Reconcile reported a change, want the previous pool retained")
			}
			if b.Pool() == nil {
				t.Fatal("Pool is nil after a failed reload; every public CA would now be trusted")
			}
			if b.Pool() != before {
				t.Error("Pool was replaced after a failed reload, want the last known good pool")
			}
			if got, want := subjectsOf(b), []string{"CN=trusted-ca"}; !slices.Equal(got, want) {
				t.Errorf("anchors = %v, want the last known good %v", got, want)
			}
		})
	}
}

// TestBundle_ShrinkingBundlePublishesImmediately is the test for invariant 2:
// removing a CA is revocation and must take effect on the next reconcile. A
// rule that only ever grew the pool would make revocation impossible, which is
// the other way this feature could fail open.
func TestBundle_ShrinkingBundlePublishesImmediately(t *testing.T) {
	t.Parallel()

	f := newBundleFixture(t, "retained-ca", "revoked-ca")
	b := newTestBundle(t, f)

	f.write(t, "retained-ca")

	changed, err := b.Reconcile()
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !changed {
		t.Fatal("Reconcile reported no change, want the smaller bundle published immediately")
	}
	if got, want := subjectsOf(b), []string{"CN=retained-ca"}; !slices.Equal(got, want) {
		t.Errorf("anchors = %v, want only %v", got, want)
	}
}

func TestBundle_Reconcile(t *testing.T) {
	t.Parallel()

	t.Run("republishes changed content", func(t *testing.T) {
		t.Parallel()

		f := newBundleFixture(t, "before-ca")
		b := newTestBundle(t, f)
		before := b.Pool()

		f.write(t, "after-ca")

		changed, err := b.Reconcile()
		if err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		if !changed {
			t.Error("Reconcile reported no change, want the rotated bundle published")
		}
		if b.Pool() == before {
			t.Error("Pool was not replaced, want the rotated pool")
		}
	})

	t.Run("is quiet when the content is unchanged", func(t *testing.T) {
		t.Parallel()

		f := newBundleFixture(t, "steady-ca")
		b := newTestBundle(t, f)

		changed, err := b.Reconcile()
		if err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		if changed {
			t.Error("Reconcile reported a change for identical content")
		}
	})

	// Trust is a set. A writer that emits the same anchors in a different
	// order has changed nothing anyone can act on, and republishing would
	// churn every derived tls.Config for no reason.
	t.Run("ignores a reordering of the same anchors", func(t *testing.T) {
		t.Parallel()

		first, second := caCertPEM(t, "alpha-ca"), caCertPEM(t, "beta-ca")

		f := newBundleFixture(t)
		f.writeRaw(t, append(slices.Clone(first), second...))
		b := newTestBundle(t, f)

		f.writeRaw(t, append(slices.Clone(second), first...))

		changed, err := b.Reconcile()
		if err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		if changed {
			t.Error("Reconcile reported a change for reordered but identical anchors")
		}
	})
}

func TestBundle_OnChange(t *testing.T) {
	t.Parallel()

	t.Run("fires with the newly published pool", func(t *testing.T) {
		t.Parallel()

		f := newBundleFixture(t, "before-ca")
		b := newTestBundle(t, f)

		var got []*x509.CertPool
		b.OnChange(func(pool *x509.CertPool) { got = append(got, pool) })

		f.write(t, "after-ca")
		if _, err := b.Reconcile(); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}

		if len(got) != 1 {
			t.Fatalf("callback ran %d times, want 1", len(got))
		}
		if got[0] != b.Pool() {
			t.Error("callback received a pool other than the published one")
		}
	})

	t.Run("does not fire when nothing changed", func(t *testing.T) {
		t.Parallel()

		f := newBundleFixture(t, "steady-ca")
		b := newTestBundle(t, f)

		var calls int
		b.OnChange(func(*x509.CertPool) { calls++ })

		if _, err := b.Reconcile(); err != nil {
			t.Fatalf("Reconcile: %v", err)
		}
		if calls != 0 {
			t.Errorf("callback ran %d times, want 0 for unchanged content", calls)
		}
	})

	t.Run("does not fire when the reload failed", func(t *testing.T) {
		t.Parallel()

		f := newBundleFixture(t, "steady-ca")
		b := newTestBundle(t, f)

		var calls int
		b.OnChange(func(*x509.CertPool) { calls++ })

		f.remove(t)
		if _, err := b.Reconcile(); err == nil {
			t.Fatal("Reconcile returned no error for a removed bundle")
		}
		if calls != 0 {
			t.Errorf("callback ran %d times, want 0 for a failed reload", calls)
		}
	})
}

func TestBundle_Status(t *testing.T) {
	t.Parallel()

	f := newBundleFixture(t, "status-ca")

	loaded := time.Date(2026, 8, 18, 5, 0, 0, 0, time.UTC)
	clock := loaded
	b := newTestBundle(t, f, WithClock(func() time.Time { return clock }))

	status := b.Status()
	if status.FilePath != f.path {
		t.Errorf("FilePath = %q, want %q", status.FilePath, f.path)
	}
	if len(status.Anchors) != 1 || status.Anchors[0].Subject != "CN=status-ca" {
		t.Errorf("Anchors = %+v, want the loaded CA", status.Anchors)
	}
	if status.Anchors[0].FingerprintSHA256 == "" {
		t.Error("anchor fingerprint is empty; a rotation that reuses the subject would be invisible")
	}
	if !status.LoadedAt.Equal(loaded) || !status.LastSuccess.Equal(loaded) {
		t.Errorf("LoadedAt = %s, LastSuccess = %s, want both %s", status.LoadedAt, status.LastSuccess, loaded)
	}
	if status.LastError != "" {
		t.Errorf("LastError = %q, want empty after a successful load", status.LastError)
	}

	// A failed reload must be visible: it is the only warning an operator gets
	// that the pool being enforced is no longer the one on disk.
	clock = loaded.Add(time.Minute)
	f.remove(t)
	if _, err := b.Reconcile(); err == nil {
		t.Fatal("Reconcile returned no error for a removed bundle")
	}

	status = b.Status()
	if status.LastError == "" {
		t.Error("LastError is empty after a failed reload")
	}
	if !status.LastSuccess.Equal(loaded) {
		t.Errorf("LastSuccess = %s, want it pinned to the last good read %s", status.LastSuccess, loaded)
	}
	if !status.LoadedAt.Equal(loaded) {
		t.Errorf("LoadedAt = %s, want the retained pool's load time %s", status.LoadedAt, loaded)
	}
}

// TestBundle_StatusAnchorsAreACopy guards the published snapshot: every
// concurrent reader shares it, so a caller must not be able to mutate what it
// holds.
func TestBundle_StatusAnchorsAreACopy(t *testing.T) {
	t.Parallel()

	f := newBundleFixture(t, "copy-ca")
	b := newTestBundle(t, f)

	b.Status().Anchors[0].Subject = "CN=tampered"

	if got := b.Status().Anchors[0].Subject; got != "CN=copy-ca" {
		t.Errorf("subject = %q after mutating a returned copy, want CN=copy-ca", got)
	}
}

// TestBundle_WatchObservesAtomicRotation reproduces the Kubernetes projected
// volume layout: the configured path is a symlink into a `..data` directory
// which is replaced by an atomic rename. Events name `..data`, never the
// bundle, so this only passes if the watch is registered on the directory.
func TestBundle_WatchObservesAtomicRotation(t *testing.T) {
	t.Parallel()

	root := t.TempDir()
	bundlePath := filepath.Join(root, "client-ca.pem")

	writeGeneration := func(name, commonName string) string {
		dir := filepath.Join(root, name)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatalf("mkdir %s: %v", dir, err)
		}
		if err := os.WriteFile(filepath.Join(dir, "client-ca.pem"), caCertPEM(t, commonName), 0o600); err != nil {
			t.Fatalf("write generation %s: %v", name, err)
		}
		return dir
	}

	symlink := func(target, link string) {
		t.Helper()
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("symlink %s -> %s: %v", link, target, err)
		}
	}

	first := writeGeneration("..data_1", "rotation-before-ca")
	symlink(first, filepath.Join(root, "..data"))
	symlink(filepath.Join(root, "..data", "client-ca.pem"), bundlePath)

	b, err := NewBundle(bundlePath,
		WithLogger(quietLogger()),
		WithDebounce(20*time.Millisecond),
		// Long enough that no periodic pass can fire: this asserts the event
		// path, not the ticker.
		WithReconcileInterval(time.Hour),
	)
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- b.Watch(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Watch returned %v, want nil on cancellation", err)
			}
		case <-time.After(5 * time.Second):
			t.Error("Watch did not return within 5s of cancellation")
		}
	})

	// Give the watcher a moment to register before rotating.
	time.Sleep(50 * time.Millisecond)

	second := writeGeneration("..data_2", "rotation-after-ca")
	staging := filepath.Join(root, "..data_tmp")
	symlink(second, staging)
	if err := os.Rename(staging, filepath.Join(root, "..data")); err != nil {
		t.Fatalf("rename %s: %v", staging, err)
	}

	deadline := time.Now().Add(5 * time.Second)
	for {
		if slices.Equal(subjectsOf(b), []string{"CN=rotation-after-ca"}) {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("anchors = %v after 5s, want the rotated CA", subjectsOf(b))
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// TestBundle_WatchFailsOnUnwatchableDirectory proves the watcher reports a
// terminal failure rather than running blind. cmd wires Watch into
// runComponents, so this is what brings the process down.
func TestBundle_WatchFailsOnUnwatchableDirectory(t *testing.T) {
	t.Parallel()

	f := newBundleFixture(t, "doomed-ca")
	b := newTestBundle(t, f)

	if err := os.RemoveAll(f.dir); err != nil {
		t.Fatalf("remove %s: %v", f.dir, err)
	}

	if err := b.Watch(t.Context()); err == nil {
		t.Fatal("expected Watch to fail when the directory cannot be watched")
	}
}

// TestBundle_LogsAreQuietOnSuccess keeps the reload log line at info and names
// the file, so an operator grepping for a rotation finds it.
func TestBundle_LogsReloads(t *testing.T) {
	t.Parallel()

	var logged bytes.Buffer
	f := newBundleFixture(t, "logged-before-ca")
	b, err := NewBundle(f.path, WithLogger(slog.New(slog.NewTextHandler(&logged, nil))))
	if err != nil {
		t.Fatalf("NewBundle: %v", err)
	}

	f.write(t, "logged-after-ca")
	if _, err := b.Reconcile(); err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if !bytes.Contains(logged.Bytes(), []byte(f.path)) {
		t.Errorf("reload log does not name the bundle file:\n%s", logged.String())
	}
}
