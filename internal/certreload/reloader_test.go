package certreload

import (
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func newTestReloader(t *testing.T, f *certFixture, opts ...Option) *Reloader {
	t.Helper()
	opts = append([]Option{WithLogger(quietLogger())}, opts...)
	r, err := New(f.certFile, f.keyFile, opts...)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

func TestNew_LoadsInitialCertificate(t *testing.T) {
	t.Parallel()

	f := newFixture(t, certOptions{commonName: "initial.example.com"})
	r := newTestReloader(t, f)

	cert, err := r.GetCertificate(nil)
	if err != nil {
		t.Fatalf("GetCertificate: %v", err)
	}
	if cert == nil || cert.Leaf == nil {
		t.Fatal("expected a certificate with a populated leaf")
	}
	if got := cert.Leaf.Subject.CommonName; got != "initial.example.com" {
		t.Errorf("common name = %q, want %q", got, "initial.example.com")
	}

	info, ok := r.CertificateInfo()
	if !ok {
		t.Fatal("CertificateInfo reported no certificate")
	}
	if info.Fingerprint == "" {
		t.Error("fingerprint is empty")
	}
	if info.FilePath != f.certFile {
		t.Errorf("file path = %q, want %q", info.FilePath, f.certFile)
	}
	if err := r.Ready(); err != nil {
		t.Errorf("Ready: %v", err)
	}
}

func TestNew_Rejects(t *testing.T) {
	t.Parallel()

	valid := newFixture(t, certOptions{})

	tests := map[string]struct {
		certFile string
		keyFile  string
		setup    func(t *testing.T) (string, string)
		wantErr  error
	}{
		"empty certificate path": {certFile: "", keyFile: valid.keyFile},
		"empty key path":         {certFile: valid.certFile, keyFile: ""},
		"missing files": {
			certFile: filepath.Join(t.TempDir(), "absent.crt"),
			keyFile:  filepath.Join(t.TempDir(), "absent.key"),
		},
		"malformed certificate": {
			setup: func(t *testing.T) (string, string) {
				f := newFixture(t, certOptions{})
				f.writeRaw(t, []byte("not a certificate"), []byte("not a key"))
				return f.certFile, f.keyFile
			},
		},
		"mismatched key": {
			setup: func(t *testing.T) (string, string) {
				a := newFixture(t, certOptions{commonName: "a.example.com"})
				b := newFixture(t, certOptions{commonName: "b.example.com"})
				// A certificate from one pair alongside the key from another is
				// what a half-completed rotation looks like on disk.
				return a.certFile, b.keyFile
			},
		},
		"expired certificate": {
			setup: func(t *testing.T) (string, string) {
				f := newFixture(t, certOptions{
					notBefore: time.Now().Add(-48 * time.Hour),
					notAfter:  time.Now().Add(-24 * time.Hour),
				})
				return f.certFile, f.keyFile
			},
			wantErr: ErrCertificateExpired,
		},
		"not yet valid certificate": {
			setup: func(t *testing.T) (string, string) {
				f := newFixture(t, certOptions{
					notBefore: time.Now().Add(24 * time.Hour),
					notAfter:  time.Now().Add(48 * time.Hour),
				})
				return f.certFile, f.keyFile
			},
			wantErr: ErrCertificateNotYetValid,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			certFile, keyFile := tc.certFile, tc.keyFile
			if tc.setup != nil {
				certFile, keyFile = tc.setup(t)
			}

			_, err := New(certFile, keyFile, WithLogger(quietLogger()))
			if err == nil {
				t.Fatal("expected an error, got nil")
			}
			if tc.wantErr != nil && !errors.Is(err, tc.wantErr) {
				t.Errorf("error = %v, want one matching %v", err, tc.wantErr)
			}
		})
	}
}

func TestNew_AllowExpiredOptIn(t *testing.T) {
	t.Parallel()

	f := newFixture(t, certOptions{
		notBefore: time.Now().Add(-48 * time.Hour),
		notAfter:  time.Now().Add(-24 * time.Hour),
	})

	r, err := New(f.certFile, f.keyFile, WithLogger(quietLogger()), AllowExpired(true))
	if err != nil {
		t.Fatalf("New with AllowExpired: %v", err)
	}

	// The certificate is served so the operator can inspect it, but readiness
	// reports the problem rather than hiding it.
	if _, err := r.GetCertificate(nil); err != nil {
		t.Errorf("GetCertificate: %v", err)
	}
	if err := r.Ready(); !errors.Is(err, ErrCertificateExpired) {
		t.Errorf("Ready error = %v, want one matching %v", err, ErrCertificateExpired)
	}

	info, _ := r.CertificateInfo()
	if state, _ := info.State(time.Now()); state != ValidityExpired {
		t.Errorf("state = %v, want %v", state, ValidityExpired)
	}
}

// TestReconcile_DetectsContentChangeWithOlderModTime is the regression test for
// the reload mechanism this refactor replaced. The previous implementation
// compared stat().ModTime() against the last load, so a rotation that preserved
// or backdated the timestamp was ignored indefinitely.
func TestReconcile_DetectsContentChangeWithOlderModTime(t *testing.T) {
	t.Parallel()

	f := newFixture(t, certOptions{commonName: "before.example.com"})
	r := newTestReloader(t, f)

	original := fingerprintOf(t, r)
	originalModTime := f.modTime(t)

	f.write(t, certOptions{commonName: "after.example.com"})
	// Backdate the replacement well before the original load.
	f.setModTime(t, originalModTime.Add(-time.Hour))

	changed, err := r.Reconcile()
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if !changed {
		t.Fatal("expected the replacement to be detected despite an older modification time")
	}
	if got := fingerprintOf(t, r); got == original {
		t.Error("fingerprint did not change after rotation")
	}

	info, _ := r.CertificateInfo()
	if info.Subject != "CN=after.example.com" {
		t.Errorf("subject = %q, want %q", info.Subject, "CN=after.example.com")
	}
}

// TestReconcile_SuppressesDuplicatePublication covers the "exactly one
// publication for an event burst" requirement: a burst produces repeated
// reconciliations, and identical content must not republish.
func TestReconcile_SuppressesDuplicatePublication(t *testing.T) {
	t.Parallel()

	f := newFixture(t, certOptions{})
	r := newTestReloader(t, f)

	for i := range 5 {
		changed, err := r.Reconcile()
		if err != nil {
			t.Fatalf("Reconcile %d: %v", i, err)
		}
		if changed {
			t.Fatalf("Reconcile %d republished unchanged content", i)
		}
	}
}

func TestReconcile_RetainsCachedCertificate(t *testing.T) {
	t.Parallel()

	tests := map[string]func(t *testing.T, f *certFixture){
		"source removed": func(t *testing.T, f *certFixture) {
			f.remove(t)
		},
		"malformed replacement": func(t *testing.T, f *certFixture) {
			f.writeRaw(t, []byte("-----BEGIN CERTIFICATE-----\ngarbage\n"), []byte("garbage"))
		},
		"mismatched replacement": func(t *testing.T, f *certFixture) {
			// Replace only the certificate: the key on disk no longer matches.
			certPEM, _ := generateCert(t, certOptions{commonName: "other.example.com"})
			writeFile(t, f.certFile, certPEM)
		},
		"empty certificate file": func(t *testing.T, f *certFixture) {
			writeFile(t, f.certFile, nil)
		},
	}

	for name, breakIt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			f := newFixture(t, certOptions{commonName: "cached.example.com"})
			r := newTestReloader(t, f)
			original := fingerprintOf(t, r)

			breakIt(t, f)

			if _, err := r.Reconcile(); err == nil {
				t.Fatal("expected Reconcile to fail")
			}

			// The handshake path must keep working on last-good material.
			cert, err := r.GetCertificate(nil)
			if err != nil {
				t.Fatalf("GetCertificate after failed reload: %v", err)
			}
			if cert.Leaf.Subject.CommonName != "cached.example.com" {
				t.Errorf("common name = %q, want the cached certificate", cert.Leaf.Subject.CommonName)
			}
			if got := fingerprintOf(t, r); got != original {
				t.Error("a failed reload replaced the cached certificate")
			}

			health := r.Health()
			if health.ConsecutiveFailures != 1 {
				t.Errorf("consecutive failures = %d, want 1", health.ConsecutiveFailures)
			}
			if health.LastError == "" {
				t.Error("expected the failure to be recorded")
			}
		})
	}
}

func TestReconcile_RecoversAfterFailure(t *testing.T) {
	t.Parallel()

	f := newFixture(t, certOptions{commonName: "original.example.com"})
	r := newTestReloader(t, f)
	original := fingerprintOf(t, r)

	f.writeRaw(t, []byte("truncated"), []byte("truncated"))
	if _, err := r.Reconcile(); err == nil {
		t.Fatal("expected the malformed replacement to fail")
	}

	f.write(t, certOptions{commonName: "recovered.example.com"})
	changed, err := r.Reconcile()
	if err != nil {
		t.Fatalf("Reconcile after recovery: %v", err)
	}
	if !changed {
		t.Fatal("expected the recovered certificate to be published")
	}
	if got := fingerprintOf(t, r); got == original {
		t.Error("still serving the original certificate after recovery")
	}

	health := r.Health()
	if health.ConsecutiveFailures != 0 {
		t.Errorf("consecutive failures = %d, want 0 after recovery", health.ConsecutiveFailures)
	}
	if err := r.Ready(); err != nil {
		t.Errorf("Ready after recovery: %v", err)
	}
}

// TestGetCertificate_ConcurrentWithRotation is the regression test for the data
// race this work started from. Run under -race it fails on any unsynchronised
// access between the handshake path and reload publication.
func TestGetCertificate_ConcurrentWithRotation(t *testing.T) {
	t.Parallel()

	f := newFixture(t, certOptions{})
	r := newTestReloader(t, f)

	const (
		readers   = 32
		reloads   = 16
		perReader = 50
	)

	var (
		wg    sync.WaitGroup
		stop  atomic.Bool
		reads atomic.Int64
	)

	wg.Add(readers)
	for range readers {
		go func() {
			defer wg.Done()
			for range perReader {
				if stop.Load() {
					return
				}
				cert, err := r.GetCertificate(&tls.ClientHelloInfo{})
				if err != nil {
					t.Errorf("GetCertificate: %v", err)
					return
				}
				// Touch the published state the way crypto/tls would.
				if cert.Leaf == nil || len(cert.Certificate) == 0 {
					t.Error("published snapshot is incomplete")
					return
				}
				_, _ = r.CertificateInfo()
				reads.Add(1)
			}
		}()
	}

	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := range reloads {
			f.write(t, certOptions{commonName: "rotated.example.com"})
			if _, err := r.Reconcile(); err != nil {
				t.Errorf("Reconcile %d: %v", i, err)
				stop.Store(true)
				return
			}
		}
	}()

	wg.Wait()

	if reads.Load() == 0 {
		t.Fatal("no reads were performed")
	}
	if _, err := r.GetCertificate(nil); err != nil {
		t.Errorf("GetCertificate after rotation: %v", err)
	}
}

// TestCertificateInfo_ReturnsIndependentCopy verifies the snapshot is immutable
// in practice: a caller mutating the returned slices must not affect the
// published state that every other reader shares.
func TestCertificateInfo_ReturnsIndependentCopy(t *testing.T) {
	t.Parallel()

	f := newFixture(t, certOptions{
		commonName: "copy.example.com",
		dnsNames:   []string{"copy.example.com", "alias.example.com"},
	})
	r := newTestReloader(t, f)

	first, _ := r.CertificateInfo()
	if len(first.DNSNames) != 2 {
		t.Fatalf("dns names = %v, want 2 entries", first.DNSNames)
	}
	first.DNSNames[0] = "mutated.example.com"

	second, _ := r.CertificateInfo()
	if second.DNSNames[0] == "mutated.example.com" {
		t.Error("mutating the returned Info changed the published snapshot")
	}
}

func TestInfoState(t *testing.T) {
	t.Parallel()

	now := time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)

	tests := map[string]struct {
		notBefore    time.Time
		notAfter     time.Time
		wantState    Validity
		wantDuration time.Duration
	}{
		"valid": {
			notBefore:    now.Add(-time.Hour),
			notAfter:     now.Add(2 * time.Hour),
			wantState:    ValidityValid,
			wantDuration: 2 * time.Hour,
		},
		"expired": {
			notBefore:    now.Add(-3 * time.Hour),
			notAfter:     now.Add(-time.Hour),
			wantState:    ValidityExpired,
			wantDuration: time.Hour,
		},
		"not yet valid": {
			notBefore:    now.Add(time.Hour),
			notAfter:     now.Add(3 * time.Hour),
			wantState:    ValidityNotYetValid,
			wantDuration: time.Hour,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			info := Info{NotBefore: tc.notBefore, NotAfter: tc.notAfter}
			state, duration := info.State(now)
			if state != tc.wantState {
				t.Errorf("state = %v, want %v", state, tc.wantState)
			}
			if duration != tc.wantDuration {
				t.Errorf("duration = %v, want %v", duration, tc.wantDuration)
			}
		})
	}
}

func TestReady_FailsAfterProlongedStaleness(t *testing.T) {
	t.Parallel()

	f := newFixture(t, certOptions{})

	// A clock the test advances by hand, so staleness is exercised without
	// sleeping.
	var current atomic.Pointer[time.Time]
	start := time.Now()
	current.Store(&start)
	clock := func() time.Time { return *current.Load() }

	r := newTestReloader(t, f,
		WithClock(clock),
		WithMaximumStalePeriod(10*time.Minute),
	)

	f.remove(t)
	if _, err := r.Reconcile(); err == nil {
		t.Fatal("expected Reconcile to fail after the source was removed")
	}

	// Within the stale window the cached certificate is still good enough.
	if err := r.Ready(); err != nil {
		t.Errorf("Ready during the grace period: %v", err)
	}

	later := start.Add(11 * time.Minute)
	current.Store(&later)

	if err := r.Ready(); err == nil {
		t.Error("expected Ready to fail once the source had been unreadable past the stale period")
	}
}
