package main

import (
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// serverFiles and clientFiles name the files each mode of run writes.
var (
	serverFiles = []string{"demo.pem", "demo-key.pem", "bundle.pem"}
	clientFiles = []string{"client-ca.pem", "client-ca-key.pem", "client.pem", "client-key.pem"}
)

// dirEntryNames returns the base names of the regular files in dir.
func dirEntryNames(t *testing.T, dir string) []string {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("ReadDir(%q): %v", dir, err)
	}
	var names []string
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

// containsAll reports whether got contains every element of want.
func containsAll(got, want []string) bool {
	set := make(map[string]bool, len(got))
	for _, name := range got {
		set[name] = true
	}
	for _, name := range want {
		if !set[name] {
			return false
		}
	}
	return true
}

func TestRun_DefaultWritesOnlyServerFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := run(dir, "*.raf.tech", []string{"*.raf.tech", "raf.tech"}, 24*time.Hour, false); err != nil {
		t.Fatalf("run: %v", err)
	}

	got := dirEntryNames(t, dir)
	if !containsAll(got, serverFiles) {
		t.Fatalf("dir entries = %v, want at least %v", got, serverFiles)
	}
	for _, name := range clientFiles {
		if err := existsIn(dir, name); err == nil {
			t.Errorf("default run wrote client file %s, want none", name)
		}
	}
	if len(got) != len(serverFiles) {
		t.Errorf("dir entries = %v, want exactly %v", got, serverFiles)
	}
}

// existsIn returns nil if dir contains a file named name, or an error
// otherwise - a small readability wrapper around os.Stat for the negative
// assertions above.
func existsIn(dir, name string) error {
	_, err := os.Stat(filepath.Join(dir, name))
	return err
}

func TestRun_ClientCAWritesOnlyClientFiles(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := run(dir, "*.raf.tech", []string{"*.raf.tech"}, 24*time.Hour, true); err != nil {
		t.Fatalf("run: %v", err)
	}

	got := dirEntryNames(t, dir)
	if !containsAll(got, clientFiles) {
		t.Fatalf("dir entries = %v, want at least %v", got, clientFiles)
	}
	for _, name := range serverFiles {
		if err := existsIn(dir, name); err == nil {
			t.Errorf("-client-ca run wrote server file %s, want none", name)
		}
	}
	if len(got) != len(clientFiles) {
		t.Errorf("dir entries = %v, want exactly %v", got, clientFiles)
	}
}

// TestRun_ClientCALeavesDemoFilesUntouched proves -client-ca does not rewrite
// the committed server material: it must not disturb files that are already
// there, not merely skip writing files with those names.
func TestRun_ClientCALeavesDemoFilesUntouched(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := run(dir, "*.raf.tech", []string{"*.raf.tech"}, 24*time.Hour, false); err != nil {
		t.Fatalf("run (server): %v", err)
	}

	before := make(map[string][]byte, len(serverFiles))
	for _, name := range serverFiles {
		content, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		before[name] = content
	}

	if err := run(dir, "*.raf.tech", []string{"*.raf.tech"}, 24*time.Hour, true); err != nil {
		t.Fatalf("run (client-ca): %v", err)
	}

	for _, name := range serverFiles {
		after, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("read %s after -client-ca run: %v", name, err)
		}
		if string(after) != string(before[name]) {
			t.Errorf("%s changed after -client-ca run", name)
		}
	}
}

// parseCertPEM decodes a single PEM-encoded certificate from path.
func parseCertPEM(t *testing.T, path string) *x509.Certificate {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		t.Fatalf("%s: no CERTIFICATE PEM block", path)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	return cert
}

func TestRun_ClientCA_IsACertSigningCA(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := run(dir, "", nil, 24*time.Hour, true); err != nil {
		t.Fatalf("run: %v", err)
	}

	ca := parseCertPEM(t, filepath.Join(dir, "client-ca.pem"))
	if !ca.IsCA {
		t.Error("client CA: IsCA = false, want true")
	}
	if ca.KeyUsage&x509.KeyUsageCertSign == 0 {
		t.Error("client CA: KeyUsageCertSign not set")
	}
}

func TestRun_ClientLeaf_VerifiesForClientAuthOnly(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := run(dir, "", nil, 24*time.Hour, true); err != nil {
		t.Fatalf("run: %v", err)
	}

	ca := parseCertPEM(t, filepath.Join(dir, "client-ca.pem"))
	leaf := parseCertPEM(t, filepath.Join(dir, "client.pem"))

	if leaf.IsCA {
		t.Error("client leaf: IsCA = true, want false")
	}

	pool := x509.NewCertPool()
	pool.AddCert(ca)

	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		t.Errorf("client leaf did not verify for ClientAuth: %v", err)
	}

	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     pool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}); err == nil {
		t.Error("client leaf verified for ServerAuth, want an error")
	}
}

func TestRun_ServerLeaf_ServerAuthOnlyNoKeyEncipherment(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := run(dir, "*.raf.tech", []string{"*.raf.tech"}, 24*time.Hour, false); err != nil {
		t.Fatalf("run: %v", err)
	}

	leaf := parseCertPEM(t, filepath.Join(dir, "demo.pem"))

	want := []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
	if len(leaf.ExtKeyUsage) != len(want) || leaf.ExtKeyUsage[0] != want[0] {
		t.Errorf("ExtKeyUsage = %v, want %v", leaf.ExtKeyUsage, want)
	}
	if leaf.KeyUsage&x509.KeyUsageKeyEncipherment != 0 {
		t.Error("KeyUsage includes KeyEncipherment, want it dropped for a TLS 1.3-only server")
	}
	if leaf.KeyUsage&x509.KeyUsageDigitalSignature == 0 {
		t.Error("KeyUsage missing DigitalSignature")
	}
}

// TestWriteFiles_PermissionsIncludingOnOverwrite is the regression test for
// the private-key permission bug: os.WriteFile's mode argument only applies
// when a file is newly created, so writing 0o600 over a file that already
// exists 0o644 - as a stale client-ca-key.pem from an older gencerts build
// would - silently leaves it world-readable. Each file is pre-created at
// 0o644 here so a reversion to plain os.WriteFile fails this test.
func TestWriteFiles_PermissionsIncludingOnOverwrite(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	for _, name := range append(append([]string{}, serverFiles...), clientFiles...) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte("stale"), 0o644); err != nil {
			t.Fatalf("pre-create %s: %v", name, err)
		}
	}

	if err := run(dir, "*.raf.tech", []string{"*.raf.tech"}, 24*time.Hour, false); err != nil {
		t.Fatalf("run (server): %v", err)
	}
	if err := run(dir, "", nil, 24*time.Hour, true); err != nil {
		t.Fatalf("run (client-ca): %v", err)
	}

	for _, name := range append(append([]string{}, serverFiles...), clientFiles...) {
		wantMode := os.FileMode(0o600)
		if !strings.Contains(name, "key") && name != "bundle.pem" {
			wantMode = 0o644
		}

		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil {
			t.Fatalf("stat %s: %v", name, err)
		}
		if got := info.Mode().Perm(); got != wantMode {
			t.Errorf("%s: mode = %v, want %v (pre-existed as 0o644)", name, got, wantMode)
		}
	}
}

func TestWriteFiles_BundleIsKeyThenCertificate(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := run(dir, "*.raf.tech", []string{"*.raf.tech"}, 24*time.Hour, false); err != nil {
		t.Fatalf("run: %v", err)
	}

	data, err := os.ReadFile(filepath.Join(dir, "bundle.pem"))
	if err != nil {
		t.Fatalf("read bundle.pem: %v", err)
	}

	first, rest := pem.Decode(data)
	if first == nil {
		t.Fatal("bundle.pem: no first PEM block")
	}
	if first.Type != "PRIVATE KEY" {
		t.Errorf("bundle.pem first block type = %q, want %q", first.Type, "PRIVATE KEY")
	}

	second, _ := pem.Decode(rest)
	if second == nil {
		t.Fatal("bundle.pem: no second PEM block")
	}
	if second.Type != "CERTIFICATE" {
		t.Errorf("bundle.pem second block type = %q, want %q", second.Type, "CERTIFICATE")
	}
}

func TestRun_RejectsNonPositiveValidFor(t *testing.T) {
	t.Parallel()

	tests := map[string]time.Duration{
		"zero":     0,
		"negative": -time.Hour,
	}

	for name, validFor := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			err := run(dir, "*.raf.tech", []string{"*.raf.tech"}, validFor, false)
			if err == nil {
				t.Fatalf("run(validFor=%v) = nil error, want an error", validFor)
			}
		})
	}
}
