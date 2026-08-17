package certreload

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// certOptions describes the certificate a test wants generated.
type certOptions struct {
	commonName string
	dnsNames   []string
	notBefore  time.Time
	notAfter   time.Time
}

// generateCert returns PEM-encoded certificate and key material.
//
// Certificates are generated in process rather than committed as fixtures:
// fixtures expire, and an expired fixture is what made this repository's demo
// unbootable in the first place.
func generateCert(t *testing.T, opts certOptions) (certPEM, keyPEM []byte) {
	t.Helper()

	if opts.commonName == "" {
		opts.commonName = "test.example.com"
	}
	if opts.dnsNames == nil {
		opts.dnsNames = []string{opts.commonName}
	}
	if opts.notBefore.IsZero() {
		opts.notBefore = time.Now().Add(-time.Hour)
	}
	if opts.notAfter.IsZero() {
		opts.notAfter = time.Now().Add(24 * time.Hour)
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		t.Fatalf("generate serial: %v", err)
	}

	template := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: opts.commonName},
		DNSNames:              opts.dnsNames,
		NotBefore:             opts.notBefore,
		NotAfter:              opts.notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
}

// certFixture is a certificate and key written to a temporary directory.
type certFixture struct {
	dir      string
	certFile string
	keyFile  string
}

// newFixture writes a fresh key pair into a temporary directory.
func newFixture(t *testing.T, opts certOptions) *certFixture {
	t.Helper()

	dir := t.TempDir()
	f := &certFixture{
		dir:      dir,
		certFile: filepath.Join(dir, "tls.crt"),
		keyFile:  filepath.Join(dir, "tls.key"),
	}
	f.write(t, opts)
	return f
}

// write replaces the fixture's material with a newly generated key pair and
// returns the certificate's SHA-256 fingerprint.
func (f *certFixture) write(t *testing.T, opts certOptions) {
	t.Helper()

	certPEM, keyPEM := generateCert(t, opts)
	writeFile(t, f.certFile, certPEM)
	writeFile(t, f.keyFile, keyPEM)
}

// writeRaw replaces the fixture's files with arbitrary bytes, simulating
// malformed or partially written material.
func (f *certFixture) writeRaw(t *testing.T, certContent, keyContent []byte) {
	t.Helper()
	writeFile(t, f.certFile, certContent)
	writeFile(t, f.keyFile, keyContent)
}

// setModTime backdates both files, so a test can prove that change detection
// does not depend on modification time.
func (f *certFixture) setModTime(t *testing.T, when time.Time) {
	t.Helper()
	for _, path := range []string{f.certFile, f.keyFile} {
		if err := os.Chtimes(path, when, when); err != nil {
			t.Fatalf("chtimes %s: %v", path, err)
		}
	}
}

func (f *certFixture) modTime(t *testing.T) time.Time {
	t.Helper()
	stat, err := os.Stat(f.certFile)
	if err != nil {
		t.Fatalf("stat %s: %v", f.certFile, err)
	}
	return stat.ModTime()
}

func (f *certFixture) remove(t *testing.T) {
	t.Helper()
	for _, path := range []string{f.certFile, f.keyFile} {
		if err := os.Remove(path); err != nil {
			t.Fatalf("remove %s: %v", path, err)
		}
	}
}

func writeFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// fingerprintOf returns the fingerprint the reloader currently serves.
func fingerprintOf(t *testing.T, r *Reloader) string {
	t.Helper()
	info, ok := r.CertificateInfo()
	if !ok {
		t.Fatal("no certificate published")
	}
	return info.Fingerprint
}
