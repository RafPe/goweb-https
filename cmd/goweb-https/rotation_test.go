package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"
)

// authority is a throwaway CA together with the material it issues.
type authority struct {
	certPEM []byte
	cert    *x509.Certificate
	key     *ecdsa.PrivateKey
}

// newAuthority creates a self-signed CA that satisfies every check
// clientauth.LoadTrustStore makes.
func newAuthority(t *testing.T, commonName string) *authority {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}
	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create ca certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse ca certificate: %v", err)
	}

	return &authority{
		certPEM: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		cert:    cert,
		key:     key,
	}
}

// issue returns a leaf certificate signed by the authority.
func (a *authority) issue(t *testing.T, template x509.Certificate) *tls.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, a.cert, &key.PublicKey, a.key)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse leaf certificate: %v", err)
	}

	return &tls.Certificate{
		// The chain is sent complete - leaf then issuer - so the server does
		// not need the CA delivered out of band to build the chain.
		Certificate: [][]byte{der, a.cert.Raw},
		PrivateKey:  key,
		Leaf:        leaf,
	}
}

// clientCertificate issues a clientAuth leaf.
func (a *authority) clientCertificate(t *testing.T, commonName string) *tls.Certificate {
	t.Helper()

	return a.issue(t, x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	})
}

// writeServingMaterial issues a serverAuth leaf for 127.0.0.1 and writes the
// PEM key pair into dir.
func writeServingMaterial(t *testing.T, dir string, ca *authority) (certFile, keyFile string) {
	t.Helper()

	pair := ca.issue(t, x509.Certificate{
		SerialNumber:          big.NewInt(3),
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	})

	keyDER, err := x509.MarshalPKCS8PrivateKey(pair.PrivateKey)
	if err != nil {
		t.Fatalf("marshal serving key: %v", err)
	}

	certFile = filepath.Join(dir, "tls.crt")
	keyFile = filepath.Join(dir, "tls.key")
	writeTestFile(t, certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: pair.Certificate[0]}))
	writeTestFile(t, keyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	return certFile, keyFile
}

func writeTestFile(t *testing.T, path string, content []byte) {
	t.Helper()
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
}

// projectedBundle lays a client CA bundle out the way a Kubernetes projected
// volume does: the configured path is a symlink into a `..data` directory,
// which rotation replaces by an atomic rename.
//
// The layout matters. Events name `..data` and never the bundle, so a watch
// registered on the file itself would see nothing - and the atomicity is what
// makes it safe to act on a smaller bundle immediately, because no reader can
// observe a half-written one.
type projectedBundle struct {
	root       string
	path       string
	generation int
}

func newProjectedBundle(t *testing.T, cas ...*authority) *projectedBundle {
	t.Helper()

	b := &projectedBundle{root: t.TempDir()}
	b.path = filepath.Join(b.root, "client-ca.pem")

	data := b.writeGeneration(t, cas...)
	symlinkTest(t, data, filepath.Join(b.root, "..data"))
	symlinkTest(t, filepath.Join(b.root, "..data", "client-ca.pem"), b.path)
	return b
}

// writeGeneration writes a new timestamped directory holding the bundle.
func (b *projectedBundle) writeGeneration(t *testing.T, cas ...*authority) string {
	t.Helper()

	b.generation++
	dir := filepath.Join(b.root, "..data_"+strconv.Itoa(b.generation))
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}

	var content []byte
	for _, ca := range cas {
		content = append(content, ca.certPEM...)
	}
	writeTestFile(t, filepath.Join(dir, "client-ca.pem"), content)
	return dir
}

// rotate replaces the bundle by the atomic symlink swap Kubernetes performs.
func (b *projectedBundle) rotate(t *testing.T, cas ...*authority) {
	t.Helper()

	dir := b.writeGeneration(t, cas...)
	staging := filepath.Join(b.root, "..data_tmp")
	symlinkTest(t, dir, staging)
	if err := os.Rename(staging, filepath.Join(b.root, "..data")); err != nil {
		t.Fatalf("rename %s: %v", staging, err)
	}
}

func symlinkTest(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		t.Fatalf("symlink %s -> %s: %v", link, target, err)
	}
}

// reservePort returns a port that was free a moment ago.
func reservePort(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	defer func() { _ = listener.Close() }()

	_, port, err := net.SplitHostPort(listener.Addr().String())
	if err != nil {
		t.Fatalf("split %s: %v", listener.Addr(), err)
	}
	return port
}

// TestRotatingTheTrustBundleTakesEffectEndToEnd is the proof that the feature
// does what it was asked to do.
//
// It exercises the assembled application - run() itself, the same function
// main() calls, with configuration supplied the only way production supplies it
// - rather than a hand-wired stack that could differ from what run() actually
// builds. A client whose CA is not in the bundle is refused, the bundle is
// rotated by the projected-volume symlink swap, and the same client is then
// accepted over a fresh handshake, with no restart in between.
func TestRotatingTheTrustBundleTakesEffectEndToEnd(t *testing.T) {
	serving := newAuthority(t, "e2e serving ca")
	certFile, keyFile := writeServingMaterial(t, t.TempDir(), serving)

	roots := x509.NewCertPool()
	roots.AddCert(serving.cert)

	original := newAuthority(t, "e2e original client ca")
	added := newAuthority(t, "e2e added client ca")
	bundle := newProjectedBundle(t, original)

	port := reservePort(t)
	t.Setenv("GOWEB_PORT", port)
	t.Setenv("GOWEB_X509_CER", certFile)
	t.Setenv("GOWEB_X509_KEY", keyFile)
	t.Setenv("GOWEB_MTLS_CLIENT_CA", bundle.path)
	t.Setenv("GOWEB_RELOAD_DEBOUNCE", "20ms")
	// Far longer than the test: the rotation must be picked up from the
	// filesystem event, not from a periodic pass that would pass anyway.
	t.Setenv("GOWEB_RELOAD_INTERVAL", "1h")
	t.Setenv("GOWEB_SHUTDOWN_TIMEOUT", "2s")

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- run(ctx) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("run returned %v, want nil on cancellation", err)
			}
		case <-time.After(10 * time.Second):
			t.Error("run did not return within 10s of cancellation")
		}
	})

	url := "https://127.0.0.1:" + port

	// Each call builds its own client so that every assertion is made over a
	// new handshake rather than a connection pooled from the previous pool.
	get := func(t *testing.T, path string, cert *tls.Certificate) (*http.Response, error) {
		t.Helper()

		tlsConfig := &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}
		if cert != nil {
			// GetClientCertificate rather than Certificates: given Certificates,
			// Go's client silently sends nothing when the certificate matches
			// none of the CAs the server advertised, which would turn the
			// untrusted case into the no-certificate case.
			tlsConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
				return cert, nil
			}
		}
		client := &http.Client{
			Transport: &http.Transport{TLSClientConfig: tlsConfig},
			Timeout:   5 * time.Second,
		}
		return client.Get(url + path)
	}

	waitFor(t, func() bool {
		resp, err := get(t, "/livez", nil)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, "server to become reachable")

	originalClient := original.clientCertificate(t, "original-client")
	newClient := added.clientCertificate(t, "new-client")

	// Before the rotation the new client's CA is not in the bundle.
	if resp, err := get(t, "/whoami", newClient); err == nil {
		resp.Body.Close()
		t.Fatal("a client issued by an untrusted CA completed a handshake before the rotation")
	}

	bundle.rotate(t, original, added)

	waitFor(t, func() bool {
		resp, err := get(t, "/whoami", newClient)
		if err != nil {
			return false
		}
		defer resp.Body.Close()
		return resp.StatusCode == http.StatusOK
	}, "the rotated trust bundle to take effect")

	// The CA that survived the rotation is still trusted.
	resp, err := get(t, "/whoami", originalClient)
	if err != nil {
		t.Fatalf("original client: %v, want it still accepted after the rotation", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Errorf("original client: status = %d, want %d", resp.StatusCode, http.StatusOK)
	}

	// /status.json is how an external suite observes the same thing without
	// having to own a client certificate.
	assertStatusAnchors(t, get, []string{"CN=e2e original client ca", "CN=e2e added client ca"})
}

// assertStatusAnchors checks that the trust_bundle block names exactly the
// expected CAs, each with a fingerprint.
func assertStatusAnchors(t *testing.T, get func(*testing.T, string, *tls.Certificate) (*http.Response, error), want []string) {
	t.Helper()

	resp, err := get(t, "/status.json", nil)
	if err != nil {
		t.Fatalf("GET /status.json: %v", err)
	}
	defer resp.Body.Close()

	var document struct {
		TrustBundle *struct {
			FilePath string `json:"file_path"`
			Anchors  []struct {
				Subject           string `json:"subject"`
				FingerprintSHA256 string `json:"fingerprint_sha256"`
			} `json:"anchors"`
			LastError string `json:"last_error"`
		} `json:"trust_bundle"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&document); err != nil {
		t.Fatalf("decode /status.json: %v", err)
	}

	if document.TrustBundle == nil {
		t.Fatal("trust_bundle is absent while client verification is enabled")
	}
	if document.TrustBundle.LastError != "" {
		t.Errorf("last_error = %q, want empty after a successful rotation", document.TrustBundle.LastError)
	}
	if len(document.TrustBundle.Anchors) != len(want) {
		t.Fatalf("anchors = %d, want %d", len(document.TrustBundle.Anchors), len(want))
	}
	for i, anchor := range document.TrustBundle.Anchors {
		if anchor.Subject != want[i] {
			t.Errorf("anchor %d subject = %q, want %q", i, anchor.Subject, want[i])
		}
		if anchor.FingerprintSHA256 == "" {
			t.Errorf("anchor %d has no fingerprint; a rotation reusing the subject would be invisible", i)
		}
	}
}
