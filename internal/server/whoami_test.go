package server

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestWhoami(t *testing.T) {
	serverCert, roots := testCertificate(t)
	clientCAs, trustedClient := testClientCertificate(t)
	_, untrustedClient := testClientCertificate(t)

	srv := newTestServer(t, serverCert, clientCAs)

	t.Run("trusted client certificate is reported", func(t *testing.T) {
		client := tlsClient(roots, trustedClient)

		resp, err := client.Get(srv.URL + "/whoami.json")
		if err != nil {
			t.Fatalf("GET /whoami.json returned %v, want no error", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}

		var report WhoamiReport
		if err := json.NewDecoder(resp.Body).Decode(&report); err != nil {
			t.Fatalf("decode body: %v", err)
		}
		if !report.Authenticated {
			t.Error("authenticated = false, want true")
		}
		if report.Client == nil {
			t.Fatal("client = null, want the verified identity")
		}
		if !strings.Contains(report.Client.Subject, "test-client") {
			t.Errorf("Subject = %q, want it to contain %q", report.Client.Subject, "test-client")
		}
		if len(report.Client.Chain) < 2 {
			t.Errorf("Chain = %v, want the leaf and its issuer", report.Client.Chain)
		}
	})

	t.Run("no client certificate is refused", func(t *testing.T) {
		client := tlsClient(roots, nil)

		resp, err := client.Get(srv.URL + "/whoami")
		if err != nil {
			t.Fatalf("GET /whoami returned %v, want no error", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusForbidden {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		// The literal string is contract: external suites match on it.
		if got, want := string(body), "no client certificate presented\n"; got != want {
			t.Errorf("body = %q, want %q", got, want)
		}
	})

	// An untrusted certificate is rejected during the handshake and never
	// reaches HTTP, so there is no status code to assert. Under TLS 1.3 the
	// client learns of it on its first read rather than from Handshake, so
	// this asserts only that no successful response comes back - not any
	// particular error string.
	t.Run("untrusted client certificate never reaches HTTP", func(t *testing.T) {
		client := tlsClient(roots, untrustedClient)

		resp, err := client.Get(srv.URL + "/whoami")
		if err == nil {
			defer resp.Body.Close()
			t.Fatalf("GET /whoami succeeded with status %d, want a connection failure", resp.StatusCode)
		}
	})
}

func TestWhoamiWithoutTrustStore(t *testing.T) {
	serverCert, roots := testCertificate(t)
	srv := newTestServer(t, serverCert, nil)

	client := tlsClient(roots, nil)
	resp, err := client.Get(srv.URL + "/whoami")
	if err != nil {
		t.Fatalf("GET /whoami returned %v, want no error", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

// testClientCertificate issues a clientAuth leaf, "test-client", from a
// throwaway CA distinct from the server's, and returns a pool trusting that
// CA together with the leaf.
//
// Keys are ECDSA P-256 rather than RSA: this suite runs under -race, and
// RSA-2048 keygen is slow enough to be felt there.
func testClientCertificate(t *testing.T) (*x509.CertPool, *tls.Certificate) {
	t.Helper()

	// Each call gets its own CA subject. TestWhoami mints two CAs - trusted
	// and untrusted - and a shared subject would make the two chains
	// indistinguishable in failure output, hiding a false negative in the
	// untrusted-certificate subtest behind identical-looking names.
	suffix := make([]byte, 4)
	if _, err := rand.Read(suffix); err != nil {
		t.Fatalf("generate ca subject suffix: %v", err)
	}

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}
	caTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "goweb test client ca " + hex.EncodeToString(suffix)},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create ca certificate: %v", err)
	}
	ca, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca certificate: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "test-client"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, &leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf certificate: %v", err)
	}

	pool := x509.NewCertPool()
	pool.AddCert(ca)

	return pool, &tls.Certificate{
		// The chain is sent complete - leaf then issuer - so the server does
		// not need the CA to be delivered out of band to build the chain.
		Certificate: [][]byte{leafDER, caDER},
		PrivateKey:  leafKey,
		Leaf:        leaf,
	}
}

// newTestServer starts a real TLS listener serving routes(deps), configured
// with the same client-auth policy New applies - the only way to prove the
// client-certificate wiring works end to end.
//
// serverCert is set on Certificates rather than GetCertificate. Production
// uses GetCertificate because tls.Config prefers it whenever the client sends
// SNI, but this test dials a loopback IP literal, which never carries SNI -
// crypto/tls would then fall through to Certificates, and httptest.StartTLS
// additionally replaces an empty Certificates slice with its own throwaway
// cert, serving neither our certificate nor triggering the callback. Setting
// Certificates directly sidesteps both.
func newTestServer(t *testing.T, serverCert *tls.Certificate, clientCAs *x509.CertPool) *httptest.Server {
	t.Helper()

	deps := testDeps(healthyProvider())
	deps.ClientCAs = clientCAs

	srv := httptest.NewUnstartedServer(routes(deps))
	srv.TLS = &tls.Config{
		Certificates: []tls.Certificate{*serverCert},
		MinVersion:   tls.VersionTLS13,
	}
	if clientCAs != nil {
		srv.TLS.ClientAuth = tls.VerifyClientCertIfGiven
		srv.TLS.ClientCAs = clientCAs
	}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	return srv
}

// tlsClient builds an http.Client that trusts roots and, when cert is
// non-nil, presents it during the handshake.
func tlsClient(roots *x509.CertPool, cert *tls.Certificate) *http.Client {
	tlsConfig := &tls.Config{
		RootCAs:    roots,
		MinVersion: tls.VersionTLS13,
	}
	if cert != nil {
		// GetClientCertificate, not Certificates: given Certificates, Go's TLS
		// client matches entries against the CAs the server advertised in its
		// CertificateRequest and silently sends no certificate at all when
		// none match. That would make the untrusted-certificate test dial with
		// no certificate rather than a rejected one, silently degrading it into
		// a duplicate of the no-certificate case. GetClientCertificate bypasses
		// that matching and always sends the certificate given here.
		tlsConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
			return cert, nil
		}
	}

	return &http.Client{
		Transport: &http.Transport{TLSClientConfig: tlsConfig},
		Timeout:   5 * time.Second,
	}
}
