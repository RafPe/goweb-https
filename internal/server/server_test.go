package server

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"io"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/RafPe/goweb-https/internal/certreload"
)

func quietLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// stubProvider is a hand-written double for the consumer-owned interface. The
// interface has two methods, so a mocking framework would cost more than it saves.
type stubProvider struct {
	info      certreload.Info
	available bool
	readyErr  error
}

func (s stubProvider) CertificateInfo() (certreload.Info, bool) { return s.info, s.available }
func (s stubProvider) Ready() error                             { return s.readyErr }

var testNow = time.Date(2026, 8, 17, 12, 0, 0, 0, time.UTC)

func testDeps(provider CertificateStatusProvider) Dependencies {
	return Dependencies{
		Certificates: provider,
		Logger:       quietLogger(),
		Now:          func() time.Time { return testNow },
		Location:     time.UTC,
		Hostname:     "test-host",
		PodName:      "goweb-0",
		PodNamespace: "demo",
		StartedAt:    testNow.Add(-90 * time.Second),
	}
}

func healthyProvider() stubProvider {
	return stubProvider{
		available: true,
		info: certreload.Info{
			Subject:     "CN=demo.example.com",
			Issuer:      "CN=demo.example.com",
			Serial:      "12345",
			DNSNames:    []string{"demo.example.com"},
			URIs:        []string{"spiffe://cluster.local/ns/demo/sa/goweb"},
			NotBefore:   testNow.Add(-time.Hour),
			NotAfter:    testNow.Add(72 * time.Hour),
			FilePath:    "/tls/tls.crt",
			LoadedAt:    testNow.Add(-time.Minute),
			Fingerprint: "abc123",
		},
	}
}

func do(t *testing.T, handler http.Handler, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(method, target, nil))
	return rec
}

func TestRoutes(t *testing.T) {
	t.Parallel()

	handler := routes(testDeps(healthyProvider()))

	tests := map[string]struct {
		method     string
		target     string
		wantStatus int
	}{
		"root":                {method: http.MethodGet, target: "/", wantStatus: http.StatusOK},
		"status":              {method: http.MethodGet, target: "/status", wantStatus: http.StatusOK},
		"status json":         {method: http.MethodGet, target: "/status.json", wantStatus: http.StatusOK},
		"livez":               {method: http.MethodGet, target: "/livez", wantStatus: http.StatusOK},
		"readyz":              {method: http.MethodGet, target: "/readyz", wantStatus: http.StatusOK},
		"unknown path":        {method: http.MethodGet, target: "/nope", wantStatus: http.StatusNotFound},
		"subpath of root":     {method: http.MethodGet, target: "/anything/here", wantStatus: http.StatusNotFound},
		"wrong method root":   {method: http.MethodPost, target: "/", wantStatus: http.StatusMethodNotAllowed},
		"wrong method status": {method: http.MethodDelete, target: "/status", wantStatus: http.StatusMethodNotAllowed},
		// Go's ServeMux matches HEAD on a GET pattern, which keeps header-only
		// health checks working.
		"head on status": {method: http.MethodHead, target: "/status", wantStatus: http.StatusOK},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rec := do(t, handler, tc.method, tc.target)
			if rec.Code != tc.wantStatus {
				t.Errorf("%s %s = %d, want %d", tc.method, tc.target, rec.Code, tc.wantStatus)
			}
		})
	}
}

func TestHandleStatus_RendersCertificateDetail(t *testing.T) {
	t.Parallel()

	rec := do(t, routes(testDeps(healthyProvider())), http.MethodGet, "/status")
	body := rec.Body.String()

	for _, want := range []string{
		"demo.example.com",
		"spiffe://cluster.local/ns/demo/sa/goweb",
		"abc123",
		"goweb-0",
		"Uptime: 1m30s",
		"✅ Valid",
		"Readiness: ✅ ready",
	} {
		if !strings.Contains(body, want) {
			t.Errorf("status body does not contain %q\n%s", want, body)
		}
	}
}

// TestHandleStatus_ReportsExpiredCertificate covers the case the previous design
// could not reach: an expired certificate must be reported, not hidden behind a
// startup failure.
func TestHandleStatus_ReportsExpiredCertificate(t *testing.T) {
	t.Parallel()

	provider := healthyProvider()
	provider.info.NotBefore = testNow.Add(-72 * time.Hour)
	provider.info.NotAfter = testNow.Add(-2 * time.Hour)
	provider.readyErr = errors.New("certificate expired 2h0m0s ago")

	rec := do(t, routes(testDeps(provider)), http.MethodGet, "/status")
	body := rec.Body.String()

	if rec.Code != http.StatusOK {
		t.Errorf("status code = %d, want 200: diagnostics stay reachable", rec.Code)
	}
	if !strings.Contains(body, "❌ EXPIRED (expired 2h0m0s ago)") {
		t.Errorf("status body does not report expiry\n%s", body)
	}
	if !strings.Contains(body, "Readiness: ❌") {
		t.Errorf("status body does not report the readiness failure\n%s", body)
	}
}

func TestHandleStatus_ValidityStates(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		notBefore time.Time
		notAfter  time.Time
		want      string
	}{
		"valid":         {notBefore: testNow.Add(-time.Hour), notAfter: testNow.Add(48 * time.Hour), want: "✅ Valid"},
		"expiring soon": {notBefore: testNow.Add(-time.Hour), notAfter: testNow.Add(5 * time.Minute), want: "⚠️  EXPIRES SOON"},
		"expired":       {notBefore: testNow.Add(-time.Hour), notAfter: testNow.Add(-time.Minute), want: "❌ EXPIRED"},
		"not yet valid": {notBefore: testNow.Add(time.Hour), notAfter: testNow.Add(48 * time.Hour), want: "⏳ NOT YET VALID"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			provider := healthyProvider()
			provider.info.NotBefore = tc.notBefore
			provider.info.NotAfter = tc.notAfter

			rec := do(t, routes(testDeps(provider)), http.MethodGet, "/status")
			if !strings.Contains(rec.Body.String(), tc.want) {
				t.Errorf("status body does not contain %q\n%s", tc.want, rec.Body.String())
			}
		})
	}
}

func TestHandleStatus_MarksProxyHeadersUnverified(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	req.Header.Set("X-Forwarded-For", "203.0.113.9")
	rec := httptest.NewRecorder()
	routes(testDeps(healthyProvider())).ServeHTTP(rec, req)

	body := rec.Body.String()
	if !strings.Contains(body, "X-Forwarded-For (unverified): 203.0.113.9") {
		t.Errorf("client-supplied header is not marked unverified\n%s", body)
	}
}

func TestHandleStatus_NoCertificate(t *testing.T) {
	t.Parallel()

	rec := do(t, routes(testDeps(stubProvider{readyErr: certreload.ErrCertificateUnavailable})), http.MethodGet, "/status")
	if rec.Code != http.StatusOK {
		t.Errorf("status code = %d, want 200", rec.Code)
	}
	if !strings.Contains(rec.Body.String(), "No certificate is currently available") {
		t.Errorf("unexpected body\n%s", rec.Body.String())
	}
}

func TestHandleReady(t *testing.T) {
	t.Parallel()

	t.Run("ready", func(t *testing.T) {
		t.Parallel()
		rec := do(t, routes(testDeps(healthyProvider())), http.MethodGet, "/readyz")
		if rec.Code != http.StatusOK {
			t.Errorf("status = %d, want 200", rec.Code)
		}
	})

	t.Run("not ready", func(t *testing.T) {
		t.Parallel()
		provider := healthyProvider()
		provider.readyErr = errors.New("certificate source unreadable for 20m0s")

		rec := do(t, routes(testDeps(provider)), http.MethodGet, "/readyz")
		if rec.Code != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want 503", rec.Code)
		}
		if !strings.Contains(rec.Body.String(), "certificate source unreadable") {
			t.Errorf("body does not explain the failure\n%s", rec.Body.String())
		}
	})
}

// TestHandleLive_IndependentOfCertificate documents the probe split: a
// certificate problem must not restart the process, so liveness stays green.
func TestHandleLive_IndependentOfCertificate(t *testing.T) {
	t.Parallel()

	rec := do(t, routes(testDeps(stubProvider{readyErr: errors.New("no certificate")})), http.MethodGet, "/livez")
	if rec.Code != http.StatusOK {
		t.Errorf("liveness = %d, want 200 even without a usable certificate", rec.Code)
	}
}

func TestNew_Validation(t *testing.T) {
	t.Parallel()

	getCert := func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return nil, nil }

	tests := map[string]struct {
		provider CertificateStatusProvider
		getCert  func(*tls.ClientHelloInfo) (*tls.Certificate, error)
		timeout  time.Duration
	}{
		"missing provider":     {provider: nil, getCert: getCert, timeout: time.Second},
		"missing callback":     {provider: healthyProvider(), getCert: nil, timeout: time.Second},
		"non-positive timeout": {provider: healthyProvider(), getCert: getCert, timeout: 0},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := New(":0", tc.timeout, tc.getCert, Dependencies{Certificates: tc.provider, Logger: quietLogger()})
			if err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

// TestServerRun_GracefulShutdown exercises the real listener: it serves a
// request over TLS, then verifies that cancellation drains and returns cleanly.
func TestServerRun_GracefulShutdown(t *testing.T) {
	t.Parallel()

	cert, roots := testCertificate(t)
	srv, err := New(reserveLocalAddr(t), 5*time.Second,
		func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert, nil },
		testDeps(healthyProvider()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()

	// The test CA is trusted explicitly rather than skipping verification, so
	// the handshake this test exercises is a real one.
	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{
			RootCAs:    roots,
			MinVersion: tls.VersionTLS13,
		}},
		Timeout: 5 * time.Second,
	}
	url := "https://" + srv.http.Addr + "/livez"

	if err := waitForOK(client, url, 5*time.Second); err != nil {
		t.Fatalf("server did not become reachable: %v", err)
	}

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Run returned %v, want nil on graceful shutdown", err)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("Run did not return after cancellation")
	}
}

// TestServerRun_ReportsListenFailure verifies a serving failure is returned
// rather than logged and swallowed.
func TestServerRun_ReportsListenFailure(t *testing.T) {
	t.Parallel()

	cert, _ := testCertificate(t)
	// Port 1 is privileged and will not bind in the test environment.
	srv, err := New("127.0.0.1:1", time.Second,
		func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert, nil },
		testDeps(healthyProvider()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	if err := srv.Run(t.Context()); err == nil {
		t.Fatal("expected Run to report the listen failure")
	}
}

func waitForOK(client *http.Client, url string, within time.Duration) error {
	deadline := time.Now().Add(within)
	var lastErr error
	for time.Now().Before(deadline) {
		resp, err := client.Get(url)
		if err == nil {
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			lastErr = errors.New(resp.Status)
		} else {
			lastErr = err
		}
		time.Sleep(20 * time.Millisecond)
	}
	return lastErr
}

// reserveLocalAddr returns a loopback address that was free a moment ago.
func reserveLocalAddr(t *testing.T) string {
	t.Helper()

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserve port: %v", err)
	}
	addr := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatalf("release reserved port: %v", err)
	}
	return addr
}

// testCertificate issues a serverAuth leaf from a throwaway CA and returns the
// leaf together with a pool trusting that CA.
//
// A real chain is generated rather than a self-signed leaf so the test client
// can verify the handshake properly instead of disabling verification.
func testCertificate(t *testing.T) (*tls.Certificate, *x509.CertPool) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}
	caTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "goweb test ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
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
		Subject:               pkix.Name{CommonName: "localhost"},
		DNSNames:              []string{"localhost"},
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
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

	roots := x509.NewCertPool()
	roots.AddCert(ca)

	return &tls.Certificate{
		Certificate: [][]byte{leafDER, caDER},
		PrivateKey:  leafKey,
		Leaf:        leaf,
	}, roots
}

// errNotReady is a stand-in readiness failure used across the status tests.
var errNotReady = errors.New("no certificate available")
