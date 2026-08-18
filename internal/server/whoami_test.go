package server

import (
	"context"
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

	srv := newTestServer(t, serverCert, roots, clientCAs)

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

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}

		var report WhoamiReport
		if err := json.Unmarshal(body, &report); err != nil {
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

		// Decoding into WhoamiReport above proves the values round-trip
		// through whatever struct produced them - it cannot catch a renamed
		// json tag, because the same struct decodes its own output either
		// way. Decoding into a bare map instead checks the wire contract
		// itself: the exact key names an external, non-Go consumer depends
		// on.
		var wire map[string]any
		if err := json.Unmarshal(body, &wire); err != nil {
			t.Fatalf("decode body as map: %v", err)
		}
		if authenticated, ok := wire["authenticated"].(bool); !ok || !authenticated {
			t.Errorf(`wire["authenticated"] = %#v, want true`, wire["authenticated"])
		}
		clientWire, ok := wire["client"].(map[string]any)
		if !ok {
			t.Fatalf(`wire["client"] = %#v, want an object`, wire["client"])
		}
		for _, key := range []string{
			"subject", "issuer", "serial", "fingerprint_sha256", "expires_in_seconds", "chain",
			"dns_names", "uris", "email_addresses", "ip_addresses", "not_before", "not_after",
		} {
			if _, ok := clientWire[key]; !ok {
				t.Errorf("wire[\"client\"] is missing key %q: %v", key, clientWire)
			}
		}

		// testClientCertificate's leaf carries no DNS SANs, so dns_names is
		// exactly what emptyIfNil (whoami.go) turns from nil into []: this is
		// the field, on this wire body, where that contract is actually
		// exercised. Decoding into a map, as above, is what lets this tell []
		// apart from null - a struct with a []string field decodes either one
		// back to an empty slice, so asserting through WhoamiReport could not
		// catch a regression here.
		dnsNames, ok := clientWire["dns_names"].([]any)
		if !ok {
			t.Fatalf(`wire["client"]["dns_names"] = %#v, want a JSON array`, clientWire["dns_names"])
		}
		if len(dnsNames) != 0 {
			t.Errorf(`wire["client"]["dns_names"] = %v, want an empty array`, dnsNames)
		}

		// expires_in_seconds is derived at render time from deps.Now(), not
		// stored on Identity. testDeps pins Now to a fixed instant while the
		// certificate's NotAfter comes from the real clock, so the two are
		// computed independently here and compared exactly: a switch to
		// time.Now() in the handler would miss by the gap between testNow and
		// the real clock, which is unmistakably large rather than a rounding
		// difference.
		wantExpires := float64(int64(trustedClient.Leaf.NotAfter.Sub(testNow).Seconds()))
		if got := clientWire["expires_in_seconds"]; got != wantExpires {
			t.Errorf(`wire["client"]["expires_in_seconds"] = %v, want %v`, got, wantExpires)
		}

		// /whoami and /whoami.json are compact by contract - unlike /status,
		// see TestStatusJSON_IsIndented - so the only newline in the body is
		// the single trailing one writeCompactJSON appends. A future switch
		// back to json.MarshalIndent must fail this, not just look different.
		if got := strings.Count(string(body), "\n"); got != 1 {
			t.Errorf("body has %d newlines, want exactly 1 (compact JSON)\n%s", got, body)
		}
		if !strings.HasSuffix(string(body), "\n") {
			t.Errorf("body does not end with a newline\n%s", body)
		}
	})

	t.Run("trusted client certificate renders the human page", func(t *testing.T) {
		resp, err := tlsClient(roots, trustedClient).Get(srv.URL + "/whoami")
		if err != nil {
			t.Fatalf("GET /whoami returned %v, want no error", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if !strings.Contains(string(body), "test-client") {
			t.Errorf("human page does not mention the client subject\n%s", body)
		}
	})

	t.Run("Accept: application/json is honoured on the human path", func(t *testing.T) {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+"/whoami", nil)
		if err != nil {
			t.Fatalf("build request: %v", err)
		}
		req.Header.Set("Accept", "application/json")

		resp, err := tlsClient(roots, trustedClient).Do(req)
		if err != nil {
			t.Fatalf("GET /whoami returned %v, want no error", err)
		}
		defer resp.Body.Close()

		if resp.StatusCode != http.StatusOK {
			t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusOK)
		}

		var wire map[string]any
		if err := json.NewDecoder(resp.Body).Decode(&wire); err != nil {
			t.Fatalf("/whoami with Accept: application/json did not return JSON: %v", err)
		}
		if _, ok := wire["client"]; !ok {
			t.Errorf(`wire is missing "client": %v`, wire)
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

// TestWhoamiWithoutTrustStore proves the trust store, not the certificate,
// gates verification. The client presents the same valid certificate that
// TestWhoami's "trusted client certificate is reported" subtest gets a 200
// for - the only thing different here is that the server has no ClientCAs
// configured. If this dialled with no certificate instead, a 403 would be
// unsurprising and wouldn't say anything about ClientCAs at all.
func TestWhoamiWithoutTrustStore(t *testing.T) {
	serverCert, roots := testCertificate(t)
	_, client := testClientCertificate(t)

	srv := newTestServer(t, serverCert, roots, nil)

	resp, err := tlsClient(roots, client).Get(srv.URL + "/whoami")
	if err != nil {
		t.Fatalf("GET /whoami returned %v, want no error", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("status = %d, want %d", resp.StatusCode, http.StatusForbidden)
	}
}

// TestWhoamiJSON_RefusalIsExplicit fetches the refusal document itself,
// rather than only the success document (as TestWhoami's JSON subtest does)
// or the text refusal (as its "no client certificate is refused" subtest
// does). Without this, an `omitempty` added to WhoamiReport.Authenticated
// would drop the field from exactly this response and nothing would notice:
// the refusal JSON was never actually fetched by any test.
//
// It checks both routes that can produce this document - /whoami.json
// unconditionally, and /whoami when the caller explicitly asks for JSON -
// and, now that the output is compact, asserts the exact byte string as well
// as the decoded keys: a single-line body is stable enough to compare
// literally, which an indented one would not be.
func TestWhoamiJSON_RefusalIsExplicit(t *testing.T) {
	t.Parallel()

	// The literal string is contract: external suites match on it.
	const wantBody = `{"authenticated":false,"reason":"no client certificate presented"}` + "\n"

	tests := map[string]struct {
		target string
		accept string
	}{
		"whoami.json":             {target: "/whoami.json"},
		"whoami with Accept:json": {target: "/whoami", accept: "application/json"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, tc.target, nil)
			if tc.accept != "" {
				req.Header.Set("Accept", tc.accept)
			}
			rec := httptest.NewRecorder()
			routes(testDeps(healthyProvider())).ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
			}
			if got := rec.Body.String(); got != wantBody {
				t.Errorf("body = %q, want %q", got, wantBody)
			}

			var wire map[string]any
			if err := json.Unmarshal(rec.Body.Bytes(), &wire); err != nil {
				t.Fatalf("decode body: %v", err)
			}

			authenticated, ok := wire["authenticated"]
			if !ok {
				t.Fatal(`wire is missing "authenticated"`)
			}
			if authenticated != false {
				t.Errorf(`wire["authenticated"] = %#v, want false`, authenticated)
			}
			if got, want := wire["reason"], noClientCertificate; got != want {
				t.Errorf(`wire["reason"] = %#v, want %q`, got, want)
			}
		})
	}
}

// TestWhoami_CacheControl checks that every /whoami and /whoami.json
// response - authenticated and refused alike - carries Cache-Control:
// no-store. A refusal is as cacheable as a success to an intermediary, and a
// cached 403 served to a client that did present a certificate would be just
// as wrong as leaking one client's identity to another.
func TestWhoami_CacheControl(t *testing.T) {
	t.Parallel()

	serverCert, roots := testCertificate(t)
	clientCAs, trustedClient := testClientCertificate(t)
	srv := newTestServer(t, serverCert, roots, clientCAs)

	tests := map[string]struct {
		client *tls.Certificate
		target string
		accept string
	}{
		"whoami.json authenticated":        {client: trustedClient, target: "/whoami.json"},
		"whoami.json refusal":              {client: nil, target: "/whoami.json"},
		"whoami text authenticated":        {client: trustedClient, target: "/whoami"},
		"whoami text refusal":              {client: nil, target: "/whoami"},
		"whoami Accept:json authenticated": {client: trustedClient, target: "/whoami", accept: "application/json"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, srv.URL+tc.target, nil)
			if err != nil {
				t.Fatalf("build request: %v", err)
			}
			if tc.accept != "" {
				req.Header.Set("Accept", tc.accept)
			}

			resp, err := tlsClient(roots, tc.client).Do(req)
			if err != nil {
				t.Fatalf("GET %s returned %v, want no error", tc.target, err)
			}
			defer resp.Body.Close()

			if got := resp.Header.Get("Cache-Control"); got != "no-store" {
				t.Errorf("Cache-Control = %q, want %q", got, "no-store")
			}
		})
	}
}

// TestWhoami_VaryAccept checks that /whoami, which changes representation
// based on Accept (see prefersJSON), advertises that to caches - and that
// /whoami.json, which has exactly one representation, does not.
func TestWhoami_VaryAccept(t *testing.T) {
	t.Parallel()

	serverCert, roots := testCertificate(t)
	clientCAs, trustedClient := testClientCertificate(t)
	srv := newTestServer(t, serverCert, roots, clientCAs)

	tests := map[string]struct {
		target   string
		wantVary bool
	}{
		"whoami":      {target: "/whoami", wantVary: true},
		"whoami.json": {target: "/whoami.json", wantVary: false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			resp, err := tlsClient(roots, trustedClient).Get(srv.URL + tc.target)
			if err != nil {
				t.Fatalf("GET %s returned %v, want no error", tc.target, err)
			}
			defer resp.Body.Close()

			got := resp.Header.Get("Vary")
			if tc.wantVary && got != "Accept" {
				t.Errorf("Vary = %q, want %q", got, "Accept")
			}
			if !tc.wantVary && got != "" {
				t.Errorf("Vary = %q, want unset", got)
			}
		})
	}
}

// TestRootShowsSNIAndVerifiedClient checks the two consistency changes to
// handleRoot: SNI is a property of every TLS request and must show up even
// without a client certificate, and the client identity it does report comes
// from clientauth.IdentityFrom rather than an unverified peer certificate.
func TestRootShowsSNIAndVerifiedClient(t *testing.T) {
	serverCert, roots := testCertificate(t)
	clientCAs, trustedClient := testClientCertificate(t)
	srv := newTestServer(t, serverCert, roots, clientCAs)

	t.Run("SNI is shown without a client certificate", func(t *testing.T) {
		resp, err := tlsClient(roots, nil).Get(srv.URL + "/")
		if err != nil {
			t.Fatalf("GET / returned %v, want no error", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if !strings.Contains(string(body), "SNI:") {
			t.Errorf("body did not mention SNI; got:\n%s", body)
		}
		if strings.Contains(string(body), "Client Certificate") {
			t.Errorf("body reported a client certificate when none was sent; got:\n%s", body)
		}
	})

	t.Run("a verified client certificate is shown", func(t *testing.T) {
		resp, err := tlsClient(roots, trustedClient).Get(srv.URL + "/")
		if err != nil {
			t.Fatalf("GET / returned %v, want no error", err)
		}
		defer resp.Body.Close()

		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatalf("read body: %v", err)
		}
		if !strings.Contains(string(body), "test-client") {
			t.Errorf("body did not report the client subject; got:\n%s", body)
		}
	})
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

// testServer is the minimal handle callers need from newTestServer.
type testServer struct {
	URL string
}

// newTestServer starts a real listener through New() itself, the same
// constructor production uses, rather than a hand-rolled tls.Config that
// copies New's policy. A hand-rolled copy can drift from what New actually
// does and silently stop guarding the risk these tests exist for - e.g. it
// would keep passing even if New started requiring client certificates,
// because the copy, not New, is what decided ClientAuth. Going through New
// means these tests fail the moment New's behaviour changes.
func newTestServer(t *testing.T, serverCert *tls.Certificate, roots *x509.CertPool, clientCAs *x509.CertPool) *testServer {
	t.Helper()

	deps := testDeps(healthyProvider())
	deps.ClientCAs = clientCAs

	srv, err := New(reserveLocalAddr(t), 5*time.Second,
		func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return serverCert, nil },
		deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	ctx, cancel := context.WithCancel(t.Context())
	done := make(chan error, 1)
	go func() { done <- srv.Run(ctx) }()
	t.Cleanup(func() {
		cancel()
		if err := <-done; err != nil {
			t.Errorf("Run returned %v, want nil on shutdown", err)
		}
	})

	url := "https://" + srv.http.Addr

	// The readiness probe never presents a client certificate: whether the
	// listener accepts that is exactly what these tests are here to check,
	// so the probe must not beg the question by trusting clientCAs is unset.
	if err := waitForOK(tlsClient(roots, nil), url+"/livez", 5*time.Second); err != nil {
		t.Fatalf("server did not become reachable: %v", err)
	}

	return &testServer{URL: url}
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
