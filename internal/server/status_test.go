package server

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// decodeStatus issues a request and decodes the JSON body.
func decodeStatus(t *testing.T, handler http.Handler, target string, accept string) StatusReport {
	t.Helper()

	req := httptest.NewRequest(http.MethodGet, target, nil)
	if accept != "" {
		req.Header.Set("Accept", accept)
	}
	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", rec.Code)
	}
	if got := rec.Header().Get("Content-Type"); got != "application/json; charset=utf-8" {
		t.Errorf("content type = %q, want application/json; charset=utf-8", got)
	}

	var report StatusReport
	if err := json.Unmarshal(rec.Body.Bytes(), &report); err != nil {
		t.Fatalf("decode body: %v\n%s", err, rec.Body.String())
	}
	return report
}

func TestStatusJSON_Fields(t *testing.T) {
	t.Parallel()

	report := decodeStatus(t, routes(testDeps(healthyProvider())), "/status.json", "")

	if report.Server.Hostname != "test-host" {
		t.Errorf("hostname = %q, want test-host", report.Server.Hostname)
	}
	if report.Server.UptimeSeconds != 90 {
		t.Errorf("uptime = %d, want 90", report.Server.UptimeSeconds)
	}
	if report.Server.PodName != "goweb-0" || report.Server.PodNamespace != "demo" {
		t.Errorf("pod identity = %q/%q", report.Server.PodName, report.Server.PodNamespace)
	}

	cert := report.Certificate
	if cert == nil {
		t.Fatal("certificate is null, want a certificate")
	}
	if cert.Subject != "CN=demo.example.com" {
		t.Errorf("subject = %q", cert.Subject)
	}
	if cert.FingerprintSHA256 != "abc123" {
		t.Errorf("fingerprint = %q", cert.FingerprintSHA256)
	}
	if cert.Validity != "valid" {
		t.Errorf("validity = %q, want valid", cert.Validity)
	}
	// The stub certificate expires 72h after the frozen clock.
	if want := int64((72 * time.Hour).Seconds()); cert.ExpiresInSeconds != want {
		t.Errorf("expires_in_seconds = %d, want %d", cert.ExpiresInSeconds, want)
	}
	if len(cert.URIs) != 1 || cert.URIs[0] != "spiffe://cluster.local/ns/demo/sa/goweb" {
		t.Errorf("uris = %v", cert.URIs)
	}
	if !report.Readiness.Ready || report.Readiness.Reason != "" {
		t.Errorf("readiness = %+v, want ready", report.Readiness)
	}
}

// TestStatusJSON_IsPlain guards the machine-readable contract: no emoji, and no
// human prose that a parser would have to strip.
func TestStatusJSON_IsPlain(t *testing.T) {
	t.Parallel()

	req := httptest.NewRequest(http.MethodGet, "/status.json", nil)
	rec := httptest.NewRecorder()
	routes(testDeps(healthyProvider())).ServeHTTP(rec, req)

	body := rec.Body.String()
	for _, forbidden := range []string{"🖥️", "📜", "✅", "❌", "⚠️", "⏳", "Certificate Status", "Readiness:"} {
		if strings.Contains(body, forbidden) {
			t.Errorf("json body contains presentation text %q\n%s", forbidden, body)
		}
	}
}

func TestStatusJSON_ValidityStates(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		notBefore    time.Time
		notAfter     time.Time
		wantValidity string
		wantNegative bool
	}{
		"valid":         {notBefore: testNow.Add(-time.Hour), notAfter: testNow.Add(48 * time.Hour), wantValidity: "valid"},
		"expiring soon": {notBefore: testNow.Add(-time.Hour), notAfter: testNow.Add(5 * time.Minute), wantValidity: "valid"},
		"expired":       {notBefore: testNow.Add(-time.Hour), notAfter: testNow.Add(-time.Minute), wantValidity: "expired", wantNegative: true},
		"not yet valid": {notBefore: testNow.Add(time.Hour), notAfter: testNow.Add(48 * time.Hour), wantValidity: "not_yet_valid"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			provider := healthyProvider()
			provider.info.NotBefore = tc.notBefore
			provider.info.NotAfter = tc.notAfter

			report := decodeStatus(t, routes(testDeps(provider)), "/status.json", "")
			if report.Certificate.Validity != tc.wantValidity {
				t.Errorf("validity = %q, want %q", report.Certificate.Validity, tc.wantValidity)
			}
			if got := report.Certificate.ExpiresInSeconds; tc.wantNegative != (got < 0) {
				t.Errorf("expires_in_seconds = %d, wantNegative = %v", got, tc.wantNegative)
			}
		})
	}
}

// TestStatusJSON_NoCertificateIsNull distinguishes "no certificate" from "a
// certificate with blank fields", which a consumer must be able to tell apart.
func TestStatusJSON_NoCertificateIsNull(t *testing.T) {
	t.Parallel()

	deps := testDeps(stubProvider{readyErr: errNotReady})
	report := decodeStatus(t, routes(deps), "/status.json", "")

	if report.Certificate != nil {
		t.Errorf("certificate = %+v, want null", report.Certificate)
	}
	if report.Readiness.Ready {
		t.Error("readiness = ready, want not ready")
	}
	if report.Readiness.Reason == "" {
		t.Error("readiness reason is empty")
	}
}

func TestStatusJSON_EmptyListsAreNotNull(t *testing.T) {
	t.Parallel()

	provider := healthyProvider()
	provider.info.DNSNames = nil
	provider.info.URIs = nil

	rec := httptest.NewRecorder()
	routes(testDeps(provider)).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/status.json", nil))

	body := rec.Body.String()
	if strings.Contains(body, `"dns_names": null`) || strings.Contains(body, `"uris": null`) {
		t.Errorf("empty lists encoded as null, want []\n%s", body)
	}
}

func TestStatus_ContentNegotiation(t *testing.T) {
	t.Parallel()

	handler := routes(testDeps(healthyProvider()))

	tests := map[string]struct {
		accept   string
		wantJSON bool
	}{
		"explicit json":       {accept: "application/json", wantJSON: true},
		"json with qvalue":    {accept: "application/json;q=0.9", wantJSON: true},
		"json among several":  {accept: "text/html, application/json", wantJSON: true},
		"wildcard stays text": {accept: "*/*", wantJSON: false},
		"no accept header":    {accept: "", wantJSON: false},
		"html stays text":     {accept: "text/html", wantJSON: false},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			req := httptest.NewRequest(http.MethodGet, "/status", nil)
			if tc.accept != "" {
				req.Header.Set("Accept", tc.accept)
			}
			rec := httptest.NewRecorder()
			handler.ServeHTTP(rec, req)

			isJSON := strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json")
			if isJSON != tc.wantJSON {
				t.Errorf("Accept %q produced content type %q, wantJSON = %v",
					tc.accept, rec.Header().Get("Content-Type"), tc.wantJSON)
			}
		})
	}
}

// TestStatus_TextAndJSONAgree checks the two representations are built from the
// same report, so a change to one cannot silently diverge from the other.
func TestStatus_TextAndJSONAgree(t *testing.T) {
	t.Parallel()

	provider := healthyProvider()
	provider.info.NotAfter = testNow.Add(-2 * time.Hour)
	provider.readyErr = errNotReady

	handler := routes(testDeps(provider))
	report := decodeStatus(t, handler, "/status.json", "")

	rec := httptest.NewRecorder()
	handler.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/status", nil))
	text := rec.Body.String()

	if report.Certificate.Validity != "expired" {
		t.Fatalf("json validity = %q, want expired", report.Certificate.Validity)
	}
	if !strings.Contains(text, "❌ EXPIRED") {
		t.Errorf("text does not report expiry while json does\n%s", text)
	}
	if report.Readiness.Ready {
		t.Error("json reports ready while the certificate is expired")
	}
	if !strings.Contains(text, "Readiness: ❌") {
		t.Errorf("text does not report the readiness failure\n%s", text)
	}
	if !strings.Contains(text, report.Certificate.FingerprintSHA256) {
		t.Error("text and json disagree about the fingerprint")
	}
}

// TestStatusJSON_IsIndented pins /status.json to json.MarshalIndent - the
// opposite of /whoami.json's single-line contract (see
// TestWhoamiJSON_RefusalIsExplicit and the "compact JSON" assertion in
// TestWhoami). The two endpoints diverge on layout deliberately, and this
// stops either being "harmonised" with the other by accident.
func TestStatusJSON_IsIndented(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	routes(testDeps(healthyProvider())).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/status.json", nil))

	body := rec.Body.String()
	if got := strings.Count(body, "\n"); got < 2 {
		t.Errorf("body has %d newlines, want an indented multi-line document\n%s", got, body)
	}
	if !strings.Contains(body, "\n  \"server\"") {
		t.Errorf("body is not indented with two spaces\n%s", body)
	}
}

func TestStatusJSON_MethodScoped(t *testing.T) {
	t.Parallel()

	rec := httptest.NewRecorder()
	routes(testDeps(healthyProvider())).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/status.json", nil))
	if rec.Code != http.StatusMethodNotAllowed {
		t.Errorf("POST /status.json = %d, want 405", rec.Code)
	}
}
