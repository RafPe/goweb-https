package server

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"testing"
	"time"

	"github.com/RafPe/goweb-https/internal/clientauth"
)

// stubTrustBundle is a TrustBundleStatusProvider returning a fixed status.
type stubTrustBundle struct {
	status clientauth.BundleStatus
}

func (s stubTrustBundle) Status() clientauth.BundleStatus { return s.status }

// healthyTrustBundle describes a bundle that was read successfully a moment
// ago.
func healthyTrustBundle(now time.Time) stubTrustBundle {
	return stubTrustBundle{status: clientauth.BundleStatus{
		FilePath: "/tls/client-ca.pem",
		Anchors: []clientauth.Anchor{{
			Subject:           "CN=goweb-client-ca",
			FingerprintSHA256: "5704a5b2",
			NotAfter:          now.Add(365 * 24 * time.Hour),
		}},
		LoadedAt:    now,
		LastSuccess: now,
	}}
}

// newServerWithClientCAs builds a Server with client verification enabled,
// without starting a listener.
func newServerWithClientCAs(t *testing.T, pool *x509.CertPool) *Server {
	t.Helper()

	cert, _ := testCertificate(t)
	deps := testDeps(healthyProvider())
	deps.ClientCAs = pool

	srv, err := New("127.0.0.1:0", time.Second,
		func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert, nil },
		deps)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return srv
}

// configForClient returns what the listener would hand a handshake.
func configForClient(t *testing.T, srv *Server) *tls.Config {
	t.Helper()

	hook := srv.http.TLSConfig.GetConfigForClient
	if hook == nil {
		t.Fatal("GetConfigForClient is nil; the trust bundle could never be rotated")
	}
	config, err := hook(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetConfigForClient: %v", err)
	}
	if config == nil {
		t.Fatal("GetConfigForClient returned a nil config")
	}
	return config
}

// TestGetConfigForClient_CarriesTheBaseConfig guards the trap in deriving a
// config per handshake: a config returned from GetConfigForClient replaces the
// base wholesale, so anything omitted from it is not inherited but lost. A
// derived config missing GetCertificate cannot complete a handshake at all, and
// one missing MinVersion silently drops the floor to TLS 1.0.
//
// The equivalent assertion exists one layer up on New's own config; this is the
// copy that catches a future edit to the derived path.
func TestGetConfigForClient_CarriesTheBaseConfig(t *testing.T) {
	t.Parallel()

	clientCAs, _ := testClientCertificate(t)
	config := configForClient(t, newServerWithClientCAs(t, clientCAs))

	if config.GetCertificate == nil {
		t.Error("GetCertificate is nil on the derived config; server authentication would be broken")
	}
	if got := config.MinVersion; got != tls.VersionTLS13 {
		t.Errorf("MinVersion = %v on the derived config, want TLS 1.3", got)
	}
	if got := config.ClientAuth; got != tls.VerifyClientCertIfGiven {
		t.Errorf("ClientAuth = %v on the derived config, want tls.VerifyClientCertIfGiven", got)
	}
	if config.ClientCAs == nil {
		t.Error("ClientCAs is nil on the derived config")
	}
}

// TestGetConfigForClient_NeverPublishesANilPool is the direct regression test
// for the system-root fallback: crypto/x509 substitutes the system trust store
// when VerifyOptions.Roots is nil, and crypto/tls passes ClientCAs straight
// into Roots. A nil pool alongside an enabled ClientAuth therefore does not
// reject everyone - it accepts every publicly issued client certificate as a
// verified identity.
//
// SetClientCAs refusing nil is what stops a careless caller reaching that
// state, and this asserts it at the only place that matters: what the handshake
// is actually handed.
func TestGetConfigForClient_NeverPublishesANilPool(t *testing.T) {
	t.Parallel()

	clientCAs, _ := testClientCertificate(t)
	srv := newServerWithClientCAs(t, clientCAs)

	srv.SetClientCAs(nil)

	config := configForClient(t, srv)
	if config.ClientAuth == tls.NoClientCert {
		t.Fatal("ClientAuth was disabled rather than the nil pool being refused")
	}
	if config.ClientCAs == nil {
		t.Fatal("ClientCAs is nil while client verification is enabled; every public CA is now trusted")
	}
	if config.ClientCAs != clientCAs {
		t.Error("ClientCAs was replaced, want the last known good pool retained")
	}
}

// TestSetClientCAsIsInertWithoutATrustStore keeps the mTLS-off path exactly as
// it was: with no pool configured there is no hook, and a stray call cannot
// switch verification on behind the operator's back.
func TestSetClientCAsIsInertWithoutATrustStore(t *testing.T) {
	t.Parallel()

	cert, _ := testCertificate(t)
	srv, err := New("127.0.0.1:0", time.Second,
		func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert, nil },
		testDeps(healthyProvider()))
	if err != nil {
		t.Fatalf("New: %v", err)
	}

	pool, _ := testClientCertificate(t)
	srv.SetClientCAs(pool)

	if srv.http.TLSConfig.GetConfigForClient != nil {
		t.Error("GetConfigForClient is set with no trust store configured")
	}
	if got := srv.http.TLSConfig.ClientAuth; got != tls.NoClientCert {
		t.Errorf("ClientAuth = %v, want tls.NoClientCert", got)
	}
	if srv.http.TLSConfig.ClientCAs != nil {
		t.Error("ClientCAs is set with no trust store configured")
	}
}

// TestRotatingTheTrustBundleTakesEffect proves both directions of a rotation
// over real handshakes, which is the behaviour this feature exists to provide:
// a client the server did not trust becomes trusted, and - the revocation case
// - a client it did trust stops being trusted.
//
// Each request uses a fresh client, so every assertion is made on a new
// handshake rather than on a pooled connection that was authenticated under the
// previous pool.
func TestRotatingTheTrustBundleTakesEffect(t *testing.T) {
	t.Parallel()

	serverCert, roots := testCertificate(t)
	_, retainedClient := testClientCertificate(t)
	_, revokedClient := testClientCertificate(t)

	// A pool exposes no accessor for the certificates in it, so both the
	// starting bundle and the rotated one are built from the chains the helpers
	// issued rather than by merging the pools they returned.
	srv := newTestServer(t, serverCert, roots, poolOf(t, retainedClient, revokedClient))

	whoami := func(t *testing.T, cert *tls.Certificate) (int, error) {
		t.Helper()

		resp, err := tlsClient(roots, cert).Get(srv.URL + "/whoami.json")
		if err != nil {
			return 0, err
		}
		defer resp.Body.Close()
		return resp.StatusCode, nil
	}

	for name, cert := range map[string]*tls.Certificate{"retained": retainedClient, "revoked": revokedClient} {
		status, err := whoami(t, cert)
		if err != nil {
			t.Fatalf("%s client: %v, want a successful handshake before the rotation", name, err)
		}
		if status != http.StatusOK {
			t.Fatalf("%s client: status = %d before the rotation, want %d", name, status, http.StatusOK)
		}
	}

	// Revocation: the bundle now names only one of the two CAs.
	srv.server.SetClientCAs(poolOf(t, retainedClient))

	status, err := whoami(t, retainedClient)
	if err != nil {
		t.Fatalf("retained client: %v, want it still accepted after the rotation", err)
	}
	if status != http.StatusOK {
		t.Errorf("retained client: status = %d after the rotation, want %d", status, http.StatusOK)
	}

	if _, err := whoami(t, revokedClient); err == nil {
		t.Error("revoked client completed a handshake after its CA was removed from the bundle")
	}
}

// poolOf builds a pool trusting the issuing CA of each supplied client
// certificate. The helpers send the chain leaf-first, so the issuer is the
// second entry.
func poolOf(t *testing.T, clients ...*tls.Certificate) *x509.CertPool {
	t.Helper()

	pool := x509.NewCertPool()
	for _, client := range clients {
		if len(client.Certificate) < 2 {
			t.Fatalf("client certificate carries %d entries, want leaf and issuer", len(client.Certificate))
		}
		ca, err := x509.ParseCertificate(client.Certificate[1])
		if err != nil {
			t.Fatalf("parse issuing ca: %v", err)
		}
		pool.AddCert(ca)
	}
	return pool
}

// TestReadinessIgnoresTheTrustBundle pins the asymmetry between the two
// reloading sources. Without a valid serving certificate the pod cannot serve
// TLS at all, so staleness there fails readiness. A stale trust bundle serves
// correctly and may merely be trusting a CA that has since been removed:
// pulling a working pod out of service for that costs more than it buys, and
// the condition is reported through /status.json instead.
func TestReadinessIgnoresTheTrustBundle(t *testing.T) {
	t.Parallel()

	now := time.Now()
	stale := stubTrustBundle{status: clientauth.BundleStatus{
		FilePath:    "/tls/client-ca.pem",
		LoadedAt:    now.Add(-48 * time.Hour),
		LastSuccess: now.Add(-48 * time.Hour),
		LastError:   "clientauth: read client CA file: no such file or directory",
	}}

	t.Run("a stale trust bundle stays ready", func(t *testing.T) {
		t.Parallel()

		deps := testDeps(healthyProvider())
		deps.TrustBundle = stale

		resp := do(t, routes(deps), http.MethodGet, "/readyz")
		if resp.Code != http.StatusOK {
			t.Errorf("status = %d, want %d: a stale trust bundle must not fail readiness", resp.Code, http.StatusOK)
		}
	})

	t.Run("a stale serving certificate does not", func(t *testing.T) {
		t.Parallel()

		provider := healthyProvider()
		provider.readyErr = errNotReady

		deps := testDeps(provider)
		deps.TrustBundle = healthyTrustBundle(now)

		resp := do(t, routes(deps), http.MethodGet, "/readyz")
		if resp.Code != http.StatusServiceUnavailable {
			t.Errorf("status = %d, want %d", resp.Code, http.StatusServiceUnavailable)
		}
	})
}

// TestStatusJSON_TrustBundle covers the block external suites read to assert
// that a rotation landed.
func TestStatusJSON_TrustBundle(t *testing.T) {
	t.Parallel()

	t.Run("reports the trusted anchors", func(t *testing.T) {
		t.Parallel()

		now := time.Now()
		deps := testDeps(healthyProvider())
		deps.Now = func() time.Time { return now.Add(30 * time.Second) }
		deps.TrustBundle = healthyTrustBundle(now)

		report := decodeStatus(t, routes(deps), "/status.json", "")
		bundle := report.TrustBundle
		if bundle == nil {
			t.Fatal("trust_bundle is absent while client verification is enabled")
		}
		if bundle.FilePath != "/tls/client-ca.pem" {
			t.Errorf("file_path = %q, want the configured bundle", bundle.FilePath)
		}
		if len(bundle.Anchors) != 1 {
			t.Fatalf("anchors = %d, want 1", len(bundle.Anchors))
		}
		if got := bundle.Anchors[0].FingerprintSHA256; got != "5704a5b2" {
			t.Errorf("fingerprint_sha256 = %q, want the anchor's fingerprint", got)
		}
		if got := bundle.StaleSeconds; got != 30 {
			t.Errorf("stale_seconds = %d, want 30", got)
		}
		if bundle.LastError != "" {
			t.Errorf("last_error = %q, want empty", bundle.LastError)
		}
	})

	// Absent, not null: a consumer distinguishes "this deployment does not do
	// client verification" from "it does, and here is the bundle" by the key
	// being there at all.
	t.Run("is absent when client verification is disabled", func(t *testing.T) {
		t.Parallel()

		resp := do(t, routes(testDeps(healthyProvider())), http.MethodGet, "/status.json")

		var document map[string]json.RawMessage
		if err := json.Unmarshal(resp.Body.Bytes(), &document); err != nil {
			t.Fatalf("decode status: %v", err)
		}
		if _, ok := document["trust_bundle"]; ok {
			t.Errorf("trust_bundle is present with no trust store configured: %s", resp.Body.String())
		}
	})

	// A failed reload is the one warning an operator gets that the enforced
	// pool is no longer the one on disk, so it must survive into the document.
	t.Run("reports a failed reload", func(t *testing.T) {
		t.Parallel()

		now := time.Now()
		bundle := healthyTrustBundle(now)
		bundle.status.LastSuccess = now.Add(-5 * time.Minute)
		bundle.status.LastError = "clientauth: /tls/client-ca.pem contains no PEM certificate"

		deps := testDeps(healthyProvider())
		deps.Now = func() time.Time { return now }
		deps.TrustBundle = bundle

		report := decodeStatus(t, routes(deps), "/status.json", "")
		if report.TrustBundle == nil {
			t.Fatal("trust_bundle is absent")
		}
		if report.TrustBundle.LastError == "" {
			t.Error("last_error is empty after a failed reload")
		}
		if got := report.TrustBundle.StaleSeconds; got != 300 {
			t.Errorf("stale_seconds = %d, want 300", got)
		}
	})
}
