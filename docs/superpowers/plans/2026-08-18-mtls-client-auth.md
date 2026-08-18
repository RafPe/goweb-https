# mTLS Client Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give `goweb-https` optional client-certificate verification and a `/whoami` endpoint that reports the verified client identity, so e2e suites in other repositories can use the binary as an mTLS fixture.

**Architecture:** Client certificates are verified listener-wide with `tls.VerifyClientCertIfGiven` — optional at the handshake — and required only by the new route. Probes and existing endpoints are untouched. A new `internal/clientauth` package owns the trust store and the single definition of "the verified client"; `internal/server` consumes it through a narrow `Identity` type, the same shape as the existing `certreload.Info` relationship.

**Tech Stack:** Go (stdlib only — `crypto/tls`, `crypto/x509`, `net/http`). No new dependencies. Tests are stdlib `testing` with `net/http/httptest`.

**Spec:** `docs/superpowers/specs/2026-08-18-mtls-client-auth-design.md` — read it before starting. This plan implements it and does not repeat its rationale.

## Global Constraints

- **Go stdlib only.** Adding a module dependency is out of scope. `go.mod` must not change.
- **TLS floor stays `tls.VersionTLS13`.** Never remove or lower `MinVersion`.
- **Never read `PeerCertificates` to establish identity.** Only `VerifiedChains`. This is the invariant the whole design rests on.
- **Lint gate:** `make lint` runs golangci-lint v2.1.6 with `gosec`, `revive` (exported symbols need doc comments), `errcheck`, `errorlint`, `nilerr`. Every exported symbol needs a doc comment starting with its name.
- **`os.ReadFile` with a variable path trips gosec G304.** Annotate the one occurrence with `// #nosec G304 -- the path is operator-supplied configuration; reading it is the point` rather than restructuring around it.
- **Test style:** table-driven with subtests, following `internal/config/config_test.go`. `make test` runs with `-race`.
- **Comments explain why, not what.** Match the density and voice of the surrounding code — see `internal/server/status.go` for the house style.
- **Commit after every task.** Small commits, imperative subject lines.

---

### Task 1: `clientauth.LoadPool`

Loads the client CA trust store from a PEM file.

**Files:**
- Create: `internal/clientauth/clientauth.go`
- Create: `internal/clientauth/clientauth_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `func LoadPool(path string) (*x509.CertPool, error)` — used by Task 7 (`cmd/goweb-https/main.go`).

- [ ] **Step 1: Write the failing test**

Create `internal/clientauth/clientauth_test.go`:

```go
package clientauth

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// writeCAFile writes a self-signed CA certificate to a temporary PEM file and
// returns its path.
func writeCAFile(t *testing.T) string {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	path := filepath.Join(t.TempDir(), "ca.pem")
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("write ca file: %v", err)
	}
	return path
}

func TestLoadPool(t *testing.T) {
	valid := writeCAFile(t)

	notPEM := filepath.Join(t.TempDir(), "garbage.pem")
	if err := os.WriteFile(notPEM, []byte("this is not a certificate"), 0o600); err != nil {
		t.Fatalf("write garbage file: %v", err)
	}

	emptyPEM := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(emptyPEM, []byte("-----BEGIN OTHER-----\nAA==\n-----END OTHER-----\n"), 0o600); err != nil {
		t.Fatalf("write empty pem: %v", err)
	}

	tests := map[string]struct {
		path      string
		wantError bool
	}{
		"valid CA file":                    {path: valid, wantError: false},
		"missing file":                     {path: filepath.Join(t.TempDir(), "absent.pem"), wantError: true},
		"file that is not PEM":             {path: notPEM, wantError: true},
		"PEM without any certificate":      {path: emptyPEM, wantError: true},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			pool, err := LoadPool(test.path)

			if test.wantError {
				if err == nil {
					t.Fatalf("LoadPool(%q) = nil error, want an error", test.path)
				}
				if pool != nil {
					t.Errorf("LoadPool returned a pool alongside an error; want nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("LoadPool(%q) returned %v, want no error", test.path, err)
			}
			if pool == nil {
				t.Fatal("LoadPool returned a nil pool without an error")
			}
		})
	}
}
```

- [ ] **Step 2: Run the test and confirm it fails**

Run: `go test ./internal/clientauth/...`
Expected: build failure, `undefined: LoadPool`.

- [ ] **Step 3: Write the implementation**

Create `internal/clientauth/clientauth.go`:

```go
// Package clientauth owns the client-certificate trust store and the
// extraction of a verified client identity from a TLS connection.
//
// It is a separate package from internal/server so that deciding what "the
// verified client" means is one decision made in one place. The server
// consumes the result through the narrow Identity type, the same way it
// consumes certreload.Info.
package clientauth

import (
	"crypto/x509"
	"fmt"
	"os"
)

// LoadPool reads a PEM file of client CA certificates and returns a pool that
// client certificates are verified against.
//
// A file that yields no certificate is an error rather than an empty pool.
// An empty pool would fail every client certificate presented to it, which is
// an operator mistake and not a configuration anyone intends.
func LoadPool(path string) (*x509.CertPool, error) {
	// #nosec G304 -- the path is operator-supplied configuration; reading it is the point
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("clientauth: read client CA file: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(encoded) {
		return nil, fmt.Errorf("clientauth: %s contains no PEM certificate", path)
	}

	return pool, nil
}
```

- [ ] **Step 4: Run the test and confirm it passes**

Run: `go test -race ./internal/clientauth/...`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add internal/clientauth/
git commit -m "Add clientauth.LoadPool for the client CA trust store"
```

---

### Task 2: `clientauth.Identity` and `IdentityFrom`

Turns a TLS connection state into a verified client identity.

**Files:**
- Modify: `internal/clientauth/clientauth.go`
- Modify: `internal/clientauth/clientauth_test.go`

**Interfaces:**
- Consumes: nothing from Task 1 beyond the package.
- Produces: `type Identity struct{...}` and `func IdentityFrom(state *tls.ConnectionState) (Identity, bool)` — used by Tasks 5 and 6.

- [ ] **Step 1: Write the failing test**

Append to `internal/clientauth/clientauth_test.go`. Note the third case: it is the regression test for the invariant this package exists to enforce.

```go
// leafCertificate returns a parsed self-signed leaf for use in a fake
// connection state.
func leafCertificate(t *testing.T, commonName string) *x509.Certificate {
	t.Helper()

	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     []string{"client.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

func TestIdentityFrom(t *testing.T) {
	leaf := leafCertificate(t, "verified-client")

	t.Run("nil connection state", func(t *testing.T) {
		if _, ok := IdentityFrom(nil); ok {
			t.Error("IdentityFrom(nil) reported an identity; want none")
		}
	})

	t.Run("no peer certificate", func(t *testing.T) {
		if _, ok := IdentityFrom(&tls.ConnectionState{}); ok {
			t.Error("IdentityFrom reported an identity for a bare state; want none")
		}
	})

	// The whole point of the package: a certificate the client presented but
	// the server did not verify is not an identity. If this test ever passes
	// an identity back, something started reading PeerCertificates.
	t.Run("peer certificate present but unverified", func(t *testing.T) {
		state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
		if _, ok := IdentityFrom(state); ok {
			t.Error("IdentityFrom reported an identity from an unverified certificate")
		}
	})

	t.Run("verified chain", func(t *testing.T) {
		state := &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{leaf},
			VerifiedChains:   [][]*x509.Certificate{{leaf}},
		}

		identity, ok := IdentityFrom(state)
		if !ok {
			t.Fatal("IdentityFrom reported no identity for a verified chain")
		}
		if got, want := identity.Subject, "CN=verified-client"; got != want {
			t.Errorf("Subject = %q, want %q", got, want)
		}
		if got, want := identity.Serial, "42"; got != want {
			t.Errorf("Serial = %q, want %q", got, want)
		}
		if len(identity.FingerprintSHA256) != 64 {
			t.Errorf("FingerprintSHA256 = %q, want 64 hex characters", identity.FingerprintSHA256)
		}
		if got, want := identity.DNSNames, []string{"client.example"}; !slices.Equal(got, want) {
			t.Errorf("DNSNames = %v, want %v", got, want)
		}
		if got, want := identity.Chain, []string{"CN=verified-client"}; !slices.Equal(got, want) {
			t.Errorf("Chain = %v, want %v", got, want)
		}
	})
}
```

Add `"crypto/tls"` and `"slices"` to the test file's imports.

- [ ] **Step 2: Run the test and confirm it fails**

Run: `go test ./internal/clientauth/...`
Expected: build failure, `undefined: IdentityFrom`.

- [ ] **Step 3: Write the implementation**

Append to `internal/clientauth/clientauth.go`, and extend its imports with `crypto/sha256`, `crypto/tls`, `encoding/hex`, and `time`:

```go
// Identity describes a client certificate that the server verified.
//
// Every field is derived from the verified leaf, so a populated Identity
// always means the handshake proved possession of the corresponding key.
type Identity struct {
	Subject           string
	Issuer            string
	Serial            string
	FingerprintSHA256 string
	DNSNames          []string
	URIs              []string
	EmailAddresses    []string
	IPAddresses       []string
	NotBefore         time.Time
	NotAfter          time.Time

	// Chain lists the verified chain by subject, leaf first.
	Chain []string
}

// IdentityFrom extracts the verified client identity from state. The boolean
// reports whether the client presented a certificate that the server verified.
//
// It reads VerifiedChains and never PeerCertificates. Under the listener's
// tls.VerifyClientCertIfGiven setting the two agree, because an unverifiable
// certificate aborts the handshake before any handler runs. They stop agreeing
// the moment ClientAuth changes, and the failure mode of the wrong choice is
// treating an unverified certificate as an identity - so this reads the field
// that is safe under every setting.
func IdentityFrom(state *tls.ConnectionState) (Identity, bool) {
	if state == nil || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return Identity{}, false
	}

	chain := state.VerifiedChains[0]
	leaf := chain[0]
	fingerprint := sha256.Sum256(leaf.Raw)

	identity := Identity{
		Subject:           leaf.Subject.String(),
		Issuer:            leaf.Issuer.String(),
		Serial:            leaf.SerialNumber.String(),
		FingerprintSHA256: hex.EncodeToString(fingerprint[:]),
		DNSNames:          leaf.DNSNames,
		EmailAddresses:    leaf.EmailAddresses,
		NotBefore:         leaf.NotBefore,
		NotAfter:          leaf.NotAfter,
	}

	for _, uri := range leaf.URIs {
		identity.URIs = append(identity.URIs, uri.String())
	}
	for _, ip := range leaf.IPAddresses {
		identity.IPAddresses = append(identity.IPAddresses, ip.String())
	}
	for _, cert := range chain {
		identity.Chain = append(identity.Chain, cert.Subject.String())
	}

	return identity, true
}
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `go test -race ./internal/clientauth/...`
Expected: PASS, all four subtests.

- [ ] **Step 5: Commit**

```bash
git add internal/clientauth/
git commit -m "Add clientauth.IdentityFrom, gated on the verified chain"
```

---

### Task 3: `GOWEB_MTLS_CLIENT_CA` configuration

**Files:**
- Modify: `internal/config/config.go`
- Modify: `internal/config/config_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `Config.ClientCAFile string` — read by Task 7.

- [ ] **Step 1: Write the failing test**

Add to `internal/config/config_test.go`, following the existing table style in that file:

```go
func TestLoadFromClientCA(t *testing.T) {
	tests := map[string]struct {
		env       map[string]string
		want      string
		wantError bool
	}{
		"unset means disabled": {
			env:  map[string]string{},
			want: "",
		},
		"set names the trust store": {
			env:  map[string]string{"GOWEB_MTLS_CLIENT_CA": "/tls/client-ca.pem"},
			want: "/tls/client-ca.pem",
		},
		"set but empty is an operator mistake": {
			env:       map[string]string{"GOWEB_MTLS_CLIENT_CA": ""},
			wantError: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			cfg, err := LoadFrom(lookupFrom(test.env))

			if test.wantError {
				if err == nil {
					t.Fatal("LoadFrom returned no error, want one")
				}
				return
			}

			if err != nil {
				t.Fatalf("LoadFrom returned %v, want no error", err)
			}
			if cfg.ClientCAFile != test.want {
				t.Errorf("ClientCAFile = %q, want %q", cfg.ClientCAFile, test.want)
			}
		})
	}
}
```

**Before writing this, read `internal/config/config_test.go` and reuse its existing helper for building a `LookupFunc` from a map.** It already has one; `lookupFrom` above is a placeholder for whatever that helper is actually called. Do not add a second helper that does the same thing.

- [ ] **Step 2: Run the test and confirm it fails**

Run: `go test ./internal/config/...`
Expected: build failure, `cfg.ClientCAFile undefined`.

- [ ] **Step 3: Write the implementation**

In `internal/config/config.go`, add to the `Config` struct after `PodNamespace`:

```go
	// ClientCAFile is the PEM file of client CA certificates that client
	// certificates are verified against. Empty means client-certificate
	// verification is disabled and the server requests no certificate.
	ClientCAFile string
```

Add the resolver next to `certificatePaths`:

```go
// clientCAPath resolves the client CA trust store location.
//
// The variable being set is what enables client-certificate verification.
// There is no separate boolean, because a second variable that can disagree
// with this one is a way to be misconfigured rather than a feature. Set but
// empty is an operator mistake, matching certificatePaths.
func clientCAPath(lookup LookupFunc) (string, error) {
	value, ok := lookup("GOWEB_MTLS_CLIENT_CA")
	if !ok {
		return "", nil
	}
	if value == "" {
		return "", errors.New("GOWEB_MTLS_CLIENT_CA: must not be empty when set")
	}
	return value, nil
}
```

In `LoadFrom`, alongside the other accumulating calls and before `errors.Join`:

```go
	clientCAFile, err := clientCAPath(lookup)
	if err != nil {
		errs = append(errs, err)
	}
```

And in the returned `Config` literal:

```go
		ClientCAFile:            clientCAFile,
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `go test -race ./internal/config/...`
Expected: PASS. Existing config tests must still pass unchanged.

- [ ] **Step 5: Commit**

```bash
git add internal/config/
git commit -m "Read GOWEB_MTLS_CLIENT_CA into the configuration"
```

---

### Task 4: Wire the trust store into the listener

Sets `ClientAuth` and `ClientCAs` when a pool is supplied, and proves the existing endpoints are unaffected.

**Files:**
- Modify: `internal/server/server.go`
- Modify: `internal/server/server_test.go`

**Interfaces:**
- Consumes: nothing.
- Produces: `Dependencies.ClientCAs *x509.CertPool` — set by Task 7, read by Task 5's tests.

- [ ] **Step 1: Write the failing test**

Read `internal/server/server_test.go` first — around line 289 there is an existing test that starts a real TLS listener, and `testCertificate` at line 383 builds server material. Reuse both.

Add a test proving the probes still work when a client CA pool is configured and the client presents no certificate. This is the test that would have caught `RequireAndVerifyClientCert`:

```go
func TestProbesWorkWithoutClientCertificate(t *testing.T) {
	cert, roots := testCertificate(t)

	// A trust store that will never match: the point is that configuring one
	// must not stop a client that presents no certificate at all.
	clientCAs := x509.NewCertPool()
	clientCAs.AddCert(cert.Leaf)

	srv, err := New(
		"127.0.0.1:0",
		time.Second,
		func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert, nil },
		Dependencies{
			Certificates: stubProvider{},
			Logger:       slog.New(slog.DiscardHandler),
			ClientCAs:    clientCAs,
		},
	)
	if err != nil {
		t.Fatalf("New returned %v, want no error", err)
	}

	if got := srv.http.TLSConfig.ClientAuth; got != tls.VerifyClientCertIfGiven {
		t.Errorf("ClientAuth = %v, want tls.VerifyClientCertIfGiven", got)
	}
	if srv.http.TLSConfig.ClientCAs == nil {
		t.Error("ClientCAs is nil, want the configured pool")
	}
	if got := srv.http.TLSConfig.MinVersion; got != tls.VersionTLS13 {
		t.Errorf("MinVersion = %v, want TLS 1.3", got)
	}
	if srv.http.TLSConfig.GetCertificate == nil {
		t.Error("GetCertificate is nil; server authentication would be broken")
	}

	_ = roots
}

func TestClientAuthDisabledByDefault(t *testing.T) {
	cert, _ := testCertificate(t)

	srv, err := New(
		"127.0.0.1:0",
		time.Second,
		func(*tls.ClientHelloInfo) (*tls.Certificate, error) { return cert, nil },
		Dependencies{Certificates: stubProvider{}, Logger: slog.New(slog.DiscardHandler)},
	)
	if err != nil {
		t.Fatalf("New returned %v, want no error", err)
	}

	if got := srv.http.TLSConfig.ClientAuth; got != tls.NoClientCert {
		t.Errorf("ClientAuth = %v, want tls.NoClientCert when no pool is configured", got)
	}
}
```

`stubProvider` above is a placeholder: **use whatever fake `CertificateStatusProvider` `server_test.go` already defines.** Read the file and match it. Do not introduce a second fake.

- [ ] **Step 2: Run the test and confirm it fails**

Run: `go test ./internal/server/...`
Expected: build failure, `unknown field ClientCAs in struct literal`.

- [ ] **Step 3: Write the implementation**

In `internal/server/server.go`, add `"crypto/x509"` to the imports and this field to `Dependencies`, after `PodNamespace`:

```go
	// ClientCAs is the trust store that client certificates are verified
	// against. When nil, no client certificate is requested and the routes
	// that need one always refuse.
	ClientCAs *x509.CertPool
```

Replace the inline `TLSConfig` literal in `New` with a value built beforehand:

```go
	// Client certificates are optional at the listener and required only by
	// the routes that ask for one. Requiring them here would stop /livez and
	// /readyz working, because probes present no certificate - the pod would
	// never become ready.
	tlsConfig := &tls.Config{
		GetCertificate: getCertificate,
		MinVersion:     tls.VersionTLS13,
	}
	if deps.ClientCAs != nil {
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
		tlsConfig.ClientCAs = deps.ClientCAs
	}
```

and use `TLSConfig: tlsConfig` in the `http.Server` literal.

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `go test -race ./internal/server/...`
Expected: PASS, including every pre-existing test unchanged.

- [ ] **Step 5: Commit**

```bash
git add internal/server/
git commit -m "Verify client certificates when a trust store is configured"
```

---

### Task 5: The `/whoami` endpoint

**Files:**
- Create: `internal/server/whoami.go`
- Create: `internal/server/whoami_test.go`
- Modify: `internal/server/server.go` (the `routes` function only)

**Interfaces:**
- Consumes: `clientauth.Identity`, `clientauth.IdentityFrom` (Task 2); `Dependencies.ClientCAs` (Task 4).
- Produces: routes `GET /whoami` and `GET /whoami.json`.

- [ ] **Step 1: Write the failing test**

Create `internal/server/whoami_test.go`. This test drives a real listener through a real handshake — the only way to prove the wiring works.

Write a helper that mints a CA plus a client leaf signed by it, then three cases. Model the listener setup on the existing test near `internal/server/server_test.go:289`.

```go
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
```

Write these three helpers in the same file:

- `testClientCertificate(t)` → `(*x509.CertPool, *tls.Certificate)`: generates a CA (`IsCA: true`, `KeyUsage: CertSign|CRLSign`), then a leaf with `CommonName: "test-client"` and `ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}` signed by that CA. Returns a pool containing the CA, and a `tls.Certificate` whose `Certificate` field holds `[leafDER, caDER]` so the chain is sent complete.
- `newTestServer(t, serverCert *tls.Certificate, clientCAs *x509.CertPool)` → `*httptest.Server`: builds `routes(deps)` with the fake provider `server_test.go` already defines, wraps it in `httptest.NewUnstartedServer`, sets `TLSConfig` exactly as `New` does (`GetCertificate`, `MinVersion: tls.VersionTLS13`, and `ClientAuth`/`ClientCAs` when the pool is non-nil), calls `StartTLS`, and registers `t.Cleanup(srv.Close)`.
- `tlsClient(roots *x509.CertPool, cert *tls.Certificate)` → `*http.Client`: an `http.Client` whose transport has `TLSClientConfig` with `RootCAs: roots`, `MinVersion: tls.VersionTLS13`, and `Certificates: []tls.Certificate{*cert}` when `cert` is non-nil.

Imports for the test file: `crypto/rand`, `crypto/rsa`, `crypto/tls`, `crypto/x509`, `crypto/x509/pkix`, `encoding/json`, `io`, `math/big`, `net/http`, `net/http/httptest`, `strings`, `testing`, `time`.

- [ ] **Step 2: Run the test and confirm it fails**

Run: `go test ./internal/server/...`
Expected: build failure, `undefined: WhoamiReport`.

- [ ] **Step 3: Write the implementation**

Create `internal/server/whoami.go`:

```go
package server

import (
	"net/http"
	"time"

	"github.com/RafPe/goweb-https/internal/clientauth"
)

// noClientCertificate is the refusal returned when no verified client
// certificate accompanied the request.
//
// It is a constant because e2e suites in other repositories match on it, which
// makes it contract rather than a message that can be reworded freely.
const noClientCertificate = "no client certificate presented"

// WhoamiReport is the identity of the calling client.
//
// It backs both representations of /whoami for the same reason StatusReport
// backs both representations of /status: rendering one value two ways is what
// stops the two from drifting apart.
type WhoamiReport struct {
	// Authenticated is always present, so a consumer branches on one field
	// rather than on the absence of another.
	Authenticated bool `json:"authenticated"`

	Reason string        `json:"reason,omitempty"`
	Client *ClientStatus `json:"client,omitempty"`
}

// ClientStatus describes the client certificate the server verified.
type ClientStatus struct {
	Subject           string    `json:"subject"`
	Issuer            string    `json:"issuer"`
	Serial            string    `json:"serial"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	DNSNames          []string  `json:"dns_names"`
	URIs              []string  `json:"uris"`
	EmailAddresses    []string  `json:"email_addresses"`
	IPAddresses       []string  `json:"ip_addresses"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`

	// ExpiresInSeconds counts down to NotAfter and goes negative once the
	// certificate has expired, matching CertificateStatus.
	ExpiresInSeconds int64 `json:"expires_in_seconds"`

	// Chain lists the verified chain by subject, leaf first.
	Chain []string `json:"chain"`
}

// buildWhoami gathers the verified identity of the client behind r.
func buildWhoami(deps Dependencies, r *http.Request) WhoamiReport {
	identity, ok := clientauth.IdentityFrom(r.TLS)
	if !ok {
		return WhoamiReport{Authenticated: false, Reason: noClientCertificate}
	}

	now := deps.Now()
	return WhoamiReport{
		Authenticated: true,
		Client: &ClientStatus{
			Subject:           identity.Subject,
			Issuer:            identity.Issuer,
			Serial:            identity.Serial,
			FingerprintSHA256: identity.FingerprintSHA256,
			DNSNames:          emptyIfNil(identity.DNSNames),
			URIs:              emptyIfNil(identity.URIs),
			EmailAddresses:    emptyIfNil(identity.EmailAddresses),
			IPAddresses:       emptyIfNil(identity.IPAddresses),
			NotBefore:         identity.NotBefore,
			NotAfter:          identity.NotAfter,
			ExpiresInSeconds:  int64(identity.NotAfter.Sub(now).Seconds()),
			Chain:             emptyIfNil(identity.Chain),
		},
	}
}

// whoamiStatus maps a report to its HTTP status.
func whoamiStatus(report WhoamiReport) int {
	if report.Authenticated {
		return http.StatusOK
	}
	return http.StatusForbidden
}

// handleWhoami reports the verified client identity to humans.
//
// Like /status it honours an explicit Accept: application/json, so a consumer
// that cannot be pointed at a different URL still has a machine-readable
// option.
func handleWhoami(deps Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		report := buildWhoami(deps, r)

		if prefersJSON(r) {
			writeJSON(w, deps, whoamiStatus(report), report)
			return
		}

		writeText(w, whoamiStatus(report), renderWhoamiText(report, deps.Location))
	}
}

// handleWhoamiJSON serves the machine-readable identity document.
func handleWhoamiJSON(deps Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		report := buildWhoami(deps, r)
		writeJSON(w, deps, whoamiStatus(report), report)
	}
}

// renderWhoamiText renders a report as the human-readable page.
func renderWhoamiText(report WhoamiReport, location *time.Location) string {
	if !report.Authenticated {
		return noClientCertificate + "\n"
	}

	client := report.Client

	var b strings.Builder
	fmt.Fprint(&b, "🔐 Verified Client Certificate:\n\n")
	fmt.Fprintf(&b, "Subject: %s\n", client.Subject)
	fmt.Fprintf(&b, "Issuer: %s\n", client.Issuer)
	fmt.Fprintf(&b, "Serial: %s\n", client.Serial)
	fmt.Fprintf(&b, "Fingerprint (SHA-256): %s\n", client.FingerprintSHA256)
	fmt.Fprintf(&b, "Valid: %s to %s\n",
		formatTime(client.NotBefore, location),
		formatTime(client.NotAfter, location))

	for _, name := range client.DNSNames {
		fmt.Fprintf(&b, "  DNS: %s\n", name)
	}
	for _, uri := range client.URIs {
		fmt.Fprintf(&b, "  URI: %s\n", uri)
	}
	for _, email := range client.EmailAddresses {
		fmt.Fprintf(&b, "  Email: %s\n", email)
	}
	for _, ip := range client.IPAddresses {
		fmt.Fprintf(&b, "  IP: %s\n", ip)
	}

	fmt.Fprint(&b, "Chain:\n")
	for _, subject := range client.Chain {
		fmt.Fprintf(&b, "  %s\n", subject)
	}

	return b.String()
}
```

Add `"fmt"` and `"strings"` to that file's imports.

In `internal/server/server.go`, add to `routes` after the `/status.json` line:

```go
	// The client identity the handshake proved. A separate path from /status
	// because it answers a different question and, unlike /status, refuses
	// callers it cannot identify.
	mux.HandleFunc("GET /whoami", handleWhoami(deps))
	mux.HandleFunc("GET /whoami.json", handleWhoamiJSON(deps))
```

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `go test -race ./internal/server/...`
Expected: PASS.

If the untrusted-certificate subtest fails because the request unexpectedly *succeeded*, stop and report it — that means verification is not happening and the feature is broken. If it fails on an error-message assertion, relax the assertion; only "no successful response" is being tested.

- [ ] **Step 5: Commit**

```bash
git add internal/server/
git commit -m "Add /whoami reporting the verified client identity"
```

---

### Task 6: `handleRoot` reads the verified identity, and SNI moves out

**Files:**
- Modify: `internal/server/handlers.go:24-32`
- Modify: `internal/server/whoami_test.go`

**Interfaces:**
- Consumes: `clientauth.IdentityFrom` (Task 2).
- Produces: nothing.

Read the "Related change to `handleRoot`" section of the spec before starting. The current block is not a security bug; this is a consistency change plus one deliberate output fix.

- [ ] **Step 1: Write the failing test**

Add to `internal/server/whoami_test.go`:

```go
func TestRootShowsSNIAndVerifiedClient(t *testing.T) {
	serverCert, roots := testCertificate(t)
	clientCAs, trustedClient := testClientCertificate(t)
	srv := newTestServer(t, serverCert, clientCAs)

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
```

- [ ] **Step 2: Run the test and confirm it fails**

Run: `go test ./internal/server/ -run TestRootShowsSNI -v`
Expected: FAIL — the body has no `SNI:` line, because SNI currently sits inside the client-certificate guard and no certificate arrives in the first subtest.

- [ ] **Step 3: Write the implementation**

In `internal/server/handlers.go`, replace lines 24-32 with:

```go
		// SNI is a property of every TLS request, not only of requests that
		// carry a client certificate - it used to be printed inside the
		// certificate branch, where it never appeared at all.
		if r.TLS != nil {
			fmt.Fprintf(&b, "🔐 SNI: %s\n", r.TLS.ServerName)
		}

		// Read through clientauth so that one place in the codebase decides
		// what "the verified client" means, and so this stays correct if the
		// listener's ClientAuth setting ever changes.
		if identity, ok := clientauth.IdentityFrom(r.TLS); ok {
			fmt.Fprintf(&b, "📜 Client Certificate Subject: %s\n", identity.Subject)
			fmt.Fprintf(&b, "🏷️ Client Certificate SANs: %v\n", identity.DNSNames)
			fmt.Fprintf(&b, "⏳ Client Certificate Valid: %s to %s\n",
				formatTime(identity.NotBefore, deps.Location),
				formatTime(identity.NotAfter, deps.Location))
		}
```

Add `"github.com/RafPe/goweb-https/internal/clientauth"` to the imports.

- [ ] **Step 4: Run the tests and confirm they pass**

Run: `go test -race ./internal/server/...`
Expected: PASS. If an existing test asserted on the old root output, update it — this output change is intended and is recorded in the spec.

- [ ] **Step 5: Commit**

```bash
git add internal/server/
git commit -m "Show SNI on every TLS request and read the client identity via clientauth"
```

---

### Task 7: Wire it up in `main`

**Files:**
- Modify: `cmd/goweb-https/main.go`

**Interfaces:**
- Consumes: `config.Config.ClientCAFile` (Task 3), `clientauth.LoadPool` (Task 1), `server.Dependencies.ClientCAs` (Task 4).
- Produces: nothing.

- [ ] **Step 1: Write the implementation**

There is no unit test for this step: `run` is covered indirectly by `cmd/goweb-https/main_test.go` and the wiring is proven by Task 5's handshake tests. Task 8's manual check is what exercises it end to end.

In `cmd/goweb-https/main.go`, add `"crypto/x509"` and the `clientauth` import, then insert after the `config.Load()` block:

```go
	// The trust store is loaded once. It changes on a different timescale
	// from the served certificate, and a restart is an acceptable way to
	// pick up a new one.
	var clientCAs *x509.CertPool
	if cfg.ClientCAFile != "" {
		clientCAs, err = clientauth.LoadPool(cfg.ClientCAFile)
		if err != nil {
			return err
		}
	}
```

Pass it in the `server.Dependencies` literal:

```go
		ClientCAs:    clientCAs,
```

And extend the existing `logger.Info("starting https server", ...)` call with:

```go
		"client_certificate_verification", cfg.ClientCAFile != "",
		"client_ca_file", cfg.ClientCAFile,
```

Startup logging is how an operator confirms the fixture is configured the way the external suite expects.

- [ ] **Step 2: Run the full suite**

Run: `make test`
Expected: PASS across every package.

- [ ] **Step 3: Commit**

```bash
git add cmd/goweb-https/
git commit -m "Load the client CA trust store at startup"
```

---

### Task 8: `gencerts` emits a client CA and client certificate

This is the largest piece of new code. `run` currently builds one template and signs it with itself (`hack/gencerts/main.go:53-69`); signing a leaf with a separate CA key needs two keys and two templates, so `run` is restructured rather than extended.

**Files:**
- Modify: `hack/gencerts/main.go`
- Modify: `Makefile`

**Interfaces:**
- Consumes: nothing.
- Produces: `certs/client-ca.pem`, `certs/client-ca-key.pem`, `certs/client.pem`, `certs/client-key.pem` when `-client-ca` is passed.

- [ ] **Step 1: Restructure `run` around a signing helper**

Add to `hack/gencerts/main.go`:

```go
// issued is a generated certificate together with the key that signs for it.
type issued struct {
	template *x509.Certificate
	der      []byte
	key      *rsa.PrivateKey
}

// issue creates a certificate from template, signed by parent. A nil parent
// makes it self-signed, which is how the root of each chain is produced.
func issue(template *x509.Certificate, parent *issued) (*issued, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	template.SerialNumber = serial

	signerTemplate, signerKey := template, key
	if parent != nil {
		signerTemplate, signerKey = parent.template, parent.key
	}

	der, err := x509.CreateCertificate(rand.Reader, template, signerTemplate, &key.PublicKey, signerKey)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	return &issued{template: template, der: der, key: key}, nil
}

// pemPair renders a certificate and its key as PEM.
func pemPair(c *issued) (certPEM, keyPEM []byte, err error) {
	keyDER, err := x509.MarshalPKCS8PrivateKey(c.key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		nil
}
```

Rewrite the existing server-certificate path in `run` to use `issue(&template, nil)` and `pemPair`, dropping the now-duplicated key, serial, and marshalling code. The files it writes and their modes must not change: `demo.pem`, `demo-key.pem`, and `bundle.pem` (key then certificate), with `0o600` for anything holding a key.

- [ ] **Step 2: Verify the existing behaviour is unchanged**

Run: `go run ./hack/gencerts -dir "$(mktemp -d)"`
Expected: writes `demo.pem`, `demo-key.pem`, `bundle.pem` and prints the common name and expiry, exactly as before.

- [ ] **Step 3: Commit the restructure on its own**

```bash
git add hack/gencerts/
git commit -m "Restructure gencerts around an issue helper so leaves can have a parent"
```

- [ ] **Step 4: Add the `-client-ca` mode**

Add the flag in `main`:

```go
		clientCA = flag.Bool("client-ca", false, "also emit a client CA and a client certificate signed by it")
```

and pass it into `run`. When set, `run` additionally issues:

```go
	caTemplate := x509.Certificate{
		Subject:               pkix.Name{CommonName: "goweb-client-ca"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(validFor),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	ca, err := issue(&caTemplate, nil)
	if err != nil {
		return fmt.Errorf("client CA: %w", err)
	}

	// A client leaf: ClientAuth only, so it cannot be mistaken for, or used
	// as, a server certificate.
	clientTemplate := x509.Certificate{
		Subject:               pkix.Name{CommonName: "goweb-client"},
		NotBefore:             now.Add(-time.Hour),
		NotAfter:              now.Add(validFor),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	client, err := issue(&clientTemplate, ca)
	if err != nil {
		return fmt.Errorf("client certificate: %w", err)
	}
```

Write `client-ca.pem`, `client-ca-key.pem`, `client.pem`, `client-key.pem` through the same write loop, with `0o600` on the key files.

- [ ] **Step 5: Verify end to end by hand**

This is the check that proves Tasks 1-7 actually work in the real binary.

```bash
DIR=$(mktemp -d)
go run ./hack/gencerts -dir "$DIR" -client-ca -dns-names localhost
GOWEB_X509_CER=$DIR/demo.pem GOWEB_X509_KEY=$DIR/demo-key.pem \
  GOWEB_MTLS_CLIENT_CA=$DIR/client-ca.pem \
  go run ./cmd/goweb-https &
sleep 2

# Expect 200 and the client subject:
/usr/bin/curl -sS --cacert "$DIR/demo.pem" \
  --cert "$DIR/client.pem" --key "$DIR/client-key.pem" \
  https://localhost:8443/whoami.json

# Expect 403 and "no client certificate presented":
/usr/bin/curl -sS --cacert "$DIR/demo.pem" https://localhost:8443/whoami

# Expect connection failure, not an HTTP status:
/usr/bin/curl -sS --cacert "$DIR/demo.pem" \
  --cert "$DIR/demo.pem" --key "$DIR/demo-key.pem" \
  https://localhost:8443/whoami

# Probes must still work with no client certificate:
/usr/bin/curl -sS --cacert "$DIR/demo.pem" https://localhost:8443/readyz

kill %1
```

Use `/usr/bin/curl` explicitly — plain `curl` is aliased to `curlie` on this machine and formats output differently.

Record what each command returned in your report.

- [ ] **Step 6: Add the Makefile target**

In the `##@ Development` section of the `Makefile`, next to the existing certificate target:

```make
.PHONY: certs-client
certs-client: ## Generate a client CA and client certificate for mTLS testing.
	go run ./hack/gencerts -client-ca
```

- [ ] **Step 7: Commit**

```bash
git add hack/gencerts/ Makefile
git commit -m "Add gencerts -client-ca and a certs-client target"
```

---

### Task 9: Documentation

**Files:**
- Modify: `README.md`

**Interfaces:**
- Consumes: everything above.
- Produces: the contract external e2e suites read.

- [ ] **Step 1: Update the configuration table**

In the "Server and reload behaviour" table (around `README.md:31`), add:

```markdown
| GOWEB_MTLS_CLIENT_CA | _(unset)_ | PEM file of client CA certificates. Setting it enables client-certificate verification; leaving it unset disables it entirely. |
```

- [ ] **Step 2: Update the endpoints table**

In the "Endpoints" section (around `README.md:40`), add:

```markdown
| `/whoami` | The client certificate the server verified, as a human-readable page. `403` when the caller presented none. |
| `/whoami.json` | The same, as JSON. Always carries an `authenticated` boolean. |
```

- [ ] **Step 3: Add a client-certificate authentication section**

After the "Endpoints" section, add a new `# Client certificate authentication` section containing:

- One paragraph: verification is off unless `GOWEB_MTLS_CLIENT_CA` is set; it applies to the whole listener but only `/whoami` requires a certificate, so probes and every existing endpoint are unaffected.
- The three-outcome table, copied verbatim from the spec's "Correct mTLS semantics" section. State plainly that a certificate signed by an untrusted CA fails the TLS handshake and never produces an HTTP status — an external suite asserts on a connection error there, not on a `403`.
- One paragraph noting the trust store is read once at startup, so replacing it needs a restart.
- The generate-and-call example:

````markdown
```bash
make certs-client

GOWEB_MTLS_CLIENT_CA=./certs/client-ca.pem ./bin/goweb-https &

curl --cacert ./certs/demo.pem \
     --cert ./certs/client.pem --key ./certs/client-key.pem \
     https://localhost:8443/whoami.json
```
````

- Then a sample of the `200` response body, copied from the spec's JSON example.

- [ ] **Step 4: Check the documentation against reality**

Re-read the section against the code you wrote. Every environment variable name, endpoint path, status code, JSON field name and literal string must match. This is the artefact another team codes against; a wrong field name here costs someone a debugging session.

- [ ] **Step 5: Commit**

```bash
git add README.md
git commit -m "Document client certificate authentication and the /whoami contract"
```

---

### Task 10: Full verification

**Files:** none.

- [ ] **Step 1: Run the whole gate**

```bash
make test
make lint
```

Both must pass. `make test` runs `fmt` and `vet` first.

- [ ] **Step 2: Confirm the unchanged-behaviour criterion**

With `GOWEB_MTLS_CLIENT_CA` unset, start the server and check `/status`, `/status.json`, `/livez` and `/readyz` behave as they do on `main`. `/` is expected to differ by exactly one added SNI line.

- [ ] **Step 3: Check the plan against the spec**

Re-read `docs/superpowers/specs/2026-08-18-mtls-client-auth-design.md` "Definition of done" and confirm every bullet holds. Report anything that does not, rather than quietly adjusting the criterion.

- [ ] **Step 4: Report**

Report: every command run and its result, anything that deviated from this plan and why, and anything you were unsure about. Do not push or open a pull request — that is handled by the coordinating session.

## Self-Review

Checked against the spec:

- Listener-wide verification, per-route enforcement — Task 4.
- `GOWEB_MTLS_CLIENT_CA` presence as the switch, set-but-empty an error — Task 3.
- Three-outcome contract — Task 5 (tests), Task 9 (documentation).
- Trust store loaded once at startup — Task 7.
- Generated test material, no new committed certificates — Tasks 1, 2, 5 helpers; Task 8 for manual material.
- `internal/clientauth` with `LoadPool`, `Identity`, `IdentityFrom`, gated on `VerifiedChains` — Tasks 1 and 2, with the regression test in Task 2.
- `/whoami` and `/whoami.json`, one struct behind both, `expires_in_seconds` derived at render time, literal `403` bodies — Task 5.
- `handleRoot` via `clientauth`, SNI moved out — Task 6.
- `gencerts` restructured, `-client-ca` mode, `make certs-client` — Task 8.
- README configuration, endpoints, contract table, example — Task 9.
- Definition of done — Task 10.

Type consistency: `LoadPool`, `Identity`, `IdentityFrom`, `Dependencies.ClientCAs`, `Config.ClientCAFile`, `WhoamiReport`, `ClientStatus`, `buildWhoami`, `whoamiStatus`, `renderWhoamiText`, `handleWhoami`, `handleWhoamiJSON`, `issue`, `issued`, `pemPair` are each defined once and referred to by the same name throughout. `emptyIfNil`, `writeJSON`, `writeText`, `prefersJSON` and `formatTime` are existing helpers reused rather than redefined.

Known placeholders, deliberately flagged in-task rather than guessed: the `LookupFunc` test helper name in Task 3, and the fake `CertificateStatusProvider` name in Task 4. Both instruct the implementer to read the existing test file and reuse what is there.
