# Client-certificate authentication endpoint

Date: 2026-08-18
Status: proposed, awaiting review
Branch: `worktree-mtls-client-auth`

## Purpose

`goweb-https` is used as a fixture by e2e suites that live in other
repositories. Those suites need a target that proves an mTLS handshake
happened and reports which client identity the server verified.

This design adds that: optional client-certificate verification on the
existing listener, and one endpoint that reports the verified client
identity.

Nothing e2e-shaped ships here. No `make e2e` target, no CI e2e job, no
container harness. The deliverable is the behaviour, its Go tests, the
means to mint client certificates the server trusts, and documentation
precise enough for an external suite to assert against.

## Scope

In scope:

- Optional client-certificate verification, off by default.
- `GET /whoami` and `GET /whoami.json` reporting the verified client identity.
- A new `internal/clientauth` package owning trust-store loading and
  identity extraction.
- `hack/gencerts` gains a mode that emits a client CA and a client leaf.
- README documentation of the endpoint contract and the environment variable.

Out of scope:

- Client CA reloading. See "Decisions" below.
- Any change to `/`, `/status`, `/status.json`, `/livez`, `/readyz` behaviour
  beyond one labelling fix described under "Related fix".
- Authorisation. The endpoint reports identity; it does not decide what an
  identity may do.

## Decisions

### Verification is listener-wide, enforcement is per-route

`server.New` builds one `tls.Config` for one listener serving every route
(`internal/server/server.go:88`). Setting `tls.RequireAndVerifyClientCert`
on it would stop `/livez` and `/readyz` from working, because Kubernetes
probes present no client certificate. The pod would never become ready and
the manifests in the README would break.

So the listener is configured with `tls.VerifyClientCertIfGiven`, which
makes a client certificate optional, and `/whoami` alone requires one.

Rejected: a second mTLS-only listener on its own port. It doubles the
`Run` and shutdown plumbing and the configuration surface, and buys
nothing this fixture needs.

### Presence of the CA path enables the feature

`GOWEB_MTLS_CLIENT_CA` names a PEM file of trusted client CA certificates.
When it is unset, `ClientAuth` stays at `tls.NoClientCert` and the server
behaves exactly as it does today. When it is set, the file must exist and
must contain at least one certificate, or startup fails.

This follows `certificatePaths` (`internal/config/config.go:150`), where a
half-configured certificate is treated as an operator mistake rather than a
request to fall back to a default. There is no separate boolean flag: a
second variable that can disagree with the first is a way to be
misconfigured, not a feature.

### Correct mTLS semantics, not a friendlier error

Under `tls.VerifyClientCertIfGiven` a client certificate that fails to
verify aborts the handshake. It never reaches HTTP. There are therefore
three observable outcomes:

| Client behaviour | Result |
| --- | --- |
| No client certificate | TLS succeeds; `GET /whoami` returns `403` |
| Certificate not signed by a configured CA | TLS handshake fails; no HTTP response |
| Certificate signed by a configured CA | TLS succeeds; `GET /whoami` returns `200` |

Rejected: `tls.RequestClientCert` plus a hand-written `VerifyPeerCertificate`,
which would turn the middle row into a `403` carrying a reason. That is
friendlier for an external suite to assert on, but hand-rolled certificate
chain verification is where authentication bugs live, and the failure mode
is accepting an untrusted identity. The middle row stays a handshake
failure. External suites assert on the connection error.

This table is part of the contract and must appear in the README.

### The client CA loads once, at startup

The served certificate reloads because it rotates. A client trust store
changes on a different timescale and a restart is an acceptable way to pick
up a new one.

Reloading it would mean `GetConfigForClient`, whose returned config
*replaces* the base config rather than merging with it. Every future
change to `TLSConfig` would then have to be mirrored into that path, and
forgetting to mirror `GetCertificate` or `MinVersion` breaks server
authentication or the TLS floor silently. Not worth it for this.

If reloading is wanted later it is a separate, deliberate change.

### Test material is generated, not committed

Tests mint their own CA, server leaf, and client leaf with `crypto/x509`.
No new files under `certs/`.

The committed demo material already has the problem that it expires on a
schedule nobody watches — `hack/gencerts` exists because of it, and says
so in its own doc comment. Adding a committed client CA and client
certificate would add two more.

External suites need material the server trusts, so `hack/gencerts` gains
a mode that emits one. That is a tool invocation, not a committed artefact.

## Architecture

### New package: `internal/clientauth`

Owns everything about the client trust store and about turning a TLS
connection state into an identity. It is the unit that can be tested
without an HTTP server and without a listener.

```go
// LoadPool reads a PEM file of trusted client CA certificates.
// It fails when the file cannot be read or contains no certificate,
// because a trust store that trusts nothing is a configuration error.
func LoadPool(path string) (*x509.CertPool, error)

// Identity describes a verified client certificate.
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

    // Chain lists the verified chain from leaf to root, by subject.
    Chain []string
}

// IdentityFrom extracts the verified client identity from a connection.
// The boolean reports whether the peer presented a certificate that the
// server verified. It reads VerifiedChains, never PeerCertificates.
func IdentityFrom(state *tls.ConnectionState) (Identity, bool)
```

`IdentityFrom` must gate on `len(state.VerifiedChains) > 0` and read the
leaf from `state.VerifiedChains[0][0]`. It must not read
`state.PeerCertificates`. Under the current `VerifyClientCertIfGiven`
setting the two agree, but they stop agreeing the moment anyone changes
`ClientAuth`, and the failure is silent acceptance of an unverified
identity. The distinction is enforced by the code and stated in the
doc comment.

This mirrors how `certreload.Info` is produced by one package and consumed
by `internal/server` through a narrow type.

### `internal/config`

`Config` gains one field:

```go
// ClientCAFile is the PEM file of client CA certificates to verify client
// certificates against. Empty means client-certificate verification is
// disabled.
ClientCAFile string
```

Read from `GOWEB_MTLS_CLIENT_CA`. Set-but-empty is an error, matching the
existing style. The file is not opened here — `config` reads the
environment and nothing else, and that property is worth keeping.

### `internal/server`

`Dependencies` gains:

```go
// ClientCAs is the trust store for client certificates. When nil, client
// certificates are not requested and /whoami always refuses.
ClientCAs *x509.CertPool
```

`New` sets, only when `deps.ClientCAs != nil`:

```go
ClientAuth: tls.VerifyClientCertIfGiven,
ClientCAs:  deps.ClientCAs,
```

`GetCertificate` and `MinVersion: tls.VersionTLS13` are unchanged.

`routes` gains:

```go
mux.HandleFunc("GET /whoami", handleWhoami(deps))
mux.HandleFunc("GET /whoami.json", handleWhoamiJSON(deps))
```

### `cmd/goweb-https`

`run` loads the pool when `cfg.ClientCAFile != ""`, fails startup on error,
passes it into `server.Dependencies`, and logs that client-certificate
verification is enabled along with the subjects it will trust. Startup
logging is how an operator confirms the fixture is configured the way the
external suite expects.

## The endpoint

### Response contract

`GET /whoami` with no verified client certificate returns `403` and
exactly this plain-text body, newline included:

```
no client certificate presented
```

`GET /whoami.json` in the same case returns `403` and:

```json
{ "authenticated": false, "reason": "no client certificate presented" }
```

Both strings are literal and are part of the contract. External suites
will match on them, so they are asserted in the tests rather than left to
whatever `fmt` produces.

### Encoding: `/whoami` JSON is compact

`/whoami.json`, and `/whoami` answering an explicit `Accept: application/json`,
emit **compact** JSON on a single line — no indentation, no spaces after
separators — followed by one trailing newline:

```
{"authenticated":false,"reason":"no client certificate presented"}
```

This deliberately diverges from `/status.json`, which stays indented via the
existing `writeJSON`. The two endpoints have different audiences: `/status`
is read by operators in a terminal, where indentation earns its bytes;
`/whoami` exists to be consumed by e2e suites in other repositories, where
layout is noise and a single line is easier to match, log and diff.

The consequence for consumers is that a compact document is stable enough
to compare as a string, so the JSON body joins the plain-text body as
literal contract rather than merely structural. Tests still assert key
names through a decoded `map[string]any` as well, because a decode-into-the-
same-struct assertion cannot catch a renamed JSON tag.

With a verified certificate, both return `200`. The JSON document is:

```json
{
  "authenticated": true,
  "client": {
    "subject": "CN=e2e-client,O=goweb",
    "issuer": "CN=goweb-test-ca",
    "serial": "...",
    "fingerprint_sha256": "...",
    "dns_names": [],
    "uris": [],
    "email_addresses": [],
    "ip_addresses": [],
    "not_before": "2026-08-18T00:00:00Z",
    "not_after": "2027-08-18T00:00:00Z",
    "expires_in_seconds": 31536000,
    "chain": ["CN=e2e-client,O=goweb", "CN=goweb-test-ca"]
  }
}
```

`authenticated` is always present, so a consumer can branch on one field
rather than on the absence of another.

`expires_in_seconds` is not a field of `clientauth.Identity`. It is derived
at render time from `deps.Now()`, exactly as `CertificateStatus` does for
the served certificate (`internal/server/status.go:66`). Keeping it out of
`Identity` keeps that type a description of the certificate rather than a
value whose correctness depends on when it was built.

Both representations render from a single struct, the way `StatusReport`
already backs both forms of `/status` (`internal/server/status.go:16`).
Rendering both from one value is what stops them drifting apart.

`GET /whoami` honours `prefersJSON` for the same reason `/status` does: a
scraper that cannot be pointed at a different URL still has a
machine-readable option.

### Related change to `handleRoot`

`handleRoot` (`internal/server/handlers.go:24`) already prints
`state.PeerCertificates[0]` as "Certificate CN" and "Certificate SANs".
Today no client certificate ever arrives, so the whole block is dead code.
This change makes it live.

This is **not** a security bug. Under `VerifyClientCertIfGiven` anything in
`PeerCertificates` has been verified, so the label is accurate today. Two
changes are wanted anyway:

1. Read the identity through `clientauth.IdentityFrom` rather than
   `PeerCertificates` directly. Not because the current read is unsafe, but
   so that there is one place in the codebase that decides what "the
   verified client" means, and so the block stays correct if `ClientAuth`
   is ever changed. Label it as the client certificate.

2. `🔐 SNI` currently sits *inside* the `len(PeerCertificates) > 0` guard,
   so it prints only when a client certificate arrives — which is
   backwards, and today means never. Move it out and print it whenever
   `r.TLS != nil`.

Point 2 is a deliberate change to the landing page: it gains an SNI line on
every TLS request. That is wanted for a TLS fixture. It is called out here
because it is the one place this work alters existing output, and the
"done" criteria below carve it out explicitly rather than leaving an
implementer to guess.

## Testing

All Go tests. `make test` already runs with `-race`.

`internal/clientauth`:

- `LoadPool` on a valid CA file, a missing file, a file of non-PEM bytes,
  and a PEM file containing no certificate.
- `IdentityFrom` with a nil state, a state with no peer certificate, and a
  state with a verified chain.
- A test asserting `IdentityFrom` returns false when `PeerCertificates` is
  populated but `VerifiedChains` is empty. This is the regression test for
  the distinction the package exists to enforce.

`internal/server`, over a real listener with a real handshake — extend the
existing pattern at `internal/server/server_test.go:289`:

- Client with a certificate signed by the trusted CA: `200`, and the body
  reports that client's subject.
- Client with no certificate: `403`, `authenticated` false.
- Client with a certificate signed by an untrusted CA: the request fails.
  Assert that no successful HTTP response is returned rather than matching
  an exact error string.
- `ClientCAs` nil: `/whoami` returns `403` and the handshake requests no
  certificate.
- The existing routes and probes still behave identically with `ClientCAs`
  set. This is the test that would have caught `RequireAndVerifyClientCert`.

`internal/config`: `GOWEB_MTLS_CLIENT_CA` unset, set, and set-empty.

Note for the implementer: under TLS 1.3 the client certificate is verified
after the server's Finished message, so a rejected client certificate may
surface as an error on the client's first `Read` rather than from
`Handshake`. Write the untrusted-certificate test to tolerate either.

## `hack/gencerts`

Today `run` builds one `x509.Certificate` template and signs it with
itself (`hack/gencerts/main.go:53-69`). Emitting a CA and a leaf signed by
that CA needs two templates and two keys, with the leaf signed by the CA's
key rather than its own. That is a restructure of `run` into a small
"build key, build template, sign with parent" helper called three times —
not a flag bolted onto the existing single-template path. It is the
largest piece of new code in this plan; budget for it accordingly.

The new `-client-ca` flag additionally emits:

- `client-ca.pem` / `client-ca-key.pem`: a CA with `IsCA: true`,
  `KeyUsage: CertSign | CRLSign`.
- `client.pem` / `client-key.pem`: a leaf signed by that CA, with
  `ExtKeyUsage: ClientAuth` only.

The existing default behaviour is unchanged when the flag is absent.

A `make certs-client` target wraps it, and the README shows the curl
invocation an external suite would mirror:

```
curl --cacert certs/demo.pem \
     --cert certs/client.pem --key certs/client-key.pem \
     https://localhost:8443/whoami.json
```

## Documentation

README gains:

- `GOWEB_MTLS_CLIENT_CA` in the configuration table, noting that its
  presence enables client-certificate verification.
- `/whoami` and `/whoami.json` in the endpoints table.
- The three-outcome table from "Decisions" above, verbatim. An external
  suite author needs to know that an untrusted certificate is a connection
  failure and not a `403`.
- The `make certs-client` and curl example.

## Files touched

| File | Change |
| --- | --- |
| `internal/clientauth/clientauth.go` | New. `LoadPool`, `Identity`, `IdentityFrom`. |
| `internal/clientauth/clientauth_test.go` | New. |
| `internal/config/config.go` | `ClientCAFile` field, `GOWEB_MTLS_CLIENT_CA`. |
| `internal/config/config_test.go` | Cases for the new variable. |
| `internal/server/server.go` | `Dependencies.ClientCAs`, `tls.Config`, routes. |
| `internal/server/whoami.go` | New. Handlers and the response struct. |
| `internal/server/handlers.go` | `handleRoot`: identity via `clientauth`, SNI moved out of the cert guard. |
| `internal/server/whoami_test.go` | New. Handshake-level tests. |
| `internal/server/server_test.go` | Probes and existing routes under `ClientCAs`. |
| `cmd/goweb-https/main.go` | Load the pool, pass it, log it. |
| `hack/gencerts/main.go` | `-client-ca` mode. |
| `Makefile` | `certs-client` target. |
| `README.md` | Configuration, endpoints, contract table, example. |

## Definition of done

- `make test` passes with `-race`.
- `make lint` passes.
- Every test listed under "Testing" exists and passes. Every new exported
  function and every new route has at least one test. No percentage
  target: the list above is the gate, because a coverage number moves
  when the denominator does and invites filler tests to chase it.
- With `GOWEB_MTLS_CLIENT_CA` unset, `/status`, `/status.json`, `/livez`
  and `/readyz` behave byte-identically to `main`. `/` differs only by
  the added SNI line described under "Related change to `handleRoot`".
- The README contract table matches what the code actually does.

## Amendment: 2026-08-18 review round

The decisions above stand as written; this records what changed after
review found two real gaps in them, plus two smaller fixes bundled into
the same round.

**`LoadPool` is replaced by `LoadTrustStore`.** The plan above (`## New
package: internal/clientauth`) specified `LoadPool(path string)
(*x509.CertPool, error)` failing only when the file cannot be read or
contains no certificate. Review found that this let any parseable
certificate become a trust anchor — Go's `x509.CertPool` does not check
`BasicConstraints`, `IsCA`, or `KeyUsage` for certificates added directly
to a pool. `certs/demo.pem` (see below) is exactly this shape: a leaf,
`BasicConstraintsValid` true, `IsCA` false. Pointing
`GOWEB_MTLS_CLIENT_CA` at it and its committed key would have let anyone
holding this public repository authenticate as a verified client.
Separately, `AppendCertsFromPEM`-style parsing treats a bundle as loaded
successfully if any block parses, so a corrupt CA sitting beside valid
ones was silently dropped rather than surfaced — the wrong default for a
trust store.

`internal/clientauth.LoadTrustStore(path string) (*TrustStore, error)`
now fails closed: every `CERTIFICATE` block must have
`BasicConstraintsValid`, `IsCA`, and `KeyUsageCertSign`, and must be
within its validity window; a block that claims to be a certificate but
fails to parse fails the whole load rather than being skipped.
`TrustStore.Pool()` returns the `*x509.CertPool` for
`tls.Config.ClientCAs`; `TrustStore.Anchors() []Anchor` returns each
anchor's subject, issuer, serial, SHA-256 fingerprint, and validity
window, for startup logging. The fingerprint is included because CA
rotation commonly preserves the subject DN, so a subject alone cannot
tell an operator which CA is actually trusted — `main.go`'s startup log
field is renamed from `client_ca_subjects` to `client_ca_trust_anchors`
accordingly.

**The demo server leaf's profile is trimmed.** The "Never point
`GOWEB_MTLS_CLIENT_CA` at `certs/demo.pem`" hazard was already known and
documented (see the README section this plan specified), but the demo
server leaf itself carried `ExtKeyUsage: ServerAuth, ClientAuth` and
`KeyUsage: DigitalSignature | KeyEncipherment` — a server fixture with
client-auth capability it never needed, and RSA key transport that this
server's TLS 1.3-only configuration never uses. `hack/gencerts` now
emits the server leaf with `ExtKeyUsage: ServerAuth` only and `KeyUsage:
DigitalSignature` only; `certs/demo.pem`, `certs/demo-key.pem` and
`certs/bundle.pem` were regenerated with the trimmed profile (common
name and SANs unchanged). With `LoadTrustStore` in place, pointing
`GOWEB_MTLS_CLIENT_CA` at `certs/demo.pem` now fails startup outright
rather than silently trusting the committed key — the trimmed leaf
profile is defense in depth on top of that, not the primary control.

`hack/gencerts` also now writes key material through a temp file created
with the intended mode, then renames it into place: `os.WriteFile`'s mode
argument only applies when a file is newly created, so regenerating a key
over one that already existed at `0o644` previously left it
world-readable.

**The probes-are-unaffected claim needed a correction.** The plan's
"Scope" section says probe behaviour is unchanged "beyond one labelling
fix." Review found the README's phrasing of that claim — that
`/livez`, `/readyz`, `/status` and `/status.json` are unaffected "whether
or not a client certificate is configured or presented" — was wrong
about the word "presented." Under `VerifyClientCertIfGiven`, a client
certificate that fails verification aborts the TLS handshake before any
route runs, so those endpoints fail too when one is presented and
invalid. This was already correctly captured in the three-outcome table
this plan specified (`## Documentation`); the prose above it
contradicted its own table. The README prose is corrected to match the
table: those endpoints never *require* a client certificate and work
when none is presented, but a *presented* certificate must still verify,
for every endpoint on the listener.

**New response headers on `/whoami` and `/status`, not specified above.**
`/whoami` and `/whoami.json` now send `Cache-Control: no-store` on every
response, including refusals, since the body carries one client's
identity keyed only by the URL and must never be cached and replayed to
a different client. `/whoami` and `/status` send `Vary: Accept`, since
both negotiate representation from that header; the dedicated `.json`
endpoints have exactly one representation and don't send it. Also,
`writeJSONEncodeError`'s fallback body now goes through `writeJSONBody`
instead of `http.Error`, so a JSON consumer that hits an encoding
failure still gets `Content-Type: application/json` rather than
`text/plain`.
