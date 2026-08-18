# Reloading the client CA trust bundle

Date: 2026-08-18
Status: proposed, awaiting review
Branch: `mtls-trust-reload`, stacked on `mtls-client-auth` (PR #9)

## Purpose

`GOWEB_MTLS_CLIENT_CA` is read once, at startup. In Kubernetes the file it
names is typically a projected volume — a ConfigMap, a Secret, or a
ClusterTrustBundle — which is updated **in place**. A restart is not an
acceptable way to pick up a rotated trust bundle.

This design makes the trust store track its source the way the served
certificate already does.

It supersedes the "The client CA loads once, at startup" decision in
`2026-08-18-mtls-client-auth-design.md`. That decision was deliberate YAGNI
and is now retired by a concrete deployment requirement.

## The security constraint that shapes everything

Under `tls.VerifyClientCertIfGiven`, Go passes `Config.ClientCAs` straight
into `x509.VerifyOptions.Roots`:

```
crypto/tls/handshake_server.go:956    Roots: c.config.ClientCAs
```

and `Certificate.Verify` falls back to the system trust store when `Roots`
is nil:

```
crypto/x509/verify.go:815-816    if opts.Roots == nil { opts.Roots = systemRootsPool() }
```

**A nil `ClientCAs` with `ClientAuth` enabled therefore trusts every
publicly-issued client certificate.** Anyone holding a certificate from a
public CA would be reported by `/whoami` as a verified identity.

Today this is unreachable: `ClientAuth` is only set when a pool exists
(`internal/server/server.go`), and `LoadPool` fails startup rather than
returning an empty pool. Adding reload creates the path. It is the mistake a
careless reconcile writes, and it fails open rather than closed.

Two invariants follow, and every part of this design is subordinate to them:

1. **A reload never publishes a nil or empty pool.** An unreadable file, a
   file that parses to zero certificates, or any other failure leaves the
   previously published pool in place.
2. **A successfully parsed bundle is published even when it contains fewer
   CAs than before.** Removing a CA is revocation and must take effect.
   There is no "only grow" rule — that would make revocation impossible,
   which is the other way to fail open.

Invariant 1 gets a dedicated test asserting the published pool is never nil
after a failed reload. Invariant 2 gets a test asserting a client trusted
before a shrinking rotation is rejected after it.

### Why last-known-good, and not fail-closed

Publishing nil is a bug, not a policy. Given that, the real choice on a
failed reload was between retaining the last good pool, publishing an empty
pool so every client is rejected, and treating the failure as fatal.

Retaining the last good pool is chosen. The failure mode it accepts is
continuing to trust a CA someone was trying to remove, until an operator
notices the warning. The failure mode the alternatives accept is that a
single bad edit to a ConfigMap takes the fixture down for every consumer,
including e2e suites mid-run. For a component whose purpose is to be
available to other teams' test suites, availability under operator error is
worth more than immediate strictness — and the staleness is not silent: it
is logged on every failed reconcile and reported in `/status.json`.

Treating it as fatal was rejected for the same reason, with the extra cost
that startup also fails, so the pod enters CrashLoopBackOff until the file
is fixed.

This mirrors how the served certificate already behaves: the reloader
continues to serve the last valid certificate rather than dropping traffic
(`internal/certreload/watch.go`).

### Why a shrinking bundle applies immediately

The alternative considered was requiring two consecutive reconciles to agree
before applying a bundle with fewer CAs, guarding against a writer caught
mid-write whose partial output happens to parse.

Rejected. It delays every genuine revocation by up to one
`GOWEB_RELOAD_INTERVAL`, and revocation is the emergency this feature exists
to serve. The risk it guards against does not arise under the deployment
this is built for: Kubernetes writes a new timestamped directory and
atomically swaps the `..data` symlink, so a reader never observes a
partially written bundle.

That makes atomic replacement an **operational requirement**, not an
assumption to leave implicit. A writer that rewrites the file in place can
be read mid-write, and a partial bundle that still parses is
indistinguishable from a deliberate revocation — no reader-side logic can
tell them apart. The README must say so: replace the bundle atomically, as
projected volumes, ConfigMaps, Secrets and ClusterTrustBundles all do.

## Decisions

### Reuse the existing watch loop; do not write a second one

`internal/certreload/watch.go` already solves the hard part, and its own doc
comment describes this exact scenario:

> Directories are watched rather than files. Kubernetes rotates projected
> volumes and mounted secrets by writing a new timestamped directory and
> atomically swapping the `..data` symlink, so events never name the
> certificate path itself and a watch registered on the file would observe
> nothing.

It also carries three behaviours that took work to get right and that a
second implementation would get wrong: a true debounce with a bounded
ceiling so a churning directory cannot postpone a reload forever; bounded
retries because material can be briefly inconsistent mid-rotation; and a
periodic reconcile because fsnotify is not a durable event log and watches
can be dropped.

The loop is generic apart from four couplings: `watchDirectories()`,
`Reconcile()`, `recordWatcherError`, and log strings naming
`certificate_file`. It is extracted into a driver parameterised by the
directories to watch, a reconcile function, an error recorder, a label for
logs, and the existing timing knobs.

**`internal/certreload/watch_test.go` must pass unchanged.** It is the guard
on this extraction. If its assertions need editing, the extraction changed
behaviour — stop and reconsider rather than updating the test.

Rejected: a second watcher inside `internal/clientauth`. Duplicating subtle,
hard-won loop logic is how the two copies drift.

Rejected: teaching `certreload.Reloader` about a third file. The serving
identity and the trust store have independent lifecycles, independent
failure modes and — per the decision below — different readiness semantics.
Conflating them would force one policy on both.

### `GetConfigForClient`, built on reload rather than per handshake

`server.New` builds the base `tls.Config` once, as today. On each successful
pool change the trust reloader publishes a derived config:

```go
derived := base.Clone()
derived.ClientAuth = tls.VerifyClientCertIfGiven
derived.ClientCAs = pool
current.Store(derived)   // atomic.Pointer[tls.Config]
```

`GetConfigForClient` loads that pointer and returns it. Handing the same
derived pointer to concurrent handshakes is safe because it is read-only;
mutating a `tls.Config` after first use is not, which is why a whole config
is swapped rather than a field.

Cloning from one base is what defuses the trap the original spec named: a
config returned from `GetConfigForClient` **replaces** the base wholesale,
so `GetCertificate` and `MinVersion` must ride along. Deriving by clone
means they cannot be lost by omission.

A test asserts the config returned by `GetConfigForClient` has a non-nil
`GetCertificate` and `MinVersion == tls.VersionTLS13`. The equivalent
assertion already exists one layer up at `New()`; this is the copy that
catches a future edit to the derived path.

### Readiness: keep serving, report loudly

A stale or unreadable trust bundle does **not** fail `/readyz`.

This deliberately differs from the served certificate, where staleness
beyond `GOWEB_MAX_STALE_PERIOD` does fail readiness. The asymmetry is the
point: without a valid serving certificate the pod cannot serve TLS at all,
whereas with a stale trust bundle it serves correctly and may merely be
trusting a CA that has since been removed. Pulling a test fixture out of
service for a degraded-but-working condition costs more than it buys.

The condition is not silent. It is logged at warning level on every failed
reconcile and surfaced in `/status.json` (below), so an operator or a test
suite can see it.

A dead watcher is different and keeps the existing treatment: it means
rotation is no longer observed at all and cannot recover without a restart,
so the watcher joins `runComponents` in `cmd/goweb-https/main.go` and its
termination brings the process down. That matches the existing argument for
the certificate watcher — a component whose death means silent degradation
should fail the process, not be logged and ignored.

### `/status.json` reports the trust bundle

A new `trust_bundle` block reports the CA subjects, when the bundle was last
loaded, and its staleness:

```json
"trust_bundle": {
  "file_path": "/tls/client-ca.pem",
  "subjects": ["CN=goweb-client-ca"],
  "loaded_at": "2026-08-18T05:00:00Z",
  "last_success": "2026-08-18T05:04:00Z",
  "stale_seconds": 0,
  "last_error": ""
}
```

The block is **absent** when client-certificate verification is disabled,
matching how `certificate` is null rather than an empty object when no
certificate is available.

This is a contract addition to an endpoint external suites read, and it is
what makes rotation assertable. Without it a suite can only infer a reload
landed by polling `/whoami` with a certificate and watching it start or stop
working — indirect, slow, and ambiguous when it fails.

`/whoami`'s contract does not change. Reload is invisible to it.

### Configuration reuses the existing knobs

`GOWEB_RELOAD_DEBOUNCE`, `GOWEB_RELOAD_INTERVAL` and
`GOWEB_MAX_STALE_PERIOD` apply to both the certificate and the trust bundle.
No trust-specific twins.

This follows the same reasoning as having no boolean beside
`GOWEB_MTLS_CLIENT_CA`: a second knob that can disagree with the first is a
way to be misconfigured, not a feature. Nobody has yet wanted these two
sources reloaded at different cadences, and adding the knobs later is easy
if they do.

## Architecture

### `internal/certreload`: extract the driver

The `Watch` method's loop moves into an unexported driver:

```go
// watchSource is what the shared loop needs to know about the thing it is
// watching. It exists so the trust bundle can reuse the loop rather than
// grow a second copy of its debounce, retry and reconcile behaviour.
type watchSource struct {
    // Directories to watch. Directories rather than files, because of the
    // projected-volume symlink swap described on Watch.
    Directories []string

    // Reconcile re-reads the source. The boolean reports whether the
    // published value changed.
    Reconcile func() (bool, error)

    // RecordWatcherError records a terminal watcher failure for health
    // reporting.
    RecordWatcherError func(error)

    // Label names the source in log messages, e.g. "certificate" or
    // "trust bundle".
    Label string

    // LogKey and LogValue add the source's path to log lines, e.g.
    // "certificate_file" and the path.
    LogKey   string
    LogValue string
}

func runWatch(ctx context.Context, src watchSource, t watchTiming, logger *slog.Logger, now func() time.Time) error
```

`Reloader.Watch` becomes a thin call into `runWatch`. Its behaviour, its
error wrapping of `ErrWatcherClosed`, and its log output are unchanged —
`watch_test.go` proves it.

### `internal/clientauth`: the trust reloader

```go
// Bundle tracks a client CA trust bundle on disk and republishes it as it
// rotates.
type Bundle struct { /* ... */ }

// NewBundle loads path once and returns a Bundle ready to watch it.
// A file that cannot be read, or that yields no certificate, is an error:
// startup must not proceed with a trust store that trusts nothing, and -
// see the security constraint above - must never proceed with a nil pool.
func NewBundle(path string, opts ...BundleOption) (*Bundle, error)

// Pool returns the currently published trust pool. It is never nil.
func (b *Bundle) Pool() *x509.CertPool

// Subjects returns the subjects of the currently trusted CAs.
func (b *Bundle) Subjects() []string

// Status describes the bundle for /status.json.
func (b *Bundle) Status() BundleStatus

// Reconcile re-reads the bundle. The boolean reports whether the published
// pool changed. On any error the previously published pool is retained.
func (b *Bundle) Reconcile() (bool, error)

// Watch observes the bundle's directory and republishes as it rotates.
func (b *Bundle) Watch(ctx context.Context) error

// OnChange registers a callback invoked after a successful change. The
// server uses it to rebuild its derived tls.Config.
func (b *Bundle) OnChange(fn func(*x509.CertPool))
```

`LoadPool` keeps its current signature and becomes `NewBundle`'s
one-shot loader, so the parsing and subject-collection logic has one home.

### `internal/server`

`Dependencies` gains one field. The existing `Certificates
CertificateStatusProvider` is a consumer-declared interface; rather than
widening it — which would force the certificate reloader to grow trust
methods it has no business having — a second narrow interface is declared
beside it:

```go
// TrustBundleStatusProvider is the narrow view of the client CA trust
// bundle that the handlers need. Declared separately from
// CertificateStatusProvider because the served identity and the trust store
// are independent sources with independent health.
type TrustBundleStatusProvider interface {
    Status() clientauth.BundleStatus
}

// TrustBundle reports the client CA trust bundle. Nil when
// client-certificate verification is disabled.
TrustBundle TrustBundleStatusProvider
```

`New` keeps `Dependencies.ClientCAs` for the initial pool and gains the
`atomic.Pointer[tls.Config]` and `GetConfigForClient` wiring described
above.

### `cmd/goweb-https`

`run` builds the `Bundle` instead of calling `LoadPool` directly, registers
the server's rebuild callback, passes the bundle as both the initial pool
and the status provider, and adds `bundle.Watch` to `runComponents`
alongside `srv.Run` and `reloader.Watch`.

## Testing

- **Invariant 1** — a reload whose file is unreadable, truncated, or parses
  to zero certificates leaves the published pool unchanged and non-nil.
  Asserted directly on `Bundle`, and again at the TLS layer: a client
  trusted before the failed reload is still accepted after it.
- **Invariant 2** — rotating to a bundle with one CA removed causes a client
  issued by the removed CA to be rejected on a new handshake, while a client
  issued by a retained CA still succeeds. This is the revocation test and it
  runs over a real handshake.
- **The nil-pool trap** — a test asserting that a `tls.Config` produced by
  `GetConfigForClient` never has a nil `ClientCAs` while `ClientAuth` is
  not `NoClientCert`. This is the direct regression test for the system-root
  fallback documented above.
- **Derived config completeness** — `GetConfigForClient`'s result has a
  non-nil `GetCertificate` and `MinVersion == tls.VersionTLS13`.
- **Rotation end to end** — write a new bundle into the watched directory
  using the atomic-swap layout (`..data` symlink) and assert a previously
  untrusted client becomes trusted, over real handshakes, without a restart.
  This is the test that proves the feature does what it was asked to do.
- **`watch_test.go` passes unchanged**, proving the driver extraction was
  behaviour-preserving.
- **Readiness** — a stale trust bundle does NOT fail `/readyz`; a stale
  serving certificate still does. Both asserted, so the asymmetry is
  deliberate and pinned.
- **`/status.json`** — the `trust_bundle` block appears with the right
  subjects when verification is on, and is absent when it is off.

## Out of scope

- Reloading `GOWEB_MTLS_CLIENT_CA` itself — the path is fixed for the
  process lifetime. Only the file's contents are watched.
- CRL or OCSP checking. Revocation here means removing a CA from the bundle.
- Any change to `/whoami`'s request or response contract.

## Definition of done

- `make test` (`-race`) and `make lint` pass.
- `internal/certreload/watch_test.go` is byte-identical to its state on
  `mtls-client-auth`.
- Both security invariants have tests that fail if the invariant is removed,
  demonstrated by mutation.
- A rotation applied to a running server takes effect without a restart,
  demonstrated end to end against the real binary with a projected-volume
  style atomic swap.
- With `GOWEB_MTLS_CLIENT_CA` unset, behaviour is byte-identical to
  `mtls-client-auth`.
- README documents the reload behaviour, the readiness asymmetry, the new
  `/status.json` block, and the requirement that the bundle be replaced
  atomically rather than rewritten in place.
