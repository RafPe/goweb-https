# goweb-https
Simple GO based web server using HTTPs that supports reading certificates from a given directory and uses SNI in order to serve simple request along with loaded certificates and their status. 

Its purpose is to help you when securing/working with SSL certificates for your pods in your Kubernetes cluster environment.

Please be mindful it is in `development` and subject to change.


# Configuration

All configuration is read from the environment once at startup and validated
before the server binds. An invalid value fails startup with a message naming
the variable, rather than being silently ignored.

## Certificate material

| Variable           | Priority | Purpose |
| --------           | -------  | ------- |
| GOWEB_X509_BUNDLE  | 1        | Combined key and certificate file path. |
| GOWEB_X509_KEY     | 2        | Key file path. |
| GOWEB_X509_CER     | 2        | Certificate file path. |

> `GOWEB_X509_BUNDLE` takes precedence over the separate certificate and key
> paths. `GOWEB_X509_CER` and `GOWEB_X509_KEY` must be supplied together; setting
> only one of them is rejected at startup.

## Server and reload behaviour

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| GOWEB_PORT | `8443` | Listen port. |
| TZ / TIMEZONE | `UTC` | Display timezone for timestamps. An unknown zone fails startup. |
| GOWEB_SHUTDOWN_TIMEOUT | `10s` | How long in-flight requests may drain for on SIGTERM. |
| GOWEB_RELOAD_DEBOUNCE | `500ms` | Quiet period after a filesystem event before re-reading. Applies to the certificate and the client CA trust bundle alike. |
| GOWEB_RELOAD_INTERVAL | `30s` | Periodic reconciliation against disk, independent of events. Applies to both sources. |
| GOWEB_MAX_STALE_PERIOD | `15m` | How long the certificate source may be unreadable before `/readyz` fails. It does not apply to the trust bundle, whose staleness is reported and never enforced — see [Trust bundle reloading](#trust-bundle-reloading). |
| GOWEB_ALLOW_EXPIRED_CERTIFICATE | `false` | Start with an already-expired certificate and report it instead of exiting. |
| POD_NAME / POD_NAMESPACE | – | Shown on `/status`. |
| GOWEB_MTLS_CLIENT_CA | _(unset)_ | PEM file of client CA certificates. Setting it enables client-certificate verification; leaving it unset disables it entirely. |

# Endpoints

| Path | Purpose |
| ---- | ------- |
| `/` | Landing page showing host, time, SNI, and — when a client certificate is verified — its identity. |
| `/status` | Human-readable certificate and process diagnostics. |
| `/status.json` | The same information as plain JSON, for machine consumers. |
| `/whoami` | The client certificate the server verified, as a human-readable page. `403` when the caller presented none. |
| `/whoami.json` | The same, as JSON. Always carries an `authenticated` boolean. |
| `/livez` | Liveness. Reports only that the HTTP loop is running. |
| `/readyz` | Readiness. Fails when no usable certificate exists, when the served certificate is outside its validity period, or when the certificate source has been unreadable for longer than `GOWEB_MAX_STALE_PERIOD`. A stale client CA trust bundle deliberately does **not** fail it. |

Unknown paths return 404 and unsupported methods return 405.

## Machine-readable status

`/status.json` returns the same data as `/status` with no emoji or prose. Both
are rendered from one struct, so they cannot report different things.

`/status` also honours content negotiation: send `Accept: application/json` and
it returns the JSON document instead. A wildcard `Accept: */*` — which curl and
most probes send — still gets the human page.

```console
$ curl -sk https://localhost:8443/status.json | jq '.certificate.validity, .readiness.ready'
"valid"
true
```

```json
{
  "server": {
    "hostname": "goweb-0",
    "pod_name": "goweb-0",
    "pod_namespace": "demo",
    "time": "2026-08-17T20:14:37Z",
    "started_at": "2026-08-17T20:10:12Z",
    "uptime_seconds": 265
  },
  "request": {
    "remote_address": "10.244.0.1:58262",
    "user_agent": "curl/8.7.1"
  },
  "certificate": {
    "file_path": "/tls/tls.crt",
    "subject": "CN=*.raf.tech",
    "issuer": "CN=*.raf.tech",
    "serial": "290383568814942334872090304415376416195",
    "fingerprint_sha256": "26e170f3...ed9f224b",
    "dns_names": ["*.raf.tech", "raf.tech"],
    "uris": [],
    "not_before": "2026-08-17T18:30:11Z",
    "not_after": "2036-08-14T19:30:11Z",
    "loaded_at": "2026-08-17T20:10:12Z",
    "validity": "valid",
    "expires_in_seconds": 315357333
  },
  "trust_bundle": {
    "file_path": "/tls/client-ca.pem",
    "anchors": [
      {
        "subject": "CN=goweb-client-ca",
        "fingerprint_sha256": "5704a5b2...9c1de4a0",
        "not_after": "2036-08-15T09:50:28Z"
      }
    ],
    "loaded_at": "2026-08-17T20:10:12Z",
    "last_success": "2026-08-17T20:14:12Z",
    "stale_seconds": 25,
    "last_error": ""
  },
  "readiness": { "ready": true }
}
```

Notes for consumers:

- `validity` is one of `valid`, `not_yet_valid`, `expired`.
- `expires_in_seconds` goes negative once the certificate has expired, so a
  scrape can alert on a single number.
- `certificate` is `null` when none is loaded. That is a different state from a
  certificate with blank fields.
- `trust_bundle` is **absent entirely** when `GOWEB_MTLS_CLIENT_CA` is unset.
  It is not `null` — a pod that is not doing client verification has no bundle
  to describe, so the key is not there at all. Branch on its presence.
- `trust_bundle.anchors[].fingerprint_sha256` is what a rotation should be
  asserted on. A replacement CA commonly reuses the subject DN of the one it
  replaces, so `subject` alone cannot tell the new CA from the old.
- `trust_bundle.stale_seconds` counts from the last successful read of the
  bundle, and `last_error` is non-empty while reloads are failing. Together
  they mean "the pool being enforced is no longer the one on disk". Neither
  affects `readiness`.
- `dns_names` and `uris` are always arrays, never `null`.
- `unverified_headers` echoes `X-Forwarded-For`, `X-Real-IP` and `X-Request-ID`
  exactly as received. They are client supplied. Do not treat them as identity
  unless a proxy in front of this server overwrites them.
- Timestamps are RFC 3339 in the server's own zone.

> **Probe endpoints changed.** Earlier versions had no dedicated probe paths, so
> the manifests below used `/status` and `/`. Use `/livez` and `/readyz` instead
> and update existing manifests accordingly. A certificate that fails to reload
> is not fixed by restarting the process, which is why it degrades readiness
> rather than liveness.

# Client certificate authentication

Client-certificate verification is off unless `GOWEB_MTLS_CLIENT_CA` is set.
It is a listener-wide setting — every TLS handshake on the port may present a
client certificate — but only `/whoami` and `/whoami.json` require one.
`/livez`, `/readyz`, `/status` and `/status.json` never require a client
certificate and work whether or not one is configured. They also work when
one is configured but the caller presents none. What they cannot survive is
a *presented* certificate that fails verification: under
`VerifyClientCertIfGiven`, that aborts the TLS handshake before any route
runs, so every endpoint on the listener fails alike — see the three-outcome
table below. Kubernetes probes keep working unchanged only because probes
never present a client certificate.

`/` is not unaffected: it always prints the SNI name from the handshake, and
when the caller presented a certificate the server verified, it additionally
prints that certificate's subject, SANs and validity period. All of this is
new output; see the config table above for how verification is enabled in
the first place.

Because a client certificate is only ever optional at the TLS layer, there
are three observable outcomes, not two:

| Client behaviour | Result |
| --- | --- |
| No client certificate | TLS succeeds; `GET /whoami` returns `403` |
| Certificate not signed by a configured CA | TLS handshake fails; no HTTP response (curl exits `56`, `tlsv1 alert unknown ca`) |
| Certificate signed by a configured CA | TLS succeeds; `GET /whoami` returns `200` |

The middle row is not a `403`. An untrusted client certificate aborts the TLS
handshake before any HTTP request is ever read, so nothing about the
response can be inspected — an external suite has to assert on a connection
error there, not on a status code.

The trust store named by `GOWEB_MTLS_CLIENT_CA` is validated on every read,
at startup and on every reload: every certificate in the file must be a genuine CA — a valid
`BasicConstraints` extension with `IsCA` set, `KeyUsage` including
`CertSign`, and inside its validity window. Requiring `CertSign` is stricter
than RFC 5280, which permits a CA certificate to omit the `KeyUsage`
extension entirely; a legitimate private-PKI root built that way is refused
here by design, not because the file is corrupt. A file that cannot be
read, contains no PEM certificate, contains a block that is not a valid CA,
or contains a CERTIFICATE block whose PEM armour is malformed and was
silently dropped by the decoder, fails startup outright — naming the
offending certificate, or the block count that does not add up — rather
than silently leaving client-certificate verification disabled or
half-trusting a bundle. Once running, the same file is watched and the same
checks are applied to every reload: see [Trust bundle
reloading](#trust-bundle-reloading).

Generate a client CA and a client certificate signed by it, then call the
endpoint the way an external suite would:

> **Never point `GOWEB_MTLS_CLIENT_CA` at `certs/demo.pem`.** `certs/demo.pem`
> is a server leaf, not a CA, and `certs/demo-key.pem` is committed alongside
> it, so pointing client-certificate verification at it would have made
> anyone with this public repository a trusted client. That misuse is no
> longer just discouraged: trust-store validation rejects any file that
> isn't built from genuine CAs, so this now fails startup outright instead
> of silently trusting whoever holds the demo key. `GOWEB_MTLS_CLIENT_CA`
> names the client CA generated below (`client-ca.pem`); `--cacert
> ./certs/demo.pem` in the command below is unrelated — that's curl
> verifying the server's identity, not the server trusting a client.

```bash
make certs-client
make build && GOWEB_MTLS_CLIENT_CA=./certs/client-ca.pem ./bin/server &

curl --cacert ./certs/demo.pem \
     --resolve raf.tech:8443:127.0.0.1 \
     --cert ./certs/client.pem --key ./certs/client-key.pem \
     https://raf.tech:8443/whoami.json
```

The demo certificate's SANs are `*.raf.tech` and `raf.tech` — not `localhost`
— so `--resolve` points the hostname the certificate is actually valid for at
the loopback address, rather than skipping server verification with `-k`
inside the very section that teaches certificate verification.

```json
{"authenticated":true,"client":{"subject":"CN=goweb-client","issuer":"CN=goweb-client-ca","serial":"83851253258372398577627422287466861029","fingerprint_sha256":"e7467fda77ae120de4e71a9659106479a1ae8fbc2cd97f4bf8d7656305166a0f","dns_names":[],"uris":[],"email_addresses":[],"ip_addresses":[],"not_before":"2026-08-18T04:02:28Z","not_after":"2036-08-15T05:02:28Z","expires_in_seconds":315359986,"chain":["CN=goweb-client","CN=goweb-client-ca"]}}
```

Without a client certificate, `/whoami.json` returns `403` and:

```json
{"authenticated":false,"reason":"no client certificate presented"}
```

Both are single-line, compact JSON — no indentation, no spaces after `:` or
`,` — unlike `/status.json`. `/status` is read by operators in a terminal,
where indentation earns its bytes; `/whoami` exists to be matched, logged and
diffed by e2e suites in other repositories, where layout is noise. Every
response body is followed by exactly one trailing newline. `authenticated`
is always present, so a consumer can branch on one field rather than on the
absence of another.

`/whoami` and `/whoami.json` send `Cache-Control: no-store` on every
response, including refusals — the body carries one client's identity keyed
only by the URL, and a cache must never store it and replay it to a
different client. `/whoami` and `/status` additionally send `Vary: Accept`,
since both negotiate their representation from that header; the dedicated
`.json` endpoints have exactly one representation and don't send it.

`/` sends the same `Cache-Control: no-store`, unconditionally, for the same
reason — it too prints the verified client's identity when one is present.
It cannot use `Vary` to describe that: a client certificate is not a request
header, so no `Vary` value exists that would tell a cache the response
differs by caller. `/status` and `/status.json` carry no per-client
information and deliberately send neither header.

# Certificate reloading

The certificate is reloaded while the server runs, without dropping connections:

- The parent directories of the certificate and key are watched, so Kubernetes
  atomic/symlink rotations of projected volumes and mounted secrets are observed
  even though the events never name the configured file.
- Event bursts are debounced, and a partially written or mismatched key pair is
  retried rather than published.
- Changes are detected by comparing a SHA-256 fingerprint of the certificate,
  not its modification time, so a rotation that preserves or backdates the
  timestamp is still picked up.
- A periodic reconciliation runs regardless of events, so a lost event cannot
  strand an old certificate indefinitely.
- If a reload fails, the last valid certificate keeps being served and the
  failure is surfaced through `/readyz` and `/status`.

# Trust bundle reloading

The client CA trust bundle named by `GOWEB_MTLS_CLIENT_CA` is watched the same
way, on the same `GOWEB_RELOAD_DEBOUNCE` and `GOWEB_RELOAD_INTERVAL` knobs and
through the same loop. Adding or removing a trusted CA takes effect on the next
handshake, with no restart. Connections already established keep the pool they
were authenticated under.

Two rules govern what a reload may publish, and both exist because the
interesting failure here opens the door rather than closing it:

- **A failed reload never replaces the pool.** An unreadable file, a bundle
  that parses to nothing, a block that is not a genuine CA, or a CERTIFICATE
  block whose armour is malformed all leave the previous pool in force. This is
  not merely conservative: Go substitutes the *system* root pool when the
  configured client CA pool is `nil`, so publishing nothing would not reject
  every client — it would accept every publicly issued client certificate as a
  verified identity.
- **A smaller bundle applies immediately.** Removing a CA is how revocation is
  expressed here, so a bundle with fewer CAs is published as soon as it parses.
  There is no rule that the pool may only grow and no waiting for a second
  reconcile to agree, because either would delay a revocation by up to one
  `GOWEB_RELOAD_INTERVAL`.

> **Replace the bundle atomically. Do not rewrite it in place.** Kubernetes
> projected volumes, ConfigMaps, Secrets and ClusterTrustBundles all write a new
> timestamped directory and swap a `..data` symlink over it, so a reader never
> observes a half-written file. A writer that rewrites the file in place can be
> read mid-write, and a partially written bundle that still parses is
> indistinguishable from a deliberate revocation — no reader-side logic can tell
> the two apart, which is why this is an operational requirement rather than a
> tolerated risk.

## Readiness is deliberately asymmetric

A stale or unreadable **trust bundle does not fail `/readyz`**, while a stale
serving certificate still does.

The asymmetry is the point. Without a valid serving certificate the pod cannot
serve TLS at all. With a stale trust bundle it serves perfectly well and may
merely be trusting a CA that has since been removed — and pulling a working test
fixture out of service for a degraded-but-functioning condition costs more than
it buys, especially mid-run for a suite in another repository.

The condition is not silent. It is logged at warning level on every failed
reconcile and reported in `/status.json` as `trust_bundle.last_error` and
`trust_bundle.stale_seconds`, so an operator or a suite can see it and decide
for itself.

A dead *watcher* is a different matter and is still fatal: it means rotation is
no longer observed at all and cannot recover without a restart, so it brings the
process down rather than being logged and ignored.

# Releases

Releases are cut by CI. Nothing is tagged, built or pushed by hand.

Every PR into `main` must carry exactly one label, which decides the version
bump. CI fails the PR if the label is missing or ambiguous.

| Label | Effect on merge |
| ----- | --------------- |
| `release/major` | Bumps `X` — breaking change. |
| `release/minor` | Bumps `Y` — new feature or improvement. |
| `release/patch` | Bumps `Z` — fix or small change. |
| `release/skip` | No tag, no image, no release. |

On merge of a non-skip PR, CI resolves the next version from the newest
existing tag, re-runs `go vet` and `go test -race` against the merge commit,
creates the tag, builds and pushes the image, and only then publishes the
GitHub release. The release is created last, so a version is never advertised
whose image failed to build.

## Published image

```
ghcr.io/rafpe/goweb-https/server:vX.Y.Z   # exact release
ghcr.io/rafpe/goweb-https/server:vX.Y     # newest patch of that minor
ghcr.io/rafpe/goweb-https/server:vX       # newest minor of that major
ghcr.io/rafpe/goweb-https/server:latest   # newest release
```

Images are built for `linux/amd64` and `linux/arm64`, carry an SPDX SBOM
attestation, and are signed keyless with cosign. Verify a release with:

```bash
cosign verify ghcr.io/rafpe/goweb-https/server:vX.Y.Z \
  --certificate-identity-regexp '^https://github.com/RafPe/goweb-https/' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

To release without merging a PR, run the **Release** workflow manually and pick
the bump.

# Development

```bash
make test         # go test -race -cover ./...
make lint         # golangci-lint, installed into ./bin on first use
make build        # binary into ./bin/server
make run          # run from source
make certs        # regenerate the self-signed demo certificates
make certs-client # generate a client CA and client certificate for mTLS testing
```

`make docker-build` and `make docker-push` still exist for local use, but
merging to `main` publishes the image, so neither is needed for a release.

The demo certificates in `certs/` are self-signed and committed so the server
starts with no configuration. Regenerate them with `make certs`.

# k8s manifest
Sample manifests which can be used to explore the https based simple server. 

## Using simple native resources with preconfigured certificate to use
```yaml
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: goweb
  labels:
    app: goweb-https
spec:
  replicas: 1
  selector:
    matchLabels:
      app: goweb-https
  template:
    metadata:
      labels:
        app: goweb-https     
    spec:
      containers:
      - name: server
        image: ghcr.io/rafpe/goweb-https/server:latest
        ports:
        - containerPort: 8443
          name: https
          protocol: TCP
        env:
        - name: GOWEB_PORT
          value: "8443"
        - name: GOWEB_X509_KEY
          value: /app/combined.pem
        - name: GOWEB_X509_CER
          value: /app/combined.pem
        - name: TZ
          value: "Europe/Amsterdam"
        - name: POD_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: POD_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
        volumeMounts:
        - name: combined-cert
          mountPath: /app/combined.pem
          subPath: combined.pem
          readOnly: true
        resources:
          requests:
            memory: "64Mi"
            cpu: "50m"
          limits:
            memory: "128Mi"
            cpu: "100m"
        livenessProbe:
          httpGet:
            path: /livez
            port: 8443
            scheme: HTTPS
          initialDelaySeconds: 30
          periodSeconds: 30
          timeoutSeconds: 10
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /readyz
            port: 8443
            scheme: HTTPS
          initialDelaySeconds: 10
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        securityContext:
          allowPrivilegeEscalation: false
          runAsNonRoot: true
          runAsUser: 65532
          runAsGroup: 65532
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
      volumes:
      - name: combined-cert
        secret:
          secretName: https-server-combined-cert
          defaultMode: 0400
      securityContext:
        fsGroup: 65532
      restartPolicy: Always
      terminationGracePeriodSeconds: 30
```

## Using Kubernetes v1.34+ PodCertificate and associated custom signer ( in development )

```yaml
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: goweb
  labels:
    app: goweb-https
spec:
  replicas: 1
  selector:
    matchLabels:
      app: goweb-https
  template:
    metadata:
      labels:
        app: goweb-https
      annotations:
        coolcert.example.com/foo-cn: "some-epic-name.com"
        coolcert.example.com/foo-san: "example.com, www.example.com, anotherexample.com.cy"
        coolcert.example.com/foo-duration: "1h"
        coolcert.example.com/foo-refresh: "49m"        
    spec:
      containers:
      - name: server
        image: ghcr.io/rafpe/goweb-https/server:latest        
        ports:
        - containerPort: 8443
          name: https
          protocol: TCP
        env:
        - name: GOWEB_PORT
          value: "8443"
        - name: GOWEB_X509_BUNDLE
          value: /var/run/pcr-x509/credentialbundle.pem
        - name: TZ
          value: "Europe/Nicosia"
        - name: POD_NAME
          valueFrom:
            fieldRef:
              fieldPath: metadata.name
        - name: POD_NAMESPACE
          valueFrom:
            fieldRef:
              fieldPath: metadata.namespace
        volumeMounts:
        - name: pcr-x509
          mountPath: /var/run/pcr-x509
          readOnly: true
        resources:
          requests:
            memory: "64Mi"
            cpu: "50m"
          limits:
            memory: "128Mi"
            cpu: "100m"
        livenessProbe:
          httpGet:
            path: /livez
            port: 8443
            scheme: HTTPS
          initialDelaySeconds: 30
          periodSeconds: 30
          timeoutSeconds: 10
          failureThreshold: 3
        # With a 1h certificate refreshed at 49m, a rotation the server fails to
        # pick up must take the pod out of service before the old material
        # expires. Readiness - not liveness - is the right signal: restarting
        # does not fix a certificate that will not load.
        readinessProbe:
          httpGet:
            path: /readyz
            port: 8443
            scheme: HTTPS
          initialDelaySeconds: 10
          periodSeconds: 10
          timeoutSeconds: 5
          failureThreshold: 3
        securityContext:
          allowPrivilegeEscalation: false
          runAsNonRoot: true
          runAsUser: 65532
          runAsGroup: 65532
          readOnlyRootFilesystem: true
          capabilities:
            drop:
            - ALL
      volumes:
      - name: pcr-x509
        projected:
          defaultMode: 420
          sources:
          - podCertificate:
              keyType: RSA4096
              signerName: coolcert.example.com/foo
              credentialBundlePath: credentialbundle.pem
      securityContext:
        fsGroup: 65532
      restartPolicy: Always
      terminationGracePeriodSeconds: 5
```


