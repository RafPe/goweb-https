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
| GOWEB_RELOAD_DEBOUNCE | `500ms` | Quiet period after a filesystem event before re-reading. |
| GOWEB_RELOAD_INTERVAL | `30s` | Periodic reconciliation against disk, independent of events. |
| GOWEB_MAX_STALE_PERIOD | `15m` | How long the source may be unreadable before `/readyz` fails. |
| GOWEB_ALLOW_EXPIRED_CERTIFICATE | `false` | Start with an already-expired certificate and report it instead of exiting. |
| POD_NAME / POD_NAMESPACE | – | Shown on `/status`. |

# Endpoints

| Path | Purpose |
| ---- | ------- |
| `/` | Landing page showing host, time, and peer certificate details. |
| `/status` | Human-readable certificate and process diagnostics. |
| `/status.json` | The same information as plain JSON, for machine consumers. |
| `/livez` | Liveness. Reports only that the HTTP loop is running. |
| `/readyz` | Readiness. Fails when no usable certificate exists, when the served certificate is outside its validity period, or when the source has been unreadable for longer than `GOWEB_MAX_STALE_PERIOD`. |

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
  "readiness": { "ready": true }
}
```

Notes for consumers:

- `validity` is one of `valid`, `not_yet_valid`, `expired`.
- `expires_in_seconds` goes negative once the certificate has expired, so a
  scrape can alert on a single number.
- `certificate` is `null` when none is loaded. That is a different state from a
  certificate with blank fields.
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
make test    # go test -race -cover ./...
make lint    # golangci-lint, installed into ./bin on first use
make build   # binary into ./bin/server
make run     # run from source
make certs   # regenerate the self-signed demo certificates
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


