# goweb-https
Simple GO based web server using HTTPs that supports reading certificates from a given directory and uses SNI in order to serve simple request along with loaded certificates and their status. 

Its purpose is to help you when securing/working with SSL certificates for your pods in your Kubernetes cluster environment.

Please be mindful it is in `development` and subject to change.


# Configuration

This simple webserver allows for minimalistic configuration of the following fields.

## Certificate material

| Variable           | Priority | Purpose |
| --------           | -------  | ------- |
| GOWEB_X509_BUNDLE  | 1        | Defines the combined key and certificate file path to be used. |
| GOWEB_X509_KEY     | 2        | Defines key file path. |
| GOWEB_X509_CER     | 2        | Defines certificate file path. |

> In terms of priority `GOWEB_X509_BUNDLE` is considered first over cert and file paths.

Defaults to `./certs/demo.pem` and `./certs/demo-key.pem`. These exist in a
source checkout but are **not** included in the container image, so a deployment
must always mount its own certificate material and set the variables above.

## Server

| Variable | Default | Purpose |
| -------- | ------- | ------- |
| GOWEB_PORT | `8443` | Listen port. |
| TZ / TIMEZONE | `UTC` | Display timezone for timestamps. `TZ` is checked first, then `TIMEZONE`. An unknown zone is ignored with a warning. |
| POD_NAME | – | Shown on `/status` when set. |
| POD_NAMESPACE | – | Shown on `/status` when set. |

> The default display timezone is now `UTC`. It was previously a fixed `UTC+3`
> zone, so timestamps shift for anyone who did not set `TZ` or `TIMEZONE`.

# Endpoints

| Path | Purpose |
| ---- | ------- |
| `/` | Landing page showing host, time, and peer certificate details. |
| `/status` | Certificate and process status. |

Routes are method scoped. Unknown paths return **404** and unsupported methods
return **405**. Previously every path was served by the `/` handler.

# Behaviour

- The certificate is reloaded while the server runs when the certificate file
  changes on disk, so a rotated secret is picked up without a restart.
- If a reload fails, or the certificate file is briefly missing during a
  rotation, the last valid certificate keeps being served.
- Read, write, and idle timeouts are set on the HTTP server.
- `SIGTERM` and `SIGINT` start a graceful shutdown with a **10 second** window to
  drain in-flight connections. Set `terminationGracePeriodSeconds` above 10 in
  your manifests so Kubernetes does not `SIGKILL` the pod mid-drain.

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
            path: /status
            port: 8443
            scheme: HTTPS
          initialDelaySeconds: 30
          periodSeconds: 30
          timeoutSeconds: 10
          failureThreshold: 3
        readinessProbe:
          httpGet:
            path: /
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
      # Must exceed the server's 10s connection drain window.
      terminationGracePeriodSeconds: 30
```


