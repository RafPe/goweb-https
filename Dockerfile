# Build the server binary.
#
# --platform=$BUILDPLATFORM keeps the build stage native to the build host, so
# foreign target architectures are cross-compiled via GOARCH instead of emulated.
FROM --platform=$BUILDPLATFORM golang:1.24 AS builder
ARG TARGETOS
ARG TARGETARCH

WORKDIR /workspace

# Copy the Go module manifests and download dependencies first, so that source
# changes do not invalidate the dependency layer.
COPY go.mod go.sum ./
RUN go mod download

# Copy the go source. The command lives under cmd/ and its packages under
# internal/, so whole directories are copied rather than a single file.
COPY cmd/ cmd/
COPY internal/ internal/

# The GOARCH has no default value, which allows the binary to be built for the
# host that invoked the build when no target platform was requested.
#
# -trimpath removes local filesystem paths from the binary and -s -w strips the
# symbol and DWARF tables, both of which make the output smaller and more
# reproducible.
RUN CGO_ENABLED=0 GOOS=${TARGETOS:-linux} GOARCH=${TARGETARCH} \
    go build -trimpath -ldflags="-s -w" -o server ./cmd/goweb-https

# Use distroless as minimal base image to package the server binary.
# Refer to https://github.com/GoogleContainerTools/distroless for more details
FROM gcr.io/distroless/static:nonroot

LABEL org.opencontainers.image.source="https://github.com/rafpe/goweb-https"
LABEL org.opencontainers.image.description="HTTPS server demonstrating certificate rotation in Kubernetes"
LABEL org.opencontainers.image.licenses="Apache-2.0"

WORKDIR /
COPY --from=builder /workspace/server .
USER 65532:65532

ENTRYPOINT ["/server"]
