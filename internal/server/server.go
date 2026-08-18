// Package server assembles the HTTPS listener, its routes, and the handlers
// that report certificate and process state.
package server

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/RafPe/goweb-https/internal/certreload"
	"github.com/RafPe/goweb-https/internal/clientauth"
)

// CertificateStatusProvider is the narrow view of the certificate reloader that
// the handlers need.
//
// It is declared here, by the consumer, rather than alongside the
// implementation: certreload returns its concrete *Reloader and knows nothing
// about this package.
type CertificateStatusProvider interface {
	// CertificateInfo describes the served certificate. The boolean reports
	// whether one has been published.
	CertificateInfo() (certreload.Info, bool)

	// Ready reports whether the certificate source is healthy enough to serve.
	Ready() error
}

// TrustBundleStatusProvider is the narrow view of the client CA trust bundle
// that the handlers need.
//
// It is declared beside CertificateStatusProvider rather than folded into it
// because the served identity and the trust store are independent sources with
// independent health: widening the one interface would force the certificate
// reloader to grow trust methods it has no business having.
type TrustBundleStatusProvider interface {
	// Status describes the trust bundle and how well it is tracking its source.
	Status() clientauth.BundleStatus
}

// Dependencies carries the collaborators and process facts the handlers need.
// Passing them explicitly keeps the handlers deterministic under test and
// removes the process-derived package globals they would otherwise read.
type Dependencies struct {
	Certificates CertificateStatusProvider
	Logger       *slog.Logger
	Now          func() time.Time
	Location     *time.Location
	Hostname     string
	PodName      string
	PodNamespace string

	// ClientCAs is the trust store that client certificates are verified
	// against. When nil, no client certificate is requested and the routes
	// that need one always refuse.
	ClientCAs *x509.CertPool

	// TrustBundle reports the client CA trust bundle on the diagnostic
	// endpoint. Nil when client-certificate verification is disabled, which is
	// what makes the trust_bundle block absent rather than empty.
	TrustBundle TrustBundleStatusProvider

	// StartedAt is when serving began, which is what uptime should measure -
	// not when the process happened to initialise its packages.
	StartedAt time.Time
}

// Timeouts applied to the HTTP server.
const (
	readHeaderTimeout = 5 * time.Second
	readTimeout       = 10 * time.Second
	writeTimeout      = 10 * time.Second
	idleTimeout       = 120 * time.Second
)

// Server owns the HTTPS listener and its lifecycle.
type Server struct {
	http            *http.Server
	logger          *slog.Logger
	shutdownTimeout time.Duration

	// baseTLS is the template every derived config is cloned from. It is built
	// once, before the listener starts, and never mutated afterwards: a
	// tls.Config must not be modified once it has been used. Nil when
	// client-certificate verification is disabled.
	baseTLS *tls.Config

	// clientTLS holds the config handed to each handshake. A whole config is
	// swapped rather than a field, because concurrent handshakes read the one
	// they were given and mutating it underneath them is a data race.
	clientTLS atomic.Pointer[tls.Config]
}

// New builds a Server listening on addr and serving TLS via getCertificate.
func New(addr string, shutdownTimeout time.Duration, getCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error), deps Dependencies) (*Server, error) {
	if deps.Certificates == nil {
		return nil, errors.New("server: certificate status provider is required")
	}
	if getCertificate == nil {
		return nil, errors.New("server: certificate callback is required")
	}
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	if deps.Now == nil {
		deps.Now = time.Now
	}
	if deps.Location == nil {
		deps.Location = time.UTC
	}
	if shutdownTimeout <= 0 {
		return nil, errors.New("server: shutdown timeout must be positive")
	}

	// Client certificates are optional at the listener and required only by
	// the routes that ask for one. Requiring them here would stop /livez and
	// /readyz working, because probes present no certificate - the pod would
	// never become ready.
	tlsConfig := &tls.Config{
		GetCertificate: getCertificate,
		MinVersion:     tls.VersionTLS13,
	}

	srv := &Server{
		logger:          deps.Logger,
		shutdownTimeout: shutdownTimeout,
		http: &http.Server{
			Addr:              addr,
			Handler:           routes(deps),
			TLSConfig:         tlsConfig,
			ReadHeaderTimeout: readHeaderTimeout,
			ReadTimeout:       readTimeout,
			WriteTimeout:      writeTimeout,
			IdleTimeout:       idleTimeout,
			ErrorLog:          slog.NewLogLogger(deps.Logger.Handler(), slog.LevelWarn),
		},
	}

	if deps.ClientCAs != nil {
		tlsConfig.ClientAuth = tls.VerifyClientCertIfGiven
		tlsConfig.ClientCAs = deps.ClientCAs

		// The template is captured before the hook is installed, so a derived
		// config never carries a self-reference back into this one.
		srv.baseTLS = tlsConfig.Clone()
		srv.clientTLS.Store(srv.baseTLS)
		tlsConfig.GetConfigForClient = srv.configForClient
	}

	return srv, nil
}

// configForClient implements the tls.Config.GetConfigForClient callback.
//
// It performs an atomic load and nothing else: no filesystem access, parsing,
// locking or logging happens on the handshake path. Handing the same config to
// concurrent handshakes is safe because it is read only.
func (s *Server) configForClient(*tls.ClientHelloInfo) (*tls.Config, error) {
	return s.clientTLS.Load(), nil
}

// SetClientCAs publishes a new client CA trust pool, which subsequent
// handshakes verify against. Already-established connections keep the pool they
// were authenticated under; the change applies from the next handshake.
//
// It is the callback the trust bundle reloader invokes on a successful
// rotation, and it is a no-op when client-certificate verification is disabled:
// a rotation must not be able to switch verification on behind the operator's
// back.
//
// A nil pool is refused rather than published. crypto/tls passes ClientCAs
// straight into x509.VerifyOptions.Roots, and crypto/x509 substitutes the
// system root pool when Roots is nil - so publishing nil here would not reject
// every client but accept every publicly issued client certificate as a
// verified identity. Retaining the last known good pool is the only safe answer
// to being handed nothing.
//
// The new config is derived by cloning the base rather than being built from
// scratch, because a config returned from GetConfigForClient replaces the base
// wholesale: GetCertificate and MinVersion have to ride along, and cloning is
// what stops them being lost by omission.
func (s *Server) SetClientCAs(pool *x509.CertPool) {
	if s.baseTLS == nil {
		return
	}
	if pool == nil {
		s.logger.Error("refusing to publish a nil client CA pool; retaining the previous trust store")
		return
	}

	derived := s.baseTLS.Clone()
	derived.ClientAuth = tls.VerifyClientCertIfGiven
	derived.ClientCAs = pool
	s.clientTLS.Store(derived)
}

// routes builds the request multiplexer.
//
// Patterns are method scoped, so an unknown path is a 404 and an unsupported
// method a 405, rather than the catch-all pattern answering everything.
func routes(deps Dependencies) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", handleRoot(deps))
	mux.HandleFunc("GET /status", handleStatus(deps))
	// A dedicated path for machine consumers. This is a separate URL rather
	// than a deployment-wide format switch so that the response type is a
	// property of the endpoint, identical in every deployment, instead of
	// something a scraper has to know the pod's configuration to predict.
	mux.HandleFunc("GET /status.json", handleStatusJSON(deps))
	// The client identity the handshake proved. A separate path from /status
	// because it answers a different question and, unlike /status, refuses
	// callers it cannot identify.
	mux.HandleFunc("GET /whoami", handleWhoami(deps))
	mux.HandleFunc("GET /whoami.json", handleWhoamiJSON(deps))
	mux.HandleFunc("GET /livez", handleLive())
	mux.HandleFunc("GET /readyz", handleReady(deps))
	return mux
}

// Run serves until ctx is cancelled, then drains in-flight requests within the
// configured shutdown timeout.
//
// A normal shutdown returns nil. http.ErrServerClosed is expected during
// shutdown and is not reported as a failure; every other serving or shutdown
// error is returned rather than merely logged.
func (s *Server) Run(ctx context.Context) error {
	serveErr := make(chan error, 1)
	go func() {
		// The certificate and key are supplied through TLSConfig.GetCertificate.
		serveErr <- s.http.ListenAndServeTLS("", "")
	}()

	select {
	case err := <-serveErr:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve https on %s: %w", s.http.Addr, err)

	case <-ctx.Done():
		s.logger.Info("shutdown signal received, draining connections",
			"timeout", s.shutdownTimeout)

		// A fresh context: the shutdown budget must not inherit the
		// cancellation that triggered it.
		shutdownCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), s.shutdownTimeout)
		defer cancel()

		shutdownErr := s.http.Shutdown(shutdownCtx)

		// Shutdown returns once listeners are closed; wait for the serving
		// goroutine so a serving failure is not lost.
		if err := <-serveErr; err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve https on %s: %w", s.http.Addr, err)
		}
		if shutdownErr != nil {
			return fmt.Errorf("drain connections: %w", shutdownErr)
		}
		return nil
	}
}
