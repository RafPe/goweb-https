// Command goweb-https serves a diagnostic HTTPS endpoint backed by a
// certificate that is reloaded as it is rotated on disk.
package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/RafPe/goweb-https/internal/certreload"
	"github.com/RafPe/goweb-https/internal/clientauth"
	"github.com/RafPe/goweb-https/internal/config"
	"github.com/RafPe/goweb-https/internal/server"
)

func main() {
	if err := run(context.Background()); err != nil {
		slog.Error("application stopped", "err", err)
		os.Exit(1)
	}
}

// run assembles the application and blocks until it stops.
//
// Every failure is returned rather than terminating the process from depth, so
// deferred cleanup runs and the exit decision stays in main.
func run(ctx context.Context) error {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: slog.LevelInfo}))
	slog.SetDefault(logger)

	cfg, err := config.Load()
	if err != nil {
		return err
	}

	// The trust store tracks its file the way the served certificate does: in
	// Kubernetes it is a projected volume updated in place, so a restart is not
	// an acceptable way to pick up a rotated bundle.
	var trustBundle *clientauth.Bundle
	if cfg.ClientCAFile != "" {
		trustBundle, err = clientauth.NewBundle(cfg.ClientCAFile,
			clientauth.WithLogger(logger),
			clientauth.WithDebounce(cfg.ReloadDebounce),
			clientauth.WithReconcileInterval(cfg.ReloadInterval),
		)
		if err != nil {
			return fmt.Errorf("load client CA trust store: %w", err)
		}
	}

	reloader, err := certreload.New(cfg.CertificateFile, cfg.KeyFile,
		certreload.WithLogger(logger),
		certreload.WithDebounce(cfg.ReloadDebounce),
		certreload.WithReconcileInterval(cfg.ReloadInterval),
		certreload.WithMaximumStalePeriod(cfg.MaximumStalePeriod),
		certreload.AllowExpired(cfg.AllowExpiredCertificate),
	)
	if err != nil {
		return err
	}

	hostname, err := os.Hostname()
	if err != nil {
		logger.Warn("could not determine hostname", "err", err)
		hostname = "unknown"
	}

	deps := server.Dependencies{
		Certificates: reloader,
		Logger:       logger,
		Now:          time.Now,
		Location:     cfg.Timezone,
		Hostname:     hostname,
		PodName:      cfg.PodName,
		PodNamespace: cfg.PodNamespace,
		StartedAt:    time.Now(),
	}
	// Assigned inside the guard rather than unconditionally: a nil *Bundle
	// stored in the interface field would be a non-nil interface holding a nil
	// pointer, and the status handler would report a trust bundle that does not
	// exist rather than omitting the block.
	var trustAnchors []clientauth.Anchor
	if trustBundle != nil {
		deps.ClientCAs = trustBundle.Pool()
		deps.TrustBundle = trustBundle
		trustAnchors = trustBundle.Anchors()
	}

	srv, err := server.New(cfg.Address, cfg.ShutdownTimeout, reloader.GetCertificate, deps)
	if err != nil {
		return err
	}

	// Registered after the server exists, so the first pool the server sees is
	// the one New was given and every later one arrives through here. A
	// rotation landing in the gap is not lost: the bundle's watcher reconciles
	// once at startup, which is after this point.
	if trustBundle != nil {
		trustBundle.OnChange(srv.SetClientCAs)
	}

	if info, ok := reloader.CertificateInfo(); ok {
		logger.Info("certificate loaded",
			"certificate_file", info.FilePath,
			"subject", info.Subject,
			"issuer", info.Issuer,
			"serial", info.Serial,
			"fingerprint", info.Fingerprint,
			"dns_names", info.DNSNames,
			"uris", info.URIs,
			"not_before", info.NotBefore,
			"not_after", info.NotAfter,
		)
	}
	logger.Info("starting https server",
		"address", cfg.Address,
		"reload_interval", cfg.ReloadInterval,
		"shutdown_timeout", cfg.ShutdownTimeout,
		"client_certificate_verification", cfg.ClientCAFile != "",
		"client_ca_file", cfg.ClientCAFile,
		"client_ca_trust_anchors", clientauth.AnchorLogFields(trustAnchors),
	)

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	// The trust bundle's watcher joins the same lifecycle as the certificate
	// watcher and the server: a watcher that terminates means rotation is no
	// longer observed and cannot recover without a restart, which the
	// orchestrator should see as the process failing rather than as a silently
	// degraded pod. Note this differs from the bundle merely being stale, which
	// is reported and deliberately does not fail readiness.
	components := []func(context.Context) error{srv.Run, reloader.Watch}
	if trustBundle != nil {
		components = append(components, trustBundle.Watch)
	}

	return runComponents(ctx, components...)
}

// runComponents runs each component until one returns, then cancels the rest
// and waits for them.
//
// The certificate watcher and the HTTP server share a lifecycle: a watcher that
// terminates means rotation is no longer observed, which the orchestrator
// should see as the process failing rather than as a silently degraded pod.
func runComponents(ctx context.Context, components ...func(context.Context) error) error {
	ctx, cancel := context.WithCancel(ctx)
	defer cancel()

	errs := make([]error, len(components))

	var wg sync.WaitGroup
	wg.Add(len(components))
	for i, component := range components {
		go func() {
			defer wg.Done()
			// The first component to return brings the others down with it.
			defer cancel()
			errs[i] = component(ctx)
		}()
	}
	wg.Wait()

	return errors.Join(errs...)
}
