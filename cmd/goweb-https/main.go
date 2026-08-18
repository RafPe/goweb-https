// Command goweb-https serves a diagnostic HTTPS endpoint backed by a
// certificate that is reloaded as it is rotated on disk.
package main

import (
	"context"
	"crypto/x509"
	"errors"
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

	// The trust store is loaded once. It changes on a different timescale
	// from the served certificate, and a restart is an acceptable way to
	// pick up a new one.
	var (
		clientCAs        *x509.CertPool
		clientCASubjects []string
	)
	if cfg.ClientCAFile != "" {
		clientCAs, clientCASubjects, err = clientauth.LoadPool(cfg.ClientCAFile)
		if err != nil {
			return err
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

	srv, err := server.New(cfg.Address, cfg.ShutdownTimeout, reloader.GetCertificate, server.Dependencies{
		Certificates: reloader,
		Logger:       logger,
		Now:          time.Now,
		Location:     cfg.Timezone,
		Hostname:     hostname,
		PodName:      cfg.PodName,
		PodNamespace: cfg.PodNamespace,
		StartedAt:    time.Now(),
		ClientCAs:    clientCAs,
	})
	if err != nil {
		return err
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
		"client_ca_subjects", clientCASubjects,
	)

	ctx, stop := signal.NotifyContext(ctx, os.Interrupt, syscall.SIGTERM)
	defer stop()

	return runComponents(ctx, srv.Run, reloader.Watch)
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
