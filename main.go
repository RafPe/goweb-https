package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"
)

// Package-level state resolved once at startup.
var (
	startTime      = time.Now()
	localTZ        = getLocalTimezone()
	serverHostname = getHostname()
)

type CertificateInfo struct {
	X509Cert *x509.Certificate
	Domains  []string
	FilePath string
}

// certSnapshot is an immutable view of the currently served certificate.
// Reloads publish a new snapshot atomically, so readers never need a lock.
type certSnapshot struct {
	cert    *tls.Certificate
	info    *CertificateInfo
	modTime time.Time
}

type CertReloader struct {
	CertFile string // path to the x509 certificate for https
	KeyFile  string // path to the x509 private key matching `CertFile`

	reloadMu sync.Mutex // serializes reloads; readers go through `current`
	current  atomic.Pointer[certSnapshot]
}

func NewCertReloader(certFile, keyFile string) *CertReloader {
	return &CertReloader{
		CertFile: certFile,
		KeyFile:  keyFile,
	}
}

func (cr *CertReloader) Initialize() error {
	if err := cr.reload(); err != nil {
		return err
	}

	cr.printCertificateDetails()

	return nil
}

// reload loads the key pair from disk and atomically replaces the current snapshot.
func (cr *CertReloader) reload() error {
	stat, err := os.Stat(cr.CertFile)
	if err != nil {
		return fmt.Errorf("failed to stat certificate file %s: %w", cr.CertFile, err)
	}

	pair, err := tls.LoadX509KeyPair(cr.CertFile, cr.KeyFile)
	if err != nil {
		return fmt.Errorf("failed loading tls key pair: %w", err)
	}

	info, err := parseCertificateInfo(&pair, cr.CertFile)
	if err != nil {
		return err
	}

	cr.current.Store(&certSnapshot{
		cert:    &pair,
		info:    info,
		modTime: stat.ModTime(),
	})

	return nil
}

// Implementation for tls.Config.GetCertificate - practical when running with PodCertificates mounted volumes
// or secrets with TLS certificates which can be potentially updated.
func (cr *CertReloader) GetCertificate(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
	snap := cr.current.Load()

	stat, err := os.Stat(cr.CertFile)
	if err != nil {
		// The certificate file can be briefly unavailable while Kubernetes
		// rotates a mounted secret; keep serving the cached certificate.
		if snap != nil {
			log.Printf("WARNING: cannot stat certificate file %s (%v), serving cached certificate", cr.CertFile, err)
			return snap.cert, nil
		}
		return nil, err
	}

	if snap == nil || stat.ModTime().After(snap.modTime) {
		cr.reloadMu.Lock()
		defer cr.reloadMu.Unlock()

		// Re-check under the lock; a concurrent handshake may have reloaded already.
		snap = cr.current.Load()
		if snap == nil || stat.ModTime().After(snap.modTime) {
			log.Printf("(re)Loading certificate from %s", cr.CertFile)
			if err := cr.reload(); err != nil {
				if snap != nil {
					log.Printf("WARNING: certificate reload failed (%v), serving cached certificate", err)
					return snap.cert, nil
				}
				return nil, err
			}
			snap = cr.current.Load()
		}
	}

	return snap.cert, nil
}

func (cr *CertReloader) GetCertificateInfo() *CertificateInfo {
	if snap := cr.current.Load(); snap != nil {
		return snap.info
	}
	return nil
}

func parseCertificateInfo(cert *tls.Certificate, filePath string) (*CertificateInfo, error) {
	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse x509 certificate: %w", err)
	}

	// Check if certificate is expired or not yet valid
	now := time.Now()
	if now.Before(x509Cert.NotBefore) {
		validIn := x509Cert.NotBefore.Sub(now).Truncate(time.Second)
		log.Printf("WARNING: Certificate %s is not yet valid (valid in %s)", filePath, validIn)
	}
	if now.After(x509Cert.NotAfter) {
		expiredFor := now.Sub(x509Cert.NotAfter).Truncate(time.Second)
		return nil, fmt.Errorf("certificate %s expired %s ago", filePath, expiredFor)
	}

	return &CertificateInfo{
		X509Cert: x509Cert,
		Domains:  extractSANs(x509Cert),
		FilePath: filePath,
	}, nil
}

func extractSANs(cert *x509.Certificate) []string {
	var domains []string

	for _, san := range cert.DNSNames {
		domains = append(domains, strings.ToLower(san))
	}

	return domains
}

func getCertificateKeyPairPaths() (string, string) {
	// This function is implemented to support scenario where we provide a PEM file instead of separate certificate and key files.
	// GOWEB_X509_BUNDLE env variable is used to indicate that we are using a bundle file and takes precedence over GOWEB_X509_CER and GOWEB_X509_KEY ( if all provided )

	// # GOWEB_X509_CER      - certificate file path
	// # GOWEB_X509_KEY      - key file path
	// # GOWEB_X509_BUNDLE   - bundle file path ( key and certificate in one file )

	bundlePath, useBundle := os.LookupEnv("GOWEB_X509_BUNDLE")
	if useBundle {
		log.Printf("Using bundle file: %s", bundlePath)
		return bundlePath, bundlePath
	}

	certFile := getEnvOrDefault("GOWEB_X509_CER", "./certs/demo.pem")
	keyFile := getEnvOrDefault("GOWEB_X509_KEY", "./certs/demo-key.pem")

	log.Printf("Using certificate file: %s", certFile)
	log.Printf("Using key file: %s", keyFile)

	return certFile, keyFile
}

func getEnvOrDefault(name, defaultValue string) string {
	if value, exists := os.LookupEnv(name); exists {
		return value
	}
	return defaultValue
}

func (cr *CertReloader) printCertificateDetails() {
	now := time.Now()
	info := cr.GetCertificateInfo()

	log.Printf("Certificate loaded from: %s", info.FilePath)
	log.Printf("  Subject: %s", info.X509Cert.Subject.String())
	log.Printf("  Issuer: %s", info.X509Cert.Issuer.String())
	log.Printf("  Serial: %s", info.X509Cert.SerialNumber.String())
	log.Printf("  Valid: %s to %s",
		formatTimeWithTimezone(info.X509Cert.NotBefore),
		formatTimeWithTimezone(info.X509Cert.NotAfter))

	if now.After(info.X509Cert.NotAfter) {
		expiredFor := now.Sub(info.X509Cert.NotAfter).Truncate(time.Second)
		log.Printf("  ⚠️  EXPIRED %s ago", expiredFor)
	} else if now.Before(info.X509Cert.NotBefore) {
		validIn := info.X509Cert.NotBefore.Sub(now).Truncate(time.Second)
		log.Printf("  ⚠️  NOT YET VALID (valid in %s)", validIn)
	} else if info.X509Cert.NotAfter.Sub(now) < 30*time.Minute {
		timeUntilExpiry := info.X509Cert.NotAfter.Sub(now).Truncate(time.Second)
		log.Printf("  ⚠️  EXPIRES SOON (in %s)", timeUntilExpiry)
	} else {
		timeUntilExpiry := info.X509Cert.NotAfter.Sub(now).Truncate(time.Second)
		log.Printf("  ✅ Valid (expires in %s)", timeUntilExpiry)
	}

	log.Printf("  Domains: %v", info.Domains)
}

func getLocalTimezone() *time.Location {
	// Check common timezone environment variables
	for _, envVar := range []string{"TZ", "TIMEZONE"} {
		if tzEnv := os.Getenv(envVar); tzEnv != "" {
			if loc, err := time.LoadLocation(tzEnv); err == nil {
				return loc
			}
			log.Printf("WARNING: invalid timezone %q in %s, ignoring", tzEnv, envVar)
		}
	}

	return time.UTC
}

func getHostname() string {
	hostname, err := os.Hostname()
	if err != nil {
		return "unknown"
	}
	return hostname
}

func formatTimeWithTimezone(t time.Time) string {
	utcTime := t.UTC().Format("2006-01-02 15:04:05 UTC")
	localTime := t.In(localTZ).Format("2006-01-02 15:04:05 MST")

	if utcTime == localTime {
		return utcTime
	}
	return fmt.Sprintf("%s (%s)", localTime, utcTime)
}

func handlerRoot(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	log.Printf("Handling request %s", r.URL.Path)

	fmt.Fprintf(w, "Hello there! I am serving this content via https :) \n")
	fmt.Fprintf(w, "🖥️ Server: %s\n", serverHostname)
	fmt.Fprintf(w, "⏰ Time: %s\n", formatTimeWithTimezone(time.Now()))
	fmt.Fprintf(w, "🌐 Client IP: %s\n", r.RemoteAddr)

	connState := r.TLS
	if connState != nil && len(connState.PeerCertificates) > 0 {
		cert := connState.PeerCertificates[0]
		fmt.Fprintf(w, "🔐 SNI: %s\n", connState.ServerName)
		fmt.Fprintf(w, "📜 Certificate CN: %s\n", cert.Subject.CommonName)
		fmt.Fprintf(w, "🏷️ Certificate SANs: %v\n", cert.DNSNames)
		fmt.Fprintf(w, "⏳ Certificate Valid: %s to %s\n",
			formatTimeWithTimezone(cert.NotBefore),
			formatTimeWithTimezone(cert.NotAfter))
	}
}

func handlerStatus(cm *CertReloader) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		log.Printf("Handling request /status")

		fmt.Fprintf(w, "🖥️  Server Information:\n")
		fmt.Fprintf(w, "   Hostname: %s\n", serverHostname)
		if podName := os.Getenv("POD_NAME"); podName != "" {
			fmt.Fprintf(w, "   Pod Name: %s\n", podName)
		}
		if podNamespace := os.Getenv("POD_NAMESPACE"); podNamespace != "" {
			fmt.Fprintf(w, "   Pod Namespace: %s\n", podNamespace)
		}

		fmt.Fprintf(w, "   Server Time: %s\n", formatTimeWithTimezone(time.Now()))
		fmt.Fprintf(w, "   Uptime: %s\n", time.Since(startTime).Truncate(time.Second))
		fmt.Fprintf(w, "   Request From: %s\n", r.RemoteAddr)
		fmt.Fprintf(w, "   User-Agent: %s\n", r.UserAgent())

		// Add request headers that might indicate load balancer info
		if forwarded := r.Header.Get("X-Forwarded-For"); forwarded != "" {
			fmt.Fprintf(w, "   X-Forwarded-For: %s\n", forwarded)
		}
		if realIP := r.Header.Get("X-Real-IP"); realIP != "" {
			fmt.Fprintf(w, "   X-Real-IP: %s\n", realIP)
		}
		if requestID := r.Header.Get("X-Request-ID"); requestID != "" {
			fmt.Fprintf(w, "   X-Request-ID: %s\n", requestID)
		}

		fmt.Fprint(w, "\n📜 Certificate Status:\n\n")

		info := cm.GetCertificateInfo()
		fmt.Fprintf(w, "File: %s\n", info.FilePath)
		fmt.Fprintf(w, "Issuer: %s\n", info.X509Cert.Issuer.String())
		fmt.Fprintf(w, "Serial: %s\n", info.X509Cert.SerialNumber.String())
		fmt.Fprintf(w, "CN: %s\n", info.X509Cert.Subject.CommonName)
		fmt.Fprintf(w, "Domains:\n")
		for _, domain := range info.Domains {
			fmt.Fprintf(w, "  Domain: %s\n", domain)
		}
		fmt.Fprintf(w, "Valid: %s to %s\n",
			formatTimeWithTimezone(info.X509Cert.NotBefore),
			formatTimeWithTimezone(info.X509Cert.NotAfter))

		now := time.Now()
		if now.After(info.X509Cert.NotAfter) {
			expiredFor := now.Sub(info.X509Cert.NotAfter).Truncate(time.Second)
			fmt.Fprintf(w, "  Status: ❌ EXPIRED (expired %s ago)\n", expiredFor)
		} else if now.Before(info.X509Cert.NotBefore) {
			validIn := info.X509Cert.NotBefore.Sub(now).Truncate(time.Second)
			fmt.Fprintf(w, "  Status: ⏳ NOT YET VALID (valid in %s)\n", validIn)
		} else {
			timeUntilExpiry := info.X509Cert.NotAfter.Sub(now).Truncate(time.Second)
			if timeUntilExpiry < 30*time.Minute {
				fmt.Fprintf(w, "  Status: ⚠️  EXPIRES SOON (in %s)\n", timeUntilExpiry)
			} else {
				fmt.Fprintf(w, "  Status: ✅ Valid (expires in %s)\n", timeUntilExpiry)
			}
		}
		fmt.Fprint(w, "\n")

	}
}

func main() {

	certFile, keyFile := getCertificateKeyPairPaths()

	certReloader := NewCertReloader(
		certFile,
		keyFile,
	)
	if err := certReloader.Initialize(); err != nil {
		log.Fatal("ERROR: Failed to initialize certificate reloader: ", err)
	}

	tlsConfig := &tls.Config{
		GetCertificate: certReloader.GetCertificate,
		MinVersion:     tls.VersionTLS13,
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{$}", handlerRoot)
	mux.HandleFunc("GET /status", handlerStatus(certReloader))

	// Get port from environment variable, default to 8443
	port := getEnvOrDefault("GOWEB_PORT", "8443")

	server := &http.Server{
		Addr:              ":" + port,
		Handler:           mux,
		TLSConfig:         tlsConfig,
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	log.Printf("Init completed ...")
	log.Printf("  🚀 HTTPS server starting on :%s", port)
	log.Printf("  📜 Loaded certificate with domains: %v", certReloader.GetCertificateInfo().Domains)
	log.Printf("  🔍 Certificate status available at: https://localhost:%s/status", port)

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	serveErr := make(chan error, 1)
	go func() {
		serveErr <- server.ListenAndServeTLS("", "")
	}()

	select {
	case err := <-serveErr:
		log.Fatal("Server failed to start: ", err)
	case <-ctx.Done():
		log.Printf("Shutdown signal received, draining connections ...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Printf("WARNING: graceful shutdown failed: %v", err)
		}
	}
}
