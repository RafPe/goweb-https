package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Global variable to track server start time
var startTime = time.Now()

// Get local timezone or configured timezone
var localTZ = getLocalTimezone()

type CertReloader struct {
	certMu            sync.RWMutex
	CertFile          string // path to the x509 certificate for https
	KeyFile           string // path to the x509 private key matching `CertFile`
	certInfo          *CertificateInfo
	cachedCert        *tls.Certificate
	cachedCertModTime time.Time
}
type CertificateInfo struct {
	Certificate *tls.Certificate
	X509Cert    *x509.Certificate
	Domains     []string
	URIs        []string
	FilePath    string
	LoadedAt    time.Time
}

func NewCertReloader(certFile, keyFile string) *CertReloader {
	return &CertReloader{
		CertFile: certFile,
		KeyFile:  keyFile,
	}
}

func (cr *CertReloader) Initialize() error {
	modTime, err := cr.getFileInfo(cr.CertFile)
	if err != nil {
		return err
	}
	cr.cachedCertModTime = modTime.ModTime() // Set the initial modification time on the file

	tlsCertificate, err := cr.loadCertificate()
	if err != nil {
		return err
	}
	cr.cachedCert = tlsCertificate // Set the initially loaded certificate

	certificateInfo, err := cr.parseCertificateInfo(tlsCertificate)
	if err != nil {
		return err
	}
	cr.certInfo = certificateInfo // Set the initially parsed certificate info

	cr.printCertificateDetails()

	return nil
}

// Implementation for tls.Config.GetCertificate - practical when running with PodCertificates mounted volumes
// or secrets with TLS certificates which can be potentially updated.
func (cr *CertReloader) GetCertificate(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
	stat, err := cr.getFileInfo(cr.CertFile)
	if err != nil {
		return nil, err
	}

	if cr.cachedCert == nil || stat.ModTime().After(cr.cachedCertModTime) {
		log.Printf("(re)Loading certificate\n")

		pair, err := cr.loadCertificate()
		if err != nil {
			return nil, err
		}
		cr.certMu.RLock()
		defer cr.certMu.RUnlock()

		cr.certInfo, err = cr.parseCertificateInfo(pair)
		if err != nil {
			return nil, fmt.Errorf("failed to parse certificate info: %w", err)
		}

		cr.cachedCert = pair
		cr.cachedCertModTime = stat.ModTime()
	}

	return cr.cachedCert, nil
}

func (cr *CertReloader) GetCertificateInfo() *CertificateInfo {
	return cr.certInfo
}

func (cr *CertReloader) loadCertificate() (*tls.Certificate, error) {
	pair, err := tls.LoadX509KeyPair(cr.CertFile, cr.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("failed loading tls key pair: %w", err)
	}
	return &pair, nil
}

func (cr *CertReloader) parseCertificateInfo(cert *tls.Certificate) (*CertificateInfo, error) {

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse x509 certificate: %w", err)
	}

	// Check if certificate is expired or not yet valid
	now := time.Now()
	if now.Before(x509Cert.NotBefore) {
		validIn := x509Cert.NotBefore.Sub(now).Truncate(time.Second)
		log.Printf("WARNING: Certificate %s is not yet valid (valid in %s)", cr.CertFile, validIn)
	}
	if now.After(x509Cert.NotAfter) {
		expiredFor := now.Sub(x509Cert.NotAfter).Truncate(time.Second)
		return nil, fmt.Errorf("Certificate %s has EXPIRED %s ago", cr.CertFile, expiredFor)
	}

	certificateInfo := &CertificateInfo{
		Certificate: cert,
		X509Cert:    x509Cert,
		Domains:     cr.extractSANs(x509Cert),
		URIs:        cr.extractURIs(x509Cert),
		FilePath:    cr.CertFile,
		LoadedAt:    time.Now(),
	}

	return certificateInfo, nil
}

func (cr *CertReloader) extractSANs(cert *x509.Certificate) []string {
	var domains []string

	for _, san := range cert.DNSNames {
		domains = append(domains, strings.ToLower(san))
	}

	return domains
}

func (cr *CertReloader) extractURIs(cert *x509.Certificate) []string {
	var uris []string

	for _, uri := range cert.URIs {
		uris = append(uris, strings.ToLower(uri.String()))
	}

	return uris
}

func (cr *CertReloader) getFileInfo(filePath string) (os.FileInfo, error) {
	stat, err := os.Stat(filePath)
	if err != nil {
		return stat, fmt.Errorf("failed checking key file modification time: %w", err)
	}
	return stat, nil
}

func getEnvOrDefault(envVar, defaultValue string) string {
	envVar, exists := os.LookupEnv(envVar)
	if !exists {
		envVar = defaultValue
	}
	return envVar
}

func (cr *CertReloader) printCertificateDetails() {
	now := time.Now()
	log.Printf("Certificate loaded from: %s", cr.CertFile)
	log.Printf("  Subject: %s", cr.certInfo.X509Cert.Subject.String())
	log.Printf("  Issuer: %s", cr.certInfo.X509Cert.Issuer.String())
	log.Printf("  Serial: %s", cr.certInfo.X509Cert.SerialNumber.String())
	log.Printf("  Valid: %s to %s",
		formatTimeWithTimezone(cr.certInfo.X509Cert.NotBefore),
		formatTimeWithTimezone(cr.certInfo.X509Cert.NotAfter))

	if now.After(cr.certInfo.X509Cert.NotAfter) {
		expiredFor := now.Sub(cr.certInfo.X509Cert.NotAfter).Truncate(time.Second)
		log.Printf("  ⚠️  EXPIRED %s ago", expiredFor)
	} else if now.Before(cr.certInfo.X509Cert.NotBefore) {
		validIn := cr.certInfo.X509Cert.NotBefore.Sub(now).Truncate(time.Second)
		log.Printf("  ⚠️  NOT YET VALID (valid in %s)", validIn)
	} else if cr.certInfo.X509Cert.NotAfter.Sub(now) < 30*time.Minute {
		timeUntilExpiry := cr.certInfo.X509Cert.NotAfter.Sub(now).Truncate(time.Second)
		log.Printf("  ⚠️  EXPIRES SOON (in %s)", timeUntilExpiry)
	} else {
		timeUntilExpiry := cr.certInfo.X509Cert.NotAfter.Sub(now).Truncate(time.Second)
		log.Printf("  ✅ Valid (expires in %s)", timeUntilExpiry)
	}

	log.Printf("  Domains: %v", cr.certInfo.Domains)
}

func getLocalTimezone() *time.Location {
	// Check environment variables for timezone
	if tzEnv := os.Getenv("TZ"); tzEnv != "" {
		if loc, err := time.LoadLocation(tzEnv); err == nil {
			return loc
		}
	}

	// Check for common timezone environment variables
	if tzEnv := os.Getenv("TIMEZONE"); tzEnv != "" {
		if loc, err := time.LoadLocation(tzEnv); err == nil {
			return loc
		}
	}

	// Default to UTC+3 (could be Europe/Athens, Europe/Istanbul, etc.)
	// You can customize this to your specific timezone
	utcPlus3 := time.FixedZone("UTC+3", 3*60*60)
	return utcPlus3
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
	w.WriteHeader(http.StatusOK)

	log.Printf("Handling request /")

	// Get hostname information
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	fmt.Fprintf(w, "Hello there! I am serving this content via https :) \n")
	fmt.Fprintf(w, "🖥️ Server: %s\n", hostname)
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

		// Get hostname information
		hostname, err := os.Hostname()
		if err != nil {
			hostname = "unknown"
		}

		fmt.Fprintf(w, "🖥️  Server Information:\n")
		fmt.Fprintf(w, "   Hostname: %s\n", hostname)
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

	certReloader := NewCertReloader(getEnvOrDefault("GOWEB_CERT_FILE", "./certs/demo.pem"), getEnvOrDefault("GOWEB_KEY_FILE", "./certs/demo-key.pem"))
	if err := certReloader.Initialize(); err != nil {
		log.Fatal("ERROR: Failed to initialize certificate reloader: ", err)
	}

	tlsConfig := &tls.Config{
		GetCertificate: certReloader.GetCertificate,
		MinVersion:     tls.VersionTLS13,
	}

	http.HandleFunc("/", handlerRoot)
	http.HandleFunc("/status", handlerStatus(certReloader))

	// Get port from environment variable, default to 8443
	port := getEnvOrDefault("GOWEB_PORT", "8443")

	server := &http.Server{
		Addr:      ":" + port,
		TLSConfig: tlsConfig,
	}

	log.Printf("Init completed ... \n")
	log.Printf("  🚀 Production-ready HTTPS server starting on :%s\n", port)
	log.Printf("  📜 Loaded certificate with domains: %v\n", certReloader.GetCertificateInfo().Domains)
	log.Printf("  🔍 Certificate status available at: https://localhost:%s/status\n", port)

	err := server.ListenAndServeTLS("", "")
	if err != nil {
		log.Fatal("Server failed to start: ", err)
	}
}
