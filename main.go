package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// Global variable to track server start time
var startTime = time.Now()

// Get local timezone or configured timezone
var localTZ = getLocalTimezone()

type CertificateManager struct {
	certMap     map[string]*tls.Certificate
	certDetails map[string]*CertificateInfo
}

type CertificateInfo struct {
	Certificate *tls.Certificate
	X509Cert    *x509.Certificate
	Domains     []string
	FilePath    string
	LoadedAt    time.Time
}

func NewCertificateManager() *CertificateManager {
	return &CertificateManager{
		certMap:     make(map[string]*tls.Certificate),
		certDetails: make(map[string]*CertificateInfo),
	}
}

// LoadCertificatesFromDirectory scans a directory for certificate files
func (cm *CertificateManager) LoadCertificatesFromDirectory(dir string) error {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("failed to read directory %s: %w", dir, err)
	}

	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}

		name := entry.Name()
		if strings.HasSuffix(name, ".pem") || strings.HasSuffix(name, ".crt") {
			certPath := filepath.Join(dir, name)
			keyPath := certPath // Assume combined file first

			// Check if there's a separate key file
			keyName := strings.TrimSuffix(name, filepath.Ext(name)) + ".key"
			separateKeyPath := filepath.Join(dir, keyName)
			if _, err := os.Stat(separateKeyPath); err == nil {
				keyPath = separateKeyPath
			}

			if err := cm.LoadCertificate(certPath, keyPath); err != nil {
				log.Printf("Warning: Failed to load %s: %v", certPath, err)
			}
		}
	}

	return nil
}

func (cm *CertificateManager) LoadCertificate(certFile, keyFile string) error {
	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return fmt.Errorf("failed to load certificate %s/%s: %w", certFile, keyFile, err)
	}

	x509Cert, err := x509.ParseCertificate(cert.Certificate[0])
	if err != nil {
		return fmt.Errorf("failed to parse certificate: %w", err)
	}

	// Check if certificate is expired or not yet valid
	now := time.Now()
	if now.Before(x509Cert.NotBefore) {
		validIn := x509Cert.NotBefore.Sub(now).Truncate(time.Second)
		log.Printf("Warning: Certificate %s is not yet valid (valid in %s)", certFile, validIn)
	}
	if now.After(x509Cert.NotAfter) {
		expiredFor := now.Sub(x509Cert.NotAfter).Truncate(time.Second)
		log.Printf("Warning: Certificate %s has EXPIRED %s ago", certFile, expiredFor)
	}

	domains := cm.extractDomains(x509Cert)
	if len(domains) == 0 {
		return fmt.Errorf("no valid domains found in certificate %s", certFile)
	}

	certInfo := &CertificateInfo{
		Certificate: &cert,
		X509Cert:    x509Cert,
		Domains:     domains,
		FilePath:    certFile,
		LoadedAt:    time.Now(),
	}

	// Map each domain to this certificate
	for _, domain := range domains {
		if existingCert, exists := cm.certMap[domain]; exists {
			// Check which certificate is newer/better
			existingInfo := cm.getCertificateInfo(existingCert)
			if existingInfo != nil && x509Cert.NotAfter.After(existingInfo.X509Cert.NotAfter) {
				log.Printf("Replacing certificate for domain '%s' with newer certificate", domain)
			} else {
				log.Printf("Keeping existing certificate for domain '%s'", domain)
				continue
			}
		}

		cm.certMap[domain] = &cert
		cm.certDetails[domain] = certInfo
		log.Printf("Mapped domain '%s' to certificate from %s", domain, certFile)
	}

	cm.logCertificateDetails(x509Cert, domains, certFile)
	return nil
}

func (cm *CertificateManager) getCertificateInfo(cert *tls.Certificate) *CertificateInfo {
	for _, info := range cm.certDetails {
		if info.Certificate == cert {
			return info
		}
	}
	return nil
}

func (cm *CertificateManager) extractDomains(cert *x509.Certificate) []string {
	var domains []string
	seen := make(map[string]bool)

	// Add Common Name
	if cert.Subject.CommonName != "" && cm.isValidDomain(cert.Subject.CommonName) {
		domains = append(domains, strings.ToLower(cert.Subject.CommonName))
		seen[strings.ToLower(cert.Subject.CommonName)] = true
	}

	// Add SANs
	for _, san := range cert.DNSNames {
		lowerSan := strings.ToLower(san)
		if !seen[lowerSan] && cm.isValidDomain(san) {
			domains = append(domains, lowerSan)
			seen[lowerSan] = true
		}
	}

	return domains
}

func (cm *CertificateManager) isValidDomain(domain string) bool {
	if domain == "" {
		return false
	}

	domain = strings.TrimSpace(domain)
	if strings.ContainsAny(domain, " \t\n\r") {
		return false
	}

	// Allow wildcards and regular domains
	if strings.HasPrefix(domain, "*.") {
		domain = domain[2:]
	}

	return strings.Contains(domain, ".") || domain == "localhost"
}

func (cm *CertificateManager) GetCertificate(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	serverName := strings.ToLower(clientHello.ServerName)
	log.Printf("SNI requested: '%s'", serverName)

	// Exact match
	if cert, ok := cm.certMap[serverName]; ok {
		log.Printf("Exact match found for %s", serverName)
		return cert, nil
	}

	// Wildcard matching
	for domain, cert := range cm.certMap {
		if strings.HasPrefix(domain, "*.") {
			wildcardSuffix := domain[2:]
			if strings.HasSuffix(serverName, "."+wildcardSuffix) || serverName == wildcardSuffix {
				log.Printf("Wildcard match: %s matches %s", serverName, domain)
				return cert, nil
			}
		}
	}

	// Fallback to any available certificate
	for domain, cert := range cm.certMap {
		log.Printf("No match for '%s', using fallback certificate for domain '%s'", serverName, domain)
		return cert, nil
	}

	return nil, fmt.Errorf("no certificates available")
}

func (cm *CertificateManager) logCertificateDetails(cert *x509.Certificate, domains []string, filePath string) {
	now := time.Now()
	log.Printf("Certificate loaded from: %s", filePath)
	log.Printf("  Subject: %s", cert.Subject.String())
	log.Printf("  Issuer: %s", cert.Issuer.String())
	log.Printf("  Serial: %s", cert.SerialNumber.String())
	log.Printf("  Valid: %s to %s",
		formatTimeWithTimezone(cert.NotBefore),
		formatTimeWithTimezone(cert.NotAfter))

	if now.After(cert.NotAfter) {
		expiredFor := now.Sub(cert.NotAfter).Truncate(time.Second)
		log.Printf("  ⚠️  EXPIRED %s ago", expiredFor)
	} else if now.Before(cert.NotBefore) {
		validIn := cert.NotBefore.Sub(now).Truncate(time.Second)
		log.Printf("  ⚠️  NOT YET VALID (valid in %s)", validIn)
	} else if cert.NotAfter.Sub(now) < 30*24*time.Hour {
		timeUntilExpiry := cert.NotAfter.Sub(now).Truncate(time.Second)
		log.Printf("  ⚠️  EXPIRES SOON (in %s)", timeUntilExpiry)
	} else {
		timeUntilExpiry := cert.NotAfter.Sub(now).Truncate(time.Second)
		log.Printf("  ✅ Valid (expires in %s)", timeUntilExpiry)
	}

	log.Printf("  Domains: %v", domains)
}

func (cm *CertificateManager) GetStatus() map[string]*CertificateInfo {
	return cm.certDetails
}

func statusHandler(cm *CertificateManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")

		// Get hostname information
		hostname, err := os.Hostname()
		if err != nil {
			hostname = "unknown"
		}

		fmt.Fprintf(w, "🖥️  Server Information:\n")
		fmt.Fprintf(w, "   Hostname: %s\n", hostname)

		// Add container/pod specific information if available
		if podName := os.Getenv("POD_NAME"); podName != "" {
			fmt.Fprintf(w, "   Pod Name: %s\n", podName)
		}
		if podNamespace := os.Getenv("POD_NAMESPACE"); podNamespace != "" {
			fmt.Fprintf(w, "   Pod Namespace: %s\n", podNamespace)
		}
		if nodeName := os.Getenv("NODE_NAME"); nodeName != "" {
			fmt.Fprintf(w, "   Node Name: %s\n", nodeName)
		}
		if containerName := os.Getenv("CONTAINER_NAME"); containerName != "" {
			fmt.Fprintf(w, "   Container: %s\n", containerName)
		}

		// Docker container ID (if available)
		if containerID := getContainerID(); containerID != "" {
			fmt.Fprintf(w, "   Container ID: %s\n", containerID[:12]) // Show first 12 chars like docker ps
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

		for domain, info := range cm.GetStatus() {
			fmt.Fprintf(w, "Domain: %s\n", domain)
			fmt.Fprintf(w, "  File: %s\n", info.FilePath)
			fmt.Fprintf(w, "  CN: %s\n", info.X509Cert.Subject.CommonName)
			fmt.Fprintf(w, "  Valid: %s to %s\n",
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
				if timeUntilExpiry < 30*24*time.Hour {
					fmt.Fprintf(w, "  Status: ⚠️  EXPIRES SOON (in %s)\n", timeUntilExpiry)
				} else {
					fmt.Fprintf(w, "  Status: ✅ Valid (expires in %s)\n", timeUntilExpiry)
				}
			}
			fmt.Fprint(w, "\n")
		}
	}
}

// Helper function to get container ID from /proc/self/cgroup (Linux containers)
func getContainerID() string {
	data, err := os.ReadFile("/proc/self/cgroup")
	if err != nil {
		return ""
	}

	lines := strings.Split(string(data), "\n")
	for _, line := range lines {
		if strings.Contains(line, "/docker/") {
			parts := strings.Split(line, "/")
			if len(parts) > 0 {
				containerID := parts[len(parts)-1]
				if len(containerID) >= 12 {
					return containerID
				}
			}
		}
		// Handle other container runtimes
		if strings.Contains(line, "/containerd/") {
			parts := strings.Split(line, "/")
			if len(parts) > 0 {
				containerID := parts[len(parts)-1]
				if len(containerID) >= 12 {
					return containerID
				}
			}
		}
	}

	return ""
}

// Get timezone from environment or default to UTC+3
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

// Format time in both UTC and local timezone
func formatTimeWithTimezone(t time.Time) string {
	utcTime := t.UTC().Format("2006-01-02 15:04:05 UTC")
	localTime := t.In(localTZ).Format("2006-01-02 15:04:05 MST")

	if utcTime == localTime {
		return utcTime
	}
	return fmt.Sprintf("%s (%s)", localTime, utcTime)
}

func helloHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	// Get hostname information
	hostname, err := os.Hostname()
	if err != nil {
		hostname = "unknown"
	}

	fmt.Fprintf(w, "I am ok in https\n")
	fmt.Fprintf(w, "🖥️  Server: %s\n", hostname)
	fmt.Fprintf(w, "⏰ Time: %s\n", formatTimeWithTimezone(time.Now()))
	fmt.Fprintf(w, "🌐 Client IP: %s\n", r.RemoteAddr)

	connState := r.TLS
	if connState != nil && len(connState.PeerCertificates) > 0 {
		cert := connState.PeerCertificates[0]
		fmt.Fprintf(w, "🔐 SNI: %s\n", connState.ServerName)
		fmt.Fprintf(w, "📜 Certificate CN: %s\n", cert.Subject.CommonName)
		fmt.Fprintf(w, "🏷️  Certificate SANs: %v\n", cert.DNSNames)
		fmt.Fprintf(w, "⏳ Certificate Valid: %s to %s\n",
			formatTimeWithTimezone(cert.NotBefore),
			formatTimeWithTimezone(cert.NotAfter))
	}
}

func main() {
	certManager := NewCertificateManager()

	// Load from directory (configurable via environment variable)
	certificatesDir := os.Getenv("GOWEB_CERT_DIRECTORY_PATH")
	if certificatesDir == "" {
		certificatesDir = "./certs"
	}

	// // Load from individual files
	// if err := certManager.LoadCertificate("combined.pem", "combined.pem"); err != nil {
	// 	log.Printf("Warning: %v", err)
	// }

	// Optionally load from a directory
	if err := certManager.LoadCertificatesFromDirectory(certificatesDir); err != nil {
		log.Printf("Warning: Failed to load certificates from directory: %v", err)
	}

	domains := make([]string, 0, len(certManager.certMap))
	for domain := range certManager.certMap {
		domains = append(domains, domain)
	}

	if len(domains) == 0 {
		log.Fatal("No certificates loaded successfully")
	}

	tlsConfig := &tls.Config{
		GetCertificate: certManager.GetCertificate,
		MinVersion:     tls.VersionTLS13,
	}

	http.HandleFunc("/", helloHandler)
	http.HandleFunc("/status", statusHandler(certManager))

	// Get port from environment variable, default to 8443
	port := os.Getenv("GOWEB_PORT")
	if port == "" {
		port = "8443"
	}

	server := &http.Server{
		Addr:      ":" + port,
		TLSConfig: tlsConfig,
	}

	fmt.Printf("🚀 Production-ready HTTPS server starting on :%s\n", port)
	fmt.Printf("📜 Loaded certificates for domains: %v\n", domains)
	fmt.Printf("🔍 Certificate status available at: https://localhost:%s/status\n", port)

	err := server.ListenAndServeTLS("", "")
	if err != nil {
		log.Fatal("Server failed to start: ", err)
	}
}
