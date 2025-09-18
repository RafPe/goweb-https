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
		log.Printf("Warning: Certificate %s is not yet valid (valid from %s)", certFile, x509Cert.NotBefore)
	}
	if now.After(x509Cert.NotAfter) {
		log.Printf("Warning: Certificate %s has expired (expired %s)", certFile, x509Cert.NotAfter)
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
	log.Printf("Certificate loaded from: %s", filePath)
	log.Printf("  Subject: %s", cert.Subject.String())
	log.Printf("  Issuer: %s", cert.Issuer.String())
	log.Printf("  Serial: %s", cert.SerialNumber.String())
	log.Printf("  Valid: %s to %s", cert.NotBefore.Format(time.RFC3339), cert.NotAfter.Format(time.RFC3339))

	if time.Now().After(cert.NotAfter) {
		log.Printf("  ⚠️  EXPIRED")
	} else if time.Until(cert.NotAfter) < 30*24*time.Hour {
		log.Printf("  ⚠️  EXPIRES SOON (within 30 days)")
	}

	log.Printf("  Domains: %v", domains)
}

func (cm *CertificateManager) GetStatus() map[string]*CertificateInfo {
	return cm.certDetails
}

func statusHandler(cm *CertificateManager) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprint(w, "Certificate Status:\n\n")

		for domain, info := range cm.GetStatus() {
			fmt.Fprintf(w, "Domain: %s\n", domain)
			fmt.Fprintf(w, "  File: %s\n", info.FilePath)
			fmt.Fprintf(w, "  CN: %s\n", info.X509Cert.Subject.CommonName)
			fmt.Fprintf(w, "  Valid: %s to %s\n",
				info.X509Cert.NotBefore.Format(time.RFC3339),
				info.X509Cert.NotAfter.Format(time.RFC3339))

			if time.Now().After(info.X509Cert.NotAfter) {
				fmt.Fprint(w, "  Status: EXPIRED\n")
			} else {
				fmt.Fprintf(w, "  Status: Valid (expires in %s)\n", time.Until(info.X509Cert.NotAfter).Truncate(time.Hour))
			}
			fmt.Fprint(w, "\n")
		}
	}
}

func helloHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)

	connState := r.TLS
	if connState != nil && len(connState.PeerCertificates) > 0 {
		cert := connState.PeerCertificates[0]
		fmt.Fprintf(w, "I am ok in https\n")
		fmt.Fprintf(w, "SNI: %s\n", connState.ServerName)
		fmt.Fprintf(w, "Certificate CN: %s\n", cert.Subject.CommonName)
		fmt.Fprintf(w, "Certificate SANs: %v\n", cert.DNSNames)
		fmt.Fprintf(w, "Certificate Valid: %s to %s\n",
			cert.NotBefore.Format(time.RFC3339),
			cert.NotAfter.Format(time.RFC3339))
	} else {
		fmt.Fprint(w, "I am ok in https")
	}
}

func main() {
	certManager := NewCertificateManager()

	// load from a directory
	if err := certManager.LoadCertificatesFromDirectory("./certs"); err != nil {
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
		//MinVersion:     tls.VersionTLS12,
	}

	http.HandleFunc("/", helloHandler)
	http.HandleFunc("/status", statusHandler(certManager))

	server := &http.Server{
		Addr:      ":8443",
		TLSConfig: tlsConfig,
	}

	fmt.Println("🚀 Production-ready HTTPS server starting on :8443")
	fmt.Printf("📜 Loaded certificates for domains: %v\n", domains)
	fmt.Println("🔍 Certificate status available at: https://localhost:8443/status")

	err := server.ListenAndServeTLS("", "")
	if err != nil {
		log.Fatal("Server failed to start: ", err)
	}
}
