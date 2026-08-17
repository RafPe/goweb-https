// Command gencerts regenerates the self-signed demo certificate used when no
// certificate is configured.
//
// The demo material is committed so the server starts out of the box, which
// means it expires on a schedule nobody is watching. Regenerating it is one
// command - `make certs` - rather than a sequence of openssl invocations
// recalled from memory, and the profile below is the one a TLS server
// certificate should actually have.
package main

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func main() {
	var (
		dir        = flag.String("dir", "certs", "directory to write the demo material into")
		commonName = flag.String("common-name", "*.raf.tech", "certificate common name")
		dnsNames   = flag.String("dns-names", "*.raf.tech,raf.tech", "comma-separated DNS subject alternative names")
		validFor   = flag.Duration("valid-for", 10*365*24*time.Hour, "how long the certificate stays valid")
	)
	flag.Parse()

	if err := run(*dir, *commonName, splitAndTrim(*dnsNames), *validFor); err != nil {
		log.Fatalf("generate demo certificates: %v", err)
	}
}

func run(dir, commonName string, dnsNames []string, validFor time.Duration) error {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return fmt.Errorf("generate serial: %w", err)
	}

	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     dnsNames,
		NotBefore:    now.Add(-time.Hour),
		NotAfter:     now.Add(validFor),

		// A server leaf, not a CA. The previous regeneration produced
		// CA:TRUE with no key usage at all, which does not model the profile
		// this project exists to demonstrate.
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		return fmt.Errorf("create certificate: %w", err)
	}

	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("marshal key: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}

	files := map[string][]byte{
		"demo.pem":     certPEM,
		"demo-key.pem": keyPEM,
		// The bundle holds the key followed by the certificate, matching the
		// layout GOWEB_X509_BUNDLE expects.
		"bundle.pem": append(append([]byte{}, keyPEM...), certPEM...),
	}
	for name, content := range files {
		path := filepath.Join(dir, name)
		mode := os.FileMode(0o644)
		if strings.Contains(name, "key") || name == "bundle.pem" {
			mode = 0o600
		}
		if err := os.WriteFile(path, content, mode); err != nil {
			return fmt.Errorf("write %s: %w", path, err)
		}
		fmt.Printf("wrote %s\n", path)
	}

	fmt.Printf("common name %s, valid until %s\n",
		commonName, template.NotAfter.UTC().Format(time.RFC3339))
	return nil
}

func splitAndTrim(value string) []string {
	parts := strings.Split(value, ",")
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		if trimmed := strings.TrimSpace(part); trimmed != "" {
			out = append(out, trimmed)
		}
	}
	return out
}
