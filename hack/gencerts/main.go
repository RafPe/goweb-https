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
		clientCA   = flag.Bool("client-ca", false, "also emit a client CA and a client certificate signed by it")
	)
	flag.Parse()

	if err := run(*dir, *commonName, splitAndTrim(*dnsNames), *validFor, *clientCA); err != nil {
		log.Fatalf("generate demo certificates: %v", err)
	}
}

// issued is a generated certificate together with the key that signs for it.
type issued struct {
	template *x509.Certificate
	der      []byte
	key      *rsa.PrivateKey
}

// issue creates a certificate from template, signed by parent. A nil parent
// makes it self-signed, which is how the root of each chain is produced.
func issue(template *x509.Certificate, parent *issued) (*issued, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, fmt.Errorf("generate serial: %w", err)
	}
	template.SerialNumber = serial

	signerTemplate, signerKey := template, key
	if parent != nil {
		signerTemplate, signerKey = parent.template, parent.key
	}

	der, err := x509.CreateCertificate(rand.Reader, template, signerTemplate, &key.PublicKey, signerKey)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	return &issued{template: template, der: der, key: key}, nil
}

// pemPair renders a certificate and its key as PEM.
func pemPair(c *issued) (certPEM, keyPEM []byte, err error) {
	keyDER, err := x509.MarshalPKCS8PrivateKey(c.key)
	if err != nil {
		return nil, nil, fmt.Errorf("marshal key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: c.der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		nil
}

func run(dir, commonName string, dnsNames []string, validFor time.Duration, clientCA bool) error {
	now := time.Now()
	template := x509.Certificate{
		Subject:   pkix.Name{CommonName: commonName},
		DNSNames:  dnsNames,
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(validFor),

		// A server leaf, not a CA. The previous regeneration produced
		// CA:TRUE with no key usage at all, which does not model the profile
		// this project exists to demonstrate.
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	server, err := issue(&template, nil)
	if err != nil {
		return fmt.Errorf("server certificate: %w", err)
	}

	certPEM, keyPEM, err := pemPair(server)
	if err != nil {
		return err
	}

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

	if clientCA {
		caTemplate := x509.Certificate{
			Subject:               pkix.Name{CommonName: "goweb-client-ca"},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(validFor),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
		}
		ca, err := issue(&caTemplate, nil)
		if err != nil {
			return fmt.Errorf("client CA: %w", err)
		}

		// A client leaf: ClientAuth only, so it cannot be mistaken for, or used
		// as, a server certificate.
		clientTemplate := x509.Certificate{
			Subject:               pkix.Name{CommonName: "goweb-client"},
			NotBefore:             now.Add(-time.Hour),
			NotAfter:              now.Add(validFor),
			KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			BasicConstraintsValid: true,
			IsCA:                  false,
		}
		client, err := issue(&clientTemplate, ca)
		if err != nil {
			return fmt.Errorf("client certificate: %w", err)
		}

		caCertPEM, caKeyPEM, err := pemPair(ca)
		if err != nil {
			return err
		}
		clientCertPEM, clientKeyPEM, err := pemPair(client)
		if err != nil {
			return err
		}

		files["client-ca.pem"] = caCertPEM
		files["client-ca-key.pem"] = caKeyPEM
		files["client.pem"] = clientCertPEM
		files["client-key.pem"] = clientKeyPEM
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
