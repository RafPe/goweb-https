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
		clientCA   = flag.Bool("client-ca", false, "emit a client CA and a client certificate signed by it, instead of the server material")
	)
	flag.Parse()

	if err := run(*dir, *commonName, splitAndTrim(*dnsNames), *validFor, *clientCA); err != nil {
		log.Fatalf("generate demo certificates: %v", err)
	}
}

// issued is a generated certificate together with the key that signs for it.
type issued struct {
	cert *x509.Certificate
	der  []byte
	key  *rsa.PrivateKey
}

// issue creates a certificate from template, signed by parent. A nil parent
// makes it self-signed, which is how the root of each chain is produced.
//
// Children are signed against parent.cert - the parsed, already-issued
// certificate - rather than parent's pre-signing template. CreateCertificate
// computes a CA's SubjectKeyId from its public key and encodes it into the
// output DER, but never writes it back into the template struct that was
// passed in; signing against that template would hand CreateCertificate a
// parent with an empty SubjectKeyId, so the child comes out with no
// AuthorityKeyId. Go's own verifier matches by distinguished name and
// tolerates that, but hack/ is exactly the code another team copies, so it
// should produce a correctly linked chain regardless.
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

	signerCert, signerKey := template, key
	if parent != nil {
		signerCert, signerKey = parent.cert, parent.key
	}

	der, err := x509.CreateCertificate(rand.Reader, template, signerCert, &key.PublicKey, signerKey)
	if err != nil {
		return nil, fmt.Errorf("create certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("parse certificate: %w", err)
	}

	return &issued{cert: cert, der: der, key: key}, nil
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
	// A non-positive window produces a certificate whose NotAfter is at or
	// before its NotBefore - already expired the moment it is written, or
	// invalid outright - which every TLS client will reject. Catching it
	// here gives a caller a clear reason instead of a mysterious handshake
	// failure once the material is deployed.
	if validFor <= 0 {
		return fmt.Errorf("valid-for must be positive, got %s", validFor)
	}

	if err := os.MkdirAll(dir, 0o750); err != nil {
		return fmt.Errorf("create %s: %w", dir, err)
	}

	if clientCA {
		return writeClientMaterial(dir, validFor)
	}
	return writeServerMaterial(dir, commonName, dnsNames, validFor)
}

// writeServerMaterial (re)issues the demo server certificate and writes
// demo.pem, demo-key.pem and bundle.pem. This is the default, unconditional
// behaviour of `make certs`.
func writeServerMaterial(dir, commonName string, dnsNames []string, validFor time.Duration) error {
	now := time.Now()
	template := x509.Certificate{
		Subject:   pkix.Name{CommonName: commonName},
		DNSNames:  dnsNames,
		NotBefore: now.Add(-time.Hour),
		NotAfter:  now.Add(validFor),

		// A server leaf, not a CA. The previous regeneration produced
		// CA:TRUE with no key usage at all, which does not model the profile
		// this project exists to demonstrate.
		//
		// ServerAuth only: this fixture demonstrates a server-only leaf, and
		// ClientAuth here is what previously made it possible to point
		// GOWEB_MTLS_CLIENT_CA at the committed certs/demo-key.pem and
		// authenticate as a verified client. KeyEncipherment is dropped too:
		// it exists for RSA key transport, which TLS 1.3 - the only protocol
		// this server negotiates - never uses.
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}

	serverCert, err := issue(&template, nil)
	if err != nil {
		return fmt.Errorf("server certificate: %w", err)
	}

	certPEM, keyPEM, err := pemPair(serverCert)
	if err != nil {
		return err
	}

	files := map[string][]byte{
		"demo.pem":     certPEM,
		"demo-key.pem": keyPEM,
		// The bundle holds the key followed by the certificate, matching the
		// layout GOWEB_X509_BUNDLE expects.
		"bundle.pem": append(append([]byte{}, keyPEM...), certPEM...),
	}

	if err := writeFiles(dir, files); err != nil {
		return err
	}

	fmt.Printf("common name %s, valid until %s\n",
		commonName, template.NotAfter.UTC().Format(time.RFC3339))
	return nil
}

// writeClientMaterial issues a client CA and a client leaf signed by it, and
// writes only those four files. It never touches demo.pem, demo-key.pem or
// bundle.pem: those are committed server material, and -client-ca used to
// silently rewrite all three even though nothing about them needed to
// change, leaving a contributor with unrelated modified files one `git
// commit -a` away from landing.
func writeClientMaterial(dir string, validFor time.Duration) error {
	now := time.Now()

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

	files := map[string][]byte{
		"client-ca.pem":     caCertPEM,
		"client-ca-key.pem": caKeyPEM,
		"client.pem":        clientCertPEM,
		"client-key.pem":    clientKeyPEM,
	}

	if err := writeFiles(dir, files); err != nil {
		return err
	}

	fmt.Printf("client CA CN=goweb-client-ca, client CN=goweb-client, valid until %s\n",
		clientTemplate.NotAfter.UTC().Format(time.RFC3339))
	return nil
}

// writeFiles writes each named file into dir, using a restrictive mode for
// keys and the combined bundle.
func writeFiles(dir string, files map[string][]byte) error {
	for name, content := range files {
		mode := os.FileMode(0o644)
		if strings.Contains(name, "key") || name == "bundle.pem" {
			mode = 0o600
		}
		if err := writeFileAtomic(dir, name, content, mode); err != nil {
			return err
		}
		fmt.Printf("wrote %s\n", filepath.Join(dir, name))
	}
	return nil
}

// writeFileAtomic writes content to dir/name by way of a temporary file that
// is renamed into place once fully written.
//
// os.WriteFile's mode argument is only applied when the file is newly
// created; it has no effect on a file that already exists. Regenerating
// client-ca-key.pem - a CA signing key - over a copy that was previously
// created 0o644 would therefore silently leave it world-readable, mode
// argument notwithstanding. Going through a temp file sidesteps that: the
// temp file is created fresh, so os.CreateTemp's own restrictive 0o600
// default mode applies, and it is set to the caller's mode before any
// content is written to it - so an empty file never sits at a mode wider
// than its final one with content in it. The rename is also what makes the
// write atomic: a reader opening dir/name either sees the previous complete
// file or the new complete one, never a partially written certificate.
func writeFileAtomic(dir, name string, content []byte, mode os.FileMode) (err error) {
	tmp, err := os.CreateTemp(dir, "."+name+".tmp-*")
	if err != nil {
		return fmt.Errorf("create temp file for %s: %w", name, err)
	}
	tmpPath := tmp.Name()
	defer func() {
		if err != nil {
			_ = os.Remove(tmpPath)
		}
	}()

	if err = tmp.Chmod(mode); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("chmod %s: %w", tmpPath, err)
	}
	if _, err = tmp.Write(content); err != nil {
		_ = tmp.Close()
		return fmt.Errorf("write %s: %w", tmpPath, err)
	}
	if err = tmp.Close(); err != nil {
		return fmt.Errorf("close %s: %w", tmpPath, err)
	}

	if err = os.Rename(tmpPath, filepath.Join(dir, name)); err != nil {
		return fmt.Errorf("rename %s to %s: %w", tmpPath, name, err)
	}
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
