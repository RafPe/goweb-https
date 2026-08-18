package clientauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// caCertPEM generates a self-signed CA certificate with the given common name
// and returns it PEM encoded.
func caCertPEM(t *testing.T, commonName string) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// writeCAFile writes a single self-signed CA certificate, CN "test-ca", to a
// temporary PEM file and returns its path.
func writeCAFile(t *testing.T) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(path, caCertPEM(t, "test-ca"), 0o600); err != nil {
		t.Fatalf("write ca file: %v", err)
	}
	return path
}

func TestLoadPool(t *testing.T) {
	valid := writeCAFile(t)

	notPEM := filepath.Join(t.TempDir(), "garbage.pem")
	if err := os.WriteFile(notPEM, []byte("this is not a certificate"), 0o600); err != nil {
		t.Fatalf("write garbage file: %v", err)
	}

	emptyPEM := filepath.Join(t.TempDir(), "empty.pem")
	if err := os.WriteFile(emptyPEM, []byte("-----BEGIN OTHER-----\nAA==\n-----END OTHER-----\n"), 0o600); err != nil {
		t.Fatalf("write empty pem: %v", err)
	}

	tests := map[string]struct {
		path      string
		wantError bool
	}{
		"valid CA file":               {path: valid, wantError: false},
		"missing file":                {path: filepath.Join(t.TempDir(), "absent.pem"), wantError: true},
		"file that is not PEM":        {path: notPEM, wantError: true},
		"PEM without any certificate": {path: emptyPEM, wantError: true},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			pool, subjects, err := LoadPool(test.path)

			if test.wantError {
				if err == nil {
					t.Fatalf("LoadPool(%q) = nil error, want an error", test.path)
				}
				if pool != nil {
					t.Errorf("LoadPool returned a pool alongside an error; want nil")
				}
				if subjects != nil {
					t.Errorf("LoadPool returned subjects alongside an error; want nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("LoadPool(%q) returned %v, want no error", test.path, err)
			}
			if pool == nil {
				t.Fatal("LoadPool returned a nil pool without an error")
			}
			if want := []string{"CN=test-ca"}; !slices.Equal(subjects, want) {
				t.Errorf("subjects = %v, want %v", subjects, want)
			}
		})
	}
}

// TestLoadPool_Subjects proves the returned subjects are collected from the
// CAs actually in the file, in order, rather than being some placeholder
// that happens to satisfy TestLoadPool's single-CA case. This is what a
// startup log naming "the subjects it will trust" depends on: a subject list
// that doesn't reliably reflect the file's contents would be worse than no
// list, since it would read as confirmation of the wrong thing.
func TestLoadPool_Subjects(t *testing.T) {
	var encoded []byte
	for _, name := range []string{"first-ca", "second-ca"} {
		encoded = append(encoded, caCertPEM(t, name)...)
	}

	path := filepath.Join(t.TempDir(), "cas.pem")
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
		t.Fatalf("write ca file: %v", err)
	}

	pool, subjects, err := LoadPool(path)
	if err != nil {
		t.Fatalf("LoadPool(%q) returned %v, want no error", path, err)
	}
	if pool == nil {
		t.Fatal("LoadPool returned a nil pool without an error")
	}

	want := []string{"CN=first-ca", "CN=second-ca"}
	if !slices.Equal(subjects, want) {
		t.Errorf("subjects = %v, want %v", subjects, want)
	}
}

// leafCertificate returns a parsed self-signed leaf for use in a fake
// connection state.
func leafCertificate(t *testing.T, commonName string) *x509.Certificate {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: big.NewInt(42),
		Subject:      pkix.Name{CommonName: commonName},
		DNSNames:     []string{"client.example"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}
	return cert
}

// issuedLeaf returns a leaf certificate carrying DNS, email, URI and IP SANs,
// signed by a throwaway issuing CA, together with that CA certificate.
//
// A real two-certificate chain is used (rather than a self-signed leaf) so
// the "verified chain" subtest can assert the documented leaf-first ordering
// of Identity.Chain against something that isn't trivially a single-element
// list, and so every SAN kind Identity exposes has a real source value to
// check against.
func issuedLeaf(t *testing.T, commonName string) (leaf, ca *x509.Certificate) {
	t.Helper()

	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate ca key: %v", err)
	}
	caTemplate := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-issuing-ca"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, &caTemplate, &caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create ca certificate: %v", err)
	}
	ca, err = x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse ca certificate: %v", err)
	}

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTemplate := x509.Certificate{
		SerialNumber:   big.NewInt(42),
		Subject:        pkix.Name{CommonName: commonName},
		DNSNames:       []string{"client.example"},
		EmailAddresses: []string{"client@example.com"},
		URIs:           []*url.URL{{Scheme: "spiffe", Host: "example.com", Path: "/client"}},
		IPAddresses:    []net.IP{net.ParseIP("192.0.2.1")},
		NotBefore:      time.Now().Add(-time.Hour),
		NotAfter:       time.Now().Add(time.Hour),
		KeyUsage:       x509.KeyUsageDigitalSignature,
		ExtKeyUsage:    []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, &leafTemplate, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	leaf, err = x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatalf("parse leaf certificate: %v", err)
	}

	return leaf, ca
}

func TestIdentityFrom(t *testing.T) {
	leaf := leafCertificate(t, "verified-client")

	t.Run("nil connection state", func(t *testing.T) {
		if _, ok := IdentityFrom(nil); ok {
			t.Error("IdentityFrom(nil) reported an identity; want none")
		}
	})

	t.Run("no peer certificate", func(t *testing.T) {
		if _, ok := IdentityFrom(&tls.ConnectionState{}); ok {
			t.Error("IdentityFrom reported an identity for a bare state; want none")
		}
	})

	// A non-empty VerifiedChains slice whose first chain is itself empty is
	// the shape crypto/tls would never produce, but IdentityFrom guards
	// against it explicitly (it indexes VerifiedChains[0][0]); this exercises
	// that guard directly rather than trusting it by inspection.
	t.Run("verified chain present but empty", func(t *testing.T) {
		state := &tls.ConnectionState{VerifiedChains: [][]*x509.Certificate{{}}}
		if _, ok := IdentityFrom(state); ok {
			t.Error("IdentityFrom reported an identity for an empty verified chain")
		}
	})

	// The whole point of the package: a certificate the client presented but
	// the server did not verify is not an identity. If this test ever passes
	// an identity back, something started reading PeerCertificates.
	t.Run("peer certificate present but unverified", func(t *testing.T) {
		state := &tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
		if _, ok := IdentityFrom(state); ok {
			t.Error("IdentityFrom reported an identity from an unverified certificate")
		}
	})

	t.Run("verified chain", func(t *testing.T) {
		verifiedLeaf, ca := issuedLeaf(t, "verified-client")
		state := &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{verifiedLeaf},
			VerifiedChains:   [][]*x509.Certificate{{verifiedLeaf, ca}},
		}

		identity, ok := IdentityFrom(state)
		if !ok {
			t.Fatal("IdentityFrom reported no identity for a verified chain")
		}
		if got, want := identity.Subject, "CN=verified-client"; got != want {
			t.Errorf("Subject = %q, want %q", got, want)
		}
		if got, want := identity.Issuer, ca.Subject.String(); got != want {
			t.Errorf("Issuer = %q, want %q", got, want)
		}
		if got, want := identity.Serial, "42"; got != want {
			t.Errorf("Serial = %q, want %q", got, want)
		}
		wantFingerprint := sha256.Sum256(verifiedLeaf.Raw)
		if got, want := identity.FingerprintSHA256, hex.EncodeToString(wantFingerprint[:]); got != want {
			t.Errorf("FingerprintSHA256 = %q, want %q", got, want)
		}
		if !identity.NotBefore.Equal(verifiedLeaf.NotBefore) {
			t.Errorf("NotBefore = %v, want %v", identity.NotBefore, verifiedLeaf.NotBefore)
		}
		if !identity.NotAfter.Equal(verifiedLeaf.NotAfter) {
			t.Errorf("NotAfter = %v, want %v", identity.NotAfter, verifiedLeaf.NotAfter)
		}
		if got, want := identity.DNSNames, []string{"client.example"}; !slices.Equal(got, want) {
			t.Errorf("DNSNames = %v, want %v", got, want)
		}
		if got, want := identity.EmailAddresses, []string{"client@example.com"}; !slices.Equal(got, want) {
			t.Errorf("EmailAddresses = %v, want %v", got, want)
		}
		if got, want := identity.URIs, []string{"spiffe://example.com/client"}; !slices.Equal(got, want) {
			t.Errorf("URIs = %v, want %v", got, want)
		}
		if got, want := identity.IPAddresses, []string{"192.0.2.1"}; !slices.Equal(got, want) {
			t.Errorf("IPAddresses = %v, want %v", got, want)
		}
		if got, want := identity.Chain, []string{verifiedLeaf.Subject.String(), ca.Subject.String()}; !slices.Equal(got, want) {
			t.Errorf("Chain = %v, want %v", got, want)
		}
	})
}
