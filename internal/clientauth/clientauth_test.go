package clientauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"
)

// writeCAFile writes a self-signed CA certificate to a temporary PEM file and
// returns its path.
func writeCAFile(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	template := x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test-ca"},
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

	path := filepath.Join(t.TempDir(), "ca.pem")
	encoded := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	if err := os.WriteFile(path, encoded, 0o600); err != nil {
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
			pool, err := LoadPool(test.path)

			if test.wantError {
				if err == nil {
					t.Fatalf("LoadPool(%q) = nil error, want an error", test.path)
				}
				if pool != nil {
					t.Errorf("LoadPool returned a pool alongside an error; want nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("LoadPool(%q) returned %v, want no error", test.path, err)
			}
			if pool == nil {
				t.Fatal("LoadPool returned a nil pool without an error")
			}
		})
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
		state := &tls.ConnectionState{
			PeerCertificates: []*x509.Certificate{leaf},
			VerifiedChains:   [][]*x509.Certificate{{leaf}},
		}

		identity, ok := IdentityFrom(state)
		if !ok {
			t.Fatal("IdentityFrom reported no identity for a verified chain")
		}
		if got, want := identity.Subject, "CN=verified-client"; got != want {
			t.Errorf("Subject = %q, want %q", got, want)
		}
		if got, want := identity.Serial, "42"; got != want {
			t.Errorf("Serial = %q, want %q", got, want)
		}
		if len(identity.FingerprintSHA256) != 64 {
			t.Errorf("FingerprintSHA256 = %q, want 64 hex characters", identity.FingerprintSHA256)
		}
		if got, want := identity.DNSNames, []string{"client.example"}; !slices.Equal(got, want) {
			t.Errorf("DNSNames = %v, want %v", got, want)
		}
		if got, want := identity.Chain, []string{"CN=verified-client"}; !slices.Equal(got, want) {
			t.Errorf("Chain = %v, want %v", got, want)
		}
	})
}
