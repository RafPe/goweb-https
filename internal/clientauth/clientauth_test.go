package clientauth

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
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
