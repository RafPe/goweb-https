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
	"strings"
	"testing"
	"time"
)

// caTemplate returns a template for a client CA certificate that satisfies
// every check LoadTrustStore makes: BasicConstraintsValid, IsCA, and
// KeyUsageCertSign are all set, and the validity window covers now. Tests
// that need an anchor LoadTrustStore rejects start from this and unset the
// one property under test, rather than building an unrelated template from
// scratch, so each failing case is a one-property mutation away from a
// certificate that passes.
func caTemplate(commonName string) x509.Certificate {
	return x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
}

// certPEM self-signs template with a fresh ECDSA P-256 key and returns it
// PEM encoded.
func certPEM(t *testing.T, template x509.Certificate) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// caCertPEM generates a self-signed CA certificate that passes every
// LoadTrustStore check, with the given common name, and returns it PEM
// encoded.
func caCertPEM(t *testing.T, commonName string) []byte {
	t.Helper()
	return certPEM(t, caTemplate(commonName))
}

// corruptArmourCertificateBlock returns a hand-written PEM block whose
// armour ("-----BEGIN/END CERTIFICATE-----") is well-formed but whose body
// contains '!', a byte outside the base64 alphabet.
//
// This must not be built with pem.EncodeToMemory: that always produces valid
// base64, so at worst it exercises the malformed-DER path already covered by
// "bundle mixing a valid CA with a malformed CERTIFICATE block" above -
// x509.ParseCertificate rejects garbage bytes loudly. A corrupt *armour*
// body is a different failure mode: pem.Decode does not report it as an
// error at all, it silently skips the block and resumes decoding at the
// next one, so this is the only way to reach the code path this test exists
// to cover.
func corruptArmourCertificateBlock() []byte {
	return []byte("-----BEGIN CERTIFICATE-----\nMIIBIjANBgkqhkiG9w0BAQEF!AOCAQ8A\n-----END CERTIFICATE-----\n")
}

// writeFile writes content to a file named name inside a fresh temporary
// directory and returns its path.
func writeFile(t *testing.T, name string, content []byte) string {
	t.Helper()

	path := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(path, content, 0o600); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
	return path
}

func TestLoadTrustStore(t *testing.T) {
	tests := map[string]struct {
		path func(t *testing.T) string
		// wantErr, if non-empty, is a substring the returned error must
		// contain. An empty wantErr means LoadTrustStore must succeed.
		wantErr string
		// check, when set, inspects the successful result.
		check func(t *testing.T, store *TrustStore)
	}{
		"valid CA": {
			path: func(t *testing.T) string {
				return writeFile(t, "ca.pem", caCertPEM(t, "test-ca"))
			},
			check: func(t *testing.T, store *TrustStore) {
				want := []string{"CN=test-ca"}
				if got := anchorSubjects(store); !slices.Equal(got, want) {
					t.Errorf("subjects = %v, want %v", got, want)
				}
			},
		},
		"multiple valid CAs": {
			path: func(t *testing.T) string {
				var bundle []byte
				for _, name := range []string{"first-ca", "second-ca", "third-ca"} {
					bundle = append(bundle, caCertPEM(t, name)...)
				}
				return writeFile(t, "cas.pem", bundle)
			},
			check: func(t *testing.T, store *TrustStore) {
				// Order matters: it is what makes a startup log naming the
				// anchors a faithful description of the file, not a set that
				// happens to contain the right elements.
				want := []string{"CN=first-ca", "CN=second-ca", "CN=third-ca"}
				if got := anchorSubjects(store); !slices.Equal(got, want) {
					t.Errorf("subjects = %v, want %v", got, want)
				}
			},
		},
		// This is the demo.pem regression test: certs/demo.pem is a leaf
		// certificate with BasicConstraintsValid true and IsCA false. Before
		// this validation existed, Go's x509.CertPool accepted it as a
		// trust anchor anyway, so anyone holding the committed
		// certs/demo-key.pem could authenticate as a verified client.
		"non-CA leaf with basic constraints": {
			path: func(t *testing.T) string {
				template := caTemplate("demo-leaf")
				template.IsCA = false
				return writeFile(t, "leaf.pem", certPEM(t, template))
			},
			wantErr: "not a CA",
		},
		// Omitting the BasicConstraints extension entirely leaves both
		// BasicConstraintsValid and IsCA false once the certificate is
		// parsed back - Go derives IsCA solely from that extension, so this
		// case is actually caught by validateAnchor's !cert.IsCA arm, the
		// same arm every non-CA case in this table exercises. The
		// !cert.BasicConstraintsValid guard is kept for defense in depth
		// against a hand-constructed x509.Certificate where the two fields
		// could disagree, but no case here exercises it independently of
		// !IsCA - x509.ParseCertificate can't produce that combination.
		"CA certificate with BasicConstraints extension omitted": {
			path: func(t *testing.T) string {
				template := caTemplate("no-basic-constraints")
				template.BasicConstraintsValid = false
				template.IsCA = false
				return writeFile(t, "leaf.pem", certPEM(t, template))
			},
			wantErr: "not a CA",
		},
		"CA without KeyUsageCertSign": {
			path: func(t *testing.T) string {
				template := caTemplate("no-cert-sign")
				template.KeyUsage = x509.KeyUsageDigitalSignature
				return writeFile(t, "ca.pem", certPEM(t, template))
			},
			wantErr: "no keyCertSign key usage",
		},
		"expired CA": {
			path: func(t *testing.T) string {
				template := caTemplate("expired-ca")
				template.NotBefore = time.Now().Add(-2 * time.Hour)
				template.NotAfter = time.Now().Add(-time.Hour)
				return writeFile(t, "ca.pem", certPEM(t, template))
			},
			wantErr: "expired",
		},
		"not-yet-valid CA": {
			path: func(t *testing.T) string {
				template := caTemplate("future-ca")
				template.NotBefore = time.Now().Add(time.Hour)
				template.NotAfter = time.Now().Add(2 * time.Hour)
				return writeFile(t, "ca.pem", certPEM(t, template))
			},
			wantErr: "not yet valid",
		},
		"bundle mixing a valid CA with a malformed CERTIFICATE block": {
			path: func(t *testing.T) string {
				malformed := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("not a certificate")})
				bundle := append(caCertPEM(t, "good-ca"), malformed...)
				return writeFile(t, "bundle.pem", bundle)
			},
			// x509.CertPool.AppendCertsFromPEM would report success here
			// because one block parsed; a trust store must not silently
			// drop the corrupt CA and trust only the rest of the bundle.
			wantErr: "parse certificate",
		},
		"bundle with a corrupt-armour CERTIFICATE block between two valid CAs": {
			path: func(t *testing.T) string {
				var bundle []byte
				bundle = append(bundle, caCertPEM(t, "first-ca")...)
				bundle = append(bundle, corruptArmourCertificateBlock()...)
				bundle = append(bundle, caCertPEM(t, "second-ca")...)
				return writeFile(t, "bundle.pem", bundle)
			},
			// pem.Decode treats the middle block as if it were never there:
			// it decodes the two well-formed CAs and returns with rest fully
			// consumed, so nothing here looks incomplete by the usual
			// signals. Only comparing the marker count against the decoded
			// count catches the drop.
			wantErr: "found 3 ",
		},
		"bundle with a non-CERTIFICATE PEM block alongside a valid CA": {
			path: func(t *testing.T) string {
				comment := pem.EncodeToMemory(&pem.Block{Type: "COMMENT", Bytes: []byte("not a certificate")})
				bundle := append(comment, caCertPEM(t, "good-ca")...)
				return writeFile(t, "bundle.pem", bundle)
			},
			check: func(t *testing.T, store *TrustStore) {
				want := []string{"CN=good-ca"}
				if got := anchorSubjects(store); !slices.Equal(got, want) {
					t.Errorf("subjects = %v, want %v", got, want)
				}
			},
		},
		"file that is not PEM at all": {
			path: func(t *testing.T) string {
				return writeFile(t, "garbage.pem", []byte("this is not a certificate"))
			},
			wantErr: "no PEM certificate",
		},
		"missing file": {
			path: func(t *testing.T) string {
				return filepath.Join(t.TempDir(), "absent.pem")
			},
			wantErr: "read client CA file",
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			path := test.path(t)
			store, err := LoadTrustStore(path)

			if test.wantErr != "" {
				if err == nil {
					t.Fatalf("LoadTrustStore(%q) = nil error, want an error containing %q", path, test.wantErr)
				}
				if !strings.Contains(err.Error(), test.wantErr) {
					t.Errorf("LoadTrustStore(%q) error = %q, want it to contain %q", path, err, test.wantErr)
				}
				if store != nil {
					t.Errorf("LoadTrustStore returned a store alongside an error; want nil")
				}
				return
			}

			if err != nil {
				t.Fatalf("LoadTrustStore(%q) returned %v, want no error", path, err)
			}
			if store == nil {
				t.Fatal("LoadTrustStore returned a nil store without an error")
			}
			if store.Pool() == nil {
				t.Error("TrustStore.Pool() = nil, want a non-nil pool")
			}
			if test.check != nil {
				test.check(t, store)
			}
		})
	}
}

// anchorSubjects returns the subjects of store's anchors, in order.
func anchorSubjects(store *TrustStore) []string {
	var subjects []string
	for _, anchor := range store.Anchors() {
		subjects = append(subjects, anchor.Subject)
	}
	return subjects
}

// TestLoadTrustStore_Anchors proves each field of Anchor is populated from
// the certificate actually in the file, not left zero-valued or copied from
// the wrong source. The fingerprint is checked against an independently
// computed digest so a bug that hashed the wrong bytes - the DER of a
// different certificate, or the PEM block instead of the DER - would be
// caught rather than passing because both sides used the same helper.
func TestLoadTrustStore_Anchors(t *testing.T) {
	template := caTemplate("known-ca")
	template.SerialNumber = big.NewInt(987654321)

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse certificate: %v", err)
	}

	path := writeFile(t, "ca.pem", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))

	store, err := LoadTrustStore(path)
	if err != nil {
		t.Fatalf("LoadTrustStore(%q) returned %v, want no error", path, err)
	}

	anchors := store.Anchors()
	if len(anchors) != 1 {
		t.Fatalf("Anchors() returned %d anchors, want 1", len(anchors))
	}
	got := anchors[0]

	if got.Subject != cert.Subject.String() {
		t.Errorf("Subject = %q, want %q", got.Subject, cert.Subject.String())
	}
	if got.Issuer != cert.Issuer.String() {
		t.Errorf("Issuer = %q, want %q", got.Issuer, cert.Issuer.String())
	}
	if got.Serial != cert.SerialNumber.String() {
		t.Errorf("Serial = %q, want %q", got.Serial, cert.SerialNumber.String())
	}
	wantFingerprint := sha256.Sum256(cert.Raw)
	if got.FingerprintSHA256 != hex.EncodeToString(wantFingerprint[:]) {
		t.Errorf("FingerprintSHA256 = %q, want %q", got.FingerprintSHA256, hex.EncodeToString(wantFingerprint[:]))
	}
	if !got.NotBefore.Equal(cert.NotBefore) {
		t.Errorf("NotBefore = %v, want %v", got.NotBefore, cert.NotBefore)
	}
	if !got.NotAfter.Equal(cert.NotAfter) {
		t.Errorf("NotAfter = %v, want %v", got.NotAfter, cert.NotAfter)
	}
}

// TestLoadTrustStore_AnchorsIndependentOfPool proves Anchors returns a copy:
// mutating the slice returned by one call must not be visible through a
// second call, since the TrustStore is meant to be handed to a listener and
// read from concurrently.
func TestLoadTrustStore_AnchorsIndependentOfPool(t *testing.T) {
	path := writeFile(t, "ca.pem", caCertPEM(t, "test-ca"))
	store, err := LoadTrustStore(path)
	if err != nil {
		t.Fatalf("LoadTrustStore(%q) returned %v, want no error", path, err)
	}

	first := store.Anchors()
	first[0].Subject = "tampered"

	second := store.Anchors()
	if second[0].Subject == "tampered" {
		t.Error("Anchors() returned a slice aliasing internal state; mutation leaked across calls")
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
