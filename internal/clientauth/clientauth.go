// Package clientauth owns the client-certificate trust store and the
// extraction of a verified client identity from a TLS connection.
//
// It is a separate package from internal/server so that deciding what "the
// verified client" means is one decision made in one place. The server
// consumes the result through the narrow Identity type, the same way it
// consumes certreload.Info.
package clientauth

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"fmt"
	"os"
	"time"
)

// LoadPool reads a PEM file of client CA certificates and returns a pool that
// client certificates are verified against.
//
// A file that yields no certificate is an error rather than an empty pool.
// An empty pool would fail every client certificate presented to it, which is
// an operator mistake and not a configuration anyone intends.
func LoadPool(path string) (*x509.CertPool, error) {
	// #nosec G304 -- the path is operator-supplied configuration; reading it is the point
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("clientauth: read client CA file: %w", err)
	}

	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(encoded) {
		return nil, fmt.Errorf("clientauth: %s contains no PEM certificate", path)
	}

	return pool, nil
}

// Identity describes a client certificate that the server verified.
//
// Every field is derived from the verified leaf, so a populated Identity
// always means the handshake proved possession of the corresponding key.
type Identity struct {
	Subject           string
	Issuer            string
	Serial            string
	FingerprintSHA256 string
	DNSNames          []string
	URIs              []string
	EmailAddresses    []string
	IPAddresses       []string
	NotBefore         time.Time
	NotAfter          time.Time

	// Chain lists the verified chain by subject, leaf first.
	Chain []string
}

// IdentityFrom extracts the verified client identity from state. The boolean
// reports whether the client presented a certificate that the server verified.
//
// It reads VerifiedChains and never PeerCertificates. Under the listener's
// tls.VerifyClientCertIfGiven setting the two agree, because an unverifiable
// certificate aborts the handshake before any handler runs. They stop agreeing
// the moment ClientAuth changes, and the failure mode of the wrong choice is
// treating an unverified certificate as an identity - so this reads the field
// that is safe under every setting.
func IdentityFrom(state *tls.ConnectionState) (Identity, bool) {
	if state == nil || len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return Identity{}, false
	}

	chain := state.VerifiedChains[0]
	leaf := chain[0]
	fingerprint := sha256.Sum256(leaf.Raw)

	identity := Identity{
		Subject:           leaf.Subject.String(),
		Issuer:            leaf.Issuer.String(),
		Serial:            leaf.SerialNumber.String(),
		FingerprintSHA256: hex.EncodeToString(fingerprint[:]),
		DNSNames:          leaf.DNSNames,
		EmailAddresses:    leaf.EmailAddresses,
		NotBefore:         leaf.NotBefore,
		NotAfter:          leaf.NotAfter,
	}

	for _, uri := range leaf.URIs {
		identity.URIs = append(identity.URIs, uri.String())
	}
	for _, ip := range leaf.IPAddresses {
		identity.IPAddresses = append(identity.IPAddresses, ip.String())
	}
	for _, cert := range chain {
		identity.Chain = append(identity.Chain, cert.Subject.String())
	}

	return identity, true
}
