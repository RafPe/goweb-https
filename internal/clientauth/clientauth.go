// Package clientauth owns the client-certificate trust store and the
// extraction of a verified client identity from a TLS connection.
//
// It is a separate package from internal/server so that deciding what "the
// verified client" means is one decision made in one place. The server
// consumes the result through the narrow Identity type, the same way it
// consumes certreload.Info.
package clientauth

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"os"
	"slices"
	"time"
)

// certificateArmourMarker is the literal PEM boundary that opens every
// CERTIFICATE block. Counting it against the number of CERTIFICATE blocks
// LoadTrustStore actually decodes is what catches a corrupt block that
// pem.Decode would otherwise drop without a trace: see the "corrupt PEM
// armour" paragraph on LoadTrustStore.
const certificateArmourMarker = "-----BEGIN CERTIFICATE-----"

// TrustStore is a validated set of client CA trust anchors: every
// certificate it holds passed the checks in LoadTrustStore, so the pool it
// exposes can be handed to tls.Config.ClientCAs without a caller having to
// re-verify what's in it.
type TrustStore struct {
	pool    *x509.CertPool
	anchors []Anchor
}

// Pool returns the trust anchors as an x509 pool for use as
// tls.Config.ClientCAs. Never nil: LoadTrustStore fails rather than
// producing a TrustStore with an empty pool.
func (t *TrustStore) Pool() *x509.CertPool {
	return t.pool
}

// Anchors describes each trusted CA, in the order it appeared in the source
// file, for startup logging and diagnostics.
func (t *TrustStore) Anchors() []Anchor {
	return slices.Clone(t.anchors)
}

// Anchor describes one trusted CA.
//
// Subject alone does not identify a CA across rotation: a replacement CA is
// commonly issued with the same subject DN as the one it replaces, so a log
// line naming only the subject cannot tell an operator which CA is actually
// live. FingerprintSHA256 can.
type Anchor struct {
	Subject           string
	Issuer            string
	Serial            string
	FingerprintSHA256 string
	NotBefore         time.Time
	NotAfter          time.Time
}

// LoadTrustStore reads and validates a PEM file of client CA certificates.
//
// Every CERTIFICATE block must be a CA: BasicConstraintsValid, IsCA, and
// KeyUsageCertSign are all required, so a leaf certificate - which is
// exactly the shape of a committed demo certificate that operators are
// warned not to trust - cannot be pointed at this file and accepted as an
// issuer. Rejecting an unvalidated basic-constraints extension the same way
// a CA that explicitly disclaims itself does: a certificate that does not
// assert it is a CA must not be trusted as one.
//
// An expired or not-yet-valid anchor is also rejected here, even though
// crypto/tls independently refuses an expired anchor at handshake time. That
// stdlib check fails silently and per-connection; validating at load time
// turns the same condition into a loud, named failure at startup instead of
// a mystery the first time a legitimate client is rejected.
//
// A block that is not a CERTIFICATE, such as a comment or another PEM type,
// is skipped: a bundle may legitimately carry other content alongside the
// certificates. A block that claims to be a CERTIFICATE but fails to parse
// is not skipped - x509.CertPool.AppendCertsFromPEM treats that as success
// if any other block in the file parsed, which means a corrupt CA can sit
// beside a valid one in a bundle and be silently dropped rather than fixed.
// For a trust store, partial success is the wrong default.
//
// pem.Decode itself has the same failure mode one level lower: a block whose
// armour is well-formed but whose base64 body is corrupt is not reported as
// an error at all - it is silently skipped, and decoding resumes at the next
// good block. A three-CA bundle with one mangled entry would then load two
// anchors, log two, and look perfectly healthy while every client under the
// third CA is refused with no diagnostic anywhere. LoadTrustStore guards
// against that by counting "-----BEGIN CERTIFICATE-----" markers in the raw
// file and comparing that count to the number of CERTIFICATE blocks it
// actually decoded; a shortfall fails startup by name rather than passing
// unnoticed.
//
// A file that yields no certificate is an error rather than an empty pool.
// An empty pool would fail every client certificate presented to it, which is
// an operator mistake and not a configuration anyone intends.
func LoadTrustStore(path string) (*TrustStore, error) {
	// #nosec G304 -- the path is operator-supplied configuration; reading it is the point
	encoded, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("clientauth: read client CA file: %w", err)
	}

	pool := x509.NewCertPool()
	var anchors []Anchor

	wantBlocks := bytes.Count(encoded, []byte(certificateArmourMarker))
	var decodedBlocks int

	rest := encoded
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		decodedBlocks++
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("clientauth: %s: parse certificate: %w", path, err)
		}
		if err := validateAnchor(cert); err != nil {
			return nil, fmt.Errorf("clientauth: %s: %s: %w", path, cert.Subject, err)
		}

		pool.AddCert(cert)
		fingerprint := sha256.Sum256(cert.Raw)
		anchors = append(anchors, Anchor{
			Subject:           cert.Subject.String(),
			Issuer:            cert.Issuer.String(),
			Serial:            cert.SerialNumber.String(),
			FingerprintSHA256: hex.EncodeToString(fingerprint[:]),
			NotBefore:         cert.NotBefore,
			NotAfter:          cert.NotAfter,
		})
	}

	// Checked before the empty-anchors case below so a file with a single,
	// entirely corrupt block (wantBlocks=1, decodedBlocks=0) is reported as
	// a dropped block rather than as the less specific "no certificate" -
	// the operator needs to know a block was there and was lost, not just
	// that the result is empty.
	if decodedBlocks < wantBlocks {
		return nil, fmt.Errorf("clientauth: %s: found %d %q marker(s) but only decoded %d CERTIFICATE block(s); a block's PEM armour is malformed and was silently dropped",
			path, wantBlocks, certificateArmourMarker, decodedBlocks)
	}

	if len(anchors) == 0 {
		return nil, fmt.Errorf("clientauth: %s contains no PEM certificate", path)
	}

	return &TrustStore{pool: pool, anchors: anchors}, nil
}

// validateAnchor reports why cert cannot be trusted as a client CA, or nil
// if it can.
func validateAnchor(cert *x509.Certificate) error {
	if !cert.BasicConstraintsValid || !cert.IsCA {
		return errors.New("not a CA certificate")
	}
	if cert.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("no keyCertSign key usage: RFC 5280 permits a CA certificate to omit the " +
			"KeyUsage extension entirely, but this server requires certSign to be asserted explicitly")
	}
	now := time.Now()
	if now.Before(cert.NotBefore) {
		return fmt.Errorf("not yet valid (not before %s)", cert.NotBefore)
	}
	if now.After(cert.NotAfter) {
		return fmt.Errorf("expired (not after %s)", cert.NotAfter)
	}
	return nil
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
		DNSNames:          slices.Clone(leaf.DNSNames),
		EmailAddresses:    slices.Clone(leaf.EmailAddresses),
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
