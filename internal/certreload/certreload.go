// Package certreload loads a TLS key pair from disk, keeps it up to date as the
// underlying files are rotated, and publishes it for use by tls.Config.
//
// The read path is lock free: handshakes load an immutable snapshot through an
// atomic pointer and perform no filesystem access, parsing, or locking. All
// discovery happens on a separate goroutine driven by [Reloader.Watch].
//
// It also hosts [RunWatch], the rotation-watching loop that [Reloader.Watch] is
// built from. The loop is exported so that the client CA trust bundle in
// internal/clientauth can be driven by the same code rather than by a second
// copy of it.
package certreload

import (
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"time"
)

// Sentinel errors callers may match with errors.Is.
var (
	// ErrCertificateUnavailable reports that no certificate has been published.
	ErrCertificateUnavailable = errors.New("no certificate available")

	// ErrNoLeafCertificate reports key material that parsed but contained no
	// leaf certificate.
	ErrNoLeafCertificate = errors.New("key pair contains no leaf certificate")

	// ErrCertificateExpired reports a certificate whose validity period has passed.
	ErrCertificateExpired = errors.New("certificate expired")

	// ErrCertificateNotYetValid reports a certificate that is not valid yet.
	ErrCertificateNotYetValid = errors.New("certificate not yet valid")

	// ErrWatcherClosed reports that the filesystem watcher terminated. Rotation
	// can no longer be observed promptly and the process should react.
	ErrWatcherClosed = errors.New("filesystem watcher closed")
)

// Validity describes where a certificate sits relative to its validity period.
type Validity int

// Validity states.
const (
	ValidityValid Validity = iota
	ValidityNotYetValid
	ValidityExpired
)

// String implements fmt.Stringer.
func (v Validity) String() string {
	switch v {
	case ValidityValid:
		return "valid"
	case ValidityNotYetValid:
		return "not yet valid"
	case ValidityExpired:
		return "expired"
	default:
		return "unknown"
	}
}

// Info is an immutable description of a loaded certificate.
//
// It deliberately does not expose the underlying *x509.Certificate: that object
// is shared by every concurrent reader of a published snapshot and mutating it
// would introduce a data race in state that is documented as immutable. Values
// are copied out of it at load time instead.
type Info struct {
	Subject   string
	Issuer    string
	Serial    string
	DNSNames  []string
	URIs      []string
	NotBefore time.Time
	NotAfter  time.Time
	FilePath  string

	// LoadedAt is when this certificate was published. It is the field that
	// distinguishes "reloaded a moment ago" from "loaded at boot and never
	// refreshed" on the diagnostic endpoint.
	LoadedAt time.Time

	// Fingerprint is the hex-encoded SHA-256 of the leaf certificate's DER
	// encoding. Certificate identity is derived from content, never from file
	// metadata such as modification time.
	Fingerprint string
}

// clone returns a copy that shares no mutable state with the receiver.
func (i Info) clone() Info {
	i.DNSNames = slices.Clone(i.DNSNames)
	i.URIs = slices.Clone(i.URIs)
	return i
}

// State reports the certificate's validity at time now, together with the time
// until expiry, the time since expiry, or the time until it becomes valid,
// depending on the returned state.
func (i Info) State(now time.Time) (Validity, time.Duration) {
	switch {
	case now.Before(i.NotBefore):
		return ValidityNotYetValid, i.NotBefore.Sub(now)
	case now.After(i.NotAfter):
		return ValidityExpired, now.Sub(i.NotAfter)
	default:
		return ValidityValid, i.NotAfter.Sub(now)
	}
}

// snapshot is an immutable view of a published certificate. A snapshot is fully
// built before it is stored, and is never mutated afterwards.
type snapshot struct {
	certificate *tls.Certificate
	info        Info
	fingerprint [sha256.Size]byte
}

// loadKeyPair reads and validates the key pair at the supplied paths.
//
// tls.LoadX509KeyPair already verifies that the private key matches the leaf
// certificate, so a partially written rotation - a new certificate next to the
// previous key - fails here rather than being published.
func loadKeyPair(certFile, keyFile string, now time.Time) (*snapshot, error) {
	pair, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil, fmt.Errorf("load tls key pair from %s and %s: %w", certFile, keyFile, err)
	}

	// Guard the index rather than assuming a well-formed chain: malformed
	// material must produce an error, not a panic.
	if len(pair.Certificate) == 0 {
		return nil, fmt.Errorf("%s: %w", certFile, ErrNoLeafCertificate)
	}

	leaf, err := x509.ParseCertificate(pair.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("parse x509 certificate from %s: %w", certFile, err)
	}

	// Populating Leaf lets crypto/tls skip re-parsing on every handshake.
	pair.Leaf = leaf

	fingerprint := sha256.Sum256(pair.Certificate[0])

	return &snapshot{
		certificate: &pair,
		fingerprint: fingerprint,
		info: Info{
			Subject:     leaf.Subject.String(),
			Issuer:      leaf.Issuer.String(),
			Serial:      leaf.SerialNumber.String(),
			DNSNames:    lowercased(leaf.DNSNames),
			URIs:        uriStrings(leaf),
			NotBefore:   leaf.NotBefore,
			NotAfter:    leaf.NotAfter,
			FilePath:    certFile,
			LoadedAt:    now,
			Fingerprint: hex.EncodeToString(fingerprint[:]),
		},
	}, nil
}

// serverAuthWarning returns a non-empty message when the certificate declares
// extended key usages that do not include server authentication, which makes it
// unsuitable for the purpose it is about to be used for.
//
// This is reported rather than rejected: a certificate with no EKU extension at
// all is unconstrained and legitimate, and operators occasionally serve
// deliberately unusual material while debugging.
func serverAuthWarning(certFile string, leaf *x509.Certificate) string {
	if len(leaf.ExtKeyUsage) == 0 && len(leaf.UnknownExtKeyUsage) == 0 {
		return ""
	}
	if slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageServerAuth) ||
		slices.Contains(leaf.ExtKeyUsage, x509.ExtKeyUsageAny) {
		return ""
	}
	return fmt.Sprintf("certificate %s does not declare the server authentication extended key usage", certFile)
}

func lowercased(values []string) []string {
	if len(values) == 0 {
		return nil
	}
	out := make([]string, 0, len(values))
	for _, value := range values {
		out = append(out, strings.ToLower(value))
	}
	return out
}

// uriStrings extracts URI subject alternative names. Workload identity
// certificates - including those issued by Kubernetes PodCertificate signers -
// carry the identity here rather than in DNS names, so this stays populated
// even when DNSNames is empty.
func uriStrings(leaf *x509.Certificate) []string {
	if len(leaf.URIs) == 0 {
		return nil
	}
	out := make([]string, 0, len(leaf.URIs))
	for _, uri := range leaf.URIs {
		out = append(out, strings.ToLower(uri.String()))
	}
	return out
}
