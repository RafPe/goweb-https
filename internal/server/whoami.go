package server

import (
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/RafPe/goweb-https/internal/clientauth"
)

// noClientCertificate is the refusal returned when no verified client
// certificate accompanied the request.
//
// It is a constant because e2e suites in other repositories match on it, which
// makes it contract rather than a message that can be reworded freely.
const noClientCertificate = "no client certificate presented"

// WhoamiReport is the identity of the calling client.
//
// It backs both representations of /whoami for the same reason StatusReport
// backs both representations of /status: rendering one value two ways is what
// stops the two from drifting apart.
type WhoamiReport struct {
	// Authenticated is always present, so a consumer branches on one field
	// rather than on the absence of another.
	Authenticated bool `json:"authenticated"`

	Reason string        `json:"reason,omitempty"`
	Client *ClientStatus `json:"client,omitempty"`
}

// ClientStatus describes the client certificate the server verified.
type ClientStatus struct {
	Subject           string    `json:"subject"`
	Issuer            string    `json:"issuer"`
	Serial            string    `json:"serial"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	DNSNames          []string  `json:"dns_names"`
	URIs              []string  `json:"uris"`
	EmailAddresses    []string  `json:"email_addresses"`
	IPAddresses       []string  `json:"ip_addresses"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`

	// ExpiresInSeconds counts down to NotAfter and goes negative once the
	// certificate has expired, matching CertificateStatus.
	ExpiresInSeconds int64 `json:"expires_in_seconds"`

	// Chain lists the verified chain by subject, leaf first.
	Chain []string `json:"chain"`
}

// buildWhoami gathers the verified identity of the client behind r.
func buildWhoami(deps Dependencies, r *http.Request) WhoamiReport {
	identity, ok := clientauth.IdentityFrom(r.TLS)
	if !ok {
		return WhoamiReport{Authenticated: false, Reason: noClientCertificate}
	}

	now := deps.Now()
	return WhoamiReport{
		Authenticated: true,
		Client: &ClientStatus{
			Subject:           identity.Subject,
			Issuer:            identity.Issuer,
			Serial:            identity.Serial,
			FingerprintSHA256: identity.FingerprintSHA256,
			DNSNames:          emptyIfNil(identity.DNSNames),
			URIs:              emptyIfNil(identity.URIs),
			EmailAddresses:    emptyIfNil(identity.EmailAddresses),
			IPAddresses:       emptyIfNil(identity.IPAddresses),
			NotBefore:         identity.NotBefore,
			NotAfter:          identity.NotAfter,
			ExpiresInSeconds:  int64(identity.NotAfter.Sub(now).Seconds()),
			Chain:             emptyIfNil(identity.Chain),
		},
	}
}

// whoamiStatus maps a report to its HTTP status.
func whoamiStatus(report WhoamiReport) int {
	if report.Authenticated {
		return http.StatusOK
	}
	return http.StatusForbidden
}

// handleWhoami reports the verified client identity to humans.
//
// Like /status it honours an explicit Accept: application/json, so a consumer
// that cannot be pointed at a different URL still has a machine-readable
// option.
func handleWhoami(deps Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		report := buildWhoami(deps, r)

		if prefersJSON(r) {
			writeJSON(w, deps, whoamiStatus(report), report)
			return
		}

		writeText(w, whoamiStatus(report), renderWhoamiText(report, deps.Location))
	}
}

// handleWhoamiJSON serves the machine-readable identity document.
func handleWhoamiJSON(deps Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		report := buildWhoami(deps, r)
		writeJSON(w, deps, whoamiStatus(report), report)
	}
}

// renderWhoamiText renders a report as the human-readable page.
func renderWhoamiText(report WhoamiReport, location *time.Location) string {
	if !report.Authenticated {
		return noClientCertificate + "\n"
	}

	client := report.Client

	var b strings.Builder
	fmt.Fprint(&b, "🔐 Verified Client Certificate:\n\n")
	fmt.Fprintf(&b, "Subject: %s\n", client.Subject)
	fmt.Fprintf(&b, "Issuer: %s\n", client.Issuer)
	fmt.Fprintf(&b, "Serial: %s\n", client.Serial)
	fmt.Fprintf(&b, "Fingerprint (SHA-256): %s\n", client.FingerprintSHA256)
	fmt.Fprintf(&b, "Valid: %s to %s\n",
		formatTime(client.NotBefore, location),
		formatTime(client.NotAfter, location))

	for _, name := range client.DNSNames {
		fmt.Fprintf(&b, "  DNS: %s\n", name)
	}
	for _, uri := range client.URIs {
		fmt.Fprintf(&b, "  URI: %s\n", uri)
	}
	for _, email := range client.EmailAddresses {
		fmt.Fprintf(&b, "  Email: %s\n", email)
	}
	for _, ip := range client.IPAddresses {
		fmt.Fprintf(&b, "  IP: %s\n", ip)
	}

	fmt.Fprint(&b, "Chain:\n")
	for _, subject := range client.Chain {
		fmt.Fprintf(&b, "  %s\n", subject)
	}

	return b.String()
}
