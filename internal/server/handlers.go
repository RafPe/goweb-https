package server

import (
	"fmt"
	"net/http"
	"strings"
	"time"
)

// expiryWarningThreshold is how close to expiry a certificate must be before
// status output flags it.
const expiryWarningThreshold = 30 * time.Minute

// handleRoot serves the human-facing landing page.
func handleRoot(deps Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var b strings.Builder

		fmt.Fprintf(&b, "Hello there! I am serving this content via https :) \n")
		fmt.Fprintf(&b, "🖥️ Server: %s\n", deps.Hostname)
		fmt.Fprintf(&b, "⏰ Time: %s\n", formatTime(deps.Now(), deps.Location))
		fmt.Fprintf(&b, "🌐 Client IP: %s\n", r.RemoteAddr)

		if state := r.TLS; state != nil && len(state.PeerCertificates) > 0 {
			peer := state.PeerCertificates[0]
			fmt.Fprintf(&b, "🔐 SNI: %s\n", state.ServerName)
			fmt.Fprintf(&b, "📜 Certificate CN: %s\n", peer.Subject.CommonName)
			fmt.Fprintf(&b, "🏷️ Certificate SANs: %v\n", peer.DNSNames)
			fmt.Fprintf(&b, "⏳ Certificate Valid: %s to %s\n",
				formatTime(peer.NotBefore, deps.Location),
				formatTime(peer.NotAfter, deps.Location))
		}

		writeText(w, http.StatusOK, b.String())
	}
}

// handleStatus serves human-readable diagnostics.
//
// This endpoint is for operators, not for probes: use /livez and /readyz for
// those. It deliberately reports an expired certificate rather than failing,
// because surfacing that condition is the reason the endpoint exists.
func handleStatus(deps Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		report := buildStatus(deps, r)

		// A client that explicitly asked for JSON gets JSON from this path too,
		// so a scraper that cannot be pointed at a different URL still has a
		// machine-readable option. Anything else - including the Accept: */*
		// that curl and probes send - gets the human page.
		if prefersJSON(r) {
			writeJSON(w, deps, http.StatusOK, report)
			return
		}

		writeText(w, http.StatusOK, renderStatusText(report, deps.Location))
	}
}

// renderStatusText renders a status report as the human-readable page.
func renderStatusText(report StatusReport, location *time.Location) string {
	var b strings.Builder

	fmt.Fprintf(&b, "🖥️  Server Information:\n")
	fmt.Fprintf(&b, "   Hostname: %s\n", report.Server.Hostname)
	if report.Server.PodName != "" {
		fmt.Fprintf(&b, "   Pod Name: %s\n", report.Server.PodName)
	}
	if report.Server.PodNamespace != "" {
		fmt.Fprintf(&b, "   Pod Namespace: %s\n", report.Server.PodNamespace)
	}
	fmt.Fprintf(&b, "   Server Time: %s\n", formatTime(report.Server.Time, location))
	fmt.Fprintf(&b, "   Uptime: %s\n", time.Duration(report.Server.UptimeSeconds)*time.Second)
	fmt.Fprintf(&b, "   Request From: %s\n", report.Request.RemoteAddress)
	fmt.Fprintf(&b, "   User-Agent: %s\n", report.Request.UserAgent)

	// These headers are echoed exactly as received. They are attacker
	// controlled unless a trusted proxy is known to overwrite them, so they
	// are shown as diagnostics only and must not be treated as the client
	// identity.
	for _, name := range proxyHeaders {
		if value := report.Request.UnverifiedHeaders[name]; value != "" {
			fmt.Fprintf(&b, "   %s (unverified): %s\n", name, value)
		}
	}

	fmt.Fprint(&b, "\n📜 Certificate Status:\n\n")

	cert := report.Certificate
	if cert == nil {
		fmt.Fprint(&b, "No certificate is currently available.\n")
		return b.String()
	}

	fmt.Fprintf(&b, "File: %s\n", cert.FilePath)
	fmt.Fprintf(&b, "Issuer: %s\n", cert.Issuer)
	fmt.Fprintf(&b, "Subject: %s\n", cert.Subject)
	fmt.Fprintf(&b, "Serial: %s\n", cert.Serial)
	fmt.Fprintf(&b, "Fingerprint (SHA-256): %s\n", cert.FingerprintSHA256)
	fmt.Fprintf(&b, "Loaded At: %s\n", formatTime(cert.LoadedAt, location))

	fmt.Fprintf(&b, "Domains:\n")
	for _, domain := range cert.DNSNames {
		fmt.Fprintf(&b, "  Domain: %s\n", domain)
	}
	if len(cert.URIs) > 0 {
		fmt.Fprintf(&b, "URIs:\n")
		for _, uri := range cert.URIs {
			fmt.Fprintf(&b, "  URI: %s\n", uri)
		}
	}

	fmt.Fprintf(&b, "Valid: %s to %s\n",
		formatTime(cert.NotBefore, location),
		formatTime(cert.NotAfter, location))
	fmt.Fprintf(&b, "  Status: %s\n", describeValidity(*cert, report.Server.Time))

	if report.Readiness.Ready {
		fmt.Fprint(&b, "  Readiness: ✅ ready\n")
	} else {
		fmt.Fprintf(&b, "  Readiness: ❌ %s\n", report.Readiness.Reason)
	}

	fmt.Fprint(&b, "\n")
	return b.String()
}

// handleLive reports process liveness.
//
// Liveness stays process oriented: reaching this handler means the HTTP loop is
// running. Certificate problems are reported through readiness, because
// restarting the process does not fix rotated material that failed to load.
func handleLive() http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		writeText(w, http.StatusOK, "ok\n")
	}
}

// handleReady reports whether the server can serve TLS traffic.
func handleReady(deps Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, _ *http.Request) {
		if err := deps.Certificates.Ready(); err != nil {
			deps.Logger.Warn("readiness check failed", "err", err)
			writeText(w, http.StatusServiceUnavailable, fmt.Sprintf("not ready: %s\n", err))
			return
		}
		writeText(w, http.StatusOK, "ready\n")
	}
}

// describeValidity renders the certificate's validity state for humans.
//
// It reads the same Validity value the JSON document exposes, so the two
// representations can never disagree about whether a certificate is expired.
func describeValidity(cert CertificateStatus, now time.Time) string {
	switch cert.Validity {
	case "expired":
		return fmt.Sprintf("❌ EXPIRED (expired %s ago)", now.Sub(cert.NotAfter).Truncate(time.Second))
	case "not_yet_valid":
		return fmt.Sprintf("⏳ NOT YET VALID (valid in %s)", cert.NotBefore.Sub(now).Truncate(time.Second))
	case "valid":
		remaining := cert.NotAfter.Sub(now).Truncate(time.Second)
		if remaining < expiryWarningThreshold {
			return fmt.Sprintf("⚠️  EXPIRES SOON (in %s)", remaining)
		}
		return fmt.Sprintf("✅ Valid (expires in %s)", remaining)
	default:
		return "unknown"
	}
}

// formatTime renders t in the configured display timezone alongside UTC.
func formatTime(t time.Time, location *time.Location) string {
	utc := t.UTC().Format("2006-01-02 15:04:05 UTC")
	local := t.In(location).Format("2006-01-02 15:04:05 MST")
	if utc == local {
		return utc
	}
	return fmt.Sprintf("%s (%s)", local, utc)
}

// writeText sends a complete plain-text response.
//
// The body is assembled first so that the status code is chosen before anything
// is written, and so a single write can fail rather than twenty. A failed write
// means the client is gone, which no handler can act on, so the error is
// deliberately discarded here rather than at each call site.
func writeText(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write([]byte(body))
}
