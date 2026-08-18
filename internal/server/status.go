package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/RafPe/goweb-https/internal/certreload"
)

// StatusReport is the full diagnostic status of the process.
//
// It is the single source of truth behind both representations of /status: the
// human-readable page and the JSON document. Rendering both from one struct is
// what keeps them from drifting apart.
type StatusReport struct {
	Server      ServerStatus       `json:"server"`
	Request     RequestStatus      `json:"request"`
	Certificate *CertificateStatus `json:"certificate"`
	Readiness   ReadinessStatus    `json:"readiness"`
}

// ServerStatus describes the process.
type ServerStatus struct {
	Hostname      string    `json:"hostname"`
	PodName       string    `json:"pod_name,omitempty"`
	PodNamespace  string    `json:"pod_namespace,omitempty"`
	Time          time.Time `json:"time"`
	StartedAt     time.Time `json:"started_at"`
	UptimeSeconds int64     `json:"uptime_seconds"`
}

// RequestStatus describes the request that asked for the status.
type RequestStatus struct {
	RemoteAddress string `json:"remote_address"`
	UserAgent     string `json:"user_agent,omitempty"`

	// UnverifiedHeaders holds proxy headers exactly as received. They are
	// supplied by the client and are only trustworthy if a proxy in front of
	// this server is known to overwrite them. The field name says so because a
	// machine consumer cannot read the caveat in the docs.
	UnverifiedHeaders map[string]string `json:"unverified_headers,omitempty"`
}

// CertificateStatus describes the certificate currently being served.
type CertificateStatus struct {
	FilePath          string    `json:"file_path"`
	Subject           string    `json:"subject"`
	Issuer            string    `json:"issuer"`
	Serial            string    `json:"serial"`
	FingerprintSHA256 string    `json:"fingerprint_sha256"`
	DNSNames          []string  `json:"dns_names"`
	URIs              []string  `json:"uris"`
	NotBefore         time.Time `json:"not_before"`
	NotAfter          time.Time `json:"not_after"`
	LoadedAt          time.Time `json:"loaded_at"`

	// Validity is one of "valid", "not_yet_valid" or "expired".
	Validity string `json:"validity"`

	// ExpiresInSeconds counts down to NotAfter and goes negative once the
	// certificate has expired, so a scrape can alert on a single number.
	ExpiresInSeconds int64 `json:"expires_in_seconds"`
}

// ReadinessStatus mirrors what /readyz reports.
type ReadinessStatus struct {
	Ready  bool   `json:"ready"`
	Reason string `json:"reason,omitempty"`
}

// proxyHeaders are echoed back as diagnostics. They are never trusted.
var proxyHeaders = []string{"X-Forwarded-For", "X-Real-IP", "X-Request-ID"}

// buildStatus gathers the current status.
func buildStatus(deps Dependencies, r *http.Request) StatusReport {
	now := deps.Now()

	report := StatusReport{
		Server: ServerStatus{
			Hostname:      deps.Hostname,
			PodName:       deps.PodName,
			PodNamespace:  deps.PodNamespace,
			Time:          now,
			StartedAt:     deps.StartedAt,
			UptimeSeconds: int64(now.Sub(deps.StartedAt).Seconds()),
		},
		Request: RequestStatus{
			RemoteAddress: r.RemoteAddr,
			UserAgent:     r.UserAgent(),
		},
	}

	for _, name := range proxyHeaders {
		if value := r.Header.Get(name); value != "" {
			if report.Request.UnverifiedHeaders == nil {
				report.Request.UnverifiedHeaders = make(map[string]string, len(proxyHeaders))
			}
			report.Request.UnverifiedHeaders[name] = value
		}
	}

	if err := deps.Certificates.Ready(); err != nil {
		report.Readiness = ReadinessStatus{Ready: false, Reason: err.Error()}
	} else {
		report.Readiness = ReadinessStatus{Ready: true}
	}

	info, ok := deps.Certificates.CertificateInfo()
	if !ok {
		// Explicitly null rather than an empty object: "no certificate" is a
		// distinct state from "a certificate with blank fields".
		return report
	}

	state, _ := info.State(now)
	report.Certificate = &CertificateStatus{
		FilePath:          info.FilePath,
		Subject:           info.Subject,
		Issuer:            info.Issuer,
		Serial:            info.Serial,
		FingerprintSHA256: info.Fingerprint,
		DNSNames:          emptyIfNil(info.DNSNames),
		URIs:              emptyIfNil(info.URIs),
		NotBefore:         info.NotBefore,
		NotAfter:          info.NotAfter,
		LoadedAt:          info.LoadedAt,
		Validity:          validityCode(state),
		ExpiresInSeconds:  int64(info.NotAfter.Sub(now).Seconds()),
	}

	return report
}

// validityCode renders the validity state as a stable JSON enum. It is
// deliberately separate from Validity.String, which is prose meant for humans
// and may be reworded; these values are a contract.
func validityCode(v certreload.Validity) string {
	switch v {
	case certreload.ValidityValid:
		return "valid"
	case certreload.ValidityNotYetValid:
		return "not_yet_valid"
	case certreload.ValidityExpired:
		return "expired"
	default:
		return "unknown"
	}
}

// emptyIfNil keeps list fields as [] rather than null, so consumers can iterate
// without a nil check.
func emptyIfNil(values []string) []string {
	if values == nil {
		return []string{}
	}
	return values
}

// handleStatusJSON serves the machine-readable status document.
func handleStatusJSON(deps Dependencies) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, deps, http.StatusOK, buildStatus(deps, r))
	}
}

// writeJSON encodes v and sends it as a complete response.
//
// The body is encoded first so that an encoding failure can still be turned
// into a 500, rather than being discovered halfway through a 200 that has
// already been committed to the wire.
func writeJSON(w http.ResponseWriter, deps Dependencies, status int, v any) {
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		writeJSONEncodeError(w, deps, err)
		return
	}
	writeJSONBody(w, status, body)
}

// writeCompactJSON encodes v as a single line and sends it as a complete
// response.
//
// Used by /whoami and /whoami.json, not /status: those are consumed by
// external e2e suites, where layout is noise and a single line is easier to
// match, log, and diff than an indented document.
func writeCompactJSON(w http.ResponseWriter, deps Dependencies, status int, v any) {
	body, err := json.Marshal(v)
	if err != nil {
		writeJSONEncodeError(w, deps, err)
		return
	}
	writeJSONBody(w, status, body)
}

// writeJSONEncodeError reports a JSON encoding failure as a 500. Shared by
// writeJSON and writeCompactJSON - and so by /status.json and /whoami.json
// alike - so the error path cannot drift between the two encodings. The
// message stays neutral across both endpoints rather than naming "status",
// so a /whoami.json failure doesn't misreport itself as a status-encoding
// problem.
func writeJSONEncodeError(w http.ResponseWriter, deps Dependencies, err error) {
	deps.Logger.Error("encoding JSON response failed", "err", err)
	http.Error(w, `{"error":"failed to encode response"}`, http.StatusInternalServerError)
}

// writeJSONBody sends body as a complete JSON response. Shared by writeJSON
// and writeCompactJSON so the trailing newline, the Content-Type header, and
// the WriteHeader-then-Write ordering cannot drift between the two encodings.
func writeJSONBody(w http.ResponseWriter, status int, body []byte) {
	body = append(body, '\n')

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(body)
}

// prefersJSON reports whether the client asked for JSON.
//
// This is a deliberately narrow check for an explicit "application/json" in
// Accept. A wildcard such as Accept: */* - which curl and most probes send -
// does not count, so the default for /status stays the human page and only a
// client that actually asked for JSON gets it.
func prefersJSON(r *http.Request) bool {
	for _, accept := range r.Header.Values("Accept") {
		for part := range strings.SplitSeq(accept, ",") {
			// Drop any parameters, such as a q-value.
			media, _, _ := strings.Cut(part, ";")
			if strings.EqualFold(strings.TrimSpace(media), "application/json") {
				return true
			}
		}
	}
	return false
}
