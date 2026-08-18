// Package config parses and validates the process configuration from the
// environment. All environment access in this application happens here, once,
// at startup, so that the rest of the code depends on typed values instead of
// on the ambient process environment.
package config

import (
	"errors"
	"fmt"
	"net"
	"os"
	"strconv"
	"time"
)

// lookupEnv is the production LookupFunc.
func lookupEnv(key string) (string, bool) { return os.LookupEnv(key) }

// Default values applied when the corresponding variable is unset.
const (
	DefaultPort               = 8443
	DefaultCertificateFile    = "./certs/demo.pem"
	DefaultKeyFile            = "./certs/demo-key.pem"
	DefaultShutdownTimeout    = 10 * time.Second
	DefaultReloadDebounce     = 500 * time.Millisecond
	DefaultReloadInterval     = 30 * time.Second
	DefaultMaximumStalePeriod = 15 * time.Minute
)

// Config is the fully resolved, validated process configuration.
type Config struct {
	// Address is the listen address for the HTTPS server, in host:port form.
	Address string

	// CertificateFile and KeyFile point at the PEM material to serve. When a
	// bundle is configured both fields hold the same path.
	CertificateFile string
	KeyFile         string

	// Timezone is used to render timestamps in log and status output.
	Timezone *time.Location

	// ShutdownTimeout bounds how long in-flight requests may drain for.
	ShutdownTimeout time.Duration

	// ReloadDebounce is the quiet period observed after a filesystem event
	// before the certificate is re-read.
	ReloadDebounce time.Duration

	// ReloadInterval is how often the certificate is reconciled against disk
	// regardless of filesystem events.
	ReloadInterval time.Duration

	// MaximumStalePeriod is how long the reloader may fail to observe the
	// certificate source before readiness starts failing.
	MaximumStalePeriod time.Duration

	// AllowExpiredCertificate permits startup with an already-expired
	// certificate. The certificate is then served and reported as expired
	// rather than causing startup to fail.
	AllowExpiredCertificate bool

	// PodName and PodNamespace are optional Kubernetes identity hints shown on
	// the diagnostic endpoint.
	PodName      string
	PodNamespace string

	// ClientCAFile is the PEM file of client CA certificates that client
	// certificates are verified against. Empty means client-certificate
	// verification is disabled and the server requests no certificate.
	ClientCAFile string
}

// LookupFunc resolves an environment variable. It matches os.LookupEnv so that
// tests can supply a deterministic environment without mutating the process.
type LookupFunc func(key string) (string, bool)

// Load reads the configuration from the process environment.
func Load() (Config, error) {
	return LoadFrom(lookupEnv)
}

// LoadFrom reads the configuration using the supplied lookup function.
func LoadFrom(lookup LookupFunc) (Config, error) {
	var errs []error

	certFile, keyFile, err := certificatePaths(lookup)
	if err != nil {
		errs = append(errs, err)
	}

	port, err := intVar(lookup, "GOWEB_PORT", DefaultPort)
	if err != nil {
		errs = append(errs, err)
	} else if port < 1 || port > 65535 {
		errs = append(errs, fmt.Errorf("GOWEB_PORT: %d is out of range 1-65535", port))
	}

	location, err := timezone(lookup)
	if err != nil {
		errs = append(errs, err)
	}

	shutdownTimeout, err := durationVar(lookup, "GOWEB_SHUTDOWN_TIMEOUT", DefaultShutdownTimeout)
	if err != nil {
		errs = append(errs, err)
	}

	reloadDebounce, err := durationVar(lookup, "GOWEB_RELOAD_DEBOUNCE", DefaultReloadDebounce)
	if err != nil {
		errs = append(errs, err)
	}

	reloadInterval, err := durationVar(lookup, "GOWEB_RELOAD_INTERVAL", DefaultReloadInterval)
	if err != nil {
		errs = append(errs, err)
	}

	maximumStale, err := durationVar(lookup, "GOWEB_MAX_STALE_PERIOD", DefaultMaximumStalePeriod)
	if err != nil {
		errs = append(errs, err)
	}

	allowExpired, err := boolVar(lookup, "GOWEB_ALLOW_EXPIRED_CERTIFICATE", false)
	if err != nil {
		errs = append(errs, err)
	}

	clientCAFile, err := clientCAPath(lookup)
	if err != nil {
		errs = append(errs, err)
	}

	if err := errors.Join(errs...); err != nil {
		return Config{}, err
	}

	return Config{
		Address:                 net.JoinHostPort("", strconv.Itoa(port)),
		CertificateFile:         certFile,
		KeyFile:                 keyFile,
		Timezone:                location,
		ShutdownTimeout:         shutdownTimeout,
		ReloadDebounce:          reloadDebounce,
		ReloadInterval:          reloadInterval,
		MaximumStalePeriod:      maximumStale,
		AllowExpiredCertificate: allowExpired,
		PodName:                 stringVar(lookup, "POD_NAME", ""),
		PodNamespace:            stringVar(lookup, "POD_NAMESPACE", ""),
		ClientCAFile:            clientCAFile,
	}, nil
}

// certificatePaths resolves the certificate and key locations.
//
// GOWEB_X509_BUNDLE names a single file holding both the key and the
// certificate and takes precedence over the separate GOWEB_X509_CER and
// GOWEB_X509_KEY paths. The separate paths must be supplied together: setting
// only one of them is an operator mistake rather than a request to fall back to
// the demo material for the other half.
func certificatePaths(lookup LookupFunc) (certFile, keyFile string, err error) {
	if bundle, ok := lookup("GOWEB_X509_BUNDLE"); ok {
		if bundle == "" {
			return "", "", errors.New("GOWEB_X509_BUNDLE: must not be empty when set")
		}
		return bundle, bundle, nil
	}

	cert, certSet := lookup("GOWEB_X509_CER")
	key, keySet := lookup("GOWEB_X509_KEY")

	switch {
	case certSet != keySet:
		return "", "", errors.New("GOWEB_X509_CER and GOWEB_X509_KEY must be set together")
	case certSet && cert == "":
		return "", "", errors.New("GOWEB_X509_CER: must not be empty when set")
	case keySet && key == "":
		return "", "", errors.New("GOWEB_X509_KEY: must not be empty when set")
	case !certSet:
		return DefaultCertificateFile, DefaultKeyFile, nil
	}

	return cert, key, nil
}

// clientCAPath resolves the client CA trust store location.
//
// The variable being set is what enables client-certificate verification.
// There is no separate boolean, because a second variable that can disagree
// with this one is a way to be misconfigured rather than a feature. Set but
// empty is an operator mistake, matching certificatePaths.
func clientCAPath(lookup LookupFunc) (string, error) {
	value, ok := lookup("GOWEB_MTLS_CLIENT_CA")
	if !ok {
		return "", nil
	}
	if value == "" {
		return "", errors.New("GOWEB_MTLS_CLIENT_CA: must not be empty when set")
	}
	return value, nil
}

// timezone resolves the display timezone. An explicitly configured but
// unloadable timezone fails startup: it is operator configuration, not an
// optional value that is reasonable to silently ignore.
func timezone(lookup LookupFunc) (*time.Location, error) {
	for _, name := range []string{"TZ", "TIMEZONE"} {
		value, ok := lookup(name)
		if !ok || value == "" {
			continue
		}
		location, err := time.LoadLocation(value)
		if err != nil {
			return nil, fmt.Errorf("%s: %q is not a known timezone: %w", name, value, err)
		}
		return location, nil
	}
	return time.UTC, nil
}

func stringVar(lookup LookupFunc, name, fallback string) string {
	if value, ok := lookup(name); ok && value != "" {
		return value
	}
	return fallback
}

func intVar(lookup LookupFunc, name string, fallback int) (int, error) {
	raw, ok := lookup(name)
	if !ok || raw == "" {
		return fallback, nil
	}
	value, err := strconv.Atoi(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not a number", name, raw)
	}
	return value, nil
}

func boolVar(lookup LookupFunc, name string, fallback bool) (bool, error) {
	raw, ok := lookup(name)
	if !ok || raw == "" {
		return fallback, nil
	}
	value, err := strconv.ParseBool(raw)
	if err != nil {
		return false, fmt.Errorf("%s: %q is not a boolean", name, raw)
	}
	return value, nil
}

func durationVar(lookup LookupFunc, name string, fallback time.Duration) (time.Duration, error) {
	raw, ok := lookup(name)
	if !ok || raw == "" {
		return fallback, nil
	}
	value, err := time.ParseDuration(raw)
	if err != nil {
		return 0, fmt.Errorf("%s: %q is not a duration", name, raw)
	}
	if value <= 0 {
		return 0, fmt.Errorf("%s: %s must be positive", name, value)
	}
	return value, nil
}
