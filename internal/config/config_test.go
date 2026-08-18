package config

import (
	"strings"
	"testing"
	"time"
)

// env builds a LookupFunc over a fixed map, so tests never mutate the process
// environment and can run in parallel.
func env(pairs map[string]string) LookupFunc {
	return func(key string) (string, bool) {
		value, ok := pairs[key]
		return value, ok
	}
}

func TestLoadFrom_Defaults(t *testing.T) {
	t.Parallel()

	cfg, err := LoadFrom(env(nil))
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}

	if cfg.Address != ":8443" {
		t.Errorf("address = %q, want %q", cfg.Address, ":8443")
	}
	if cfg.CertificateFile != DefaultCertificateFile {
		t.Errorf("certificate file = %q, want %q", cfg.CertificateFile, DefaultCertificateFile)
	}
	if cfg.KeyFile != DefaultKeyFile {
		t.Errorf("key file = %q, want %q", cfg.KeyFile, DefaultKeyFile)
	}
	if cfg.Timezone != time.UTC {
		t.Errorf("timezone = %v, want UTC", cfg.Timezone)
	}
	if cfg.ShutdownTimeout != DefaultShutdownTimeout {
		t.Errorf("shutdown timeout = %v, want %v", cfg.ShutdownTimeout, DefaultShutdownTimeout)
	}
	if cfg.AllowExpiredCertificate {
		t.Error("expired certificates should not be allowed by default")
	}
}

func TestLoadFrom_CertificatePaths(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		env      map[string]string
		wantCert string
		wantKey  string
		wantErr  string
	}{
		"bundle takes precedence": {
			env: map[string]string{
				"GOWEB_X509_BUNDLE": "/tls/bundle.pem",
				"GOWEB_X509_CER":    "/tls/cert.pem",
				"GOWEB_X509_KEY":    "/tls/key.pem",
			},
			wantCert: "/tls/bundle.pem",
			wantKey:  "/tls/bundle.pem",
		},
		"separate paths": {
			env: map[string]string{
				"GOWEB_X509_CER": "/tls/cert.pem",
				"GOWEB_X509_KEY": "/tls/key.pem",
			},
			wantCert: "/tls/cert.pem",
			wantKey:  "/tls/key.pem",
		},
		"certificate without key": {
			env:     map[string]string{"GOWEB_X509_CER": "/tls/cert.pem"},
			wantErr: "must be set together",
		},
		"key without certificate": {
			env:     map[string]string{"GOWEB_X509_KEY": "/tls/key.pem"},
			wantErr: "must be set together",
		},
		"empty bundle": {
			env:     map[string]string{"GOWEB_X509_BUNDLE": ""},
			wantErr: "must not be empty",
		},
		"empty certificate path": {
			env: map[string]string{
				"GOWEB_X509_CER": "",
				"GOWEB_X509_KEY": "/tls/key.pem",
			},
			wantErr: "must not be empty",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg, err := LoadFrom(env(tc.env))
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected an error containing %q", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Errorf("error = %v, want it to contain %q", err, tc.wantErr)
				}
				return
			}
			if err != nil {
				t.Fatalf("LoadFrom: %v", err)
			}
			if cfg.CertificateFile != tc.wantCert {
				t.Errorf("certificate file = %q, want %q", cfg.CertificateFile, tc.wantCert)
			}
			if cfg.KeyFile != tc.wantKey {
				t.Errorf("key file = %q, want %q", cfg.KeyFile, tc.wantKey)
			}
		})
	}
}

func TestLoadFrom_Validation(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		env     map[string]string
		wantErr string
	}{
		"non-numeric port":   {env: map[string]string{"GOWEB_PORT": "https"}, wantErr: "not a number"},
		"port out of range":  {env: map[string]string{"GOWEB_PORT": "99999"}, wantErr: "out of range"},
		"zero port":          {env: map[string]string{"GOWEB_PORT": "0"}, wantErr: "out of range"},
		"unknown timezone":   {env: map[string]string{"TZ": "Mars/Olympus"}, wantErr: "not a known timezone"},
		"bad duration":       {env: map[string]string{"GOWEB_RELOAD_INTERVAL": "soon"}, wantErr: "not a duration"},
		"negative duration":  {env: map[string]string{"GOWEB_SHUTDOWN_TIMEOUT": "-5s"}, wantErr: "must be positive"},
		"zero duration":      {env: map[string]string{"GOWEB_RELOAD_DEBOUNCE": "0s"}, wantErr: "must be positive"},
		"non-boolean toggle": {env: map[string]string{"GOWEB_ALLOW_EXPIRED_CERTIFICATE": "maybe"}, wantErr: "not a boolean"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			if _, err := LoadFrom(env(tc.env)); err == nil {
				t.Fatalf("expected an error containing %q", tc.wantErr)
			} else if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error = %v, want it to contain %q", err, tc.wantErr)
			}
		})
	}
}

// TestLoadFrom_ReportsAllProblems verifies that a misconfigured deployment shows
// every mistake at once rather than one per restart.
func TestLoadFrom_ReportsAllProblems(t *testing.T) {
	t.Parallel()

	_, err := LoadFrom(env(map[string]string{
		"GOWEB_PORT":            "nope",
		"TZ":                    "Mars/Olympus",
		"GOWEB_RELOAD_INTERVAL": "soon",
	}))
	if err == nil {
		t.Fatal("expected an error")
	}

	for _, want := range []string{"GOWEB_PORT", "TZ", "GOWEB_RELOAD_INTERVAL"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %v does not mention %s", err, want)
		}
	}
}

func TestLoadFromClientCA(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		env       map[string]string
		want      string
		wantError bool
	}{
		"unset means disabled": {
			env:  map[string]string{},
			want: "",
		},
		"set names the trust store": {
			env:  map[string]string{"GOWEB_MTLS_CLIENT_CA": "/tls/client-ca.pem"},
			want: "/tls/client-ca.pem",
		},
		"set but empty is an operator mistake": {
			env:       map[string]string{"GOWEB_MTLS_CLIENT_CA": ""},
			wantError: true,
		},
	}

	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			cfg, err := LoadFrom(env(test.env))

			if test.wantError {
				if err == nil {
					t.Fatal("LoadFrom returned no error, want one")
				}
				return
			}

			if err != nil {
				t.Fatalf("LoadFrom returned %v, want no error", err)
			}
			if cfg.ClientCAFile != test.want {
				t.Errorf("ClientCAFile = %q, want %q", cfg.ClientCAFile, test.want)
			}
		})
	}
}

func TestLoadFrom_Overrides(t *testing.T) {
	t.Parallel()

	cfg, err := LoadFrom(env(map[string]string{
		"GOWEB_PORT":                      "9443",
		"TIMEZONE":                        "Europe/Warsaw",
		"GOWEB_SHUTDOWN_TIMEOUT":          "25s",
		"GOWEB_RELOAD_DEBOUNCE":           "1s",
		"GOWEB_RELOAD_INTERVAL":           "45s",
		"GOWEB_MAX_STALE_PERIOD":          "5m",
		"GOWEB_ALLOW_EXPIRED_CERTIFICATE": "true",
		"POD_NAME":                        "goweb-0",
		"POD_NAMESPACE":                   "demo",
	}))
	if err != nil {
		t.Fatalf("LoadFrom: %v", err)
	}

	if cfg.Address != ":9443" {
		t.Errorf("address = %q, want %q", cfg.Address, ":9443")
	}
	if cfg.Timezone.String() != "Europe/Warsaw" {
		t.Errorf("timezone = %v, want Europe/Warsaw", cfg.Timezone)
	}
	if cfg.ShutdownTimeout != 25*time.Second {
		t.Errorf("shutdown timeout = %v, want 25s", cfg.ShutdownTimeout)
	}
	if cfg.ReloadInterval != 45*time.Second {
		t.Errorf("reload interval = %v, want 45s", cfg.ReloadInterval)
	}
	if cfg.MaximumStalePeriod != 5*time.Minute {
		t.Errorf("maximum stale period = %v, want 5m", cfg.MaximumStalePeriod)
	}
	if !cfg.AllowExpiredCertificate {
		t.Error("expected expired certificates to be allowed")
	}
	if cfg.PodName != "goweb-0" || cfg.PodNamespace != "demo" {
		t.Errorf("pod identity = %q/%q, want goweb-0/demo", cfg.PodName, cfg.PodNamespace)
	}
}
