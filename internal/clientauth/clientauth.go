// Package clientauth owns the client-certificate trust store and the
// extraction of a verified client identity from a TLS connection.
//
// It is a separate package from internal/server so that deciding what "the
// verified client" means is one decision made in one place. The server
// consumes the result through the narrow Identity type, the same way it
// consumes certreload.Info.
package clientauth

import (
	"crypto/x509"
	"fmt"
	"os"
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
