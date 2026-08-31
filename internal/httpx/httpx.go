package httpx

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
)

// TLSConfig describes optional TLS relaxations/overrides for reaching a target.
type TLSConfig struct {
	InsecureSkipVerify bool
	CACertFile         string // PEM bundle added to the trusted roots
	ClientCertFile     string // client certificate (with ClientKeyFile) for mTLS
	ClientKeyFile      string
}

// Transport clones the default transport and applies the TLS config. A zero
// TLSConfig returns a transport equivalent to net/http's default.
func Transport(cfg TLSConfig) (*http.Transport, error) {
	base := http.DefaultTransport.(*http.Transport).Clone()
	tc := &tls.Config{InsecureSkipVerify: cfg.InsecureSkipVerify} //nolint:gosec // opt-in for pentest targets

	if cfg.CACertFile != "" {
		// Seed from the OS trust store so --ca-cert adds trust rather than
		// replacing it; fall back to a fresh pool if the system pool is
		// unavailable (e.g. some Windows/plan9 configurations).
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		pem, err := os.ReadFile(cfg.CACertFile)
		if err != nil {
			return nil, fmt.Errorf("read ca cert %q: %w", cfg.CACertFile, err)
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca cert %q: no certificates found", cfg.CACertFile)
		}
		tc.RootCAs = pool
	}

	if cfg.ClientCertFile != "" || cfg.ClientKeyFile != "" {
		if cfg.ClientCertFile == "" || cfg.ClientKeyFile == "" {
			return nil, fmt.Errorf("client cert and key must both be set")
		}
		cert, err := tls.LoadX509KeyPair(cfg.ClientCertFile, cfg.ClientKeyFile)
		if err != nil {
			return nil, fmt.Errorf("load client cert: %w", err)
		}
		tc.Certificates = []tls.Certificate{cert}
	}

	base.TLSClientConfig = tc
	return base, nil
}

// Client returns an *http.Client using the TLS transport. Callers that need a
// custom redirect policy set it on the returned client.
func Client(cfg TLSConfig) (*http.Client, error) {
	t, err := Transport(cfg)
	if err != nil {
		return nil, err
	}
	return &http.Client{Transport: t}, nil
}
