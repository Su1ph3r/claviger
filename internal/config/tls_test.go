package config

import (
	"testing"
	"time"
)

func TestConfigParsesTLSAndBackoff(t *testing.T) {
	p := writeConfig(t, `
target: https://app.example.com
tls:
  insecure: true
backoff:
  max_burst: 4
  window: 30s
identities:
  - name: a
    type: form
    login_url: https://app.example.com/login
    username: u
    password: p
    tls:
      ca_cert: /tmp/ca.pem
    logout:
      status_codes: [401]
`)
	c, err := Load(p)
	if err != nil {
		t.Fatal(err)
	}
	if !c.TLS.Insecure {
		t.Fatal("global tls.insecure not parsed")
	}
	if c.Backoff.MaxBurst != 4 || c.Backoff.Window != 30*time.Second {
		t.Fatalf("backoff = %+v", c.Backoff)
	}
	if c.Identities[0].TLS == nil || c.Identities[0].TLS.CACert != "/tmp/ca.pem" {
		t.Fatalf("per-identity tls not parsed: %+v", c.Identities[0].TLS)
	}
	if hx := c.TLS.ToHTTPX(); !hx.InsecureSkipVerify {
		t.Fatal("ToHTTPX mapping wrong")
	}
}
