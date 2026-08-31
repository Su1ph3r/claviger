package httpx

import (
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestZeroConfigReachesNormalServer(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()
	c, err := Client(TLSConfig{})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Get(ts.URL)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("zero-config client failed: %v (status %v)", err, resp)
	}
}

func TestInsecureReachesSelfSigned(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	// A strict client rejects the self-signed cert.
	strict, _ := Client(TLSConfig{})
	if _, err := strict.Get(ts.URL); err == nil {
		t.Fatal("strict client should reject a self-signed server")
	}
	// An insecure client reaches it.
	insecure, err := Client(TLSConfig{InsecureSkipVerify: true})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := insecure.Get(ts.URL)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("insecure client failed: %v", err)
	}
}

func TestCustomCAAugmentsSystemRoots(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(200) }))
	defer ts.Close()
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	os.WriteFile(caFile, pemBytes, 0o600)

	tr, err := Transport(TLSConfig{CACertFile: caFile})
	if err != nil {
		t.Fatal(err)
	}
	pool := tr.TLSClientConfig.RootCAs
	if pool == nil {
		t.Fatal("RootCAs nil")
	}
	// The pool holds the custom CA plus the system roots (many), proving augmentation
	// rather than replacement. Skip where the platform exposes no enumerable system
	// roots: on macOS SystemCertPool returns a non-nil pool whose Subjects() is empty
	// because roots are fetched lazily from the OS keychain.
	if sys, _ := x509.SystemCertPool(); sys != nil && len(sys.Subjects()) > 0 {
		if len(pool.Subjects()) <= 1 {
			t.Fatalf("pool has %d subjects, expected system roots + custom CA", len(pool.Subjects()))
		}
	}
}

func TestCustomCATrustsServer(t *testing.T) {
	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200)
	}))
	defer ts.Close()

	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: ts.Certificate().Raw})
	caFile := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caFile, pemBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	c, err := Client(TLSConfig{CACertFile: caFile})
	if err != nil {
		t.Fatal(err)
	}
	resp, err := c.Get(ts.URL)
	if err != nil || resp.StatusCode != 200 {
		t.Fatalf("custom-CA client failed: %v", err)
	}
}
