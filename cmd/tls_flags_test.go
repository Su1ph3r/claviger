package cmd

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/Su1ph3r/claviger/internal/config"
)

func TestApplyTLSFlagsOverridesConfig(t *testing.T) {
	cfg := &config.Config{TLS: config.TLSConfig{Insecure: false}}
	applyTLSFlags(cfg, tlsFlags{insecure: true, insecureSet: true, caCert: "/x", caCertSet: true})
	if !cfg.TLS.Insecure || cfg.TLS.CACert != "/x" {
		t.Fatalf("flags did not override: %+v", cfg.TLS)
	}
}

func TestApplyTLSFlagsLeavesUnsetFieldsAlone(t *testing.T) {
	cfg := &config.Config{TLS: config.TLSConfig{
		Insecure:   true,
		CACert:     "/keep-ca",
		ClientCert: "/keep-cert",
		ClientKey:  "/keep-key",
	}}
	// Only client-cert is set on the command line; everything else must survive.
	applyTLSFlags(cfg, tlsFlags{clientCert: "/new-cert", clientCertSet: true})
	if !cfg.TLS.Insecure {
		t.Fatalf("unset --insecure clobbered configured value: %+v", cfg.TLS)
	}
	if cfg.TLS.CACert != "/keep-ca" || cfg.TLS.ClientKey != "/keep-key" {
		t.Fatalf("unset flags clobbered configured values: %+v", cfg.TLS)
	}
	if cfg.TLS.ClientCert != "/new-cert" {
		t.Fatalf("set --client-cert did not override: %+v", cfg.TLS)
	}
}

func TestWarnIfInsecureWritesWhenInsecure(t *testing.T) {
	var buf bytes.Buffer
	warnIfInsecure(&buf, &config.Config{TLS: config.TLSConfig{Insecure: true}})
	if !strings.Contains(buf.String(), "TLS verification disabled") {
		t.Fatalf("expected insecure warning, got %q", buf.String())
	}
}

// TestWarnIfInsecurePerIdentityWarnsAndNames covers an identity that disables TLS
// verification through its own tls block while the global policy stays secure. The
// warning must fire and name that identity, since it produces an insecure login
// client for that identity alone.
func TestWarnIfInsecurePerIdentityWarnsAndNames(t *testing.T) {
	var buf bytes.Buffer
	cfg := &config.Config{
		TLS: config.TLSConfig{Insecure: false},
		Identities: []config.IdentityConfig{
			{Name: "alice"},
			{Name: "bob", TLS: &config.TLSConfig{Insecure: true}},
		},
	}
	warnIfInsecure(&buf, cfg)
	out := buf.String()
	if !strings.Contains(out, "TLS verification disabled") {
		t.Fatalf("expected per-identity insecure warning, got %q", out)
	}
	if !strings.Contains(out, `"bob"`) {
		t.Fatalf("expected warning to name identity bob, got %q", out)
	}
	if strings.Contains(out, "global tls policy") {
		t.Fatalf("unexpected global warning when only per-identity is insecure: %q", out)
	}
	if strings.Contains(out, "alice") {
		t.Fatalf("secure identity alice should not be warned about: %q", out)
	}
}

func TestWarnIfInsecureSilentWhenSecure(t *testing.T) {
	var buf bytes.Buffer
	warnIfInsecure(&buf, &config.Config{TLS: config.TLSConfig{Insecure: false}})
	if buf.Len() != 0 {
		t.Fatalf("expected no warning when secure, got %q", buf.String())
	}
}

// TestStandaloneInsecureLoginWarns drives the identities command standalone (no
// daemon socket) with --insecure and asserts the warning lands on stderr, so an
// opt-in insecure run is never silent.
func TestStandaloneInsecureLoginWarns(t *testing.T) {
	cfg := "target: https://example.test\nidentities:\n  - name: alice\n    type: form\n    login_url: https://example.test/login\n    username: alice\n    password: pw\n"
	p := filepath.Join(t.TempDir(), "claviger.yaml")
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	// Point --socket at a path with no live daemon so the standalone branch runs.
	deadSocket := filepath.Join(t.TempDir(), "nope.sock")

	root := NewRootCmd()
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs([]string{"identities", "--config", p, "--socket", deadSocket, "--insecure"})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("identities --insecure failed: %v", err)
	}
	if !strings.Contains(errOut.String(), "TLS verification disabled") {
		t.Fatalf("expected insecure warning on stderr, got %q", errOut.String())
	}
	if !strings.Contains(out.String(), "alice") {
		t.Fatalf("expected identity listing on stdout, got %q", out.String())
	}
}

// TestStandaloneSecureIsSilent is the negative mutation check: without --insecure,
// no warning should appear.
func TestStandaloneSecureIsSilent(t *testing.T) {
	cfg := "target: https://example.test\nidentities:\n  - name: alice\n    type: form\n    login_url: https://example.test/login\n    username: alice\n    password: pw\n"
	p := filepath.Join(t.TempDir(), "claviger.yaml")
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	deadSocket := filepath.Join(t.TempDir(), "nope.sock")

	root := NewRootCmd()
	var out, errOut bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&errOut)
	root.SetArgs([]string{"identities", "--config", p, "--socket", deadSocket})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("identities failed: %v", err)
	}
	if strings.Contains(errOut.String(), "TLS verification disabled") {
		t.Fatalf("unexpected insecure warning when secure: %q", errOut.String())
	}
}

func TestRegisterTLSFlagsAddsFourFlags(t *testing.T) {
	cmd := newReplayCmd()
	for _, name := range []string{"insecure", "ca-cert", "client-cert", "client-key"} {
		if cmd.Flags().Lookup(name) == nil {
			t.Fatalf("flag --%s not registered on replay", name)
		}
	}
}
