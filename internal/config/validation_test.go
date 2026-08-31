package config

import (
	"os"
	"path/filepath"
	"testing"
)

func writeConfig(t *testing.T, body string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), "claviger.yaml")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadRejectsTargetWithoutScheme(t *testing.T) {
	p := writeConfig(t, "target: localhost:9000\nidentities: []\n")
	if _, err := Load(p); err == nil {
		t.Fatal("expected an error for a target with no http(s) scheme")
	}
}

func TestLoadAcceptsHTTPSTarget(t *testing.T) {
	p := writeConfig(t, "target: https://app.example.com\nidentities: []\n")
	if _, err := Load(p); err != nil {
		t.Fatalf("valid https target rejected: %v", err)
	}
}

func TestRecipesRejectsDuplicateName(t *testing.T) {
	c := &Config{Target: "https://x", Identities: []IdentityConfig{
		{Name: "a", Type: "form", LoginURL: "https://x/login"},
		{Name: "a", Type: "form", LoginURL: "https://x/login"},
	}}
	if _, err := c.Recipes(); err == nil {
		t.Fatal("expected a duplicate-name error")
	}
}

func TestRecipesRejectsMalformedLoginURL(t *testing.T) {
	c := &Config{Target: "https://x", Identities: []IdentityConfig{
		{Name: "a", Type: "form", LoginURL: "login.example.com/login"}, // no scheme
	}}
	if _, err := c.Recipes(); err == nil {
		t.Fatal("expected an error for a login URL without an http(s) scheme")
	}
}

func TestRecipesRejectsReservedAnon(t *testing.T) {
	c := &Config{Target: "https://x", Identities: []IdentityConfig{{Name: "anon", Type: "form"}}}
	if _, err := c.Recipes(); err == nil {
		t.Fatal("expected a reserved-name error for anon")
	}
}

func TestRecipesRejectsEmptyName(t *testing.T) {
	c := &Config{Target: "https://x", Identities: []IdentityConfig{{Name: "", Type: "form"}}}
	if _, err := c.Recipes(); err == nil {
		t.Fatal("expected an empty-name error")
	}
}
