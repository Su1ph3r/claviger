package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAndBuildRecipes(t *testing.T) {
	yaml := `
target: https://app.example.com
identities:
  - name: alice
    type: form
    login_url: https://app.example.com/login
    username: alice
    password: pw
    logout:
      status_codes: [401]
      body_contains: unauthenticated
  - name: bob
    type: oauth
    token_url: https://app.example.com/oauth/token
    username: bob
    password: pw
    logout:
      status_codes: [401]
`
	dir := t.TempDir()
	path := filepath.Join(dir, "claviger.yaml")
	if err := os.WriteFile(path, []byte(yaml), 0o600); err != nil {
		t.Fatal(err)
	}

	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Target != "https://app.example.com" {
		t.Fatalf("target = %q", cfg.Target)
	}
	recipes, err := cfg.Recipes()
	if err != nil {
		t.Fatal(err)
	}
	if len(recipes) != 2 {
		t.Fatalf("got %d recipes, want 2", len(recipes))
	}
	if _, ok := recipes["alice"]; !ok {
		t.Fatal("missing alice recipe")
	}
	if recipes["bob"].Identity() != "bob" {
		t.Fatal("bob recipe wrong identity")
	}
}
