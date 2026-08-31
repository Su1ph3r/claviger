package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestResolveSecretsEnvFileCommand(t *testing.T) {
	t.Setenv("CLV_PW", "envpass")
	dir := t.TempDir()
	pwFile := filepath.Join(dir, "pw")
	os.WriteFile(pwFile, []byte("filepass\n"), 0o600)

	cfg := &Config{Target: "https://x", Identities: []IdentityConfig{
		{Name: "env", Type: "form", Password: "${CLV_PW}"},
		{Name: "file", Type: "form", PasswordFile: pwFile},
		{Name: "cmd", Type: "form", PasswordCommand: "printf cmdpass"},
	}}
	if err := cfg.resolveSecrets(); err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, id := range cfg.Identities {
		got[id.Name] = id.Password
	}
	for name, want := range map[string]string{"env": "envpass", "file": "filepass", "cmd": "cmdpass"} {
		if got[name] != want {
			t.Errorf("%s password = %q, want %q", name, got[name], want)
		}
	}
}

func TestResolveSecretsMissingEnvErrors(t *testing.T) {
	cfg := &Config{Identities: []IdentityConfig{{Name: "a", Password: "${DEFINITELY_UNSET_CLV}"}}}
	if err := cfg.resolveSecrets(); err == nil {
		t.Fatal("expected an error for an unset env var")
	}
}
