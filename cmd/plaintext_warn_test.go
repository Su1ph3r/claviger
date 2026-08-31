package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/Su1ph3r/claviger/internal/config"
)

func TestWarnIfPlaintextAuth(t *testing.T) {
	cfg := &config.Config{
		Identities: []config.IdentityConfig{
			{Name: "plain", Type: "form", LoginURL: "http://app.test/login"},
			{Name: "secure", Type: "form", LoginURL: "https://app.test/login"},
			{Name: "tok", Type: "oauth", TokenURL: "http://idp.test/token"},
			// A multistep identity posts {{password}} to its step URLs; an http
			// step leaks the password just like an http login URL.
			{Name: "msplain", Type: "multistep", Steps: []config.StepConfig{
				{Method: "GET", URL: "https://app.test/form"},
				{Method: "POST", URL: "http://app.test/login", Form: map[string]string{"password": "{{password}}"}},
			}},
			{Name: "mssecure", Type: "multistep", Steps: []config.StepConfig{
				{Method: "POST", URL: "https://app.test/login"},
			}},
			// A templated step URL cannot be scheme-checked at config time; skip it.
			{Name: "mstemplate", Type: "multistep", Steps: []config.StepConfig{
				{Method: "POST", URL: "{{base}}/login"},
			}},
			// A literal http:// scheme with a templated host is still cleartext.
			{Name: "mshttphost", Type: "multistep", Steps: []config.StepConfig{
				{Method: "POST", URL: "http://{{host}}/login"},
			}},
		},
	}
	var buf bytes.Buffer
	warnIfPlaintextAuth(&buf, cfg)
	out := buf.String()
	if !strings.Contains(out, `"plain"`) || !strings.Contains(out, "cleartext") {
		t.Errorf("expected a plaintext warning for %q, got %q", "plain", out)
	}
	if !strings.Contains(out, `"tok"`) {
		t.Errorf("expected a plaintext warning for the token URL identity, got %q", out)
	}
	if !strings.Contains(out, `"msplain"`) {
		t.Errorf("expected a plaintext warning for the multistep identity with an http step, got %q", out)
	}
	if strings.Contains(out, `"secure"`) {
		t.Errorf("https identity should not warn, got %q", out)
	}
	if strings.Contains(out, `"mssecure"`) {
		t.Errorf("https multistep identity should not warn, got %q", out)
	}
	if strings.Contains(out, `"mstemplate"`) {
		t.Errorf("templated step URL should be skipped, got %q", out)
	}
	if !strings.Contains(out, `"mshttphost"`) {
		t.Errorf("a literal http:// scheme with a templated host should still warn, got %q", out)
	}
}
