package config

import (
	"testing"

	"github.com/Su1ph3r/claviger/internal/recipe"
)

// TestRecipesBuildBrowser proves a `type: browser` identity parses from YAML and
// builds a recipe.Browser with the selectors, success condition, and the
// bearer_localstorage capture key threaded through. It does not launch Chrome.
func TestRecipesBuildBrowser(t *testing.T) {
	body := `
target: https://app.example.com
identities:
  - name: sso
    type: browser
    login_url: https://idp.example.com/login
    username_selector: "#user"
    password_selector: "#pass"
    submit_selector: "button[type=submit]"
    success_url_contains: "/dashboard"
    headful: true
    username: alice
    password: secret
    capture:
      bearer_localstorage: access_token
    logout:
      status_codes: [401]
`
	cfg, err := Load(writeConfig(t, body))
	if err != nil {
		t.Fatal(err)
	}
	recipes, err := cfg.Recipes()
	if err != nil {
		t.Fatal(err)
	}
	r, ok := recipes["sso"].(*recipe.Browser)
	if !ok {
		t.Fatalf("sso recipe is %T, want *recipe.Browser", recipes["sso"])
	}
	if r.LoginURL != "https://idp.example.com/login" {
		t.Errorf("LoginURL = %q", r.LoginURL)
	}
	if r.UsernameSelector != "#user" || r.PasswordSelector != "#pass" || r.SubmitSelector != "button[type=submit]" {
		t.Errorf("selectors not threaded: %+v", r)
	}
	if r.SuccessURLContains != "/dashboard" {
		t.Errorf("SuccessURLContains = %q", r.SuccessURLContains)
	}
	if !r.Headful {
		t.Error("Headful not threaded")
	}
	if r.BearerLocalStorage != "access_token" {
		t.Errorf("BearerLocalStorage = %q, want access_token", r.BearerLocalStorage)
	}
	if r.Username != "alice" || r.Password != "secret" {
		t.Error("credentials not threaded")
	}
	if len(r.Signature.StatusCodes) != 1 || r.Signature.StatusCodes[0] != 401 {
		t.Errorf("logout signature = %+v", r.Signature)
	}
	if r.Client == nil {
		t.Error("TLS client not injected for interface symmetry")
	}
}

// TestRecipesRejectsBrowserMalformedLoginURL proves the browser case validates
// its login_url at load, like the other recipes.
func TestRecipesRejectsBrowserMalformedLoginURL(t *testing.T) {
	c := &Config{Target: "https://x", Identities: []IdentityConfig{
		{Name: "sso", Type: "browser", LoginURL: "idp.example.com/login"}, // no scheme
	}}
	if _, err := c.Recipes(); err == nil {
		t.Fatal("expected an error for a browser login URL without an http(s) scheme")
	}
}
