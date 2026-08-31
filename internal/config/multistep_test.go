package config

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// TestRecipesBuildMultiStep proves a `type: multistep` identity parses from YAML
// and builds a working recipe: the built recipe fetches the CSRF token, threads
// it into the POST, and captures the resulting cookie and bearer.
func TestRecipesBuildMultiStep(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Write([]byte(`<input name="csrf" value="TOK123">`))
			return
		}
		r.ParseForm()
		if r.PostFormValue("csrf") != "TOK123" || r.PostFormValue("password") != "pw" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc", Path: "/"})
		w.Write([]byte(`{"access_token":"bearer1"}`))
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	yaml := `
target: ` + ts.URL + `
identities:
  - name: alice
    type: multistep
    password: pw
    steps:
      - method: GET
        url: ` + ts.URL + `/login
        extract:
          - {name: csrf, from: body, pattern: 'name="csrf" value="([^"]+)"'}
      - method: POST
        url: ` + ts.URL + `/login
        form: {username: alice, password: "{{password}}", csrf: "{{csrf}}"}
    capture:
      csrf: "{{csrf}}"
      bearer: {from: json, pattern: access_token}
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
	recipes, err := cfg.Recipes()
	if err != nil {
		t.Fatal(err)
	}
	r, ok := recipes["alice"]
	if !ok {
		t.Fatal("missing alice multistep recipe")
	}
	sess, err := r.Establish(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sess.BearerToken != "bearer1" {
		t.Fatalf("bearer = %q, want bearer1", sess.BearerToken)
	}
	if sess.CSRF != "TOK123" {
		t.Fatalf("csrf = %q, want TOK123", sess.CSRF)
	}
	found := false
	for _, c := range sess.Cookies {
		if c.Name == "session" && c.Value == "abc" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected session cookie captured, got %v", sess.Cookies)
	}
}
