package recipe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

// multistepServer mocks a CSRF-guarded form login: GET /login hands out a token
// in the HTML, POST /login demands that exact token plus the password, then sets
// a session cookie and returns a bearer JSON.
func multistepServer() *httptest.Server {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet {
			w.Header().Set("Content-Type", "text/html")
			w.Write([]byte(`<html><body><input name="csrf" value="TOK123"></body></html>`))
			return
		}
		r.ParseForm()
		if r.PostFormValue("csrf") != "TOK123" || r.PostFormValue("password") != "pw" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "session", Value: "abc", Path: "/"})
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"access_token":"bearer1"}`))
	})
	return httptest.NewServer(mux)
}

func multistepRecipe(base string) *MultiStep {
	return &MultiStep{
		ID:       "alice",
		Password: "pw",
		Steps: []Step{
			{Method: "GET", URL: base + "/login", Extract: []ExtractRule{
				{Name: "csrf", From: "body", Pattern: `name="csrf" value="([^"]+)"`},
			}},
			{Method: "POST", URL: base + "/login", Form: map[string]string{
				"username": "alice",
				"password": "{{password}}",
				"csrf":     "{{csrf}}",
			}},
		},
		Capture: CaptureSpec{
			CSRF:   "{{csrf}}",
			Bearer: &ExtractRule{From: "json", Pattern: "access_token"},
		},
		Signature: LogoutSignature{StatusCodes: []int{401}},
	}
}

func TestMultiStepEstablish(t *testing.T) {
	ts := multistepServer()
	defer ts.Close()

	// A green result here IS the mutation check: the POST only succeeds if the
	// csrf extracted from step 1's HTML was substituted into step 2's form. If the
	// {{csrf}} thread were broken, the server would 401 and this would fail.
	sess, err := multistepRecipe(ts.URL).Establish(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sess.Identity != "alice" {
		t.Fatalf("identity = %q", sess.Identity)
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
		t.Fatalf("expected session=abc cookie captured, got %v", sess.Cookies)
	}
}

func TestMultiStepWrongCSRFFails(t *testing.T) {
	ts := multistepServer()
	defer ts.Close()

	r := multistepRecipe(ts.URL)
	// Break the thread on purpose: post a wrong csrf literal instead of {{csrf}}.
	// The server must 401, and Establish must surface that as an error.
	r.Steps[1].Form["csrf"] = "WRONG"
	if _, err := r.Establish(context.Background()); err == nil {
		t.Fatal("expected establish to fail when the posted csrf is wrong")
	}
}

func TestMultiStepMissingExtractErrors(t *testing.T) {
	ts := multistepServer()
	defer ts.Close()

	r := multistepRecipe(ts.URL)
	// A required extract whose pattern matches nothing must error, not proceed
	// with an empty variable.
	r.Steps[0].Extract[0].Pattern = `name="nope" value="([^"]+)"`
	if _, err := r.Establish(context.Background()); err == nil {
		t.Fatal("expected establish to fail when a required extract yields nothing")
	}
}

func TestMultiStepKeepsInjectedTransport(t *testing.T) {
	ts := multistepServer()
	defer ts.Close()

	// The per-Establish client (which owns the cookie jar) must still route
	// through the injected transport, or a self-signed TLS target is unreachable.
	marker := &markerTransport{next: http.DefaultTransport}
	r := multistepRecipe(ts.URL)
	r.Client = &http.Client{Transport: marker}
	if _, err := r.Establish(context.Background()); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt64(&marker.calls) == 0 {
		t.Fatal("multistep did not keep the injected transport")
	}
}
