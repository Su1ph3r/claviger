package recipe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// loginPage serves a self-contained login form. Submitting it (client-side, no
// real POST) sets a session cookie, stashes a bearer in localStorage, and swaps
// in a #home element so the success wait has a stable selector to latch onto.
const loginPage = `<!doctype html>
<html><body>
<form id="login" onsubmit="return doLogin(event)">
  <input id="user" name="user">
  <input id="pass" name="pass" type="password">
  <button type="submit">Sign in</button>
</form>
<div id="app"></div>
<script>
function doLogin(e) {
  e.preventDefault();
  document.cookie = "session=ok; path=/";
  localStorage.setItem("access_token", "b1");
  var d = document.createElement("div");
  d.id = "home";
  d.textContent = "welcome";
  document.getElementById("app").appendChild(d);
  history.pushState({}, "", "/dashboard");
  return false;
}
</script>
</body></html>`

// TestBrowserEstablishHeadless drives the chromedp recipe against a local login
// page and asserts it captures both the cookie and the localStorage bearer. It
// skips when no Chrome/Chromium is present; on this machine Chrome is installed,
// so it must actually run.
func TestBrowserEstablishHeadless(t *testing.T) {
	if chromePath() == "" {
		t.Skip("chrome not available")
	}

	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(loginPage))
	}))
	defer ts.Close()

	r := &Browser{
		ID:                 "sso",
		LoginURL:           ts.URL + "/login",
		UsernameSelector:   "#user",
		PasswordSelector:   "#pass",
		SubmitSelector:     "button[type=submit]",
		SuccessSelector:    "#home",
		BearerLocalStorage: "access_token",
		Username:           "alice",
		Password:           "secret",
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	sess, err := r.Establish(ctx)
	if err != nil {
		t.Fatalf("Establish: %v", err)
	}
	if sess.BearerToken != "b1" {
		t.Fatalf("BearerToken = %q, want b1", sess.BearerToken)
	}
	found := false
	for _, c := range sess.Cookies {
		if c.Name == "session" && c.Value == "ok" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected session=ok cookie, got %v", sess.Cookies)
	}
}

// TestBrowserEstablishInsecureTLS serves the login page over a self-signed HTTPS
// server (httptest.NewTLSServer) and drives the recipe with Insecure:true. Chrome
// validates the certificate itself, independent of any injected HTTP client, so
// without the ignore-certificate-errors flag the page never loads and the run
// hangs to the timeout. The test asserts the session material is captured, proving
// the flag lets Chrome reach a self-signed IdP. It skips when Chrome is absent; on
// this machine Chrome is installed, so it must actually run.
func TestBrowserEstablishInsecureTLS(t *testing.T) {
	if chromePath() == "" {
		t.Skip("chrome not available")
	}

	ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write([]byte(loginPage))
	}))
	defer ts.Close()

	r := &Browser{
		ID:                 "sso-tls",
		LoginURL:           ts.URL + "/login",
		UsernameSelector:   "#user",
		PasswordSelector:   "#pass",
		SubmitSelector:     "button[type=submit]",
		SuccessSelector:    "#home",
		BearerLocalStorage: "access_token",
		Username:           "alice",
		Password:           "secret",
		Insecure:           true,
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	sess, err := r.Establish(ctx)
	if err != nil {
		t.Fatalf("Establish over self-signed TLS: %v", err)
	}
	if sess.BearerToken != "b1" {
		t.Fatalf("BearerToken = %q, want b1", sess.BearerToken)
	}
	found := false
	for _, c := range sess.Cookies {
		if c.Name == "session" && c.Value == "ok" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected session=ok cookie over self-signed TLS, got %v", sess.Cookies)
	}
}
