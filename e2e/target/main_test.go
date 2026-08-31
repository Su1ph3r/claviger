package main

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

// startTestServer boots the target's mux over real HTTPS on 127.0.0.1:0 using
// an in-process self-signed cert, and returns the base URL plus a client that
// trusts it. The server is torn down when the test ends.
func startTestServer(t *testing.T, ttl time.Duration) (string, *http.Client) {
	t.Helper()

	cert, _, _, err := selfSignedCert([]string{"127.0.0.1", "localhost"})
	if err != nil {
		t.Fatalf("selfSignedCert: %v", err)
	}

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}

	srv := &http.Server{
		Handler:   newMux(ttl),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}
	go srv.ServeTLS(ln, "", "")
	t.Cleanup(func() { _ = srv.Close() })

	client := &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}},
		// Do not auto-follow redirects so we can inspect the /sso -> /dashboard hop.
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	return "https://" + ln.Addr().String(), client
}

// formLogin performs the /login form flow and returns the minted token.
func formLogin(t *testing.T, base string, client *http.Client, user, pass string) (*http.Response, string) {
	t.Helper()
	form := url.Values{"username": {user}, "password": {pass}}
	resp, err := client.PostForm(base+"/login", form)
	if err != nil {
		t.Fatalf("login post: %v", err)
	}
	if resp.StatusCode != http.StatusOK {
		return resp, ""
	}
	var body struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatalf("decode login: %v", err)
	}
	resp.Body.Close()
	return resp, body.AccessToken
}

func bearerGet(t *testing.T, base string, client *http.Client, path, token string) *http.Response {
	t.Helper()
	req, _ := http.NewRequest(http.MethodGet, base+path, nil)
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("get %s: %v", path, err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	return resp
}

func TestFormLoginReturnsTokenAndCookie(t *testing.T) {
	base, client := startTestServer(t, 2*time.Second)

	resp, token := formLogin(t, base, client, "alice", "pw")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("login status = %d, want 200", resp.StatusCode)
	}
	if token == "" {
		t.Fatal("login returned empty access_token")
	}
	var gotCookie bool
	for _, c := range resp.Cookies() {
		if c.Name == "session" && c.Value != "" {
			gotCookie = true
		}
	}
	if !gotCookie {
		t.Fatalf("login did not set a session cookie: %v", resp.Cookies())
	}
}

func TestFormLoginWrongCreds(t *testing.T) {
	base, client := startTestServer(t, 2*time.Second)
	resp, _ := formLogin(t, base, client, "alice", "wrong")
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bad login status = %d, want 401", resp.StatusCode)
	}
}

func TestRecordsObjectLevelAuthz(t *testing.T) {
	base, client := startTestServer(t, 2*time.Second)

	_, aliceTok := formLogin(t, base, client, "alice", "pw")
	_, bobTok := formLogin(t, base, client, "bob", "pw")

	if got := bearerGet(t, base, client, "/records/alice", aliceTok).StatusCode; got != http.StatusOK {
		t.Fatalf("alice -> /records/alice = %d, want 200", got)
	}
	if got := bearerGet(t, base, client, "/records/alice", bobTok).StatusCode; got != http.StatusForbidden {
		t.Fatalf("bob -> /records/alice = %d, want 403", got)
	}
	if got := bearerGet(t, base, client, "/records/alice", "").StatusCode; got != http.StatusUnauthorized {
		t.Fatalf("anon -> /records/alice = %d, want 401", got)
	}
}

func TestIdorBrokenBoundary(t *testing.T) {
	base, client := startTestServer(t, 2*time.Second)

	_, bobTok := formLogin(t, base, client, "bob", "pw")

	if got := bearerGet(t, base, client, "/idor/alice", bobTok).StatusCode; got != http.StatusOK {
		t.Fatalf("bob -> /idor/alice = %d, want 200 (broken boundary)", got)
	}
	if got := bearerGet(t, base, client, "/idor/alice", "").StatusCode; got != http.StatusUnauthorized {
		t.Fatalf("anon -> /idor/alice = %d, want 401", got)
	}
}

func TestTokenExpires(t *testing.T) {
	base, client := startTestServer(t, 200*time.Millisecond)

	_, tok := formLogin(t, base, client, "alice", "pw")
	if got := bearerGet(t, base, client, "/whoami", tok).StatusCode; got != http.StatusOK {
		t.Fatalf("fresh token -> /whoami = %d, want 200", got)
	}
	time.Sleep(250 * time.Millisecond)
	if got := bearerGet(t, base, client, "/whoami", tok).StatusCode; got != http.StatusUnauthorized {
		t.Fatalf("expired token -> /whoami = %d, want 401", got)
	}
}

func TestCsrfMissingFieldRejected(t *testing.T) {
	base, client := startTestServer(t, 2*time.Second)

	// Prime the csrf cookie by fetching the form.
	resp, err := client.Get(base + "/csrf-form")
	if err != nil {
		t.Fatalf("csrf-form get: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), `name="csrf"`) {
		t.Fatalf("csrf-form missing csrf field: %s", body)
	}

	// POST without the csrf field (cookie is sent automatically by the jar-less
	// client only if we forward it; forward the cookie so we isolate the missing field).
	form := url.Values{"username": {"alice"}, "password": {"pw"}}
	req, _ := http.NewRequest(http.MethodPost, base+"/csrf-login", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	for _, c := range resp.Cookies() {
		req.AddCookie(c)
	}
	post, err := client.Do(req)
	if err != nil {
		t.Fatalf("csrf-login post: %v", err)
	}
	io.Copy(io.Discard, post.Body)
	post.Body.Close()
	if post.StatusCode != http.StatusForbidden {
		t.Fatalf("csrf-login without csrf field = %d, want 403", post.StatusCode)
	}
}

func TestSelfSignedCertPEM(t *testing.T) {
	cert, certPEM, keyPEM, err := selfSignedCert([]string{"127.0.0.1", "localhost"})
	if err != nil {
		t.Fatalf("selfSignedCert: %v", err)
	}
	if len(cert.Certificate) == 0 {
		t.Fatal("empty certificate")
	}
	if !strings.Contains(string(certPEM), "BEGIN CERTIFICATE") {
		t.Fatalf("certPEM not PEM: %s", certPEM)
	}
	if !strings.Contains(string(keyPEM), "PRIVATE KEY") {
		t.Fatalf("keyPEM not PEM: %s", keyPEM)
	}
}

// fetchCSRF does GET /csrf-form and returns the issued csrf token (from the
// hidden field) and the csrf_cookie value, so a test can drive the double-submit
// POST without a cookie jar.
func fetchCSRF(t *testing.T, base string, client *http.Client) (token, cookie string) {
	t.Helper()
	resp, err := client.Get(base + "/csrf-form")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	m := regexp.MustCompile(`name="csrf" value="([^"]+)"`).FindSubmatch(body)
	if m == nil {
		t.Fatalf("csrf form did not contain a csrf token: %s", body)
	}
	for _, c := range resp.Cookies() {
		if c.Name == "csrf_cookie" {
			cookie = c.Value
		}
	}
	if cookie == "" {
		t.Fatal("csrf form did not set csrf_cookie")
	}
	return string(m[1]), cookie
}

// postCSRFLogin posts to /csrf-login with an explicit csrf field and csrf_cookie
// value (attached manually since the test client has no jar).
func postCSRFLogin(t *testing.T, base string, client *http.Client, user, pass, field, cookieVal string) *http.Response {
	t.Helper()
	form := url.Values{"username": {user}, "password": {pass}, "csrf": {field}}
	req, err := http.NewRequest(http.MethodPost, base+"/csrf-login", strings.NewReader(form.Encode()))
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: "csrf_cookie", Value: cookieVal})
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp
}

// TestCsrfHappyPathAndValidation pins the multistep double-submit CSRF check in
// both directions: a matching, issued token succeeds; a forged (never-issued)
// token fails even when field==cookie (pins validCSRF); a field/cookie mismatch
// fails (pins the double-submit compare). This is what the missing-field test
// could not catch, since that tripped the empty-field short-circuit.
func TestCsrfHappyPathAndValidation(t *testing.T) {
	base, client := startTestServer(t, 2*time.Second)

	// Happy path: issued token, field == cookie, valid creds -> 200 + token.
	tok, cookie := fetchCSRF(t, base, client)
	resp := postCSRFLogin(t, base, client, "alice", "pw", tok, cookie)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("csrf happy path status = %d, want 200", resp.StatusCode)
	}
	var payload struct {
		AccessToken string `json:"access_token"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil || payload.AccessToken == "" {
		t.Fatalf("csrf happy path did not return an access_token (err=%v)", err)
	}

	// Forged token: field == cookie but never issued -> 403 (pins validCSRF).
	forged := postCSRFLogin(t, base, client, "alice", "pw", "forged-not-issued", "forged-not-issued")
	forged.Body.Close()
	if forged.StatusCode != http.StatusForbidden {
		t.Errorf("forged csrf status = %d, want 403 (validCSRF should reject an unissued token)", forged.StatusCode)
	}

	// Mismatch: issued field but a different cookie -> 403 (pins double-submit).
	tok2, _ := fetchCSRF(t, base, client)
	mismatch := postCSRFLogin(t, base, client, "alice", "pw", tok2, "a-different-cookie")
	mismatch.Body.Close()
	if mismatch.StatusCode != http.StatusForbidden {
		t.Errorf("mismatched csrf status = %d, want 403 (double-submit should reject field != cookie)", mismatch.StatusCode)
	}
}

// TestOAuthPasswordGrant covers the oauth recipe's endpoint: a valid password
// grant returns a bearer access token; a bad grant type is 400; bad creds 401.
func TestOAuthPasswordGrant(t *testing.T) {
	base, client := startTestServer(t, 2*time.Second)

	resp, err := client.PostForm(base+"/oauth/token", url.Values{
		"grant_type": {"password"}, "username": {"alice"}, "password": {"pw"},
	})
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("oauth status = %d, want 200", resp.StatusCode)
	}
	var payload struct {
		AccessToken string `json:"access_token"`
		TokenType   string `json:"token_type"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		t.Fatal(err)
	}
	if payload.AccessToken == "" || payload.TokenType != "bearer" {
		t.Fatalf("oauth payload = %+v, want a bearer access_token", payload)
	}

	bad, err := client.PostForm(base+"/oauth/token", url.Values{
		"grant_type": {"client_credentials"}, "username": {"alice"}, "password": {"pw"},
	})
	if err != nil {
		t.Fatal(err)
	}
	bad.Body.Close()
	if bad.StatusCode != http.StatusBadRequest {
		t.Errorf("oauth wrong grant_type status = %d, want 400", bad.StatusCode)
	}

	wrong, err := client.PostForm(base+"/oauth/token", url.Values{
		"grant_type": {"password"}, "username": {"alice"}, "password": {"nope"},
	})
	if err != nil {
		t.Fatal(err)
	}
	wrong.Body.Close()
	if wrong.StatusCode != http.StatusUnauthorized {
		t.Errorf("oauth wrong creds status = %d, want 401", wrong.StatusCode)
	}
}
