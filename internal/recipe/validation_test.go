package recipe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Su1ph3r/claviger/testutil/mockauth"
)

// A 200 login that carries neither a cookie nor a token is not a real session and
// must be rejected rather than cached as an empty (no-op) session.
func TestFormPostRejectsEmptySession(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(200) // no Set-Cookie, no token body
	}))
	defer ts.Close()

	r := &FormPost{ID: "x", LoginURL: ts.URL, Username: "u", Password: "p"}
	if _, err := r.Establish(context.Background()); err == nil {
		t.Fatal("expected an error when login returns no cookie and no token")
	}
}

func TestFormPostSetsExpiryFromExpiresIn(t *testing.T) {
	ts := httptest.NewServer(mockauth.New(time.Minute).Handler()) // mock returns expires_in: 60
	defer ts.Close()

	r := &FormPost{ID: "alice", LoginURL: ts.URL + "/login", Username: "alice", Password: "pw"}
	sess, err := r.Establish(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if sess.ExpiresAt.IsZero() {
		t.Fatal("expected ExpiresAt to be set from expires_in")
	}
	if d := time.Until(sess.ExpiresAt); d < 30*time.Second || d > 90*time.Second {
		t.Fatalf("ExpiresAt %v is not ~60s out (delta %v)", sess.ExpiresAt, d)
	}
}

// A pathological expires_in (a lifetime mistakenly reported in milliseconds) must
// not overflow the seconds->duration multiply and wrap to a past time, which would
// mark the session expired immediately and force endless refreshes.
func TestExpiresAtClampsOverflow(t *testing.T) {
	got := expiresAt(31536000000) // one year expressed in milliseconds
	if !got.After(time.Now()) {
		t.Fatalf("clamped expiry must be in the future, got %v", got)
	}
	if !expiresAt(0).IsZero() || !expiresAt(-5).IsZero() {
		t.Fatal("non-positive expires_in must yield the zero time (unknown)")
	}
}

// A 200 token response with no access_token (e.g. a 200-wrapped error) is rejected.
func TestOAuth2RejectsEmptyToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"error":"invalid_grant"}`))
	}))
	defer ts.Close()

	r := &OAuth2{ID: "bob", TokenURL: ts.URL, Username: "bob", Password: "pw"}
	if _, err := r.Establish(context.Background()); err == nil {
		t.Fatal("expected an error when the token response has no access_token")
	}
}
