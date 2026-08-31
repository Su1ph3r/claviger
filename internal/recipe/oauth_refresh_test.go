package recipe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/Su1ph3r/claviger/internal/session"
)

// When a refresh-grant response omits refresh_token (the server does not rotate),
// the prior refresh token must be carried forward, not overwritten with "".
func TestOAuth2RefreshCarriesForwardToken(t *testing.T) {
	var refreshCalls int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		switch r.FormValue("grant_type") {
		case "password":
			w.Write([]byte(`{"access_token":"a1","refresh_token":"r1","expires_in":60}`))
		case "refresh_token":
			refreshCalls++
			w.Write([]byte(`{"access_token":"a2","expires_in":60}`)) // no refresh_token
		default:
			w.WriteHeader(400)
		}
	}))
	defer ts.Close()

	r := &OAuth2{ID: "bob", TokenURL: ts.URL, Username: "bob", Password: "pw"}
	sess, err := r.Establish(context.Background())
	if err != nil || sess.RefreshToken != "r1" {
		t.Fatalf("establish sess=%+v err=%v", sess, err)
	}
	refreshed, err := r.Refresh(context.Background(), sess)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.BearerToken != "a2" {
		t.Fatalf("bearer = %q, want a2", refreshed.BearerToken)
	}
	if refreshed.RefreshToken != "r1" {
		t.Fatalf("refresh token = %q, want carried-forward r1", refreshed.RefreshToken)
	}
	if refreshCalls != 1 {
		t.Fatalf("refresh grant called %d times, want 1", refreshCalls)
	}
}

// A revoked refresh token (refresh grant fails) must fall back to a fresh password
// grant so the identity recovers rather than failing every cycle.
func TestOAuth2RefreshFallsBackToEstablish(t *testing.T) {
	var passwordGrants int
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		w.Header().Set("Content-Type", "application/json")
		switch r.FormValue("grant_type") {
		case "password":
			passwordGrants++
			w.Write([]byte(`{"access_token":"fresh","refresh_token":"r2","expires_in":60}`))
		case "refresh_token":
			w.WriteHeader(400)
			w.Write([]byte(`{"error":"invalid_grant"}`))
		}
	}))
	defer ts.Close()

	r := &OAuth2{ID: "bob", TokenURL: ts.URL, Username: "bob", Password: "pw"}
	cur := &session.Session{Identity: "bob", BearerToken: "old", RefreshToken: "revoked"}
	refreshed, err := r.Refresh(context.Background(), cur)
	if err != nil {
		t.Fatalf("refresh should fall back to establish, got err %v", err)
	}
	if refreshed.BearerToken != "fresh" {
		t.Fatalf("bearer = %q, want fresh (password fallback)", refreshed.BearerToken)
	}
	if passwordGrants != 1 {
		t.Fatalf("password grant called %d times, want 1", passwordGrants)
	}
}
