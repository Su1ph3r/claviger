package session

import (
	"net/http"
	"testing"
	"time"
)

func TestApplyInjectsBearerAndCookie(t *testing.T) {
	s := &Session{
		BearerToken: "abc",
		Cookies:     []*http.Cookie{{Name: "session", Value: "xyz"}},
		CSRF:        "csrf1",
		Headers:     http.Header{"X-Test": {"1"}},
	}
	req, _ := http.NewRequest("GET", "http://t/", nil)
	s.Apply(req)

	if got := req.Header.Get("Authorization"); got != "Bearer abc" {
		t.Fatalf("Authorization = %q", got)
	}
	if c, _ := req.Cookie("session"); c == nil || c.Value != "xyz" {
		t.Fatal("session cookie not applied")
	}
	if req.Header.Get("X-CSRF-Token") != "csrf1" {
		t.Fatal("csrf header not applied")
	}
	if req.Header.Get("X-Test") != "1" {
		t.Fatal("extra header not applied")
	}
}

func TestExpired(t *testing.T) {
	now := time.Now()
	if (&Session{}).Expired(now) {
		t.Fatal("zero ExpiresAt should never be expired")
	}
	if !(&Session{ExpiresAt: now.Add(-time.Second)}).Expired(now) {
		t.Fatal("past ExpiresAt should be expired")
	}
}
