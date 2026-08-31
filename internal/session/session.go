package session

import (
	"net/http"
	"time"
)

// Session is the live authentication state for one identity.
type Session struct {
	Identity     string
	Cookies      []*http.Cookie
	BearerToken  string
	RefreshToken string
	CSRF         string
	Headers      http.Header
	ExpiresAt    time.Time
}

// Apply injects this session's auth into an outbound request.
func (s *Session) Apply(req *http.Request) {
	if s.BearerToken != "" {
		req.Header.Set("Authorization", "Bearer "+s.BearerToken)
	}
	for _, c := range s.Cookies {
		req.AddCookie(c)
	}
	if s.CSRF != "" {
		req.Header.Set("X-CSRF-Token", s.CSRF)
	}
	for k, vals := range s.Headers {
		for _, v := range vals {
			req.Header.Add(k, v)
		}
	}
}

// Expired reports whether the session is known to be past its expiry. A zero
// ExpiresAt means unknown, treated as not expired (the gateway relies on the
// logout signature instead).
func (s *Session) Expired(now time.Time) bool {
	return !s.ExpiresAt.IsZero() && now.After(s.ExpiresAt)
}
