package recipe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/Su1ph3r/claviger/internal/session"
)

// FormPost logs in by posting username and password to a form endpoint.
type FormPost struct {
	ID        string
	LoginURL  string
	Username  string
	Password  string
	UserField string // defaults to "username"
	PassField string // defaults to "password"
	Signature LogoutSignature
	Client    *http.Client // optional; nil uses http.DefaultClient
}

func (r *FormPost) Identity() string        { return r.ID }
func (r *FormPost) Logout() LogoutSignature { return r.Signature }

func (r *FormPost) client() *http.Client {
	if r.Client != nil {
		return r.Client
	}
	return http.DefaultClient
}

func (r *FormPost) Establish(ctx context.Context) (*session.Session, error) {
	uf, pf := r.UserField, r.PassField
	if uf == "" {
		uf = "username"
	}
	if pf == "" {
		pf = "password"
	}
	form := url.Values{uf: {r.Username}, pf: {r.Password}}
	req, err := http.NewRequestWithContext(ctx, "POST", r.LoginURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := r.client().Do(req)
	if err != nil {
		return nil, err
	}
	// Drain any trailing bytes before closing so the connection can return to the
	// idle pool; json.Decoder stops at the closing brace and would otherwise leave
	// the body partially read, forcing a fresh handshake on the next login.
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("login for %q failed: status %d", r.ID, resp.StatusCode)
	}

	var payload struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	// A missing or non-JSON body is tolerated: cookie-only logins are valid.
	json.NewDecoder(resp.Body).Decode(&payload)

	sess := &session.Session{
		Identity:     r.ID,
		Cookies:      resp.Cookies(),
		BearerToken:  payload.AccessToken,
		RefreshToken: payload.RefreshToken,
		ExpiresAt:    expiresAt(payload.ExpiresIn),
	}
	// A 200 that carried neither a cookie nor a token is not a real login (an HTML
	// interstitial, a 200-with-error-body). Reject it loudly rather than caching an
	// empty session that would silently inject nothing.
	if len(sess.Cookies) == 0 && sess.BearerToken == "" {
		return nil, fmt.Errorf("login for %q returned no session material (no cookie and no token)", r.ID)
	}
	return sess, nil
}

// Refresh for a form login re-runs Establish (there is no refresh grant).
func (r *FormPost) Refresh(ctx context.Context, _ *session.Session) (*session.Session, error) {
	return r.Establish(ctx)
}
