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

// OAuth2 logs in with the resource-owner password grant and refreshes with the
// refresh-token grant.
type OAuth2 struct {
	ID        string
	TokenURL  string
	Username  string
	Password  string
	Signature LogoutSignature
	Client    *http.Client // optional; nil uses http.DefaultClient
}

func (r *OAuth2) Identity() string        { return r.ID }
func (r *OAuth2) Logout() LogoutSignature { return r.Signature }

func (r *OAuth2) client() *http.Client {
	if r.Client != nil {
		return r.Client
	}
	return http.DefaultClient
}

func (r *OAuth2) token(ctx context.Context, form url.Values, prev *session.Session) (*session.Session, error) {
	req, err := http.NewRequestWithContext(ctx, "POST", r.TokenURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := r.client().Do(req)
	if err != nil {
		return nil, err
	}
	// Drain trailing bytes before closing so the connection can be reused; the
	// JSON decoder stops at the closing brace and would otherwise leave the body
	// partially read.
	defer func() {
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("token request for %q failed: status %d", r.ID, resp.StatusCode)
	}

	var payload struct {
		AccessToken  string `json:"access_token"`
		RefreshToken string `json:"refresh_token"`
		ExpiresIn    int    `json:"expires_in"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil, err
	}
	// A 200 that decoded to no access token is not a real grant (servers that
	// answer {"error":"invalid_grant"} with HTTP 200). Reject it rather than
	// caching a tokenless session that would inject nothing.
	if payload.AccessToken == "" {
		return nil, fmt.Errorf("token request for %q returned no access token", r.ID)
	}
	// The refresh_token field is optional in a refresh-grant response (RFC 6749
	// sec. 6): a server that does not rotate omits it, and the client must keep
	// reusing the prior one. Carry it forward rather than overwriting with "".
	refreshTok := payload.RefreshToken
	if refreshTok == "" && prev != nil {
		refreshTok = prev.RefreshToken
	}
	return &session.Session{
		Identity:     r.ID,
		BearerToken:  payload.AccessToken,
		RefreshToken: refreshTok,
		ExpiresAt:    expiresAt(payload.ExpiresIn),
	}, nil
}

func (r *OAuth2) Establish(ctx context.Context) (*session.Session, error) {
	return r.token(ctx, url.Values{
		"grant_type": {"password"},
		"username":   {r.Username},
		"password":   {r.Password},
	}, nil)
}

func (r *OAuth2) Refresh(ctx context.Context, cur *session.Session) (*session.Session, error) {
	if cur == nil || cur.RefreshToken == "" {
		return r.Establish(ctx)
	}
	sess, err := r.token(ctx, url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {cur.RefreshToken},
	}, cur)
	if err != nil {
		// A revoked or expired refresh token fails the refresh grant. Fall back to a
		// fresh password grant so the identity recovers instead of failing every
		// cycle until the backoff caps it.
		return r.Establish(ctx)
	}
	return sess, nil
}
