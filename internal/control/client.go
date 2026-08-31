package control

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"

	"github.com/Su1ph3r/claviger/internal/session"
)

// Wire types shared by the control server and client.

type Cookie struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}

type CredsResponse struct {
	Identity    string      `json:"identity"`
	BearerToken string      `json:"bearer_token"`
	Cookies     []Cookie    `json:"cookies"`
	CSRF        string      `json:"csrf,omitempty"`
	Headers     http.Header `json:"headers,omitempty"`
}

type IdentityStatus struct {
	Name        string `json:"name"`
	Established bool   `json:"established"`
	ExpiresAt   string `json:"expires_at,omitempty"`   // RFC3339, empty = unknown
	LastRefresh string `json:"last_refresh,omitempty"` // RFC3339, empty = never
	LastError   string `json:"last_error,omitempty"`
}

type StatusResponse struct {
	Identities []IdentityStatus `json:"identities"`
}

// SocketExists reports whether a control socket is live at the path (a Unix socket
// file that exists), so a CLI command can decide whether to attach to a running
// daemon or fall back to logging in standalone.
func SocketExists(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode()&os.ModeSocket != 0
}

// Client talks to a running daemon's control server over its Unix socket.
type Client struct {
	http *http.Client
}

func NewClient(socket string) *Client {
	return &Client{http: &http.Client{
		Transport: &http.Transport{
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				return (&net.Dialer{}).DialContext(ctx, "unix", socket)
			},
		},
	}}
}

func (c *Client) get(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", "http://claviger"+path, nil)
	if err != nil {
		return nil, err
	}
	return c.http.Do(req)
}

// Creds fetches the daemon's live session for an identity and reconstructs it as a
// session.Session (bearer token, cookies, captured CSRF, and any extra headers), so
// a caller applies the warm, single-flighted session exactly as a standalone login
// would, instead of logging in again.
func (c *Client) Creds(ctx context.Context, id string) (*session.Session, error) {
	resp, err := c.get(ctx, "/creds/"+url.PathEscape(id))
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("daemon /creds/%s returned %d", id, resp.StatusCode)
	}
	var cr CredsResponse
	if err := json.NewDecoder(resp.Body).Decode(&cr); err != nil {
		return nil, err
	}
	sess := &session.Session{
		Identity:    cr.Identity,
		BearerToken: cr.BearerToken,
		CSRF:        cr.CSRF,
		Headers:     cr.Headers,
	}
	for _, ck := range cr.Cookies {
		sess.Cookies = append(sess.Cookies, &http.Cookie{Name: ck.Name, Value: ck.Value})
	}
	return sess, nil
}

// Get satisfies the session source used by replay, delegating to Creds.
func (c *Client) Get(ctx context.Context, id string) (*session.Session, error) {
	return c.Creds(ctx, id)
}

// Status fetches the daemon's per-identity health.
func (c *Client) Status(ctx context.Context) (StatusResponse, error) {
	var out StatusResponse
	resp, err := c.get(ctx, "/status")
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return out, fmt.Errorf("daemon /status returned %d", resp.StatusCode)
	}
	err = json.NewDecoder(resp.Body).Decode(&out)
	return out, err
}
