// internal/gateway/gateway.go
package gateway

import (
	"bytes"
	"context"
	"crypto/subtle"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/textproto"
	"net/url"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/Su1ph3r/claviger/internal/httpx"
	"github.com/Su1ph3r/claviger/internal/recipe"
	"github.com/Su1ph3r/claviger/internal/store"
)

// csrfTTL is how long a fetched anti-CSRF token is reused before the gateway
// re-fetches it. Short enough that a rotating token stays fresh, long enough that
// a burst of state-changing requests does not re-fetch on every call.
const csrfTTL = 30 * time.Second

// CSRFPolicy is a per-identity anti-CSRF token policy the gateway applies: before
// forwarding a state-changing request it fetches FetchURL (with the identity's
// session applied), extracts the token via the compiled pattern's first capture
// group, and sets it on Header. Build one with NewCSRFPolicy.
type CSRFPolicy struct {
	FetchURL string
	Pattern  string
	Header   string
	Methods  map[string]bool
	re       *regexp.Regexp
}

// NewCSRFPolicy compiles pattern and normalizes methods, returning a ready policy.
// A bad pattern is a configuration error surfaced here rather than at request time.
// An empty methods list defaults to the standard state-changing verbs.
func NewCSRFPolicy(fetchURL, pattern, header string, methods []string) (CSRFPolicy, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return CSRFPolicy{}, fmt.Errorf("csrf pattern %q: %w", pattern, err)
	}
	ms := make(map[string]bool, len(methods))
	for _, m := range methods {
		if m = strings.ToUpper(strings.TrimSpace(m)); m != "" {
			ms[m] = true
		}
	}
	if len(ms) == 0 {
		for _, m := range []string{http.MethodPost, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			ms[m] = true
		}
	}
	return CSRFPolicy{FetchURL: fetchURL, Pattern: pattern, Header: header, Methods: ms, re: re}, nil
}

// cachedToken is a fetched anti-CSRF token and the time it was fetched.
type cachedToken struct {
	value string
	at    time.Time
}

// Gateway forwards requests to a single target base URL, injecting a chosen
// identity's session and reauthenticating transparently on expiry.
type Gateway struct {
	store   *store.Store
	recipes map[string]recipe.Recipe
	target  *url.URL
	client  *http.Client
	// Logger receives the gateway's lifecycle events (reauth, csrf, retry failures
	// and successes). Secrets are never logged. Defaults to a text handler on stderr
	// at Info; the daemon overrides the level via WithLogger.
	Logger *slog.Logger
	// audit, when set via WithAudit, receives one structured record per gateway
	// request: identity, method, path (never the query string), and upstream status.
	// It never carries headers, cookies, tokens, or bodies. Default nil (no audit log).
	audit *slog.Logger
	// RequireToken, when non-empty, requires every request to carry a matching
	// X-Claviger-Token header. It fully closes the browser-CSRF vector (a web page
	// cannot set a custom header on a cross-site request) at the cost of the
	// operator configuring their tools to send it. Empty (default) keeps the
	// transparent Host/Origin/Sec-Fetch guard only.
	RequireToken string

	// tlsConfig, when set via WithTLS, is turned into the client's transport in
	// New after all options are applied. Storing it (rather than building the
	// transport in the option) lets New surface any transport-build error.
	tlsConfig *httpx.TLSConfig

	// csrf holds the per-identity anti-CSRF policies set via WithCSRF. csrfCache
	// caches the last-fetched token per identity (guarded by csrfMu) so a burst of
	// state-changing requests re-fetches at most once per csrfTTL.
	csrf      map[string]CSRFPolicy
	csrfMu    sync.Mutex
	csrfCache map[string]cachedToken
}

// Option customizes a Gateway during New.
type Option func(*Gateway)

// WithTLS makes the gateway reach its target through a transport built from cfg
// (custom CA, client cert, or InsecureSkipVerify). The transport is built by New
// so a construction error surfaces from New; the client's no-follow redirect
// policy is preserved.
func WithTLS(cfg httpx.TLSConfig) Option {
	return func(g *Gateway) {
		c := cfg
		g.tlsConfig = &c
	}
}

// WithCSRF makes the gateway apply the given per-identity anti-CSRF policies. For a
// managed identity whose request method is covered by its policy, the gateway
// fetches and injects a fresh token before forwarding. Identities without a policy
// are unaffected.
func WithCSRF(policies map[string]CSRFPolicy) Option {
	return func(g *Gateway) {
		g.csrf = policies
	}
}

// WithLogger sets the gateway's structured logger. A nil logger is ignored so the
// default (text handler on stderr at Info) stands.
func WithLogger(l *slog.Logger) Option {
	return func(g *Gateway) {
		if l != nil {
			g.Logger = l
		}
	}
}

// WithAudit sets the gateway's per-request audit logger. It records only identity,
// method, path, and upstream status per request, never secrets. A nil logger is
// ignored so no audit log is written (the default).
func WithAudit(l *slog.Logger) Option {
	return func(g *Gateway) {
		if l != nil {
			g.audit = l
		}
	}
}

func New(st *store.Store, recipes map[string]recipe.Recipe, targetBase string, opts ...Option) (*Gateway, error) {
	u, err := url.Parse(targetBase)
	if err != nil {
		return nil, fmt.Errorf("bad target base %q: %w", targetBase, err)
	}
	// The gateway follows no redirects itself: a 302 to /login is a logout signal,
	// not something to chase.
	client := &http.Client{
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	g := &Gateway{
		store:     st,
		recipes:   recipes,
		target:    u,
		client:    client,
		Logger:    slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelInfo})),
		csrfCache: map[string]cachedToken{},
	}
	for _, opt := range opts {
		opt(g)
	}
	// Apply a configured TLS transport after options, keeping the client's
	// CheckRedirect policy (only the Transport is replaced).
	if g.tlsConfig != nil {
		tr, err := httpx.Transport(*g.tlsConfig)
		if err != nil {
			return nil, fmt.Errorf("gateway tls transport: %w", err)
		}
		g.client.Transport = tr
	}
	return g, nil
}

func (g *Gateway) Handler(identity string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.serve(w, r, identity)
	})
}

func (g *Gateway) serve(w http.ResponseWriter, r *http.Request, identity string) {
	// Reject requests whose Host is not a loopback literal. The listeners bind
	// 127.0.0.1, so a well-behaved CLI client sends Host: 127.0.0.1:PORT; a browser
	// tricked by DNS rebinding into resolving evil.com to 127.0.0.1 still sends
	// Host: evil.com and is refused before any credential is injected.
	if !isLoopbackHost(r.Host) {
		http.Error(w, "forbidden: unexpected Host header", http.StatusForbidden)
		return
	}

	// Reject cross-origin/cross-site requests. A bearer-token API is normally
	// immune to browser CSRF because the browser never attaches the token; the
	// gateway would re-introduce that exposure by injecting the warm token onto
	// whatever arrives on the loopback port. A browser attaches Origin and
	// Sec-Fetch-Site; a CLI client (curl, scripts) attaches neither, so this
	// blocks a web page the operator visits from driving blind, credentialed
	// state-changing requests, while leaving legitimate tooling untouched.
	if origin := r.Header.Get("Origin"); origin != "" {
		if u, err := url.Parse(origin); err != nil || !isLoopbackHost(u.Host) {
			http.Error(w, "forbidden: cross-origin request", http.StatusForbidden)
			return
		}
	}
	if sf := r.Header.Get("Sec-Fetch-Site"); sf != "" && sf != "same-origin" && sf != "none" {
		http.Error(w, "forbidden: cross-site request", http.StatusForbidden)
		return
	}
	// Optional shared-secret gate. When enabled it closes the residual browser-CSRF
	// path for clients that omit Fetch Metadata (a cross-site request cannot attach
	// a custom header). When disabled (default) it is a no-op.
	if g.RequireToken != "" {
		got := r.Header.Get("X-Claviger-Token")
		if subtle.ConstantTimeCompare([]byte(got), []byte(g.RequireToken)) != 1 {
			http.Error(w, "forbidden: missing or invalid gateway token", http.StatusForbidden)
			return
		}
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		http.Error(w, "read body: "+err.Error(), http.StatusBadGateway)
		return
	}

	rec, hasRecipe := g.recipes[identity]

	// Anti-CSRF injection: for a managed identity whose method the policy covers,
	// fetch a fresh token (cached per csrfTTL) and inject it on the forwarded
	// request. A fetch or extract failure is logged and the request proceeds
	// without the header, so a token problem never blocks the operator.
	var csrfHeader, csrfToken string
	if hasRecipe {
		if pol, ok := g.csrf[identity]; ok && pol.Methods[strings.ToUpper(r.Method)] {
			tok, ferr := g.csrfTokenFor(r.Context(), identity, pol)
			if ferr != nil {
				g.Logger.Warn("csrf token fetch failed", "identity", identity, "error", ferr)
			} else {
				csrfHeader, csrfToken = pol.Header, tok
			}
		}
	}

	resp, respBody, err := g.forward(r, body, identity, hasRecipe, csrfHeader, csrfToken)
	if err != nil {
		http.Error(w, "forward: "+err.Error(), http.StatusBadGateway)
		return
	}

	// Transparent reauth: when we manage this identity and the response looks logged
	// out, renew the session regardless of method so the NEXT request (of any method)
	// uses a live session. Only idempotent methods are additionally auto-replayed; a
	// POST is re-authed but its response is surfaced as-is rather than blindly
	// re-sent, so a POST-heavy run does not stay wedged on a dead token. A reauth or
	// retry failure is logged, not swallowed.
	if hasRecipe && rec.Logout().Matches(resp, respBody) {
		if _, rerr := g.store.Refresh(r.Context(), identity); rerr != nil {
			g.Logger.Warn("reauth failed", "identity", identity, "error", rerr)
		} else {
			g.Logger.Info("reauthenticated", "identity", identity)
			// The old CSRF token was bound to the now-dead session; drop it so the
			// next state-changing request fetches one against the live session
			// instead of replaying a stale token for up to csrfTTL (a burst of 403s).
			g.invalidateCSRF(identity)
			if IsIdempotent(r.Method) {
				// The captured token was bound to the dead session and just
				// invalidated; fetch a fresh one against the live session for a
				// covered method so the retry is not rejected for a stale token.
				retryHeader, retryToken := csrfHeader, csrfToken
				if pol, ok := g.csrf[identity]; ok && pol.Methods[strings.ToUpper(r.Method)] {
					if tok, ferr := g.csrfTokenFor(r.Context(), identity, pol); ferr != nil {
						g.Logger.Warn("csrf token refetch after reauth failed", "identity", identity, "error", ferr)
					} else {
						retryHeader, retryToken = pol.Header, tok
					}
				}
				if resp2, body2, ferr := g.forward(r, body, identity, true, retryHeader, retryToken); ferr != nil {
					g.Logger.Warn("retry after reauth failed", "identity", identity, "error", ferr)
				} else {
					resp, respBody = resp2, body2
				}
			}
		}
	}

	// Per-request audit record for the engagement log. Path only, never the query
	// string (which can carry secrets); no headers, cookies, tokens, or bodies.
	if g.audit != nil {
		g.audit.Info("request",
			"identity", identity,
			"method", r.Method,
			"path", r.URL.Path,
			"status", resp.StatusCode,
		)
	}

	copyHeader(w.Header(), resp.Header)
	w.WriteHeader(resp.StatusCode)
	w.Write(respBody)
}

// forward builds and sends one request to the target with the identity applied.
// When apply is true and csrfHeader is non-empty, the anti-CSRF token is set on the
// outbound request after the session is applied, so a policy token wins over any
// session-level default for the same header.
func (g *Gateway) forward(r *http.Request, body []byte, identity string, apply bool, csrfHeader, csrfToken string) (*http.Response, []byte, error) {
	out := *g.target
	// Preserve the escaped path so percent-encoded reserved characters (e.g. an
	// object id containing %2F) reach the target verbatim. Using only the decoded
	// r.URL.Path would normalize %2F to "/" and silently change the object
	// reference, which breaks faithful replay for authz testing.
	out.Path = strings.TrimRight(g.target.Path, "/") + r.URL.Path
	out.RawPath = strings.TrimRight(g.target.EscapedPath(), "/") + r.URL.EscapedPath()
	out.RawQuery = r.URL.RawQuery

	req, err := http.NewRequestWithContext(r.Context(), r.Method, out.String(), bytes.NewReader(body))
	if err != nil {
		return nil, nil, err
	}
	copyHeader(req.Header, r.Header)
	req.Header.Del("X-Claviger-Identity") // internal routing header, never forwarded
	req.Header.Del("X-Claviger-Token")    // gateway shared secret, never forwarded upstream

	if apply {
		sess, err := g.store.Get(context.WithoutCancel(r.Context()), identity)
		if err != nil {
			return nil, nil, err
		}
		sess.Apply(req)
		if csrfHeader != "" && csrfToken != "" {
			req.Header.Set(csrfHeader, csrfToken)
		}
	}

	resp, err := g.client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()
	rb, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, nil, err
	}
	return resp, rb, nil
}

// csrfTokenFor returns the anti-CSRF token for the identity, serving a cached value
// while it is younger than csrfTTL and otherwise fetching policy.FetchURL with the
// identity's session applied and extracting the first capture group of the compiled
// pattern. The token is not logged. The fetch uses the gateway's own (TLS-configured)
// client so it reaches the target under the same trust as forwarded traffic.
func (g *Gateway) csrfTokenFor(ctx context.Context, identity string, pol CSRFPolicy) (string, error) {
	g.csrfMu.Lock()
	if ct, ok := g.csrfCache[identity]; ok && time.Since(ct.at) < csrfTTL {
		g.csrfMu.Unlock()
		return ct.value, nil
	}
	g.csrfMu.Unlock()

	// Detach from the request cancellation so a fetch begun for one request can
	// still populate the cache even if that request's context is cancelled.
	fctx := context.WithoutCancel(ctx)
	req, err := http.NewRequestWithContext(fctx, http.MethodGet, pol.FetchURL, nil)
	if err != nil {
		return "", err
	}
	sess, err := g.store.Get(fctx, identity)
	if err != nil {
		return "", err
	}
	sess.Apply(req)

	resp, err := g.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", err
	}
	m := pol.re.FindSubmatch(body)
	if len(m) < 2 {
		return "", fmt.Errorf("csrf pattern found no token at %s", pol.FetchURL)
	}
	token := string(m[1])

	g.csrfMu.Lock()
	g.csrfCache[identity] = cachedToken{value: token, at: time.Now()}
	g.csrfMu.Unlock()
	return token, nil
}

// invalidateCSRF drops the cached anti-CSRF token for an identity under the csrf
// mutex. It is called after a successful reauth so a token bound to the dead
// session is not reused; the next state-changing request fetches a fresh one.
func (g *Gateway) invalidateCSRF(identity string) {
	g.csrfMu.Lock()
	delete(g.csrfCache, identity)
	g.csrfMu.Unlock()
}

// isLoopbackHost reports whether a request's Host header names a loopback literal
// (127.0.0.1, localhost, or ::1). An empty or non-loopback Host is rejected.
func isLoopbackHost(host string) bool {
	if host == "" {
		return false
	}
	h, _, err := net.SplitHostPort(host)
	if err != nil {
		h = host // no port present
	}
	// Normalize case and a trailing dot so valid loopback spellings (LOCALHOST,
	// localhost.) are accepted. This only broadens loopback acceptance; no
	// non-loopback name newly passes.
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	switch h {
	case "127.0.0.1", "localhost", "::1":
		return true
	}
	if ip := net.ParseIP(strings.Trim(h, "[]")); ip != nil && ip.IsLoopback() {
		return true
	}
	return false
}

// alwaysHopByHop are the connection-scoped headers a proxy must not forward
// (RFC 7230 6.1), stored canonicalized.
var alwaysHopByHop = map[string]bool{
	"Connection":          true,
	"Keep-Alive":          true,
	"Transfer-Encoding":   true,
	"Te":                  true,
	"Trailer":             true,
	"Upgrade":             true,
	"Proxy-Connection":    true,
	"Proxy-Authenticate":  true,
	"Proxy-Authorization": true,
}

// hopByHop returns the set of headers to drop for one message: the always
// hop-by-hop names plus any token listed in this message's Connection header.
func hopByHop(connectionHeader string) map[string]bool {
	set := make(map[string]bool, len(alwaysHopByHop)+2)
	for k := range alwaysHopByHop {
		set[k] = true
	}
	for _, tok := range strings.Split(connectionHeader, ",") {
		tok = strings.TrimSpace(tok)
		if tok != "" {
			set[textproto.CanonicalMIMEHeaderKey(tok)] = true
		}
	}
	return set
}

func copyHeader(dst, src http.Header) {
	drop := hopByHop(src.Get("Connection"))
	for k, vals := range src {
		if drop[textproto.CanonicalMIMEHeaderKey(k)] {
			continue
		}
		for _, v := range vals {
			dst.Add(k, v)
		}
	}
}
