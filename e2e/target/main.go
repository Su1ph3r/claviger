// Command target is a self-contained HTTPS mock application used by the
// Claviger end-to-end acceptance harness. It serves a small surface of auth
// flows (form, oauth, csrf, sso) that mint short-lived opaque tokens, plus an
// authz surface (correct object-level checks and a deliberately broken IDOR
// route) that the harness drives through the Claviger gateway with real tools.
//
// It generates an in-process self-signed RSA cert for 127.0.0.1/localhost,
// writes the cert PEM to -cert-out so external tools can --cacert it, and binds
// on -addr (default 127.0.0.1:0). After binding it prints exactly two lines the
// harness parses:
//
//	LISTENING https://127.0.0.1:<port>
//	CERT <path>
package main

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"html"
	"log"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"
)

// validUsers are the accounts the mock accepts, all with password "pw".
var validUsers = map[string]string{
	"alice": "pw",
	"bob":   "pw",
}

// session ties an opaque token to a user and an expiry instant.
type session struct {
	user   string
	expiry time.Time
}

// tokenStore is a mutex-guarded map of opaque token -> session, plus the set of
// live csrf tokens issued by GET /csrf-form.
type tokenStore struct {
	ttl  time.Duration
	mu   sync.Mutex
	toks map[string]session
	csrf map[string]struct{}
}

// seededAliceToken is a long-lived token for alice, seeded at startup. The e2e
// corpus carries it as a captured "session=" cookie so the harness can prove HAR
// credential-stripping: if stripping regressed and this cookie reached the target,
// anon would authenticate as alice and get a non-401; correct stripping keeps anon
// unauthenticated (401). A random-string cookie could not test this, since an
// unminted token misses lookup and yields 401 whether or not stripping works.
const seededAliceToken = "e2e-seeded-alice-token"

func newTokenStore(ttl time.Duration) *tokenStore {
	s := &tokenStore{
		ttl:  ttl,
		toks: make(map[string]session),
		csrf: make(map[string]struct{}),
	}
	// Far-future expiry so it survives the whole e2e run regardless of -ttl.
	s.toks[seededAliceToken] = session{user: "alice", expiry: time.Now().Add(100 * 365 * 24 * time.Hour)}
	return s
}

// randToken returns an opaque, URL-safe random token.
func randToken() string {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		// crypto/rand should not fail; fall back to a time-based token.
		return fmt.Sprintf("t%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b)
}

// mint creates and stores a fresh token for user, expiring after the store ttl.
func (s *tokenStore) mint(user string) string {
	t := randToken()
	s.mu.Lock()
	s.toks[t] = session{user: user, expiry: time.Now().Add(s.ttl)}
	s.mu.Unlock()
	return t
}

// lookup returns the user for a token if it exists and has not expired.
func (s *tokenStore) lookup(token string) (string, bool) {
	if token == "" {
		return "", false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.toks[token]
	if !ok {
		return "", false
	}
	if time.Now().After(sess.expiry) {
		delete(s.toks, token)
		return "", false
	}
	return sess.user, true
}

func (s *tokenStore) mintCSRF() string {
	t := randToken()
	s.mu.Lock()
	s.csrf[t] = struct{}{}
	s.mu.Unlock()
	return t
}

func (s *tokenStore) validCSRF(t string) bool {
	if t == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	_, ok := s.csrf[t]
	return ok
}

// identify resolves the caller's user from a bearer header or session cookie.
func (s *tokenStore) identify(r *http.Request) (string, bool) {
	const prefix = "Bearer "
	if h := r.Header.Get("Authorization"); len(h) > len(prefix) && h[:len(prefix)] == prefix {
		if user, ok := s.lookup(h[len(prefix):]); ok {
			return user, true
		}
	}
	if c, err := r.Cookie("session"); err == nil {
		if user, ok := s.lookup(c.Value); ok {
			return user, true
		}
	}
	return "", false
}

// selfSignedCert generates an in-process RSA 2048 self-signed certificate valid
// for the given hosts (DNS names and/or IPs). It returns the tls.Certificate
// ready to serve, plus the cert and key PEM encodings.
func selfSignedCert(hosts []string) (tls.Certificate, []byte, []byte, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("generate key: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("serial: %w", err)
	}

	tmpl := x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: "claviger-e2e-target"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, h)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("create cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustMarshalKey(key)})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, nil, nil, fmt.Errorf("x509 key pair: %w", err)
	}
	return cert, certPEM, keyPEM, nil
}

func mustMarshalKey(key *rsa.PrivateKey) []byte {
	b, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		// PKCS8 marshal of an RSA key does not fail in practice.
		return x509.MarshalPKCS1PrivateKey(key)
	}
	return b
}

// newMux builds the routing table for the mock target with a fresh token store
// using the given token ttl.
func newMux(ttl time.Duration) *http.ServeMux {
	store := newTokenStore(ttl)
	ttlSecs := int(ttl.Seconds())
	if ttlSecs < 1 {
		ttlSecs = 1
	}

	mux := http.NewServeMux()

	writeJSON := func(w http.ResponseWriter, status int, v any) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_ = json.NewEncoder(w).Encode(v)
	}

	setSession := func(w http.ResponseWriter, token string) {
		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    token,
			Path:     "/",
			HttpOnly: true,
		})
	}

	// POST /login (form recipe).
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		user := r.FormValue("username")
		if pw, ok := validUsers[user]; !ok || pw != r.FormValue("password") {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		token := store.mint(user)
		setSession(w, token)
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": token,
			"expires_in":   ttlSecs,
		})
	})

	// POST /oauth/token (oauth recipe).
	mux.HandleFunc("POST /oauth/token", func(w http.ResponseWriter, r *http.Request) {
		if r.FormValue("grant_type") != "password" {
			http.Error(w, "unsupported_grant_type", http.StatusBadRequest)
			return
		}
		user := r.FormValue("username")
		if pw, ok := validUsers[user]; !ok || pw != r.FormValue("password") {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		token := store.mint(user)
		setSession(w, token)
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": token,
			"token_type":   "bearer",
			"expires_in":   ttlSecs,
		})
	})

	// GET /csrf-form + POST /csrf-login (multistep recipe).
	mux.HandleFunc("GET /csrf-form", func(w http.ResponseWriter, r *http.Request) {
		csrf := store.mintCSRF()
		http.SetCookie(w, &http.Cookie{Name: "csrf_cookie", Value: csrf, Path: "/"})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!doctype html><html><body>
<form method="post" action="/csrf-login">
<input type="hidden" name="csrf" value="%s">
<input name="username"><input name="password" type="password">
<button type="submit">Log in</button>
</form></body></html>`, html.EscapeString(csrf))
	})

	mux.HandleFunc("POST /csrf-login", func(w http.ResponseWriter, r *http.Request) {
		field := r.FormValue("csrf")
		cookie, cErr := r.Cookie("csrf_cookie")
		if field == "" || cErr != nil || cookie.Value != field || !store.validCSRF(field) {
			http.Error(w, "csrf validation failed", http.StatusForbidden)
			return
		}
		user := r.FormValue("username")
		if pw, ok := validUsers[user]; !ok || pw != r.FormValue("password") {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		token := store.mint(user)
		setSession(w, token)
		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": token,
			"expires_in":   ttlSecs,
		})
	})

	// GET /sso + POST /sso (browser recipe).
	mux.HandleFunc("GET /sso", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprint(w, `<!doctype html><html><body>
<form id="ssoform" method="post" action="/sso">
<input id="user" name="username">
<input id="pass" name="password" type="password">
<button type="submit">Sign in</button>
</form></body></html>`)
	})

	mux.HandleFunc("POST /sso", func(w http.ResponseWriter, r *http.Request) {
		user := r.FormValue("username")
		if pw, ok := validUsers[user]; !ok || pw != r.FormValue("password") {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		token := store.mint(user)
		setSession(w, token)
		// Redirect to /dashboard so browser recipes matching
		// success_url_contains: /dashboard succeed.
		http.Redirect(w, r, "/dashboard", http.StatusSeeOther)
	})

	// GET /dashboard is the post-SSO success page: sets access_token in
	// localStorage and contains a #dashboard selector plus /dashboard in the URL.
	mux.HandleFunc("GET /dashboard", func(w http.ResponseWriter, r *http.Request) {
		user, ok := store.identify(r)
		token := ""
		if c, err := r.Cookie("session"); err == nil {
			token = c.Value
		}
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!doctype html><html><body>
<div id="dashboard">Welcome %s</div>
<script>localStorage.setItem('access_token', %q)</script>
</body></html>`, html.EscapeString(user), token)
		_ = ok
	})

	// GET /records/{owner}: correct object-level authz.
	mux.HandleFunc("GET /records/{owner}", func(w http.ResponseWriter, r *http.Request) {
		user, ok := store.identify(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		owner := r.PathValue("owner")
		if user != owner {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{
			"owner":  owner,
			"record": fmt.Sprintf("private record for %s", owner),
		})
	})

	// GET /idor/{owner}: DELIBERATELY BROKEN object-level authz. Returns 200 to
	// any authenticated caller regardless of {owner}; anon is still 401.
	mux.HandleFunc("GET /idor/{owner}", func(w http.ResponseWriter, r *http.Request) {
		if _, ok := store.identify(r); !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		owner := r.PathValue("owner")
		writeJSON(w, http.StatusOK, map[string]any{
			"owner":  owner,
			"record": fmt.Sprintf("private record for %s", owner),
		})
	})

	// GET /whoami: caller identity, for keep-alive checks.
	mux.HandleFunc("GET /whoami", func(w http.ResponseWriter, r *http.Request) {
		user, ok := store.identify(r)
		if !ok {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		writeJSON(w, http.StatusOK, map[string]any{"user": user})
	})

	// GET /search?q=: reflect q into HTML (a probe surface for nuclei/sqlmap).
	// This is a pure reflected echo, not a real database.
	mux.HandleFunc("GET /search", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query().Get("q")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		fmt.Fprintf(w, `<!doctype html><html><body>
<p>Results for: %s</p>
</body></html>`, html.EscapeString(q))
	})

	return mux
}

func main() {
	addr := flag.String("addr", "127.0.0.1:0", "listen address")
	certOut := flag.String("cert-out", "", "path to write the server cert PEM (default: a temp file)")
	ttl := flag.Duration("ttl", 3*time.Second, "token time-to-live")
	flag.Parse()

	cert, certPEM, _, err := selfSignedCert([]string{"127.0.0.1", "localhost"})
	if err != nil {
		log.Fatalf("target: cert: %v", err)
	}

	certPath := *certOut
	if certPath == "" {
		f, err := os.CreateTemp("", "claviger-e2e-cert-*.pem")
		if err != nil {
			log.Fatalf("target: temp cert file: %v", err)
		}
		certPath = f.Name()
		f.Close()
	}
	if err := os.WriteFile(certPath, certPEM, 0o600); err != nil {
		log.Fatalf("target: write cert: %v", err)
	}

	// Bind first so :0 resolves to a real port we can print.
	ln, err := net.Listen("tcp", *addr)
	if err != nil {
		log.Fatalf("target: listen: %v", err)
	}

	srv := &http.Server{
		Handler:   newMux(*ttl),
		TLSConfig: &tls.Config{Certificates: []tls.Certificate{cert}},
	}

	// Exactly two lines the harness parses.
	fmt.Printf("LISTENING https://%s\n", ln.Addr().String())
	fmt.Printf("CERT %s\n", certPath)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()

	errc := make(chan error, 1)
	go func() {
		errc <- srv.ServeTLS(ln, "", "")
	}()

	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("target: shutdown: %v", err)
		}
	case err := <-errc:
		if err != nil && err != http.ErrServerClosed {
			log.Fatalf("target: serve: %v", err)
		}
	}
}
