// internal/gateway/csrf_test.go
package gateway

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"testing"

	"github.com/Su1ph3r/claviger/internal/recipe"
	"github.com/Su1ph3r/claviger/internal/store"
)

// csrfTarget is a mock upstream that issues a rotating anti-CSRF token from GET
// /form (incrementing on every fetch so caching is observable via formHits) and
// requires the most recent token on POST /do.
type csrfTarget struct {
	mu         sync.Mutex
	formHits   int
	seq        int
	lastToken  string
	logoutOnDo bool // when set, POST /do answers with the logout signature to force a reauth
}

func (tg *csrfTarget) handler() http.Handler {
	mux := http.NewServeMux()
	// Minimal login so the FormPost recipe can establish a session (cookie + token).
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session=abc; Path=/")
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token":"tok","expires_in":60}`)
	})
	mux.HandleFunc("/form", func(w http.ResponseWriter, r *http.Request) {
		tg.mu.Lock()
		tg.formHits++
		tg.seq++
		tg.lastToken = "CT-" + strconv.Itoa(tg.seq)
		tok := tg.lastToken
		tg.mu.Unlock()
		io.WriteString(w, `<input name="csrf" value="`+tok+`">`)
	})
	mux.HandleFunc("/do", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			tg.mu.Lock()
			want := tg.lastToken
			forceLogout := tg.logoutOnDo
			tg.mu.Unlock()
			if forceLogout {
				w.WriteHeader(401)
				io.WriteString(w, "unauthenticated")
				return
			}
			if got := r.Header.Get("X-CSRF-Token"); got != "" && got == want {
				w.WriteHeader(200)
				io.WriteString(w, "ok")
				return
			}
			w.WriteHeader(403)
			io.WriteString(w, "bad csrf")
			return
		}
		w.WriteHeader(200)
		io.WriteString(w, "get-ok")
	})
	return mux
}

func (tg *csrfTarget) hits() int {
	tg.mu.Lock()
	defer tg.mu.Unlock()
	return tg.formHits
}

func newCSRFGateway(t *testing.T, targetURL, fetchURL string) *Gateway {
	t.Helper()
	r := &recipe.FormPost{
		ID:        "alice",
		LoginURL:  targetURL + "/login",
		Username:  "alice",
		Password:  "pw",
		Signature: recipe.LogoutSignature{StatusCodes: []int{401}, BodyContains: "unauthenticated"},
	}
	st := store.New()
	st.Register(r)
	pol, err := NewCSRFPolicy(fetchURL, `name="csrf" value="([^"]+)"`, "X-CSRF-Token", []string{"POST"})
	if err != nil {
		t.Fatal(err)
	}
	g, err := New(st, map[string]recipe.Recipe{"alice": r}, targetURL,
		WithCSRF(map[string]CSRFPolicy{"alice": pol}))
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func TestCSRFTokenInjectedOnPost(t *testing.T) {
	tg := &csrfTarget{}
	ts := httptest.NewServer(tg.handler())
	defer ts.Close()

	g := newCSRFGateway(t, ts.URL, ts.URL+"/form")
	front := httptest.NewServer(g.Handler("alice"))
	defer front.Close()

	resp, err := http.Post(front.URL+"/do", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("POST status = %d, want 200 (token should be fetched and injected)", resp.StatusCode)
	}
	if h := tg.hits(); h != 1 {
		t.Fatalf("/form hits = %d, want 1", h)
	}
}

func TestCSRFNotFetchedForGet(t *testing.T) {
	tg := &csrfTarget{}
	ts := httptest.NewServer(tg.handler())
	defer ts.Close()

	g := newCSRFGateway(t, ts.URL, ts.URL+"/form")
	front := httptest.NewServer(g.Handler("alice"))
	defer front.Close()

	resp, err := http.Get(front.URL + "/do")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// A GET is not in the policy methods, so the gateway must not fetch /form.
	if h := tg.hits(); h != 0 {
		t.Fatalf("/form hits = %d after a GET, want 0 (GET must not trigger a token fetch)", h)
	}
}

func TestCSRFTokenCachedAcrossRapidPosts(t *testing.T) {
	tg := &csrfTarget{}
	ts := httptest.NewServer(tg.handler())
	defer ts.Close()

	g := newCSRFGateway(t, ts.URL, ts.URL+"/form")
	front := httptest.NewServer(g.Handler("alice"))
	defer front.Close()

	for i := 0; i < 2; i++ {
		resp, err := http.Post(front.URL+"/do", "text/plain", nil)
		if err != nil {
			t.Fatal(err)
		}
		if resp.StatusCode != 200 {
			t.Fatalf("POST %d status = %d, want 200", i, resp.StatusCode)
		}
		resp.Body.Close()
	}
	if h := tg.hits(); h != 1 {
		t.Fatalf("/form hits = %d after two POSTs, want 1 (token should be cached)", h)
	}
}

// TestCSRFCacheInvalidatedOnReauth proves that a reauth drops the cached CSRF
// token so it is not replayed against the fresh session. Each POST /do answers
// with a logout signal, so the gateway reauths and must invalidate the token; the
// following POST then re-fetches /form instead of serving the stale cached token.
// Without the invalidation the second POST would reuse the cached token and /form
// hits would stay at 1.
func TestCSRFCacheInvalidatedOnReauth(t *testing.T) {
	tg := &csrfTarget{logoutOnDo: true}
	ts := httptest.NewServer(tg.handler())
	defer ts.Close()

	g := newCSRFGateway(t, ts.URL, ts.URL+"/form")
	front := httptest.NewServer(g.Handler("alice"))
	defer front.Close()

	// First POST: gateway fetches /form (hit 1), forwards, gets a logout signal and
	// reauths successfully, which invalidates the cached token.
	resp, err := http.Post(front.URL+"/do", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if h := tg.hits(); h != 1 {
		t.Fatalf("/form hits after first POST = %d, want 1", h)
	}

	// Second POST: because the reauth invalidated the cache, the gateway must
	// re-fetch /form for a token bound to the live session rather than replay the
	// stale one.
	resp2, err := http.Post(front.URL+"/do", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp2.Body.Close()
	if h := tg.hits(); h != 2 {
		t.Fatalf("/form hits after reauth = %d, want 2 (cache must be invalidated on reauth)", h)
	}
}

func TestCSRFFetchFailureDoesNotError(t *testing.T) {
	tg := &csrfTarget{}
	ts := httptest.NewServer(tg.handler())
	defer ts.Close()

	// Point the fetch at an unreachable address so token retrieval fails.
	g := newCSRFGateway(t, ts.URL, "http://127.0.0.1:1/form")
	front := httptest.NewServer(g.Handler("alice"))
	defer front.Close()

	resp, err := http.Post(front.URL+"/do", "text/plain", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	// The fetch failure is logged and the request proceeds WITHOUT the header, so
	// the target rejects it with 403. It must never surface as a 5xx.
	if resp.StatusCode >= 500 {
		t.Fatalf("POST status = %d, want a non-5xx (fetch failure must not error the request)", resp.StatusCode)
	}
	if resp.StatusCode != 403 {
		t.Fatalf("POST status = %d, want 403 (request should proceed without the CSRF header)", resp.StatusCode)
	}
}

// TestReauthRetryRefetchesCSRF pins that after a transparent reauth on an
// idempotent, CSRF-covered method (PUT), the auto-retry fetches a FRESH token
// against the live session rather than replaying the token bound to the dead
// session. The discriminator is the /form fetch count: the fix re-fetches (2),
// the bug reuses the stale token without re-fetching (1).
func TestReauthRetryRefetchesCSRF(t *testing.T) {
	var mu sync.Mutex
	formHits, seq, doHits := 0, 0, 0
	lastTok := ""

	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session=abc; Path=/")
		w.Header().Set("Content-Type", "application/json")
		io.WriteString(w, `{"access_token":"tok","expires_in":60}`)
	})
	mux.HandleFunc("/form", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		formHits++
		seq++
		lastTok = "CT-" + strconv.Itoa(seq)
		tok := lastTok
		mu.Unlock()
		io.WriteString(w, `<input name="csrf" value="`+tok+`">`)
	})
	mux.HandleFunc("/do", func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		doHits++
		firstCall := doHits == 1
		want := lastTok
		mu.Unlock()
		if firstCall {
			// Logout signature on the first PUT forces a transparent reauth.
			w.WriteHeader(401)
			io.WriteString(w, "unauthenticated")
			return
		}
		if got := r.Header.Get("X-CSRF-Token"); got != "" && got == want {
			w.WriteHeader(200)
			io.WriteString(w, "ok")
			return
		}
		w.WriteHeader(403)
		io.WriteString(w, "stale csrf")
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	r := &recipe.FormPost{
		ID: "alice", LoginURL: ts.URL + "/login", Username: "alice", Password: "pw",
		Signature: recipe.LogoutSignature{StatusCodes: []int{401}, BodyContains: "unauthenticated"},
	}
	st := store.New()
	st.Register(r)
	pol, err := NewCSRFPolicy(ts.URL+"/form", `name="csrf" value="([^"]+)"`, "X-CSRF-Token", []string{"PUT"})
	if err != nil {
		t.Fatal(err)
	}
	g, err := New(st, map[string]recipe.Recipe{"alice": r}, ts.URL, WithCSRF(map[string]CSRFPolicy{"alice": pol}))
	if err != nil {
		t.Fatal(err)
	}
	front := httptest.NewServer(g.Handler("alice"))
	defer front.Close()

	req, _ := http.NewRequest(http.MethodPut, front.URL+"/do", nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	mu.Lock()
	fh := formHits
	mu.Unlock()
	if fh != 2 {
		t.Errorf("/form hits = %d, want 2 (the reauth retry must re-fetch a fresh CSRF token against the live session)", fh)
	}
}
