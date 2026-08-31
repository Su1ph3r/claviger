package replay

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/Su1ph3r/claviger/internal/corpus"
	"github.com/Su1ph3r/claviger/internal/recipe"
	"github.com/Su1ph3r/claviger/internal/store"
)

// corpusTarget is a self-contained app: /login sets a session=<username> cookie,
// and the app endpoints authorize off that cookie. /api/records/alice is owned by
// alice (200), forbidden to any other authenticated user (403), and 401 to anon;
// /api/secret is uniformly 403 for everyone.
func corpusTarget() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		user := r.FormValue("username")
		http.SetCookie(w, &http.Cookie{Name: "session", Value: user, Path: "/"})
		w.WriteHeader(200)
	})
	user := func(r *http.Request) string {
		if c, err := r.Cookie("session"); err == nil {
			return c.Value
		}
		return ""
	}
	mux.HandleFunc("/api/records/alice", func(w http.ResponseWriter, r *http.Request) {
		switch user(r) {
		case "":
			w.WriteHeader(401)
		case "alice":
			w.WriteHeader(200)
		default:
			w.WriteHeader(403)
		}
	})
	mux.HandleFunc("/api/secret", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403)
	})
	return mux
}

func statusesDiffer(results []Result) bool {
	first := -1
	for _, r := range results {
		if r.Err != nil {
			continue
		}
		if first == -1 {
			first = r.Status
			continue
		}
		if r.Status != first {
			return true
		}
	}
	return false
}

// TestRunCorpusHARDoesNotLeakCapturedCookie pins Fix 1 behaviorally: a HAR
// exported from the capturing user's browser would carry `Cookie: session=captured`.
// After loadHAR drops identity headers, the corpus request carries no cookie, so
// the anon identity (which skips session injection) must be seen as unauthenticated
// (401), not as the capturing user (200). Before the fix, loadHAR forwarded the
// captured cookie and anon appeared authenticated (200), suppressing the diff.
func TestRunCorpusHARDoesNotLeakCapturedCookie(t *testing.T) {
	// Target returns 200 only when it sees the capturing user's cookie, else 401.
	mux := http.NewServeMux()
	mux.HandleFunc("/api/thing", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("session"); err == nil && c.Value == "captured" {
			w.WriteHeader(200)
			return
		}
		w.WriteHeader(401)
	})
	ts := httptest.NewServer(mux)
	defer ts.Close()

	// Build the HAR a browser would have exported, with the captured cookie, then
	// run it through the real loadHAR path via corpus.Load so the fix is exercised.
	har := `{"log":{"entries":[{"request":{"method":"GET","url":"` + ts.URL +
		`/api/thing","headers":[{"name":"Cookie","value":"session=captured"}]}}]}}`
	p := filepath.Join(t.TempDir(), "cap.har")
	if err := os.WriteFile(p, []byte(har), 0o600); err != nil {
		t.Fatal(err)
	}
	reqs, err := corpus.Load(p, "har")
	if err != nil {
		t.Fatal(err)
	}

	// anon skips Get, so a nil SessionSource is fine here.
	rows, err := RunCorpus(context.Background(), nil, []string{"anon"}, reqs, ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || len(rows[0].Results) != 1 {
		t.Fatalf("got %d rows, want 1 with 1 result", len(rows))
	}
	if got := rows[0].Results[0].Status; got != 401 {
		t.Fatalf("anon status = %d, want 401 (captured cookie must not leak)", got)
	}
}

func TestRunCorpusMatrix(t *testing.T) {
	ts := httptest.NewServer(corpusTarget())
	defer ts.Close()

	st := store.New()
	for _, name := range []string{"alice", "bob"} {
		st.Register(&recipe.FormPost{
			ID: name, LoginURL: ts.URL + "/login",
			Username: name, Password: "pw",
			Signature: recipe.LogoutSignature{StatusCodes: []int{401}},
		})
	}

	reqs := []corpus.Request{
		{Method: "GET", Path: "/api/records/alice"},
		{Method: "GET", Path: "/api/secret"},
	}
	ids := []string{"alice", "bob", "anon"}

	rows, err := RunCorpus(context.Background(), st, ids, reqs, ts.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("got %d rows, want 2", len(rows))
	}
	if rows[0].Request.Path != "/api/records/alice" || rows[1].Request.Path != "/api/secret" {
		t.Fatalf("rows out of order: %q, %q", rows[0].Request.Path, rows[1].Request.Path)
	}

	// row0: alice 200, bob 403, anon 401 -> statuses differ.
	for i, r := range rows[0].Results {
		if r.Err != nil {
			t.Fatalf("row0 %s unexpected error: %v", ids[i], r.Err)
		}
	}
	if rows[0].Results[0].Status != 200 || rows[0].Results[1].Status != 403 || rows[0].Results[2].Status != 401 {
		t.Fatalf("row0 statuses = %d/%d/%d, want 200/403/401",
			rows[0].Results[0].Status, rows[0].Results[1].Status, rows[0].Results[2].Status)
	}
	if !statusesDiffer(rows[0].Results) {
		t.Error("row0 (records/alice) should DIFFER across identities")
	}

	// row1: uniformly 403 -> statuses all equal.
	for i, r := range rows[1].Results {
		if r.Err != nil {
			t.Fatalf("row1 %s unexpected error: %v", ids[i], r.Err)
		}
		if r.Status != 403 {
			t.Errorf("row1 %s status = %d, want 403", ids[i], r.Status)
		}
	}
	if statusesDiffer(rows[1].Results) {
		t.Error("row1 (secret) should NOT differ; all identities are 403")
	}
}
