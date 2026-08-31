package cmd

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// corpusTestTarget is a self-contained app: /login sets a session=<username>
// cookie; /api/records/alice answers 200 to alice, 403 to any other
// authenticated user, 401 to anon; /api/secret is uniformly 403.
func corpusTestTarget() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		http.SetCookie(w, &http.Cookie{Name: "session", Value: r.FormValue("username"), Path: "/"})
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

func writeCorpusConfig(t *testing.T, url string) string {
	t.Helper()
	cfg := "target: " + url + "\n" +
		"identities:\n" +
		"  - name: alice\n" +
		"    type: form\n" +
		"    login_url: " + url + "/login\n" +
		"    username: alice\n" +
		"    password: pw\n" +
		"    logout:\n" +
		"      status_codes: [401]\n" +
		"  - name: bob\n" +
		"    type: form\n" +
		"    login_url: " + url + "/login\n" +
		"    username: bob\n" +
		"    password: pw\n" +
		"    logout:\n" +
		"      status_codes: [401]\n"
	p := filepath.Join(t.TempDir(), "claviger.yaml")
	if err := os.WriteFile(p, []byte(cfg), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func writeCorpusFile(t *testing.T) string {
	t.Helper()
	body := "# two endpoints\nGET /api/records/alice\nGET /api/secret\n"
	p := filepath.Join(t.TempDir(), "corpus.txt")
	if err := os.WriteFile(p, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestReplayCorpusAndPathMutuallyExclusive(t *testing.T) {
	ts := httptest.NewServer(corpusTestTarget())
	defer ts.Close()
	cfg := writeCorpusConfig(t, ts.URL)
	corpusFile := writeCorpusFile(t)

	root := NewRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"replay", "--config", cfg, "--as", "alice", "--as", "bob",
		"--corpus", corpusFile, "--path", "/"})
	err := root.ExecuteContext(context.Background())
	if err == nil {
		t.Fatal("expected an error when both --corpus and --path are set")
	}
	if !strings.Contains(err.Error(), "mutually exclusive") {
		t.Fatalf("error = %v, want mutual-exclusion message", err)
	}
}

// TestReplayCorpusAndMethodMutuallyExclusive pins Fix 3: in corpus mode methods
// come from the corpus, so a changed --method is a contradiction rather than a
// silently ignored flag.
func TestReplayCorpusAndMethodMutuallyExclusive(t *testing.T) {
	ts := httptest.NewServer(corpusTestTarget())
	defer ts.Close()
	cfg := writeCorpusConfig(t, ts.URL)
	corpusFile := writeCorpusFile(t)

	root := NewRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"replay", "--config", cfg, "--as", "alice", "--as", "bob",
		"--corpus", corpusFile, "--method", "POST"})
	err := root.ExecuteContext(context.Background())
	if err == nil {
		t.Fatal("expected an error when both --corpus and --method are set")
	}
	if !strings.Contains(err.Error(), "--method cannot be combined with --corpus") {
		t.Fatalf("error = %v, want --method/--corpus mutual-exclusion message", err)
	}
}

func TestReplayCorpusRendersMatrix(t *testing.T) {
	ts := httptest.NewServer(corpusTestTarget())
	defer ts.Close()
	cfg := writeCorpusConfig(t, ts.URL)
	corpusFile := writeCorpusFile(t)

	root := NewRootCmd()
	var out bytes.Buffer
	root.SetOut(&out)
	root.SetErr(&out)
	root.SetArgs([]string{"replay", "--config", cfg, "--as", "alice", "--as", "bob",
		"--corpus", corpusFile})
	if err := root.ExecuteContext(context.Background()); err != nil {
		t.Fatalf("replay --corpus failed: %v", err)
	}

	s := out.String()
	if !strings.Contains(s, "GET /api/records/alice") {
		t.Errorf("output missing records request line:\n%s", s)
	}
	if !strings.Contains(s, "GET /api/secret") {
		t.Errorf("output missing secret request line:\n%s", s)
	}
	// alice 200, bob 403 on the records endpoint -> DIFFERS; /api/secret is
	// uniformly 403, so DIFFERS must appear exactly once (on the records line).
	if !strings.Contains(s, "DIFFERS") {
		t.Errorf("output missing DIFFERS marker:\n%s", s)
	}
	if n := strings.Count(s, "DIFFERS"); n != 1 {
		t.Errorf("DIFFERS appears %d times, want 1:\n%s", n, s)
	}
}
