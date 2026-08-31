package corpus

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

func writeTemp(t *testing.T, name, content string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestLoadRequests(t *testing.T) {
	p := writeTemp(t, "corpus.txt", "GET /a\n# comment\n\nPOST /b\n")
	reqs, err := Load(p, "requests")
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 2 {
		t.Fatalf("got %d requests, want 2", len(reqs))
	}
	if reqs[0].Method != "GET" || reqs[0].Path != "/a" {
		t.Fatalf("req0 = %+v, want {GET /a}", reqs[0])
	}
	if reqs[1].Method != "POST" || reqs[1].Path != "/b" {
		t.Fatalf("req1 = %+v, want {POST /b}", reqs[1])
	}
}

func TestLoadRequestsBadLineErrors(t *testing.T) {
	p := writeTemp(t, "corpus.txt", "GET\n")
	if _, err := Load(p, "requests"); err == nil {
		t.Fatal("expected error on malformed line, got nil")
	}
}

func TestLoadRequestsLowercaseMethodUppercased(t *testing.T) {
	p := writeTemp(t, "corpus.txt", "get /a\n")
	reqs, err := Load(p, "requests")
	if err != nil {
		t.Fatal(err)
	}
	if reqs[0].Method != "GET" {
		t.Fatalf("method = %q, want GET", reqs[0].Method)
	}
}

// TestLoadRequestsRejectsRelativePath pins Fix 2: a requests-file path without a
// leading slash yields a malformed target URL, so loadRequests must reject it and
// name the offending line. A valid slashed path still loads.
func TestLoadRequestsRejectsRelativePath(t *testing.T) {
	p := writeTemp(t, "corpus.txt", "GET /ok\nPOST /fine\nGET api/thing\n")
	_, err := Load(p, "requests")
	if err == nil {
		t.Fatal("expected error on path without leading slash, got nil")
	}
	if !strings.Contains(err.Error(), `must start with "/"`) {
		t.Fatalf("error = %v, want message containing `must start with \"/\"`", err)
	}
}

func TestLoadRequestsValidSlashedPathLoads(t *testing.T) {
	p := writeTemp(t, "corpus.txt", "GET /a\n")
	reqs, err := Load(p, "requests")
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 1 || reqs[0].Path != "/a" {
		t.Fatalf("reqs = %+v, want one {GET /a}", reqs)
	}
}

const harFixture = `{
  "log": {
    "entries": [
      {
        "request": {
          "method": "post",
          "url": "http://x/api/do?y=1",
          "headers": [
            {"name": ":authority", "value": "x"},
            {"name": "X-Test", "value": "1"}
          ],
          "postData": {"text": "k=v"}
        }
      }
    ]
  }
}`

func TestLoadHAR(t *testing.T) {
	p := writeTemp(t, "cap.har", harFixture)
	reqs, err := Load(p, "har")
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 1 {
		t.Fatalf("got %d requests, want 1", len(reqs))
	}
	r := reqs[0]
	if r.Method != "POST" {
		t.Fatalf("method = %q, want POST", r.Method)
	}
	if r.Path != "/api/do?y=1" {
		t.Fatalf("path = %q, want /api/do?y=1", r.Path)
	}
	if got := r.Header.Get("X-Test"); got != "1" {
		t.Fatalf("X-Test header = %q, want 1", got)
	}
	if _, ok := r.Header[":authority"]; ok {
		t.Fatal("pseudo-header :authority should be skipped")
	}
	if string(r.Body) != "k=v" {
		t.Fatalf("body = %q, want k=v", string(r.Body))
	}
}

// TestLoadHARDropsIdentityHeaders pins Fix 1: a HAR exported from a browser
// carries the capturing user's Cookie/Authorization/X-CSRF-Token, and forwarding
// those verbatim defeats the per-identity authz diff. loadHAR must drop them and
// keep only the request shape (method, path, body, content-type, custom headers).
func TestLoadHARDropsIdentityHeaders(t *testing.T) {
	const fixture = `{
	  "log": {
	    "entries": [
	      {
	        "request": {
	          "method": "GET",
	          "url": "http://x/api/thing",
	          "headers": [
	            {"name": "Cookie", "value": "session=captured"},
	            {"name": "Authorization", "value": "Bearer captured"},
	            {"name": "Proxy-Authorization", "value": "Basic captured"},
	            {"name": "X-CSRF-Token", "value": "captured"},
	            {"name": "Content-Type", "value": "application/json"},
	            {"name": "X-App-Trace", "value": "keep"}
	          ]
	        }
	      }
	    ]
	  }
	}`
	p := writeTemp(t, "cap.har", fixture)
	reqs, err := Load(p, "har")
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 1 {
		t.Fatalf("got %d requests, want 1", len(reqs))
	}
	h := reqs[0].Header
	for _, drop := range []string{"Cookie", "Authorization", "Proxy-Authorization", "X-CSRF-Token"} {
		if got := h.Get(drop); got != "" {
			t.Errorf("header %q = %q, want dropped (empty)", drop, got)
		}
	}
	if got := h.Get("Content-Type"); got != "application/json" {
		t.Errorf("Content-Type = %q, want application/json (kept)", got)
	}
	if got := h.Get("X-App-Trace"); got != "keep" {
		t.Errorf("X-App-Trace = %q, want keep (kept)", got)
	}
}

func TestLoadHARMalformedErrors(t *testing.T) {
	p := writeTemp(t, "cap.har", "{not json")
	if _, err := Load(p, "har"); err == nil {
		t.Fatal("expected error on malformed HAR JSON, got nil")
	}
}

const openapiFixture = `openapi: 3.0.0
paths:
  /a:
    get: {}
    post: {}
  /b:
    get: {}
`

func sortedPairs(reqs []Request) []string {
	out := make([]string, 0, len(reqs))
	for _, r := range reqs {
		out = append(out, r.Method+" "+r.Path)
	}
	sort.Strings(out)
	return out
}

func TestLoadOpenAPISafeOnly(t *testing.T) {
	p := writeTemp(t, "spec.yaml", openapiFixture)
	reqs, err := LoadOptions(p, "openapi", false)
	if err != nil {
		t.Fatal(err)
	}
	got := sortedPairs(reqs)
	want := []string{"GET /a", "GET /b"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestLoadOpenAPIIncludeUnsafe(t *testing.T) {
	p := writeTemp(t, "spec.yaml", openapiFixture)
	reqs, err := LoadOptions(p, "openapi", true)
	if err != nil {
		t.Fatal(err)
	}
	got := sortedPairs(reqs)
	want := []string{"GET /a", "GET /b", "POST /a"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("got %v, want %v", got, want)
		}
	}
}

func TestLoadDefaultsToSafeOnly(t *testing.T) {
	p := writeTemp(t, "spec.yaml", openapiFixture)
	reqs, err := Load(p, "openapi")
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 2 {
		t.Fatalf("Load default = %d requests, want 2 (safe only)", len(reqs))
	}
}

func TestAutoDetectHAR(t *testing.T) {
	p := writeTemp(t, "cap.har", harFixture)
	reqs, err := Load(p, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 1 || reqs[0].Method != "POST" {
		t.Fatalf("auto-detect .har failed: %+v", reqs)
	}
}

func TestAutoDetectOpenAPI(t *testing.T) {
	p := writeTemp(t, "spec.yaml", openapiFixture)
	reqs, err := Load(p, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 2 {
		t.Fatalf("auto-detect openapi yaml = %d, want 2", len(reqs))
	}
}

func TestAutoDetectRequests(t *testing.T) {
	p := writeTemp(t, "corpus.txt", "GET /a\nPOST /b\n")
	reqs, err := Load(p, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 2 {
		t.Fatalf("auto-detect requests .txt = %d, want 2", len(reqs))
	}
}

func TestAutoDetectJSONOpenAPI(t *testing.T) {
	p := writeTemp(t, "spec.json", `{"openapi":"3.0.0","paths":{"/a":{"get":{}}}}`)
	reqs, err := Load(p, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(reqs) != 1 || reqs[0].Method != "GET" || reqs[0].Path != "/a" {
		t.Fatalf("auto-detect json openapi failed: %+v", reqs)
	}
}

// TestLoadOpenAPIDeterministicOrder guards the review follow-up: the loader sorts
// by path then method, so map-iteration randomization cannot reorder the corpus
// run-to-run. The fixture has multiple paths and methods to exercise both keys.
func TestLoadOpenAPIDeterministicOrder(t *testing.T) {
	p := writeTemp(t, "spec.yaml", openapiFixture)
	want := []string{"GET /a", "POST /a", "GET /b"}
	for i := 0; i < 20; i++ {
		reqs, err := LoadOptions(p, "openapi", true)
		if err != nil {
			t.Fatal(err)
		}
		got := make([]string, 0, len(reqs))
		for _, r := range reqs {
			got = append(got, r.Method+" "+r.Path)
		}
		if len(got) != len(want) {
			t.Fatalf("iteration %d: got %v, want %v", i, got, want)
		}
		for j := range want {
			if got[j] != want[j] {
				t.Fatalf("iteration %d: order = %v, want %v", i, got, want)
			}
		}
	}
}
