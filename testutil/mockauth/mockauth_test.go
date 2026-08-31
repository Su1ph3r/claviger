package mockauth

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

func TestLoginThenWhoami(t *testing.T) {
	ts := httptest.NewServer(New(time.Minute).Handler())
	defer ts.Close()

	resp, err := http.PostForm(ts.URL+"/login", url.Values{"username": {"alice"}, "password": {"pw"}})
	if err != nil {
		t.Fatal(err)
	}
	if resp.StatusCode != 200 {
		t.Fatalf("login status = %d, want 200", resp.StatusCode)
	}
	var cookie *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "session" {
			cookie = c
		}
	}
	if cookie == nil {
		t.Fatal("no session cookie set")
	}

	req, _ := http.NewRequest("GET", ts.URL+"/api/whoami", nil)
	req.AddCookie(cookie)
	who, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	if who.StatusCode != 200 {
		t.Fatalf("whoami status = %d, want 200", who.StatusCode)
	}
}

func TestWhoamiUnauthenticated(t *testing.T) {
	ts := httptest.NewServer(New(time.Minute).Handler())
	defer ts.Close()

	resp, _ := http.Get(ts.URL + "/api/whoami")
	if resp.StatusCode != 401 {
		t.Fatalf("status = %d, want 401", resp.StatusCode)
	}
	body := make([]byte, 256)
	n, _ := resp.Body.Read(body)
	if !strings.Contains(string(body[:n]), "unauthenticated") {
		t.Fatal("body missing unauthenticated marker")
	}
}
