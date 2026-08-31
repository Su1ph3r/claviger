package recipe

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
)

func TestFormPostUsesInjectedClient(t *testing.T) {
	var hits int64
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		atomic.AddInt64(&hits, 1)
		w.Header().Set("Set-Cookie", "session=x; Path=/")
		w.Write([]byte(`{"access_token":"t"}`))
	}))
	defer ts.Close()

	// A client with a marker transport proves the recipe used the injected client.
	marker := &markerTransport{next: http.DefaultTransport}
	r := &FormPost{ID: "a", LoginURL: ts.URL, Username: "u", Password: "p", Client: &http.Client{Transport: marker}}
	if _, err := r.Establish(context.Background()); err != nil {
		t.Fatal(err)
	}
	if atomic.LoadInt64(&marker.calls) == 0 {
		t.Fatal("recipe did not use the injected client")
	}
	_ = hits
}

type markerTransport struct {
	next  http.RoundTripper
	calls int64
}

func (m *markerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	atomic.AddInt64(&m.calls, 1)
	return m.next.RoundTrip(r)
}
