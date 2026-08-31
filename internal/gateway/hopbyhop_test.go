// internal/gateway/hopbyhop_test.go
package gateway

import (
	"net/http"
	"testing"
)

func TestCopyHeaderStripsHopByHop(t *testing.T) {
	src := http.Header{}
	src.Set("Content-Type", "application/json")
	src.Set("X-App-Data", "keep-me")
	src.Set("Connection", "keep-alive, X-Custom-Hop")
	src.Set("Keep-Alive", "timeout=5")
	src.Set("Transfer-Encoding", "chunked")
	src.Set("Upgrade", "websocket")
	src.Set("Proxy-Connection", "keep-alive")
	src.Set("Proxy-Authorization", "Basic abc")
	src.Set("Te", "trailers")
	src.Set("Trailer", "Expires")
	src.Set("X-Custom-Hop", "drop-me") // named in Connection

	dst := http.Header{}
	copyHeader(dst, src)

	for _, keep := range []string{"Content-Type", "X-App-Data"} {
		if dst.Get(keep) == "" {
			t.Errorf("end-to-end header %q was dropped", keep)
		}
	}
	for _, drop := range []string{
		"Connection", "Keep-Alive", "Transfer-Encoding", "Upgrade",
		"Proxy-Connection", "Proxy-Authorization", "Te", "Trailer", "X-Custom-Hop",
	} {
		if dst.Get(drop) != "" {
			t.Errorf("hop-by-hop header %q reached the destination", drop)
		}
	}
}

func TestHopByHopEmptyConnection(t *testing.T) {
	set := hopByHop("")
	if !set["Connection"] || !set["Keep-Alive"] {
		t.Fatal("always-hop-by-hop names missing from the set")
	}
	if set["Content-Type"] {
		t.Fatal("an end-to-end header was marked hop-by-hop")
	}
}
