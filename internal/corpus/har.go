package corpus

import (
	"encoding/json"
	"net/http"
	"net/textproto"
	"net/url"
	"strings"
)

// harDropHeaders are the captured request headers loadHAR must NOT forward.
// A HAR exported from a browser carries the capturing user's session; forwarding
// it means every identity replays with those credentials (authed identities send
// both captured and injected, anon sends the captured ones alone and looks
// authenticated), which defeats the per-identity authz diff. Identity is injected
// per-identity by session.Apply, so the corpus must carry only the request shape.
// Proxy-Authorization is included because a HAR captured through an intercepting
// proxy (Burp, mitmproxy) carries it. App-specific bearer headers (X-Api-Key and
// the like) are unbounded and out of scope. Keys are in canonical MIME form for a
// direct map lookup.
var harDropHeaders = map[string]bool{
	textproto.CanonicalMIMEHeaderKey("Cookie"):              true,
	textproto.CanonicalMIMEHeaderKey("Authorization"):       true,
	textproto.CanonicalMIMEHeaderKey("Proxy-Authorization"): true,
	textproto.CanonicalMIMEHeaderKey("X-CSRF-Token"):        true,
}

type harFile struct {
	Log struct {
		Entries []struct {
			Request struct {
				Method  string `json:"method"`
				URL     string `json:"url"`
				Headers []struct {
					Name  string `json:"name"`
					Value string `json:"value"`
				} `json:"headers"`
				PostData *struct {
					Text string `json:"text"`
				} `json:"postData"`
			} `json:"request"`
		} `json:"entries"`
	} `json:"log"`
}

func loadHAR(data []byte) ([]Request, error) {
	var h harFile
	if err := json.Unmarshal(data, &h); err != nil {
		return nil, err
	}
	var reqs []Request
	for _, e := range h.Log.Entries {
		r := e.Request
		if r.Method == "" || r.URL == "" {
			continue
		}
		u, err := url.Parse(r.URL)
		if err != nil {
			return nil, err
		}
		req := Request{
			Method: strings.ToUpper(r.Method),
			Path:   u.RequestURI(),
		}
		for _, hd := range r.Headers {
			if strings.HasPrefix(hd.Name, ":") {
				continue // HTTP/2 pseudo-header
			}
			if harDropHeaders[textproto.CanonicalMIMEHeaderKey(hd.Name)] {
				continue // identity is injected per-identity by session.Apply
			}
			if req.Header == nil {
				req.Header = http.Header{}
			}
			req.Header.Add(hd.Name, hd.Value)
		}
		if r.PostData != nil && r.PostData.Text != "" {
			req.Body = []byte(r.PostData.Text)
		}
		reqs = append(reqs, req)
	}
	return reqs, nil
}
