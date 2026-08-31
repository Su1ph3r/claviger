package mockauth

import (
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type tokenInfo struct {
	user    string
	expires time.Time // zero means no self-expiry
}

// Server is an in-memory auth server for tests.
type Server struct {
	ttl    time.Duration
	mu     sync.Mutex
	tokens map[string]tokenInfo
	seq    int
}

func New(ttl time.Duration) *Server {
	return &Server{ttl: ttl, tokens: map[string]tokenInfo{}}
}

func (s *Server) issue(user string) (access, refresh string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seq++
	access = fmt.Sprintf("acc-%s-%d", user, s.seq)
	refresh = fmt.Sprintf("ref-%s-%d", user, s.seq)
	var exp time.Time
	if s.ttl > 0 {
		exp = time.Now().Add(s.ttl)
	}
	s.tokens[access] = tokenInfo{user: user, expires: exp}
	return access, refresh
}

func (s *Server) valid(tok string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	info, ok := s.tokens[tok]
	if !ok {
		return "", false
	}
	if !info.expires.IsZero() && time.Now().After(info.expires) {
		delete(s.tokens, tok)
		return "", false
	}
	return info.user, true
}

func writeTokens(w http.ResponseWriter, access, refresh string) {
	w.Header().Set("Set-Cookie", "session="+access+"; Path=/")
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"access_token":  access,
		"refresh_token": refresh,
		"expires_in":    60,
	})
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		user := r.FormValue("username")
		if user == "" {
			http.Error(w, "missing username", 400)
			return
		}
		access, refresh := s.issue(user)
		writeTokens(w, access, refresh)
	})

	mux.HandleFunc("/oauth/token", func(w http.ResponseWriter, r *http.Request) {
		r.ParseForm()
		switch r.FormValue("grant_type") {
		case "password":
			access, refresh := s.issue(r.FormValue("username"))
			writeTokens(w, access, refresh)
		case "refresh_token":
			// A refresh always issues a new access token for a generic user.
			access, refresh := s.issue("refreshed")
			writeTokens(w, access, refresh)
		default:
			http.Error(w, "unsupported_grant_type", 400)
		}
	})

	mux.HandleFunc("/api/whoami", func(w http.ResponseWriter, r *http.Request) {
		tok := ""
		if h := r.Header.Get("Authorization"); len(h) > 7 && h[:7] == "Bearer " {
			tok = h[7:]
		} else if c, err := r.Cookie("session"); err == nil {
			tok = c.Value
		}
		user, ok := s.valid(tok)
		if !ok {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(401)
			w.Write([]byte(`{"error":"unauthenticated"}`))
			return
		}
		w.Header().Set("Content-Type", "application/json")
		json.NewEncoder(w).Encode(map[string]string{"user": user})
	})

	return mux
}
