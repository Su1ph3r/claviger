package control

import (
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/Su1ph3r/claviger/internal/store"
)

// NewServer builds the local control-plane handler. It is intended to be served
// over a Unix socket, so it performs no auth of its own; filesystem permissions on
// the socket are the boundary.
func NewServer(st *store.Store) http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("/creds/", func(w http.ResponseWriter, r *http.Request) {
		id := strings.TrimPrefix(r.URL.Path, "/creds/")
		if id == "" {
			http.Error(w, "identity required", 400)
			return
		}
		sess, err := st.Get(r.Context(), id)
		if err != nil {
			// Distinguish "not managed" from "managed but authentication failed" so a
			// transient auth-backend outage does not read as a nonexistent identity.
			if errors.Is(err, store.ErrUnknownIdentity) {
				http.Error(w, err.Error(), http.StatusNotFound)
			} else {
				http.Error(w, err.Error(), http.StatusBadGateway)
			}
			return
		}
		cookies := make([]Cookie, 0, len(sess.Cookies))
		for _, c := range sess.Cookies {
			cookies = append(cookies, Cookie{Name: c.Name, Value: c.Value})
		}
		writeJSON(w, CredsResponse{
			Identity:    sess.Identity,
			BearerToken: sess.BearerToken,
			Cookies:     cookies,
			CSRF:        sess.CSRF,
			Headers:     sess.Headers,
		})
	})

	mux.HandleFunc("/status", func(w http.ResponseWriter, r *http.Request) {
		list := make([]IdentityStatus, 0)
		for _, h := range st.Health() {
			s := IdentityStatus{Name: h.Name, Established: h.Established, LastError: h.LastError}
			if !h.ExpiresAt.IsZero() {
				s.ExpiresAt = h.ExpiresAt.UTC().Format(time.RFC3339)
			}
			if !h.LastRefresh.IsZero() {
				s.LastRefresh = h.LastRefresh.UTC().Format(time.RFC3339)
			}
			list = append(list, s)
		}
		writeJSON(w, StatusResponse{Identities: list})
	})

	return mux
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}
