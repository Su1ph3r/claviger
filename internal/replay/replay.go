package replay

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"time"

	"github.com/Su1ph3r/claviger/internal/session"
)

// SessionSource provides a live session for an identity. It is satisfied by the
// local *store.Store (standalone) and by the control client (attached to a running
// daemon), so replay can reuse warm daemon sessions or log in itself.
type SessionSource interface {
	Get(ctx context.Context, id string) (*session.Session, error)
}

type Result struct {
	Identity string
	Status   int
	Size     int
	Duration time.Duration
	Body     []byte
	// Err records a per-identity failure (login, transport, or body read). It is
	// non-nil only for the row that failed; the other identities still produce
	// results, so one bad row never erases the whole comparison table.
	Err error
}

// Run sends the same request under each identity. The request is verbatim except
// for the injected session, so object references in the URL and body are preserved
// (this is what makes horizontal/IDOR checks possible). A failure for one identity
// is captured in that identity's Result.Err and the fan-out continues; the returned
// error is reserved for failures that abort the whole run (currently none).
// The trailing client selects the TLS policy for the requests to the target. A
// nil client uses the default strict policy; a supplied client (e.g. one built
// from the config TLS settings) is used instead. Either way replay forces the
// no-redirect policy so status codes are compared verbatim: for a supplied
// client this is done on a shallow copy, so the caller's client is not mutated.
func Run(ctx context.Context, src SessionSource, ids []string, method, targetURL string, header http.Header, body []byte, client *http.Client) ([]Result, error) {
	noRedirect := func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	if client == nil {
		client = &http.Client{CheckRedirect: noRedirect}
	} else {
		c := *client
		c.CheckRedirect = noRedirect
		client = &c
	}
	results := make([]Result, 0, len(ids))

	for _, id := range ids {
		req, err := http.NewRequestWithContext(ctx, method, targetURL, bytes.NewReader(body))
		if err != nil {
			results = append(results, Result{Identity: id, Err: err})
			continue
		}
		for k, vals := range header {
			for _, v := range vals {
				req.Header.Add(k, v)
			}
		}

		if id != "anon" {
			sess, err := src.Get(ctx, id)
			if err != nil {
				results = append(results, Result{Identity: id, Err: err})
				continue
			}
			sess.Apply(req)
		}

		start := time.Now()
		resp, err := client.Do(req)
		if err != nil {
			results = append(results, Result{Identity: id, Duration: time.Since(start), Err: err})
			continue
		}
		rb, readErr := io.ReadAll(resp.Body)
		resp.Body.Close()

		// A body-read error is recorded but the status and partial body are still
		// reported, so a truncated read is visible rather than silently shortening
		// the comparison input.
		results = append(results, Result{
			Identity: id,
			Status:   resp.StatusCode,
			Size:     len(rb),
			Duration: time.Since(start),
			Body:     rb,
			Err:      readErr,
		})
	}
	return results, nil
}
