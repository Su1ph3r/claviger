package replay

import (
	"context"
	"net/http"
	"strings"

	"github.com/Su1ph3r/claviger/internal/corpus"
)

// CorpusRow pairs one corpus request with its per-identity replay results. The
// Results are in the input ids order, matching Run.
type CorpusRow struct {
	Request corpus.Request
	Results []Result
}

// RunCorpus replays every request in reqs under each identity, returning one row
// per request in the input request order. Each request's Path is appended to
// targetBase (a single joining slash is preserved). The request's method, header,
// and body are passed through verbatim to Run, so object references are preserved
// for horizontal/IDOR comparison. A nil Request.Header is tolerated (Run ranges
// over it safely).
func RunCorpus(ctx context.Context, src SessionSource, ids []string, reqs []corpus.Request, targetBase string, client *http.Client) ([]CorpusRow, error) {
	base := strings.TrimRight(targetBase, "/")
	rows := make([]CorpusRow, 0, len(reqs))
	for _, req := range reqs {
		targetURL := base + req.Path
		results, err := Run(ctx, src, ids, req.Method, targetURL, req.Header, req.Body, client)
		if err != nil {
			return nil, err
		}
		rows = append(rows, CorpusRow{Request: req, Results: results})
	}
	return rows, nil
}
