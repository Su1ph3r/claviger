package gateway

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/Su1ph3r/claviger/testutil/mockauth"
)

func TestGatewayAuditLogsOneRecordPerRequest(t *testing.T) {
	ma := mockauth.New(time.Minute)
	target := httptest.NewServer(ma.Handler())
	defer target.Close()

	g, _ := newTestGateway(t, target.URL, time.Minute)
	var buf bytes.Buffer
	WithAudit(slog.New(slog.NewJSONHandler(&buf, nil)))(g)

	front := httptest.NewServer(g.Handler("alice"))
	defer front.Close()

	resp, err := http.Get(front.URL + "/api/whoami")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()

	var rec map[string]any
	if err := json.Unmarshal(bytes.TrimSpace(buf.Bytes()), &rec); err != nil {
		t.Fatalf("audit line is not one JSON object: %v (%q)", err, buf.String())
	}
	if rec["identity"] != "alice" || rec["method"] != "GET" || rec["path"] != "/api/whoami" {
		t.Errorf("audit record fields wrong: %v", rec)
	}
	if _, ok := rec["status"]; !ok {
		t.Error("audit record missing status")
	}
	if _, ok := rec["time"]; !ok {
		t.Error("audit record missing timestamp")
	}
}
