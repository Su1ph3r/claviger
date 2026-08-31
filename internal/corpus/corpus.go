// Package corpus loads a set of HTTP requests from a simple requests file, a
// HAR export, or an OpenAPI spec, for batch replay across identities.
package corpus

import (
	"bufio"
	"fmt"
	"net/http"
	"os"
	"strings"
)

// Request is one HTTP request to replay. Path is the path (and query) on the
// target; replay prepends the configured target base.
type Request struct {
	Method string
	Path   string
	Header http.Header
	Body   []byte
}

// Load reads a corpus from path. format is one of "requests", "har", or
// "openapi"; an empty format auto-detects by extension and content. OpenAPI
// specs yield only safe methods (GET/HEAD/OPTIONS); use LoadOptions to include
// unsafe methods.
func Load(path, format string) ([]Request, error) {
	return LoadOptions(path, format, false)
}

// LoadOptions is Load with control over whether OpenAPI unsafe methods
// (POST/PUT/PATCH/DELETE) are included. includeUnsafe only affects the openapi
// format.
func LoadOptions(path, format string, includeUnsafe bool) ([]Request, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if format == "" {
		format = detectFormat(path, data)
	}
	switch format {
	case "requests":
		return loadRequests(data)
	case "har":
		return loadHAR(data)
	case "openapi":
		return loadOpenAPI(data, includeUnsafe)
	default:
		return nil, fmt.Errorf("unknown corpus format %q", format)
	}
}

func detectFormat(path string, data []byte) string {
	lower := strings.ToLower(path)
	switch {
	case strings.HasSuffix(lower, ".har"):
		return "har"
	case strings.HasSuffix(lower, ".yaml"), strings.HasSuffix(lower, ".yml"), strings.HasSuffix(lower, ".json"):
		c := strings.ToLower(string(data))
		if strings.Contains(c, "openapi") || strings.Contains(c, "swagger") {
			return "openapi"
		}
		return "requests"
	default:
		return "requests"
	}
}

func loadRequests(data []byte) ([]Request, error) {
	var reqs []Request
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	line := 0
	for sc.Scan() {
		line++
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Fields(text)
		if len(fields) != 2 {
			return nil, fmt.Errorf("line %d: expected `METHOD /path`, got %q", line, text)
		}
		// A path without a leading slash yields a malformed target (host glued to
		// the path) once replay prepends the base, matching single-request replay's
		// own --path guard rather than silently building a wrong URL.
		if !strings.HasPrefix(fields[1], "/") {
			return nil, fmt.Errorf("line %d: path must start with \"/\": %q", line, fields[1])
		}
		reqs = append(reqs, Request{
			Method: strings.ToUpper(fields[0]),
			Path:   fields[1],
		})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return reqs, nil
}
