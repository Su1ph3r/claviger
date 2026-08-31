package recipe

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/url"
	"regexp"
	"strconv"
	"strings"

	"github.com/Su1ph3r/claviger/internal/session"
)

// ExtractRule pulls one value out of a step's response into a flow variable.
// From selects the source: "body" (regex first capture group), "header" (the
// named response header), or "json" (a dotted key path in the JSON body).
type ExtractRule struct {
	Name    string
	From    string // "body" | "header" | "json"
	Pattern string
}

// Step is one request in a multistep login flow. Form, when non-empty, is sent
// url-encoded; otherwise Body is sent verbatim. URL, Form values, and Body may
// contain {{name}} templates resolved against the accumulated flow variables.
type Step struct {
	Method  string
	URL     string
	Form    map[string]string
	Body    string
	Extract []ExtractRule
}

// CaptureSpec maps flow variables onto the final Session. CSRF is a template
// resolved after all steps run; Bearer, when set, is an extract applied to the
// LAST step's response.
type CaptureSpec struct {
	CSRF   string
	Bearer *ExtractRule
}

// MultiStep runs a scripted sequence of HTTP requests to establish a session,
// threading cookies through a per-Establish jar and values through {{name}}
// templates. It is the declarative recipe for logins that need a CSRF fetch,
// a redirect hop, or a token pulled from an intermediate page.
type MultiStep struct {
	ID        string
	Password  string
	Steps     []Step
	Capture   CaptureSpec
	Signature LogoutSignature
	Client    *http.Client // optional; supplies the TLS transport
}

func (r *MultiStep) Identity() string        { return r.ID }
func (r *MultiStep) Logout() LogoutSignature { return r.Signature }

// transport returns the recipe client's transport so the per-Establish client
// keeps the injected TLS trust, falling back to the default when unset.
func (r *MultiStep) transport() http.RoundTripper {
	if r.Client != nil && r.Client.Transport != nil {
		return r.Client.Transport
	}
	return http.DefaultTransport
}

func (r *MultiStep) Establish(ctx context.Context) (*session.Session, error) {
	if len(r.Steps) == 0 {
		return nil, fmt.Errorf("multistep login for %q: no steps configured", r.ID)
	}
	// A per-Establish jar accumulates cookies across steps (the CSRF cookie set on
	// the GET is what the POST must echo back). The injected transport is kept so
	// the flow reaches the target under the configured TLS trust.
	jar, err := cookiejar.New(nil)
	if err != nil {
		return nil, err
	}
	c := &http.Client{Transport: r.transport(), Jar: jar}

	// vars is seeded with the resolved password so {{password}} substitutes, and
	// grows as each step's extracts fire.
	vars := map[string]string{"password": r.Password}

	var lastResp *http.Response
	var lastBody []byte
	var lastURL string

	for i, step := range r.Steps {
		method := step.Method
		if method == "" {
			method = http.MethodGet
		}
		reqURL := subst(step.URL, vars)

		var bodyReader io.Reader
		contentType := ""
		if len(step.Form) > 0 {
			form := url.Values{}
			for k, v := range step.Form {
				form.Set(k, subst(v, vars))
			}
			bodyReader = strings.NewReader(form.Encode())
			contentType = "application/x-www-form-urlencoded"
		} else if step.Body != "" {
			bodyReader = strings.NewReader(subst(step.Body, vars))
		}

		req, err := http.NewRequestWithContext(ctx, method, reqURL, bodyReader)
		if err != nil {
			return nil, fmt.Errorf("multistep login for %q: step %d: %w", r.ID, i+1, err)
		}
		if contentType != "" {
			req.Header.Set("Content-Type", contentType)
		}

		resp, err := c.Do(req)
		if err != nil {
			return nil, fmt.Errorf("multistep login for %q: step %d (%s): %w", r.ID, i+1, method, err)
		}
		body, err := io.ReadAll(resp.Body)
		resp.Body.Close()
		if err != nil {
			return nil, fmt.Errorf("multistep login for %q: step %d: reading body: %w", r.ID, i+1, err)
		}
		if resp.StatusCode >= 400 {
			return nil, fmt.Errorf("multistep login for %q: step %d (%s) returned status %d", r.ID, i+1, method, resp.StatusCode)
		}

		for _, rule := range step.Extract {
			val, err := applyExtract(rule, resp, body)
			if err != nil {
				return nil, fmt.Errorf("multistep login for %q: step %d: %w", r.ID, i+1, err)
			}
			if val == "" {
				return nil, fmt.Errorf("multistep login for %q: step %d: extract %q yielded nothing", r.ID, i+1, rule.Name)
			}
			vars[rule.Name] = val
		}

		lastResp, lastBody, lastURL = resp, body, reqURL
	}

	u, err := url.Parse(lastURL)
	if err != nil {
		return nil, fmt.Errorf("multistep login for %q: parsing last url: %w", r.ID, err)
	}

	sess := &session.Session{
		Identity: r.ID,
		Cookies:  jar.Cookies(u),
	}
	if r.Capture.CSRF != "" {
		sess.CSRF = subst(r.Capture.CSRF, vars)
	}
	if r.Capture.Bearer != nil {
		val, err := applyExtract(*r.Capture.Bearer, lastResp, lastBody)
		if err != nil {
			return nil, fmt.Errorf("multistep login for %q: capture bearer: %w", r.ID, err)
		}
		sess.BearerToken = val
	}
	// A flow that captured neither a cookie nor a bearer never really logged in;
	// reject it rather than caching an empty session that injects nothing.
	if len(sess.Cookies) == 0 && sess.BearerToken == "" {
		return nil, fmt.Errorf("multistep login for %q captured no session material (no cookie and no token)", r.ID)
	}
	return sess, nil
}

// Refresh re-runs the whole flow; a multistep login has no incremental refresh.
func (r *MultiStep) Refresh(ctx context.Context, _ *session.Session) (*session.Session, error) {
	return r.Establish(ctx)
}

// subst replaces every {{name}} occurrence with its variable value. A missing
// variable leaves the literal token in place, which surfaces downstream (a
// server rejecting the unresolved value) rather than silently vanishing.
func subst(s string, vars map[string]string) string {
	for k, v := range vars {
		s = strings.ReplaceAll(s, "{{"+k+"}}", v)
	}
	return s
}

// applyExtract resolves one rule against a response, returning the extracted
// string ("" when the source is present but the value is absent).
func applyExtract(rule ExtractRule, resp *http.Response, body []byte) (string, error) {
	switch rule.From {
	case "", "body":
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			return "", fmt.Errorf("extract %q: bad pattern: %w", rule.Name, err)
		}
		m := re.FindSubmatch(body)
		if m == nil {
			return "", nil
		}
		if len(m) > 1 {
			return string(m[1]), nil
		}
		return string(m[0]), nil
	case "header":
		return resp.Header.Get(rule.Pattern), nil
	case "json":
		var data map[string]any
		if err := json.Unmarshal(body, &data); err != nil {
			return "", fmt.Errorf("extract %q: response body is not JSON: %w", rule.Name, err)
		}
		return jsonPath(data, rule.Pattern), nil
	default:
		return "", fmt.Errorf("extract %q: unknown source %q", rule.Name, rule.From)
	}
}

// jsonPath walks a dotted key path through decoded JSON and renders the leaf as
// a string. A path that runs off the object, or a leaf that is an object/array,
// yields "".
func jsonPath(data map[string]any, path string) string {
	var cur any = data
	for _, part := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return ""
		}
		cur, ok = m[part]
		if !ok {
			return ""
		}
	}
	switch v := cur.(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(v)
	default:
		return ""
	}
}
