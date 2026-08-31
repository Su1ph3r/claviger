package config

import (
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/Su1ph3r/claviger/internal/httpx"
	"github.com/Su1ph3r/claviger/internal/recipe"
)

type LogoutConfig struct {
	StatusCodes      []int  `yaml:"status_codes"`
	LocationContains string `yaml:"location_contains"`
	BodyContains     string `yaml:"body_contains"`
}

// TLSConfig is the TLS trust and client-auth policy for reaching a target. It
// applies globally and can be overridden per identity.
type TLSConfig struct {
	Insecure   bool   `yaml:"insecure"`
	CACert     string `yaml:"ca_cert"`
	ClientCert string `yaml:"client_cert"`
	ClientKey  string `yaml:"client_key"`
}

// ToHTTPX maps the config-level TLS policy onto the httpx client's TLSConfig.
func (t TLSConfig) ToHTTPX() httpx.TLSConfig {
	return httpx.TLSConfig{
		InsecureSkipVerify: t.Insecure,
		CACertFile:         t.CACert,
		ClientCertFile:     t.ClientCert,
		ClientKeyFile:      t.ClientKey,
	}
}

// BackoffConfig overrides the store's refresh rate-limit ceiling and window. A
// zero value means the store default (10 refreshes per 60s).
type BackoffConfig struct {
	MaxBurst int           `yaml:"max_burst"`
	Window   time.Duration `yaml:"window"`
}

// ExtractConfig mirrors recipe.ExtractRule for the multistep recipe.
type ExtractConfig struct {
	Name    string `yaml:"name"`
	From    string `yaml:"from"`
	Pattern string `yaml:"pattern"`
}

// StepConfig mirrors recipe.Step for the multistep recipe.
type StepConfig struct {
	Method  string            `yaml:"method"`
	URL     string            `yaml:"url"`
	Form    map[string]string `yaml:"form"`
	Body    string            `yaml:"body"`
	Extract []ExtractConfig   `yaml:"extract"`
}

// CaptureConfig mirrors recipe.CaptureSpec for the multistep recipe. It also
// carries BearerLocalStorage, which is used only by the browser recipe: the
// localStorage key whose value becomes the session's bearer token.
type CaptureConfig struct {
	CSRF               string         `yaml:"csrf"`
	Bearer             *ExtractConfig `yaml:"bearer"`
	BearerLocalStorage string         `yaml:"bearer_localstorage"`
}

// CSRFConfig is an optional per-identity anti-CSRF token policy. When set, the
// gateway fetches FetchURL, extracts the token via Pattern's first capture group,
// and sets it on Header for the listed Methods before forwarding. It is consumed by
// the daemon (which builds the gateway-facing policy) rather than by Recipes, so
// config does not import gateway.
type CSRFConfig struct {
	FetchURL string   `yaml:"fetch_url"`
	Pattern  string   `yaml:"pattern"`
	Header   string   `yaml:"header"`
	Methods  []string `yaml:"methods"`
}

type IdentityConfig struct {
	Name     string `yaml:"name"`
	Type     string `yaml:"type"` // "form", "oauth", "multistep", or "browser"
	LoginURL string `yaml:"login_url"`
	TokenURL string `yaml:"token_url"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	// PasswordFile and PasswordCommand are alternative password sources resolved at
	// load. Precedence is password, then password_file, then password_command.
	PasswordFile    string       `yaml:"password_file"`
	PasswordCommand string       `yaml:"password_command"`
	TLS             *TLSConfig   `yaml:"tls"` // per-identity override of the global TLS policy
	Logout          LogoutConfig `yaml:"logout"`
	// Steps and Capture drive the multistep recipe. Password (above) supplies the
	// {{password}} template value.
	Steps   []StepConfig   `yaml:"steps"`
	Capture *CaptureConfig `yaml:"capture"`
	// CSRF is an optional per-identity anti-CSRF policy the gateway applies to
	// state-changing requests. Nil means no policy for this identity.
	CSRF *CSRFConfig `yaml:"csrf"`
	// The fields below drive the browser recipe (type: browser): CSS selectors
	// for the login form and the success condition. Exactly one of
	// SuccessURLContains or SuccessSelector should be set. Headful opens a visible
	// window for interactive MFA.
	UsernameSelector   string `yaml:"username_selector"`
	PasswordSelector   string `yaml:"password_selector"`
	SubmitSelector     string `yaml:"submit_selector"`
	SuccessURLContains string `yaml:"success_url_contains"`
	SuccessSelector    string `yaml:"success_selector"`
	Headful            bool   `yaml:"headful"`
}

type Config struct {
	Target     string           `yaml:"target"`
	TLS        TLSConfig        `yaml:"tls"`
	Backoff    BackoffConfig    `yaml:"backoff"`
	Identities []IdentityConfig `yaml:"identities"`
}

func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var c Config
	if err := yaml.Unmarshal(raw, &c); err != nil {
		return nil, fmt.Errorf("parse %s: %w", path, err)
	}
	if c.Target == "" {
		return nil, fmt.Errorf("config %s: target is required", path)
	}
	// Validate the target once at load so a missing scheme fails here rather than
	// cryptically on every proxied request.
	if u, err := url.Parse(c.Target); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return nil, fmt.Errorf("config %s: target must be an absolute http(s) URL, got %q", path, c.Target)
	}
	if err := c.resolveSecrets(); err != nil {
		return nil, err
	}
	return &c, nil
}

// validEndpoint checks a login/token URL is a well-formed absolute http(s) URL so a
// missing-scheme typo fails at load rather than on the first login. http is allowed
// (the operator may test an http-only app), so this checks form, not TLS.
func validEndpoint(name, endpoint string) error {
	if u, err := url.Parse(endpoint); err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
		return fmt.Errorf("identity %q: login/token URL must be an absolute http(s) URL, got %q", name, endpoint)
	}
	return nil
}

func (c *Config) Recipes() (map[string]recipe.Recipe, error) {
	out := make(map[string]recipe.Recipe, len(c.Identities))
	for _, id := range c.Identities {
		// A blank name would key the map on "", and "anon" collides with the
		// replay sentinel for the unauthenticated baseline. A duplicate name would
		// silently drop all but the last definition. Reject all three loudly.
		if id.Name == "" {
			return nil, fmt.Errorf("identity with an empty name")
		}
		if id.Name == "anon" {
			return nil, fmt.Errorf("identity name %q is reserved (it is the unauthenticated baseline)", id.Name)
		}
		if _, dup := out[id.Name]; dup {
			return nil, fmt.Errorf("duplicate identity name %q", id.Name)
		}
		sig := recipe.LogoutSignature{
			StatusCodes:      id.Logout.StatusCodes,
			LocationContains: id.Logout.LocationContains,
			BodyContains:     id.Logout.BodyContains,
		}
		// The effective TLS policy is the identity's own override if set, else the
		// global one. Build a dedicated client so the recipe reaches the target under
		// the correct trust and client-auth settings.
		eff := c.TLS
		if id.TLS != nil {
			eff = *id.TLS
		}
		client, err := httpx.Client(eff.ToHTTPX())
		if err != nil {
			return nil, fmt.Errorf("identity %q: tls: %w", id.Name, err)
		}
		switch id.Type {
		case "form":
			if err := validEndpoint(id.Name, id.LoginURL); err != nil {
				return nil, err
			}
			out[id.Name] = &recipe.FormPost{
				ID: id.Name, LoginURL: id.LoginURL,
				Username: id.Username, Password: id.Password, Signature: sig, Client: client,
			}
		case "oauth":
			if err := validEndpoint(id.Name, id.TokenURL); err != nil {
				return nil, err
			}
			out[id.Name] = &recipe.OAuth2{
				ID: id.Name, TokenURL: id.TokenURL,
				Username: id.Username, Password: id.Password, Signature: sig, Client: client,
			}
		case "multistep":
			ms, err := buildMultiStep(id, sig, client)
			if err != nil {
				return nil, err
			}
			out[id.Name] = ms
		case "browser":
			if err := validEndpoint(id.Name, id.LoginURL); err != nil {
				return nil, err
			}
			var bearerLS string
			if id.Capture != nil {
				bearerLS = id.Capture.BearerLocalStorage
			}
			out[id.Name] = &recipe.Browser{
				ID:                 id.Name,
				LoginURL:           id.LoginURL,
				UsernameSelector:   id.UsernameSelector,
				PasswordSelector:   id.PasswordSelector,
				SubmitSelector:     id.SubmitSelector,
				SuccessURLContains: id.SuccessURLContains,
				SuccessSelector:    id.SuccessSelector,
				Headful:            id.Headful,
				Insecure:           eff.Insecure,
				BearerLocalStorage: bearerLS,
				Username:           id.Username,
				Password:           id.Password,
				Signature:          sig,
				Client:             client,
			}
		default:
			return nil, fmt.Errorf("identity %q: unknown type %q", id.Name, id.Type)
		}
	}
	return out, nil
}

// buildMultiStep maps a multistep identity's config onto a recipe.MultiStep,
// carrying the per-identity TLS client through so the flow reaches the target
// under the correct trust. id.Password supplies the {{password}} value.
func buildMultiStep(id IdentityConfig, sig recipe.LogoutSignature, client *http.Client) (*recipe.MultiStep, error) {
	if len(id.Steps) == 0 {
		return nil, fmt.Errorf("identity %q: multistep requires at least one step", id.Name)
	}
	steps := make([]recipe.Step, 0, len(id.Steps))
	for _, sc := range id.Steps {
		// Validate literal step URLs at load so a missing-scheme typo fails here.
		// Templated URLs (containing {{...}}) are only known at run time, so skip
		// those rather than reject a valid template.
		if !strings.Contains(sc.URL, "{{") {
			if err := validEndpoint(id.Name, sc.URL); err != nil {
				return nil, err
			}
		}
		extract := make([]recipe.ExtractRule, 0, len(sc.Extract))
		for _, ec := range sc.Extract {
			extract = append(extract, recipe.ExtractRule{Name: ec.Name, From: ec.From, Pattern: ec.Pattern})
		}
		steps = append(steps, recipe.Step{
			Method:  sc.Method,
			URL:     sc.URL,
			Form:    sc.Form,
			Body:    sc.Body,
			Extract: extract,
		})
	}
	var capSpec recipe.CaptureSpec
	if id.Capture != nil {
		capSpec.CSRF = id.Capture.CSRF
		if b := id.Capture.Bearer; b != nil {
			capSpec.Bearer = &recipe.ExtractRule{Name: b.Name, From: b.From, Pattern: b.Pattern}
		}
	}
	return &recipe.MultiStep{
		ID:        id.Name,
		Password:  id.Password,
		Steps:     steps,
		Capture:   capSpec,
		Signature: sig,
		Client:    client,
	}, nil
}
