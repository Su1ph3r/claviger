package cmd

import (
	"fmt"
	"io"
	"net/url"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Su1ph3r/claviger/internal/config"
)

// tlsFlags holds the CLI TLS override values plus a per-field "was it set on the
// command line" marker. A flag overrides the config's global TLS block only when
// its matching *Set marker is true, so an unset flag leaves the configured value
// untouched. The markers mirror cobra's cmd.Flags().Changed(name); markChanged
// fills them from a parsed command.
type tlsFlags struct {
	insecure    bool
	insecureSet bool

	caCert    string
	caCertSet bool

	clientCert    string
	clientCertSet bool

	clientKey    string
	clientKeySet bool
}

// registerTLSFlags adds the four TLS override flags to cmd, binding them to f.
func registerTLSFlags(cmd *cobra.Command, f *tlsFlags) {
	cmd.Flags().BoolVar(&f.insecure, "insecure", false, "skip TLS certificate verification for the target (overrides config; opt-in and unsafe)")
	cmd.Flags().StringVar(&f.caCert, "ca-cert", "", "PEM CA bundle to trust for the target (overrides config)")
	cmd.Flags().StringVar(&f.clientCert, "client-cert", "", "client certificate PEM for mutual TLS (overrides config)")
	cmd.Flags().StringVar(&f.clientKey, "client-key", "", "client private key PEM for mutual TLS (overrides config)")
}

// markChanged records which TLS flags the user actually set, using cobra's per-flag
// change tracking, so applyTLSFlags overrides only those fields. Call it inside RunE
// after cobra has parsed the flags.
func (f *tlsFlags) markChanged(cmd *cobra.Command) {
	f.insecureSet = cmd.Flags().Changed("insecure")
	f.caCertSet = cmd.Flags().Changed("ca-cert")
	f.clientCertSet = cmd.Flags().Changed("client-cert")
	f.clientKeySet = cmd.Flags().Changed("client-key")
}

// applyTLSFlags overrides cfg's global TLS fields with each flag the user set,
// leaving unset flags at their configured value. Per-identity TLS overrides in the
// config still take precedence over the global block, so a flag reaches only the
// identities that inherit the global policy.
func applyTLSFlags(cfg *config.Config, f tlsFlags) {
	if f.insecureSet {
		cfg.TLS.Insecure = f.insecure
	}
	if f.caCertSet {
		cfg.TLS.CACert = f.caCert
	}
	if f.clientCertSet {
		cfg.TLS.ClientCert = f.clientCert
	}
	if f.clientKeySet {
		cfg.TLS.ClientKey = f.clientKey
	}
}

// warnIfInsecure prints a stderr line whenever TLS verification is disabled, so
// neither the global policy nor a per-identity override is ever silent. An identity
// can carry its own tls block that disables verification for its login client even
// when the global policy is secure, so both sources are checked and named.
func warnIfInsecure(w io.Writer, cfg *config.Config) {
	if cfg.TLS.Insecure {
		fmt.Fprintln(w, "warning: TLS verification disabled (global tls policy)")
	}
	for _, id := range cfg.Identities {
		if id.TLS != nil && id.TLS.Insecure {
			fmt.Fprintf(w, "warning: TLS verification disabled for identity %q\n", id.Name)
		}
	}
}

// warnIfPlaintextAuth prints a stderr line for every identity whose login or token
// URL uses a plaintext http:// scheme, since real credentials sent there travel in
// cleartext. This is a warning, not an error: config.validEndpoint already permits
// http:// because a test target may legitimately be plaintext. Only the scheme is
// reported, never the endpoint value.
func warnIfPlaintextAuth(w io.Writer, cfg *config.Config) {
	for _, id := range cfg.Identities {
		endpoints := []struct{ which, raw string }{
			{"login", id.LoginURL},
			{"token", id.TokenURL},
		}
		// A multistep identity carries its credential-posting endpoints in its
		// steps (which POST the {{password}} template), not in LoginURL/TokenURL,
		// so an http step leaks the password just as a plaintext login URL would.
		for _, s := range id.Steps {
			if strings.Contains(s.URL, "{{") {
				// A templated URL cannot be parsed for its scheme until run time,
				// so it is not added to the parse list below. But a LITERAL http://
				// prefix is a plaintext risk even when only the host is templated
				// (e.g. http://{{host}}/login), so warn on that here.
				if strings.HasPrefix(strings.ToLower(s.URL), "http://") {
					fmt.Fprintf(w, "warning: identity %q uses a plaintext http:// step URL; credentials will be sent in cleartext\n", id.Name)
				}
				continue
			}
			endpoints = append(endpoints, struct{ which, raw string }{"step", s.URL})
		}
		for _, ep := range endpoints {
			if ep.raw == "" {
				continue
			}
			parsed, err := url.Parse(ep.raw)
			if err != nil {
				// Endpoint URLs are validated when recipes are built; a malformed
				// URL here is simply ignored rather than reported as plaintext.
				continue
			}
			if parsed.Scheme == "http" {
				fmt.Fprintf(w, "warning: identity %q uses a plaintext http:// %s URL; credentials will be sent in cleartext\n", id.Name, ep.which)
			}
		}
	}
}
