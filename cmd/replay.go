package cmd

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/spf13/cobra"

	"github.com/Su1ph3r/claviger/internal/config"
	"github.com/Su1ph3r/claviger/internal/corpus"
	"github.com/Su1ph3r/claviger/internal/httpx"
	"github.com/Su1ph3r/claviger/internal/replay"
)

func newReplayCmd() *cobra.Command {
	var cfgPath, method, path, socket string
	var corpusFile, format string
	var includeUnsafe bool
	var ids []string
	var tls tlsFlags
	cmd := &cobra.Command{
		Use:           "replay",
		Short:         "Send one request under each identity and print a status table",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			cfg, err := config.Load(cfgPath)
			if err != nil {
				return err
			}
			// The replay client always reaches the target locally, whether or not a
			// daemon supplies the sessions, so the TLS flags override cfg here and the
			// insecure warning fires whenever verification ends up disabled.
			tls.markChanged(cmd)
			applyTLSFlags(cfg, tls)
			warnIfInsecure(cmd.ErrOrStderr(), cfg)
			warnIfPlaintextAuth(cmd.ErrOrStderr(), cfg)
			if len(ids) == 0 {
				return fmt.Errorf("at least one --as identity is required")
			}

			if corpusFile != "" {
				// --corpus fans a whole request set across identities; the single-request
				// --path mode is the alternative, so a non-default --path alongside it is a
				// contradiction rather than a silent precedence.
				if cmd.Flags().Changed("path") {
					return fmt.Errorf("--corpus and --path are mutually exclusive")
				}
				// Methods come from the corpus, so a changed --method is silently
				// ignored otherwise; reject it like a non-default --path above.
				if cmd.Flags().Changed("method") {
					return fmt.Errorf("--method cannot be combined with --corpus (methods come from the corpus)")
				}
				return runCorpus(cmd, cfg, cfgPath, socket, tls, ids, corpusFile, format, includeUnsafe)
			}

			if !strings.HasPrefix(path, "/") {
				return fmt.Errorf("--path must begin with '/', got %q", path)
			}
			method = strings.ToUpper(strings.TrimSpace(method))

			// Reuse a running daemon's warm sessions if one is up, else log in standalone.
			src, err := replaySource(socket, cfgPath, tls)
			if err != nil {
				return err
			}

			client, err := httpx.Client(cfg.TLS.ToHTTPX())
			if err != nil {
				return err
			}

			target := strings.TrimRight(cfg.Target, "/") + path
			results, err := replay.Run(cmd.Context(), src, ids, method, target, http.Header{}, nil, client)
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "%-12s %-6s %-8s %s\n", "IDENTITY", "STATUS", "SIZE", "TIME")
			failures := 0
			for _, r := range results {
				if r.Err != nil {
					failures++
					fmt.Fprintf(cmd.OutOrStdout(), "%-12s %-6s %-8s %v\n", r.Identity, "ERR", "-", r.Err)
					continue
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%-12s %-6d %-8d %s\n", r.Identity, r.Status, r.Size, r.Duration)
			}
			// A non-zero exit when every identity failed lets a CI wrapper gate on it;
			// partial failures still exit 0 because the table is the deliverable.
			if len(results) > 0 && failures == len(results) {
				return fmt.Errorf("all %d identities failed", failures)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "claviger.yaml", "path to config file")
	cmd.Flags().StringVar(&method, "method", "GET", "HTTP method")
	cmd.Flags().StringVar(&path, "path", "/", "request path on the target")
	cmd.Flags().StringArrayVar(&ids, "as", nil, "identity to replay as (repeatable)")
	cmd.Flags().StringVar(&socket, "socket", "", "control socket to attach to (default: the daemon's default path if running)")
	cmd.Flags().StringVar(&corpusFile, "corpus", "", "replay a corpus file across identities (requests/HAR/OpenAPI) instead of a single --path")
	cmd.Flags().StringVar(&format, "format", "", "corpus format: requests|har|openapi (default: auto-detect by extension)")
	cmd.Flags().BoolVar(&includeUnsafe, "include-unsafe", false, "include state-changing methods (POST/PUT/PATCH/DELETE) from an OpenAPI corpus")
	registerTLSFlags(cmd, &tls)
	return cmd
}

// runCorpus loads a corpus and replays every request across the identities,
// printing a request-by-identity status matrix. It attaches to a running daemon
// and uses the config-TLS client exactly like single-request replay.
func runCorpus(cmd *cobra.Command, cfg *config.Config, cfgPath, socket string, tls tlsFlags, ids []string, corpusFile, format string, includeUnsafe bool) error {
	reqs, err := corpus.LoadOptions(corpusFile, format, includeUnsafe)
	if err != nil {
		return err
	}
	if len(reqs) == 0 {
		return fmt.Errorf("corpus %q has no requests", corpusFile)
	}

	src, err := replaySource(socket, cfgPath, tls)
	if err != nil {
		return err
	}
	client, err := httpx.Client(cfg.TLS.ToHTTPX())
	if err != nil {
		return err
	}

	rows, err := replay.RunCorpus(cmd.Context(), src, ids, reqs, cfg.Target, client)
	if err != nil {
		return err
	}

	out := cmd.OutOrStdout()
	requests, allFailed := 0, 0
	for _, row := range rows {
		requests++
		differs := statusesDiffer(row.Results)
		marker := ""
		if differs {
			marker = "  DIFFERS"
		}
		fmt.Fprintf(out, "%s %s%s\n", row.Request.Method, row.Request.Path, marker)
		failures := 0
		for _, r := range row.Results {
			if r.Err != nil {
				failures++
				fmt.Fprintf(out, "  %-12s %-6s %-8s %v\n", r.Identity, "ERR", "-", r.Err)
				continue
			}
			fmt.Fprintf(out, "  %-12s %-6d %-8d\n", r.Identity, r.Status, r.Size)
		}
		if failures == len(row.Results) {
			allFailed++
		}
	}
	// Mirror single-request replay's all-failed rule: exit non-zero only when every
	// request failed for every identity. A partial matrix is still the deliverable.
	if requests > 0 && allFailed == requests {
		return fmt.Errorf("all %d requests failed for every identity", requests)
	}
	return nil
}

// statusesDiffer reports whether the non-error statuses across a row's identities
// are not all equal. It is a fact about the responses, not a verdict.
func statusesDiffer(results []replay.Result) bool {
	first := -1
	for _, r := range results {
		if r.Err != nil {
			continue
		}
		if first == -1 {
			first = r.Status
			continue
		}
		if r.Status != first {
			return true
		}
	}
	return false
}
