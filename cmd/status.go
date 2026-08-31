package cmd

import (
	"fmt"
	"io"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"

	"github.com/Su1ph3r/claviger/internal/control"
)

const (
	cReset  = "\033[0m"
	cGreen  = "\033[32m"
	cYellow = "\033[33m"
	cRed    = "\033[31m"
	cDim    = "\033[2m"
	cBold   = "\033[1m"
)

// statusClient returns a control client, erroring clearly when no daemon is running
// (status and watch read live state and have no standalone fallback).
func statusClient(socketFlag string) (*control.Client, error) {
	client, path, ok, err := attachClient(socketFlag)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("no daemon running at %s (start `claviger daemon`)", path)
	}
	return client, nil
}

func newStatusCmd() *cobra.Command {
	var socket string
	var noColor bool
	cmd := &cobra.Command{
		Use:           "status",
		Short:         "Show per-identity session health from a running daemon",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := statusClient(socket)
			if err != nil {
				return err
			}
			st, err := client.Status(cmd.Context())
			if err != nil {
				return err
			}
			renderStatus(cmd.OutOrStdout(), st, time.Now(), !noColor)
			return nil
		},
	}
	cmd.Flags().StringVar(&socket, "socket", "", "control socket (default: the daemon's default path)")
	cmd.Flags().BoolVar(&noColor, "no-color", false, "disable ANSI color")
	return cmd
}

func newWatchCmd() *cobra.Command {
	var socket string
	var interval time.Duration
	cmd := &cobra.Command{
		Use:           "watch",
		Short:         "Live-updating session-health monitor",
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(cmd *cobra.Command, _ []string) error {
			client, err := statusClient(socket)
			if err != nil {
				return err
			}
			ctx, stop := signal.NotifyContext(cmd.Context(), syscall.SIGINT, syscall.SIGTERM)
			defer stop()
			out := cmd.OutOrStdout()

			draw := func() {
				fmt.Fprint(out, "\033[H\033[2J") // cursor home + clear screen
				fmt.Fprintf(out, "%sclaviger watch%s  %s%s%s\n\n", cBold, cReset, cDim, time.Now().Format("15:04:05"), cReset)
				st, err := client.Status(ctx)
				if err != nil {
					fmt.Fprintf(out, "%v\n", err)
					return
				}
				renderStatus(out, st, time.Now(), true)
				fmt.Fprintf(out, "\n%sctrl-c to quit%s\n", cDim, cReset)
			}

			draw()
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				select {
				case <-ctx.Done():
					fmt.Fprintln(out)
					return nil
				case <-ticker.C:
					draw()
				}
			}
		},
	}
	cmd.Flags().StringVar(&socket, "socket", "", "control socket (default: the daemon's default path)")
	cmd.Flags().DurationVar(&interval, "interval", time.Second, "refresh interval")
	return cmd
}

// renderStatus prints a health table. Only the STATE cell is colored, and the color
// codes wrap an already-padded string so column alignment is preserved.
func renderStatus(w io.Writer, st control.StatusResponse, now time.Time, color bool) {
	fmt.Fprintf(w, "%-14s %-12s %-14s %-14s %s\n", "IDENTITY", "STATE", "EXPIRES", "LAST-REFRESH", "LAST-ERROR")
	if len(st.Identities) == 0 {
		fmt.Fprintln(w, "(no identities)")
		return
	}
	for _, s := range st.Identities {
		state, stateColor := deriveState(s, now)
		cell := fmt.Sprintf("%-12s", state)
		if color {
			cell = stateColor + cell + cReset
		}
		lastErr := s.LastError
		if lastErr == "" {
			lastErr = "-"
		}
		fmt.Fprintf(w, "%-14s %s %-14s %-14s %s\n",
			s.Name, cell, relExpiry(s.ExpiresAt, now), relPast(s.LastRefresh, now), lastErr)
	}
}

func deriveState(s control.IdentityStatus, now time.Time) (string, string) {
	if !s.Established {
		return "no-session", cDim
	}
	if s.ExpiresAt == "" {
		return "live", cGreen
	}
	exp, err := time.Parse(time.RFC3339, s.ExpiresAt)
	if err != nil {
		return "live", cGreen
	}
	switch d := exp.Sub(now); {
	case d <= 0:
		return "EXPIRED", cRed
	case d < time.Minute:
		return "expiring", cYellow
	default:
		return "live", cGreen
	}
}

func relExpiry(rfc string, now time.Time) string {
	if rfc == "" {
		return "unknown"
	}
	t, err := time.Parse(time.RFC3339, rfc)
	if err != nil {
		return rfc
	}
	if d := t.Sub(now); d <= 0 {
		return "expired"
	} else {
		return "in " + d.Round(time.Second).String()
	}
}

func relPast(rfc string, now time.Time) string {
	if rfc == "" {
		return "never"
	}
	t, err := time.Parse(time.RFC3339, rfc)
	if err != nil {
		return rfc
	}
	return now.Sub(t).Round(time.Second).String() + " ago"
}
