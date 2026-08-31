package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newHeaderCmd() *cobra.Command {
	var cfgPath, socket string
	var tls tlsFlags
	cmd := &cobra.Command{
		Use:   "header <identity>",
		Short: "Print a live Authorization header for an identity",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]
			tls.markChanged(cmd)
			sess, err := sessionFor(cmd.Context(), socket, cfgPath, id, tls, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			if sess.BearerToken == "" {
				return fmt.Errorf("identity %q has no bearer token (cookie-only session)", id)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Authorization: Bearer %s\n", sess.BearerToken)
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "claviger.yaml", "path to config file (standalone fallback)")
	cmd.Flags().StringVar(&socket, "socket", "", "control socket to attach to (default: the daemon's default path if running)")
	registerTLSFlags(cmd, &tls)
	return cmd
}
