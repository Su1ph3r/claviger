package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

func newIdentitiesCmd() *cobra.Command {
	var cfgPath, socket string
	var tls tlsFlags
	cmd := &cobra.Command{
		Use:   "identities",
		Short: "List configured identities",
		RunE: func(cmd *cobra.Command, _ []string) error {
			tls.markChanged(cmd)
			names, err := identityNames(cmd.Context(), socket, cfgPath, tls, cmd.ErrOrStderr())
			if err != nil {
				return err
			}
			for _, id := range names {
				fmt.Fprintln(cmd.OutOrStdout(), id)
			}
			return nil
		},
	}
	cmd.Flags().StringVar(&cfgPath, "config", "claviger.yaml", "path to config file (standalone fallback)")
	cmd.Flags().StringVar(&socket, "socket", "", "control socket to attach to (default: the daemon's default path if running)")
	registerTLSFlags(cmd, &tls)
	return cmd
}
