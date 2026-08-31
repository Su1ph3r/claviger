package cmd

import (
	"fmt"

	"github.com/spf13/cobra"
)

// version is overridden at build time via -ldflags -X.
var version = "dev"

func newVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the claviger version",
		RunE: func(cmd *cobra.Command, _ []string) error {
			fmt.Fprintf(cmd.OutOrStdout(), "claviger %s\n", version)
			return nil
		},
	}
}
