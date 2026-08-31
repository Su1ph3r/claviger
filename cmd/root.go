package cmd

import "github.com/spf13/cobra"

func NewRootCmd() *cobra.Command {
	root := &cobra.Command{
		Use:   "claviger",
		Short: "A local session authority for penetration testers",
		// A runtime error (bad config, failed login) is self-explanatory; do not
		// bury it under a usage dump. main() prints the error to stderr.
		SilenceUsage:  true,
		SilenceErrors: true,
	}
	root.Version = version
	root.SetVersionTemplate("claviger {{.Version}}\n")
	root.AddCommand(newDaemonCmd())
	root.AddCommand(newIdentitiesCmd())
	root.AddCommand(newHeaderCmd())
	root.AddCommand(newReplayCmd())
	root.AddCommand(newStatusCmd())
	root.AddCommand(newWatchCmd())
	root.AddCommand(newVersionCmd())
	return root
}

func Execute() error {
	return NewRootCmd().Execute()
}
