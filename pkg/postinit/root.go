package postinit

import (
	"os"

	"github.com/kralicky/post-init/pkg/postinit/commands"
	"github.com/spf13/cobra"
)

func CreateRootCmd() *cobra.Command {
	var rootCmd = &cobra.Command{
		Use: "post-init",
		RunE: func(cmd *cobra.Command, _ []string) error {
			return cmd.Help()
		},
	}

	rootCmd.AddCommand(commands.BuildAgentCmd())
	rootCmd.AddCommand(commands.BuildRelayCmd())
	return rootCmd
}

func Execute() {
	if err := CreateRootCmd().Execute(); err != nil {
		os.Exit(1)
	}
}
