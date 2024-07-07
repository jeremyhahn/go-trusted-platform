package cmd

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/cmd/subcommands"
)

func init() {

	rootCmd.AddCommand(platformCmd)

	platformCmd.AddCommand(subcommands.PFDestroyCmd)
}

var platformCmd = &cobra.Command{
	Use:   "platform",
	Short: "Platform Operations",
	Long:  `Perform platform administrator operations`,
	Run: func(cmd *cobra.Command, args []string) {

	},
}
