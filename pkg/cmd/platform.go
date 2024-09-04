package cmd

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/cmd/platform"

	"github.com/spf13/cobra"

	subcmd "github.com/jeremyhahn/go-trusted-platform/pkg/cmd/platform"
)

func init() {

	platformCmd.AddCommand(platform.DestroyCmd)
	platformCmd.AddCommand(platform.PasswordCmd)
	platformCmd.AddCommand(platform.ProvisionCmd)
	platformCmd.AddCommand(platform.InstallCmd)

	rootCmd.AddCommand(platformCmd)
}

func initPlatform() {

	subcmd.App = App
	subcmd.InitParams = InitParams
	subcmd.CAParams = CAParams
}

var platformCmd = &cobra.Command{
	Use:   "platform",
	Short: "Platform Operations",
	Long:  `Perform Platform Administrator operations`,
	Run: func(cmd *cobra.Command, args []string) {

	},
}
