package subcommands

import (
	"github.com/spf13/cobra"
)

var PFSetupCmd = &cobra.Command{
	Use:   "setup",
	Short: "Performs initial platform setup",
	Long: `Initializes the platform and Certificate Authority by creating new Root
and Intermediate Certificate Authorities, sets initial passwords, and issues an
x509 certificate for the web server.`,
	Run: func(cmd *cobra.Command, args []string) {
		// Root calls App.Init() which initializes the CA
		App.Logger.Info("Platform is ready to Go!")
	},
}
