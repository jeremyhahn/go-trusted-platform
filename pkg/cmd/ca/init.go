package ca

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/prompt"
	"github.com/spf13/cobra"
)

var InitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize the Certificate Authority",
	Long: `Initializes the Certificate Authority by creating a Root and
Intermediates as specified in the platform configuration file.`,
	Run: func(cmd *cobra.Command, args []string) {

		prompt.PrintBanner(app.Version)

		App, err = App.Init(InitParams)
		if err != nil {
			cmd.PrintErrln(err)
			return
		}

		soPIN, userPIN, err := App.ParsePINs(InitParams.SOPin, InitParams.Pin)
		if err != nil {
			App.Logger.FatalError(err)
		}

		if _, err := App.InitCA(InitParams.PlatformCA, soPIN, userPIN); err != nil {
			cmd.PrintErrln(err)
			return
		}

		cmd.Println("Certificate Authority successfully initialized")
	},
}
