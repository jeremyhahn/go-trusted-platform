package ca

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/prompt"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
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

		var soPIN, userPIN keystore.Password
		if App.CA == nil {
			soPIN, userPIN, err = App.ParsePINs(InitParams.SOPin, InitParams.Pin)
			if err != nil {
				App.Logger.Error(err)
				cmd.PrintErrln(err)
				return
			}
			if err := App.LoadCA(soPIN, userPIN); err != nil {
				App.Logger.Error(err)
				cmd.PrintErrln(err)
				return
			}
		}

		if _, err := App.InitCA(soPIN, userPIN, InitParams); err != nil {
			cmd.PrintErrln(err)
			return
		}

		cmd.Println("Certificate Authority successfully initialized")
	},
}
