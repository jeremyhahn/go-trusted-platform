package ca

import (
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var InitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize the Certificate Authority",
	Long: `Initializes the Certificate Authority by creating a Root and
Intermediates as specified in the platform configuration file.`,
	Run: func(cmd *cobra.Command, args []string) {

		App.Init(InitParams)

		soPIN, userPIN, err := App.ParsePINs(InitParams.SOPin, InitParams.Pin)
		if err != nil {
			App.Logger.Fatal(err)
		}

		App.InitCA(InitParams.PlatformCA, soPIN, userPIN)

		color.New(color.FgGreen).Printf(
			"Certificate Authority successfully initialized")
	},
}
