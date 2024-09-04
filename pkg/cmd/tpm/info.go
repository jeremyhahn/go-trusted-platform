package tpm

import (
	"github.com/spf13/cobra"
)

func init() {

}

var InfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Retrieve TPM 2.0 general information",
	Long:  `Display TPM 2.0 Endorsement Public Key in PEM form`,
	Run: func(cmd *cobra.Command, args []string) {

		App.Init(InitParams)

		if err := App.OpenTPM(); err != nil {
			App.Logger.Warning(err)
		}
		defer func() {
			if err := App.TPM.Close(); err != nil {
				App.Logger.Fatal(err)
			}
		}()

		App.TPM.PrintCapabilities()
	},
}
