package ca

import (
	"github.com/spf13/cobra"
)

var UninstallCmd = &cobra.Command{
	Use:   "uninstall-ca-certificates",
	Short: "Uninstalls the Certificate Authority Certificates",
	Long: `Deletes the Root and Intermediate Certificate Authority certificates
from the operating system trusted certificate store.`,
	Run: func(cmd *cobra.Command, args []string) {

		App, err = App.Init(InitParams)
		if err != nil {
			cmd.PrintErrln(err)
			return
		}

		if App.CA == nil {
			soPIN, userPIN, err := App.ParsePINs(InitParams.SOPin, InitParams.Pin)
			if err != nil {
				App.Logger.Error(err)
				cmd.PrintErrln(err)
				return
			}
			if err := App.LoadCA(soPIN, userPIN); err != nil {
				cmd.PrintErrln(err)
				return
			}
		}

		intermediateCN := App.CA.Identity().Subject.CommonName
		if err := App.CA.OSTrustStore().Uninstall(intermediateCN); err != nil {
			cmd.PrintErrln(err)
		}

		cmd.Println("CA certificates successfully uninstalled")
	},
}
