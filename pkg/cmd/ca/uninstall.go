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

		App.Init(InitParams)

		intermediateCN := App.CA.Identity().Subject.CommonName
		if err := App.CA.OSTrustStore().Uninstall(intermediateCN); err != nil {
			cmd.PrintErrln(err)
		}

		cmd.Println("CA certificates successfully uninstalled")
	},
}
