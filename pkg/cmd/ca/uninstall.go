package ca

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
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

		userPIN := keystore.NewClearPassword(InitParams.Pin)
		if err := App.LoadCA(userPIN); err != nil {
			cmd.PrintErrln(err)
			return
		}

		intermediateCN := App.CA.Identity().Subject.CommonName
		if err := App.CA.OSTrustStore().Uninstall(intermediateCN); err != nil {
			cmd.PrintErrln(err)
		}

		cmd.Println("CA certificates successfully uninstalled")
	},
}
