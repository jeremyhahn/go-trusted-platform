package ca

import (
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/spf13/cobra"
)

var UninstallCmd = &cobra.Command{
	Use:   "uninstall-ca-certificates",
	Short: "Uninstalls the Certificate Authority Certificates",
	Long: `Deletes the Root and Intermediate Certificate Authority certificates
from the operating system trusted certificate store.`,
	Run: func(cmd *cobra.Command, args []string) {

		App.Init(InitParams)

		rootCA, intermediateCA, err := ca.NewCA(CAParams)
		if err != nil {
			App.Logger.Fatal(err)
		}
		if err := rootCA.TrustStore().Uninstall(
			App.CAConfig.Identity[0].Subject.CommonName); err != nil {

			App.Logger.Fatal(err)
		}
		intermediateCN := App.CAConfig.Identity[1].Subject.CommonName
		if err := intermediateCA.TrustStore().Uninstall(intermediateCN); err != nil {
			App.Logger.Fatal(err)
		}
		fmt.Println("CA certificates successfully uninstalled")
	},
}
