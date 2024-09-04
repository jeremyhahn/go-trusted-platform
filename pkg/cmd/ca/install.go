package ca

import (
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/spf13/cobra"
)

var InstallCmd = &cobra.Command{
	Use:   "install-ca-certificates",
	Short: "Install Certificate Authority Certificates",
	Long: `Installs the Root and Intermediate Certificate Authority certificates
to the operating system trusted certificate store.`,
	Run: func(cmd *cobra.Command, args []string) {

		App.Init(InitParams)

		rootCA, intermediateCA, err := ca.NewCA(CAParams)
		if err != nil {
			App.Logger.Fatal(err)
		}

		if err := rootCA.TrustStore().Install(
			App.CAConfig.Identity[0].Subject.CommonName); err != nil {

			App.Logger.Fatal(err)
		}

		intermediateCN := App.CAConfig.Identity[CAParams.SelectedCA].Subject.CommonName
		if err := intermediateCA.TrustStore().Install(intermediateCN); err != nil {
			App.Logger.Fatal(err)
		}

		fmt.Println("CA certificates successfully installed")
	},
}
