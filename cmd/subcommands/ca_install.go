package subcommands

import (
	"github.com/jeremyhahn/go-trusted-platform/ca"
	"github.com/spf13/cobra"
)

var CAInstallCmd = &cobra.Command{
	Use:   "install-ca-certificates",
	Short: "Install Certificate Authority Certificates",
	Long: `Installs the Root and Intermediate Certificate Authority certificates
to the operating system trusted certificate store.`,
	Run: func(cmd *cobra.Command, args []string) {
		rootCA, intermediateCA, err := ca.NewCA(CAParams)
		if err != nil {
			App.Logger.Fatal(err)
		}
		if err := rootCA.TrustStore().Install(
			App.CAConfig.Identity[0].Subject.CommonName); err != nil {

			App.Logger.Fatal(err)
		}
		intermediateCN := App.CAConfig.Identity[1].Subject.CommonName
		if err := intermediateCA.TrustStore().Install(intermediateCN); err != nil {
			App.Logger.Fatal(err)
		}
		App.Logger.Info("CA certificates successfully installed")
	},
}
