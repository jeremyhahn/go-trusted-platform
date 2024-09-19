package ca

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/prompt"
	"github.com/spf13/cobra"
)

var InstallCmd = &cobra.Command{
	Use:   "install-ca-certificates",
	Short: "Install Certificate Authority Certificates",
	Long: `Installs the Root and Intermediate Certificate Authority certificates
to the operating system trusted certificate store.`,
	Run: func(cmd *cobra.Command, args []string) {

		prompt.PrintBanner(app.Version)

		App, err = App.Init(InitParams)
		if err != nil {
			cmd.PrintErrln(err)
			return
		}

		intermediateCN := App.CA.Identity().Subject.CommonName
		if err := App.CA.OSTrustStore().Install(intermediateCN); err != nil {
			cmd.PrintErrln(err)
		}

		cmd.Println("CA certificates successfully installed")
	},
}
