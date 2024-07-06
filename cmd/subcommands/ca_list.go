package subcommands

import (
	"github.com/spf13/cobra"
)

var CAListCmd = &cobra.Command{
	Use:   "list",
	Short: "Lists issued certificates",
	Long: `This command lists all of the certificates in the Certificate
Authority certificate store.`,
	Run: func(cmd *cobra.Command, args []string) {
		certs, err := App.CA.IssuedCertificates()
		if err != nil {
			App.Logger.Fatal(err)
		}
		for _, cert := range certs {
			App.Logger.Info(cert)
			App.Logger.Info("")

		}
	},
}
