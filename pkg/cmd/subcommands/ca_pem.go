package subcommands

import (
	"github.com/spf13/cobra"
)

func init() {
	CAPemCmd.PersistentFlags().StringVarP(&CAFile, "pem", "p", "", "The common name of the PEM certificate to retrieve")
}

var CAPemCmd = &cobra.Command{
	Use:   "pem",
	Short: "Retrieve a PEM certificate",
	Long: `This command retrieves a PEM certificate from the Certificate
Authority certificate store`,
	Run: func(cmd *cobra.Command, args []string) {

		for algo, attrs := range App.CA.CAKeyAttributesList() {

			App.Logger.Infof("$s Key Attributes", algo)

			caAttrs := App.CA.CAKeyAttributes(&attrs.KeyAlgorithm)

			bytes, err := App.CA.PEM(caAttrs)
			if err != nil {
				App.Logger.Fatal(err)
			}

			App.Logger.Info(string(bytes))
		}
	},
}
