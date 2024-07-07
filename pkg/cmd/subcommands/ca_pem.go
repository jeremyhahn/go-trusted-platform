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
		bytes, err := App.CA.PEM(CAFile)
		if err != nil {
			App.Logger.Fatal(err)
		}
		App.Logger.Info(string(bytes))
	},
}
