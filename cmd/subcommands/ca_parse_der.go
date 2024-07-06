package subcommands

import (
	"os"

	"github.com/spf13/cobra"
)

func init() {
	CAParseDERCmd.PersistentFlags().StringVarP(&CAFile, "file", "f", "", "The path to the certificate")
}

var CAParseDERCmd = &cobra.Command{
	Use:   "parse-der",
	Short: "Parses a PEM encoded x509 certificate",
	Long:  `Parses the specified PEM encoded x509 certificate and dumps it to STDOUT`,
	Run: func(cmd *cobra.Command, args []string) {
		bytes, err := os.ReadFile(CAFile)
		if err != nil {
			App.Logger.Fatal(err)
		}
		cert, err := App.CA.DecodePEM(bytes)
		if err != nil {
			App.Logger.Fatal(err)
		}
		App.Logger.Infof("%+v", cert)
	},
}
