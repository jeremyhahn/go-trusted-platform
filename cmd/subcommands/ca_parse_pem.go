package subcommands

import (
	"crypto/x509"
	"os"

	"github.com/spf13/cobra"
)

func init() {
	CAParsePEMCmd.PersistentFlags().StringVarP(&CAFile, "file", "f", "", "The path to the certificate")
}

var CAParsePEMCmd = &cobra.Command{
	Use:   "parse-pem",
	Short: "Parses a PEM encoded x509 certificate",
	Long:  `Parses the specified PEM encoded x509 certificate and dumps it to STDOUT`,
	Run: func(cmd *cobra.Command, args []string) {
		bytes, err := os.ReadFile(CAFile)
		if err != nil {
			App.Logger.Fatal(err)
		}
		cert, err := x509.ParseCertificate(bytes)
		if err != nil {
			App.Logger.Fatal(err)
		}
		App.Logger.Infof("%+v", cert)
	},
}
