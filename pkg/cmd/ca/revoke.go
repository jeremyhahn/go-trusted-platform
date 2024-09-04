package ca

import (
	"github.com/fatih/color"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/spf13/cobra"
)

func init() {
	RevokeCmd.PersistentFlags().StringVar(&CN, "cn", "", "The common name of the certificate to revoke")
	RevokeCmd.PersistentFlags().StringVarP(&Algorithm, "algorithm", "a", "", "Optional key algorithm. [ RSA | ECDSA | Ed35519 ]")
}

var RevokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "Revokes an issued certificate",
	Long: `Add the certificate to the CA Certificate Revocation List and delete
the certificate and any keys from the stores.`,
	Run: func(cmd *cobra.Command, args []string) {

		App.Init(InitParams)

		algo, err := keystore.ParseKeyAlgorithm(Algorithm)
		if err != nil {
			App.Logger.Fatal(err)
		}

		keyAttrs, err := keystore.Template(algo)
		if err != nil {
			App.Logger.Fatal(err)
		}

		certificate, err := App.CA.Certificate(keyAttrs)
		if err != nil {
			App.Logger.Fatal(err)
		}

		err = App.CA.Revoke(certificate)
		if err != nil {
			App.Logger.Fatal(err)
		}

		color.New(color.FgGreen).Printf("Successfully revoked certificate")
	},
}
