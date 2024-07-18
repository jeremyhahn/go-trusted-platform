package subcommands

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/spf13/cobra"
)

func init() {
	CARevokeCmd.PersistentFlags().StringVar(&CACN, "cn", "", "The common name of the certificate to revoke")
	CARevokeCmd.PersistentFlags().StringVarP(&CAAlgorithm, "algorithm", "a", "", "Optional key algorithm. [ RSA | ECDSA | Ed35519 ]")
}

var CARevokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "Revokes an issued certificate",
	Long: `Add the certificate to the CA Certificate Revocation List and optionally
delete the certificates.`,
	Run: func(cmd *cobra.Command, args []string) {

		algo, err := keystore.ParseKeyAlgorithm(CAAlgorithm)
		if err != nil {
			App.Logger.Fatal(err)
		}

		attrs, err := keystore.Template(algo)
		if err != nil {
			App.Logger.Fatal(err)
		}
		attrs.Domain = CACN
		attrs.CN = CAKeyName

		err = App.CA.Revoke(attrs)
		if err != nil {
			App.Logger.Fatal(err)
		}
		App.Logger.Info("Successfully revoked certificate")
	},
}
