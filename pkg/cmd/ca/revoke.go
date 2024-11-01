package ca

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/spf13/cobra"
)

var (
	revokeDeleteKeys bool
)

func init() {
	CertificateCmd.PersistentFlags().BoolVar(&revokeDeleteKeys, "delete-keys", true, "True to delete associated key pair")
}

var RevokeCmd = &cobra.Command{
	Use:   "revoke [cn] [store] [algorithm]",
	Short: "Revokes an issued certificate",
	Long: `Add the certificate to the CA Certificate Revocation List and delete
the certificate and any keys from the stores.`,
	Args: cobra.MinimumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {

		App, err = App.Init(InitParams)
		if err != nil {
			cmd.PrintErrln(err)
			return
		}

		userPIN := keystore.NewClearPassword(InitParams.Pin)
		if err := App.LoadCA(userPIN); err != nil {
			cmd.PrintErrln(err)
			return
		}

		cn := args[0]
		store := args[1]
		algorithm := args[2]

		storeType, err := keystore.ParseStoreType(store)
		if err != nil {
			cmd.PrintErrln(err)
			return
		}

		keyAlgo, err := keystore.ParseKeyAlgorithm(algorithm)
		if err != nil {
			cmd.PrintErrln(err)
			return
		}

		keyAttrs, err := keystore.Template(keyAlgo)
		if err != nil {
			cmd.PrintErrln(err)
			return
		}
		keyAttrs.CN = cn
		keyAttrs.KeyAlgorithm = keyAlgo
		keyAttrs.StoreType = storeType

		certificate, err := App.CA.Certificate(keyAttrs)
		if err != nil {
			cmd.PrintErrln(err)
			return
		}

		err = App.CA.Revoke(certificate, revokeDeleteKeys)
		if err != nil {
			cmd.PrintErrln(err)
			return
		}

	},
}
