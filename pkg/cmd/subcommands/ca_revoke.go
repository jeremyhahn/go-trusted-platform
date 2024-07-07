package subcommands

import (
	"github.com/spf13/cobra"
)

func init() {
	CARevokeCmd.PersistentFlags().StringVar(&CACertCN, "cn", "", "The common name of the certificate to revoke")
}

var CARevokeCmd = &cobra.Command{
	Use:   "revoke",
	Short: "Revokes an issued certificate",
	Long: `Add the certificate to the CA Certificate Revocation List and optionally
delete the certificates.`,
	Run: func(cmd *cobra.Command, args []string) {
		err := App.CA.Revoke(CACertCN, App.CAPasswordPrompt())
		if err != nil {
			App.Logger.Fatal(err)
		}
		App.Logger.Info("Successfully revoked certificate")
	},
}
