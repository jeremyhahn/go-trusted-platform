package subcommands

import (
	"github.com/spf13/cobra"
)

var CAInitCmd = &cobra.Command{
	Use:   "init",
	Short: "Initialize the Certificate Authority",
	Long: `Initializes the Certificate Authority by creating a Root and
Intermediate CA with a password protected private key. `,
	Run: func(cmd *cobra.Command, args []string) {

		App.Logger.Info("CA successfully initialized")
	},
}
