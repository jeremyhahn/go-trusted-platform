package cmd

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verifier"
	"github.com/spf13/cobra"
)

var VFAttestor string
var VFAKPassword string

func init() {

	verifierCmd.PersistentFlags().StringVarP(&VFAttestor, "attestor", "a", "localhost", "The hostname, DNS name, or IP of the attestor to verify")
	verifierCmd.PersistentFlags().StringVar(&VFAKPassword, "ak-password", "", "The host or dns name of the attestor to verify")

	rootCmd.AddCommand(verifierCmd)
}

var verifierCmd = &cobra.Command{
	Use:   "verifier",
	Short: "Starts the Verifier as a client",
	Long:  `Performs Remote Attestation with the specified Attestor`,
	Run: func(cmd *cobra.Command, args []string) {
		var caPassword, serverPassword, akPassword []byte
		if CAPassword != "" {
			caPassword = []byte(CAPassword)
		}
		if ServerPassword != "" {
			serverPassword = []byte(ServerPassword)
		}
		if VFAKPassword != "" {
			akPassword = []byte(VFAKPassword)
		}
		verifier, err := verifier.NewVerifier(
			App, VFAttestor, caPassword, serverPassword, akPassword)
		if err != nil {
			App.Logger.Fatal(err)
		}
		if err := verifier.Attest(); err != nil {
			App.Logger.Fatal(err)
		}
	},
}
