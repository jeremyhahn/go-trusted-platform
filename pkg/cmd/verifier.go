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

		// Initialize CA and TPM
		App.InitCA()

		// Create new verifier
		verifier, err := verifier.NewVerifier(
			App, VFAttestor,
			[]byte(InitParams.CAPassword),
			[]byte(InitParams.ServerPassword),
			[]byte(VFAKPassword))
		if err != nil {
			App.Logger.Fatal(err)
		}

		// Perform remote attestation
		if err := verifier.Attest(); err != nil {
			App.Logger.Fatal(err)
		}
	},
}
