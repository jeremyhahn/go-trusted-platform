package cmd

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verifier"
	"github.com/spf13/cobra"
)

var VFAttestor string
var VFAKPassword string

func init() {

	verifierCmd.PersistentFlags().StringVarP(&VFAttestor, "attestor", "a", "localhost", "The hostname, DNS name, or IP of the attestor to verify")

	rootCmd.AddCommand(verifierCmd)
}

var verifierCmd = &cobra.Command{
	Use:   "verifier",
	Short: "Starts the Verifier gRPC client",
	Long:  `Performs Remote Attestation with the specified Attestor`,
	Run: func(cmd *cobra.Command, args []string) {

		App, err = App.Init(InitParams)
		if err != nil {
			cmd.PrintErrln(err)
			return
		}

		// Create new verifier
		verifier, err := verifier.NewVerifier(App, VFAttestor)
		if err != nil {
			App.Logger.FatalError(err)
		}

		// Perform remote attestation
		if err := verifier.Attest(); err != nil {
			App.Logger.FatalError(err)
		}
	},
}
