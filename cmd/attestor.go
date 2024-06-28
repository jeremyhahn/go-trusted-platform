package cmd

import (
	"github.com/jeremyhahn/go-trusted-platform/attestation/attestor"
	"github.com/spf13/cobra"
)

var (
	ATTPassword string
)

func init() {

	// attestorCmd.PersistentFlags().StringVarP(&ATTPassword, "password", "a", "", "Storage Root Key (SRK) authentication password")

	rootCmd.AddCommand(attestorCmd)
}

var attestorCmd = &cobra.Command{
	Use:   "attestor",
	Short: "Starts the Attestor as a service",
	Long: `Starts the Attestor service to bebin listening for inbound
verification requests from the Verifier to begin Full Remote Attestation`,
	Run: func(cmd *cobra.Command, args []string) {
		srkAuth := App.AttestationConfig.SRKAuth
		if ATTPassword != "" {
			// Override config with CLI argument if specified
			srkAuth = ATTPassword
		}
		if _, err := attestor.NewAttestor(App, []byte(srkAuth)); err != nil {
			App.Logger.Fatal(err)
		}
		// Run forever
	},
}
