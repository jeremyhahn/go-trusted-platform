package cmd

import (
	"github.com/jeremyhahn/go-trusted-platform/attestation/verifier"
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
	Short: "Starts the Attestor as a service",
	Long: `Starts the Attestor service to begin listening for inbound
verification requests from the Verifier to perform Provisioning, Remote
Attestation or quote / Verify operations`,
	Run: func(cmd *cobra.Command, args []string) {
		var caPassword, serverPassword, akPassword []byte
		if CAPassword != "" {
			caPassword = []byte(CAPassword)
		}
		if CAPassword != "" {
			serverPassword = []byte(TLSPassword)
		}
		if VFAKPassword != "" {
			akPassword = []byte(VFAKPassword)
		}
		verifier, err := verifier.NewVerifier(
			App, VFAttestor, caPassword, serverPassword, akPassword)
		if err != nil {
			App.Logger.Fatal(err)
		}
		if err := verifier.Provision(); err != nil {
			App.Logger.Fatal(err)
		}
	},
}
