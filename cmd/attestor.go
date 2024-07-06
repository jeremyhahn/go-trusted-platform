package cmd

import (
	"github.com/jeremyhahn/go-trusted-platform/attestation/attestor"
	"github.com/spf13/cobra"
)

var (
	ATTListenAddress string
)

func init() {

	attestorCmd.PersistentFlags().StringVar(&ATTListenAddress, "listen", "", "The IP address or hostname to listen on for incoming verifier requests")

	rootCmd.AddCommand(attestorCmd)
}

var attestorCmd = &cobra.Command{
	Use:   "attestor",
	Short: "Starts the Attestor as a service",
	Long: `Starts the Attestor service to bebin listening for inbound
verification requests from the Verifier to begin Full Remote Attestation`,
	Run: func(cmd *cobra.Command, args []string) {

		_, err := attestor.NewAttestor(
			App,
			ATTListenAddress,
			[]byte(CAPassword),
			[]byte(ServerPassword),
			[]byte(SRKAuth))

		if err != nil {
			App.Logger.Fatal(err)
		}

		// Run forever
	},
}
