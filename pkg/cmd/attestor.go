package cmd

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/attestor"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/spf13/cobra"
)

var (
	ATTListenAddress string
)

func init() {

	attestorCmd.PersistentFlags().StringVarP(&ATTListenAddress, "listen", "l", "localhost", "The IP address or hostname to listen on for incoming verifier requests")

	rootCmd.AddCommand(attestorCmd)
}

var attestorCmd = &cobra.Command{
	Use:   "attestor",
	Short: "Starts the Attestor gRPC service",
	Long: `Starts the Attestor service to begin listening for inbound
verification requests from the Verifier to begin Remote Attestation`,
	Run: func(cmd *cobra.Command, args []string) {

		App.Init(InitParams)

		sopin := keystore.NewClearPassword(InitParams.SOPin)
		pin := keystore.NewClearPassword(InitParams.Pin)

		if App.CA == nil {
			App.InitCA(InitParams.PlatformCA, sopin, pin)
		}

		_, err := attestor.NewAttestor(App)
		if err != nil {
			App.Logger.Fatal(err)
		}

		// Run forever
	},
}
