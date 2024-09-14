package ca

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/prompt"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/spf13/cobra"
)

var InfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Display information about a Certificate Authority",
	Long: `Displays key store, certificate store, and general information
about a Certificate Authority.`,
	Run: func(cmd *cobra.Command, args []string) {

		prompt.PrintBanner(app.Version)

		App.Init(InitParams)

		if len(App.CAConfig.Identity) == 0 {
			App.Logger.Fatal("No Certificate Authorities configured")
		}

		initialized, err := App.CA.IsInitialized()
		if err != nil {
			cmd.PrintErrln(err)
			return
		}

		cmd.Printf("Initialized: %t:\n", initialized)

		identity := App.CAConfig.Identity[App.CAConfig.PlatformCA]

		// Iterate over the configured keys
		for _, keyConfig := range identity.Keys {

			// Parse the store type and key algorithm
			storeType, err := keystore.ParseStoreType(keyConfig.StoreType)
			if err != nil {
				cmd.PrintErrln(err)
				return
			}
			keyAlgorithm, err := keystore.ParseKeyAlgorithm(keyConfig.KeyAlgorithm)
			if err != nil {
				cmd.PrintErrln(err)
				return
			}
			// Get the loaded key attributes
			attrs, err := App.CA.CAKeyAttributes(storeType, keyAlgorithm)
			if err != nil {
				cmd.PrintErrln(err)
				return
			}
			cmd.Println(attrs)
		}

	},
}
