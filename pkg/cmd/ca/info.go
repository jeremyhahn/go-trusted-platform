package ca

import (
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/spf13/cobra"
)

var InfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Display information about a Certificate Authority",
	Long: `Displays key store, certificate store, and general information
about a Certificate Authority.`,
	Run: func(cmd *cobra.Command, args []string) {

		App.Init(InitParams)

		if len(App.CAConfig.Identity) == 0 {
			App.Logger.Fatal("No Certificate Authorities configured")
		}

		for _, identity := range App.CAConfig.Identity {

			for _, keyConfig := range identity.Keys {

				fmt.Printf("---- %s ----\n",
					identity.Subject.CommonName)

				attrs, err := keystore.KeyAttributesFromConfig(keyConfig)
				if err != nil {
					App.Logger.Fatal(err)
				}

				keystore.PrintKeyAttributes(attrs)
				fmt.Println()
			}
		}
	},
}
