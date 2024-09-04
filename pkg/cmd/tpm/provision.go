package tpm

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
)

var (
	hierarchyAuth string
)

var ProvisionCmd = &cobra.Command{
	Use:   "provision",
	Short: "Provision Trusted Platform Module",
	Long: `Provisions a Trusted Platform Module in alignment with the TCG
provisioning guidance.`,
	Run: func(cmd *cobra.Command, args []string) {

		InitParams.Initialize = true
		App.Init(InitParams)

		App.InitTPM(InitParams.PlatformCA, InitParams.SOPin, InitParams.Pin)

		ekAttrs, err := App.TPM.EKAttributes()
		if err != nil {
			App.Logger.Fatal(err)
		}
		keystore.PrintKeyAttributes(ekAttrs)

		ssrkAttrs, err := App.TPM.SSRKAttributes()
		if err != nil {
			App.Logger.Fatal(err)
		}
		keystore.PrintKeyAttributes(ssrkAttrs)

		iakAttrs, err := App.TPM.IAKAttributes()
		if err != nil {
			App.Logger.Fatal(err)
		}
		keystore.PrintKeyAttributes(iakAttrs)
	},
}
