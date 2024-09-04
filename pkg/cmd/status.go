package cmd

import (
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/certstore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/spf13/cobra"
)

func init() {

	rootCmd.AddCommand(statusCmd)
}

var statusCmd = &cobra.Command{
	Use:   "status",
	Short: "Displays the Trusted Platform status",
	Long: `Displays information about the current status of the Trusted Platform
installation, including TPM keys & certificates, Certificate Authority, and
running services.`,
	Run: func(cmd *cobra.Command, args []string) {

		App.Init(InitParams)

		if err := App.OpenTPM(); err != nil {
			App.Logger.Fatal(err)
		}

		App.TPM.PrintCapabilities()

		fmt.Println("Endorsement Key (EK)")
		ekAttrs, _ := App.TPM.EKAttributes()
		keystore.PrintKeyAttributes(ekAttrs)
		fmt.Printf("Public Key: %+v", App.TPM.EK())

		fmt.Println("EK Certificate (EK Credential Profile)")
		ekCert, _ := App.TPM.EKCertificate()
		certstore.PrintCertificate(ekCert)

		fmt.Println()

		fmt.Println("Shared Storage Root Key (SSRK)")
		ssrkAttrs, _ := App.TPM.SSRKAttributes()
		keystore.PrintKeyAttributes(ssrkAttrs)

		fmt.Println()

		fmt.Println("Initial Attestation Key (IAK)")
		iakAttrs, _ := App.TPM.IAKAttributes()
		keystore.PrintKeyAttributes(iakAttrs)
		fmt.Printf("Public Key: %s", App.TPM.IAK())

		fmt.Println()

		fmt.Println("Initial Device ID (IDevID)")
		idevidAttrs, _ := App.TPM.IDevIDAttributes()
		keystore.PrintKeyAttributes(idevidAttrs)
		fmt.Printf("Public Key: %s", App.TPM.IDevID())
	},
}
