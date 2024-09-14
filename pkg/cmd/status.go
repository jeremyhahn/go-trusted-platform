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

		info, err := App.TPM.Info()
		if err != nil {
			cmd.PrintErrln(err)
			return
		}

		fmt.Println(info)

		fmt.Println("Endorsement Key (EK)")
		ekAttrs, _ := App.TPM.EKAttributes()
		cmd.Println(ekAttrs.String())
		cmd.Println(keystore.PublicKeyToString(ekAttrs))

		fmt.Println("EK Certificate (EK Credential Profile)")
		ekCert, _ := App.TPM.EKCertificate()
		cmd.Println(certstore.ToString(ekCert))

		fmt.Println("Shared Storage Root Key (SSRK)")
		ssrkAttrs, _ := App.TPM.SSRKAttributes()
		cmd.Println(ssrkAttrs.String())
		cmd.Println(keystore.PublicKeyToString(ssrkAttrs))

		fmt.Println("Initial Attestation Key (IAK)")
		iakAttrs, _ := App.TPM.IAKAttributes()
		cmd.Println(iakAttrs.String())
		cmd.Println(keystore.PublicKeyToString(iakAttrs))

		fmt.Println("Initial Device ID (IDevID)")
		idevidAttrs, _ := App.TPM.IDevIDAttributes()
		cmd.Println(idevidAttrs.String())
		cmd.Println(keystore.PublicKeyToString(idevidAttrs))
	},
}
