package platform

import (
	"log"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/auth"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/prompt"
	"github.com/spf13/cobra"
)

var (
	initTPM      bool
	yubiClientID string
)

func init() {

	// Options
	ProvisionCmd.PersistentFlags().StringVar(&yubiClientID, "yubi-client-id", "", "Yubico YubiKey OTP Client ID. Get one here: https://upgrade.yubico.com/getapikey/")

	// Flags
	ProvisionCmd.PersistentFlags().BoolVarP(&initTPM, "tpm2", "t", false, "Initialize the Trusted Platform Module 2.0")
}

var ProvisionCmd = &cobra.Command{
	Use:   "provision",
	Short: "Performs initial platform provisioning",
	Long: `Initializes the platform by establishing an initial Security
Officer whose credentials are used to take ownership of the TPM and key stores.
The TPM is provisioned per TCG recommended guidance, with an EK and SRK persisted
to their recommended storage hierarchy handle indexes. Key stores, services and
components referenced in the platform configuration file are initialized.`,
	Run: func(cmd *cobra.Command, args []string) {

		prompt.PrintBanner(app.Version)

		InitParams.Initialize = true

		App, err = App.Init(InitParams)
		if err != nil {
			cmd.PrintErrln(err)
			return
		}

		props, err := App.TPM.FixedProperties()
		if err != nil {
			cmd.PrintErrln(err)
			return
		}

		cmd.Println("TPM Information")
		cmd.Printf("Manufacturer: %s\n", props.Manufacturer)
		cmd.Printf("Vendor ID:    %s\n", props.VendorID)
		cmd.Printf("Family:       %s\n", props.Family)
		cmd.Printf("Revision:     %s\n", props.Revision)
		cmd.Printf("Firmware:     %d.%d\n", props.FwMajor, props.FwMinor)
		cmd.Printf("FIPS 140-2:   %t\n", props.Fips1402)
	},
}

func ykauth() {
	ykauth, err := auth.NewYubiKeyAuthenticator(
		logging.DefaultLogger(),
		yubiClientID,
		nil)
	if err != nil {
		log.Fatal(err)
	}
	otp := ykauth.Prompt()
	if err := ykauth.Authenticate(otp); err != nil {
		log.Fatal(err)
	}
}
