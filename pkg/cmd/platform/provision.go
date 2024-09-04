package platform

import (
	"log"

	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/auth"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/spf13/cobra"
)

var (
	initTPM      bool
	yubiClientID string
)

func init() {

	ProvisionCmd.PersistentFlags().StringVar(&yubiClientID, "yubi-client-id", "", "Yubico YubiKey OTP Client ID. Get one here: https://upgrade.yubico.com/getapikey/")
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
		InitParams.Initialize = true
		App.Init(InitParams)
		App.InitTPM(InitParams.PlatformCA, InitParams.SOPin, InitParams.Pin)
	},
}

func ykauth() {
	ykauth, err := auth.NewYubiKeyAuthenticator(
		util.Logger(),
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
