package platform

import (
	"github.com/fatih/color"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"
	"github.com/spf13/cobra"
)

var InstallCmd = &cobra.Command{
	Use:   "install",
	Short: "Safely provisions the platform",
	Long: `Perform a modified version of the TCG recommended provisioning 
guidance procedure, intended for platforms with a pre-provisioned TPM, either
from the TPM Manufacturer or Owner. Instead of clearing the hierarchies, 
setting hierarchy authorizations and provisioning new keys and certificates
from scratch, this operation will use pre-existing EK, Shared SRK and IAK keys
and certificates if they already exist. The Security Officer PIN is required
and used as Endorsement and Storage hierarchy authorization values during
installation. This operation is safe and idempotent, and will not modify or
destroy existing data.`,
	Run: func(cmd *cobra.Command, args []string) {

		InitParams.Initialize = true
		App.Init(InitParams)

		sopin := keystore.NewClearPassword(InitParams.SOPin)
		pin := keystore.NewClearPassword(InitParams.Pin)

		// Open a connection to the TPM
		if err := App.OpenTPM(); err != nil {
			if err != tpm2.ErrNotInitialized {
				App.Logger.Fatal(err)
			}
		}

		if App.DebugSecretsFlag {
			App.Logger.Debugf(
				"Setting Security Officer / hierarchy authorization PIN: %s",
				InitParams.SOPin)

			App.Logger.Debugf("Setting user PIN: %s", InitParams.Pin)
		}

		// Perform platform installation
		if err := App.TPM.Install(sopin); err != nil {

			if err == tpm2.ErrEndorsementCertNotFound {

				if App.CA == nil {
					// TODO: Perform ACME device enrollment instead of
					// self-signed CA cert with tpm2-software attestation
					// procedure.
					App.InitCA(InitParams.PlatformCA, sopin, pin)
				}

				// Create missing EK cert
				App.ImportEndorsementKey()
			} else {
				App.Logger.Fatal(err)
			}
		}

		color.New(color.FgGreen).Printf("Platform installed successfully")
	},
}
