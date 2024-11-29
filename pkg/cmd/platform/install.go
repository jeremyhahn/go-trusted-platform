package platform

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/certstore"
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

		var soPIN, userPIN keystore.Password
		if App.CA == nil {
			soPIN, userPIN, err = App.ParsePINs(InitParams.SOPin, InitParams.Pin)
			if err != nil {
				App.Logger.Error(err)
				cmd.PrintErrln(err)
				return
			}
		}

		App.OpenTPM(false)

		if err := App.TPM.Install(soPIN); err != nil {

			if err == tpm2.ErrEndorsementCertNotFound {

				if App.CA == nil {
					if _, err := App.InitCA(soPIN, userPIN, InitParams); err != nil {
						cmd.PrintErrln(err)
						return
					}
				}

				cert, err := App.ImportEndorsementKeyCertificate()
				if err != nil {
					cmd.PrintErrln(err)
					return
				}

				pem, err := certstore.EncodePEM(cert.Raw)
				if err != nil {
					cmd.PrintErrln(err)
					return
				}

				cmd.Println(string(pem))

			} else {

				cmd.PrintErrln(err)
				return
			}
		}
	},
}
