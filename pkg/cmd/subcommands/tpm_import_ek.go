package subcommands

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/spf13/cobra"
)

func init() {
	cobra.OnInitialize(func() {
		TPMImportEKCmd.PersistentFlags().StringVarP(&InitParams.EKCert, "file", "f", "", "The path to a TPM Endorsement Key certificate to import into the Certificate Authority")
		TPMImportEKCmd.PersistentFlags().StringVarP(&InitParams.SRKAuth, "srk-auth", "a", "", "The TPM Storage Root Key authorization password")
	})
}

var TPMImportEKCmd = &cobra.Command{
	Use:   "import-ek",
	Short: "Imports a local TPM Endorsement Key and x509 certificate",
	Long: `Signs and stores a TPM Endorsement key and x509 certificate
to the Certificate Authority signed blob store. `,
	Run: func(cmd *cobra.Command, args []string) {
		// The platform automatically imports the EK during
		// initialization, which happens in the root command
		// during cobra.OnInitialize.
		//
		// App.Init has already completed platform initialization
		// before this function gets invoked.
		//
		// This method is intended to update the Endorsement Key on
		// an existing platform, for example, migrating the Certificate
		// Authority to a new host with a different TPM, using retained
		// data that already has the previous EK installed.

		if err := App.OpenTPM(); err != nil {
			App.Logger.Fatal(err)
		}
		defer func() {
			if err := App.TPM.Close(); err != nil {
				App.Logger.Fatal(err)
			}
		}()

		attrs := App.CA.CAKeyAttributes(nil)

		// Import the cert
		cert, err := App.TPM.EKCert(attrs)
		if err != nil {
			App.Logger.Fatal(err)
		}
		// Encode to PEM and print to the console
		ekPEM, err := ca.EncodePEM(cert.Raw)
		App.Logger.Info("Successfully imported Endorsement Public Key and Certificate")
		App.Logger.Infof("PEM:\n%s", string(ekPEM))
	},
}
