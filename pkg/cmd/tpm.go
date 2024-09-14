package cmd

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/cmd/tpm"
	"github.com/spf13/cobra"

	subcmd "github.com/jeremyhahn/go-trusted-platform/pkg/cmd/tpm"
)

func init() {

	tpmCmd.AddCommand(tpm.ClearCmd)
	tpmCmd.AddCommand(tpm.EKCmd)
	tpmCmd.AddCommand(tpm.EventLogCmd)
	tpmCmd.AddCommand(tpm.InfoCmd)
	tpmCmd.AddCommand(tpm.ProvisionCmd)
	tpmCmd.AddCommand(tpm.UnsealCmd)
	tpmCmd.AddCommand(tpm.SealCmd)
	tpmCmd.AddCommand(tpm.SRKCmd)

	rootCmd.AddCommand(tpmCmd)
}

func initTPM() {

	subcmd.App = App
	subcmd.InitParams = InitParams
}

var tpmCmd = &cobra.Command{
	Use:   "tpm",
	Short: "Trusted Platform Module",
	Long: `The Trusted Platform Module (TPM) technology is designed to provide hardware-based,
security-related functions. A TPM chip is a secure crypto-processor that is designed
to carry out cryptographic operations. The chip includes multiple physical security
mechanisms to make it tamper-resistant, and malicious software is unable to tamper
with the security functions of the TPM. Some of the advantages of using TPM technology
are:

* Automatic device onboarding
* Device health attestation
* Device identity for network access control
* Secret (configuration data, IP, and etc) protection
* Secured communication with TLS
* Secured firmware update
* Secured key storage
* Verification of device authenticity
* Licensing

For more information:
https://trustedcomputinggroup.org/about/what-is-a-trusted-platform-module-tpm/
https://link.springer.com/book/10.1007/978-1-4302-6584-9

This command set provides the following capabilities outlined in the TCG
TPM 2.0  Provisioning Guidance:

* Section 8:  Utilities and Capabilities Provided to the Platform Administrator
* Section 10: Platform Manufacturer Provisioning
* Section 11: Platform Administrator Provisioning
https://trustedcomputinggroup.org/wp-content/uploads/TCG-TPM-v2.0-Provisioning-Guidance-Published-v1r1.pdf
`,
	// Run: func(cmd *cobra.Command, args []string) {
	// },
}
