package cmd

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/cmd/subcommands"
	"github.com/spf13/cobra"
)

var TPMImportEkCert string
var TPMFormDER bool
var TPMVerify bool
var TPMEventLog bool
var EKCertName string

func init() {

	rootCmd.AddCommand(tpmCmd)

	tpmCmd.AddCommand(subcommands.TPMEventLogEKCmd)
	tpmCmd.AddCommand(subcommands.TPMImportEKCmd)
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
		   `,
	Run: func(cmd *cobra.Command, args []string) {

		App.InitCA()
	},
}
