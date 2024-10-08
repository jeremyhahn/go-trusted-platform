package cmd

import (
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	subcmd "github.com/jeremyhahn/go-trusted-platform/pkg/cmd/ca"
)

func init() {

	// CA options
	caCmd.PersistentFlags().StringVar(&subcmd.SansDNS, "sans-dns", "", "Comma separated list of SANS DNS names (ex: domain1.com,domain2.com)")
	caCmd.PersistentFlags().StringVar(&subcmd.SansIPs, "sans-ips", "", "Comma separated list of SANS IP Addresses (ex: 1.2.3.4,5.6.7.8)")
	caCmd.PersistentFlags().StringVar(&subcmd.SansEmails, "sans-emails", "", "Comma separated list of SANS IP Email addresses (ex: me@domain1.com,me@domain2.com)")

	// Add CA subcommands
	caCmd.AddCommand(subcmd.CertificateCmd)
	caCmd.AddCommand(subcmd.InfoCmd)
	caCmd.AddCommand(subcmd.InitCmd)
	caCmd.AddCommand(subcmd.InstallCmd)
	caCmd.AddCommand(subcmd.IssueCmd)
	caCmd.AddCommand(subcmd.RevokeCmd)
	caCmd.AddCommand(subcmd.UninstallCmd)

	// Add CA commands to root
	rootCmd.AddCommand(caCmd)
}

func initCA() {

	if App.CAConfig != nil {
		// Certificate Authority initialization parameters.
		// These are the shared params between all CA's.
		CAParams = &ca.CAParams{
			Debug:        App.DebugFlag,
			DebugSecrets: App.DebugSecretsFlag,
			Logger:       App.Logger,
			Config:       *App.CAConfig,
			Fs:           App.FS,
			SelectedCA:   InitParams.PlatformCA,
			Random:       App.Random,
			BlobStore:    App.BlobStore,
			SignerStore:  App.SignerStore,
			TPM:          App.TPM,
		}
	}

	// Init CA sub command variables
	subcmd.App = App
	subcmd.InitParams = InitParams
	subcmd.CAParams = CAParams
}

var caCmd = &cobra.Command{
	Use:   "ca",
	Short: "Certificate Authority",
	Long: `The Certificate Authority provides Public Key Infrastructure (PKI)
services to the platform. Create, install, issue, and revoke certificates, 
secure web services, mTLS, encryption, perform identity management, remote
attestation and more, build trusts with with other Certificate Authorities
and more..`,
	// Run: func(cmd *cobra.Command, args []string) {
	// },
}
