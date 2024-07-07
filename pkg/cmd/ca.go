package cmd

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/cmd/subcommands"

	"github.com/spf13/cobra"
)

var (
	CAInstallCACert,
	CAUninstallCACert,
	CAList bool
	CAPublicKey,
	CAIssueCertificate,
	CASubjectFile,
	CASansDNS,
	CASansIPs,
	CASansEmails,
	CAShowCert,
	CAParseDER string
)

func init() {

	cobra.OnInitialize(func() {
		subcommands.CASansDNS = CASansDNS
		subcommands.CASansIPs = CASansIPs
		subcommands.CASansEmails = CASansEmails
	})

	caCmd.PersistentFlags().StringVar(&CASansDNS, "sans-dns", "", "Comma separated list of SANS DNS names (ex: domain1.com,domain2.com)")
	caCmd.PersistentFlags().StringVar(&CASansIPs, "sans-ips", "", "Comma separated list of SANS IP Addresses (ex: 1.2.3.4,5.6.7.8)")
	caCmd.PersistentFlags().StringVar(&CASansEmails, "sans-emails", "", "Comma separated list of SANS IP Email addresses (ex: me@domain1.com,me@domain2.com)")

	rootCmd.AddCommand(caCmd)

	caCmd.AddCommand(subcommands.CAInitCmd)
	caCmd.AddCommand(subcommands.CAInstallCmd)
	caCmd.AddCommand(subcommands.CAIssueCmd)
	caCmd.AddCommand(subcommands.CAListCmd)
	caCmd.AddCommand(subcommands.CAParseDERCmd)
	caCmd.AddCommand(subcommands.CAParsePEMCmd)
	caCmd.AddCommand(subcommands.CAPemCmd)
	caCmd.AddCommand(subcommands.CARevokeCmd)
	caCmd.AddCommand(subcommands.CAShowCmd)
	caCmd.AddCommand(subcommands.CAUninstallCmd)
}

var caCmd = &cobra.Command{
	Use:   "ca",
	Short: "Certificate Authority",
	Long: `The Certificate Authority provides Private Key Infrastructure (PKI)
services to the platform. Create, install, issue, and revoke certificates
or secure web services, mTLS, encryption, and perform identity management.`,
	Run: func(cmd *cobra.Command, args []string) {

	},
}
