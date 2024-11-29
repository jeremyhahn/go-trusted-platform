package cmd

import (
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(dnsCmd)
}

var dnsCmd = &cobra.Command{
	Use:   "dns",
	Short: "DNS server",
	Long:  `Performs Domain Name Service operations`,
	Run: func(cmd *cobra.Command, args []string) {
	},
}
