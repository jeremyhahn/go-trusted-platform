package tpm

import (
	"github.com/fatih/color"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tpm2"
	"github.com/spf13/cobra"
)

var (
	tpmEventLogPath string
)

func init() {
	EventLogCmd.PersistentFlags().StringVar(&tpmEventLogPath, "path", "/sys/kernel/security/tpm0/binary_bios_measurements", "The path to the system measurement log")
}

var EventLogCmd = &cobra.Command{
	Use:   "eventlog",
	Short: "Dumps the local binary_bios_measurements log",
	Long: `Dumps the TPM system measurement log. Read permissions are required to the
measurement file (/sys/kernel/security/tpm0/binary_bios_measurements).`,
	Run: func(cmd *cobra.Command, args []string) {
		events, err := tpm2.ParseEventLog(tpmEventLogPath)
		if err != nil {
			color.New(color.FgRed).Println(err)
			return
		}
		tpm2.PrintEvents(events)
	},
}
