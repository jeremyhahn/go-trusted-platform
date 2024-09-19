package tpm

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var EventLogCmd = &cobra.Command{
	Use:   "eventlog",
	Short: "Dumps the local binary_bios_measurements log",
	Long: `Dumps the TPM event log from the local system. Read permissions are
required to the system file. 

TODO: Needs parsing to human-readable format.`,
	Run: func(cmd *cobra.Command, args []string) {
		App, err = App.Init(InitParams)
		if err != nil {
			cmd.PrintErrln(err)
			return
		}
		eventLog, err := App.TPM.EventLog()
		if err != nil {
			color.New(color.FgRed).Println(err)
			return
		}
		fmt.Println(string(eventLog))
	},
}
