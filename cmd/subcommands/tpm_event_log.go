package subcommands

import (
	"github.com/spf13/cobra"
)

var TPMEventLogEKCmd = &cobra.Command{
	Use:   "eventlog",
	Short: "Dumps the local binary_bios_measurements log",
	Long: `Dumps the TPM event log from the local system. Read permissions are
required to the system file. 

TODO: Needs parsing to human-readable format.`,
	Run: func(cmd *cobra.Command, args []string) {
		eventLog, err := App.TPM.EventLog()
		if err != nil {
			App.Logger.Fatalf("error parsing event log: %s", err)
		}
		App.Logger.Infof("%s", string(eventLog))
	},
}
