package tpm

import (
	"github.com/spf13/cobra"
)

var InfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Retrieve TPM 2.0 general information",
	Long:  `Display TPM 2.0 Endorsement Public Key in PEM form`,
	Run: func(cmd *cobra.Command, args []string) {

		App, err = App.Init(InitParams)
		if err != nil {
			cmd.PrintErrln(err)
			return
		}

		info, err := App.TPM.Info()
		if err != nil {
			cmd.PrintErrln(err)
			return
		}
		cmd.Println(info)
	},
}
