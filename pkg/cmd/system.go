package cmd

import (
	"github.com/fatih/color"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/system"
	"github.com/spf13/cobra"
)

func init() {

	rootCmd.AddCommand(systemInfoCmd)
}

var systemInfoCmd = &cobra.Command{
	Use:   "info",
	Short: "Displays system information",
	Long:  `Displays information about the platform hardware`,
	Run: func(cmd *cobra.Command, args []string) {
		if err := system.PrintSystemInfo(); err != nil {
			color.New(color.FgRed).Println(err)
			return
		}
	},
}
