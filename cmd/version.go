package cmd

import (
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/app"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(versionCmd)
}

var versionCmd = &cobra.Command{
	Use:   "version",
	Short: "Prints the software version",
	Long:  `Displays software build and version details`,
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Printf("Name:\t\t\t%s\n", app.Name)
		fmt.Printf("Version:\t\t%s\n", app.Version)
		fmt.Printf("Repository:\t\t%s\n", app.Repository)
		fmt.Printf("Package:\t\t%s\n", app.Package)
		fmt.Printf("Git Branch:\t\t%s\n", app.GitBranch)
		fmt.Printf("Git Tag:\t\t%s\n", app.GitTag)
		fmt.Printf("Git Hash:\t\t%s\n", app.GitHash)
		fmt.Printf("Build User:\t\t%s\n", app.BuildUser)
		fmt.Printf("Build Date:\t\t%s\n", app.BuildDate)
	},
}
