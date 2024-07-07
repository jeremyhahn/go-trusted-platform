package subcommands

import (
	"fmt"
	"os"
	"strings"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

var PFDestroyCmd = &cobra.Command{
	Use:   "destroy",
	Short: "Destroy the Certificate Authority",
	Long: `This command deletes the Certificate Authority and all objects
owned by the CA: certificates, keys, blob storage, etc.`,
	Run: func(cmd *cobra.Command, args []string) {

		fmt.Println("")
		color.Red(
			"Are you sure you want to delete all platform data?\n" +
				"This operation can not be reversed!")
		fmt.Println("")

		answer := App.Prompt("Delete platform data? (y/n)")
		YorN := strings.ToLower(answer)

		if YorN == "y" {
			if err := os.RemoveAll(App.PlatformDir); err != nil {
				App.Logger.Fatal(err)
			}
			App.Logger.Info("Paltform data successfully destroyed")
		}

		fmt.Println("")
		color.Green("Whew, that was close!")
	},
}
