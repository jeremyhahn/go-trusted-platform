package platform

import (
	"fmt"
	"strings"

	"github.com/fatih/color"
	"github.com/google/go-tpm/tpm2"
	"github.com/spf13/cobra"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/prompt"
)

var DestroyCmd = &cobra.Command{
	Use:   "destroy",
	Short: "Destroy the platform",
	Long: `This command deletes all platform data, including TPM keys,
Certificate Authority keys, certifiates, secrets, and blob storage.
A TPM2_Clear command is sent to the TPM, restoring it to the TPM
manufacturer and OEM factory settings.`,
	Run: func(cmd *cobra.Command, args []string) {

		prompt.PrintBanner(app.Version)

		App.Init(InitParams)

		fmt.Println("")
		color.Red(
			"Are you sure you want to delete all platform data?\n" +
				"This operation can not be reversed!")
		fmt.Println("")
		fmt.Printf("Platform Data: %s\n", App.PlatformDir)
		fmt.Println("")

		answer := prompt.Prompt("Delete platform data? (y/n)")
		YorN := strings.ToLower(strings.TrimSpace(string(answer)))

		App.Logger.Info(YorN)

		if YorN == "y" {

			lockoutAuth := prompt.PasswordPrompt("Lockout Hierarchy Password")
			endorsementAuth := prompt.PasswordPrompt("Endorsement Hierarchy Password")
			ownerAuth := prompt.PasswordPrompt("Owner Hierarchy Password")

			// Delete platform data directory
			if err := App.FS.RemoveAll(App.PlatformDir); err != nil {
				App.Logger.Error("Failed to delete platform data")
				color.New(color.FgRed).Println(err)
				return
			}
			App.Logger.Info("Platform data successfully destroyed")

			// Clear the TPM
			if App.TPM == nil {
				App.Logger.Fatal("TPM not initialized")
			} else {
				if err := App.TPM.Clear(lockoutAuth, tpm2.TPMRHLockout); err != nil {
					App.Logger.Error("Failed to clear Lockout hierarchy")
					cmd.PrintErrln(err)
					return
				}
				if err := App.TPM.Clear(endorsementAuth, tpm2.TPMRHEndorsement); err != nil {
					App.Logger.Error("Failed to clear Endorsement hierarchy")
					cmd.PrintErrln(err)
					return
				}
				if err := App.TPM.Clear(ownerAuth, tpm2.TPMRHOwner); err != nil {
					App.Logger.Error("Failed to clear Owner hierarchy")
					cmd.PrintErrln(err)
					return
				}
				App.Logger.Info("TPM 2.0 successfully cleared")
			}

		}
	},
}
