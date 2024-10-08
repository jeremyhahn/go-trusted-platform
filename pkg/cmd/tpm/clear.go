package tpm

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/fatih/color"
	"github.com/google/go-tpm/tpm2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/prompt"
	"github.com/spf13/cobra"
)

var (
	clrDevicePath string
	clrForce      bool
	clrHierarchy  string
)

func init() {

	ClearCmd.PersistentFlags().StringVar(&clrDevicePath, "device", "/dev/tpm0", "The TPM 2.0 device path")
	ClearCmd.PersistentFlags().BoolVar(&clrForce, "force", false, "Forces a UEFI platform TPM clear, requires root and reboot")
	ClearCmd.PersistentFlags().StringVar(&clrHierarchy, "hierarchy", "l", "The hierarchy to clear. Defaults to the lockout hierarchy. [ e | o | l ]")
}

var ClearCmd = &cobra.Command{
	Use:   "clear",
	Short: "TPM2_Clear",
	Long: `This command removes all TPM context associated with a specific Owner.

The clear operation will:

• flush resident objects (persistent and volatile) in the Storage and Endorsement hierarchies;
• delete any NV Index with TPMA_NV_PLATFORMCREATE == CLEAR;
• change the storage primary seed (SPS) to a new value from the TPM’s random number generator
(RNG),
• change shProof and ehProof,
NOTE 1 The proof values are permitted to be set from the RNG or derived from the associated new
Primary Seed. If derived from the Primary Seeds, the derivation of ehProof shall use both the
SPS and EPS. The computation shall use the SPS as an HMAC key and the derived value may
then be a parameter in a second HMAC in which the EPS is the HMAC key. The reference
design uses values from the RNG.
• SET shEnable and ehEnable;
• set ownerAuth, endorsementAuth, and lockoutAuth to the Empty Buffer;
• set ownerPolicy, endorsementPolicy, and lockoutPolicy to the Empty Buffer;
• set Clock to zero;
• set resetCount to zero;
• set restartCount to zero; and
• set Safe to YES.
• increment pcrUpdateCounter

This command requires Platform Authorization or Lockout Authorization. If TPM2_ClearControl() has
disabled this command, the TPM shall return TPM_RC_DISABLED.

If this command is authorized using lockoutAuth, the HMAC in the response shall use the new
lockoutAuth value (that is, the Empty Buffer) when computing the response HMAC.
	
See TPM 2.0 Part 3: Commands - Section 24.6: TPM2_Clear
https://trustedcomputinggroup.org/wp-content/uploads/TPM-2.0-1.83-Part-3-Commands.pdf	
`,
	Run: func(cmd *cobra.Command, args []string) {

		if clrForce {
			// https://github.com/tpm2-software/tpm2-tools/issues/1956
			deviceName := filepath.Base(clrDevicePath)
			file := fmt.Sprintf("/sys/class/tpm/%s/ppi/request", deviceName)
			err := os.WriteFile(file, []byte("5"), os.ModePerm)
			if err != nil {
				color.New(color.FgRed).Println(err)
				return
			}
			color.New(color.FgGreen).Println("Success, press any key to reboot...")
			prompt.NoOpPrompt()
			syscall.Reboot(syscall.LINUX_REBOOT_CMD_RESTART)
			return
		}

		App, err = App.Init(InitParams)
		if err != nil {
			cmd.PrintErrln(err)
			return
		}

		switch strings.ToLower(clrHierarchy) {
		case "e":
			err = App.TPM.Clear(InitParams.SOPin, tpm2.TPMRHEndorsement)
		case "o":
			err = App.TPM.Clear(InitParams.SOPin, tpm2.TPMRHOwner)
		case "l":
			err = App.TPM.Clear(InitParams.SOPin, tpm2.TPMRHLockout)
		}
		if err != nil {
			color.New(color.FgRed).Println(err)
			return
		}

		color.New(color.FgGreen).Printf("TPM successfully cleared")
	},
}
