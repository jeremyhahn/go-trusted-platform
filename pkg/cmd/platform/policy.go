package platform

import (
	"github.com/google/go-tpm/tpm2"
	"github.com/spf13/cobra"
)

var PolicyCmd = &cobra.Command{
	Use:   "policy [action]",
	Short: "Platform PCR policy operations",
	Long:  `Perform platform PCR policy operations.`,
	Run: func(cmd *cobra.Command, args []string) {

		App, err = App.Init(InitParams)
		if err != nil {
			cmd.PrintErrln(err)
			return
		}

		var digestHash []byte
		var err error

		if len(args) == 0 {
			digestHash, err = App.TPM.PlatformPolicyDigestHash()
			if err != nil {
				cmd.PrintErrln(err)
				return
			}
			cmd.Printf("Hash: %x\n", digestHash)
			return
		}

		switch args[0] {
		case "create":
			if err := App.TPM.CreatePlatformPolicy(); err != nil {
				cmd.PrintErrln(err)
				return
			}
			digestHash, err = App.TPM.PlatformPolicyDigestHash()
			if err != nil {
				cmd.PrintErrln(err)
				return
			}

		case "session":
			session, closer, err := App.TPM.PlatformPolicySession()
			if err != nil {
				cmd.PrintErrln(err)
				return
			}
			defer closer()

			digestHash, err = App.TPM.PlatformPolicyDigestHash()
			if err != nil {
				cmd.PrintErrln(err)
				return
			}

			pgd, err := tpm2.PolicyGetDigest{
				PolicySession: session.Handle(),
			}.Execute(App.TPM.Transport())

			cmd.Printf("PolicyDigest.Buffer: %x\n", pgd.PolicyDigest.Buffer)
			cmd.Printf("Hash:                %x\n", digestHash)
		}

	},
}
