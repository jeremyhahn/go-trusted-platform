package cmd

import (
	"fmt"

	"github.com/fatih/color"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore/pkcs11"
	"github.com/spf13/cobra"
)

var (
	module,
	tokenLabel string
	slot int
	bYKCS11,
	bSoftHSM2,
	bOpenSC bool
)

func init() {

	pkcs11Cmd.PersistentFlags().StringVarP(&module, "module", "m", "", "The PKCS #11 module path")
	pkcs11Cmd.PersistentFlags().StringVarP(&tokenLabel, "label", "l", "", "The PKCS #11 token label")
	pkcs11Cmd.PersistentFlags().IntVarP(&slot, "slot", "s", -1, "The PKCS #11 token label")

	pkcs11Cmd.PersistentFlags().BoolVar(&bYKCS11, "ykcs11", false, "Use module at /usr/local/lib/libykcs11.so")
	pkcs11Cmd.PersistentFlags().BoolVar(&bSoftHSM2, "softhsm2", false, "Use module at /usr/local/lib/softhsm/libsofthsm2.so")
	pkcs11Cmd.PersistentFlags().BoolVar(&bOpenSC, "opensc", false, "Use module at /usr/local/lib/opensc-pkcs11.so")

	rootCmd.AddCommand(pkcs11Cmd)
}

var pkcs11Cmd = &cobra.Command{
	Use:   "pkcs11",
	Short: "Perform PKCS #11 token operations",
	Long: `Shows library and hardware information about connected PKCS #11
Hardware Security Modules`,
	Run: func(cmd *cobra.Command, args []string) {

		App, err = App.Init(InitParams)
		if err != nil {
			cmd.PrintErrln(err)
			return
		}

		if bYKCS11 {
			module = "/usr/local/lib/libykcs11.so"
		}
		if bSoftHSM2 {
			module = "/usr/local/lib/softhsm/libsofthsm2.so"
		}
		if bOpenSC {
			module = "/usr/local/lib/opensc-pkcs11.so"
		}

		if module == "" {
			color.New(color.FgRed).Println("invalid PKCS #11 module path")
			return
		}

		fmt.Printf("Command Info\n")
		fmt.Printf("  Module: %s\n", module)
		fmt.Printf("  Slot: %d\n", slot)
		fmt.Printf("  Token Label: %s\n", tokenLabel)
		if App.DebugSecretsFlag {
			fmt.Printf("  SO Pin: %s\n", InitParams.SOPin)
			fmt.Printf("  Pin: %s\n", InitParams.Pin)
		}
		fmt.Println()

		var pSlot *int
		if slot >= 0 {
			pSlot = &slot
		}
		config := &pkcs11.Config{
			Library:    module,
			Slot:       pSlot,
			SOPin:      string(InitParams.SOPin),
			Pin:        string(InitParams.Pin),
			TokenLabel: tokenLabel,
		}
		hsm, err := pkcs11.NewPKCS11(App.Logger, config)
		if err != nil {
			App.Logger.FatalError(err)
		}

		hsm.PrintLibraryInfo()
		hsm.PrintTokenInfo()
	},
}
