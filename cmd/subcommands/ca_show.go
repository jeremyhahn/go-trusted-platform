package subcommands

import (
	"fmt"
	"os"
	"os/exec"

	"github.com/spf13/cobra"
)

func init() {
	CAShowCmd.PersistentFlags().StringVarP(&CAFile, "file", "f", "", "The path to the certificate")
}

var CAShowCmd = &cobra.Command{
	Use:   "show",
	Short: "Shows an x509 certificate",
	Long: `This command is a wrapper for openssl. It displays
a certificate using openssl x509 -text`,
	Run: func(cmd *cobra.Command, args []string) {
		wd, err := os.Getwd()
		if err != nil {
			App.Logger.Fatal(err)
		}
		arg0 := "x509"
		arg1 := "-in"
		arg2 := fmt.Sprintf("%s/%s/%s.crt", wd, App.CAConfig.Home, CAFile)
		arg3 := "-text"
		openssl := exec.Command("openssl", arg0, arg1, arg2, arg3)
		stdout, err := openssl.Output()
		if err != nil {
			App.Logger.Fatal(err)
		}
		App.Logger.Info(string(stdout))
	},
}
