package cmd

import (
	"crypto/rand"
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/cmd/subcommands"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	App        *app.App
	InitParams *app.AppInitParams
	CAParams   ca.CAParams
)

var rootCmd = &cobra.Command{
	Use:   app.Name,
	Short: "The Trusted Platform",
	Long: `The Trusted Platform uses a Trusted Platform Module (TPM),
Secure Boot, and a provided Certificate Authority to establish a Platform
Root of Trust, perform Local and Remote Attestation, encryption, signing,
x509 certificate management, data integrity and a framework for building
secure, scalable web applications using industry approved best practices
and standards.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
	},
	Run: func(cmd *cobra.Command, args []string) {
	},
	TraverseChildren: true,
}

func init() {

	cobra.OnInitialize(func() {

		// Initialize the platform
		App = app.NewApp().Init(InitParams)

		// Initialize subcommand globals
		CAParams := ca.CAParams{
			Logger:     App.Logger,
			Config:     App.CAConfig,
			SelectedCA: InitParams.SelectedCA,
			Random:     rand.Reader,
		}

		// Use TPM for entropy if enabled
		if App.TPM != nil {
			CAParams.Random = App.TPM.RandomReader()
		}

		subcommands.App = App
		subcommands.InitParams = InitParams
		subcommands.CAParams = CAParams
		subcommands.TPM = App.TPM
	})

	// Set provided initialization parameters for
	// commands package and program entry points
	InitParams = &app.AppInitParams{}

	wd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	platformDir := fmt.Sprintf("%s/%s", wd, "trusted-data")
	rootCmd.PersistentFlags().BoolVarP(&InitParams.Debug, "debug", "d", false, "Enable debug mode")
	rootCmd.PersistentFlags().BoolVarP(&InitParams.DebugSecrets, "debug-secrets", "", false, "Enable secret debugging mode. Includes passwords and secrets in logs")
	rootCmd.PersistentFlags().StringVarP(&InitParams.PlatformDir, "platform-dir", "", platformDir, "Trusted Platform home directory where data is stored") // doesnt work as system daemon if not wd (defaults to /)
	rootCmd.PersistentFlags().StringVarP(&InitParams.ConfigDir, "config-dir", "", fmt.Sprintf("/etc/%s", app.Name), "Platform configuration file directory")
	rootCmd.PersistentFlags().StringVarP(&InitParams.LogDir, "log-dir", "", "trusted-data/log", "Platform logs directory")
	rootCmd.PersistentFlags().StringVarP(&InitParams.CADir, "ca-dir", "", "trusted-data/ca", "Certificate Authority data directory")
	rootCmd.PersistentFlags().StringVarP(&InitParams.RuntimeUser, "setuid", "", "root", "Ther operating system user to run as")
	rootCmd.PersistentFlags().StringVarP(&InitParams.CAParentPassword, "ca-parent-password", "r", "", "Root or Parent Certificate Authority private key password")
	rootCmd.PersistentFlags().StringVarP(&InitParams.CAPassword, "ca-password", "p", "", "Intermediate Certificate Authority private key password")
	rootCmd.PersistentFlags().StringVarP(&InitParams.ServerPassword, "server-password", "s", "", "Web server TLS private key password")
	rootCmd.PersistentFlags().StringVar(&InitParams.EKCert, "ek-cert", "", "TPM Endorsement Key Certificate")
	rootCmd.PersistentFlags().StringVar(&InitParams.EKAuth, "ek-auth", "", "TPM Endorsement Key authorization password")
	rootCmd.PersistentFlags().StringVar(&InitParams.SRKAuth, "srk-auth", "", "TPM Storage Root Key authorization password")
	rootCmd.PersistentFlags().IntVarP(&InitParams.SelectedCA, "intermediate", "", 1, "The target Certificate Authority. This number is the Identity array index of the target CA.")
	rootCmd.PersistentFlags().StringVarP(&InitParams.ListenAddress, "listen", "", "", "The listen address for platform services")
	rootCmd.PersistentFlags().StringVarP(&InitParams.Domain, "domain", "", "", "The domain name for platform services")

	viper.BindPFlags(rootCmd.PersistentFlags())

	if runtime.GOOS == "darwin" {
		signal.Ignore(syscall.Signal(0xd))
	}
}

func Execute() error {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
	return nil
}
