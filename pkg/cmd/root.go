package cmd

import (
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
	App       *app.App
	DebugFlag bool
	CAParams  ca.CAParams
	ConfigDir,
	PlatformDir,
	LogDir,
	CADir,
	RuntimeUser,
	CAPassword,
	RootPassword,
	IntermediatePassword,
	ServerPassword,
	EKCert,
	EKAuth,
	SRKAuth string
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

		// The caPassword is the password for the CA that will
		// be used by the platform. This should be the Intermediate
		// CA, but a single Root CA is supported as well. This can
		// be useful for local development and testing.
		if CAPassword == "" {
			CAPassword = RootPassword
			if IntermediatePassword != "" {
				CAPassword = IntermediatePassword
			}
		}

		// Initialize the platform
		App = app.NewApp().Init(&app.AppInitParams{
			Debug:                DebugFlag,
			LogDir:               LogDir,
			ConfigDir:            ConfigDir,
			CADir:                CADir,
			PlatformDir:          PlatformDir,
			CAPassword:           CAPassword,
			RootPassword:         RootPassword,
			IntermediatePassword: IntermediatePassword,
			ServerPassword:       ServerPassword,
			EKCert:               EKCert,
			EKAuth:               EKAuth,
			SRKAuth:              SRKAuth,
		})

		// Initialize subcommand globals
		CAParams := ca.CAParams{
			Logger:               App.Logger,
			Config:               &App.CAConfig,
			Password:             []byte(CAPassword),
			SelectedIntermediate: 1,
			Random:               App.TPM.RandomReader(),
		}
		subcommands.App = App
		subcommands.CAPassword = CAPassword
		subcommands.CAParams = CAParams
		subcommands.TPM = App.TPM
	})

	wd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	platformDir := fmt.Sprintf("%s/%s", wd, "trusted-data")
	rootCmd.PersistentFlags().BoolVarP(&DebugFlag, "debug", "d", false, "Enable debug mode")
	rootCmd.PersistentFlags().BoolVarP(&DebugFlag, "debug-secrets", "", false, "Enable secret debugging mode. Includes passwords and secrets in logs")
	rootCmd.PersistentFlags().StringVarP(&PlatformDir, "platform-dir", "", platformDir, "Trusted Platform home directory where data is stored") // doesnt work as system daemon if not wd (defaults to /)
	rootCmd.PersistentFlags().StringVarP(&ConfigDir, "config-dir", "", fmt.Sprintf("/etc/%s", app.Name), "Platform configuration file directory")
	rootCmd.PersistentFlags().StringVarP(&LogDir, "log-dir", "", "trusted-data/log", "Platform logs directory")
	rootCmd.PersistentFlags().StringVarP(&CADir, "ca-dir", "", "trusted-data/ca", "Certificate Authority data directory")
	rootCmd.PersistentFlags().StringVarP(&RuntimeUser, "setuid", "", "root", "Ther operating system user to run as")
	rootCmd.PersistentFlags().StringVarP(&CAPassword, "ca-password", "p", "", "Platform Certificate Authority private key password")
	rootCmd.PersistentFlags().StringVarP(&RootPassword, "root-password", "r", "", "Root Certificate Authority private key password")
	rootCmd.PersistentFlags().StringVarP(&IntermediatePassword, "intermediate-password", "i", "", "Intermediate Certificate Authority private key password")
	rootCmd.PersistentFlags().StringVarP(&ServerPassword, "server-password", "s", "", "Web server TLS private key password")
	rootCmd.PersistentFlags().StringVar(&EKCert, "ek-cert", "", "TPM Endorsement Key Certificate")
	rootCmd.PersistentFlags().StringVar(&EKAuth, "ek-auth", "", "TPM Endorsement Key authorization password")
	rootCmd.PersistentFlags().StringVar(&SRKAuth, "srk-auth", "", "TPM Storage Root Key authorization password")

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
