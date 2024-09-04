package cmd

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/fatih/color"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/prompt"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	App        *app.App
	InitParams *app.AppInitParams
	CAParams   *ca.CAParams
	bPin       bool
	bSOPin     bool
	SOPin      string
	Pin        string

	EXIT_CODE_FAILURE = 255
)

var rootCmd = &cobra.Command{
	Use:   app.Name,
	Short: "The Trusted Platform",
	Long: `The Trusted Platform uses a Trusted Platform Module, Secure
Boot, and Certificate Authority to establish a Platform Root of Trust,
Root of Trust for Measurements, perform Local and Remote Attestation,
secure encryption, signing, x509 certificate management, data integrity
and a framework for building secure, scalable web applications and
connected devices.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
	},
	Run: func(cmd *cobra.Command, args []string) {
	},
	TraverseChildren: true,
}

func init() {

	cobra.OnInitialize(func() {

		if bSOPin {
			InitParams.SOPin = prompt.SOPin()
		}
		if bPin {
			InitParams.Pin = prompt.Pin()
		}
		if SOPin != "" {
			InitParams.SOPin = []byte(SOPin)
		}
		if Pin != "" {
			InitParams.Pin = []byte(Pin)
		}

		App = app.NewApp()

		// Initialize subcommands
		initCA()
		initPlatform()
		initTPM()
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
	rootCmd.PersistentFlags().StringVarP(&InitParams.Env, "env", "e", "dev", "Runtime environment (dev, staging, prod)")
	rootCmd.PersistentFlags().StringVarP(&InitParams.PlatformDir, "platform-dir", "", platformDir, "Trusted Platform home directory where data is stored") // doesnt work as system daemon if not wd (defaults to /)
	rootCmd.PersistentFlags().StringVarP(&InitParams.ConfigDir, "config-dir", "", fmt.Sprintf("/etc/%s", app.Name), "Platform configuration file directory")
	rootCmd.PersistentFlags().StringVarP(&InitParams.LogDir, "log-dir", "", "trusted-data/log", "Platform logs directory")
	rootCmd.PersistentFlags().StringVarP(&InitParams.CADir, "ca-dir", "", "trusted-data/ca", "Certificate Authority data directory")
	rootCmd.PersistentFlags().StringVarP(&InitParams.RuntimeUser, "setuid", "", "root", "Ther operating system user to run as")
	rootCmd.PersistentFlags().IntVarP(&InitParams.PlatformCA, "intermediate", "", 1, "The target Certificate Authority. This number is the Identity array index of the target CA.")
	rootCmd.PersistentFlags().StringVarP(&InitParams.ListenAddress, "listen", "", "", "The listen address for platform services")
	rootCmd.PersistentFlags().BoolVar(&bSOPin, "so-pin", false, "Security Officer PIN / password")
	rootCmd.PersistentFlags().BoolVar(&bPin, "pin", false, "Platform Administrator or user PIN / password")
	rootCmd.PersistentFlags().BoolVar(&InitParams.Initialize, "init", false, "True to automatically initialize and provision the platform")

	// For devops automation, testing and development - bypass PIN prompts
	rootCmd.PersistentFlags().StringVar(&SOPin, "raw-so-pin", "", "Raw plain-text Security Officer PIN / password")
	rootCmd.PersistentFlags().StringVar(&Pin, "raw-pin", "", "Raw plain-text Platform Administrator or user PIN / password")

	viper.BindPFlags(rootCmd.PersistentFlags())

	if runtime.GOOS == "darwin" {
		signal.Ignore(syscall.Signal(0xd))
	}
}

func Execute() error {

	prompt.PrintBanner(app.Version)

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
	return nil
}

func fatal(message string) {
	color.New(color.FgRed).Println(message)
	os.Exit(EXIT_CODE_FAILURE)
}
