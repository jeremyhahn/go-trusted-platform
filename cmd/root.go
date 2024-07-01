package cmd

import (
	"fmt"
	"log"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	"github.com/jeremyhahn/go-trusted-platform/app"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
)

var (
	App       *app.App
	DebugFlag bool
	ConfigDir,
	PlatformDir,
	LogDir,
	CADir,
	RuntimeUser,
	CAPassword,
	TLSPassword string
)
var rootCmd = &cobra.Command{
	Use:   app.Name,
	Short: "Golang Viper / Cobra trusted-platform project",
	Long: `The Trusted Platform uses a Trusted Platform Module (TPM),
Secure Boot, and a provided Certificate Authority to establish a Platform
Root of Trust, perform Local and Remote Attestation, encryption, signing,
x509 certificate management, data integrity and more.`,
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
		// app.NewApp().Init()
	},
	Run: func(cmd *cobra.Command, args []string) {
	},
	TraverseChildren: true,
}

func init() {

	cobra.OnInitialize(func() {
		App = app.NewApp().Init(&app.AppInitParams{
			Debug:             DebugFlag,
			LogDir:            LogDir,
			ConfigDir:         ConfigDir,
			CADir:             CADir,
			PlatformDir:       PlatformDir,
			CAPassword:        []byte(CAPassword),
			ServerTLSPassword: []byte(TLSPassword),
		})
	})

	wd, err := os.Getwd()
	if err != nil {
		log.Fatal(err)
	}

	platformDir := fmt.Sprintf("%s/%s", wd, "trusted-data")
	rootCmd.PersistentFlags().BoolVarP(&DebugFlag, "debug", "", false, "Enable debug mode")
	rootCmd.PersistentFlags().StringVarP(&PlatformDir, "platform-dir", "", platformDir, "Trusted Platform home / data directory") // doesnt work as system daemon if not wd (defaults to /)
	rootCmd.PersistentFlags().StringVarP(&ConfigDir, "config-dir", "", fmt.Sprintf("/etc/%s", app.Name), "Directory where configuration files are stored")
	rootCmd.PersistentFlags().StringVarP(&LogDir, "log-dir", "", "trusted-data/log", "Logging directory")
	rootCmd.PersistentFlags().StringVarP(&CADir, "ca-dir", "", "trusted-data/ca", "Logging directory")
	rootCmd.PersistentFlags().StringVarP(&RuntimeUser, "setuid", "", "root", "Ther operating system user to run as")
	rootCmd.PersistentFlags().StringVar(&CAPassword, "ca-password", "", "Certificate Authority private key password")
	rootCmd.PersistentFlags().StringVar(&TLSPassword, "server-password", "", "Server TLS private key password")

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
