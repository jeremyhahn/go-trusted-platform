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

var App *app.App
var DebugFlag bool
var ConfigDir string
var DataDir string
var LogDir string
var HomeDir string
var RuntimeUser string

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
		App = app.NewApp()
		App.Init()
	})

	wd, _ := os.Getwd()

	rootCmd.PersistentFlags().BoolVarP(&DebugFlag, "debug", "", false, "Enable debug mode")
	rootCmd.PersistentFlags().StringVarP(&HomeDir, "home", "", wd, "Program home directory") // doesnt work as system daemon if not wd (/)
	rootCmd.PersistentFlags().StringVarP(&DataDir, "data-dir", "", fmt.Sprintf("%s/db", wd), "Directory where database files are stored")
	rootCmd.PersistentFlags().StringVarP(&ConfigDir, "config-dir", "", fmt.Sprintf("/etc/%s", app.Name), "Directory where configuration files are stored")
	rootCmd.PersistentFlags().StringVarP(&LogDir, "log-dir", "", "./logs", "Logging directory")
	rootCmd.PersistentFlags().StringVarP(&RuntimeUser, "setuid", "", "root", "Ther operating system user to run as")

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
