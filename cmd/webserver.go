package cmd

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/jeremyhahn/go-trusted-platform/webservice"
	"github.com/jeremyhahn/go-trusted-platform/webservice/v1/rest"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(webserverCmd)
}

var webserverCmd = &cobra.Command{
	Use:   "webserver",
	Short: "Run Trusted Platform Web Services",
	Long:  `Starts the embedded web services`,
	Run: func(cmd *cobra.Command, args []string) {

		sigChan := make(chan os.Signal, 1)

		restRegistry := rest.NewRestServiceRegistry(App)
		webserver := webservice.NewWebServerV1(App, restRegistry)

		go webserver.Run()

		signal.Notify(sigChan, syscall.SIGINT) // catch CTRL+C // syscall.SIGTERM, syscall.SIGHUP)

		<-sigChan
		close(sigChan)

		App.Logger.Info("Shutting down")
	},
}
