package cmd

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest"
	"github.com/spf13/cobra"
)

func init() {
	rootCmd.AddCommand(webserverCmd)
}

var webserverCmd = &cobra.Command{
	Use:   "webservice",
	Short: "Run Trusted Platform Web Services",
	Long:  `Starts the embedded web server to host the REST API and static assets`,
	Run: func(cmd *cobra.Command, args []string) {

		sigChan := make(chan os.Signal, 1)

		// Initialize the CA and TPM
		App.InitCA()

		// Build rest service registry
		restRegistry := rest.NewRestServiceRegistry(App)
		webserver := webservice.NewWebServerV1(
			App,
			[]byte(InitParams.ServerPassword),
			restRegistry)

		// Start the web server in a background goroutine
		go webserver.Run()

		// Set CTRL+C handler to stop the web service and
		// shut down the platform
		signal.Notify(sigChan, syscall.SIGINT) //syscall.SIGTERM, syscall.SIGHUP)

		// Wait for the signal notification
		<-sigChan
		close(sigChan)

		App.Logger.Info("Shutting down")
	},
}
