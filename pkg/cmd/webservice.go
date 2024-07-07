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

		restRegistry := rest.NewRestServiceRegistry(App)
		webserver := webservice.NewWebServerV1(App, []byte(App.ServerPassword), restRegistry)

		go webserver.Run()

		signal.Notify(sigChan, syscall.SIGINT) // catch CTRL+C // syscall.SIGTERM, syscall.SIGHUP)

		<-sigChan
		close(sigChan)

		App.Logger.Info("Shutting down")
	},
}
