package cmd

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/kvstore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
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

		if _, err := App.Init(InitParams); err != nil {
			App.Logger.Error(err)
			cmd.PrintErrln(err)
			return
		}

		userPIN := keystore.NewClearPassword(InitParams.Pin)
		if err := App.LoadCA(userPIN); err != nil {
			App.Logger.Error(err)
			cmd.PrintErrln(err)
			return
		}

		if err := App.InitWebServices(); err != nil {
			App.Logger.Error(err)
			cmd.PrintErrln(err)
			return
		}

		daoFactory, err := kvstore.New(
			App.Logger,
			App.DatastoreConfig,
		)
		if err != nil {
			App.Logger.Error(err)
			cmd.PrintErrln(err)
			return
		}

		serviceRegistry, err := service.NewRegistry(App.Logger, daoFactory)
		if err != nil {
			App.Logger.Error(err)
			cmd.PrintErrln(err)
			return
		}

		restRegistry := rest.NewHandlerRegistry(
			App.Logger,
			App.CA,
			daoFactory,
			App.ServerKeyAttributes,
			serviceRegistry,
			App.WebService,
			App.Domain,
		)

		webserver := webservice.NewWebServerV1(
			App.Logger,
			App.CA,
			App.WebService,
			restRegistry,
			App.ServerKeyAttributes)

		// Start the web server in a background goroutine
		go webserver.Run()

		// Set CTRL+C handler to stop the web service and
		// shut down the platform
		signal.Notify(sigChan, syscall.SIGINT) //syscall.SIGTERM, syscall.SIGHUP)

		<-sigChan
		close(sigChan)

		App.Logger.Info("Shutting down")
	},
}
