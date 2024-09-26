package cmd

import (
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/kvstore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest"
	"github.com/spf13/afero"
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

		datastoreFactory, err := kvstore.NewFactory(&kvstore.Params{
			Fs:             afero.NewOsFs(),
			Logger:         App.Logger,
			ReadBufferSize: 50,
			RootDir:        fmt.Sprintf("%s/datastore", App.PlatformDir),
			Serializer:     datastore.SERIALIZER_YAML,
		})
		if err != nil {
			App.Logger.Error(err)
			cmd.PrintErrln(err)
			return
		}

		serviceRegistry, err := service.NewRegistry(App.Logger, datastoreFactory)
		if err != nil {
			App.Logger.Error(err)
			cmd.PrintErrln(err)
			return
		}

		restRegistry := rest.NewRestServiceRegistry(
			App.Logger,
			App.CA,
			App.ServerKeyAttributes,
			serviceRegistry,
			App.WebService,
			App.Domain,
		)

		webserver := webservice.NewWebServerV1(
			App.Logger,
			App.CA,
			App.WebService,
			App.ListenAddress,
			restRegistry,
			App.ServerKeyAttributes)

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
