package cmd

import (
	"os"
	"os/signal"
	"syscall"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/webauthn"
	"github.com/spf13/cobra"

	acmedao "github.com/jeremyhahn/go-trusted-platform/pkg/acme/dao/afero"

	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
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

		if App.CA == nil {
			soPIN, userPIN, err := App.ParsePINs(InitParams.SOPin, InitParams.Pin)
			if err != nil {
				App.Logger.Error(err)
				cmd.PrintErrln(err)
				return
			}
			if err := App.LoadCA(soPIN, userPIN); err != nil {
				App.Logger.Error(err)
				cmd.PrintErrln(err)
				return
			}
		}

		if App.ServerKeyAttributes == nil {
			if err := App.InitWebServer(); err != nil {
				App.Logger.Error(err)
				cmd.PrintErrln(err)
				return
			}
		}

		acmeDAOFactory, err := acmedao.NewFactory(
			App.Logger,
			App.DatastoreConfig,
		)
		if err != nil {
			App.Logger.Error(err)
			cmd.PrintErrln(err)
			return
		}

		restHandlerRegistry := v1.NewHandlerRegistry(v1.RegistryParams{
			ACMEConfig:          App.ACMEConfig,
			ACMEDAOFactory:      acmeDAOFactory,
			CA:                  App.CA,
			Debug:               App.DebugFlag,
			HTTPWriter:          response.NewResponseWriter(App.Logger, nil),
			Keyring:             App.CA.Keyring(),
			JWTAudience:         App.WebServiceConfig.Certificate.Subject.CommonName,
			JWTClaimsIssuer:     app.Name,
			JWTExpiration:       3600,
			Logger:              App.Logger,
			ServerKeyAttributes: App.ServerKeyAttributes,
			ServiceRegistry:     App.ServiceRegistry(),
			TPM:                 App.TPM,
			WebServiceConfig:    App.WebServiceConfig,
			WebAuthnConfig: &webauthn.Config{
				RPDisplayName: App.WebServiceConfig.WebAuthn.RPDisplayName,
				RPID:          App.WebServiceConfig.WebAuthn.RPID,
				RPOrigins:     App.WebServiceConfig.WebAuthn.RPOrigins,
			},
		})

		webserver := webservice.NewWebServerV1(
			App.DebugFlag,
			App.Logger,
			App.CA,
			App.WebServiceConfig,
			restHandlerRegistry,
			App.ServerKeyAttributes)

		go webserver.Run()

		// Set CTRL+C handler to stop the web service and
		// shut down the platform
		signal.Notify(sigChan, syscall.SIGINT) //syscall.SIGTERM, syscall.SIGHUP)

		<-sigChan
		close(sigChan)

		App.Logger.Info("Graceful shutdown complete")
	},
}
