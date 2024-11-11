package test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/kvstore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice"
	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/webauthn"

	acmedao "github.com/jeremyhahn/go-trusted-platform/pkg/acme/dao/afero"
)

var (
	App                 *app.App
	WebServer           *webservice.WebServerV1
	ServiceRegistry     *service.Registry
	RestServiceRegistry v1.RestHandlerRegistry
	JWT                 string
	TESTDATA_DIR        = "./testdata"
)

func TestMain(m *testing.M) {
	os.RemoveAll(TESTDATA_DIR)
	setup()
	// login()
	code := m.Run()
	teardown()
	os.Exit(code)
}

func teardown() {
	App.ShutdownChan <- true
	os.RemoveAll(TESTDATA_DIR)
}

func setup() {

	var err error

	App = app.DefaultTestConfig()
	// testConfig.PlatformDir = TESTDATA_DIR

	// App, err = app.NewApp().Init(&app.AppInitParams{
	// 	CADir:        fmt.Sprintf("%s/%s", TESTDATA_DIR, "ca"),
	// 	ConfigDir:    ".",
	// 	Debug:        true,
	// 	DebugSecrets: true,
	// 	Env:          app.ENV_TEST.String(),
	// 	Initialize:   true,
	// 	LogDir:       "/var/log",
	// 	Pin:          []byte("123456"),
	// 	PlatformCA:   1,
	// 	SOPin:        []byte("123456"),
	// 	PlatformDir:  TESTDATA_DIR,
	// })
	// if err != nil {
	// 	logging.DefaultLogger().FatalError(err)
	// }

	selectedCA := 1
	soPIN := []byte("123456")
	userPIN := []byte("123456")

	initParams := &app.AppInitParams{
		PlatformCA: selectedCA,
		SOPin:      soPIN,
		Pin:        userPIN,
	}

	if err := App.InitTPM(nil, nil, initParams); err != nil {
		App.Logger.FatalError(err)
	}

	datastore, err := kvstore.New(App.Logger, App.DatastoreConfig)
	if err != nil {
		App.Logger.FatalError(err)
	}

	acmeDAOFactory, err := acmedao.NewFactory(App.Logger, App.DatastoreConfig)
	if err != nil {
		App.Logger.FatalError(err)
	}

	serviceRegistry, err := service.NewRegistry(App.Logger, nil, nil, datastore)
	if err != nil {
		App.Logger.FatalError(err)
	}

	registryParams := v1.RegistryParams{
		ACMEConfig:     App.ACMEConfig,
		ACMEDAOFactory: acmeDAOFactory,
		CA:             App.CA,
		Debug:          App.DebugFlag,
		// EndpointList:   &App.EndpointList,
		HTTPWriter:          response.NewResponseWriter(App.Logger, nil),
		Keyring:             App.CA.Keyring(),
		JWTAudience:         App.WebServiceConfig.Certificate.Subject.CommonName,
		JWTClaimsIssuer:     app.Name,
		JWTExpiration:       3600,
		Logger:              App.Logger,
		ServerKeyAttributes: App.ServerKeyAttributes,
		ServiceRegistry:     serviceRegistry,
		TPM:                 App.TPM,
		WebServiceConfig:    App.WebServiceConfig,
		WebAuthnConfig: &webauthn.Config{
			RPDisplayName: App.WebServiceConfig.WebAuthn.RPDisplayName,
			RPID:          App.WebServiceConfig.WebAuthn.RPID,
			RPOrigins:     App.WebServiceConfig.WebAuthn.RPOrigins,
		},
	}

	restHandlerRegistry := v1.NewHandlerRegistry(registryParams)

	WebServer = webservice.NewWebServerV1(
		App.DebugFlag,
		App.Logger,
		App.CA,
		App.WebServiceConfig,
		restHandlerRegistry,
		App.ServerKeyAttributes,
	)

	go WebServer.Run()

	// Don't block on integration tests

	// <-App.ShutdownChan
	// close(App.ShutdownChan)

	// Set up test variables
	ServiceRegistry = serviceRegistry
	RestServiceRegistry = restHandlerRegistry
}

// Obtain a JWT using the default username and password
func login() {
	if JWT == "" {
		userCredentials := service.UserCredential{
			// Email:    common.DEFAULT_USER,
			// Password: common.DEFAULT_PASSWORD,
		}
		jsonCreds, err := json.Marshal(userCredentials)
		if err != nil {
			App.Logger.FatalError(err)
		}
		req, err := http.NewRequest("POST", "/api/v1/login", bytes.NewBuffer(jsonCreds))
		if err != nil {
			App.Logger.FatalError(err)
		}
		rr := httptest.NewRecorder()

		// Set the handler function an serve the request
		handler := http.HandlerFunc(RestServiceRegistry.JSONWebTokenHandler().GenerateToken)

		// Send the request and record the response
		handler.ServeHTTP(rr, req)

		// var jwt viewmodel.JsonWebToken
		var jwt map[string]interface{}
		err = json.Unmarshal(rr.Body.Bytes(), &jwt)
		if err != nil {
			App.Logger.Error(err)
		}
		// JWT = jwt.Value
		JWT = jwt["value"].(string)
	}
}

// func createFakeSession() service.Session {
// 	return service.CreateSession(
// 		App.Logger,
// 		[]service.OrganizationClaim{},
// 		[]service.FarmClaim{},
// 		nil,
// 		0,
// 		0,
// 		datastore.CONSISTENCY_LOCAL,
// 		entities.NewUser())
// }
