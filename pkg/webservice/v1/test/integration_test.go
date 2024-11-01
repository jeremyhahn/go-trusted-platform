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
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest"
)

var (
	App                 *app.App
	WebServer           *webservice.WebServerV1
	ServiceRegistry     *service.Registry
	RestServiceRegistry rest.RestServiceRegistry
	JWT                 string
	TESTDATA_DIR        = "testdata"
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

	if err := App.InitTPM(selectedCA, soPIN, userPIN); err != nil {
		App.Logger.FatalError(err)
	}

	datastore, err := kvstore.New(App.Logger, App.DatastoreConfig)
	if err != nil {
		App.Logger.FatalError(err)
	}

	serviceRegistry, err := service.NewRegistry(App.Logger, datastore)
	if err != nil {
		App.Logger.FatalError(err)
	}

	restServiceRegistry := rest.NewHandlerRegistry(
		App.Logger,
		App.CA,
		datastore,
		App.ServerKeyAttributes,
		serviceRegistry,
		App.WebService,
		"Trusted Platform",
	)

	WebServer = webservice.NewWebServerV1(
		App.Logger,
		App.CA,
		App.WebService,
		restServiceRegistry,
		App.ServerKeyAttributes,
	)

	go WebServer.Run()

	// Don't block on integration tests

	// <-App.ShutdownChan
	// close(App.ShutdownChan)

	// Set up test variables
	ServiceRegistry = serviceRegistry
	RestServiceRegistry = restServiceRegistry
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
		handler := http.HandlerFunc(RestServiceRegistry.JsonWebTokenService().GenerateToken)

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
