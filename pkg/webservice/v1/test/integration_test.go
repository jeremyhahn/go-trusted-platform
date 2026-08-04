// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
// 1. GNU Affero General Public License v3.0 (AGPL-3.0)
//    See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
// 2. Commercial License
//    Contact licensing@automatethethings.com for commercial licensing options.

//go:build integration

package test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	acmequicbaas "github.com/jeremyhahn/go-trusted-platform/pkg/acme/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform"
	"github.com/jeremyhahn/go-trusted-platform/pkg/platform/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/object"
	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/webauthn"
)

var (
	App                 *app.App
	ServiceRegistry     *service.Registry
	RestServiceRegistry v1.RestHandlerRegistry
	JWT                 string
	TESTDATA_DIR        = "trusted-data" // Must match app.TestConfig.PlatformDir
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
	// Non-blocking send to shutdown channel
	if App != nil && App.ShutdownChan != nil {
		select {
		case App.ShutdownChan <- true:
		default:
		}
	}
	if App != nil && App.TPM != nil {
		App.TPM.Close()
	}
	os.RemoveAll(TESTDATA_DIR)
}

func setup() {

	var err error

	// Configure for TPM simulator test - MUST be done before DefaultTestConfig()
	// When CertHandle is 0, the EK cert is loaded from x509 store instead of TPM NV RAM
	app.TestConfig.TPMConfig.EK.CertHandle = 0
	app.TestConfig.TPMConfig.EK.HierarchyAuth = "123456"
	// Use simpler IAK strategy to avoid credential activation issues with simulators
	app.TestConfig.TPMConfig.IdentityProvisioningStrategy = "IAK"

	App = app.DefaultTestConfig()

	// Configure ACME server for tests
	// BaseRESTURI should be the base URL without /acme, so the directory handler
	// can construct URLs like: BaseRESTURI + "/acme/new-account"
	acmeServerConfig := &v1.ACMEServerConfig{
		Enabled:        true,
		BaseRESTURI:    "https://localhost:8443",
		TermsOfService: "https://localhost:8443/acme/terms",
	}

	initParams := &app.AppInitParams{
		PlatformCA: 1,
		SOPin:      []byte("123456"),
		Pin:        []byte("123456"),
		Initialize: true,
		Env:        app.EnvTest.String(),
	}

	App, err = App.Init(context.Background(), initParams)
	if err != nil {
		panic(fmt.Sprintf("Failed to initialize app: %v", err))
	}

	datastore, err := quicbaas.NewFactory(App.QuicBaaSConfig, App.Logger, nil)
	if err != nil {
		App.Logger.FatalError(err)
	}

	// Use in-memory QuicBaaS ObjectStorage for ACME DAO in tests
	acmeMemoryClient := object.NewMemoryClient()
	acmeDAOFactory, err := acmequicbaas.NewFactory(acmeMemoryClient)
	if err != nil {
		App.Logger.FatalError(err)
	}

	serviceRegistry, err := service.NewRegistry(App.Logger, nil, nil, nil, nil, datastore)
	if err != nil {
		App.Logger.FatalError(err)
	}

	// Initialize web server to populate WebServiceKeyAttributes map
	if err := App.InitWebServer(context.Background()); err != nil {
		App.Logger.FatalError(err)
	}

	// Build WebAuthn config with default test values
	webAuthnConfig := &webauthn.Config{
		RPDisplayName: "Test Platform",
		RPID:          "localhost",
		RPOrigins:     []string{"https://localhost:8443"},
	}
	primaryWS := App.PrimaryWebService()
	if primaryWS != nil && primaryWS.WebAuthn != nil && len(primaryWS.WebAuthn.RPOrigins) > 0 {
		webAuthnConfig = &webauthn.Config{
			RPDisplayName: primaryWS.WebAuthn.RPDisplayName,
			RPID:          primaryWS.WebAuthn.RPID,
			RPOrigins:     primaryWS.WebAuthn.RPOrigins,
		}
	}

	// Create XKMS for JWT signing
	xkmsConfig := &platform.XKMSConfig{
		CN:             "test-xkms",
		DefaultBackend: "software",
	}
	ks, err := App.XKMSFromConfig(
		xkmsConfig,
		App.PlatformDir,
		xkmssdk.NewPassword([]byte("123456")),
		xkmssdk.NewPassword([]byte("123456")),
		nil)
	if err != nil {
		App.Logger.FatalError(err)
	}

	// Get key attributes for the primary webservice
	wsName := primaryWS.Name
	if wsName == "" {
		wsName = "default"
	}
	serverKeyAttrs := App.WebServiceKeyAttributes[wsName]
	if serverKeyAttrs == nil {
		App.Logger.FatalError(errors.New(fmt.Sprintf("key attributes not found for webservice %s", wsName)))
	}

	registryParams := v1.RegistryParams{
		ACMEServerConfig:   acmeServerConfig,
		ACMEStorageFactory: acmeDAOFactory,
		CA:                 App.CA,
		Debug:              App.DebugFlag,
		// EndpointList:   &App.EndpointList,
		HTTPWriter:          response.NewResponseWriter(App.Logger, nil),
		XKMS:                ks,
		JWTAudience:         primaryWS.Certificate.Subject.CommonName,
		JWTClaimsIssuer:     app.Name,
		JWTExpiration:       3600,
		Logger:              App.Logger,
		ServerKeyAttributes: serverKeyAttrs,
		ServiceRegistry:     serviceRegistry,
		TPM:                 App.TPM,
		WebServiceConfig:    primaryWS,
		WebAuthnConfig:      webAuthnConfig,
	}

	restHandlerRegistry := v1.NewHandlerRegistry(context.Background(), registryParams)

	// Note: We don't start the webserver here because tests use httptest.NewServer
	// to test handlers directly. Starting the real webserver would fail with TLS errors
	// and call os.Exit, killing the test process.
	// The WebServerV1 is only created if needed for future tests that require
	// the full server infrastructure.

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
			App.Logger.FatalError(err)
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
