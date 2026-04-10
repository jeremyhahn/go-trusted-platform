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

package v1

import (
	"github.com/gorilla/mux"
	trustedca "github.com/jeremyhahn/go-trusted-ca/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	restca "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/ca"
	restiam "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/iam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/kms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/sdn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/vtpm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/router"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

type Router struct {
	baseURI             string
	baseServiceURI      string
	ca                  trustedca.CACertificateAuthority
	caConfig            *trustedca.CAConfig
	restHandlerRegistry RestHandlerRegistry
	logger              *logging.Logger
	router              *mux.Router
	responseWriter      response.HttpWriter
	serverKeyAttributes *xkmssdk.KeyAttributes
	router.WebServiceRouter
}

func NewRouter(
	logger *logging.Logger,
	ca trustedca.CACertificateAuthority,
	caConfig *trustedca.CAConfig,
	serverKeyAttribtues *xkmssdk.KeyAttributes,
	restHandlerRegistry RestHandlerRegistry,
	responseWriter response.HttpWriter) router.WebServiceRouter {

	return &Router{
		ca:                  ca,
		caConfig:            caConfig,
		logger:              logger,
		restHandlerRegistry: restHandlerRegistry,
		serverKeyAttributes: serverKeyAttribtues,
		responseWriter:      responseWriter}
}

// Registers all websocket and REST services
func (v1Router *Router) RegisterRoutes(router *mux.Router) {
	v1Router.router = router
	v1Router.platformRoutes()
	v1Router.systemRoutes()
	v1Router.authenticationRoutes()
	v1Router.webAuthnRoutes()
	v1Router.acmeRoutes()
	v1Router.caRoutes()
	v1Router.deviceRoutes()
	v1Router.iamRoutes()
	v1Router.kmsRoutes()
	v1Router.sdnRoutes()
	v1Router.vtpmRoutes()
}

func (v1Router *Router) systemRoutes() {
	// Use WebAuthn as auth middleware if configured, otherwise fall back to JWT.
	var authMiddleware middleware.AuthMiddleware
	webAuthnHandler := v1Router.restHandlerRegistry.WebAuthnRestService()
	if webAuthnHandler != nil {
		authMiddleware = webAuthnHandler
	} else {
		authMiddleware = v1Router.restHandlerRegistry.JSONWebTokenHandler()
	}
	systemRouter := router.NewSystemRouter(
		v1Router.logger,
		v1Router.ca,
		v1Router.caConfig,
		v1Router.serverKeyAttributes,
		v1Router.restHandlerRegistry.JSONWebTokenHandler(),
		authMiddleware,
		v1Router.router,
		v1Router.responseWriter,
		v1Router.restHandlerRegistry.TPM())
	systemRouter.RegisterRoutes(v1Router.router)
}

func (v1Router *Router) authenticationRoutes() {
	registrationRouter := router.NewAuthenticationRouter(
		v1Router.restHandlerRegistry.JSONWebTokenHandler())
	registrationRouter.RegisterRoutes(v1Router.router)
}

func (v1Router *Router) webAuthnRoutes() {
	webAuthnService := v1Router.restHandlerRegistry.WebAuthnRestService()
	if webAuthnService == nil {
		v1Router.logger.Debug("WebAuthn not configured - WebAuthn routes not registered")
		return
	}
	webAuthnRouter := router.NewWebAuthnRouter(
		v1Router.restHandlerRegistry.JSONWebTokenHandler(),
		webAuthnService)
	webAuthnRouter.RegisterRoutes(v1Router.router)
}

func (v1Router *Router) acmeRoutes() {
	if v1Router.restHandlerRegistry.ACMERestService() == nil {
		return
	}
	acmeRouter := router.NewACMERouter(
		v1Router.restHandlerRegistry.ACMERestService())
	acmeRouter.RegisterRoutes(v1Router.router)
}

func (v1Router *Router) caRoutes() {
	if v1Router.ca == nil {
		v1Router.logger.Debug("CA service is nil - CA routes not registered")
		return
	}
	caRouter := restca.NewCARouter(
		v1Router.logger,
		v1Router.ca,
		v1Router.responseWriter)
	caRouter.RegisterRoutes(v1Router.router)
}

func (v1Router *Router) deviceRoutes() {
	deviceHandler := v1Router.restHandlerRegistry.DeviceRestHandler()
	configDeliveryHandler := v1Router.restHandlerRegistry.ConfigDeliveryHandler()

	if deviceHandler == nil && configDeliveryHandler == nil {
		v1Router.logger.Debug("Device and config delivery handlers are nil - device routes not registered")
		return
	}

	deviceRouter := router.NewDeviceRouter(
		v1Router.restHandlerRegistry.MTLSMiddleware(),
		deviceHandler,
		nil, // crudHandler — TODO: wire up when device CRUD handlers exist
		nil, // templateHandler — TODO: wire up when template service is injected
		configDeliveryHandler,
	)
	deviceRouter.RegisterRoutes(v1Router.router)
}

func (v1Router *Router) iamRoutes() {
	iamClient, pepClient := v1Router.restHandlerRegistry.IAMClients()
	if iamClient == nil {
		v1Router.logger.Debug("IAM service client is nil - IAM routes not registered")
		return
	}
	iamRouter := restiam.NewIAMRouter(
		v1Router.logger,
		iamClient,
		pepClient,
		v1Router.responseWriter)
	iamRouter.RegisterRoutes(v1Router.router)
}

func (v1Router *Router) kmsRoutes() {
	keyMgmt, crypto, dekMgmt, secrets := v1Router.restHandlerRegistry.KMSClients()
	if keyMgmt == nil {
		v1Router.logger.Debug("KMS KeyManagement client is nil - KMS routes not registered")
		return
	}
	kmsRouter := kms.NewKMSRouter(
		v1Router.logger,
		keyMgmt,
		crypto,
		dekMgmt,
		secrets,
		v1Router.responseWriter)
	kmsRouter.RegisterRoutes(v1Router.router)
}

func (v1Router *Router) sdnRoutes() {
	sdnService := v1Router.restHandlerRegistry.SDNService()
	if sdnService == nil {
		v1Router.logger.Debug("SDN service is nil - SDN routes not registered")
		return
	}
	sdnRouter := sdn.NewSDNRouter(
		v1Router.logger,
		sdnService,
		v1Router.restHandlerRegistry.ResponseWriter())
	sdnRouter.RegisterRoutes(v1Router.router)
}

func (v1Router *Router) vtpmRoutes() {
	vtpmService := v1Router.restHandlerRegistry.VTPMService()
	if vtpmService == nil {
		v1Router.logger.Debug("vTPM service is nil - vTPM routes not registered")
		return
	}
	vtpmRouter := vtpm.NewVTPMRouter(
		v1Router.logger,
		vtpmService,
		v1Router.restHandlerRegistry.ResponseWriter())
	vtpmRouter.RegisterRoutes(v1Router.router)
}

func (v1Router *Router) platformRoutes() {
	platformRouter := v1Router.restHandlerRegistry.PlatformRestRouter()
	if platformRouter == nil {
		v1Router.logger.Debug("Platform router is nil - platform routes not registered")
		return
	}
	platformRouter.RegisterRoutes(v1Router.router)
}
