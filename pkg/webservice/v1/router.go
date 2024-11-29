package v1

import (
	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/router"
)

type Router struct {
	baseURI             string
	baseServiceURI      string
	ca                  ca.CertificateAuthority
	restHandlerRegistry RestHandlerRegistry
	logger              *logging.Logger
	router              *mux.Router
	responseWriter      response.HttpWriter
	serverKeyAttributes *keystore.KeyAttributes
	router.WebServiceRouter
}

func NewRouter(
	logger *logging.Logger,
	ca ca.CertificateAuthority,
	serverKeyAttribtues *keystore.KeyAttributes,
	restHandlerRegistry RestHandlerRegistry,
	responseWriter response.HttpWriter) router.WebServiceRouter {

	return &Router{
		ca:                  ca,
		logger:              logger,
		restHandlerRegistry: restHandlerRegistry,
		serverKeyAttributes: serverKeyAttribtues,
		responseWriter:      responseWriter}
}

// Registers all websocket and REST services
func (v1Router *Router) RegisterRoutes(router *mux.Router) {
	v1Router.router = router
	v1Router.systemRoutes()
	v1Router.authenticationRoutes()
	v1Router.webAuthnRoutes()
	v1Router.acmeRoutes()
}

func (v1Router *Router) systemRoutes() {
	systemRouter := router.NewSystemRouter(
		v1Router.logger,
		v1Router.ca,
		v1Router.serverKeyAttributes,
		v1Router.restHandlerRegistry.JSONWebTokenHandler(),
		v1Router.restHandlerRegistry.WebAuthnRestService(),
		v1Router.router,
		v1Router.responseWriter)
	systemRouter.RegisterRoutes(v1Router.router)
}

func (v1Router *Router) authenticationRoutes() {
	registrationRouter := router.NewAuthenticationRouter(
		v1Router.restHandlerRegistry.JSONWebTokenHandler())
	registrationRouter.RegisterRoutes(v1Router.router)
}

func (v1Router *Router) webAuthnRoutes() {
	webAuthnRouter := router.NewWebAuthnRouter(
		v1Router.restHandlerRegistry.JSONWebTokenHandler(),
		v1Router.restHandlerRegistry.WebAuthnRestService())
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
