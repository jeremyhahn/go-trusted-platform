package v1

import (
	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/router"
)

type Router struct {
	baseURI             string
	baseServiceURI      string
	ca                  ca.CertificateAuthority
	restServiceRegistry rest.RestServiceRegistry
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
	restServiceRegistry rest.RestServiceRegistry,
	responseWriter response.HttpWriter) router.WebServiceRouter {

	return &Router{
		ca:                  ca,
		logger:              logger,
		restServiceRegistry: restServiceRegistry,
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
		v1Router.restServiceRegistry.JsonWebTokenService(),
		v1Router.restServiceRegistry.WebAuthnRestService(),
		v1Router.router,
		v1Router.responseWriter)
	systemRouter.RegisterRoutes(v1Router.router)
}

func (v1Router *Router) authenticationRoutes() {
	registrationRouter := router.NewAuthenticationRouter(
		v1Router.restServiceRegistry.JsonWebTokenService())
	registrationRouter.RegisterRoutes(v1Router.router)
}

func (v1Router *Router) webAuthnRoutes() {
	webAuthnRouter := router.NewWebAuthnRouter(
		v1Router.restServiceRegistry.JsonWebTokenService(),
		v1Router.restServiceRegistry.WebAuthnRestService())
	webAuthnRouter.RegisterRoutes(v1Router.router)
}

func (v1Router *Router) acmeRoutes() {
	acmeRouter := router.NewACMERouter(
		v1Router.restServiceRegistry.ACMERestService())
	acmeRouter.RegisterRoutes(v1Router.router)
}
