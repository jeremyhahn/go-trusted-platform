package v1

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/router"
)

type RouterV1 struct {
	baseURI             string
	baseServiceURI      string
	ca                  ca.CertificateAuthority
	restServiceRegistry rest.RestServiceRegistry
	logger              *logging.Logger
	router              *mux.Router
	responseWriter      response.HttpWriter
	serverKeyAttributes *keystore.KeyAttributes
	endpointList        []string
	router.WebServiceRouter
}

func NewRouterV1(
	logger *logging.Logger,
	ca ca.CertificateAuthority,
	serverKeyAttribtues *keystore.KeyAttributes,
	restServiceRegistry rest.RestServiceRegistry,
	router *mux.Router,
	responseWriter response.HttpWriter) router.WebServiceRouter {

	return &RouterV1{
		ca:                  ca,
		logger:              logger,
		restServiceRegistry: restServiceRegistry,
		router:              router,
		serverKeyAttributes: serverKeyAttribtues,
		responseWriter:      responseWriter,
		endpointList:        make([]string, 0)}
}

// Registers all websocket and REST services
func (v1Router *RouterV1) RegisterRoutes(router *mux.Router, baseURI string) []string {

	v1Router.baseURI = baseURI
	v1Router.baseServiceURI = fmt.Sprintf("%s/services/{id}", baseURI)

	endpointList := make([]string, 0)
	endpointList = append(endpointList, v1Router.systemRoutes()...)
	endpointList = append(endpointList, v1Router.authenticationRoutes()...)
	endpointList = append(endpointList, v1Router.webAuthnRoutes()...)

	endpoints := v1Router.sortAndDeDupe(endpointList)
	v1Router.logger.Debug(strings.Join(endpoints[:], "\n"))
	v1Router.logger.Debugf("Loaded %d REST endpoints", len(endpoints))
	v1Router.endpointList = endpoints

	return endpoints
}

func (v1Router *RouterV1) sortAndDeDupe(endpointList []string) []string {
	// Create unique list
	uniqueList := make(map[string]bool, len(endpointList))
	for _, endpoint := range endpointList {
		uniqueList[endpoint] = true
	}
	// Create a new array from the unique list
	endpoints := make([]string, len(uniqueList))
	i := 0
	for k, _ := range uniqueList {
		endpoints[i] = k
		i++
	}
	// Sort the endpoints
	sort.Strings(endpoints)
	return endpoints
}

func (v1Router *RouterV1) systemRoutes() []string {
	systemRouter := router.NewSystemRouter(
		v1Router.logger,
		v1Router.ca,
		v1Router.serverKeyAttributes,
		v1Router.restServiceRegistry.JsonWebTokenService(),
		v1Router.restServiceRegistry.WebAuthnRestService(),
		v1Router.router,
		v1Router.responseWriter,
		&v1Router.endpointList)
	return systemRouter.RegisterRoutes(v1Router.router, v1Router.baseURI)
}

func (v1Router *RouterV1) authenticationRoutes() []string {
	registrationRouter := router.NewAuthenticationRouter(
		v1Router.restServiceRegistry.JsonWebTokenService())
	return registrationRouter.RegisterRoutes(v1Router.router, v1Router.baseURI)
}

func (v1Router *RouterV1) webAuthnRoutes() []string {
	webAuthnRouter := router.NewWebAuthnRouter(
		v1Router.restServiceRegistry.JsonWebTokenService(),
		v1Router.restServiceRegistry.WebAuthnRestService())
	return webAuthnRouter.RegisterRoutes(v1Router.router, v1Router.baseURI)
}
