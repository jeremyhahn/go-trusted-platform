package v1

import (
	"fmt"
	"sort"
	"strings"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/router"
)

type RouterV1 struct {
	app                    *app.App
	baseURI                string
	baseFarmURI            string
	restServiceRegistry    rest.RestServiceRegistry
	jsonWebTokenMiddleware middleware.JsonWebTokenMiddleware
	router                 *mux.Router
	responseWriter         response.HttpWriter
	endpointList           []string
	router.WebServiceRouter
}

func NewRouterV1(
	app *app.App,
	restServiceRegistry rest.RestServiceRegistry,
	router *mux.Router,
	responseWriter response.HttpWriter) router.WebServiceRouter {

	return &RouterV1{
		app:                    app,
		restServiceRegistry:    restServiceRegistry,
		jsonWebTokenMiddleware: restServiceRegistry.JsonWebTokenService(),
		router:                 router,
		responseWriter:         responseWriter,
		endpointList:           make([]string, 0)}
}

// Registers all routes for standalone mode
func (v1Router *RouterV1) RegisterRoutes(router *mux.Router, baseURI string) []string {

	v1Router.baseURI = baseURI
	v1Router.baseFarmURI = fmt.Sprintf("%s/farms/{farmID}", baseURI)

	endpointList := make([]string, 0)
	endpointList = append(endpointList, v1Router.systemRoutes()...)
	endpointList = append(endpointList, v1Router.authenticationRoutes()...)

	endpoints := v1Router.sortAndDeDupe(endpointList)
	v1Router.app.Logger.Debug(strings.Join(endpoints[:], "\n"))
	v1Router.app.Logger.Debugf("Loaded %d REST endpoints", len(endpoints))
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
		v1Router.app,
		v1Router.restServiceRegistry.JsonWebTokenService(),
		v1Router.router,
		v1Router.responseWriter,
		&v1Router.endpointList)
	return systemRouter.RegisterRoutes(v1Router.router, v1Router.baseURI)
}

func (v1Router *RouterV1) authenticationRoutes() []string {
	registrationRouter := router.NewAuthenticationRouter(
		v1Router.app,
		v1Router.jsonWebTokenMiddleware.(middleware.AuthMiddleware))
	return registrationRouter.RegisterRoutes(v1Router.router, v1Router.baseURI)
}
