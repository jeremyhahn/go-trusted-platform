package router

import (
	"fmt"
	"net/http"

	"github.com/codegangsta/negroni"
	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest"
)

type SystemRouter struct {
	middleware        middleware.JsonWebTokenMiddleware
	systemRestService rest.SystemRestServicer
	WebServiceRouter
}

// Creates a new web service system router
func NewSystemRouter(
	app *app.App,
	middleware middleware.JsonWebTokenMiddleware,
	router *mux.Router,
	jsonWriter response.HttpWriter,
	endpointList *[]string) WebServiceRouter {

	return &SystemRouter{
		middleware: middleware,
		systemRestService: rest.NewSystemRestService(
			app,
			jsonWriter,
			endpointList)}
}

// Registers all of the system endpoints at the root of the webservice (/api/v1)
func (systemRouter *SystemRouter) RegisterRoutes(router *mux.Router, baseURI string) []string {
	return []string{
		systemRouter.endpoints(router, baseURI),
		systemRouter.status(router, baseURI),
		systemRouter.pubkey(router, baseURI),
		systemRouter.config(router, baseURI),
		systemRouter.eventlog(router, baseURI)}
}

// @Summary REST API Endpoints
// @Description Returns a list of REST API endpoints
// @Tags System
// @Produce  json
// @Success 200
// @Router /endpoints [get]
func (systemRouter *SystemRouter) endpoints(router *mux.Router, baseURI string) string {
	endpoints := fmt.Sprintf("%s/endpoints", baseURI)
	router.HandleFunc(endpoints, systemRouter.systemRestService.Endpoints)
	return endpoints
}

// @Summary System Status
// @Description Returns current system status metrics
// @Tags System
// @Produce  json
// @Success 200
// @Router /status [get]
// @Security JWT
func (systemRouter *SystemRouter) status(router *mux.Router, baseURI string) string {
	system := fmt.Sprintf("%s/status", baseURI)
	router.HandleFunc(system, systemRouter.systemRestService.Status)
	return system
}

// @Summary Retrieve RSA pubilc key
// @Description Returns the server public RSA key
// @Tags System
// @Produce  json
// @Success 200 {string} pubkey
// @Router /pubkey [get]
func (systemRouter *SystemRouter) pubkey(router *mux.Router, baseURI string) string {
	pubkey := fmt.Sprintf("%s/pubkey", baseURI)
	router.HandleFunc(pubkey, systemRouter.systemRestService.RSAPublicKey)
	return pubkey
}

// @Summary System configuration
// @Description Returns the server configuration
// @Tags System
// @Produce  json
// @Success 200 {object} app.App
// @Failure 400 {object} response.WebServiceResponse
// @Failure 401 {object} response.WebServiceResponse
// @Router /config [get]
// @Security JWT
func (systemRouter *SystemRouter) config(router *mux.Router, baseURI string) string {
	config := fmt.Sprintf("%s/config", baseURI)
	router.Handle(config, negroni.New(
		negroni.HandlerFunc(systemRouter.middleware.Validate),
		negroni.Wrap(http.HandlerFunc(systemRouter.systemRestService.Config)),
	))
	return config
}

// @Summary System Event Log
// @Description Returns a page of system event log entries
// @Tags System
// @Produce  json
// @Success 200
// @Failure 400 {object} response.WebServiceResponse
// @Failure 401 {object} response.WebServiceResponse
// @Param   page	path	string	false	"string valid"	minlength(1)	maxlength(20)
// @Router /events/{page} [get]
// @Security JWT
func (systemRouter *SystemRouter) eventlog(router *mux.Router, baseURI string) string {
	eventlog := fmt.Sprintf("%s/events/{page}", baseURI)
	router.Handle(eventlog, negroni.New(
		negroni.NewLogger(),
		negroni.HandlerFunc(systemRouter.middleware.Validate),
		negroni.Wrap(http.HandlerFunc(systemRouter.systemRestService.EventsPage)),
	))
	return eventlog
}
