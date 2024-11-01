package router

import (
	"net/http"

	"github.com/codegangsta/negroni"
	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/keystore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest"
)

type SystemRouter struct {
	authMiddleware    middleware.AuthMiddleware
	jwtMiddleware     middleware.JsonWebTokenMiddleware
	systemRestService rest.SystemRestServicer
	WebServiceRouter
}

// Creates a new web service system router
func NewSystemRouter(
	logger *logging.Logger,
	ca ca.CertificateAuthority,
	serverKeyAttributes *keystore.KeyAttributes,
	jwtMiddleware middleware.JsonWebTokenMiddleware,
	authMiddleware middleware.AuthMiddleware,
	router *mux.Router,
	jsonWriter response.HttpWriter) WebServiceRouter {

	return &SystemRouter{
		authMiddleware: authMiddleware,
		jwtMiddleware:  jwtMiddleware,
		systemRestService: rest.NewSystemRestService(
			ca,
			serverKeyAttributes,
			jsonWriter,
			logger)}
}

// Registers all of the system endpoints at the root of the webservice (/api/v1)
func (systemRouter *SystemRouter) RegisterRoutes(router *mux.Router) {

	systemRouter.status(router)
	systemRouter.pubkey(router)
	systemRouter.certificate(router)
	systemRouter.config(router)
	systemRouter.eventlog(router)
}

// @Summary System Status
// @Description Returns current system status metrics
// @Tags System
// @Produce  json
// @Success 200
// @Router /status [get]
// @Security JWT
func (systemRouter *SystemRouter) status(router *mux.Router) {
	router.HandleFunc("/status", systemRouter.systemRestService.Status)
}

// @Summary Retrieve the server pubilc key
// @Description Returns the server public RSA key
// @Tags System
// @Produce  json
// @Success 200 {string} pubkey
// @Router /pubkey [get]
func (systemRouter *SystemRouter) pubkey(router *mux.Router) {
	router.HandleFunc("/pubkey", systemRouter.systemRestService.PublicKey)
}

// @Summary Retrieve the server x509 certificate
// @Description Returns the server public RSA key
// @Tags System
// @Produce  json
// @Success 200 {string} certificate
// @Router /certificate [get]
func (systemRouter *SystemRouter) certificate(router *mux.Router) {
	router.HandleFunc("/certificate", systemRouter.systemRestService.Certificate)
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
func (systemRouter *SystemRouter) config(router *mux.Router) {
	router.Handle("/config", negroni.New(
		negroni.HandlerFunc(systemRouter.authMiddleware.Verify),
		negroni.HandlerFunc(systemRouter.jwtMiddleware.Verify),
		negroni.Wrap(http.HandlerFunc(systemRouter.systemRestService.Config)),
	))
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
func (systemRouter *SystemRouter) eventlog(router *mux.Router) {
	router.Handle("/events/{page}", negroni.New(
		negroni.NewLogger(),
		negroni.HandlerFunc(systemRouter.authMiddleware.Verify),
		negroni.HandlerFunc(systemRouter.jwtMiddleware.Verify),
		negroni.Wrap(http.HandlerFunc(systemRouter.systemRestService.EventsPage)),
	))
}
