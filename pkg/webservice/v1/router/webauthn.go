package router

import (
	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/webauthn"
)

type WebAuthnRouter struct {
	middleware          middleware.JsonWebTokenMiddleware
	webAuthnRestService webauthn.RestHandler
	WebServiceRouter
}

// Creates a new webauthn router
func NewWebAuthnRouter(
	middleware middleware.JsonWebTokenMiddleware,
	webAuthnRestService webauthn.RestHandler) WebServiceRouter {

	return &WebAuthnRouter{
		middleware:          middleware,
		webAuthnRestService: webAuthnRestService}
}

// Registers all of the webauthn endpoints at the root of the webservice (/api/v1/webauthn)
func (webAuthnRouter *WebAuthnRouter) RegisterRoutes(router *mux.Router) {

	// // Define allowed CORS options
	// corsOptions := middleware.CORSOptions{
	// 	// AllowedOrigins:   []string{"http://localhost:3000"}, // Replace with your frontend domain
	// 	// AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
	// 	// AllowedHeaders:   []string{"Content-Type", "Authorization"},
	// 	// AllowCredentials: true, // Set to true if you need to allow cookies or other credentials
	// 	AllowedOrigins:   []string{"*"}, // Replace with your frontend domain
	// 	AllowedMethods:   []string{"*"},
	// 	AllowedHeaders:   []string{"*"},
	// 	AllowCredentials: true, // Set to true if you need to allow cookies or other credentials
	// }
	// router.Use(middleware.CORSMiddleware(corsOptions))

	subrouter := router.PathPrefix("/webauthn").Subrouter()

	webAuthnRouter.beginRegistration(subrouter)
	webAuthnRouter.finishRegistration(subrouter)
	webAuthnRouter.beginLogin(subrouter)
	webAuthnRouter.finishLogin(subrouter)
	webAuthnRouter.registerStatus(subrouter)
}

// @Summary Begin Registration
// @Description Begins a new WebAuthn registration flow
// @Tags WebAuthn
// @Param UserCredential body service.UserCredential true "UserCredential struct"
// @Accept json
// @Produce json
// @Success 200
// @Failure 400 {object} response.WebServiceResponse
// @Failure 500 {object} response.WebServiceResponse
// @Router /webauthn/registration/begin [post]
func (webAuthnRouter *WebAuthnRouter) beginRegistration(router *mux.Router) {
	router.HandleFunc("/registration/begin", webAuthnRouter.webAuthnRestService.BeginRegistration)
}

// @Summary Finish Registration
// @Description Completes a pending WebAuthn registration flow
// @Tags WebAuthn
// @Accept json
// @Consume json
// @Success 200
// @Failure 400 {object} response.WebServiceResponse
// @Failure 401 {object} response.WebServiceResponse
// @Failure 500 {object} response.WebServiceResponse
// @Router /webauthn/registration/finish [post]
func (webAuthnRouter *WebAuthnRouter) finishRegistration(router *mux.Router) {
	router.HandleFunc("/registration/finish", webAuthnRouter.webAuthnRestService.FinishRegistration)
}

// @Summary Begin Login
// @Description Begins a new WebAuthn login flow
// @Tags WebAuthn
// @Accept json
// @Consume json
// @Success 200
// @Failure 400 {object} response.WebServiceResponse
// @Failure 401 {object} response.WebServiceResponse
// @Failure 500 {object} response.WebServiceResponse
// @Router /webauthn/login/begin [post]
func (webAuthnRouter *WebAuthnRouter) beginLogin(router *mux.Router) {
	router.HandleFunc("/login/begin", webAuthnRouter.webAuthnRestService.BeginLogin)
}

// @Summary Finish Login
// @Description Completes a pending WebAuthn login flow
// @Tags WebAuthn
// @Accept json
// @Consume json
// @Success 200
// @Failure 400 {object} response.WebServiceResponse
// @Failure 401 {object} response.WebServiceResponse
// @Failure 500 {object} response.WebServiceResponse
// @Router /webauthn/login/finish [post]
func (webAuthnRouter *WebAuthnRouter) finishLogin(router *mux.Router) {
	router.HandleFunc("/login/finish", webAuthnRouter.webAuthnRestService.FinishLogin)
}

// @Summary Registration Status
// @Description Provides the current registration status for the Conditional UI
// @Tags WebAuthn
// @Accept json
// @Consume json
// @Success 200
// @Failure 400 {object} response.WebServiceResponse
// @Failure 401 {object} response.WebServiceResponse
// @Failure 500 {object} response.WebServiceResponse
// @Router /webauthn/registration/status [get]
func (webAuthnRouter *WebAuthnRouter) registerStatus(router *mux.Router) {
	router.HandleFunc("/registration/status", webAuthnRouter.webAuthnRestService.RegistrationStatus).Methods("GET")
}
