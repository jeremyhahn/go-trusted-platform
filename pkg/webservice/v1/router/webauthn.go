package router

import (
	"fmt"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest"
)

type WebAuthnRouter struct {
	baseAuthURI         string
	middleware          middleware.JsonWebTokenMiddleware
	webAuthnRestService rest.WebAuthnRestServicer
	WebServiceRouter
}

// Creates a new webauthn router
func NewWebAuthnRouter(
	middleware middleware.JsonWebTokenMiddleware,
	webAuthnRestService rest.WebAuthnRestServicer) WebServiceRouter {

	return &WebAuthnRouter{
		middleware:          middleware,
		webAuthnRestService: webAuthnRestService}
}

// Registers all of the webauthn endpoints at the root of the webservice (/api/v1/webauthn)
func (webAuthnRouter *WebAuthnRouter) RegisterRoutes(router *mux.Router, baseURI string) []string {

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

	webAuthnRouter.baseAuthURI = fmt.Sprintf("%s/webauthn", baseURI)
	return []string{
		webAuthnRouter.beginRegistration(router, webAuthnRouter.baseAuthURI),
		webAuthnRouter.finishRegistration(router, webAuthnRouter.baseAuthURI),
		webAuthnRouter.beginLogin(router, webAuthnRouter.baseAuthURI),
		webAuthnRouter.finishLogin(router, webAuthnRouter.baseAuthURI),
		webAuthnRouter.registerStatus(router, webAuthnRouter.baseAuthURI)}
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
func (webAuthnRouter *WebAuthnRouter) beginRegistration(router *mux.Router, baseURI string) string {
	beginRegistration := fmt.Sprintf("%s/registration/begin", baseURI)
	router.HandleFunc(beginRegistration, webAuthnRouter.webAuthnRestService.BeginRegistration)
	return beginRegistration
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
func (webAuthnRouter *WebAuthnRouter) finishRegistration(router *mux.Router, baseURI string) string {
	finishRegistration := fmt.Sprintf("%s/registration/finish", baseURI)
	router.HandleFunc(finishRegistration, webAuthnRouter.webAuthnRestService.FinishRegistration)
	return finishRegistration
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
// @Router /webauthn/registration/finish [post]
func (webAuthnRouter *WebAuthnRouter) beginLogin(router *mux.Router, baseURI string) string {
	beginLogin := fmt.Sprintf("%s/login/begin", baseURI)
	router.HandleFunc(beginLogin, webAuthnRouter.webAuthnRestService.BeginLogin)
	return beginLogin
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
// @Router /webauthn/registration/finish [post]
func (webAuthnRouter *WebAuthnRouter) finishLogin(router *mux.Router, baseURI string) string {
	finishLogin := fmt.Sprintf("%s/login/finish", baseURI)
	router.HandleFunc(finishLogin, webAuthnRouter.webAuthnRestService.FinishLogin)
	return finishLogin
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
func (webAuthnRouter *WebAuthnRouter) registerStatus(router *mux.Router, baseURI string) string {
	statusEndpoint := fmt.Sprintf("%s/registration/status", baseURI)
	router.HandleFunc(statusEndpoint, webAuthnRouter.webAuthnRestService.RegistrationStatus).Methods("GET")
	return statusEndpoint
}
