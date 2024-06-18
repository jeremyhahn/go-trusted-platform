package router

import (
	"fmt"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/app"
	"github.com/jeremyhahn/go-trusted-platform/webservice/v1/middleware"
)

type AuthenticationRouter struct {
	middleware middleware.AuthMiddleware
	WebServiceRouter
}

// Creates a new web service authentication router
func NewAuthenticationRouter(
	app *app.App,
	middleware middleware.AuthMiddleware) WebServiceRouter {

	return &AuthenticationRouter{
		middleware: middleware}
}

// Registers all of the authentication endpoints at the root of the webservice (/api/v1)
func (authenticationRouter *AuthenticationRouter) RegisterRoutes(router *mux.Router, baseURI string) []string {
	return []string{
		authenticationRouter.login(router, baseURI),
		authenticationRouter.refreshToken(router, baseURI)}
}

// @Summary Authenticate and obtain JWT
// @Description Authenticate a user and returns a new JWT
// @Tags Authentication
// @Param UserCredentials body service.UserCredentials true "UserCredentials struct"
// @Accept json
// @Produce json
// @Success 200 {object} rest.JsonWebToken
// @Failure 400 {object} rest.JsonWebToken
// @Failure 403 {object} rest.JsonWebToken
// @Failure 500 {object} rest.JsonWebToken
// @Router /login [post]
func (authenticationRouter *AuthenticationRouter) login(router *mux.Router, baseURI string) string {
	login := fmt.Sprintf("%s/login", baseURI)
	router.HandleFunc(login, authenticationRouter.middleware.GenerateToken)
	return login
}

// @Summary Refresh JWT
// @Description Returns a new JWT token with a new, extended expiration date
// @Tags Authentication
// @Accept json
// @Consume json
// @Success 200 {object} rest.JsonWebToken
// @Failure 400 {object} rest.JsonWebToken
// @Failure 401 {object} rest.JsonWebToken
// @Failure 500 {object} rest.JsonWebToken
// @Router /login/refresh [get]
// @Security JWT
func (authenticationRouter *AuthenticationRouter) refreshToken(router *mux.Router, baseURI string) string {
	refreshToken := fmt.Sprintf("%s/login/refresh", baseURI)
	router.HandleFunc(refreshToken, authenticationRouter.middleware.RefreshToken)
	return refreshToken
}
