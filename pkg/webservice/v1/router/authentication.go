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

package router

import (
	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
)

type AuthenticationRouter struct {
	middleware middleware.JsonWebTokenMiddleware
	WebServiceRouter
}

// Creates a new web service authentication router
func NewAuthenticationRouter(
	middleware middleware.JsonWebTokenMiddleware) WebServiceRouter {

	return &AuthenticationRouter{
		middleware: middleware}
}

// Registers all of the authentication endpoints at the root of the webservice (/api/v1)
func (authenticationRouter *AuthenticationRouter) RegisterRoutes(router *mux.Router) {
	authenticationRouter.login(router)
	authenticationRouter.refreshToken(router)
}

// @Summary Authenticate and obtain JWT
// @Description Authenticate a user and returns a new JWT
// @Tags Authentication
// @Param UserCredential body service.UserCredential true "UserCredential struct"
// @Accept json
// @Produce json
// @Success 200 {object} jwt.TokenClaims
// @Failure 400 {object} jwt.TokenClaims
// @Failure 403 {object} jwt.TokenClaims
// @Failure 500 {object} jwt.TokenClaims
// @Router /login [post]
func (authenticationRouter *AuthenticationRouter) login(router *mux.Router) {
	router.HandleFunc("/login", authenticationRouter.middleware.GenerateToken)
}

// @Summary Refresh JWT
// @Description Returns a new JWT token with a new, extended expiration date
// @Tags Authentication
// @Accept json
// @Consume json
// @Success 200 {object} jwt.TokenClaims
// @Failure 400 {object} jwt.TokenClaims
// @Failure 401 {object} jwt.TokenClaims
// @Failure 500 {object} jwt.TokenClaims
// @Router /login/refresh [get]
// @Security JWT
func (authenticationRouter *AuthenticationRouter) refreshToken(router *mux.Router) {
	router.HandleFunc("/login/refresh", authenticationRouter.middleware.RefreshToken)
}
