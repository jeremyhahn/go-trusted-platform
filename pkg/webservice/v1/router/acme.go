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
	"net/http"
	"time"

	trustedca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/acme"

	"github.com/gorilla/mux"
)

type ACMERouter struct {
	restService trustedca.ACMERestServicer
	WebServiceRouter
}

// Creates a new acme certificate authority router
func NewACMERouter(
	acmeRestService trustedca.ACMERestServicer) WebServiceRouter {

	return &ACMERouter{
		restService: acmeRestService}
}

// Registers all of the Acme endpoints at the root of the webservice api router (/api/v1)
func (AcmeRouter *ACMERouter) RegisterRoutes(router *mux.Router) {

	subrouter := router.PathPrefix("/acme").Subrouter()

	// Rate limiters - generous limits for development/testing
	// DEFERRED: Make rate limits configurable via config file. Blocked by: ACME config schema design.
	accountLimiter := trustedca.NewACMERateLimiter(100, time.Hour)       // 100 requests per hour per IP for account creation
	nonceLimiter := trustedca.NewACMERateLimiter(1000, time.Minute)      // 1000 requests per minute per IP for nonce generation
	orderLimiter := trustedca.NewACMERateLimiter(500, time.Hour)         // 500 requests per hour per JWS KID for order creation
	finalizeOrderLimiter := trustedca.NewACMERateLimiter(500, time.Hour) // 500 requests per hour per JWS KID for order finalization
	orderStatusLimiter := trustedca.NewACMERateLimiter(100, time.Minute) // 100 requests per minute per JWS KID for order status
	orderListLimiter := trustedca.NewACMERateLimiter(100, time.Minute)   // 100 requests per minute per JWS KID for order listing
	authzLimiter := trustedca.NewACMERateLimiter(100, time.Minute)       // 100 requests per minute per JWS KID for authorization
	challengeLimiter := trustedca.NewACMERateLimiter(100, time.Minute)   // 100 requests per minute per JWS KID for challenge responses
	certLimiter := trustedca.NewACMERateLimiter(100, time.Hour)          // 100 requests per hour per JWS KID for certificate retrieval
	revokeLimiter := trustedca.NewACMERateLimiter(50, time.Hour)         // 50 requests per hour per JWS KID for certificate revocation
	directoryLimiter := trustedca.NewACMERateLimiter(1000, time.Hour)    // 1000 requests per hour per IP for directory endpoint

	AcmeRouter.bundle(subrouter)
	AcmeRouter.directory(subrouter, directoryLimiter)
	AcmeRouter.newNonce(subrouter, nonceLimiter)
	AcmeRouter.newAccount(subrouter, accountLimiter)
	AcmeRouter.newOrder(subrouter, orderLimiter)
	AcmeRouter.authorization(subrouter, authzLimiter)
	AcmeRouter.finalizeOrder(subrouter, finalizeOrderLimiter)
	AcmeRouter.certificate(subrouter, certLimiter)
	AcmeRouter.revokeCert(subrouter, revokeLimiter)
	AcmeRouter.accounts(subrouter, accountLimiter)
	AcmeRouter.challenge(subrouter, challengeLimiter)
	AcmeRouter.getOrder(subrouter, orderStatusLimiter)
	AcmeRouter.listOrders(subrouter, orderListLimiter)
	AcmeRouter.keyChange(subrouter, accountLimiter)
}

// @Summary Update account
// @Description Update an existing ACME account
// @Tags ACME
// @Accept json
// @Produce json
// @Param id path string true "Account ID"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /acme/accounts/{id} [post]
func (acmeRouter *ACMERouter) accounts(router *mux.Router, rateLimiter *trustedca.ACMERateLimiter) {
	subrouter := router.PathPrefix("/account/{id}").Subrouter()
	subrouter.HandleFunc("", acmeRouter.restService.AccountHandler).Methods(http.MethodPost)
	subrouter.Use(rateLimiter.MiddlewareFunc(trustedca.ACMEClientID))
}

// @Summary Get authorization
// @Description Retrieve an ACME authorization
// @Tags ACME
// @Produce json
// @Param id path string true "Authorization ID"
// @Success 200 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /acme/authz/{id} [post]
func (acmeRouter *ACMERouter) authorization(router *mux.Router, rateLimiter *trustedca.ACMERateLimiter) {
	subrouter := router.PathPrefix("/authz/{id}").Subrouter()
	subrouter.HandleFunc("", acmeRouter.restService.AuthorizationHandler).Methods(http.MethodGet, http.MethodPost)
	subrouter.Use(rateLimiter.MiddlewareFunc(trustedca.ACMEClientID))
}

// @Summary Get certificate
// @Description Retrieve an issued certificate
// @Tags ACME
// @Produce octet-stream
// @Param id path string true "Certificate ID"
// @Success 200 {file} string "PEM-encoded certificate"
// @Failure 404 {object} map[string]interface{}
// @Router /acme/cert/{id} [post]
func (acmeRouter *ACMERouter) certificate(router *mux.Router, rateLimiter *trustedca.ACMERateLimiter) {
	subrouter := router.PathPrefix("/cert/{id}").Subrouter()
	subrouter.HandleFunc("", acmeRouter.restService.CertificateHandler).Methods(http.MethodPost)
	subrouter.Use(rateLimiter.MiddlewareFunc(trustedca.ACMEClientID))
}

// @Summary Respond to challenge
// @Description Respond to an ACME challenge
// @Tags ACME
// @Accept json
// @Produce json
// @Param id path string true "Challenge ID"
// @Param response body map[string]interface{} true "Challenge response"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /acme/challenge/{id} [post]
func (acmeRouter *ACMERouter) challenge(router *mux.Router, rateLimiter *trustedca.ACMERateLimiter) {
	subrouter := router.PathPrefix("/challenge/{id}").Subrouter()
	subrouter.HandleFunc("", acmeRouter.restService.ChallengeHandler).Methods(http.MethodPost)
	subrouter.Use(rateLimiter.MiddlewareFunc(trustedca.ACMEClientID))
}

// @Summary Get ACME directory
// @Description Retrieve the ACME directory containing endpoints
// @Tags ACME
// @Produce json
// // @Success 200 {object} acme.Directory
// @Router /acme/directory [get]
func (acmeRouter *ACMERouter) directory(router *mux.Router, rateLimiter *trustedca.ACMERateLimiter) {
	subrouter := router.PathPrefix("/directory").Subrouter()
	subrouter.HandleFunc("", acmeRouter.restService.DirectoryHandler).Methods(http.MethodGet)
	subrouter.Use(rateLimiter.MiddlewareFunc(trustedca.ACMEClientID))
}

// @Summary Get order
// @Description Retrieve an existing ACME order
// @Tags ACME
// @Produce json
// @Param id path string true "Order ID"
// @Success 200 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /acme/order/{id} [post]
func (acmeRouter *ACMERouter) getOrder(router *mux.Router, rateLimiter *trustedca.ACMERateLimiter) {
	subrouter := router.PathPrefix("/order/{id}").Subrouter()
	subrouter.HandleFunc("", acmeRouter.restService.OrderHandler).Methods(http.MethodPost)
	subrouter.Use(rateLimiter.MiddlewareFunc(trustedca.ACMEClientID))
}

// @Summary Create new account
// @Description Create a new ACME account
// @Tags ACME
// @Accept json
// @Produce json
// @Param account body map[string]interface{} true "Account creation request"
// @Success 201 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Router /acme/new-account [post]
func (acmeRouter *ACMERouter) newAccount(router *mux.Router, accountLimiter *trustedca.ACMERateLimiter) {
	subrouter := router.PathPrefix("/new-account").Subrouter()
	subrouter.HandleFunc("", acmeRouter.restService.NewAccountHandler).Methods(http.MethodPost)
	subrouter.Use(accountLimiter.MiddlewareFunc(trustedca.ACMEClientID))
}

// @Summary Get new nonce
// @Description Retrieve a new nonce for ACME requests
// @Tags ACME
// @Produce plain
// @Success 204 {string} string "Nonce provided in Replay-Nonce header"
// @Router /acme/new-nonce [get]
// @Router /acme/new-nonce [head]
func (acmeRouter *ACMERouter) newNonce(router *mux.Router, rateLimiter *trustedca.ACMERateLimiter) {
	subrouter := router.PathPrefix("/new-nonce").Subrouter()
	subrouter.HandleFunc("", acmeRouter.restService.NewNonceHandler).Methods(http.MethodHead, http.MethodGet)
	subrouter.Use(rateLimiter.MiddlewareFunc(trustedca.ACMEClientID))
}

// @Summary Create new order
// @Description Create a new ACME order
// @Tags ACME
// @Accept json
// @Produce json
// @Param order body map[string]interface{} true "Order creation request"
// @Success 201 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Router /acme/new-order [post]
func (acmeRouter *ACMERouter) newOrder(router *mux.Router, rateLimiter *trustedca.ACMERateLimiter) {
	subrouter := router.PathPrefix("/new-order").Subrouter()
	subrouter.HandleFunc("", acmeRouter.restService.NewOrderHandler).Methods(http.MethodPost)
	subrouter.Use(rateLimiter.MiddlewareFunc(trustedca.ACMEClientID))
}

// @Summary List orders for account
// @Description Retrieve a list of orders for an ACME account
// @Tags ACME
// @Accept json
// @Produce json
// @Param id path string true "Account ID"
// @Success 200 {array} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /acme/orders [post]
// // @Router /acme/accounts/{id}/orders [post]
func (acmeRouter *ACMERouter) listOrders(router *mux.Router, rateLimiter *trustedca.ACMERateLimiter) {
	subrouter := router.PathPrefix("/orders").Subrouter()
	subrouter.HandleFunc("", acmeRouter.restService.OrdersListHandler).Methods(http.MethodPost)
	subrouter.Use(rateLimiter.MiddlewareFunc(trustedca.ACMEClientID))
}

// @Summary Finalize order
// @Description Finalize an ACME order
// @Tags ACME
// @Accept json
// @Produce json
// @Param id path string true "Order ID"
// // @Param finalize body acme.OrderFinalizeRequest true "Finalization request"
// @Success 200 {object} map[string]interface{}
// @Failure 400 {object} map[string]interface{}
// @Failure 404 {object} map[string]interface{}
// @Router /acme/order/{id}/finalize [post]
func (acmeRouter *ACMERouter) finalizeOrder(router *mux.Router, rateLimiter *trustedca.ACMERateLimiter) {
	subrouter := router.PathPrefix("/order/{id}/finalize").Subrouter()
	subrouter.HandleFunc("", acmeRouter.restService.OrderFinalizeHandler).Methods(http.MethodPost)
	subrouter.Use(rateLimiter.MiddlewareFunc(trustedca.ACMEClientID))
}

// @Summary Revoke certificate
// @Description Revoke an issued certificate
// @Tags ACME
// @Accept json
// @Produce json
// // @Param revocation body RevocationRequest true "Revocation request"
// @Success 200
// @Failure 400 {object} map[string]interface{}
// @Router /acme/revoke-cert [post]
func (acmeRouter *ACMERouter) revokeCert(router *mux.Router, rateLimiter *trustedca.ACMERateLimiter) {
	subrouter := router.PathPrefix("/revoke-cert").Subrouter()
	subrouter.HandleFunc("", acmeRouter.restService.RevokeCertHandler).Methods(http.MethodPost)
	subrouter.Use(rateLimiter.MiddlewareFunc(trustedca.ACMEClientID))
}

// @Summary Key change
// @Description Change the key for an ACME account as per RFC 8555 Section 7.3.5.
// @Tags ACME
// @Accept json
// @Produce json
// @Success 200 {object} map[string]interface{} "Key updated successfully"
// @Failure 400 {object} map[string]interface{} "Invalid request"
// @Failure 403 {object} map[string]interface{} "Old key does not match the current account key"
// @Failure 500 {object} map[string]interface{} "Internal server error"
// @Router /acme/key-change [post]
func (acmeRouter *ACMERouter) keyChange(router *mux.Router, rateLimiter *trustedca.ACMERateLimiter) {
	subrouter := router.PathPrefix("/key-change").Subrouter()
	subrouter.HandleFunc("", acmeRouter.restService.KeyChangeHandler).Methods(http.MethodPost)
	subrouter.Use(rateLimiter.MiddlewareFunc(trustedca.ACMEClientID))
}

// NON-RFC 8555 Endpoints

// @Summary Get CA Bundle
// @Description Retrieve the Certificate Authority certificate bundle
// @Tags ACME
// @Produce plain
// @Success 204 {string} string "PEM encoded CA bundle"
// @Router /acme/ca-bundle/{storeType}/{keyAlgo} [get]
func (acmeRouter *ACMERouter) bundle(router *mux.Router) {
	subrouter := router.PathPrefix("/ca-bundle").Subrouter()
	subrouter.HandleFunc("/{storeType}/{keyAlgo}", acmeRouter.restService.CABundleHandler).Methods(http.MethodGet)
	subrouter.HandleFunc("/{storeType}", acmeRouter.restService.CABundleHandler).Methods(http.MethodGet)
	subrouter.HandleFunc("", acmeRouter.restService.CABundleHandler).Methods(http.MethodGet)
}
