package router

import (
	"net/http"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/rest/acme"
)

type ACMERouter struct {
	restService acme.RestServicer
	WebServiceRouter
}

// Creates a new acme certificate authority router
func NewACMERouter(
	acmeRestService acme.RestServicer) WebServiceRouter {

	return &ACMERouter{
		restService: acmeRestService}
}

// Registers all of the Acme endpoints at the root of the webservice api router (/api/v1)
func (AcmeRouter *ACMERouter) RegisterRoutes(router *mux.Router) {

	subrouter := router.PathPrefix("/acme").Subrouter()

	accountLimiter := acme.NewRateLimiter(5, time.Hour)             // 5 requests per hour per IP for account creation
	nonceLimiter := acme.NewRateLimiter(60, time.Minute)            // 60 requests per minute per IP for nonce generation
	orderLimiter := acme.NewRateLimiter(50, 7*24*time.Hour)         // 50 requests per week per JWS KID for order creation
	finalizeOrderLimiter := acme.NewRateLimiter(50, 7*24*time.Hour) // 50 requests per week per JWS KID for order creation
	orderStatusLimiter := acme.NewRateLimiter(5, time.Minute)       // 5 requests per minute per JWS KID for order status
	orderListLimiter := acme.NewRateLimiter(5, time.Minute)         // 5 requests per minute per JWS KID for order status
	authzLimiter := acme.NewRateLimiter(5, time.Minute)             // 5 requests per minute per JWS KID for authorization
	challengeLimiter := acme.NewRateLimiter(5, time.Minute)         // 5 requests per minute per JWS KID for challenge responses
	certLimiter := acme.NewRateLimiter(10, time.Hour)               // 10 requests per hour per JWS KID for certificate retrieval
	revokeLimiter := acme.NewRateLimiter(5, time.Hour)              // 5 requests per hour per JWS KID for certificate revocation
	directoryLimiter := acme.NewRateLimiter(100, time.Hour)         // 100 requests per hour per IP for directory endpoint

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
}

// @Summary Update account
// @Description Update an existing ACME account
// @Tags ACME
// @Accept json
// @Produce json
// @Param id path string true "Account ID"
// @Param account body UpdateAccountRequest true "Account update request"
// @Success 200 {object} Account
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /acme/accounts/{id} [post]
func (acmeRouter *ACMERouter) accounts(router *mux.Router, rateLimiter *acme.RateLimiter) {
	subrouter := router.PathPrefix("/account/{id}").Subrouter()
	subrouter.HandleFunc("", acmeRouter.restService.AccountHandler).Methods(http.MethodPost)
	subrouter.Use(rateLimiter.MiddlewareFunc(acme.ClientID))
}

// @Summary Get authorization
// @Description Retrieve an ACME authorization
// @Tags ACME
// @Produce json
// @Param id path string true "Authorization ID"
// @Success 200 {object} Authorization
// @Failure 404 {object} ErrorResponse
// @Router /acme/authz/{id} [post]
func (acmeRouter *ACMERouter) authorization(router *mux.Router, rateLimiter *acme.RateLimiter) {
	subrouter := router.PathPrefix("/authz/{id}").Subrouter()
	subrouter.HandleFunc("", acmeRouter.restService.AuthorizationHandler).Methods(http.MethodPost)
	subrouter.Use(rateLimiter.MiddlewareFunc(acme.ClientID))
}

// @Summary Get certificate
// @Description Retrieve an issued certificate
// @Tags ACME
// @Produce octet-stream
// @Param id path string true "Certificate ID"
// @Success 200 {file} string "PEM-encoded certificate"
// @Failure 404 {object} ErrorResponse
// @Router /acme/cert/{id} [post]
func (acmeRouter *ACMERouter) certificate(router *mux.Router, rateLimiter *acme.RateLimiter) {
	subrouter := router.PathPrefix("/cert/{id}").Subrouter()
	subrouter.HandleFunc("", acmeRouter.restService.CertificateHandler).Methods(http.MethodPost)
	subrouter.Use(rateLimiter.MiddlewareFunc(acme.ClientID))
}

// @Summary Respond to challenge
// @Description Respond to an ACME challenge
// @Tags ACME
// @Accept json
// @Produce json
// @Param id path string true "Challenge ID"
// @Param response body ChallengeResponse true "Challenge response"
// @Success 200 {object} Challenge
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /acme/challenge/{id} [post]
func (acmeRouter *ACMERouter) challenge(router *mux.Router, rateLimiter *acme.RateLimiter) {
	subrouter := router.PathPrefix("/challenge/{id}").Subrouter()
	subrouter.HandleFunc("", acmeRouter.restService.ChallengeHandler).Methods(http.MethodPost)
	subrouter.Use(rateLimiter.MiddlewareFunc(acme.ClientID))
}

// @Summary Get ACME directory
// @Description Retrieve the ACME directory containing endpoints
// @Tags ACME
// @Produce json
// @Success 200 {object} DirectoryResponse
// @Router /acme/directory [get]
func (acmeRouter *ACMERouter) directory(router *mux.Router, rateLimiter *acme.RateLimiter) {
	subrouter := router.PathPrefix("/directory").Subrouter()
	subrouter.HandleFunc("", acmeRouter.restService.DirectoryHandler).Methods(http.MethodGet)
	subrouter.Use(rateLimiter.MiddlewareFunc(acme.ClientID))
}

// @Summary Get order
// @Description Retrieve an existing ACME order
// @Tags ACME
// @Produce json
// @Param id path string true "Order ID"
// @Success 200 {object} Order
// @Failure 404 {object} ErrorResponse
// @Router /acme/orders/{id} [post]
func (acmeRouter *ACMERouter) getOrder(router *mux.Router, rateLimiter *acme.RateLimiter) {
	subrouter := router.PathPrefix("/orders/{id}").Subrouter()
	subrouter.HandleFunc("", acmeRouter.restService.OrderHandler).Methods(http.MethodPost)
	subrouter.Use(rateLimiter.MiddlewareFunc(acme.ClientID))
}

// @Summary Create new account
// @Description Create a new ACME account
// @Tags ACME
// @Accept json
// @Produce json
// @Param account body NewAccountRequest true "Account creation request"
// @Success 201 {object} Account
// @Failure 400 {object} ErrorResponse
// @Router /acme/new-account [post]
func (acmeRouter *ACMERouter) newAccount(router *mux.Router, accountLimiter *acme.RateLimiter) {
	subrouter := router.PathPrefix("/new-account").Subrouter()
	subrouter.HandleFunc("", acmeRouter.restService.NewAccountHandler).Methods(http.MethodPost)
	subrouter.Use(accountLimiter.MiddlewareFunc(acme.ClientID))
}

// @Summary Get new nonce
// @Description Retrieve a new nonce for ACME requests
// @Tags ACME
// @Produce plain
// @Success 204 {string} string "Nonce provided in Replay-Nonce header"
// @Router /acme/new-nonce [get]
// @Router /acme/new-nonce [head]
func (acmeRouter *ACMERouter) newNonce(router *mux.Router, rateLimiter *acme.RateLimiter) {
	subrouter := router.PathPrefix("/new-nonce").Subrouter()
	subrouter.HandleFunc("", acmeRouter.restService.NewNonceHandler).Methods(http.MethodHead, http.MethodGet)
	subrouter.Use(rateLimiter.MiddlewareFunc(acme.ClientID))
}

// @Summary Create new order
// @Description Create a new ACME order
// @Tags ACME
// @Accept json
// @Produce json
// @Param order body NewOrderRequest true "Order creation request"
// @Success 201 {object} Order
// @Failure 400 {object} ErrorResponse
// @Router /acme/new-order [post]
func (acmeRouter *ACMERouter) newOrder(router *mux.Router, rateLimiter *acme.RateLimiter) {
	subrouter := router.PathPrefix("/new-order").Subrouter()
	subrouter.HandleFunc("", acmeRouter.restService.NewOrderHandler).Methods(http.MethodPost)
	subrouter.Use(rateLimiter.MiddlewareFunc(acme.ClientID))
}

// @Summary List orders for account
// @Description Retrieve a list of orders for an ACME account
// @Tags ACME
// @Accept json
// @Produce json
// @Param id path string true "Account ID"
// @Success 200 {array} Order
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /acme/orders [post]
// // @Router /acme/accounts/{id}/orders [post]
func (acmeRouter *ACMERouter) listOrders(router *mux.Router, rateLimiter *acme.RateLimiter) {
	subrouter := router.PathPrefix("/orders").Subrouter()
	subrouter.HandleFunc("", acmeRouter.restService.OrdersListHandler).Methods(http.MethodPost)
	subrouter.Use(rateLimiter.MiddlewareFunc(acme.ClientID))
}

// @Summary Finalize order
// @Description Finalize an ACME order
// @Tags ACME
// @Accept json
// @Produce json
// @Param id path string true "Order ID"
// @Param finalize body FinalizeRequest true "Finalization request"
// @Success 200 {object} Order
// @Failure 400 {object} ErrorResponse
// @Failure 404 {object} ErrorResponse
// @Router /acme/orders/{id}/finalize [post]
func (acmeRouter *ACMERouter) finalizeOrder(router *mux.Router, rateLimiter *acme.RateLimiter) {
	subrouter := router.PathPrefix("/orders/{id}/finalize").Subrouter()
	subrouter.HandleFunc("", acmeRouter.restService.OrderFinalizeHandler).Methods(http.MethodPost)
	subrouter.Use(rateLimiter.MiddlewareFunc(acme.ClientID))
}

// @Summary Revoke certificate
// @Description Revoke an issued certificate
// @Tags ACME
// @Accept json
// @Produce json
// @Param revocation body RevocationRequest true "Revocation request"
// @Success 200 {object} RevocationResponse
// @Failure 400 {object} ErrorResponse
// @Router /acme/revoke-cert [post]
func (acmeRouter *ACMERouter) revokeCert(router *mux.Router, rateLimiter *acme.RateLimiter) {
	subrouter := router.PathPrefix("/revoke-cert").Subrouter()
	subrouter.HandleFunc("", acmeRouter.restService.RevokeCertHandler).Methods(http.MethodPost)
	subrouter.Use(rateLimiter.MiddlewareFunc(acme.ClientID))
}

// @Summary Key change
// @Description Change the key for an ACME account as per RFC 8555 Section 7.3.5.
// @Tags ACME
// @Accept json
// @Produce json
// @Param body body acme.KeyChangeRequest true "Key change request body"
// @Success 200 {object} KeyChangeResponse "Key updated successfully"
// @Failure 400 {object} ErrorResponse "Invalid request"
// @Failure 403 {object} ErrorResponse "Old key does not match the current account key"
// @Failure 500 {object} ErrorResponse "Internal server error"
// @Router /acme/key-change [post]
func (acmeRouter *ACMERouter) keyChange(router *mux.Router, rateLimiter *acme.RateLimiter) {
	subrouter := router.PathPrefix("/key-change").Subrouter()
	subrouter.HandleFunc("", acmeRouter.restService.KeyChangeHandler).Methods(http.MethodPost)
	subrouter.Use(rateLimiter.MiddlewareFunc(acme.ClientID))
}
