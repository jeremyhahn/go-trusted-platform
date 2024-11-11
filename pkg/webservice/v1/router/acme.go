package router

import (
	"net/http"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/server"
	"github.com/jeremyhahn/go-trusted-platform/pkg/acme/server/handlers"

	"github.com/gorilla/mux"
)

type ACMERouter struct {
	restService handlers.RestServicer
	WebServiceRouter
}

// Creates a new acme certificate authority router
func NewACMERouter(
	acmeRestService handlers.RestServicer) WebServiceRouter {

	return &ACMERouter{
		restService: acmeRestService}
}

// Registers all of the Acme endpoints at the root of the webservice api router (/api/v1)
func (AcmeRouter *ACMERouter) RegisterRoutes(router *mux.Router) {

	subrouter := router.PathPrefix("/acme").Subrouter()

	accountLimiter := server.NewRateLimiter(5, time.Hour)             // 5 requests per hour per IP for account creation
	nonceLimiter := server.NewRateLimiter(60, time.Minute)            // 60 requests per minute per IP for nonce generation
	orderLimiter := server.NewRateLimiter(50, 7*24*time.Hour)         // 50 requests per week per JWS KID for order creation
	finalizeOrderLimiter := server.NewRateLimiter(50, 7*24*time.Hour) // 50 requests per week per JWS KID for order creation
	orderStatusLimiter := server.NewRateLimiter(10, time.Minute)      // 10 requests per minute per JWS KID for order status
	orderListLimiter := server.NewRateLimiter(10, time.Minute)        // 10 requests per minute per JWS KID for order status
	authzLimiter := server.NewRateLimiter(10, time.Minute)            // 10 requests per minute per JWS KID for authorization
	challengeLimiter := server.NewRateLimiter(10, time.Minute)        // 10 requests per minute per JWS KID for challenge responses
	certLimiter := server.NewRateLimiter(10, time.Hour)               // 10 requests per hour per JWS KID for certificate retrieval
	revokeLimiter := server.NewRateLimiter(5, time.Hour)              // 5 requests per hour per JWS KID for certificate revocation
	directoryLimiter := server.NewRateLimiter(100, time.Hour)         // 100 requests per hour per IP for directory endpoint

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
// // @Param account body UpdateAccountRequest true "Account update request"
// @Success 200 {object} entities.ACMEAccount
// @Failure 400 {object} entities.Error
// @Failure 404 {object} entities.Error
// @Router /acme/accounts/{id} [post]
func (acmeRouter *ACMERouter) accounts(router *mux.Router, rateLimiter *server.RateLimiter) {
	subrouter := router.PathPrefix("/account/{id}").Subrouter()
	subrouter.HandleFunc("", acmeRouter.restService.AccountHandler).Methods(http.MethodPost)
	subrouter.Use(rateLimiter.MiddlewareFunc(server.ClientID))
}

// @Summary Get authorization
// @Description Retrieve an ACME authorization
// @Tags ACME
// @Produce json
// @Param id path string true "Authorization ID"
// @Success 200 {object} entities.ACMEAuthorization
// @Failure 404 {object} entities.Error
// @Router /acme/authz/{id} [post]
func (acmeRouter *ACMERouter) authorization(router *mux.Router, rateLimiter *server.RateLimiter) {
	subrouter := router.PathPrefix("/authz/{id}").Subrouter()
	subrouter.HandleFunc("", acmeRouter.restService.AuthorizationHandler).Methods(http.MethodGet, http.MethodPost)
	subrouter.Use(rateLimiter.MiddlewareFunc(server.ClientID))
}

// @Summary Get certificate
// @Description Retrieve an issued certificate
// @Tags ACME
// @Produce octet-stream
// @Param id path string true "Certificate ID"
// @Success 200 {file} string "PEM-encoded certificate"
// @Failure 404 {object} entities.Error
// @Router /acme/cert/{id} [post]
func (acmeRouter *ACMERouter) certificate(router *mux.Router, rateLimiter *server.RateLimiter) {
	subrouter := router.PathPrefix("/cert/{id}").Subrouter()
	subrouter.HandleFunc("", acmeRouter.restService.CertificateHandler).Methods(http.MethodPost)
	subrouter.Use(rateLimiter.MiddlewareFunc(server.ClientID))
}

// @Summary Respond to challenge
// @Description Respond to an ACME challenge
// @Tags ACME
// @Accept json
// @Produce json
// @Param id path string true "Challenge ID"
// @Param response body entities.ACMEChallenge true "Challenge response"
// @Success 200 {object} entities.ACMEChallenge
// @Failure 400 {object} entities.Error
// @Failure 404 {object} entities.Error
// @Router /acme/challenge/{id} [post]
func (acmeRouter *ACMERouter) challenge(router *mux.Router, rateLimiter *server.RateLimiter) {
	subrouter := router.PathPrefix("/challenge/{id}").Subrouter()
	subrouter.HandleFunc("", acmeRouter.restService.ChallengeHandler).Methods(http.MethodPost)
	subrouter.Use(rateLimiter.MiddlewareFunc(server.ClientID))
}

// @Summary Get ACME directory
// @Description Retrieve the ACME directory containing endpoints
// @Tags ACME
// @Produce json
// // @Success 200 {object} acme.Directory
// @Router /acme/directory [get]
func (acmeRouter *ACMERouter) directory(router *mux.Router, rateLimiter *server.RateLimiter) {
	subrouter := router.PathPrefix("/directory").Subrouter()
	subrouter.HandleFunc("", acmeRouter.restService.DirectoryHandler).Methods(http.MethodGet)
	subrouter.Use(rateLimiter.MiddlewareFunc(server.ClientID))
}

// @Summary Get order
// @Description Retrieve an existing ACME order
// @Tags ACME
// @Produce json
// @Param id path string true "Order ID"
// @Success 200 {object} entities.ACMEOrder
// @Failure 404 {object} entities.Error
// @Router /acme/orders/{id} [post]
func (acmeRouter *ACMERouter) getOrder(router *mux.Router, rateLimiter *server.RateLimiter) {
	subrouter := router.PathPrefix("/orders/{id}").Subrouter()
	subrouter.HandleFunc("", acmeRouter.restService.OrderHandler).Methods(http.MethodPost)
	subrouter.Use(rateLimiter.MiddlewareFunc(server.ClientID))
}

// @Summary Create new account
// @Description Create a new ACME account
// @Tags ACME
// @Accept json
// @Produce json
// @Param account body entities.ACMEAccount true "Account creation request"
// @Success 201 {object} entities.ACMEAccount
// @Failure 400 {object} entities.Error
// @Router /acme/new-account [post]
func (acmeRouter *ACMERouter) newAccount(router *mux.Router, accountLimiter *server.RateLimiter) {
	subrouter := router.PathPrefix("/new-account").Subrouter()
	subrouter.HandleFunc("", acmeRouter.restService.NewAccountHandler).Methods(http.MethodPost)
	subrouter.Use(accountLimiter.MiddlewareFunc(server.ClientID))
}

// @Summary Get new nonce
// @Description Retrieve a new nonce for ACME requests
// @Tags ACME
// @Produce plain
// @Success 204 {string} string "Nonce provided in Replay-Nonce header"
// @Router /acme/new-nonce [get]
// @Router /acme/new-nonce [head]
func (acmeRouter *ACMERouter) newNonce(router *mux.Router, rateLimiter *server.RateLimiter) {
	subrouter := router.PathPrefix("/new-nonce").Subrouter()
	subrouter.HandleFunc("", acmeRouter.restService.NewNonceHandler).Methods(http.MethodHead, http.MethodGet)
	subrouter.Use(rateLimiter.MiddlewareFunc(server.ClientID))
}

// @Summary Create new order
// @Description Create a new ACME order
// @Tags ACME
// @Accept json
// @Produce json
// @Param order body entities.ACMEOrder true "Order creation request"
// @Success 201 {object} entities.ACMEOrder
// @Failure 400 {object} entities.Error
// @Router /acme/new-order [post]
func (acmeRouter *ACMERouter) newOrder(router *mux.Router, rateLimiter *server.RateLimiter) {
	subrouter := router.PathPrefix("/new-order").Subrouter()
	subrouter.HandleFunc("", acmeRouter.restService.NewOrderHandler).Methods(http.MethodPost)
	subrouter.Use(rateLimiter.MiddlewareFunc(server.ClientID))
}

// @Summary List orders for account
// @Description Retrieve a list of orders for an ACME account
// @Tags ACME
// @Accept json
// @Produce json
// @Param id path string true "Account ID"
// @Success 200 {array} entities.ACMEOrder
// @Failure 400 {object} entities.Error
// @Failure 404 {object} entities.Error
// @Router /acme/orders [post]
// // @Router /acme/accounts/{id}/orders [post]
func (acmeRouter *ACMERouter) listOrders(router *mux.Router, rateLimiter *server.RateLimiter) {
	subrouter := router.PathPrefix("/orders").Subrouter()
	subrouter.HandleFunc("", acmeRouter.restService.OrdersListHandler).Methods(http.MethodPost)
	subrouter.Use(rateLimiter.MiddlewareFunc(server.ClientID))
}

// @Summary Finalize order
// @Description Finalize an ACME order
// @Tags ACME
// @Accept json
// @Produce json
// @Param id path string true "Order ID"
// // @Param finalize body acme.OrderFinalizeRequest true "Finalization request"
// @Success 200 {object} entities.ACMEOrder
// @Failure 400 {object} entities.Error
// @Failure 404 {object} entities.Error
// @Router /acme/orders/{id}/finalize [post]
func (acmeRouter *ACMERouter) finalizeOrder(router *mux.Router, rateLimiter *server.RateLimiter) {
	subrouter := router.PathPrefix("/orders/{id}/finalize").Subrouter()
	subrouter.HandleFunc("", acmeRouter.restService.OrderFinalizeHandler).Methods(http.MethodPost)
	subrouter.Use(rateLimiter.MiddlewareFunc(server.ClientID))
}

// @Summary Revoke certificate
// @Description Revoke an issued certificate
// @Tags ACME
// @Accept json
// @Produce json
// // @Param revocation body RevocationRequest true "Revocation request"
// @Success 200
// @Failure 400 {object} entities.Error
// @Router /acme/revoke-cert [post]
func (acmeRouter *ACMERouter) revokeCert(router *mux.Router, rateLimiter *server.RateLimiter) {
	subrouter := router.PathPrefix("/revoke-cert").Subrouter()
	subrouter.HandleFunc("", acmeRouter.restService.RevokeCertHandler).Methods(http.MethodPost)
	subrouter.Use(rateLimiter.MiddlewareFunc(server.ClientID))
}

// @Summary Key change
// @Description Change the key for an ACME account as per RFC 8555 Section 7.3.5.
// @Tags ACME
// @Accept json
// @Produce json
// @Param body body handlers.KeyChangeRequest true "Key change request body"
// @Success 200 {object} handlers.KeyChangeResponse "Key updated successfully"
// @Failure 400 {object} entities.Error "Invalid request"
// @Failure 403 {object} entities.Error "Old key does not match the current account key"
// @Failure 500 {object} entities.Error "Internal server error"
// @Router /acme/key-change [post]
func (acmeRouter *ACMERouter) keyChange(router *mux.Router, rateLimiter *server.RateLimiter) {
	subrouter := router.PathPrefix("/key-change").Subrouter()
	subrouter.HandleFunc("", acmeRouter.restService.KeyChangeHandler).Methods(http.MethodPost)
	subrouter.Use(rateLimiter.MiddlewareFunc(server.ClientID))
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
