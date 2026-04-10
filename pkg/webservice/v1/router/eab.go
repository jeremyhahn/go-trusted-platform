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

	"github.com/codegangsta/negroni"
	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/eab"
)

// EABRouter handles EAB credential-related routes.
type EABRouter struct {
	handler          eab.RestHandler
	tenantMiddleware func(http.Handler) http.Handler
	WebServiceRouter
}

// NewEABRouter creates a new EAB router.
func NewEABRouter(
	handler eab.RestHandler,
	tenantMiddleware func(http.Handler) http.Handler,
) WebServiceRouter {
	return &EABRouter{
		handler:          handler,
		tenantMiddleware: tenantMiddleware,
	}
}

// RegisterRoutes registers all EAB credential routes.
func (r *EABRouter) RegisterRoutes(router *mux.Router) {
	// Protected routes (require auth + tenant context)
	r.createCredential(router)
	r.listCredentials(router)
	r.getCredential(router)
	r.getCredentialByKeyID(router)
	r.revokeCredential(router)
	r.deleteCredential(router)
	r.getQRCode(router)
	r.getEnrollmentURL(router)

	// Validation endpoint (may be called by ACME server)
	r.validateCredential(router)
}

// POST /api/v1/eab/credentials - Create EAB credential (owner only)
// @Summary Create a new EAB credential
// @Description Creates a new EAB credential for device enrollment (owner only)
// @Tags EAB
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer token"
// @Param credential body eab.CreateCredentialRequest true "Credential request"
// @Success 201 {object} eab.CredentialResponse
// @Failure 400 {object} response.WebServiceResponse
// @Failure 401 {object} response.WebServiceResponse
// @Failure 403 {object} response.WebServiceResponse
// @Failure 500 {object} response.WebServiceResponse
// @Router /eab/credentials [post]
func (r *EABRouter) createCredential(router *mux.Router) {
	handler := http.HandlerFunc(r.handler.Create)
	wrapped := r.tenantMiddleware(handler)
	router.Handle("/eab/credentials", negroni.New(
		negroni.Wrap(wrapped),
	)).Methods("POST")
}

// GET /api/v1/eab/credentials - List EAB credentials
// @Summary List EAB credentials
// @Description Lists all EAB credentials for the current tenant or filtered by profile_id
// @Tags EAB
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer token"
// @Param profile_id query integer false "Profile ID to filter by"
// @Success 200 {object} eab.CredentialListResponse
// @Failure 400 {object} response.WebServiceResponse
// @Failure 401 {object} response.WebServiceResponse
// @Failure 500 {object} response.WebServiceResponse
// @Router /eab/credentials [get]
func (r *EABRouter) listCredentials(router *mux.Router) {
	handler := http.HandlerFunc(r.handler.List)
	wrapped := r.tenantMiddleware(handler)
	router.Handle("/eab/credentials", negroni.New(
		negroni.Wrap(wrapped),
	)).Methods("GET")
}

// GET /api/v1/eab/credentials/{id} - Get EAB credential by ID
// @Summary Get EAB credential by ID
// @Description Retrieves an EAB credential by its ID
// @Tags EAB
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer token"
// @Param id path integer true "Credential ID"
// @Success 200 {object} eab.CredentialResponse
// @Failure 400 {object} response.WebServiceResponse
// @Failure 401 {object} response.WebServiceResponse
// @Failure 404 {object} response.WebServiceResponse
// @Failure 500 {object} response.WebServiceResponse
// @Router /eab/credentials/{id} [get]
func (r *EABRouter) getCredential(router *mux.Router) {
	handler := http.HandlerFunc(r.handler.Get)
	wrapped := r.tenantMiddleware(handler)
	router.Handle("/eab/credentials/{id:[0-9]+}", negroni.New(
		negroni.Wrap(wrapped),
	)).Methods("GET")
}

// GET /api/v1/eab/credentials/key/{key_id} - Get EAB credential by KeyID
// @Summary Get EAB credential by KeyID
// @Description Retrieves an EAB credential by its KeyID
// @Tags EAB
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer token"
// @Param key_id path string true "Key ID"
// @Success 200 {object} eab.CredentialResponse
// @Failure 400 {object} response.WebServiceResponse
// @Failure 401 {object} response.WebServiceResponse
// @Failure 404 {object} response.WebServiceResponse
// @Failure 500 {object} response.WebServiceResponse
// @Router /eab/credentials/key/{key_id} [get]
func (r *EABRouter) getCredentialByKeyID(router *mux.Router) {
	handler := http.HandlerFunc(r.handler.GetByKeyID)
	wrapped := r.tenantMiddleware(handler)
	router.Handle("/eab/credentials/key/{key_id}", negroni.New(
		negroni.Wrap(wrapped),
	)).Methods("GET")
}

// POST /api/v1/eab/credentials/{id}/revoke - Revoke EAB credential (owner only)
// @Summary Revoke an EAB credential
// @Description Revokes an EAB credential (owner only)
// @Tags EAB
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer token"
// @Param id path integer true "Credential ID"
// @Success 200 {object} eab.RevokeResponse
// @Failure 400 {object} response.WebServiceResponse
// @Failure 401 {object} response.WebServiceResponse
// @Failure 403 {object} response.WebServiceResponse
// @Failure 404 {object} response.WebServiceResponse
// @Failure 409 {object} response.WebServiceResponse
// @Failure 500 {object} response.WebServiceResponse
// @Router /eab/credentials/{id}/revoke [post]
func (r *EABRouter) revokeCredential(router *mux.Router) {
	handler := http.HandlerFunc(r.handler.Revoke)
	wrapped := r.tenantMiddleware(handler)
	router.Handle("/eab/credentials/{id:[0-9]+}/revoke", negroni.New(
		negroni.Wrap(wrapped),
	)).Methods("POST")
}

// POST /api/v1/eab/credentials/validate - Validate EAB credential
// @Summary Validate an EAB credential
// @Description Validates an EAB credential by key_id and hmac_key
// @Tags EAB
// @Accept json
// @Produce json
// @Param credential body eab.ValidateCredentialRequest true "Validation request"
// @Success 200 {object} eab.ValidateCredentialResponse
// @Failure 400 {object} response.WebServiceResponse
// @Failure 500 {object} response.WebServiceResponse
// @Router /eab/credentials/validate [post]
func (r *EABRouter) validateCredential(router *mux.Router) {
	// Validation may be called by ACME server, so no tenant middleware required
	router.HandleFunc("/eab/credentials/validate", r.handler.Validate).Methods("POST")
}

// DELETE /api/v1/eab/credentials/{id} - Delete EAB credential (owner only)
// @Summary Delete an EAB credential
// @Description Deletes an EAB credential (owner only)
// @Tags EAB
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer token"
// @Param id path integer true "Credential ID"
// @Success 200 {object} eab.DeleteResponse
// @Failure 400 {object} response.WebServiceResponse
// @Failure 401 {object} response.WebServiceResponse
// @Failure 403 {object} response.WebServiceResponse
// @Failure 404 {object} response.WebServiceResponse
// @Failure 500 {object} response.WebServiceResponse
// @Router /eab/credentials/{id} [delete]
func (r *EABRouter) deleteCredential(router *mux.Router) {
	handler := http.HandlerFunc(r.handler.Delete)
	wrapped := r.tenantMiddleware(handler)
	router.Handle("/eab/credentials/{id:[0-9]+}", negroni.New(
		negroni.Wrap(wrapped),
	)).Methods("DELETE")
}

// GET /api/v1/eab/credentials/{id}/qr - Get QR code for credential
// @Summary Get QR code for EAB credential
// @Description Generates a QR code image containing the EAB credentials
// @Tags EAB
// @Accept json
// @Produce image/png
// @Param Authorization header string true "Bearer token"
// @Param id path integer true "Credential ID"
// @Success 200 {file} png
// @Failure 400 {object} response.WebServiceResponse
// @Failure 401 {object} response.WebServiceResponse
// @Failure 404 {object} response.WebServiceResponse
// @Failure 500 {object} response.WebServiceResponse
// @Router /eab/credentials/{id}/qr [get]
func (r *EABRouter) getQRCode(router *mux.Router) {
	handler := http.HandlerFunc(r.handler.GetQRCode)
	wrapped := r.tenantMiddleware(handler)
	router.Handle("/eab/credentials/{id:[0-9]+}/qr", negroni.New(
		negroni.Wrap(wrapped),
	)).Methods("GET")
}

// GET /api/v1/eab/credentials/{id}/url - Get enrollment URL for credential
// @Summary Get enrollment URL for EAB credential
// @Description Generates an enrollment URL with embedded EAB credentials
// @Tags EAB
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer token"
// @Param id path integer true "Credential ID"
// @Success 200 {object} eab.EnrollmentURLResponse
// @Failure 400 {object} response.WebServiceResponse
// @Failure 401 {object} response.WebServiceResponse
// @Failure 404 {object} response.WebServiceResponse
// @Failure 500 {object} response.WebServiceResponse
// @Router /eab/credentials/{id}/url [get]
func (r *EABRouter) getEnrollmentURL(router *mux.Router) {
	handler := http.HandlerFunc(r.handler.GetEnrollmentURL)
	wrapped := r.tenantMiddleware(handler)
	router.Handle("/eab/credentials/{id:[0-9]+}/url", negroni.New(
		negroni.Wrap(wrapped),
	)).Methods("GET")
}

// RegisterEABRoutes is a convenience function to register EAB routes
// with the provided router and middleware.
func RegisterEABRoutes(
	router *mux.Router,
	handler eab.RestHandler,
	tenantMiddleware func(http.Handler) http.Handler,
) {
	eabRouter := NewEABRouter(handler, tenantMiddleware)
	eabRouter.RegisterRoutes(router)
}
