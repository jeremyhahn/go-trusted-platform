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
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/invitation"
)

// InvitationRouter handles invitation-related routes.
type InvitationRouter struct {
	handler          invitation.RestHandler
	tenantMiddleware func(http.Handler) http.Handler
	WebServiceRouter
}

// NewInvitationRouter creates a new invitation router.
func NewInvitationRouter(
	handler invitation.RestHandler,
	tenantMiddleware func(http.Handler) http.Handler,
) WebServiceRouter {
	return &InvitationRouter{
		handler:          handler,
		tenantMiddleware: tenantMiddleware,
	}
}

// RegisterRoutes registers all invitation routes.
func (r *InvitationRouter) RegisterRoutes(router *mux.Router) {
	// Protected routes (require auth + tenant context)
	r.createInvitation(router)
	r.listInvitations(router)
	r.getInvitation(router)
	r.revokeInvitation(router)

	// Public route (invitation lookup by token)
	r.getInvitationByToken(router)
}

// POST /api/v1/invitations - Create invitation (owner only)
// @Summary Create a new invitation
// @Description Creates a new invitation to join the tenant (owner only)
// @Tags Invitations
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer token"
// @Param invitation body invitation.CreateInvitationRequest true "Invitation request"
// @Success 201 {object} invitation.InvitationResponse
// @Failure 400 {object} response.WebServiceResponse
// @Failure 401 {object} response.WebServiceResponse
// @Failure 403 {object} response.WebServiceResponse
// @Failure 409 {object} response.WebServiceResponse
// @Failure 500 {object} response.WebServiceResponse
// @Router /invitations [post]
func (r *InvitationRouter) createInvitation(router *mux.Router) {
	handler := http.HandlerFunc(r.handler.Create)
	wrapped := r.tenantMiddleware(handler)
	router.Handle("/invitations", negroni.New(
		negroni.Wrap(wrapped),
	)).Methods("POST")
}

// GET /api/v1/invitations - List tenant invitations
// @Summary List invitations
// @Description Lists all invitations for the current tenant
// @Tags Invitations
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer token"
// @Success 200 {object} invitation.InvitationListResponse
// @Failure 401 {object} response.WebServiceResponse
// @Failure 500 {object} response.WebServiceResponse
// @Router /invitations [get]
func (r *InvitationRouter) listInvitations(router *mux.Router) {
	handler := http.HandlerFunc(r.handler.List)
	wrapped := r.tenantMiddleware(handler)
	router.Handle("/invitations", negroni.New(
		negroni.Wrap(wrapped),
	)).Methods("GET")
}

// GET /api/v1/invitations/token/{token} - Get invitation by token (public)
// @Summary Get invitation by token
// @Description Retrieves an invitation by its secure token (public endpoint)
// @Tags Invitations
// @Accept json
// @Produce json
// @Param token path string true "Invitation token"
// @Success 200 {object} invitation.InvitationResponse
// @Failure 400 {object} response.WebServiceResponse
// @Failure 404 {object} response.WebServiceResponse
// @Failure 500 {object} response.WebServiceResponse
// @Router /invitations/token/{token} [get]
func (r *InvitationRouter) getInvitationByToken(router *mux.Router) {
	// Public endpoint - no tenant middleware
	router.HandleFunc("/invitations/token/{token}", r.handler.GetByToken).Methods("GET")
}

// GET /api/v1/invitations/{id} - Get invitation by ID
// @Summary Get invitation by ID
// @Description Retrieves an invitation by its ID (authenticated users in same tenant)
// @Tags Invitations
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer token"
// @Param id path integer true "Invitation ID"
// @Success 200 {object} invitation.InvitationResponse
// @Failure 400 {object} response.WebServiceResponse
// @Failure 401 {object} response.WebServiceResponse
// @Failure 404 {object} response.WebServiceResponse
// @Failure 500 {object} response.WebServiceResponse
// @Router /invitations/{id} [get]
func (r *InvitationRouter) getInvitation(router *mux.Router) {
	handler := http.HandlerFunc(r.handler.Get)
	wrapped := r.tenantMiddleware(handler)
	router.Handle("/invitations/{id:[0-9]+}", negroni.New(
		negroni.Wrap(wrapped),
	)).Methods("GET")
}

// DELETE /api/v1/invitations/{id} - Revoke invitation (owner only)
// @Summary Revoke an invitation
// @Description Revokes an invitation (owner only)
// @Tags Invitations
// @Accept json
// @Produce json
// @Param Authorization header string true "Bearer token"
// @Param id path integer true "Invitation ID"
// @Success 200 {object} invitation.RevokeResponse
// @Failure 400 {object} response.WebServiceResponse
// @Failure 401 {object} response.WebServiceResponse
// @Failure 403 {object} response.WebServiceResponse
// @Failure 404 {object} response.WebServiceResponse
// @Failure 409 {object} response.WebServiceResponse
// @Failure 500 {object} response.WebServiceResponse
// @Router /invitations/{id} [delete]
func (r *InvitationRouter) revokeInvitation(router *mux.Router) {
	handler := http.HandlerFunc(r.handler.Revoke)
	wrapped := r.tenantMiddleware(handler)
	router.Handle("/invitations/{id:[0-9]+}", negroni.New(
		negroni.Wrap(wrapped),
	)).Methods("DELETE")
}

// RegisterInvitationRoutes is a convenience function to register invitation routes
// with the provided router and middleware.
func RegisterInvitationRoutes(
	router *mux.Router,
	handler invitation.RestHandler,
	tenantMiddleware func(http.Handler) http.Handler,
) {
	invitationRouter := NewInvitationRouter(handler, tenantMiddleware)
	invitationRouter.RegisterRoutes(router)
}
