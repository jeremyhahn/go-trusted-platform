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

// Package invitation implements REST endpoints under /api/v1/invitations.
package invitation

import (
	"github.com/gorilla/mux"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/router"
)

const basePath = "/invitations"

// InvitationRouter wires REST endpoints onto an InvitationServiceServer.
type InvitationRouter struct {
	handlers *Handlers
	router.WebServiceRouter
}

// NewInvitationRouter creates a new router.
func NewInvitationRouter(
	logger *logging.Logger,
	server platformv1.InvitationServiceServer,
	respWriter response.HttpWriter,
) *InvitationRouter {
	return &InvitationRouter{handlers: NewHandlers(logger, server, respWriter)}
}

// RegisterRoutes mounts invitation REST routes.
//
//	GET    /api/v1/invitations                       - ListInvitations
//	POST   /api/v1/invitations                       - CreateInvitation
//	GET    /api/v1/invitations/{id:[0-9]+}           - GetInvitation
//	DELETE /api/v1/invitations/{id:[0-9]+}           - DeleteInvitation
//	POST   /api/v1/invitations/{id:[0-9]+}/revoke    - RevokeInvitation
//	GET    /api/v1/invitations/token/{token}         - GetInvitationByToken (public)
//	POST   /api/v1/invitations/accept                - AcceptInvitation (public)
func (r *InvitationRouter) RegisterRoutes(parent *mux.Router) {
	sr := parent.PathPrefix(basePath).Subrouter()
	sr.HandleFunc("", r.handlers.ListInvitations).Methods("GET")
	sr.HandleFunc("", r.handlers.CreateInvitation).Methods("POST")
	sr.HandleFunc("/accept", r.handlers.AcceptInvitation).Methods("POST")
	sr.HandleFunc("/token/{token}", r.handlers.GetInvitationByToken).Methods("GET")
	sr.HandleFunc("/{id:[0-9]+}", r.handlers.GetInvitation).Methods("GET")
	sr.HandleFunc("/{id:[0-9]+}", r.handlers.DeleteInvitation).Methods("DELETE")
	sr.HandleFunc("/{id:[0-9]+}/revoke", r.handlers.RevokeInvitation).Methods("POST")
}
