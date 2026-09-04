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

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/router"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
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
//
// RegisterRoutes registers the TENANT-ADMIN half of the invitation surface
// on the provided router, which the caller must have gated.
//
//	GET    /api/v1/invitations               - list the tenant's invitations
//	POST   /api/v1/invitations               - create one
//	GET    /api/v1/invitations/{id}          - read one
//	DELETE /api/v1/invitations/{id}          - delete one
//	POST   /api/v1/invitations/{id}/revoke   - revoke one
//
// These are the five routes that resolve a tenant and an inviter from the
// caller's session, and they are exactly the five that #171's unverified
// decoders used to serve. They must be gated, or the tenant an invitation
// lands in and the identity it is attributed to are both chosen by an
// anonymous caller.
//
// The invitee-facing half is RegisterInviteeRoutes and must not be mounted
// here — it would demand a session from somebody who by definition does not
// have one yet.
func (r *InvitationRouter) RegisterRoutes(parent *mux.Router) {
	sr := parent.PathPrefix(basePath).Subrouter()
	sr.HandleFunc("", r.handlers.ListInvitations).Methods("GET")
	sr.HandleFunc("", r.handlers.CreateInvitation).Methods("POST")
	sr.HandleFunc("/{id:[0-9]+}", r.handlers.GetInvitation).Methods("GET")
	sr.HandleFunc("/{id:[0-9]+}", r.handlers.DeleteInvitation).Methods("DELETE")
	sr.HandleFunc("/{id:[0-9]+}/revoke", r.handlers.RevokeInvitation).Methods("POST")
}

// RegisterInviteeRoutes registers the two routes an invitee calls, and takes
// the UNGATED router.
//
//	GET  /api/v1/invitations/token/{token}  - read the invitation being accepted
//	POST /api/v1/invitations/accept         - accept it
//
// **The invitation token is the credential.** Both handlers take it from the
// URL or the body and hand it to the service, which is what an invitation is
// for: the caller is a person who has been sent a link and has no platform
// session yet. Requiring one here would make invitations unacceptable, so a
// role guard in front of these is not a hardening — it is an outage.
//
// Neither route resolves a tenant or an inviter from the request, so neither
// was affected by #171's decoders.
func (r *InvitationRouter) RegisterInviteeRoutes(parent *mux.Router) {
	sr := parent.PathPrefix(basePath).Subrouter()
	sr.HandleFunc("/accept", r.handlers.AcceptInvitation).Methods("POST")
	sr.HandleFunc("/token/{token}", r.handlers.GetInvitationByToken).Methods("GET")
}
