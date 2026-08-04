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

// Package eab implements REST endpoints under /api/v1/eab.
package eab

import (
	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/router"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

const basePath = "/eab"

// EABRouter wires REST endpoints onto an EABServiceServer.
type EABRouter struct {
	handlers *Handlers
	router.WebServiceRouter
}

// NewEABRouter creates a new router.
func NewEABRouter(
	logger *logging.Logger,
	server platformv1.EABServiceServer,
	respWriter response.HttpWriter,
) *EABRouter {
	return &EABRouter{handlers: NewHandlers(logger, server, respWriter)}
}

// RegisterRoutes mounts EAB credential routes.
//
//	GET    /api/v1/eab/credentials                       - ListCredentials
//	POST   /api/v1/eab/credentials                       - CreateCredential
//	GET    /api/v1/eab/credentials/{id:[0-9]+}           - GetCredential
//	DELETE /api/v1/eab/credentials/{id:[0-9]+}           - DeleteCredential
//	POST   /api/v1/eab/credentials/{id:[0-9]+}/revoke    - RevokeCredential
//	POST   /api/v1/eab/credentials/{id:[0-9]+}/used      - MarkCredentialUsed
//	GET    /api/v1/eab/credentials/{id:[0-9]+}/qrcode    - GetCredentialQRCode
//	GET    /api/v1/eab/credentials/{id:[0-9]+}/url       - GetEnrollmentURL
//	GET    /api/v1/eab/credentials/key/{key}             - GetCredentialByKeyID
//	POST   /api/v1/eab/credentials/validate              - ValidateCredential
//	POST   /api/v1/eab/credentials/cleanup               - CleanupExpiredCredentials
func (r *EABRouter) RegisterRoutes(parent *mux.Router) {
	sr := parent.PathPrefix(basePath).Subrouter()
	sr.HandleFunc("/credentials", r.handlers.ListCredentials).Methods("GET")
	sr.HandleFunc("/credentials", r.handlers.CreateCredential).Methods("POST")
	sr.HandleFunc("/credentials/cleanup", r.handlers.CleanupExpired).Methods("POST")
	sr.HandleFunc("/credentials/validate", r.handlers.ValidateCredential).Methods("POST")
	sr.HandleFunc("/credentials/key/{key}", r.handlers.GetCredentialByKeyID).Methods("GET")
	sr.HandleFunc("/credentials/{id:[0-9]+}", r.handlers.GetCredential).Methods("GET")
	sr.HandleFunc("/credentials/{id:[0-9]+}", r.handlers.DeleteCredential).Methods("DELETE")
	sr.HandleFunc("/credentials/{id:[0-9]+}/revoke", r.handlers.RevokeCredential).Methods("POST")
	sr.HandleFunc("/credentials/{id:[0-9]+}/used", r.handlers.MarkCredentialUsed).Methods("POST")
	sr.HandleFunc("/credentials/{id:[0-9]+}/qrcode", r.handlers.GetCredentialQRCode).Methods("GET")
	sr.HandleFunc("/credentials/{id:[0-9]+}/url", r.handlers.GetEnrollmentURL).Methods("GET")
}
