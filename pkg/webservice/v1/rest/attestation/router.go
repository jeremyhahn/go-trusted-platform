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

package attestation

import (
	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/router"
)

const (
	basePath = "/attestation"
)

// AttestationRouter provides REST routing for attestation operations.
type AttestationRouter struct {
	handlers *AttestationHandlers
	router.WebServiceRouter
}

// NewAttestationRouter creates a new AttestationRouter instance.
func NewAttestationRouter(
	logger *logging.Logger,
	service AttestationService,
	respWriter response.HttpWriter,
) *AttestationRouter {
	return &AttestationRouter{
		handlers: NewAttestationHandlers(logger, service, respWriter),
	}
}

// RegisterRoutes registers all attestation REST routes on the provided router.
func (r *AttestationRouter) RegisterRoutes(router *mux.Router) {
	// Create subrouter for attestation endpoints
	attRouter := router.PathPrefix(basePath).Subrouter()

	// Register all route groups
	r.registerManifestRoutes(attRouter)
	r.registerQuoteRoutes(attRouter)
}

// registerManifestRoutes registers manifest management endpoints.
// GET    /api/v1/attestation/manifest        - Get current host manifest
// POST   /api/v1/attestation/manifest/build  - Generate fresh manifest
// POST   /api/v1/attestation/verify          - Verify a manifest
func (r *AttestationRouter) registerManifestRoutes(router *mux.Router) {
	// Manifest routes
	router.HandleFunc("/manifest", r.handlers.GetManifest).Methods("GET")
	router.HandleFunc("/manifest/build", r.handlers.BuildManifest).Methods("POST")
	router.HandleFunc("/verify", r.handlers.VerifyManifest).Methods("POST")
}

// registerQuoteRoutes registers TPM quote endpoints.
// GET    /api/v1/attestation/quote           - Get TPM quote
// POST   /api/v1/attestation/quote/verify    - Verify a quote
func (r *AttestationRouter) registerQuoteRoutes(router *mux.Router) {
	// Quote routes
	router.HandleFunc("/quote", r.handlers.GetQuote).Methods("GET")
	router.HandleFunc("/quote/verify", r.handlers.VerifyQuote).Methods("POST")
}
