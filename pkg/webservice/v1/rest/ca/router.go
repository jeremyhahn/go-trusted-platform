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

package ca

import (
	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/objectstorage"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

const (
	basePath = "/ca"
)

// CARouter provides REST routing for CA operations
type CARouter struct {
	handlers *CAHandlers
}

// NewCARouter creates a new CARouter instance.
// objStorage may be nil; if nil, the revocation object-store check is skipped.
func NewCARouter(
	logger *logging.Logger,
	ca quicbaasca.CACertificateAuthority,
	respWriter response.HttpWriter,
) *CARouter {
	return &CARouter{
		handlers: NewCAHandlers(logger, ca, respWriter, nil),
	}
}

// NewCARouterWithStorage creates a new CARouter instance with an ObjectStorage client.
func NewCARouterWithStorage(
	logger *logging.Logger,
	ca quicbaasca.CACertificateAuthority,
	respWriter response.HttpWriter,
	objStorage objectstorage.Client,
) *CARouter {
	return &CARouter{
		handlers: NewCAHandlers(logger, ca, respWriter, objStorage),
	}
}

// RegisterRoutes registers all CA REST routes on the provided router
func (r *CARouter) RegisterRoutes(router *mux.Router) {
	// Create subrouter for CA endpoints
	caRouter := router.PathPrefix(basePath).Subrouter()

	// Register all route groups
	r.registerInfoRoutes(caRouter)
	r.registerCertificateRoutes(caRouter)
	r.registerBundleRoutes(caRouter)
	r.registerBootstrapRoutes(caRouter)
	r.registerCRLRoutes(caRouter)
}

// registerInfoRoutes registers CA information endpoints
// GET    /api/v1/ca/info                       - Get CA information
// GET    /api/v1/ca/root                       - Get root CA cert summary (SDK alias)
// GET    /api/v1/ca/intermediate               - Get intermediate CA cert summary (SDK alias)
func (r *CARouter) registerInfoRoutes(router *mux.Router) {
	router.HandleFunc("/info", r.handlers.GetInfo).Methods("GET")
	router.HandleFunc("/root", r.handlers.GetRoot).Methods("GET")
	router.HandleFunc("/intermediate", r.handlers.GetIntermediate).Methods("GET")
}

// registerCertificateRoutes registers certificate management endpoints
// POST   /api/v1/ca/certificates               - Issue certificate
// GET    /api/v1/ca/certificates               - List certificates
// GET    /api/v1/ca/certificates/{serial}      - Get certificate by serial
// DELETE /api/v1/ca/certificates/{serial}      - Revoke certificate
func (r *CARouter) registerCertificateRoutes(router *mux.Router) {
	// Certificate collection routes
	router.HandleFunc("/certificates", r.handlers.IssueCertificate).Methods("POST")
	router.HandleFunc("/certificates", r.handlers.ListCertificates).Methods("GET")

	// Certificate instance routes
	router.HandleFunc("/certificates/{serial}", r.handlers.GetCertificate).Methods("GET")
	router.HandleFunc("/certificates/{serial}", r.handlers.RevokeCertificate).Methods("DELETE")
}

// registerBundleRoutes registers CA bundle endpoints
// GET    /api/v1/ca/bundle                     - Get CA bundle
func (r *CARouter) registerBundleRoutes(router *mux.Router) {
	router.HandleFunc("/bundle", r.handlers.GetBundle).Methods("GET")
}

// registerBootstrapRoutes registers the unauthenticated bootstrap endpoint
// GET    /api/v1/ca/bootstrap                  - Get CA bundle as raw PEM for trust bootstrapping
func (r *CARouter) registerBootstrapRoutes(router *mux.Router) {
	router.HandleFunc("/bootstrap", r.handlers.GetBootstrapBundle).Methods("GET")
}

// registerCRLRoutes registers CRL endpoints
// GET    /api/v1/ca/crl                        - Get CRL
func (r *CARouter) registerCRLRoutes(router *mux.Router) {
	router.HandleFunc("/crl", r.handlers.GetCRL).Methods("GET")
}
