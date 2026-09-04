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

// RegisterRoutes registers the CA's PROTECTED REST routes on the provided
// router, which the caller must have gated. The CA is a mixed surface and
// the split is deliberate: certificate issuance and revocation are
// privileged operations, and the list of certificates this CA has issued is
// an inventory of every identity on the platform, so the whole
// /ca/certificates group is protected.
//
// The public half — the CA's own chain, the CRL and the trust-bootstrap
// fetch — is registered by RegisterPublicRoutes and is NOT included here.
// A caller that registers only this method publishes a CA whose bundle
// cannot be fetched by a client that does not trust it yet, which breaks
// trust bootstrap; a caller that registers only the public half publishes
// issuance to anonymous callers. Both are required.
func (r *CARouter) RegisterRoutes(router *mux.Router) {
	caRouter := router.PathPrefix(basePath).Subrouter()
	r.registerCertificateRoutes(caRouter)
}

// RegisterPublicRoutes registers the CA routes that must remain reachable
// without a credential, and it takes the UNGATED router.
//
// Every route here serves material that is already public by construction
// or must reach a client that has no credential yet:
//
//   - /ca/bootstrap is the trust-bootstrap fetch. Its whole purpose is to
//     serve the bundle to a client that does not trust this platform yet
//     and therefore cannot have authenticated to it.
//   - /ca/crl is fetched by relying parties validating a certificate this
//     CA issued. RFC 5280 CRL distribution points are retrieved
//     anonymously; a gated CRL cannot be consumed by the verifiers it
//     exists for.
//   - /ca/bundle, /ca/root and /ca/intermediate serve the CA's own
//     certificates, which appear in every chain this platform presents on
//     every TLS handshake, and are a strict subset of what /ca/bootstrap
//     already publishes.
//   - /ca/info reports the CA's identity, default algorithm and validity,
//     and summaries of those same certificates. It carries no issued-
//     certificate inventory and no key material.
//
// Nothing that mutates CA state, and nothing that enumerates issued
// certificates, may be added here.
func (r *CARouter) RegisterPublicRoutes(router *mux.Router) {
	caRouter := router.PathPrefix(basePath).Subrouter()
	r.registerInfoRoutes(caRouter)
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
