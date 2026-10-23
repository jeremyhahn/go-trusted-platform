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
	"net/http"

	"github.com/gorilla/mux"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/objectstorage"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
	"github.com/jeremyhahn/go-trusted-platform/pkg/ca/issuance"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/middleware"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

const (
	basePath = "/ca"

	// CanonicalBootstrapPath is the root-relative trust-bootstrap path the
	// go-xkms trust fetcher uses by default (its DefaultBundlePath), and the
	// path `xkey trust import-platform <host:port>` builds. The platform is
	// the consumer of that contract, so the bundle is served here in addition
	// to the platform-prefixed /api/v1/ca/bootstrap.
	CanonicalBootstrapPath = "/v1/ca/bootstrap"
)

// CARouter provides REST routing for CA operations
type CARouter struct {
	handlers        *CAHandlers
	scopeAuthorizer middleware.ScopeAuthorizer
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
// the split is deliberate: certificate issuance, CSR signing and revocation
// are privileged operations, and the list of certificates this CA has issued is
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

// RegisterCanonicalRoutes registers the trust-bootstrap fetch at its
// canonical, root-relative path on the supplied ROOT router — not the
// /api/v1 subrouter — and, like RegisterPublicRoutes, it takes the UNGATED
// router: a client bootstrapping trust has no credential yet, and no way to
// discover this platform's API prefix either. CanonicalBootstrapPath is the
// path the go-xkms trust fetcher builds by default.
//
// This publishes the same bundle RegisterPublicRoutes serves at
// /api/v1/ca/bootstrap; both paths are supported and neither supersedes the
// other.
//
// GET    /v1/ca/bootstrap                     - Get CA bundle as raw PEM for trust bootstrapping
func (r *CARouter) RegisterCanonicalRoutes(router *mux.Router) {
	router.HandleFunc(CanonicalBootstrapPath, r.handlers.GetBootstrapBundle).Methods("GET")
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

// WithKMS sets the KMS whose keys POST /api/v1/ca/sign-csr certifies.
func (r *CARouter) WithKMS(kms issuance.KMS) *CARouter {
	r.handlers.WithKMS(kms)
	return r
}

// WithService sets the CA service that renew and verify call: the one the
// gRPC, Unix and MCP transports serve.
func (r *CARouter) WithService(service platformv1.CAServiceServer) *CARouter {
	r.handlers.WithService(service)
	return r
}

// SetScopeAuthorizer supplies the scope check renew, revoke and verify take
// on top of the admin gate. Nil leaves them on the role gate alone, which is
// the case under the legacy JWT handler: its sessions carry roles, not
// scopes.
func (r *CARouter) SetScopeAuthorizer(authorizer middleware.ScopeAuthorizer) {
	r.scopeAuthorizer = authorizer
}

// requireScope wraps handler in the scope check when one is configured.
func (r *CARouter) requireScope(scope string, handler http.HandlerFunc) http.Handler {
	if r.scopeAuthorizer == nil {
		return handler
	}
	return r.scopeAuthorizer.RequireScope(scope)(handler)
}

// registerCertificateRoutes registers certificate management endpoints
// POST   /api/v1/ca/certificates               - Issue certificate
// POST   /api/v1/ca/sign-csr                   - Certify a KMS key for code signing (ca:sign-csr)
// GET    /api/v1/ca/certificates               - List certificates
// POST   /api/v1/ca/certificates/verify        - Verify a certificate against this CA (certs:read)
// GET    /api/v1/ca/certificates/{serial}      - Get certificate by serial
// DELETE /api/v1/ca/certificates/{serial}      - Revoke certificate (certs:revoke)
// POST   /api/v1/ca/certificates/{serial}/renew - Renew certificate (certs:generate)
func (r *CARouter) registerCertificateRoutes(router *mux.Router) {
	// Certificate collection routes
	router.HandleFunc("/certificates", r.handlers.IssueCertificate).Methods("POST")
	router.HandleFunc("/sign-csr", r.handlers.SignCSR).Methods("POST")
	router.HandleFunc("/certificates", r.handlers.ListCertificates).Methods("GET")
	router.Handle("/certificates/verify", r.requireScope(VerifyScope, r.handlers.VerifyCertificate)).Methods("POST")

	// Certificate instance routes
	router.HandleFunc("/certificates/{serial}", r.handlers.GetCertificate).Methods("GET")
	router.Handle("/certificates/{serial}", r.requireScope(RevokeScope, r.handlers.RevokeCertificate)).Methods("DELETE")
	router.Handle("/certificates/{serial}/renew", r.requireScope(RenewScope, r.handlers.RenewCertificate)).Methods("POST")
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
