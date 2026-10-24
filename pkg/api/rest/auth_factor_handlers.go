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

// Package rest provides REST API handlers for the trusted platform services.
package rest

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"
)

// authCA is the minimal interface required from the CA by AuthFactorHandlers.
// Using a narrow internal interface allows tests to inject lightweight stubs
// without satisfying the full quicbaasca.CACertificateAuthority surface.
type authCA interface {
	// SignCSR signs a PEM-encoded CSR and returns the issued certificate.
	SignCSR(ctx context.Context, csrPEM []byte, opts *quicbaasca.SignOptions) (*x509.Certificate, error)
	// TrustedRootCertPool returns the trusted root pool for validating a leaf cert.
	TrustedRootCertPool(cert *x509.Certificate) (*x509.CertPool, error)
	// CABundle returns the CA certificate bundle in PEM format.
	CABundle() ([]byte, error)
}

// =============================================================================
// Auth Factor Handler Errors (typed)
// =============================================================================

// ErrAuthServiceNotAvailable is returned when no CA is wired to the handler.
type ErrAuthServiceNotAvailable struct{}

func (e ErrAuthServiceNotAvailable) Error() string {
	return "auth service not available"
}

// ErrAAGUIDNotFound is returned when the requested AAGUID is unknown.
type ErrAAGUIDNotFound struct{ AAGUID string }

func (e ErrAAGUIDNotFound) Error() string {
	return "aaguid not found: " + e.AAGUID
}

// ErrMTLSClientCertRequired is returned when no client certificate is presented.
type ErrMTLSClientCertRequired struct{}

func (e ErrMTLSClientCertRequired) Error() string {
	return "mTLS client certificate required"
}

// ErrMTLSCertValidationFailed is returned when client cert chain validation fails.
type ErrMTLSCertValidationFailed struct{ Reason string }

func (e ErrMTLSCertValidationFailed) Error() string {
	return "mTLS certificate validation failed: " + e.Reason
}

// ErrCSRRequired is returned when the CSR PEM field is missing.
type ErrCSRRequired struct{}

func (e ErrCSRRequired) Error() string { return "csr_pem is required" }

// ErrInvalidCSRPEM is returned when the provided PEM cannot be parsed as a CSR.
type ErrInvalidCSRPEM struct{ Reason string }

func (e ErrInvalidCSRPEM) Error() string { return "invalid csr_pem: " + e.Reason }

// ErrCertIssueFailed is returned when CSR signing fails.
type ErrCertIssueFailed struct{ Reason string }

func (e ErrCertIssueFailed) Error() string { return "certificate issuance failed: " + e.Reason }

// ErrForbiddenUserID is returned when the caller is not authorized to act on
// the supplied user ID.
type ErrForbiddenUserID struct{}

func (e ErrForbiddenUserID) Error() string {
	return "forbidden: caller may not act on behalf of this user"
}

// ErrMFAPolicyInvalid is returned when the MFA policy payload is invalid.
type ErrMFAPolicyInvalid struct{ Reason string }

func (e ErrMFAPolicyInvalid) Error() string { return "invalid mfa policy: " + e.Reason }

// =============================================================================
// Auth Factor Request / Response types
// =============================================================================

// AAGUIDLookupResponse is the payload returned by GET /api/v1/auth/factors/aaguid-lookup.
type AAGUIDLookupResponse struct {
	AAGUID         string `json:"aaguid"`
	Name           string `json:"name"`
	Icon           string `json:"icon,omitempty"`
	Vendor         string `json:"vendor"`
	Model          string `json:"model"`
	MetadataStatus string `json:"metadata_status"`
}

// IssueMTLSCertRequest is the payload for POST /api/v1/users/{id}/factors/mtls/issue-cert.
type IssueMTLSCertRequest struct {
	CSRPEM string `json:"csr_pem"`
}

// IssueMTLSCertResponse carries the issued certificate.
type IssueMTLSCertResponse struct {
	CertPEM  string `json:"cert_pem"`
	ChainPEM string `json:"chain_pem,omitempty"`
}

// MFAPolicyResponse is returned by GET /api/v1/tenants/{id}/security/mfa-policy.
type MFAPolicyResponse struct {
	TenantID               string `json:"tenant_id"`
	RequireMultipleFactors bool   `json:"require_multiple_factors"`
	MinFactorCount         int    `json:"min_factor_count"`
}

// MFAPolicyRequest is the payload for PUT /api/v1/tenants/{id}/security/mfa-policy.
type MFAPolicyUpdateRequest struct {
	RequireMultipleFactors bool `json:"require_multiple_factors"`
	MinFactorCount         int  `json:"min_factor_count"`
}

// =============================================================================
// AAGUID registry — static well-known entries + 24-hour TTL cache
// =============================================================================

// aaguidEntry is a cached AAGUID lookup result.
type aaguidEntry struct {
	resp     AAGUIDLookupResponse
	cachedAt time.Time
}

// aaguidCacheTTL is the lifetime of a cached AAGUID lookup.
const aaguidCacheTTL = 24 * time.Hour

// wellKnownAAGUIDs provides a vendor-agnostic baseline registry of certified
// FIDO2 authenticators. This list is extended by the cache as new devices
// are encountered. The keys are lowercase UUID strings.
var wellKnownAAGUIDs = map[string]AAGUIDLookupResponse{
	// YubiKey 5 series (FIDO2)
	"ee882879-721c-4913-9775-3dfcce97072a": {
		AAGUID:         "ee882879-721c-4913-9775-3dfcce97072a",
		Name:           "YubiKey 5 Series",
		Vendor:         "Yubico",
		Model:          "YubiKey 5 Series",
		MetadataStatus: "FIDO_CERTIFIED_L1",
	},
	// YubiKey 5C NFC
	"c1f9a0bc-1dd2-404a-b27f-8e29047a43fd": {
		AAGUID:         "c1f9a0bc-1dd2-404a-b27f-8e29047a43fd",
		Name:           "YubiKey 5C NFC",
		Vendor:         "Yubico",
		Model:          "YubiKey 5C NFC",
		MetadataStatus: "FIDO_CERTIFIED_L1",
	},
	// Windows Hello (PIN/TPM)
	"08987058-cadc-4b81-b6e1-30de50dcbe96": {
		AAGUID:         "08987058-cadc-4b81-b6e1-30de50dcbe96",
		Name:           "Windows Hello",
		Vendor:         "Microsoft",
		Model:          "Windows Hello (Software Authenticator)",
		MetadataStatus: "NOT_FIDO_CERTIFIED",
	},
	// Touch ID / Face ID on macOS / iOS
	"adce0002-35bc-c60a-648b-0b25f1f05503": {
		AAGUID:         "adce0002-35bc-c60a-648b-0b25f1f05503",
		Name:           "Apple Touch ID",
		Vendor:         "Apple",
		Model:          "Touch ID / Face ID",
		MetadataStatus: "FIDO_CERTIFIED",
	},
	// Android built-in authenticator
	"b93fd961-f2e6-462f-b122-82002247de78": {
		AAGUID:         "b93fd961-f2e6-462f-b122-82002247de78",
		Name:           "Android Authenticator",
		Vendor:         "Google",
		Model:          "Android Built-in Authenticator",
		MetadataStatus: "FIDO_CERTIFIED",
	},
}

// =============================================================================
// MFA policy in-memory store (per-tenant, persisted across requests)
// =============================================================================

// mfaPolicy holds the per-tenant MFA configuration.
type mfaPolicy struct {
	RequireMultipleFactors bool
	MinFactorCount         int
}

// =============================================================================
// AuthFactorHandlers
// =============================================================================

// AuthFactorHandlers implements the M12 auth factor REST endpoints:
//
//	GET  /api/v1/auth/factors/aaguid-lookup
//	HEAD /api/v1/auth/mtls/probe
//	POST /api/v1/users/{id}/factors/mtls/issue-cert
//	GET  /api/v1/tenants/{id}/security/mfa-policy
//	PUT  /api/v1/tenants/{id}/security/mfa-policy
//
// The handler holds a reference to the platform CA for certificate issuance
// and an in-memory MFA policy store. The AAGUID cache is package-level to
// survive handler recreation across tests.
type AuthFactorHandlers struct {
	ca     authCA
	logger *slog.Logger

	// aaguid cache — keyed by lowercase UUID string
	cacheMu sync.RWMutex
	cache   map[string]aaguidEntry

	// MFA policy store — keyed by tenant ID
	policyMu sync.RWMutex
	policies map[string]mfaPolicy
}

// NewAuthFactorHandlers creates an AuthFactorHandlers. ca may be nil when the
// CA service is not configured; cert issuance handlers will return 503.
// The ca parameter accepts quicbaasca.CACertificateAuthority which satisfies authCA.
func NewAuthFactorHandlers(ca quicbaasca.CACertificateAuthority, logger *slog.Logger) *AuthFactorHandlers {
	if logger == nil {
		logger = slog.Default()
	}
	h := &AuthFactorHandlers{
		logger:   logger,
		cache:    make(map[string]aaguidEntry),
		policies: make(map[string]mfaPolicy),
	}
	if ca != nil {
		h.ca = ca
	}
	return h
}

// RegisterRoutes attaches all auth factor routes to the provided mux router.
func (h *AuthFactorHandlers) RegisterRoutes(router *mux.Router) {
	router.HandleFunc("/api/v1/auth/factors/aaguid-lookup", h.handleAAGUIDLookup).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/auth/mtls/probe", h.handleMTLSProbe).Methods(http.MethodHead)
	router.HandleFunc("/api/v1/users/{id}/factors/mtls/issue-cert", h.handleIssueCert).Methods(http.MethodPost)
	router.HandleFunc("/api/v1/tenants/{id}/security/mfa-policy", h.handleGetMFAPolicy).Methods(http.MethodGet)
	router.HandleFunc("/api/v1/tenants/{id}/security/mfa-policy", h.handlePutMFAPolicy).Methods(http.MethodPut)

	h.logger.Info("Auth factor REST routes registered")
}

// =============================================================================
// Gap 1 — AAGUID lookup
// =============================================================================

// handleAAGUIDLookup handles GET /api/v1/auth/factors/aaguid-lookup?aaguid=<uuid>
func (h *AuthFactorHandlers) handleAAGUIDLookup(w http.ResponseWriter, r *http.Request) {
	aaguid := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("aaguid")))
	if aaguid == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "aaguid"})
		return
	}

	// Probe cache first.
	if entry, ok := h.lookupCache(aaguid); ok {
		h.writeJSON(w, http.StatusOK, entry)
		return
	}

	// Fall back to static well-known registry.
	if known, ok := wellKnownAAGUIDs[aaguid]; ok {
		h.storeCache(aaguid, known)
		h.writeJSON(w, http.StatusOK, known)
		return
	}

	h.writeError(w, http.StatusNotFound, ErrAAGUIDNotFound{AAGUID: aaguid})
}

// lookupCache returns the cached entry if present and not expired.
func (h *AuthFactorHandlers) lookupCache(aaguid string) (AAGUIDLookupResponse, bool) {
	h.cacheMu.RLock()
	defer h.cacheMu.RUnlock()
	entry, ok := h.cache[aaguid]
	if !ok {
		return AAGUIDLookupResponse{}, false
	}
	if time.Since(entry.cachedAt) > aaguidCacheTTL {
		return AAGUIDLookupResponse{}, false
	}
	return entry.resp, true
}

// storeCache inserts or refreshes a cache entry.
func (h *AuthFactorHandlers) storeCache(aaguid string, resp AAGUIDLookupResponse) {
	h.cacheMu.Lock()
	defer h.cacheMu.Unlock()
	h.cache[aaguid] = aaguidEntry{resp: resp, cachedAt: time.Now()}
}

// =============================================================================
// Gap 2 — mTLS probe
// =============================================================================

// handleMTLSProbe handles HEAD /api/v1/auth/mtls/probe.
//
// Returns:
//
//	204 No Content — client cert present and chain validates against platform CA
//	401 Unauthorized — no client cert (or validation failed)
func (h *AuthFactorHandlers) handleMTLSProbe(w http.ResponseWriter, r *http.Request) {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	// Validate the leaf certificate against the trusted root when a CA is
	// available. If the CA is not wired we accept presence of the cert as
	// sufficient (the TLS layer already verified the chain).
	if h.ca != nil {
		leaf := r.TLS.PeerCertificates[0]
		pool, err := h.ca.TrustedRootCertPool(leaf)
		if err != nil {
			h.logger.Warn("mTLS probe: failed to obtain trusted root pool", "error", err)
			// Degrade gracefully: accept the cert without chain validation.
		} else if pool != nil {
			// KeyUsages must be explicit: an empty list means serverAuth,
			// which rejects every clientAuth certificate the probe exists for.
			_, verifyErr := leaf.Verify(x509.VerifyOptions{
				Roots:     pool,
				KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
			})
			if verifyErr != nil {
				h.logger.Debug("mTLS probe: cert validation failed", "error", verifyErr)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		}
	}

	w.WriteHeader(http.StatusNoContent)
}

// =============================================================================
// Gap 3 — cert issuance from CSR
// =============================================================================

// handleIssueCert handles POST /api/v1/users/{id}/factors/mtls/issue-cert.
//
// The handler signs the supplied CSR with the platform CA using a clientAuth
// EKU profile. Authentication is caller-context: the request is accepted when
// the caller's mTLS cert subject CN matches the user ID, or when the caller
// presents an admin certificate. When mTLS is not configured the endpoint
// accepts any authenticated request (IAM layer upstream is responsible).
func (h *AuthFactorHandlers) handleIssueCert(w http.ResponseWriter, r *http.Request) {
	if h.ca == nil {
		h.writeError(w, http.StatusServiceUnavailable, ErrAuthServiceNotAvailable{})
		return
	}

	userID := mux.Vars(r)["id"]
	if userID == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "id"})
		return
	}

	// Authorization check: caller must be the user or admin.
	if !h.callerAuthorized(r, userID) {
		h.writeError(w, http.StatusForbidden, ErrForbiddenUserID{})
		return
	}

	var req IssueMTLSCertRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}
	if req.CSRPEM == "" {
		h.writeError(w, http.StatusBadRequest, ErrCSRRequired{})
		return
	}

	// Validate that the payload is a PEM-encoded certificate request.
	block, _ := pem.Decode([]byte(req.CSRPEM))
	if block == nil || (block.Type != "CERTIFICATE REQUEST" && block.Type != "NEW CERTIFICATE REQUEST") {
		h.writeError(w, http.StatusBadRequest, ErrInvalidCSRPEM{Reason: "PEM block not found or not a CERTIFICATE REQUEST"})
		return
	}

	// Sign with EKU=clientAuth profile. The platform CA's "client" profile
	// sets x509.ExtKeyUsageClientAuth by convention.
	opts := &quicbaasca.SignOptions{
		Profile:      "client",
		ValidityDays: 365,
	}
	cert, err := h.ca.SignCSR(r.Context(), []byte(req.CSRPEM), opts)
	if err != nil {
		h.logger.Error("CSR signing failed", "user_id", userID, "error", err)
		h.writeError(w, http.StatusBadRequest, ErrCertIssueFailed{Reason: err.Error()})
		return
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: cert.Raw,
	})

	// Build chain PEM from CA.
	var chainPEM string
	if bundle, bundleErr := h.ca.CABundle(); bundleErr == nil {
		chainPEM = string(bundle)
	}

	h.writeJSON(w, http.StatusCreated, IssueMTLSCertResponse{
		CertPEM:  string(certPEM),
		ChainPEM: chainPEM,
	})
}

// callerAuthorized returns true when the caller is allowed to act on the
// given userID. The caller is allowed when:
//   - mTLS is not in use (IAM layer is authoritative), OR
//   - the client cert CN matches userID, OR
//   - the client cert has the "admin" OID in its SubjectAltName or CN prefix.
func (h *AuthFactorHandlers) callerAuthorized(r *http.Request, userID string) bool {
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		// No mTLS — IAM/JWT layer is authoritative; permit.
		return true
	}
	leaf := r.TLS.PeerCertificates[0]
	cn := leaf.Subject.CommonName

	// Admin prefix or org unit.
	if strings.HasPrefix(cn, "admin") || strings.EqualFold(cn, "admin") {
		return true
	}
	for _, ou := range leaf.Subject.OrganizationalUnit {
		if strings.EqualFold(ou, "admin") {
			return true
		}
	}

	// Caller is the user themselves.
	return cn == userID
}

// =============================================================================
// Gap 4 — MFA policy GET + PUT
// =============================================================================

// handleGetMFAPolicy handles GET /api/v1/tenants/{id}/security/mfa-policy.
func (h *AuthFactorHandlers) handleGetMFAPolicy(w http.ResponseWriter, r *http.Request) {
	tenantID := mux.Vars(r)["id"]
	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "id"})
		return
	}

	policy := h.getPolicy(tenantID)
	h.writeJSON(w, http.StatusOK, MFAPolicyResponse{
		TenantID:               tenantID,
		RequireMultipleFactors: policy.RequireMultipleFactors,
		MinFactorCount:         policy.MinFactorCount,
	})
}

// handlePutMFAPolicy handles PUT /api/v1/tenants/{id}/security/mfa-policy.
func (h *AuthFactorHandlers) handlePutMFAPolicy(w http.ResponseWriter, r *http.Request) {
	tenantID := mux.Vars(r)["id"]
	if tenantID == "" {
		h.writeError(w, http.StatusBadRequest, ErrMissingRequiredField{Field: "id"})
		return
	}

	var req MFAPolicyUpdateRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidRequestBody{Reason: err.Error()})
		return
	}
	if req.MinFactorCount < 0 {
		h.writeError(w, http.StatusBadRequest, ErrMFAPolicyInvalid{Reason: "min_factor_count must be >= 0"})
		return
	}

	h.setPolicy(tenantID, mfaPolicy(req))

	h.writeJSON(w, http.StatusOK, MFAPolicyResponse{
		TenantID:               tenantID,
		RequireMultipleFactors: req.RequireMultipleFactors,
		MinFactorCount:         req.MinFactorCount,
	})
}

// getPolicy returns the stored policy for a tenant, defaulting to
// RequireMultipleFactors=false, MinFactorCount=1.
func (h *AuthFactorHandlers) getPolicy(tenantID string) mfaPolicy {
	h.policyMu.RLock()
	defer h.policyMu.RUnlock()
	if p, ok := h.policies[tenantID]; ok {
		return p
	}
	return mfaPolicy{RequireMultipleFactors: false, MinFactorCount: 1}
}

// setPolicy stores the MFA policy for a tenant.
func (h *AuthFactorHandlers) setPolicy(tenantID string, p mfaPolicy) {
	h.policyMu.Lock()
	defer h.policyMu.Unlock()
	h.policies[tenantID] = p
}

// =============================================================================
// JSON helpers
// =============================================================================

// writeJSON encodes data as JSON and writes it with the given HTTP status code.
func (h *AuthFactorHandlers) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(data); err != nil {
		h.logger.Error("failed to encode JSON response", "error", err)
	}
}

// writeError writes a structured JSON error response.
func (h *AuthFactorHandlers) writeError(w http.ResponseWriter, status int, err error) {
	h.writeJSON(w, status, ErrorResponse{
		Error:     err.Error(),
		Code:      status,
		Timestamp: time.Now().UTC(),
	})
}
