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
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"
	quicbaasca "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms/ca"

	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
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

// ErrCallerGuardNotConfigured is returned when issue-cert has no ScopeGuard to
// authenticate its caller with, so it cannot tell a user from an admin.
type ErrCallerGuardNotConfigured struct{}

func (e ErrCallerGuardNotConfigured) Error() string {
	return "caller authentication is not configured for certificate issuance"
}

// ErrCallerTenantRequired is returned when the issue-cert caller belongs to no
// tenant: the issued certificate's O names the caller's tenant, so there is
// nothing to bind it to.
type ErrCallerTenantRequired struct{}

func (e ErrCallerTenantRequired) Error() string {
	return "forbidden: the caller belongs to no tenant to issue the certificate in"
}

// ErrCSRNotBoundToUser is returned when an issue-cert CSR names a principal or
// tenant other than the user it is issued for: its CN is not the user, it
// carries an OU the caller's own certificate does not, or it carries a SAN.
// Field is "CN", "OU" or "SAN"; Value is the refused CN or OU.
type ErrCSRNotBoundToUser struct {
	Field string
	Value string
}

func (e ErrCSRNotBoundToUser) Error() string {
	return "forbidden: csr " + e.Field + " " + e.Value + " does not name the user the certificate is issued to"
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

	// guard authenticates the caller whose role decides whether it may have
	// another user's certificate issued; nil refuses every issue-cert.
	guard *ScopeGuard

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

// WithScopeGuard sets the guard that authenticates the caller of the
// certificate issuance route. A caller it resolves with the admin role may
// have any user's certificate issued; without a guard nobody may.
func (h *AuthFactorHandlers) WithScopeGuard(guard *ScopeGuard) *AuthFactorHandlers {
	h.guard = guard
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
// EKU profile. The request is accepted when the authenticated caller is the
// user or holds the admin role (authorizeCaller), and the CSR names that user
// alone, in the caller's tenant (csrBoundToUser). The CA is also told the
// subject to issue, CN = the user and O = the caller's tenant, so the issued
// certificate authenticates into no other tenant.
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

	caller, status, err := h.authorizeCaller(r, userID)
	if err != nil {
		h.writeError(w, status, err)
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
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		h.writeError(w, http.StatusBadRequest, ErrInvalidCSRPEM{Reason: err.Error()})
		return
	}
	// The CA signs the CSR's subject and SANs as given, so they must name
	// this user, in the caller's tenant, and nobody else.
	if err := csrBoundToUser(csr, userID, caller.TenantID, callerLeaf(r)); err != nil {
		h.writeError(w, http.StatusForbidden, err)
		return
	}

	// Sign with EKU=clientAuth profile. The platform CA's "client" profile
	// sets x509.ExtKeyUsageClientAuth by convention. Subject overrides the
	// CSR's CN and O, so the issued O is the caller's tenant even for a CSR
	// that names none: MTLSAdapter.ExtractTenant reads the tenant from O.
	opts := &quicbaasca.SignOptions{
		Profile:      "client",
		ValidityDays: 365,
		Subject:      &quicbaasca.CASubject{CommonName: userID, Organization: caller.TenantID},
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

// authorizeCaller decides whether the caller may have userID's certificate
// issued, and returns the status and typed error that refuse it. The caller is
// the principal the guard authenticates (or the webservice replay publishes):
// one holding the admin role may issue for any user, anyone else only for
// themselves. Nothing in the client certificate's subject grants admin: the
// platform anchor issues the users' certificates too, so a user may hold one
// whose CN is "admin-x". Without a guard nobody is admitted, and a caller in
// no tenant is refused, since the certificate is issued in the caller's
// tenant. It returns the admitted caller.
func (h *AuthFactorHandlers) authorizeCaller(r *http.Request, userID string) (*platformtoken.AuthorizedContext, int, error) {
	if h.guard == nil {
		return nil, http.StatusServiceUnavailable, ErrCallerGuardNotConfigured{}
	}
	caller, err := h.guard.caller(r)
	if err != nil {
		return nil, http.StatusUnauthorized, err
	}
	if caller.TenantID == "" {
		return nil, http.StatusForbidden, ErrCallerTenantRequired{}
	}
	if caller.HasRole(common.ROLE_ADMIN) || caller.Subject == userID || caller.Username == userID {
		return caller, http.StatusOK, nil
	}
	return nil, http.StatusForbidden, ErrForbiddenUserID{}
}

// callerLeaf returns the caller's verified client certificate, or nil when the
// request carries none.
func callerLeaf(r *http.Request) *x509.Certificate {
	// A replayed request's client certificate is the front end's, not the
	// caller's, so a replayed caller has no OU to lend.
	if _, replayed := replayedCaller(r); replayed {
		return nil
	}
	if r.TLS == nil || len(r.TLS.PeerCertificates) == 0 {
		return nil
	}
	return r.TLS.PeerCertificates[0]
}

// csrBoundToUser refuses a CSR whose subject or SANs could name a principal or
// tenant other than userID in tenant. The subject carries only CN, O and OU,
// with one CN and at most one O. The CN must be userID. The O, if present, must be tenant:
// MTLSAdapter.ExtractTenant takes the tenant from O, so another tenant's O
// would authenticate into that tenant. Every OU must be one the
// caller's own certificate carries, and never "admin": an admin certificate is
// issued through the CA routes, not as a user's mTLS factor. A caller without a
// client certificate (nil) may request no OU. No SAN is allowed, since a user's
// mTLS factor names no host, address, mailbox or URI.
func csrBoundToUser(csr *x509.CertificateRequest, userID, tenant string, caller *x509.Certificate) error {
	if tenant == "" {
		return ErrCallerTenantRequired{}
	}
	if err := csrSubjectAttributesAllowed(csr.Subject.Names); err != nil {
		return err
	}
	if csr.Subject.CommonName != userID {
		return ErrCSRNotBoundToUser{Field: "CN", Value: csr.Subject.CommonName}
	}
	if len(csr.Subject.Organization) > 1 {
		return ErrCSRNotBoundToUser{Field: "O", Value: strings.Join(csr.Subject.Organization, ",")}
	}
	for _, o := range csr.Subject.Organization {
		if o != tenant {
			return ErrCSRNotBoundToUser{Field: "O", Value: o}
		}
	}
	for _, ou := range csr.Subject.OrganizationalUnit {
		if strings.EqualFold(ou, "admin") || caller == nil || !slices.Contains(caller.Subject.OrganizationalUnit, ou) {
			return ErrCSRNotBoundToUser{Field: "OU", Value: ou}
		}
	}
	if len(csr.DNSNames) > 0 || len(csr.EmailAddresses) > 0 || len(csr.IPAddresses) > 0 || len(csr.URIs) > 0 {
		return ErrCSRNotBoundToUser{Field: "SAN"}
	}
	return nil
}

// Subject attribute types an issue-cert CSR may carry: CN, O and OU (X.520
// attribute types, RFC 5280 §4.1.2.4).
var (
	oidAttributeCommonName         = asn1.ObjectIdentifier{2, 5, 4, 3}
	oidAttributeOrganization       = asn1.ObjectIdentifier{2, 5, 4, 10}
	oidAttributeOrganizationalUnit = asn1.ObjectIdentifier{2, 5, 4, 11}
)

// csrSubjectAttributesAllowed refuses a subject carrying an attribute other
// than CN, O and OU, or more than one CN. The mTLS identity and tenant
// extractors (pkg/auth/mtls.go) can be configured to read SERIALNUMBER or the
// whole DN, and x509 keeps only the last of repeated CNs, so any other
// attribute could name a principal the CN check never saw.
func csrSubjectAttributesAllowed(names []pkix.AttributeTypeAndValue) error {
	commonNames := 0
	for _, atv := range names {
		switch {
		case atv.Type.Equal(oidAttributeCommonName):
			commonNames++
			if commonNames > 1 {
				return ErrCSRNotBoundToUser{Field: "CN", Value: fmt.Sprint(atv.Value)}
			}
		case atv.Type.Equal(oidAttributeOrganization), atv.Type.Equal(oidAttributeOrganizationalUnit):
		default:
			return ErrCSRNotBoundToUser{Field: atv.Type.String(), Value: fmt.Sprint(atv.Value)}
		}
	}
	return nil
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
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	if err := dec.Decode(&req); err != nil {
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
