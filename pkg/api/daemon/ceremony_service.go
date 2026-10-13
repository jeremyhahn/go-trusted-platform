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

package daemon

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// Ceremony service errors. Typed errors are used throughout the service
// layer so transport adapters can translate them uniformly.

// ErrCeremonyNotConfigured indicates the ceremony backend is not available
// on this server (for example the node is not a control plane).
var ErrCeremonyNotConfigured = errors.New("ceremony: backend not configured")

// ErrCeremonyOfficerRequired indicates the username was missing.
var ErrCeremonyOfficerRequired = errors.New("ceremony: username is required")

// ErrCeremonyChallengeRequired indicates a challenge argument was missing.
var ErrCeremonyChallengeRequired = errors.New("ceremony: nonce and signature are required")

// ErrCeremonyCSRRequired indicates the CSR payload was missing.
var ErrCeremonyCSRRequired = errors.New("ceremony: csr_pem is required")

// ErrCeremonySignatureInvalid indicates the supplied challenge signature
// could not be decoded.
var ErrCeremonySignatureInvalid = errors.New("ceremony: signature is not valid base64")

// CeremonyAuthenticatorType enumerates officer authenticator backends.
type CeremonyAuthenticatorType string

const (
	// CeremonyAuthenticatorUnspecified indicates no authenticator was chosen.
	CeremonyAuthenticatorUnspecified CeremonyAuthenticatorType = ""
	// CeremonyAuthenticatorPIV uses a PIV smartcard.
	CeremonyAuthenticatorPIV CeremonyAuthenticatorType = "piv"
	// CeremonyAuthenticatorFIDO2 uses a FIDO2 security key.
	CeremonyAuthenticatorFIDO2 CeremonyAuthenticatorType = "fido2"
	// CeremonyAuthenticatorSoftware uses a software-only key.
	CeremonyAuthenticatorSoftware CeremonyAuthenticatorType = "software"
)

// CeremonyOfficerRole enumerates officer roles.
type CeremonyOfficerRole string

const (
	// CeremonyRoleUnspecified indicates no role was given.
	CeremonyRoleUnspecified CeremonyOfficerRole = ""
	// CeremonyRoleSO is the Security Officer role.
	CeremonyRoleSO CeremonyOfficerRole = "so"
	// CeremonyRoleAdmin is the Admin officer role.
	CeremonyRoleAdmin CeremonyOfficerRole = "admin"
	// CeremonyRoleUser is the User officer role.
	CeremonyRoleUser CeremonyOfficerRole = "user"
)

// CeremonyStateValue enumerates ceremony lifecycle states.
type CeremonyStateValue string

const (
	// CeremonyStateUnknown indicates the ceremony state could not be determined.
	CeremonyStateUnknown CeremonyStateValue = "unknown"
	// CeremonyStateUninitialized indicates the ceremony has not been initialized.
	CeremonyStateUninitialized CeremonyStateValue = "uninitialized"
	// CeremonyStateInProgress indicates the ceremony is actively enrolling.
	CeremonyStateInProgress CeremonyStateValue = "in_progress"
	// CeremonyStateComplete indicates the ceremony has completed.
	CeremonyStateComplete CeremonyStateValue = "complete"
)

// CeremonyInitRequest is the service-layer init request. Threshold is an
// "M-of-N" spec; an M-of-N init names one officer per share in Officers.
type CeremonyInitRequest struct {
	SOPIN                  string
	UserPIN                string
	Threshold              string
	Hostname               string
	SANs                   []string
	CredentialSealStrategy string
	Officers               []CeremonyOfficer
}

// CeremonyOfficer is a Security Officer enrolled by an M-of-N init: the
// ceremony signs CSRPEM into the officer's custodian certificate.
type CeremonyOfficer struct {
	Username string
	CSRPEM   string
}

// CeremonyInitResult is the service-layer init response.
//
// AdminCertPEM and AdminKeyPEM are the one-shot admin client credential: the
// platform keeps no copy, so every transport must deliver both to the caller.
type CeremonyInitResult struct {
	CeremonyID    string
	State         CeremonyStateValue
	InitializedAt time.Time
	AdminCertPEM  string
	AdminKeyPEM   string
	// SPKIPin is the SHA-256 pin of the ceremony CA's public key, as
	// returned by the upstream ceremony initialize.
	SPKIPin string
}

// CeremonyStatusInfo is the service-layer status response.
type CeremonyStatusInfo struct {
	CeremonyID       string
	State            CeremonyStateValue
	Threshold        string
	OfficersEnrolled int32
	OfficersRequired int32
	InitializedAt    time.Time
}

// CeremonyClaimCertBeginRequest is the service-layer begin request.
type CeremonyClaimCertBeginRequest struct {
	Username          string
	AuthenticatorType CeremonyAuthenticatorType
	Slot              string
	CredentialID      string
}

// CeremonyClaimCertBeginResult is the service-layer begin response.
type CeremonyClaimCertBeginResult struct {
	Nonce       string
	ChallengeID string
	ExpiresAt   time.Time
}

// CeremonyClaimCertCompleteRequest is the service-layer complete request.
type CeremonyClaimCertCompleteRequest struct {
	Username  string
	Nonce     string
	Signature string
}

// CeremonyClaimCertCompleteResult is the service-layer complete response.
type CeremonyClaimCertCompleteResult struct {
	CertificatePEM string
	ChainPEM       string
}

// CeremonyClaimShareBeginRequest is the service-layer share-claim begin
// request.
type CeremonyClaimShareBeginRequest struct {
	Username string
}

// CeremonyClaimShareBeginResult is the service-layer share-claim begin
// response. The officer signs the nonce with the private key matching
// their claimed certificate.
type CeremonyClaimShareBeginResult struct {
	Nonce     string
	ExpiresAt time.Time
}

// CeremonyClaimShareCompleteRequest is the service-layer share-claim
// complete request.
type CeremonyClaimShareCompleteRequest struct {
	Username  string
	Nonce     string
	Signature []byte
}

// CeremonyClaimShareResult is the service-layer claim-share response.
type CeremonyClaimShareResult struct {
	Share string
	Index int32
}

// CeremonySignCSRRequest is the service-layer sign-csr request.
type CeremonySignCSRRequest struct {
	Username string
	SOPIN    string
	CSRPEM   string
	Role     CeremonyOfficerRole
}

// CeremonySignCSRResult is the service-layer sign-csr response.
type CeremonySignCSRResult struct {
	CertificatePEM string
	ChainPEM       string
}

// CeremonyBackend abstracts the upstream ceremony implementation. This
// decouples the daemon service layer from the concrete go-qrdb / go-xkms
// ceremony wiring and keeps the service layer testable.
//
// Implementations are expected to be safe for concurrent use.
type CeremonyBackend interface {
	// Initialize performs the ceremony bootstrap.
	Initialize(ctx context.Context, req *CeremonyInitRequest) (*CeremonyInitResult, error)
	// Status reports the current ceremony state.
	Status(ctx context.Context) (*CeremonyStatusInfo, error)
	// ClaimCertBegin requests a cert-claim challenge for an officer.
	ClaimCertBegin(ctx context.Context, req *CeremonyClaimCertBeginRequest) (*CeremonyClaimCertBeginResult, error)
	// ClaimCertComplete completes a cert-claim challenge.
	ClaimCertComplete(ctx context.Context, req *CeremonyClaimCertCompleteRequest) (*CeremonyClaimCertCompleteResult, error)
	// ClaimShareBegin requests a share-claim challenge for an officer.
	ClaimShareBegin(ctx context.Context, req *CeremonyClaimShareBeginRequest) (*CeremonyClaimShareBeginResult, error)
	// ClaimShareComplete completes a share-claim challenge and returns the
	// caller's Shamir share.
	ClaimShareComplete(ctx context.Context, req *CeremonyClaimShareCompleteRequest) (*CeremonyClaimShareResult, error)
	// SignCSR signs a CSR using the ceremony CA.
	SignCSR(ctx context.Context, req *CeremonySignCSRRequest) (*CeremonySignCSRResult, error)
}

// CeremonyService is the platformd-side ceremony business-logic layer.
//
// It owns a CeremonyBackend (which plumbs through to go-qrdb's ceremony
// service) and validates requests before delegating. The service layer is
// the single point the transport handlers (gRPC/REST/QUIC/MCP/Unix) call.
type CeremonyService struct {
	logger  *logging.Logger
	backend CeremonyBackend

	mu sync.RWMutex
}

// NewCeremonyService constructs a new ceremony service.
//
// When backend is nil the service returns ErrCeremonyNotConfigured for every
// method — this is the expected behavior on nodes where the ceremony role is
// not present (for example non-control-plane nodes).
func NewCeremonyService(logger *logging.Logger, backend CeremonyBackend) *CeremonyService {
	return &CeremonyService{
		logger:  logger,
		backend: backend,
	}
}

// Backend returns the configured backend for testing.
func (s *CeremonyService) Backend() CeremonyBackend {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.backend
}

// SetBackend replaces the configured backend. It is safe for concurrent use
// and intended for controlled initialization paths only.
func (s *CeremonyService) SetBackend(b CeremonyBackend) {
	s.mu.Lock()
	s.backend = b
	s.mu.Unlock()
}

// Init delegates to the backend after input validation.
func (s *CeremonyService) Init(ctx context.Context, req *CeremonyInitRequest) (*CeremonyInitResult, error) {
	if req == nil {
		req = &CeremonyInitRequest{}
	}
	b := s.Backend()
	if b == nil {
		return nil, ErrCeremonyNotConfigured
	}
	return b.Initialize(ctx, req)
}

// Status delegates to the backend.
func (s *CeremonyService) Status(ctx context.Context) (*CeremonyStatusInfo, error) {
	b := s.Backend()
	if b == nil {
		return nil, ErrCeremonyNotConfigured
	}
	return b.Status(ctx)
}

// ClaimCertBegin delegates to the backend.
func (s *CeremonyService) ClaimCertBegin(ctx context.Context, req *CeremonyClaimCertBeginRequest) (*CeremonyClaimCertBeginResult, error) {
	if req == nil || req.Username == "" {
		return nil, ErrCeremonyOfficerRequired
	}
	b := s.Backend()
	if b == nil {
		return nil, ErrCeremonyNotConfigured
	}
	return b.ClaimCertBegin(ctx, req)
}

// ClaimCertComplete delegates to the backend.
func (s *CeremonyService) ClaimCertComplete(ctx context.Context, req *CeremonyClaimCertCompleteRequest) (*CeremonyClaimCertCompleteResult, error) {
	if req == nil || req.Username == "" {
		return nil, ErrCeremonyOfficerRequired
	}
	if req.Nonce == "" || req.Signature == "" {
		return nil, ErrCeremonyChallengeRequired
	}
	b := s.Backend()
	if b == nil {
		return nil, ErrCeremonyNotConfigured
	}
	return b.ClaimCertComplete(ctx, req)
}

// ClaimShareBegin delegates to the backend.
func (s *CeremonyService) ClaimShareBegin(ctx context.Context, req *CeremonyClaimShareBeginRequest) (*CeremonyClaimShareBeginResult, error) {
	if req == nil || req.Username == "" {
		return nil, ErrCeremonyOfficerRequired
	}
	b := s.Backend()
	if b == nil {
		return nil, ErrCeremonyNotConfigured
	}
	return b.ClaimShareBegin(ctx, req)
}

// ClaimShareComplete delegates to the backend.
func (s *CeremonyService) ClaimShareComplete(ctx context.Context, req *CeremonyClaimShareCompleteRequest) (*CeremonyClaimShareResult, error) {
	if req == nil || req.Username == "" {
		return nil, ErrCeremonyOfficerRequired
	}
	if req.Nonce == "" || len(req.Signature) == 0 {
		return nil, ErrCeremonyChallengeRequired
	}
	b := s.Backend()
	if b == nil {
		return nil, ErrCeremonyNotConfigured
	}
	return b.ClaimShareComplete(ctx, req)
}

// SignCSR delegates to the backend.
func (s *CeremonyService) SignCSR(ctx context.Context, req *CeremonySignCSRRequest) (*CeremonySignCSRResult, error) {
	if req == nil || req.Username == "" {
		return nil, ErrCeremonyOfficerRequired
	}
	if req.CSRPEM == "" {
		return nil, ErrCeremonyCSRRequired
	}
	b := s.Backend()
	if b == nil {
		return nil, ErrCeremonyNotConfigured
	}
	return b.SignCSR(ctx, req)
}
