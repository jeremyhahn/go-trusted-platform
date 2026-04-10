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

package network

import (
	"crypto/x509"
	"encoding/asn1"
	"time"
)

// AuthState represents the authentication state of a network port.
type AuthState string

// Authentication state constants.
const (
	AuthStateQuarantine AuthState = "quarantine"
	AuthStateEnrolling  AuthState = "enrolling"
	AuthStateAuthorized AuthState = "authorized"
	AuthStateRevoked    AuthState = "revoked"
)

// String returns the string representation of AuthState.
func (s AuthState) String() string {
	return string(s)
}

// IsValid returns true if the authentication state is valid.
func (s AuthState) IsValid() bool {
	switch s {
	case AuthStateQuarantine, AuthStateEnrolling, AuthStateAuthorized, AuthStateRevoked:
		return true
	default:
		return false
	}
}

// IsTerminal returns true if this is a terminal state (no automatic transitions).
func (s AuthState) IsTerminal() bool {
	return s == AuthStateRevoked
}

// CanTransitionTo returns true if the state can transition to the target state.
func (s AuthState) CanTransitionTo(target AuthState) bool {
	switch s {
	case AuthStateQuarantine:
		return target == AuthStateEnrolling || target == AuthStateAuthorized || target == AuthStateRevoked
	case AuthStateEnrolling:
		return target == AuthStateAuthorized || target == AuthStateQuarantine || target == AuthStateRevoked
	case AuthStateAuthorized:
		return target == AuthStateQuarantine || target == AuthStateRevoked
	case AuthStateRevoked:
		return target == AuthStateQuarantine
	default:
		return false
	}
}

// VLANTransition represents a VLAN transition event.
type VLANTransition struct {
	// PortID is the identifier of the port undergoing transition.
	PortID string

	// FromVLAN is the source VLAN ID.
	FromVLAN uint16

	// ToVLAN is the destination VLAN ID.
	ToVLAN uint16

	// FromState is the source authentication state.
	FromState AuthState

	// ToState is the destination authentication state.
	ToState AuthState

	// Reason describes why the transition occurred.
	Reason string

	// Timestamp is when the transition occurred.
	Timestamp time.Time

	// TransactionID is a unique identifier for this transition.
	TransactionID string

	// Success indicates whether the transition completed successfully.
	Success bool

	// Error contains any error that occurred during transition.
	Error string
}

// AuthResult represents the result of an authentication attempt.
type AuthResult struct {
	// PortID is the identifier of the authenticated port.
	PortID string

	// State is the resulting authentication state.
	State AuthState

	// VLAN is the assigned VLAN ID.
	VLAN uint16

	// PolicyOIDs contains the policy OIDs extracted from the certificate.
	PolicyOIDs []asn1.ObjectIdentifier

	// AttestationVerified indicates whether attestation was verified.
	AttestationVerified bool

	// PolicyEvaluated indicates whether policy was evaluated.
	PolicyEvaluated bool

	// PolicyDecision is the OPA policy decision.
	PolicyDecision bool

	// FlowRulesInstalled indicates whether OpenFlow rules were installed.
	FlowRulesInstalled bool

	// Timestamp is when the authentication completed.
	Timestamp time.Time

	// ExpiresAt is when this authentication expires.
	ExpiresAt time.Time

	// SessionID is a unique identifier for this authentication session.
	SessionID string

	// DeviceID is the device identifier from the certificate.
	DeviceID string

	// Errors contains any errors encountered during authentication.
	Errors []string
}

// IsSuccessful returns true if the authentication was successful.
func (r *AuthResult) IsSuccessful() bool {
	return r.State == AuthStateAuthorized &&
		r.AttestationVerified &&
		r.PolicyEvaluated &&
		r.PolicyDecision &&
		r.FlowRulesInstalled
}

// HasErrors returns true if there are any authentication errors.
func (r *AuthResult) HasErrors() bool {
	return len(r.Errors) > 0
}

// AddError adds an error message to the authentication result.
func (r *AuthResult) AddError(err string) {
	r.Errors = append(r.Errors, err)
}

// PolicyInfo contains policy information extracted from an x509 certificate.
type PolicyInfo struct {
	// OIDs contains the certificate policy OIDs.
	OIDs []asn1.ObjectIdentifier

	// PolicyQualifiers contains any policy qualifiers.
	PolicyQualifiers map[string]string

	// CertificateSubject is the certificate subject DN.
	CertificateSubject string

	// CertificateIssuer is the certificate issuer DN.
	CertificateIssuer string

	// CertificateSerial is the certificate serial number.
	CertificateSerial string

	// CertificateNotBefore is when the certificate becomes valid.
	CertificateNotBefore time.Time

	// CertificateNotAfter is when the certificate expires.
	CertificateNotAfter time.Time

	// ExtendedKeyUsages contains the extended key usages from the certificate.
	ExtendedKeyUsages []x509.ExtKeyUsage

	// KeyUsage contains the key usage flags from the certificate.
	KeyUsage x509.KeyUsage

	// IsCA indicates if the certificate is a CA certificate.
	IsCA bool

	// DeviceID is the device identifier extracted from the certificate.
	DeviceID string

	// ExtractedAt is when the policy info was extracted.
	ExtractedAt time.Time
}

// HasOID returns true if the policy info contains the specified OID.
func (p *PolicyInfo) HasOID(oid asn1.ObjectIdentifier) bool {
	for _, o := range p.OIDs {
		if o.Equal(oid) {
			return true
		}
	}
	return false
}

// IsExpired returns true if the certificate has expired.
func (p *PolicyInfo) IsExpired() bool {
	return time.Now().After(p.CertificateNotAfter)
}

// IsNotYetValid returns true if the certificate is not yet valid.
func (p *PolicyInfo) IsNotYetValid() bool {
	return time.Now().Before(p.CertificateNotBefore)
}

// ReattestConfig contains configuration for periodic re-attestation.
type ReattestConfig struct {
	// Enabled indicates whether re-attestation is enabled.
	Enabled bool

	// Interval is the duration between re-attestation attempts.
	Interval time.Duration

	// GracePeriod is the duration to allow network access during re-attestation.
	GracePeriod time.Duration

	// MaxFailures is the maximum number of consecutive failures before quarantine.
	MaxFailures int

	// QuarantineOnFailure indicates whether to quarantine on re-attestation failure.
	QuarantineOnFailure bool

	// AttestationTimeout is the timeout for attestation operations.
	AttestationTimeout time.Duration
}

// Validate validates the ReattestConfig fields.
func (c *ReattestConfig) Validate() error {
	if c.Enabled {
		if c.Interval <= 0 {
			return ErrInvalidConfig{Field: "Interval", Reason: "interval must be positive"}
		}
		if c.GracePeriod < 0 {
			return ErrInvalidConfig{Field: "GracePeriod", Reason: "grace period cannot be negative"}
		}
		if c.MaxFailures < 0 {
			return ErrInvalidConfig{Field: "MaxFailures", Reason: "max failures cannot be negative"}
		}
		if c.AttestationTimeout <= 0 {
			return ErrInvalidConfig{Field: "AttestationTimeout", Reason: "attestation timeout must be positive"}
		}
	}
	return nil
}

// AuthConfig contains configuration for the NetworkAuthService.
type AuthConfig struct {
	// QuarantineVLAN is the VLAN ID for quarantined devices.
	QuarantineVLAN uint16

	// ProductionVLAN is the default VLAN ID for authorized devices.
	ProductionVLAN uint16

	// BridgeName is the OVS bridge name.
	BridgeName string

	// ControllerAddress is the OpenFlow controller address.
	ControllerAddress string

	// OPAEndpoint is the OPA policy evaluation endpoint.
	OPAEndpoint string

	// OPAPolicyPath is the OPA policy path for authentication decisions.
	OPAPolicyPath string

	// RequireAttestation indicates whether TPM attestation is required.
	RequireAttestation bool

	// RequirePolicyEvaluation indicates whether OPA policy evaluation is required.
	RequirePolicyEvaluation bool

	// SessionTimeout is the duration after which authentication sessions expire.
	SessionTimeout time.Duration

	// Reattest contains re-attestation configuration.
	Reattest *ReattestConfig

	// TrustedCAs contains the trusted CA certificates for client certificate validation.
	TrustedCAs []*x509.Certificate

	// RequiredOIDs contains policy OIDs that must be present in client certificates.
	RequiredOIDs []asn1.ObjectIdentifier
}

// Validate validates the AuthConfig fields.
func (c *AuthConfig) Validate() error {
	if c.QuarantineVLAN == 0 {
		return ErrInvalidConfig{Field: "QuarantineVLAN", Reason: "quarantine VLAN cannot be zero"}
	}
	if c.ProductionVLAN == 0 {
		return ErrInvalidConfig{Field: "ProductionVLAN", Reason: "production VLAN cannot be zero"}
	}
	if c.QuarantineVLAN == c.ProductionVLAN {
		return ErrInvalidConfig{
			Field:  "ProductionVLAN",
			Reason: "production VLAN cannot be the same as quarantine VLAN",
		}
	}
	if c.BridgeName == "" {
		return ErrInvalidConfig{Field: "BridgeName", Reason: "bridge name cannot be empty"}
	}
	if c.RequirePolicyEvaluation && c.OPAEndpoint == "" {
		return ErrInvalidConfig{
			Field:  "OPAEndpoint",
			Reason: "OPA endpoint required when policy evaluation is enabled",
		}
	}
	if c.SessionTimeout < 0 {
		return ErrInvalidConfig{Field: "SessionTimeout", Reason: "session timeout cannot be negative"}
	}
	if c.Reattest != nil {
		if err := c.Reattest.Validate(); err != nil {
			return err
		}
	}
	return nil
}

// PortAuthRequest represents a request to authenticate a network port.
type PortAuthRequest struct {
	// PortID is the identifier of the port to authenticate.
	PortID string

	// Certificate is the client certificate for mTLS authentication.
	Certificate *x509.Certificate

	// CertificateChain contains intermediate certificates.
	CertificateChain []*x509.Certificate

	// RequestedVLAN is the VLAN requested by the client (optional).
	RequestedVLAN uint16

	// Nonce is the attestation nonce for freshness.
	Nonce []byte

	// ExpectedPCRs contains the expected PCR values for attestation.
	ExpectedPCRs map[int][]byte

	// AdditionalClaims contains additional claims for policy evaluation.
	AdditionalClaims map[string]interface{}

	// Timeout is the timeout for the authentication request.
	Timeout time.Duration
}

// Validate validates the PortAuthRequest fields.
func (r *PortAuthRequest) Validate() error {
	if r.PortID == "" {
		return ErrInvalidConfig{Field: "PortID", Reason: "port ID cannot be empty"}
	}
	if r.Certificate == nil {
		return ErrInvalidConfig{Field: "Certificate", Reason: "certificate cannot be nil"}
	}
	return nil
}

// PortState represents the current state of a network port.
type PortState struct {
	// PortID is the identifier of the port.
	PortID string

	// AuthState is the current authentication state.
	AuthState AuthState

	// VLAN is the current VLAN ID.
	VLAN uint16

	// SessionID is the current authentication session ID.
	SessionID string

	// DeviceID is the device identifier.
	DeviceID string

	// AuthenticatedAt is when the port was last authenticated.
	AuthenticatedAt time.Time

	// ExpiresAt is when the authentication expires.
	ExpiresAt time.Time

	// LastReattestAt is when the last re-attestation occurred.
	LastReattestAt time.Time

	// FailureCount is the number of consecutive authentication failures.
	FailureCount int

	// PolicyInfo contains the extracted policy information.
	PolicyInfo *PolicyInfo

	// Metadata contains additional port metadata.
	Metadata map[string]string
}

// IsExpired returns true if the port authentication has expired.
func (s *PortState) IsExpired() bool {
	if s.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(s.ExpiresAt)
}

// NeedsReattest returns true if the port needs re-attestation.
func (s *PortState) NeedsReattest(interval time.Duration) bool {
	if s.AuthState != AuthStateAuthorized {
		return false
	}
	if s.LastReattestAt.IsZero() {
		return time.Since(s.AuthenticatedAt) > interval
	}
	return time.Since(s.LastReattestAt) > interval
}

// OPAInput represents the input for OPA policy evaluation.
type OPAInput struct {
	// DeviceID is the device identifier.
	DeviceID string `json:"device_id"`

	// PortID is the port identifier.
	PortID string `json:"port_id"`

	// PolicyOIDs contains the certificate policy OIDs.
	PolicyOIDs []string `json:"policy_oids"`

	// CertificateSubject is the certificate subject DN.
	CertificateSubject string `json:"certificate_subject"`

	// CertificateIssuer is the certificate issuer DN.
	CertificateIssuer string `json:"certificate_issuer"`

	// AttestationVerified indicates whether attestation was verified.
	AttestationVerified bool `json:"attestation_verified"`

	// RequestedVLAN is the VLAN requested by the client.
	RequestedVLAN uint16 `json:"requested_vlan"`

	// AdditionalClaims contains additional claims for policy evaluation.
	AdditionalClaims map[string]interface{} `json:"additional_claims,omitempty"`

	// Timestamp is when the evaluation request was created.
	Timestamp time.Time `json:"timestamp"`
}

// OPAResult represents the result of an OPA policy evaluation.
type OPAResult struct {
	// Allow indicates whether access is allowed.
	Allow bool `json:"allow"`

	// AssignedVLAN is the VLAN assigned by the policy.
	AssignedVLAN uint16 `json:"assigned_vlan,omitempty"`

	// Reasons contains the reasons for the policy decision.
	Reasons []string `json:"reasons,omitempty"`

	// RequiredActions contains actions required before authorization.
	RequiredActions []string `json:"required_actions,omitempty"`

	// EvaluatedAt is when the policy was evaluated.
	EvaluatedAt time.Time `json:"evaluated_at"`
}
