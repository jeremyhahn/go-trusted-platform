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

// Package ceremony provides SDK types and a client for the platform ceremony
// service. Ceremony covers barrier initialization, officer enrollment, share
// claims, and CSR signing under the Shamir quorum model.
//
// Requests and responses are transported through the platform SDK ceremony client;
// ceremony state and policy are implemented by the composed security stack.
package ceremony

import "time"

// AuthenticatorType enumerates the officer authenticator backends supported by
// the ceremony service.
type AuthenticatorType string

const (
	// AuthenticatorUnspecified indicates no authenticator was chosen.
	AuthenticatorUnspecified AuthenticatorType = ""
	// AuthenticatorPIV uses a PIV (Personal Identity Verification) smartcard.
	AuthenticatorPIV AuthenticatorType = "piv"
	// AuthenticatorFIDO2 uses a FIDO2 security key.
	AuthenticatorFIDO2 AuthenticatorType = "fido2"
	// AuthenticatorSoftware uses a software-only key (test / lab mode).
	AuthenticatorSoftware AuthenticatorType = "software"
)

// OfficerRole enumerates the roles an officer can hold.
type OfficerRole string

const (
	// RoleUnspecified indicates the role was not provided.
	RoleUnspecified OfficerRole = ""
	// RoleSO is the Security Officer role.
	RoleSO OfficerRole = "so"
	// RoleAdmin is the Admin officer role.
	RoleAdmin OfficerRole = "admin"
	// RoleUser is the User officer role.
	RoleUser OfficerRole = "user"
)

// CeremonyState enumerates the life-cycle states of the ceremony.
type CeremonyState string

const (
	// StateUnknown indicates the ceremony state could not be determined.
	StateUnknown CeremonyState = "unknown"
	// StateUninitialized indicates the ceremony has not yet been initialized.
	StateUninitialized CeremonyState = "uninitialized"
	// StateInProgress indicates the ceremony is actively enrolling officers.
	StateInProgress CeremonyState = "in_progress"
	// StateComplete indicates the ceremony has completed.
	StateComplete CeremonyState = "complete"
)

// InitRequest requests a fresh ceremony initialization.
type InitRequest struct {
	// SOPIN is the initial Security Officer PIN.
	SOPIN string `json:"so_pin,omitempty" yaml:"so_pin,omitempty"`
	// UserPIN is the initial User PIN.
	UserPIN string `json:"user_pin,omitempty" yaml:"user_pin,omitempty"`
	// Threshold is the Shamir "n-of-m" threshold descriptor (for example "3-of-5").
	Threshold string `json:"threshold,omitempty" yaml:"threshold,omitempty"`
	// Hostname is the initial node hostname.
	Hostname string `json:"hostname,omitempty" yaml:"hostname,omitempty"`
	// SANs are subject alternative names to include in the bootstrap certificate.
	SANs []string `json:"sans,omitempty" yaml:"sans,omitempty"`
	// CredentialSealStrategy selects the seal strategy used for credential wrapping.
	CredentialSealStrategy string `json:"credential_seal_strategy,omitempty" yaml:"credential_seal_strategy,omitempty"`
}

// InitResponse is returned by Init.
type InitResponse struct {
	// CeremonyID is the server-assigned ceremony identifier.
	CeremonyID string `json:"ceremony_id,omitempty" yaml:"ceremony_id,omitempty"`
	// State is the current ceremony state.
	State CeremonyState `json:"state,omitempty" yaml:"state,omitempty"`
	// InitializedAt is when the ceremony was initialized.
	InitializedAt *time.Time `json:"initialized_at,omitempty" yaml:"initialized_at,omitempty"`
	// AdminCertPEM is the freshly minted admin client certificate. The
	// operator MUST persist this together with AdminKeyPEM to access the
	// platform after init; the platform does not retain a copy.
	AdminCertPEM string `json:"admin_cert_pem,omitempty" yaml:"admin_cert_pem,omitempty"`
	// AdminKeyPEM is the matching private key in PEM form.
	AdminKeyPEM string `json:"admin_key_pem,omitempty" yaml:"admin_key_pem,omitempty"`
	// SPKIPin is the SHA-256 SubjectPublicKeyInfo pin of the issuing CA.
	SPKIPin string `json:"spki_pin,omitempty" yaml:"spki_pin,omitempty"`
}

// StatusResponse is returned by Status.
type StatusResponse struct {
	// CeremonyID is the server-assigned ceremony identifier.
	CeremonyID string `json:"ceremony_id,omitempty" yaml:"ceremony_id,omitempty"`
	// State is the current ceremony state.
	State CeremonyState `json:"state,omitempty" yaml:"state,omitempty"`
	// Threshold is the Shamir threshold descriptor.
	Threshold string `json:"threshold,omitempty" yaml:"threshold,omitempty"`
	// OfficersEnrolled is the number of officers enrolled so far.
	OfficersEnrolled int32 `json:"officers_enrolled,omitempty" yaml:"officers_enrolled,omitempty"`
	// OfficersRequired is the total number of officers required.
	OfficersRequired int32 `json:"officers_required,omitempty" yaml:"officers_required,omitempty"`
	// InitializedAt is when the ceremony was initialized.
	InitializedAt *time.Time `json:"initialized_at,omitempty" yaml:"initialized_at,omitempty"`
}

// ClaimCertBeginRequest requests a claim-cert challenge for an officer.
type ClaimCertBeginRequest struct {
	// Username identifies the officer claiming the cert.
	Username string `json:"username" yaml:"username"`
	// AuthenticatorType selects the authenticator backend.
	AuthenticatorType AuthenticatorType `json:"authenticator_type" yaml:"authenticator_type"`
	// Slot is the PIV slot id (when AuthenticatorType == piv).
	Slot string `json:"slot,omitempty" yaml:"slot,omitempty"`
	// CredentialID is the FIDO2 credential id (when AuthenticatorType == fido2).
	CredentialID string `json:"credential_id,omitempty" yaml:"credential_id,omitempty"`
}

// ClaimCertBeginResponse returns the nonce and challenge payload the caller
// must sign to complete the claim.
type ClaimCertBeginResponse struct {
	// Nonce is the server-issued challenge nonce (base64).
	Nonce string `json:"nonce,omitempty" yaml:"nonce,omitempty"`
	// ChallengeID identifies the outstanding challenge.
	ChallengeID string `json:"challenge_id,omitempty" yaml:"challenge_id,omitempty"`
	// ExpiresAt is when the challenge expires.
	ExpiresAt *time.Time `json:"expires_at,omitempty" yaml:"expires_at,omitempty"`
}

// ClaimCertCompleteRequest completes an officer claim-cert ceremony.
type ClaimCertCompleteRequest struct {
	// Username identifies the officer completing the claim.
	Username string `json:"username" yaml:"username"`
	// Nonce is the challenge nonce returned from Begin.
	Nonce string `json:"nonce" yaml:"nonce"`
	// Signature is the officer's signature over the nonce (base64).
	Signature string `json:"signature" yaml:"signature"`
}

// ClaimCertCompleteResponse is returned by ClaimCertComplete.
type ClaimCertCompleteResponse struct {
	// Certificate is the issued PEM-encoded officer certificate.
	Certificate string `json:"certificate,omitempty" yaml:"certificate,omitempty"`
	// Chain is the intermediate chain, leaf-first, PEM encoded.
	Chain string `json:"chain,omitempty" yaml:"chain,omitempty"`
}

// ClaimShareBeginRequest requests a share-claim challenge for an officer.
type ClaimShareBeginRequest struct {
	// Username identifies the officer claiming the share.
	Username string `json:"username" yaml:"username"`
}

// ClaimShareBeginResponse returns the nonce the caller must sign with the
// private key matching their claimed certificate.
type ClaimShareBeginResponse struct {
	// Nonce is the server-issued challenge nonce (hex).
	Nonce string `json:"nonce,omitempty" yaml:"nonce,omitempty"`
	// ExpiresAt is when the challenge expires.
	ExpiresAt *time.Time `json:"expires_at,omitempty" yaml:"expires_at,omitempty"`
}

// ClaimShareCompleteRequest completes an officer share-claim ceremony.
type ClaimShareCompleteRequest struct {
	// Username identifies the officer completing the claim.
	Username string `json:"username" yaml:"username"`
	// Nonce is the challenge nonce returned from Begin.
	Nonce string `json:"nonce" yaml:"nonce"`
	// Signature is the officer's signature over the nonce bytes.
	Signature []byte `json:"signature" yaml:"signature"`
}

// ClaimShareCompleteResponse returns the officer's share.
type ClaimShareCompleteResponse struct {
	// Share is the raw Shamir share (base64).
	Share string `json:"share,omitempty" yaml:"share,omitempty"`
	// Index is the 1-based Shamir index.
	Index int32 `json:"index,omitempty" yaml:"index,omitempty"`
}

// SignCSRRequest requests that the SO sign a CSR with the ceremony CA.
type SignCSRRequest struct {
	// Username identifies the officer signing the CSR.
	Username string `json:"username" yaml:"username"`
	// SOPIN is the current SO PIN.
	SOPIN string `json:"so_pin" yaml:"so_pin"`
	// CSRPEM is the base64-encoded PEM CSR body.
	CSRPEM string `json:"csr_pem" yaml:"csr_pem"`
	// Role is the target role for the signed certificate.
	Role OfficerRole `json:"role" yaml:"role"`
}

// SignCSRResponse returns the signed certificate.
type SignCSRResponse struct {
	// Certificate is the issued PEM-encoded certificate.
	Certificate string `json:"certificate,omitempty" yaml:"certificate,omitempty"`
	// Chain is the intermediate chain, leaf-first, PEM encoded.
	Chain string `json:"chain,omitempty" yaml:"chain,omitempty"`
}
