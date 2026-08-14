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

package auth

import (
	"time"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
)

// AddFactorRequest captures the canonical "auth factor add" /
// "auth factor rotate" flag set in a transport-agnostic shape.
type AddFactorRequest struct {
	// Type selects the factor flavor: "mtls", "fido2", or "piv".
	Type string

	// Label is the human-readable factor label (required).
	Label string

	// User is the subject (username / user-id). Empty resolves to the
	// calling identity server-side.
	User string

	// Tenant is the tenant scope (optional).
	Tenant string

	// CertPath is the certificate PEM path used by --type mtls.
	CertPath string

	// FIDO2Device pins a FIDO2 enrollment to a specific device id.
	FIDO2Device string

	// PIVReader selects the go-xkms PIV backend holding the slot
	// certificate (--type piv). The upstream PC/SC reader model was
	// replaced by backend-scoped slots (file/software | pkcs11 | tpm2);
	// this field carries the backend name and defaults to "software".
	PIVReader string

	// PIVSlot is the PIV slot id used by --type piv (default "9a").
	PIVSlot string
}

// LoginRequest captures the canonical "auth login" flag set.
type LoginRequest struct {
	// Username identifies the user logging in. May be empty when the
	// server can resolve the user from the presented credential
	// (e.g., mTLS client cert).
	Username string

	// Tenant scopes the login ceremony to a tenant so the registered
	// factor authenticator can apply per-tenant configuration when it
	// issues the challenge (e.g. the WebAuthn relying-party id/origin).
	// Empty selects the server's default/global configuration.
	Tenant string

	// Method selects the auth method ("mtls", "fido2", "piv").
	// Empty enables client-side auto-discovery.
	Method string

	// FactorID pins the login to a specific enrolled factor. Optional
	// — retained for CLI compatibility. The unified login ceremony
	// resolves the factor from its credential lookup key, so this value
	// is carried as method metadata only.
	FactorID string

	// ClientCertPath overrides the default client certificate path used
	// by --method mtls. When empty, the SDK probes
	// PLATFORMCTL_CLIENT_CERT (and equivalents) and standard locations
	// such as ~/.platformctl/admin.pem.
	ClientCertPath string

	// RPID is retained for CLI compatibility. The WebAuthn relying-party
	// id is NOT a client choice: it is carried by the server-issued
	// PublicKeyCredentialRequestOptions returned by BeginLogin and the
	// authenticator binds the assertion to it, so this value is unused.
	RPID string

	// Device pins the --method fido2 flow to a specific client-LOCAL
	// authenticator (matched by quicbaas.LocalDevice.Path as enumerated
	// by Security().Auth().Devices()).
	Device string

	// Reader selects the go-xkms PIV backend used by --method piv. The
	// upstream PC/SC reader model was replaced by backend-scoped slots
	// (file/software | pkcs11 | tpm2); this field carries the backend
	// name and defaults to "software".
	Reader string

	// Slot is the PIV slot id (default "9a"). Optional.
	Slot string

	// PIN is the PIV User PIN required by backends that enforce one
	// (pkcs11, hardware tokens) under --method piv. Callers should
	// resolve this from a viper-bound environment variable
	// (PLATFORMCTL_USER_PIN, etc.) or prompt the operator out of band.
	PIN string
}

// EnrollmentResult is the canonical "auth factor add / rotate"
// success summary.
type EnrollmentResult = quicbaas.AuthFactorEnrollResponse

// ListResult is the canonical "auth factor list" success result.
type ListResult = quicbaas.AuthFactorListResponse

// ListEntry is a single entry in a ListResult.
type ListEntry = quicbaas.AuthFactorEntry

// LoginResult is the canonical "auth login" success summary. It is the
// platform projection of the unified login ceremony's
// quicbaas.FinishLoginResponse (bearer + resolved identity).
type LoginResult struct {
	// UserID is the resolved principal subject.
	UserID string

	// Username is the resolved principal subject (falls back to the
	// request's Username when the server returns no identity).
	Username string

	// TenantID is the tenant scope of the resolved identity.
	TenantID string

	// Token is the issued session bearer.
	Token string

	// RefreshToken renews the session without re-running the factor
	// ceremony. Rotated on every redemption.
	RefreshToken string

	// FactorID identifies the enrolled factor that authorized the login.
	FactorID string

	// IssuedAt records when the login ceremony completed client-side;
	// the wire response does not carry an issuance timestamp.
	IssuedAt time.Time

	// ExpiresAt is the bearer's expiry time.
	ExpiresAt time.Time
}
