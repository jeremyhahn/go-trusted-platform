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

	// PIVReader is the PC/SC reader name used by --type piv.
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

	// Method selects the auth method ("mtls", "fido2", "piv").
	// Empty enables client-side auto-discovery.
	Method string

	// FactorID pins the login to a specific enrolled factor. Optional
	// — only required when the user has multiple factors of the same
	// type enrolled.
	FactorID string

	// ClientCertPath overrides the default client certificate path used
	// by --method mtls. When empty, the SDK probes
	// PLATFORMCTL_CLIENT_CERT (and equivalents) and standard locations
	// such as ~/.platformctl/admin.pem.
	ClientCertPath string

	// RPID is the WebAuthn Relying-Party ID used by --method fido2.
	// When empty, "platform" is used.
	RPID string

	// Device pins the --method fido2 flow to a specific authenticator
	// (matched by FIDO2Device.DeviceID).
	Device string

	// Reader pins the --method piv flow to a specific PC/SC reader
	// (matched by PIVReader.Name).
	Reader string

	// Slot is the PIV slot id (default "9a"). Optional.
	Slot string

	// PIN is the PIV User PIN required for signing operations under
	// --method piv. Callers should resolve this from a viper-bound
	// environment variable (PLATFORMCTL_USER_PIN, etc.) or prompt the
	// operator out of band.
	PIN string
}

// EnrollmentResult is the canonical "auth factor add / rotate"
// success summary.
type EnrollmentResult = quicbaas.AuthFactorEnrollResponse

// ListResult is the canonical "auth factor list" success result.
type ListResult = quicbaas.AuthFactorListResponse

// ListEntry is a single entry in a ListResult.
type ListEntry = quicbaas.AuthFactorEntry

// LoginResult is the canonical "auth login" success summary.
type LoginResult = quicbaas.AuthFactorLoginResponse
