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

// Package fido2 provides SDK types and a client for the platform FIDO2 /
// WebAuthn service.
//
// Scope: device enumeration (CTAP2) and WebAuthn register / authenticate. LUKS
// FIDO2 enrollment lives in the luks package.
//
// The Phase 3 implementation is a scaffolding-only SDK: all client methods
// return ErrNotYetWired until server-side handlers land in Phase 3.5.
package fido2

// Role enumerates the ceremony roles a WebAuthn credential may be registered for.
type Role string

const (
	// RoleUnspecified indicates no role was provided.
	RoleUnspecified Role = ""
	// RoleSO is the Security Officer role.
	RoleSO Role = "so"
	// RoleAdmin is the Admin officer role.
	RoleAdmin Role = "admin"
	// RoleUser is the User officer role.
	RoleUser Role = "user"
)

// Device describes a FIDO2 authenticator attached to the host.
type Device struct {
	// ID is a stable identifier for the authenticator.
	ID string `json:"id" yaml:"id"`
	// Path is the OS-level device path (hidraw / usb-hid).
	Path string `json:"path,omitempty" yaml:"path,omitempty"`
	// Manufacturer is the reported manufacturer.
	Manufacturer string `json:"manufacturer,omitempty" yaml:"manufacturer,omitempty"`
	// Product is the reported product name.
	Product string `json:"product,omitempty" yaml:"product,omitempty"`
	// ProductID is the USB product id.
	ProductID uint32 `json:"product_id,omitempty" yaml:"product_id,omitempty"`
	// VendorID is the USB vendor id.
	VendorID uint32 `json:"vendor_id,omitempty" yaml:"vendor_id,omitempty"`
}

// Info describes an attached FIDO2 authenticator's capabilities.
type Info struct {
	// Device is the device the info applies to.
	Device Device `json:"device" yaml:"device"`
	// AAGUID is the authenticator attestation GUID.
	AAGUID string `json:"aaguid,omitempty" yaml:"aaguid,omitempty"`
	// FirmwareVersion is the reported firmware version.
	FirmwareVersion string `json:"firmware_version,omitempty" yaml:"firmware_version,omitempty"`
	// Extensions lists the CTAP2 extensions the device implements.
	Extensions []string `json:"extensions,omitempty" yaml:"extensions,omitempty"`
	// Options is the authenticator options map (for example rk, uv, clientPin).
	Options map[string]bool `json:"options,omitempty" yaml:"options,omitempty"`
	// MaxMsgSize is the maximum CTAP2 message size in bytes.
	MaxMsgSize uint32 `json:"max_msg_size,omitempty" yaml:"max_msg_size,omitempty"`
}

// ListDevicesRequest is the empty request for ListDevices.
type ListDevicesRequest struct{}

// ListDevicesResponse enumerates attached authenticators.
type ListDevicesResponse struct {
	// Devices are the authenticators currently attached.
	Devices []Device `json:"devices,omitempty" yaml:"devices,omitempty"`
}

// WaitDeviceRequest asks the service to block until a device arrives.
type WaitDeviceRequest struct {
	// TimeoutSeconds is the maximum time to wait; 0 waits indefinitely.
	TimeoutSeconds int32 `json:"timeout_seconds,omitempty" yaml:"timeout_seconds,omitempty"`
}

// WaitDeviceResponse returns the first device that arrived.
type WaitDeviceResponse struct {
	// Device is the device that appeared.
	Device Device `json:"device" yaml:"device"`
}

// InfoRequest asks for detailed device info.
type InfoRequest struct {
	// Device is the target device id.
	Device string `json:"device" yaml:"device"`
}

// InfoResponse returns the device info.
type InfoResponse struct {
	// Info is the device's capability profile.
	Info Info `json:"info" yaml:"info"`
}

// RegisterRequest registers a WebAuthn credential for an officer / user.
type RegisterRequest struct {
	// Username identifies the user being registered.
	Username string `json:"username" yaml:"username"`
	// Role is the ceremony role to bind the credential to.
	Role Role `json:"role,omitempty" yaml:"role,omitempty"`
	// RequirePIN requires the authenticator's PIN during the ceremony.
	RequirePIN bool `json:"require_pin" yaml:"require_pin"`
	// RequireUV requires user verification (biometric / PIN).
	RequireUV bool `json:"require_uv" yaml:"require_uv"`
	// RPID overrides the relying party id.
	RPID string `json:"rp_id,omitempty" yaml:"rp_id,omitempty"`
}

// RegisterResponse returns the registered credential's identifiers.
type RegisterResponse struct {
	// CredentialID is the newly registered credential's id (base64url).
	CredentialID string `json:"credential_id,omitempty" yaml:"credential_id,omitempty"`
	// AAGUID is the attestation AAGUID of the authenticator.
	AAGUID string `json:"aaguid,omitempty" yaml:"aaguid,omitempty"`
	// PublicKeyPEM is the credential's public key in PEM form.
	PublicKeyPEM string `json:"public_key_pem,omitempty" yaml:"public_key_pem,omitempty"`
}

// AuthenticateRequest tests an authentication ceremony against a credential.
type AuthenticateRequest struct {
	// CredentialID is the credential to test.
	CredentialID string `json:"credential_id" yaml:"credential_id"`
}

// AuthenticateResponse reports the outcome of the authentication ceremony.
type AuthenticateResponse struct {
	// Authenticated is true when the ceremony succeeded.
	Authenticated bool `json:"authenticated" yaml:"authenticated"`
	// Counter is the authenticator's post-ceremony signature counter.
	Counter uint32 `json:"counter,omitempty" yaml:"counter,omitempty"`
}
