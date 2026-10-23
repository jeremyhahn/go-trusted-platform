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

// Package piv provides SDK types and a client for the platform PIV service
// (Personal Identity Verification, NIST SP 800-73-4).
//
// Requests and responses are transported through the platform SDK PIV client;
// device-side operations are implemented by the composed security stack.
package piv

// Algorithm enumerates the key algorithms PIV supports.
type Algorithm string

const (
	// AlgorithmUnspecified indicates no algorithm was chosen.
	AlgorithmUnspecified Algorithm = ""
	// AlgorithmRSA is an RSA key.
	AlgorithmRSA Algorithm = "rsa"
	// AlgorithmECDSA is an ECDSA key.
	AlgorithmECDSA Algorithm = "ecdsa"
	// AlgorithmEd25519 is an Ed25519 key.
	AlgorithmEd25519 Algorithm = "ed25519"
)

// Device describes a PIV-capable device attached to the host.
type Device struct {
	// ID is a stable identifier (for example serial number) for the device.
	ID string `json:"id" yaml:"id"`
	// Name is a human-readable device name.
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	// Manufacturer is the reported manufacturer.
	Manufacturer string `json:"manufacturer,omitempty" yaml:"manufacturer,omitempty"`
	// Model is the reported model.
	Model string `json:"model,omitempty" yaml:"model,omitempty"`
	// Serial is the reported serial number.
	Serial string `json:"serial,omitempty" yaml:"serial,omitempty"`
	// FirmwareVersion is the reported firmware version.
	FirmwareVersion string `json:"firmware_version,omitempty" yaml:"firmware_version,omitempty"`
}

// Slot describes the contents of a PIV slot.
type Slot struct {
	// ID is the slot identifier (for example "9a", "9c", "82").
	ID string `json:"id" yaml:"id"`
	// Name is the canonical slot name (for example "PIV Authentication").
	Name string `json:"name,omitempty" yaml:"name,omitempty"`
	// Algorithm is the key algorithm in use, if any.
	Algorithm Algorithm `json:"algorithm,omitempty" yaml:"algorithm,omitempty"`
	// HasKey indicates whether a key is present in the slot.
	HasKey bool `json:"has_key" yaml:"has_key"`
	// HasCertificate indicates whether a certificate is present in the slot.
	HasCertificate bool `json:"has_certificate" yaml:"has_certificate"`
}

// ListDevicesRequest is the empty request for ListDevices.
type ListDevicesRequest struct{}

// ListDevicesResponse returns the list of attached PIV devices.
type ListDevicesResponse struct {
	// Devices are the PIV devices currently attached.
	Devices []Device `json:"devices,omitempty" yaml:"devices,omitempty"`
}

// ListSlotsRequest requests the slot listing for one device.
type ListSlotsRequest struct {
	// Device is the target device id.
	Device string `json:"device" yaml:"device"`
}

// ListSlotsResponse returns the slots available on a device.
type ListSlotsResponse struct {
	// Slots are the slots present on the device.
	Slots []Slot `json:"slots,omitempty" yaml:"slots,omitempty"`
}

// SlotInfoRequest requests detail on a specific slot.
type SlotInfoRequest struct {
	// Slot is the PIV slot id.
	Slot string `json:"slot" yaml:"slot"`
	// Device optionally selects a device; empty means server default.
	Device string `json:"device,omitempty" yaml:"device,omitempty"`
}

// SlotInfoResponse returns the detailed slot contents.
type SlotInfoResponse struct {
	// Slot is the canonical slot view.
	Slot Slot `json:"slot" yaml:"slot"`
	// PublicKeyPEM is the slot's public key in PEM form, if any.
	PublicKeyPEM string `json:"public_key_pem,omitempty" yaml:"public_key_pem,omitempty"`
	// CertificatePEM is the slot's certificate in PEM form, if any.
	CertificatePEM string `json:"certificate_pem,omitempty" yaml:"certificate_pem,omitempty"`
}

// GenerateRequest asks the PIV service to generate a key in a slot.
type GenerateRequest struct {
	// Slot is the target slot id.
	Slot string `json:"slot" yaml:"slot"`
	// Algorithm selects the key algorithm.
	Algorithm Algorithm `json:"algorithm" yaml:"algorithm"`
	// PIN is the user PIN.
	PIN string `json:"pin" yaml:"pin"`
}

// GenerateResponse returns the generated key's public material.
type GenerateResponse struct {
	// PublicKeyPEM is the freshly generated public key in PEM form.
	PublicKeyPEM string `json:"public_key_pem,omitempty" yaml:"public_key_pem,omitempty"`
}

// ImportRequest asks the PIV service to import an externally generated key.
type ImportRequest struct {
	// Slot is the target slot id.
	Slot string `json:"slot" yaml:"slot"`
	// PrivateKeyPEM is the PEM-encoded private key body.
	PrivateKeyPEM string `json:"private_key_pem" yaml:"private_key_pem"`
	// PIN is the user PIN.
	PIN string `json:"pin" yaml:"pin"`
}

// ImportResponse reports whether the import succeeded.
type ImportResponse struct {
	// Imported is true when the import completed without error.
	Imported bool `json:"imported" yaml:"imported"`
}

// SignRequest asks the PIV service to sign a payload with a slot's key.
type SignRequest struct {
	// Slot is the signing slot id.
	Slot string `json:"slot" yaml:"slot"`
	// Payload is the data to sign (raw bytes, base64 over the wire).
	Payload []byte `json:"payload" yaml:"payload"`
	// PIN is the user PIN.
	PIN string `json:"pin" yaml:"pin"`
}

// SignResponse returns the raw signature bytes.
type SignResponse struct {
	// Signature is the slot's signature over the payload.
	Signature []byte `json:"signature,omitempty" yaml:"signature,omitempty"`
}

// AttestRequest asks the PIV service to attest a slot's key.
type AttestRequest struct {
	// Slot is the slot to attest.
	Slot string `json:"slot" yaml:"slot"`
}

// AttestResponse returns the attestation certificate(s).
type AttestResponse struct {
	// AttestationCertPEM is the slot's attestation cert in PEM form.
	AttestationCertPEM string `json:"attestation_cert_pem,omitempty" yaml:"attestation_cert_pem,omitempty"`
	// AttestationChainPEM is the concatenated intermediate chain, leaf first.
	AttestationChainPEM string `json:"attestation_chain_pem,omitempty" yaml:"attestation_chain_pem,omitempty"`
}

// ResetRequest asks the PIV service to factory-reset the target device.
type ResetRequest struct {
	// Device is the device id.
	Device string `json:"device" yaml:"device"`
}

// ResetResponse reports the reset outcome.
type ResetResponse struct {
	// Reset is true when the reset completed without error.
	Reset bool `json:"reset" yaml:"reset"`
}
