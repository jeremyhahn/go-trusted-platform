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

package configdelivery

import (
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	devicewire "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/device"
)

// ConfigRequest is sent by a device during boot to request its platform configuration.
type ConfigRequest struct {
	EKSerial   string `json:"ek_serial,omitempty"`
	MACAddress string `json:"mac_address,omitempty"`
	// EKCert is the standard-base64 encoding of the DER-encoded TPM Endorsement
	// Key certificate the booting device presents. When the matched profile has
	// a prestaged EKCert (or EK matching is required) the resolver parses this
	// certificate and compares its public key against the prestaged one before
	// releasing any configuration.
	EKCert   string `json:"ek_cert,omitempty"`
	EABKeyID string `json:"eab_key_id"`
	EABHMAC  string `json:"eab_hmac"`
	Nonce    string `json:"nonce"`
}

// ConfigResponse contains the platform configuration for the device.
type ConfigResponse struct {
	Config any    `json:"config"`
	Status string `json:"status"`
}

// SignRequest is sent by a bare-metal node in resign-mode "remote" to have its
// UKI (or kernel-module) digest signed by the control-plane KMS Secure Boot DB
// key. The private key never leaves the control plane: only the digest crosses
// the wire. The request is authenticated exactly like ConfigRequest — EAB
// credentials, a single-use nonce, and (when the matched profile is EK-bound)
// the device's TPM Endorsement Key certificate — because at install time the
// node has no IDevID yet for mTLS.
type SignRequest struct {
	EKSerial   string `json:"ek_serial,omitempty"`
	MACAddress string `json:"mac_address,omitempty"`
	// EKCert is the standard-base64 encoding of the DER-encoded TPM Endorsement
	// Key certificate the node presents; it is compared against the profile's
	// prestaged EK certificate before any signing occurs.
	EKCert   string `json:"ek_cert,omitempty"`
	EABKeyID string `json:"eab_key_id"`
	EABHMAC  string `json:"eab_hmac"`
	Nonce    string `json:"nonce"`
	// Digest is the pre-computed message digest to sign (the SHA-256/384/512
	// Authenticode hash of the UKI, or a kernel-module digest). Marshalled as
	// base64 by encoding/json.
	Digest []byte `json:"digest"`
	// KeyRef selects which Secure Boot key signs the digest. Only the database
	// (DB) key performs remote hash-signing; an empty value defaults to "db".
	KeyRef string `json:"key_ref,omitempty"`
}

// SignResponse carries the detached signature over the requested digest and the
// PEM-encoded Secure Boot DB certificate so the node can embed it in the UKI
// Authenticode signature and enroll it into the firmware signature database.
type SignResponse struct {
	Signature []byte `json:"signature"`
	CertPEM   []byte `json:"cert_pem"`
}

// PendingResponse is returned when no matching config exists and the device
// should enter interactive (QR code) mode.
type PendingResponse struct {
	SessionID    string `json:"session_id"`
	ProvisionURL string `json:"provision_url"`
	PollInterval int    `json:"poll_interval_seconds"`
}

// FulfillRequest is sent by an operator to link a profile to a pending session.
//
// ProfileID is the device wire id type (#375): it decodes from a JSON string
// or a JSON number and rejects anything else with a typed error. Profile ids
// are minted above 2^53, so a JavaScript client can only send them safely as
// strings; a plain uint64 here refused exactly that encoding (#418).
type FulfillRequest struct {
	SessionID string        `json:"session_id"`
	ProfileID devicewire.ID `json:"profile_id"`
}

// NonceResponse is the response body for nonce issuance.
type NonceResponse struct {
	Nonce string `json:"nonce"`
}

// PollPendingResponse is returned when a session has not yet been fulfilled.
type PollPendingResponse struct {
	Status string `json:"status"`
}

// Session represents a pending provisioning session waiting for operator fulfillment.
type Session struct {
	ID         string `json:"id"`
	EKSerial   string `json:"ek_serial,omitempty"`
	MACAddress string `json:"mac_address,omitempty"`
	TenantID   string `json:"tenant_id,omitempty"`
	// ProfileID is the device wire id type (#375): emitted as a JSON string,
	// because profile ids are minted above 2^53 and a JSON number at that
	// magnitude is rounded by every JavaScript client (#425).
	ProfileID devicewire.ID           `json:"profile_id,omitempty"`
	Profile   *entities.DeviceProfile `json:"profile,omitempty"`
	Fulfilled bool                    `json:"fulfilled"`
	CreatedAt time.Time               `json:"created_at"`
	ExpiresAt time.Time               `json:"expires_at"`
}
