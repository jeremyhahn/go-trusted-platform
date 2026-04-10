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
)

// ConfigRequest is sent by a device during boot to request its platform configuration.
type ConfigRequest struct {
	EKSerial   string `json:"ek_serial,omitempty"`
	MACAddress string `json:"mac_address,omitempty"`
	EABKeyID   string `json:"eab_key_id"`
	EABHMAC    string `json:"eab_hmac"`
	Nonce      string `json:"nonce"`
}

// ConfigResponse contains the platform configuration for the device.
type ConfigResponse struct {
	Config any    `json:"config"`
	Status string `json:"status"`
}

// PendingResponse is returned when no matching config exists and the device
// should enter interactive (QR code) mode.
type PendingResponse struct {
	SessionID    string `json:"session_id"`
	ProvisionURL string `json:"provision_url"`
	PollInterval int    `json:"poll_interval_seconds"`
}

// FulfillRequest is sent by an operator to link a profile to a pending session.
type FulfillRequest struct {
	SessionID string `json:"session_id"`
	ProfileID uint64 `json:"profile_id"`
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
	ID         string                  `json:"id"`
	EKSerial   string                  `json:"ek_serial,omitempty"`
	MACAddress string                  `json:"mac_address,omitempty"`
	TenantID   string                  `json:"tenant_id,omitempty"`
	ProfileID  uint64                  `json:"profile_id,omitempty"`
	Profile    *entities.DeviceProfile `json:"profile,omitempty"`
	Fulfilled  bool                    `json:"fulfilled"`
	CreatedAt  time.Time               `json:"created_at"`
	ExpiresAt  time.Time               `json:"expires_at"`
}
