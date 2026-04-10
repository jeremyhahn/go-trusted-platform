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

package entities

import (
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

// DeviceState represents the current state of a device
type DeviceState string

const (
	// DeviceStateUnknown indicates the device state is unknown
	DeviceStateUnknown DeviceState = "unknown"

	// DeviceStateRegistered indicates the device has been registered
	DeviceStateRegistered DeviceState = "registered"

	// DeviceStateActivated indicates the device has been activated
	DeviceStateActivated DeviceState = "activated"

	// DeviceStateAttested indicates the device has been attested
	DeviceStateAttested DeviceState = "attested"

	// DeviceStateSuspended indicates the device has been suspended
	DeviceStateSuspended DeviceState = "suspended"

	// DeviceStateRevoked indicates the device has been revoked
	DeviceStateRevoked DeviceState = "revoked"
)

// String returns the string representation of DeviceState
func (s DeviceState) String() string {
	return string(s)
}

// IsValid checks if the DeviceState is valid
func (s DeviceState) IsValid() bool {
	switch s {
	case DeviceStateUnknown, DeviceStateRegistered, DeviceStateActivated,
		DeviceStateAttested, DeviceStateSuspended, DeviceStateRevoked:
		return true
	default:
		return false
	}
}

// Device represents a registered device with TPM attestation capabilities
type Device struct {
	ID       uint64 `yaml:"id" json:"id"`
	TenantID string `yaml:"tenant_id" json:"tenant_id"`

	AttestPub  string `yaml:"att-pub" json:"att_pub"`
	EKCert     string `yaml:"ek-cert" json:"ek_cert"`
	EventLog   []byte `yaml:"event-log" json:"event_log"`
	HashAlgoId uint32 `yaml:"hash-algo" json:"hash_algo"`
	Model      string `yaml:"model" json:"model"`
	Serial     string `yaml:"serial" json:"serial"`
	SigningPub string `yaml:"signing-pub" json:"signing_pub"`

	// State tracking fields
	State           DeviceState `yaml:"state" json:"state"`
	StateReason     string      `yaml:"state_reason" json:"state_reason,omitempty"`
	ActivatedAt     time.Time   `yaml:"activated_at" json:"activated_at,omitempty"`
	LastAttestedAt  time.Time   `yaml:"last_attested_at" json:"last_attested_at,omitempty"`
	LastHeartbeatAt time.Time   `yaml:"last_heartbeat_at" json:"last_heartbeat_at,omitempty"`
	CreatedAt       time.Time   `yaml:"created_at" json:"created_at"`
	UpdatedAt       time.Time   `yaml:"updated_at" json:"updated_at"`

	entities.KeyValueEntity `yaml:"-" json:"-"`
}

func (d *Device) EntityID() uint64 {
	return d.ID
}

func (d *Device) SetEntityID(id uint64) {
	d.ID = id
}

// IsActivated returns true if the device has been activated
func (d *Device) IsActivated() bool {
	return d.State == DeviceStateActivated || d.State == DeviceStateAttested
}

// IsAttested returns true if the device has been successfully attested
func (d *Device) IsAttested() bool {
	return d.State == DeviceStateAttested
}

// CanActivate returns true if the device can be activated from its current state
func (d *Device) CanActivate() bool {
	return d.State == DeviceStateRegistered || d.State == DeviceStateUnknown
}

// CanAttest returns true if the device can be attested from its current state
func (d *Device) CanAttest() bool {
	return d.State == DeviceStateActivated || d.State == DeviceStateAttested
}
