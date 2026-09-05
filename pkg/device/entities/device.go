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
	"fmt"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

// DeviceState represents the current lifecycle state of a device.
type DeviceState string

const (
	// DeviceStateUnknown indicates the device state is unknown.
	DeviceStateUnknown DeviceState = "unknown"

	// DeviceStateRegistered indicates the device has been registered.
	DeviceStateRegistered DeviceState = "registered"

	// DeviceStateInstalling indicates a bare-metal device is running its
	// operating-system install / EK-bootstrap flow. It sits between Registered
	// and Installed for devices that must be provisioned before activation.
	DeviceStateInstalling DeviceState = "installing"

	// DeviceStateInstalled indicates a bare-metal device has finished its
	// install / EK-bootstrap flow and is ready to be activated.
	DeviceStateInstalled DeviceState = "installed"

	// DeviceStateActivated indicates the device has been activated.
	DeviceStateActivated DeviceState = "activated"

	// DeviceStateAttested indicates the device has been attested successfully.
	DeviceStateAttested DeviceState = "attested"

	// DeviceStateQuarantined indicates the device has been moved to the quarantine
	// zone due to a non-severe attestation violation. The device is restricted to
	// the quarantine network and awaits remediation. PriorState and PriorZone on
	// the Device are set to allow restore when re-attestation succeeds.
	DeviceStateQuarantined DeviceState = "quarantined"

	// DeviceStateSuspended indicates the device has been suspended due to a severe
	// violation or certificate revocation. The port is set admin-down (blocked).
	DeviceStateSuspended DeviceState = "suspended"

	// DeviceStateRevoked indicates the device has been revoked.
	DeviceStateRevoked DeviceState = "revoked"
)

// allowedTransitions is the complete state transition table. A key is the
// current state; the value is the set of states reachable from it.
var allowedTransitions = map[DeviceState]map[DeviceState]struct{}{
	DeviceStateUnknown: {
		DeviceStateRegistered: {},
	},
	DeviceStateRegistered: {
		// Installing covers the bare-metal install / EK-bootstrap flow.
		// Activated is preserved for non-bare-metal devices that register and
		// activate directly without an install step.
		DeviceStateInstalling:  {},
		DeviceStateActivated:   {},
		DeviceStateQuarantined: {},
		DeviceStateSuspended:   {},
		DeviceStateRevoked:     {},
	},
	DeviceStateInstalling: {
		DeviceStateInstalled:   {},
		DeviceStateQuarantined: {},
		DeviceStateSuspended:   {},
		DeviceStateRevoked:     {},
	},
	DeviceStateInstalled: {
		DeviceStateActivated:   {},
		DeviceStateQuarantined: {},
		DeviceStateSuspended:   {},
		DeviceStateRevoked:     {},
	},
	DeviceStateActivated: {
		DeviceStateAttested:    {},
		DeviceStateQuarantined: {},
		DeviceStateSuspended:   {},
		DeviceStateRevoked:     {},
	},
	DeviceStateAttested: {
		DeviceStateQuarantined: {},
		DeviceStateSuspended:   {},
		DeviceStateRevoked:     {},
	},
	DeviceStateQuarantined: {
		// Re-attestation success restores to attested; operator may also
		// escalate to suspended or revoke.
		DeviceStateAttested:  {},
		DeviceStateSuspended: {},
		DeviceStateRevoked:   {},
	},
	DeviceStateSuspended: {
		// Manual operator restore only; can also be revoked.
		DeviceStateAttested: {},
		DeviceStateRevoked:  {},
	},
	DeviceStateRevoked: {
		// Terminal state — no further transitions allowed.
	},
}

// ErrInvalidTransition is returned when a requested state transition is
// not permitted by the device lifecycle state machine.
type ErrInvalidTransition struct {
	From DeviceState
	To   DeviceState
}

// Error implements the error interface.
func (e ErrInvalidTransition) Error() string {
	return fmt.Sprintf("device: invalid state transition %s → %s", e.From, e.To)
}

// String returns the string representation of DeviceState.
func (s DeviceState) String() string {
	return string(s)
}

// IsValid reports whether the DeviceState value is a recognised constant.
func (s DeviceState) IsValid() bool {
	switch s {
	case DeviceStateUnknown, DeviceStateRegistered, DeviceStateInstalling,
		DeviceStateInstalled, DeviceStateActivated, DeviceStateAttested,
		DeviceStateQuarantined, DeviceStateSuspended, DeviceStateRevoked:
		return true
	default:
		return false
	}
}

// CanTransitionTo reports whether the state machine permits a transition from
// s to next. It returns ErrInvalidTransition when the transition is rejected.
func (s DeviceState) CanTransitionTo(next DeviceState) error {
	targets, ok := allowedTransitions[s]
	if !ok {
		return ErrInvalidTransition{From: s, To: next}
	}
	if _, allowed := targets[next]; !allowed {
		return ErrInvalidTransition{From: s, To: next}
	}
	return nil
}

// Device represents a registered device with TPM attestation capabilities.
type Device struct {
	ID       uint64 `yaml:"id" json:"id"`
	TenantID string `yaml:"tenant_id" json:"tenant_id"`

	AttestPub string `yaml:"att-pub" json:"att_pub"`
	// AttestCert is the PEM-encoded certificate for the attestation key,
	// issued by the platform CA at enrollment. When present it is the trust
	// anchor for quote verification in place of the bare AttestPub, and it
	// must carry tcg-cap-verifiedTPMRestricted — the relying-party check TCG
	// DevID v1 r12 §8.2 requires before signed data is trusted as TPM
	// internal data (#374).
	AttestCert string `yaml:"att-cert,omitempty" json:"attest_cert,omitempty"`
	EKCert     string `yaml:"ek-cert" json:"ek_cert"`
	EventLog   []byte `yaml:"event-log" json:"event_log"`
	HashAlgoId uint32 `yaml:"hash-algo" json:"hash_algo"`
	Model      string `yaml:"model" json:"model"`
	Serial     string `yaml:"serial" json:"serial"`
	// Hostname is the IDevID common name (FQDN) recorded at enrollment. It is
	// used by the quarantine observer to map a manifest HostID to this record.
	Hostname   string `yaml:"hostname,omitempty" json:"hostname,omitempty"`
	SigningPub string `yaml:"signing-pub" json:"signing_pub"`

	// SwitchName identifies the physical switch managing this device's port.
	SwitchName string `yaml:"switch-name,omitempty" json:"switch_name,omitempty"`

	// SwitchPort is the physical port identifier on the switch (e.g., "Eth1/3").
	SwitchPort string `yaml:"switch-port,omitempty" json:"switch_port,omitempty"`

	// NetworkPortID is the OVS port (tap/interface name) the device's NIC is
	// attached to, stamped at SDN enrollment activation. This is distinct from
	// SwitchPort, which identifies the physical switch port. The quarantine
	// observer uses this field to address the correct OVS port on violation and
	// restore events without fabricating names from device IDs.
	NetworkPortID string `yaml:"network-port-id,omitempty" json:"network_port_id,omitempty"`

	// State tracking fields
	State           DeviceState `yaml:"state" json:"state"`
	StateReason     string      `yaml:"state_reason" json:"state_reason,omitempty"`
	ActivatedAt     time.Time   `yaml:"activated_at" json:"activated_at,omitempty"`
	LastAttestedAt  time.Time   `yaml:"last_attested_at" json:"last_attested_at,omitempty"`
	LastHeartbeatAt time.Time   `yaml:"last_heartbeat_at" json:"last_heartbeat_at,omitempty"`

	// LastHeartbeatAddr is the transport peer address (host:port) the most
	// recent heartbeat arrived from. It is recorded from the mTLS-verified
	// connection, never from the request body, so the attestation collector
	// may use it as a dial candidate (#377): an attacker who can only forge
	// a body cannot redirect the collector, and one who holds the device's
	// client credential is the device.
	LastHeartbeatAddr string    `yaml:"last_heartbeat_addr,omitempty" json:"last_heartbeat_addr,omitempty"`
	CreatedAt         time.Time `yaml:"created_at" json:"created_at"`
	UpdatedAt         time.Time `yaml:"updated_at" json:"updated_at"`

	// PriorState records the state the device held immediately before being
	// quarantined. It is used by the remediation restore path to return the
	// device to the correct lifecycle state when re-attestation succeeds.
	PriorState DeviceState `yaml:"prior_state,omitempty" json:"prior_state,omitempty"`

	// PriorZone records the zone name the device was assigned to before
	// quarantine, so zone flows can be restored on remediation success.
	PriorZone string `yaml:"prior_zone,omitempty" json:"prior_zone,omitempty"`

	// BMCEnrollment records the outcome of the most recent BMC enrollment
	// ceremony for this device, or nil when the BMC has never been enrolled.
	BMCEnrollment *BMCEnrollment `yaml:"bmc_enrollment,omitempty" json:"bmc_enrollment,omitempty"`

	entities.KeyValueEntity `yaml:"-" json:"-"`
}

// EntityID returns the device's unique identifier.
func (d *Device) EntityID() uint64 {
	return d.ID
}

// SetEntityID sets the device's unique identifier.
func (d *Device) SetEntityID(id uint64) {
	d.ID = id
}

// IsInstalling returns true if the device is running its install / EK-bootstrap flow.
func (d *Device) IsInstalling() bool {
	return d.State == DeviceStateInstalling
}

// IsInstalled returns true if the device has completed its install / EK-bootstrap flow.
func (d *Device) IsInstalled() bool {
	return d.State == DeviceStateInstalled
}

// IsActivated returns true if the device has been activated.
func (d *Device) IsActivated() bool {
	return d.State == DeviceStateActivated || d.State == DeviceStateAttested
}

// IsAttested returns true if the device has been successfully attested.
func (d *Device) IsAttested() bool {
	return d.State == DeviceStateAttested
}

// IsQuarantined returns true if the device is currently in the quarantine zone.
func (d *Device) IsQuarantined() bool {
	return d.State == DeviceStateQuarantined
}

// CanActivate returns true if the device can be activated from its current state.
func (d *Device) CanActivate() bool {
	return d.State == DeviceStateRegistered || d.State == DeviceStateUnknown
}

// CanAttest returns true if the device can be attested from its current state.
func (d *Device) CanAttest() bool {
	return d.State == DeviceStateActivated || d.State == DeviceStateAttested
}

// Transition attempts to move the device to next state using the state machine.
// It returns ErrInvalidTransition when the transition is not permitted.
func (d *Device) Transition(next DeviceState) error {
	if err := d.State.CanTransitionTo(next); err != nil {
		return err
	}
	d.State = next
	d.UpdatedAt = time.Now()
	return nil
}
