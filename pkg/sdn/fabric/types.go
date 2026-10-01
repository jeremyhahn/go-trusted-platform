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

package fabric

// PortRef identifies a specific switch port, optionally associated with
// a LAG group.
type PortRef struct {
	// SwitchID identifies the switch this port belongs to.
	SwitchID string `yaml:"switch-id" json:"switch_id" mapstructure:"switch-id"`

	// Port is the interface name (e.g., "Ethernet1/1").
	Port string `yaml:"port" json:"port" mapstructure:"port"`

	// LAGID optionally associates this port with a LAG group.
	LAGID string `yaml:"lag-id,omitempty" json:"lag_id,omitempty" mapstructure:"lag-id"`
}

// Validate checks that the port reference has all required fields.
func (p PortRef) Validate() error {
	if p.SwitchID == "" {
		return ErrInvalidPortRef{Reason: "switch-id is required"}
	}
	if p.Port == "" {
		return ErrInvalidPortRef{Reason: "port is required"}
	}
	return nil
}

// SwitchStatus represents the health state of a fabric switch.
type SwitchStatus struct {
	// ID is the switch identifier from configuration.
	ID string `json:"id"`

	// Connected indicates whether the driver has an active connection.
	Connected bool `json:"connected"`

	// Vendor is the switch vendor string.
	Vendor string `json:"vendor"`

	// Model is the switch model string.
	Model string `json:"model"`

	// MgmtIP is the management IP address.
	MgmtIP string `json:"mgmt_ip"`
}
