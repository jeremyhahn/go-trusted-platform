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

import "fmt"

// DefaultBMCIPMIPort is the default IPMI port.
const DefaultBMCIPMIPort = 623

// DefaultBMCRedfishPort is the default Redfish port.
const DefaultBMCRedfishPort = 443

// BMCProtocol represents the BMC communication protocol.
type BMCProtocol string

const (
	// BMCProtocolIPMI represents IPMI 2.0 communication.
	BMCProtocolIPMI BMCProtocol = "ipmi"
	// BMCProtocolRedfish represents Redfish REST API communication.
	BMCProtocolRedfish BMCProtocol = "redfish"
)

// String returns the string representation of BMCProtocol.
func (p BMCProtocol) String() string {
	return string(p)
}

// IsValid checks if the BMCProtocol is a supported protocol.
func (p BMCProtocol) IsValid() bool {
	switch p {
	case BMCProtocolIPMI, BMCProtocolRedfish:
		return true
	default:
		return false
	}
}

// DefaultPort returns the default port for the protocol.
func (p BMCProtocol) DefaultPort() int {
	defaultPorts := map[BMCProtocol]int{
		BMCProtocolIPMI:    DefaultBMCIPMIPort,
		BMCProtocolRedfish: DefaultBMCRedfishPort,
	}
	if port, ok := defaultPorts[p]; ok {
		return port
	}
	return 0
}

// BMCConfig holds baseboard management controller connection configuration
// for bare metal provisioning via IPMI or Redfish.
type BMCConfig struct {
	// Address is the BMC IP address or hostname.
	Address string `yaml:"address" json:"address"`
	// Port is the BMC port (default 623 for IPMI, 443 for Redfish).
	Port int `yaml:"port" json:"port"`
	// Username is the BMC login username.
	Username string `yaml:"username" json:"username"`
	// Password is the BMC login password (encrypted at rest).
	Password string `yaml:"password" json:"password" secret:"true"`
	// Protocol is the BMC communication protocol ("ipmi" or "redfish").
	Protocol BMCProtocol `yaml:"protocol" json:"protocol"`
}

// ErrBMCAddressRequired indicates the BMC address is missing.
type ErrBMCAddressRequired struct{}

// Error returns the error message.
func (e ErrBMCAddressRequired) Error() string {
	return "bmc: address is required"
}

// ErrBMCInvalidPort indicates the BMC port is out of range.
type ErrBMCInvalidPort struct {
	Port int
}

// Error returns the error message.
func (e ErrBMCInvalidPort) Error() string {
	return fmt.Sprintf("bmc: invalid port %d, must be between 1 and 65535", e.Port)
}

// ErrBMCUnknownProtocol indicates an unsupported BMC protocol.
type ErrBMCUnknownProtocol struct {
	Protocol string
}

// Error returns the error message.
func (e ErrBMCUnknownProtocol) Error() string {
	return fmt.Sprintf("bmc: unknown protocol %q, must be %q or %q", e.Protocol, BMCProtocolIPMI, BMCProtocolRedfish)
}

// ErrBMCUsernameRequired indicates the BMC username is missing.
type ErrBMCUsernameRequired struct{}

// Error returns the error message.
func (e ErrBMCUsernameRequired) Error() string {
	return "bmc: username is required"
}

// ErrBMCPasswordRequired indicates the BMC password is missing.
type ErrBMCPasswordRequired struct{}

// Error returns the error message.
func (e ErrBMCPasswordRequired) Error() string {
	return "bmc: password is required"
}

// Validate checks that the BMC configuration is valid.
func (c *BMCConfig) Validate() error {
	if c.Address == "" {
		return ErrBMCAddressRequired{}
	}
	if !c.Protocol.IsValid() {
		return ErrBMCUnknownProtocol{Protocol: string(c.Protocol)}
	}
	if c.Port != 0 && (c.Port < 1 || c.Port > 65535) {
		return ErrBMCInvalidPort{Port: c.Port}
	}
	if c.Username == "" {
		return ErrBMCUsernameRequired{}
	}
	if c.Password == "" {
		return ErrBMCPasswordRequired{}
	}
	return nil
}

// EffectivePort returns the configured port or the protocol default.
func (c *BMCConfig) EffectivePort() int {
	if c.Port != 0 {
		return c.Port
	}
	return c.Protocol.DefaultPort()
}
