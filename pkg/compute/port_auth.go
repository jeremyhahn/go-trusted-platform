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

package compute

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
)

// PortAuthConfig holds configuration for port authentication
type PortAuthConfig struct {
	// PortID is the network port identifier
	PortID string

	// BridgeName is the OVS bridge name
	BridgeName string

	// MACAddress is the MAC address of the port
	MACAddress string

	// PolicyEngine is the 802.1X policy engine
	PolicyEngine policy.PolicyEngine
}

// SetProvisioningState transitions a port to the provisioning state
// This allows limited network access for device enrollment (DHCP, DNS, ACME)
// but restricts full network access until the device is activated.
func SetProvisioningState(config *PortAuthConfig) error {
	if config == nil {
		return &MessageError{Msg: "port auth config is required"}
	}

	if config.PortID == "" {
		return &MessageError{Msg: "port ID is required"}
	}

	if config.PolicyEngine == nil {
		return &MessageError{Msg: "policy engine is required"}
	}

	// Transition the port to provisioning state
	// This installs limited OpenFlow rules that only allow:
	// - DHCP for IP assignment
	// - DNS for name resolution
	// - HTTPS to ACME server for certificate enrollment
	// - HTTP/HTTPS for package repositories (optional)
	if err := config.PolicyEngine.SetPortState(config.PortID, policy.PortStateProvisioning); err != nil {
		return &WrappedError{Msg: "failed to set port to provisioning state", Err: err}
	}

	return nil
}

// ActivatePort transitions a port from enrolled to authorized state
// This applies the full production policy with tenant-specific VLAN and ACLs
func ActivatePort(config *PortAuthConfig, portPolicy *policy.PortPolicy) error {
	if config == nil {
		return &MessageError{Msg: "port auth config is required"}
	}

	if config.PortID == "" {
		return &MessageError{Msg: "port ID is required"}
	}

	if config.PolicyEngine == nil {
		return &MessageError{Msg: "policy engine is required"}
	}

	if portPolicy == nil {
		return &MessageError{Msg: "port policy is required"}
	}

	// Apply the production policy
	// This transitions the port from PortStateEnrolled to PortStateAuthorized
	// and installs the full set of OpenFlow rules based on the device's
	// certificate and assigned VLAN
	if err := config.PolicyEngine.ApplyPolicy(config.PortID, portPolicy); err != nil {
		return &WrappedError{Msg: "failed to apply production policy", Err: err}
	}

	return nil
}

// GetPortState retrieves the current authentication state of a port
func GetPortState(config *PortAuthConfig) (policy.PortState, error) {
	if config == nil {
		return policy.PortStateUnconnected, &MessageError{Msg: "port auth config is required"}
	}

	if config.PortID == "" {
		return policy.PortStateUnconnected, &MessageError{Msg: "port ID is required"}
	}

	if config.PolicyEngine == nil {
		return policy.PortStateUnconnected, &MessageError{Msg: "policy engine is required"}
	}

	state, err := config.PolicyEngine.GetPortState(config.PortID)
	if err != nil {
		return policy.PortStateUnconnected, &WrappedError{Msg: "failed to get port state", Err: err}
	}

	return state, nil
}

// RemovePortAuth removes port authentication and policy
func RemovePortAuth(config *PortAuthConfig) error {
	if config == nil {
		return &MessageError{Msg: "port auth config is required"}
	}

	if config.PortID == "" {
		return &MessageError{Msg: "port ID is required"}
	}

	if config.PolicyEngine == nil {
		return &MessageError{Msg: "policy engine is required"}
	}

	// Remove the policy and reset port state
	if err := config.PolicyEngine.RemovePolicy(config.PortID); err != nil {
		return &WrappedError{Msg: "failed to remove port policy", Err: err}
	}

	return nil
}
