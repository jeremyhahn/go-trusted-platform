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

package sdn

import "fmt"

// ErrMissingBridgeID is returned when bridge ID is required but not provided
type ErrMissingBridgeID struct{}

func (e ErrMissingBridgeID) Error() string {
	return "bridge ID is required"
}

// ErrMissingBridgeName is returned when bridge name is required but not provided
type ErrMissingBridgeName struct{}

func (e ErrMissingBridgeName) Error() string {
	return "bridge name is required"
}

// ErrMissingPortID is returned when port ID is required but not provided
type ErrMissingPortID struct{}

func (e ErrMissingPortID) Error() string {
	return "port ID is required"
}

// ErrMissingPortName is returned when port name is required but not provided
type ErrMissingPortName struct{}

func (e ErrMissingPortName) Error() string {
	return "port name is required"
}

// ErrMissingFlowID is returned when flow ID is required but not provided
type ErrMissingFlowID struct{}

func (e ErrMissingFlowID) Error() string {
	return "flow ID is required"
}

// ErrMissingPolicyID is returned when policy ID is required but not provided
type ErrMissingPolicyID struct{}

func (e ErrMissingPolicyID) Error() string {
	return "policy ID is required"
}

// ErrMissingVLANID is returned when VLAN ID is required but not provided
type ErrMissingVLANID struct{}

func (e ErrMissingVLANID) Error() string {
	return "VLAN ID is required"
}

// ErrInvalidRequestBody is returned when the request body cannot be parsed
type ErrInvalidRequestBody struct {
	Reason string
}

func (e ErrInvalidRequestBody) Error() string {
	return fmt.Sprintf("invalid request body: %s", e.Reason)
}

// ErrBridgeNotFound is returned when a bridge is not found
type ErrBridgeNotFound struct {
	BridgeID string
}

func (e ErrBridgeNotFound) Error() string {
	return fmt.Sprintf("bridge not found: %s", e.BridgeID)
}

// ErrPortNotFound is returned when a port is not found
type ErrPortNotFound struct {
	BridgeID string
	PortID   string
}

func (e ErrPortNotFound) Error() string {
	return fmt.Sprintf("port not found: bridge=%s, port=%s", e.BridgeID, e.PortID)
}

// ErrFlowNotFound is returned when a flow is not found
type ErrFlowNotFound struct {
	BridgeID string
	FlowID   string
}

func (e ErrFlowNotFound) Error() string {
	return fmt.Sprintf("flow not found: bridge=%s, flow=%s", e.BridgeID, e.FlowID)
}

// ErrPolicyNotFound is returned when a policy is not found
type ErrPolicyNotFound struct {
	PolicyID string
}

func (e ErrPolicyNotFound) Error() string {
	return fmt.Sprintf("policy not found: %s", e.PolicyID)
}

// ErrVLANNotFound is returned when a VLAN is not found
type ErrVLANNotFound struct {
	BridgeID string
	VLANID   uint32
}

func (e ErrVLANNotFound) Error() string {
	return fmt.Sprintf("VLAN not found: bridge=%s, vlan=%d", e.BridgeID, e.VLANID)
}

// ErrInvalidVLANID is returned when VLAN ID is invalid
type ErrInvalidVLANID struct {
	Reason string
}

func (e ErrInvalidVLANID) Error() string {
	return fmt.Sprintf("invalid VLAN ID: %s", e.Reason)
}

// ErrInvalidPortState is returned when port state is invalid
type ErrInvalidPortState struct {
	State string
}

func (e ErrInvalidPortState) Error() string {
	return fmt.Sprintf("invalid port state: %s", e.State)
}
