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

// Bridge Errors

type ErrCreateBridgeFailed struct {
	Cause error
}

func (e *ErrCreateBridgeFailed) Error() string {
	return fmt.Sprintf("failed to create bridge: %v", e.Cause)
}

func (e *ErrCreateBridgeFailed) Unwrap() error { return e.Cause }

type ErrDeleteBridgeFailed struct {
	ID    string
	Cause error
}

func (e *ErrDeleteBridgeFailed) Error() string {
	return fmt.Sprintf("failed to delete bridge %s: %v", e.ID, e.Cause)
}

func (e *ErrDeleteBridgeFailed) Unwrap() error { return e.Cause }

type ErrGetBridgeFailed struct {
	ID    string
	Cause error
}

func (e *ErrGetBridgeFailed) Error() string {
	return fmt.Sprintf("failed to get bridge %s: %v", e.ID, e.Cause)
}

func (e *ErrGetBridgeFailed) Unwrap() error { return e.Cause }

type ErrListBridgesFailed struct {
	Cause error
}

func (e *ErrListBridgesFailed) Error() string {
	return fmt.Sprintf("failed to list bridges: %v", e.Cause)
}

func (e *ErrListBridgesFailed) Unwrap() error { return e.Cause }

// Port Errors

type ErrAddPortFailed struct {
	BridgeID string
	Cause    error
}

func (e *ErrAddPortFailed) Error() string {
	return fmt.Sprintf("failed to add port to bridge %s: %v", e.BridgeID, e.Cause)
}

func (e *ErrAddPortFailed) Unwrap() error { return e.Cause }

type ErrDeletePortFailed struct {
	BridgeID string
	PortID   string
	Cause    error
}

func (e *ErrDeletePortFailed) Error() string {
	return fmt.Sprintf("failed to delete port %s from bridge %s: %v", e.PortID, e.BridgeID, e.Cause)
}

func (e *ErrDeletePortFailed) Unwrap() error { return e.Cause }

type ErrGetPortFailed struct {
	BridgeID string
	PortID   string
	Cause    error
}

func (e *ErrGetPortFailed) Error() string {
	return fmt.Sprintf("failed to get port %s from bridge %s: %v", e.PortID, e.BridgeID, e.Cause)
}

func (e *ErrGetPortFailed) Unwrap() error { return e.Cause }

type ErrListPortsFailed struct {
	BridgeID string
	Cause    error
}

func (e *ErrListPortsFailed) Error() string {
	return fmt.Sprintf("failed to list ports on bridge %s: %v", e.BridgeID, e.Cause)
}

func (e *ErrListPortsFailed) Unwrap() error { return e.Cause }

// Flow Errors

type ErrAddFlowFailed struct {
	Cause error
}

func (e *ErrAddFlowFailed) Error() string {
	return fmt.Sprintf("failed to add flow: %v", e.Cause)
}

func (e *ErrAddFlowFailed) Unwrap() error { return e.Cause }

type ErrDeleteFlowFailed struct {
	BridgeID string
	FlowID   string
	Cause    error
}

func (e *ErrDeleteFlowFailed) Error() string {
	return fmt.Sprintf("failed to delete flow %s from bridge %s: %v", e.FlowID, e.BridgeID, e.Cause)
}

func (e *ErrDeleteFlowFailed) Unwrap() error { return e.Cause }

type ErrListFlowsFailed struct {
	BridgeID string
	Cause    error
}

func (e *ErrListFlowsFailed) Error() string {
	return fmt.Sprintf("failed to list flows on bridge %s: %v", e.BridgeID, e.Cause)
}

func (e *ErrListFlowsFailed) Unwrap() error { return e.Cause }

type ErrFlushFlowsFailed struct {
	BridgeID string
	Cause    error
}

func (e *ErrFlushFlowsFailed) Error() string {
	return fmt.Sprintf("failed to flush flows on bridge %s: %v", e.BridgeID, e.Cause)
}

func (e *ErrFlushFlowsFailed) Unwrap() error { return e.Cause }

// VLAN Errors

type ErrCreateVLANFailed struct {
	Cause error
}

func (e *ErrCreateVLANFailed) Error() string {
	return fmt.Sprintf("failed to create VLAN: %v", e.Cause)
}

func (e *ErrCreateVLANFailed) Unwrap() error { return e.Cause }

type ErrDeleteVLANFailed struct {
	BridgeID string
	VlanID   uint32
	Cause    error
}

func (e *ErrDeleteVLANFailed) Error() string {
	return fmt.Sprintf("failed to delete VLAN %d from bridge %s: %v", e.VlanID, e.BridgeID, e.Cause)
}

func (e *ErrDeleteVLANFailed) Unwrap() error { return e.Cause }

type ErrListVLANsFailed struct {
	BridgeID string
	Cause    error
}

func (e *ErrListVLANsFailed) Error() string {
	return fmt.Sprintf("failed to list VLANs on bridge %s: %v", e.BridgeID, e.Cause)
}

func (e *ErrListVLANsFailed) Unwrap() error { return e.Cause }

// Auth Errors

type ErrAuthenticatePortFailed struct {
	BridgeID string
	PortID   string
	Cause    error
}

func (e *ErrAuthenticatePortFailed) Error() string {
	return fmt.Sprintf("failed to authenticate port %s on bridge %s: %v", e.PortID, e.BridgeID, e.Cause)
}

func (e *ErrAuthenticatePortFailed) Unwrap() error { return e.Cause }

type ErrRevokePortAuthFailed struct {
	BridgeID string
	PortID   string
	Cause    error
}

func (e *ErrRevokePortAuthFailed) Error() string {
	return fmt.Sprintf("failed to revoke auth for port %s on bridge %s: %v", e.PortID, e.BridgeID, e.Cause)
}

func (e *ErrRevokePortAuthFailed) Unwrap() error { return e.Cause }

// Stats Errors

type ErrGetPortStatsFailed struct {
	BridgeID string
	PortID   string
	Cause    error
}

func (e *ErrGetPortStatsFailed) Error() string {
	return fmt.Sprintf("failed to get stats for port %s on bridge %s: %v", e.PortID, e.BridgeID, e.Cause)
}

func (e *ErrGetPortStatsFailed) Unwrap() error { return e.Cause }

type ErrGetFlowStatsFailed struct {
	BridgeID string
	FlowID   string
	Cause    error
}

func (e *ErrGetFlowStatsFailed) Error() string {
	return fmt.Sprintf("failed to get stats for flow %s on bridge %s: %v", e.FlowID, e.BridgeID, e.Cause)
}

func (e *ErrGetFlowStatsFailed) Unwrap() error { return e.Cause }

// Policy Errors

// ErrApplyPolicyFailed indicates a failure to apply a policy.
type ErrApplyPolicyFailed struct {
	PolicyID string
	Cause    error
}

func (e *ErrApplyPolicyFailed) Error() string {
	return fmt.Sprintf("failed to apply policy %s: %v", e.PolicyID, e.Cause)
}

func (e *ErrApplyPolicyFailed) Unwrap() error { return e.Cause }

// ErrGetPolicyFailed indicates a failure to retrieve a policy.
type ErrGetPolicyFailed struct {
	PolicyID string
	Cause    error
}

func (e *ErrGetPolicyFailed) Error() string {
	return fmt.Sprintf("failed to get policy %s: %v", e.PolicyID, e.Cause)
}

func (e *ErrGetPolicyFailed) Unwrap() error { return e.Cause }

// ErrListPoliciesFailed indicates a failure to list policies.
type ErrListPoliciesFailed struct {
	Cause error
}

func (e *ErrListPoliciesFailed) Error() string {
	return fmt.Sprintf("failed to list policies: %v", e.Cause)
}

func (e *ErrListPoliciesFailed) Unwrap() error { return e.Cause }

// Network Zone Errors

// ErrCreateNetworkZoneFailed indicates failure to create a network zone.
type ErrCreateNetworkZoneFailed struct {
	Cause error
}

func (e *ErrCreateNetworkZoneFailed) Error() string {
	return fmt.Sprintf("failed to create network zone: %v", e.Cause)
}

func (e *ErrCreateNetworkZoneFailed) Unwrap() error { return e.Cause }

// ErrUpdateNetworkZoneFailed indicates failure to update a network zone.
type ErrUpdateNetworkZoneFailed struct {
	Name  string
	Cause error
}

func (e *ErrUpdateNetworkZoneFailed) Error() string {
	return fmt.Sprintf("failed to update network zone %s: %v", e.Name, e.Cause)
}

func (e *ErrUpdateNetworkZoneFailed) Unwrap() error { return e.Cause }

// ErrDeleteNetworkZoneFailed indicates failure to delete a network zone.
type ErrDeleteNetworkZoneFailed struct {
	Name  string
	Cause error
}

func (e *ErrDeleteNetworkZoneFailed) Error() string {
	return fmt.Sprintf("failed to delete network zone %s: %v", e.Name, e.Cause)
}

func (e *ErrDeleteNetworkZoneFailed) Unwrap() error { return e.Cause }

// ErrListNetworkZonesFailed indicates failure to list network zones.
type ErrListNetworkZonesFailed struct {
	Cause error
}

func (e *ErrListNetworkZonesFailed) Error() string {
	return fmt.Sprintf("failed to list network zones: %v", e.Cause)
}

func (e *ErrListNetworkZonesFailed) Unwrap() error { return e.Cause }
