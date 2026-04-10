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

package bridge

import "fmt"

// ErrBridgeExists is returned when attempting to create a bridge that already exists
type ErrBridgeExists struct {
	Name string
}

func (e ErrBridgeExists) Error() string {
	return fmt.Sprintf("bridge already exists: %s", e.Name)
}

// ErrBridgeNotFound is returned when a bridge does not exist
type ErrBridgeNotFound struct {
	Name string
}

func (e ErrBridgeNotFound) Error() string {
	return fmt.Sprintf("bridge not found: %s", e.Name)
}

// ErrBridgeCreateFailed is returned when bridge creation fails
type ErrBridgeCreateFailed struct {
	Name string
	Err  error
}

func (e ErrBridgeCreateFailed) Error() string {
	return fmt.Sprintf("failed to create bridge %s: %v", e.Name, e.Err)
}

func (e ErrBridgeCreateFailed) Unwrap() error {
	return e.Err
}

// ErrBridgeDeleteFailed is returned when bridge deletion fails
type ErrBridgeDeleteFailed struct {
	Name string
	Err  error
}

func (e ErrBridgeDeleteFailed) Error() string {
	return fmt.Sprintf("failed to delete bridge %s: %v", e.Name, e.Err)
}

func (e ErrBridgeDeleteFailed) Unwrap() error {
	return e.Err
}

// ErrFlowInstallFailed is returned when flow installation fails
type ErrFlowInstallFailed struct {
	Bridge string
	Err    error
}

func (e ErrFlowInstallFailed) Error() string {
	return fmt.Sprintf("failed to install flows on bridge %s: %v", e.Bridge, e.Err)
}

func (e ErrFlowInstallFailed) Unwrap() error {
	return e.Err
}

// ErrOVSConnectionFailed is returned when connection to OVS fails
type ErrOVSConnectionFailed struct {
	Err error
}

func (e ErrOVSConnectionFailed) Error() string {
	return fmt.Sprintf("OVS connection failed: %v", e.Err)
}

func (e ErrOVSConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrInvalidBridgeName is returned when the bridge name is invalid
type ErrInvalidBridgeName struct {
	Name   string
	Reason string
}

func (e ErrInvalidBridgeName) Error() string {
	return fmt.Sprintf("invalid bridge name %q: %s", e.Name, e.Reason)
}

// ErrTenantNotFound is returned when a tenant is not found
type ErrTenantNotFound struct {
	TenantID string
}

func (e ErrTenantNotFound) Error() string {
	return fmt.Sprintf("tenant not found: %s", e.TenantID)
}

// ErrInvalidVLANRange is returned when the VLAN range is invalid
type ErrInvalidVLANRange struct {
	Start  uint16
	End    uint16
	Reason string
}

func (e ErrInvalidVLANRange) Error() string {
	return fmt.Sprintf("invalid VLAN range %d-%d: %s", e.Start, e.End, e.Reason)
}

// ErrFlowDeleteFailed is returned when flow deletion fails
type ErrFlowDeleteFailed struct {
	Bridge string
	Err    error
}

func (e ErrFlowDeleteFailed) Error() string {
	return fmt.Sprintf("failed to delete flows on bridge %s: %v", e.Bridge, e.Err)
}

func (e ErrFlowDeleteFailed) Unwrap() error {
	return e.Err
}

// ErrBridgeStatusError is returned when bridge is in error state
type ErrBridgeStatusError struct {
	Name   string
	Status BridgeStatus
}

func (e ErrBridgeStatusError) Error() string {
	return fmt.Sprintf("bridge %s is in error state: %s", e.Name, e.Status)
}

// ErrOperationInProgress is returned when an operation is already in progress
type ErrOperationInProgress struct {
	TenantID  string
	Operation string
}

func (e ErrOperationInProgress) Error() string {
	return fmt.Sprintf("operation %s already in progress for tenant %s", e.Operation, e.TenantID)
}
