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

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrMissingBridgeID_Error(t *testing.T) {
	err := ErrMissingBridgeID{}
	assert.Equal(t, "bridge ID is required", err.Error())
}

func TestErrMissingBridgeName_Error(t *testing.T) {
	err := ErrMissingBridgeName{}
	assert.Equal(t, "bridge name is required", err.Error())
}

func TestErrMissingPortID_Error(t *testing.T) {
	err := ErrMissingPortID{}
	assert.Equal(t, "port ID is required", err.Error())
}

func TestErrMissingPortName_Error(t *testing.T) {
	err := ErrMissingPortName{}
	assert.Equal(t, "port name is required", err.Error())
}

func TestErrMissingFlowID_Error(t *testing.T) {
	err := ErrMissingFlowID{}
	assert.Equal(t, "flow ID is required", err.Error())
}

func TestErrMissingPolicyID_Error(t *testing.T) {
	err := ErrMissingPolicyID{}
	assert.Equal(t, "policy ID is required", err.Error())
}

func TestErrMissingVLANID_Error(t *testing.T) {
	err := ErrMissingVLANID{}
	assert.Equal(t, "VLAN ID is required", err.Error())
}

func TestErrInvalidRequestBody_Error(t *testing.T) {
	err := ErrInvalidRequestBody{Reason: "invalid json syntax"}
	assert.Equal(t, "invalid request body: invalid json syntax", err.Error())
}

func TestErrBridgeNotFound_Error(t *testing.T) {
	err := ErrBridgeNotFound{BridgeID: "br0"}
	assert.Equal(t, "bridge not found: br0", err.Error())
}

func TestErrPortNotFound_Error(t *testing.T) {
	err := ErrPortNotFound{BridgeID: "br0", PortID: "port0"}
	assert.Equal(t, "port not found: bridge=br0, port=port0", err.Error())
}

func TestErrFlowNotFound_Error(t *testing.T) {
	err := ErrFlowNotFound{BridgeID: "br0", FlowID: "flow-1"}
	assert.Equal(t, "flow not found: bridge=br0, flow=flow-1", err.Error())
}

func TestErrPolicyNotFound_Error(t *testing.T) {
	err := ErrPolicyNotFound{PolicyID: "policy-1"}
	assert.Equal(t, "policy not found: policy-1", err.Error())
}

func TestErrVLANNotFound_Error(t *testing.T) {
	err := ErrVLANNotFound{BridgeID: "br0", VLANID: 100}
	assert.Equal(t, "VLAN not found: bridge=br0, vlan=100", err.Error())
}

func TestErrInvalidVLANID_Error(t *testing.T) {
	err := ErrInvalidVLANID{Reason: "must be between 1 and 4095"}
	assert.Equal(t, "invalid VLAN ID: must be between 1 and 4095", err.Error())
}

func TestErrInvalidPortState_Error(t *testing.T) {
	err := ErrInvalidPortState{State: "invalid"}
	assert.Equal(t, "invalid port state: invalid", err.Error())
}

// Test that all error types implement the error interface
func TestErrorInterfaceImplementation(t *testing.T) {
	var _ error = ErrMissingBridgeID{}
	var _ error = ErrMissingBridgeName{}
	var _ error = ErrMissingPortID{}
	var _ error = ErrMissingPortName{}
	var _ error = ErrMissingFlowID{}
	var _ error = ErrMissingPolicyID{}
	var _ error = ErrMissingVLANID{}
	var _ error = ErrInvalidRequestBody{}
	var _ error = ErrBridgeNotFound{}
	var _ error = ErrPortNotFound{}
	var _ error = ErrFlowNotFound{}
	var _ error = ErrPolicyNotFound{}
	var _ error = ErrVLANNotFound{}
	var _ error = ErrInvalidVLANID{}
	var _ error = ErrInvalidPortState{}
}
