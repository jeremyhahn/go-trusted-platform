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

package cluster

import (
	"errors"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestErrBridgeNotFound_Error(t *testing.T) {
	err := ErrBridgeNotFound{BridgeID: "br-123"}
	assert.Equal(t, "bridge not found: br-123", err.Error())
}

func TestErrBridgeAlreadyExists_Error(t *testing.T) {
	err := ErrBridgeAlreadyExists{BridgeID: "br-123"}
	assert.Equal(t, "bridge already exists: br-123", err.Error())
}

func TestErrPortNotFound_Error(t *testing.T) {
	err := ErrPortNotFound{PortID: "port-123"}
	assert.Equal(t, "port not found: port-123", err.Error())
}

func TestErrPortAlreadyExists_Error(t *testing.T) {
	err := ErrPortAlreadyExists{PortID: "port-123"}
	assert.Equal(t, "port already exists: port-123", err.Error())
}

func TestErrFlowNotFound_Error(t *testing.T) {
	err := ErrFlowNotFound{BridgeID: "br-123", FlowID: "flow-456"}
	assert.Equal(t, "flow not found: bridge=br-123, flow=flow-456", err.Error())
}

func TestErrFlowAlreadyExists_Error(t *testing.T) {
	err := ErrFlowAlreadyExists{BridgeID: "br-123", FlowID: "flow-456"}
	assert.Equal(t, "flow already exists: bridge=br-123, flow=flow-456", err.Error())
}

func TestErrVLANNotFound_Error(t *testing.T) {
	err := ErrVLANNotFound{VLANID: 100}
	assert.Equal(t, "VLAN not found: 100", err.Error())
}

func TestErrVLANAlreadyExists_Error(t *testing.T) {
	err := ErrVLANAlreadyExists{VLANID: 100}
	assert.Equal(t, "VLAN already exists: 100", err.Error())
}

func TestErrInvalidBridgeID_Error(t *testing.T) {
	err := ErrInvalidBridgeID{BridgeID: "br-bad", Reason: "contains invalid characters"}
	assert.Equal(t, "invalid bridge ID br-bad: contains invalid characters", err.Error())
}

func TestErrInvalidPortID_Error(t *testing.T) {
	err := ErrInvalidPortID{PortID: "port-bad", Reason: "empty string"}
	assert.Equal(t, "invalid port ID port-bad: empty string", err.Error())
}

func TestErrInvalidFlowID_Error(t *testing.T) {
	err := ErrInvalidFlowID{FlowID: "flow-bad", Reason: "missing required fields"}
	assert.Equal(t, "invalid flow ID flow-bad: missing required fields", err.Error())
}

func TestErrInvalidVLANID_Error(t *testing.T) {
	err := ErrInvalidVLANID{VLANID: 4095, Reason: "VLAN ID must be 1-4094"}
	assert.Equal(t, "invalid VLAN ID 4095: VLAN ID must be 1-4094", err.Error())
}

func TestErrInvalidConfig_Error(t *testing.T) {
	err := ErrInvalidConfig{Field: "timeout", Reason: "must be positive"}
	assert.Equal(t, "invalid configuration: timeout: must be positive", err.Error())
}

func TestErrClusterNotReady_Error(t *testing.T) {
	err := ErrClusterNotReady{Reason: "no leader elected"}
	assert.Equal(t, "cluster not ready: no leader elected", err.Error())
}

func TestErrReplicationFailed_Error(t *testing.T) {
	cause := errors.New("network error")
	err := ErrReplicationFailed{Operation: "create_bridge", Cause: cause}
	assert.Equal(t, "replication failed: create_bridge: network error", err.Error())
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrConsensusTimeout_Error(t *testing.T) {
	err := ErrConsensusTimeout{Operation: "propose_update"}
	assert.Equal(t, "consensus timeout: propose_update", err.Error())
}

func TestErrInvalidOperation_Error(t *testing.T) {
	err := ErrInvalidOperation{Operation: "delete", Reason: "bridge has active ports"}
	assert.Equal(t, "invalid operation delete: bridge has active ports", err.Error())
}

func TestErrConflict_Error(t *testing.T) {
	err := ErrConflict{EntityType: "Bridge", EntityID: "br-123", Reason: "concurrent modification"}
	assert.Equal(t, "state conflict: Bridge/br-123: concurrent modification", err.Error())
}

func TestErrSerializationFailed_Error(t *testing.T) {
	cause := errors.New("json: unsupported type")
	err := ErrSerializationFailed{EntityType: "BridgeState", Cause: cause}
	assert.Equal(t, "serialization failed for BridgeState: json: unsupported type", err.Error())
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrDeserializationFailed_Error(t *testing.T) {
	cause := errors.New("json: cannot unmarshal")
	err := ErrDeserializationFailed{EntityType: "FlowState", Cause: cause}
	assert.Equal(t, "deserialization failed for FlowState: json: cannot unmarshal", err.Error())
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrVersionConflict_Error(t *testing.T) {
	err := ErrVersionConflict{
		EntityType:      "Bridge",
		EntityID:        "br-123",
		ExpectedVersion: 5,
		ActualVersion:   3,
	}
	assert.Equal(t, "version conflict: type=Bridge id=br-123 expected=5 actual=3", err.Error())
}

func TestErrStorageUnavailable_Error(t *testing.T) {
	cause := errors.New("connection refused")
	err := ErrStorageUnavailable{Cause: cause}
	assert.Equal(t, "storage unavailable: connection refused", err.Error())
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrStorageUnavailable_Error_NilCause(t *testing.T) {
	err := ErrStorageUnavailable{}
	assert.Equal(t, "storage unavailable", err.Error())
	assert.Nil(t, err.Unwrap())
}

func TestErrOperationFailed_Error(t *testing.T) {
	cause := errors.New("timeout")
	err := ErrOperationFailed{Operation: "get_bridge", Cause: cause}
	assert.Equal(t, "operation failed: get_bridge: timeout", err.Error())
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrOperationFailed_Error_NilCause(t *testing.T) {
	err := ErrOperationFailed{Operation: "unknown"}
	assert.Equal(t, "operation failed: unknown", err.Error())
	assert.Nil(t, err.Unwrap())
}

func TestErrNilEntity_Error(t *testing.T) {
	err := ErrNilEntity{EntityType: "BridgeState"}
	assert.Equal(t, "nil entity provided: BridgeState", err.Error())
}

// Test error type assertions
func TestErrorTypeAssertions(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"BridgeNotFound", ErrBridgeNotFound{BridgeID: "br-1"}},
		{"BridgeAlreadyExists", ErrBridgeAlreadyExists{BridgeID: "br-1"}},
		{"PortNotFound", ErrPortNotFound{PortID: "port-1"}},
		{"PortAlreadyExists", ErrPortAlreadyExists{PortID: "port-1"}},
		{"FlowNotFound", ErrFlowNotFound{BridgeID: "br-1", FlowID: "flow-1"}},
		{"FlowAlreadyExists", ErrFlowAlreadyExists{BridgeID: "br-1", FlowID: "flow-1"}},
		{"VLANNotFound", ErrVLANNotFound{VLANID: 100}},
		{"VLANAlreadyExists", ErrVLANAlreadyExists{VLANID: 100}},
		{"InvalidBridgeID", ErrInvalidBridgeID{BridgeID: "bad", Reason: "test"}},
		{"InvalidPortID", ErrInvalidPortID{PortID: "bad", Reason: "test"}},
		{"InvalidFlowID", ErrInvalidFlowID{FlowID: "bad", Reason: "test"}},
		{"InvalidVLANID", ErrInvalidVLANID{VLANID: 0, Reason: "test"}},
		{"InvalidConfig", ErrInvalidConfig{Field: "f", Reason: "r"}},
		{"ClusterNotReady", ErrClusterNotReady{Reason: "test"}},
		{"ReplicationFailed", ErrReplicationFailed{Operation: "op"}},
		{"ConsensusTimeout", ErrConsensusTimeout{Operation: "op"}},
		{"InvalidOperation", ErrInvalidOperation{Operation: "op", Reason: "r"}},
		{"Conflict", ErrConflict{EntityType: "t", EntityID: "id", Reason: "r"}},
		{"SerializationFailed", ErrSerializationFailed{EntityType: "t"}},
		{"DeserializationFailed", ErrDeserializationFailed{EntityType: "t"}},
		{"VersionConflict", ErrVersionConflict{EntityType: "t", EntityID: "id"}},
		{"StorageUnavailable", ErrStorageUnavailable{}},
		{"OperationFailed", ErrOperationFailed{Operation: "op"}},
		{"NilEntity", ErrNilEntity{EntityType: "t"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// All errors should implement the error interface
			assert.NotEmpty(t, tt.err.Error())
		})
	}
}

// Additional error tests for coverage

func TestErrSyncAlreadyRunning_Error(t *testing.T) {
	err := ErrSyncAlreadyRunning{}
	assert.Equal(t, "synchronizer is already running", err.Error())
}

func TestErrSyncNotRunning_Error(t *testing.T) {
	err := ErrSyncNotRunning{}
	assert.Equal(t, "synchronizer is not running", err.Error())
}

func TestErrSyncStopped_Error(t *testing.T) {
	err := ErrSyncStopped{}
	assert.Equal(t, "synchronizer was stopped", err.Error())
}

func TestErrSyncFailed_Error(t *testing.T) {
	cause := errors.New("network error")
	err := ErrSyncFailed{Entity: "bridge", Operation: "create", Cause: cause}
	assert.Equal(t, "sync failed: create bridge: network error", err.Error())
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrSyncFailed_Error_NilCause(t *testing.T) {
	err := ErrSyncFailed{Entity: "bridge", Operation: "create"}
	assert.Equal(t, "sync failed: create bridge", err.Error())
	assert.Nil(t, err.Unwrap())
}

func TestErrMaxRetriesExceeded_Error(t *testing.T) {
	cause := errors.New("timeout")
	err := ErrMaxRetriesExceeded{Operation: "sync_bridge", LastError: cause}
	assert.Equal(t, "max retries exceeded for sync_bridge: timeout", err.Error())
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrMaxRetriesExceeded_Error_NilLastError(t *testing.T) {
	err := ErrMaxRetriesExceeded{Operation: "sync_bridge"}
	assert.Equal(t, "max retries exceeded for sync_bridge", err.Error())
	assert.Nil(t, err.Unwrap())
}

func TestErrOVSConnectionFailed_Error(t *testing.T) {
	cause := errors.New("connection refused")
	err := ErrOVSConnectionFailed{Cause: cause}
	assert.Equal(t, "OVS connection failed: connection refused", err.Error())
	assert.Equal(t, cause, err.Unwrap())
}

func TestErrOVSConnectionFailed_Error_NilCause(t *testing.T) {
	err := ErrOVSConnectionFailed{}
	assert.Equal(t, "OVS connection failed", err.Error())
	assert.Nil(t, err.Unwrap())
}

// VXLAN-specific error tests

func TestErrVTEPNotFound_Error(t *testing.T) {
	err := ErrVTEPNotFound{VTEPID: "vtep-123"}
	assert.Equal(t, "VTEP not found: vtep-123", err.Error())
}

func TestErrVTEPAlreadyExists_Error(t *testing.T) {
	ip := netip.MustParseAddr("10.0.0.1")
	err := ErrVTEPAlreadyExists{IP: ip}
	assert.Equal(t, "VTEP already exists with IP: 10.0.0.1", err.Error())
}

func TestErrInvalidVTEPID_Error(t *testing.T) {
	t.Run("with_vtep_id", func(t *testing.T) {
		err := ErrInvalidVTEPID{VTEPID: "vtep-bad", Reason: "invalid format"}
		assert.Equal(t, "invalid VTEP ID vtep-bad: invalid format", err.Error())
	})

	t.Run("without_vtep_id", func(t *testing.T) {
		err := ErrInvalidVTEPID{VTEPID: "", Reason: "cannot be empty"}
		assert.Equal(t, "invalid VTEP ID: cannot be empty", err.Error())
	})
}

func TestErrTunnelNotFound_Error(t *testing.T) {
	t.Run("with_tunnel_id", func(t *testing.T) {
		err := ErrTunnelNotFound{TunnelID: "tunnel-123"}
		assert.Equal(t, "tunnel not found: tunnel-123", err.Error())
	})

	t.Run("without_tunnel_id", func(t *testing.T) {
		err := ErrTunnelNotFound{TunnelID: ""}
		assert.Equal(t, "tunnel not found", err.Error())
	})
}

func TestErrTunnelAlreadyExists_Error(t *testing.T) {
	err := ErrTunnelAlreadyExists{TunnelID: "tunnel-123"}
	assert.Equal(t, "tunnel already exists: tunnel-123", err.Error())
}

func TestErrInvalidTunnelID_Error(t *testing.T) {
	t.Run("with_tunnel_id", func(t *testing.T) {
		err := ErrInvalidTunnelID{TunnelID: "tunnel-bad", Reason: "invalid format"}
		assert.Equal(t, "invalid tunnel ID tunnel-bad: invalid format", err.Error())
	})

	t.Run("without_tunnel_id", func(t *testing.T) {
		err := ErrInvalidTunnelID{TunnelID: "", Reason: "cannot be empty"}
		assert.Equal(t, "invalid tunnel ID: cannot be empty", err.Error())
	})
}

func TestErrVNIMappingNotFound_Error(t *testing.T) {
	t.Run("with_vni", func(t *testing.T) {
		err := ErrVNIMappingNotFound{VNI: 100}
		assert.Equal(t, "VNI mapping not found: 100", err.Error())
	})

	t.Run("without_vni", func(t *testing.T) {
		err := ErrVNIMappingNotFound{VNI: 0}
		assert.Equal(t, "VNI mapping not found", err.Error())
	})
}

func TestErrVNIAlreadyMapped_Error(t *testing.T) {
	err := ErrVNIAlreadyMapped{VNI: 100, VLAN: 10}
	assert.Equal(t, "VNI 100 already mapped to VLAN 10", err.Error())
}

func TestErrInvalidVNI_Error(t *testing.T) {
	err := ErrInvalidVNI{VNI: 16777216, Reason: "VNI must be less than 16777215"}
	assert.Equal(t, "invalid VNI 16777216: VNI must be less than 16777215", err.Error())
}

func TestErrRemoteMACNotFound_Error(t *testing.T) {
	t.Run("with_mac", func(t *testing.T) {
		err := ErrRemoteMACNotFound{MAC: "00:11:22:33:44:55", VNI: 100}
		assert.Equal(t, "remote MAC not found: mac=00:11:22:33:44:55, vni=100", err.Error())
	})

	t.Run("without_mac", func(t *testing.T) {
		err := ErrRemoteMACNotFound{MAC: "", VNI: 0}
		assert.Equal(t, "remote MAC not found", err.Error())
	})
}

func TestErrRemoteMACAlreadyExists_Error(t *testing.T) {
	err := ErrRemoteMACAlreadyExists{MAC: "00:11:22:33:44:55", VNI: 100}
	assert.Equal(t, "remote MAC already exists: mac=00:11:22:33:44:55, vni=100", err.Error())
}

func TestErrInvalidRemoteMACID_Error(t *testing.T) {
	t.Run("with_remote_mac_id", func(t *testing.T) {
		err := ErrInvalidRemoteMACID{RemoteMACID: "mac-bad", Reason: "invalid format"}
		assert.Equal(t, "invalid remote MAC ID mac-bad: invalid format", err.Error())
	})

	t.Run("without_remote_mac_id", func(t *testing.T) {
		err := ErrInvalidRemoteMACID{RemoteMACID: "", Reason: "cannot be empty"}
		assert.Equal(t, "invalid remote MAC ID: cannot be empty", err.Error())
	})
}

// Test VXLAN error type assertions
func TestVXLANErrorTypeAssertions(t *testing.T) {
	tests := []struct {
		name string
		err  error
	}{
		{"VTEPNotFound", ErrVTEPNotFound{VTEPID: "vtep-1"}},
		{"VTEPAlreadyExists", ErrVTEPAlreadyExists{IP: netip.MustParseAddr("10.0.0.1")}},
		{"InvalidVTEPID", ErrInvalidVTEPID{VTEPID: "bad", Reason: "test"}},
		{"TunnelNotFound", ErrTunnelNotFound{TunnelID: "tunnel-1"}},
		{"TunnelAlreadyExists", ErrTunnelAlreadyExists{TunnelID: "tunnel-1"}},
		{"InvalidTunnelID", ErrInvalidTunnelID{TunnelID: "bad", Reason: "test"}},
		{"VNIMappingNotFound", ErrVNIMappingNotFound{VNI: 100}},
		{"VNIAlreadyMapped", ErrVNIAlreadyMapped{VNI: 100, VLAN: 10}},
		{"InvalidVNI", ErrInvalidVNI{VNI: 0, Reason: "test"}},
		{"RemoteMACNotFound", ErrRemoteMACNotFound{MAC: "00:11:22:33:44:55", VNI: 100}},
		{"RemoteMACAlreadyExists", ErrRemoteMACAlreadyExists{MAC: "00:11:22:33:44:55", VNI: 100}},
		{"InvalidRemoteMACID", ErrInvalidRemoteMACID{RemoteMACID: "bad", Reason: "test"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// All errors should implement the error interface
			assert.NotEmpty(t, tt.err.Error())
		})
	}
}
