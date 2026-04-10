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
	"fmt"
	"net/netip"
)

// ErrBridgeNotFound is returned when a bridge is not found in the cluster state.
type ErrBridgeNotFound struct {
	BridgeID string
}

func (e ErrBridgeNotFound) Error() string {
	return fmt.Sprintf("bridge not found: %s", e.BridgeID)
}

// ErrBridgeAlreadyExists is returned when attempting to create a bridge that already exists.
type ErrBridgeAlreadyExists struct {
	BridgeID string
}

func (e ErrBridgeAlreadyExists) Error() string {
	return fmt.Sprintf("bridge already exists: %s", e.BridgeID)
}

// ErrPortNotFound is returned when a port is not found in the cluster state.
type ErrPortNotFound struct {
	PortID string
}

func (e ErrPortNotFound) Error() string {
	return fmt.Sprintf("port not found: %s", e.PortID)
}

// ErrPortAlreadyExists is returned when attempting to create a port that already exists.
type ErrPortAlreadyExists struct {
	PortID string
}

func (e ErrPortAlreadyExists) Error() string {
	return fmt.Sprintf("port already exists: %s", e.PortID)
}

// ErrFlowNotFound is returned when a flow is not found in the cluster state.
type ErrFlowNotFound struct {
	BridgeID string
	FlowID   string
}

func (e ErrFlowNotFound) Error() string {
	return fmt.Sprintf("flow not found: bridge=%s, flow=%s", e.BridgeID, e.FlowID)
}

// ErrFlowAlreadyExists is returned when attempting to create a flow that already exists.
type ErrFlowAlreadyExists struct {
	BridgeID string
	FlowID   string
}

func (e ErrFlowAlreadyExists) Error() string {
	return fmt.Sprintf("flow already exists: bridge=%s, flow=%s", e.BridgeID, e.FlowID)
}

// ErrVLANNotFound is returned when a VLAN is not found in the cluster state.
type ErrVLANNotFound struct {
	VLANID uint16
}

func (e ErrVLANNotFound) Error() string {
	return fmt.Sprintf("VLAN not found: %d", e.VLANID)
}

// ErrVLANAlreadyExists is returned when attempting to create a VLAN that already exists.
type ErrVLANAlreadyExists struct {
	VLANID uint16
}

func (e ErrVLANAlreadyExists) Error() string {
	return fmt.Sprintf("VLAN already exists: %d", e.VLANID)
}

// ErrInvalidBridgeID is returned when a bridge ID is invalid.
type ErrInvalidBridgeID struct {
	BridgeID string
	Reason   string
}

func (e ErrInvalidBridgeID) Error() string {
	return fmt.Sprintf("invalid bridge ID %s: %s", e.BridgeID, e.Reason)
}

// ErrInvalidPortID is returned when a port ID is invalid.
type ErrInvalidPortID struct {
	PortID string
	Reason string
}

func (e ErrInvalidPortID) Error() string {
	return fmt.Sprintf("invalid port ID %s: %s", e.PortID, e.Reason)
}

// ErrInvalidFlowID is returned when a flow ID is invalid.
type ErrInvalidFlowID struct {
	FlowID string
	Reason string
}

func (e ErrInvalidFlowID) Error() string {
	return fmt.Sprintf("invalid flow ID %s: %s", e.FlowID, e.Reason)
}

// ErrInvalidVLANID is returned when a VLAN ID is invalid.
type ErrInvalidVLANID struct {
	VLANID uint16
	Reason string
}

func (e ErrInvalidVLANID) Error() string {
	return fmt.Sprintf("invalid VLAN ID %d: %s", e.VLANID, e.Reason)
}

// ErrInvalidConfig is returned when cluster configuration is invalid.
type ErrInvalidConfig struct {
	Field  string
	Reason string
}

func (e ErrInvalidConfig) Error() string {
	return fmt.Sprintf("invalid configuration: %s: %s", e.Field, e.Reason)
}

// ErrClusterNotReady is returned when cluster is not ready for operations.
type ErrClusterNotReady struct {
	Reason string
}

func (e ErrClusterNotReady) Error() string {
	return fmt.Sprintf("cluster not ready: %s", e.Reason)
}

// ErrReplicationFailed is returned when state replication fails.
type ErrReplicationFailed struct {
	Operation string
	Cause     error
}

func (e ErrReplicationFailed) Error() string {
	return fmt.Sprintf("replication failed: %s: %v", e.Operation, e.Cause)
}

func (e ErrReplicationFailed) Unwrap() error {
	return e.Cause
}

// ErrConsensusTimeout is returned when consensus operation times out.
type ErrConsensusTimeout struct {
	Operation string
}

func (e ErrConsensusTimeout) Error() string {
	return fmt.Sprintf("consensus timeout: %s", e.Operation)
}

// ErrInvalidOperation is returned when an operation is invalid.
type ErrInvalidOperation struct {
	Operation string
	Reason    string
}

func (e ErrInvalidOperation) Error() string {
	return fmt.Sprintf("invalid operation %s: %s", e.Operation, e.Reason)
}

// ErrConflict is returned when a state conflict is detected.
type ErrConflict struct {
	EntityType string
	EntityID   string
	Reason     string
}

func (e ErrConflict) Error() string {
	return fmt.Sprintf("state conflict: %s/%s: %s", e.EntityType, e.EntityID, e.Reason)
}

// ErrSerializationFailed is returned when entity serialization fails.
type ErrSerializationFailed struct {
	EntityType string
	Cause      error
}

func (e ErrSerializationFailed) Error() string {
	return fmt.Sprintf("serialization failed for %s: %v", e.EntityType, e.Cause)
}

func (e ErrSerializationFailed) Unwrap() error {
	return e.Cause
}

// ErrDeserializationFailed is returned when entity deserialization fails.
type ErrDeserializationFailed struct {
	EntityType string
	Cause      error
}

func (e ErrDeserializationFailed) Error() string {
	return fmt.Sprintf("deserialization failed for %s: %v", e.EntityType, e.Cause)
}

func (e ErrDeserializationFailed) Unwrap() error {
	return e.Cause
}

// ErrVersionConflict is returned when an optimistic locking version conflict occurs.
type ErrVersionConflict struct {
	EntityType      string
	EntityID        string
	ExpectedVersion uint64
	ActualVersion   uint64
}

func (e ErrVersionConflict) Error() string {
	return fmt.Sprintf("version conflict: type=%s id=%s expected=%d actual=%d",
		e.EntityType, e.EntityID, e.ExpectedVersion, e.ActualVersion)
}

// ErrStorageUnavailable is returned when the storage backend is unavailable.
type ErrStorageUnavailable struct {
	Cause error
}

func (e ErrStorageUnavailable) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("storage unavailable: %v", e.Cause)
	}
	return "storage unavailable"
}

func (e ErrStorageUnavailable) Unwrap() error {
	return e.Cause
}

// ErrOperationFailed is returned when a storage operation fails.
type ErrOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrOperationFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("operation failed: %s: %v", e.Operation, e.Cause)
	}
	return fmt.Sprintf("operation failed: %s", e.Operation)
}

func (e ErrOperationFailed) Unwrap() error {
	return e.Cause
}

// ErrNilEntity is returned when a nil entity is provided to an operation.
type ErrNilEntity struct {
	EntityType string
}

func (e ErrNilEntity) Error() string {
	return fmt.Sprintf("nil entity provided: %s", e.EntityType)
}

// ErrSyncAlreadyRunning is returned when attempting to start a synchronizer that is already running.
type ErrSyncAlreadyRunning struct{}

func (e ErrSyncAlreadyRunning) Error() string {
	return "synchronizer is already running"
}

// ErrSyncNotRunning is returned when attempting to stop a synchronizer that is not running.
type ErrSyncNotRunning struct{}

func (e ErrSyncNotRunning) Error() string {
	return "synchronizer is not running"
}

// ErrSyncStopped is returned when a sync operation is interrupted by shutdown.
type ErrSyncStopped struct{}

func (e ErrSyncStopped) Error() string {
	return "synchronizer was stopped"
}

// ErrSyncFailed is returned when a sync operation fails.
type ErrSyncFailed struct {
	Entity    string
	Operation string
	Cause     error
}

func (e ErrSyncFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("sync failed: %s %s: %v", e.Operation, e.Entity, e.Cause)
	}
	return fmt.Sprintf("sync failed: %s %s", e.Operation, e.Entity)
}

func (e ErrSyncFailed) Unwrap() error {
	return e.Cause
}

// ErrMaxRetriesExceeded is returned when an operation exceeds its maximum retry attempts.
type ErrMaxRetriesExceeded struct {
	Operation string
	LastError error
}

func (e ErrMaxRetriesExceeded) Error() string {
	if e.LastError != nil {
		return fmt.Sprintf("max retries exceeded for %s: %v", e.Operation, e.LastError)
	}
	return fmt.Sprintf("max retries exceeded for %s", e.Operation)
}

func (e ErrMaxRetriesExceeded) Unwrap() error {
	return e.LastError
}

// ErrOVSConnectionFailed is returned when OVS connection fails.
type ErrOVSConnectionFailed struct {
	Cause error
}

func (e ErrOVSConnectionFailed) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("OVS connection failed: %v", e.Cause)
	}
	return "OVS connection failed"
}

func (e ErrOVSConnectionFailed) Unwrap() error {
	return e.Cause
}

// VXLAN-specific errors

// ErrVTEPNotFound is returned when a VTEP is not found in the cluster state.
type ErrVTEPNotFound struct {
	VTEPID string
}

func (e ErrVTEPNotFound) Error() string {
	return fmt.Sprintf("VTEP not found: %s", e.VTEPID)
}

// ErrVTEPAlreadyExists is returned when attempting to create a VTEP that already exists.
type ErrVTEPAlreadyExists struct {
	IP netip.Addr
}

func (e ErrVTEPAlreadyExists) Error() string {
	return fmt.Sprintf("VTEP already exists with IP: %s", e.IP.String())
}

// ErrInvalidVTEPID is returned when a VTEP ID is invalid.
type ErrInvalidVTEPID struct {
	VTEPID string
	Reason string
}

func (e ErrInvalidVTEPID) Error() string {
	if e.VTEPID == "" {
		return fmt.Sprintf("invalid VTEP ID: %s", e.Reason)
	}
	return fmt.Sprintf("invalid VTEP ID %s: %s", e.VTEPID, e.Reason)
}

// ErrTunnelNotFound is returned when a tunnel is not found in the cluster state.
type ErrTunnelNotFound struct {
	TunnelID string
}

func (e ErrTunnelNotFound) Error() string {
	if e.TunnelID == "" {
		return "tunnel not found"
	}
	return fmt.Sprintf("tunnel not found: %s", e.TunnelID)
}

// ErrTunnelAlreadyExists is returned when attempting to create a tunnel that already exists.
type ErrTunnelAlreadyExists struct {
	TunnelID string
}

func (e ErrTunnelAlreadyExists) Error() string {
	return fmt.Sprintf("tunnel already exists: %s", e.TunnelID)
}

// ErrInvalidTunnelID is returned when a tunnel ID is invalid.
type ErrInvalidTunnelID struct {
	TunnelID string
	Reason   string
}

func (e ErrInvalidTunnelID) Error() string {
	if e.TunnelID == "" {
		return fmt.Sprintf("invalid tunnel ID: %s", e.Reason)
	}
	return fmt.Sprintf("invalid tunnel ID %s: %s", e.TunnelID, e.Reason)
}

// ErrVNIMappingNotFound is returned when a VNI mapping is not found in the cluster state.
type ErrVNIMappingNotFound struct {
	VNI uint32
}

func (e ErrVNIMappingNotFound) Error() string {
	if e.VNI == 0 {
		return "VNI mapping not found"
	}
	return fmt.Sprintf("VNI mapping not found: %d", e.VNI)
}

// ErrVNIAlreadyMapped is returned when attempting to create a VNI mapping that already exists.
type ErrVNIAlreadyMapped struct {
	VNI  uint32
	VLAN uint16
}

func (e ErrVNIAlreadyMapped) Error() string {
	return fmt.Sprintf("VNI %d already mapped to VLAN %d", e.VNI, e.VLAN)
}

// ErrInvalidVNI is returned when a VNI is invalid.
type ErrInvalidVNI struct {
	VNI    uint32
	Reason string
}

func (e ErrInvalidVNI) Error() string {
	return fmt.Sprintf("invalid VNI %d: %s", e.VNI, e.Reason)
}

// ErrRemoteMACNotFound is returned when a remote MAC entry is not found in the cluster state.
type ErrRemoteMACNotFound struct {
	MAC string
	VNI uint32
}

func (e ErrRemoteMACNotFound) Error() string {
	if e.MAC == "" {
		return "remote MAC not found"
	}
	return fmt.Sprintf("remote MAC not found: mac=%s, vni=%d", e.MAC, e.VNI)
}

// ErrRemoteMACAlreadyExists is returned when attempting to create a remote MAC entry that already exists.
type ErrRemoteMACAlreadyExists struct {
	MAC string
	VNI uint32
}

func (e ErrRemoteMACAlreadyExists) Error() string {
	return fmt.Sprintf("remote MAC already exists: mac=%s, vni=%d", e.MAC, e.VNI)
}

// ErrInvalidRemoteMACID is returned when a remote MAC ID is invalid.
type ErrInvalidRemoteMACID struct {
	RemoteMACID string
	Reason      string
}

func (e ErrInvalidRemoteMACID) Error() string {
	if e.RemoteMACID == "" {
		return fmt.Sprintf("invalid remote MAC ID: %s", e.Reason)
	}
	return fmt.Sprintf("invalid remote MAC ID %s: %s", e.RemoteMACID, e.Reason)
}
