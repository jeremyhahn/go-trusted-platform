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
	"context"
	"time"
)

// Operation represents a state change operation that can be replicated across the cluster.
// Operations are executed through Raft consensus to ensure consistency.
type Operation interface {
	// Type returns the operation type identifier
	Type() OperationType

	// Execute applies the operation to the local state
	Execute(ctx context.Context, state StateManager) error

	// Validate checks if the operation is valid before execution
	Validate() error

	// Timestamp returns when the operation was created
	Timestamp() time.Time

	// NodeID returns the node that originated this operation
	NodeID() uint64
}

// OperationType identifies the type of operation being performed.
type OperationType string

const (
	// Bridge operations
	OpTypeCreateBridge OperationType = "create_bridge"
	OpTypeUpdateBridge OperationType = "update_bridge"
	OpTypeDeleteBridge OperationType = "delete_bridge"

	// Port operations
	OpTypeCreatePort OperationType = "create_port"
	OpTypeUpdatePort OperationType = "update_port"
	OpTypeDeletePort OperationType = "delete_port"

	// Flow operations
	OpTypeCreateFlow OperationType = "create_flow"
	OpTypeUpdateFlow OperationType = "update_flow"
	OpTypeDeleteFlow OperationType = "delete_flow"

	// VLAN operations
	OpTypeCreateVLAN OperationType = "create_vlan"
	OpTypeUpdateVLAN OperationType = "update_vlan"
	OpTypeDeleteVLAN OperationType = "delete_vlan"
)

// CreateBridgeOp represents an operation to create a new bridge.
type CreateBridgeOp struct {
	// Bridge is the bridge configuration to create
	Bridge *BridgeState

	// timestamp is when the operation was created
	timestamp time.Time

	// nodeID is the node that originated this operation
	nodeID uint64
}

// NewCreateBridgeOp creates a new bridge creation operation.
func NewCreateBridgeOp(bridge *BridgeState, nodeID uint64) *CreateBridgeOp {
	return &CreateBridgeOp{
		Bridge:    bridge,
		timestamp: time.Now(),
		nodeID:    nodeID,
	}
}

// Type returns the operation type.
func (o *CreateBridgeOp) Type() OperationType {
	return OpTypeCreateBridge
}

// Execute applies the operation to the local state.
func (o *CreateBridgeOp) Execute(ctx context.Context, state StateManager) error {
	return state.CreateBridge(ctx, o.Bridge)
}

// Validate checks if the operation is valid.
func (o *CreateBridgeOp) Validate() error {
	if o.Bridge == nil {
		return ErrInvalidOperation{Operation: string(OpTypeCreateBridge), Reason: "bridge is nil"}
	}
	if o.Bridge.ID == "" {
		return ErrInvalidBridgeID{BridgeID: o.Bridge.ID, Reason: "bridge ID is required"}
	}
	if o.Bridge.Name == "" {
		return ErrInvalidOperation{Operation: string(OpTypeCreateBridge), Reason: "bridge name is required"}
	}
	return nil
}

// Timestamp returns when the operation was created.
func (o *CreateBridgeOp) Timestamp() time.Time {
	return o.timestamp
}

// NodeID returns the node that originated this operation.
func (o *CreateBridgeOp) NodeID() uint64 {
	return o.nodeID
}

// UpdateBridgeOp represents an operation to update a bridge.
type UpdateBridgeOp struct {
	// BridgeID is the ID of the bridge to update
	BridgeID string

	// Updates contains the fields to update
	Updates *BridgeState

	// ExpectedVersion is used for optimistic locking
	ExpectedVersion uint64

	// timestamp is when the operation was created
	timestamp time.Time

	// nodeID is the node that originated this operation
	nodeID uint64
}

// NewUpdateBridgeOp creates a new bridge update operation.
func NewUpdateBridgeOp(bridgeID string, updates *BridgeState, expectedVersion uint64, nodeID uint64) *UpdateBridgeOp {
	return &UpdateBridgeOp{
		BridgeID:        bridgeID,
		Updates:         updates,
		ExpectedVersion: expectedVersion,
		timestamp:       time.Now(),
		nodeID:          nodeID,
	}
}

// Type returns the operation type.
func (o *UpdateBridgeOp) Type() OperationType {
	return OpTypeUpdateBridge
}

// Execute applies the operation to the local state.
func (o *UpdateBridgeOp) Execute(ctx context.Context, state StateManager) error {
	return state.UpdateBridge(ctx, o.BridgeID, o.Updates, o.ExpectedVersion)
}

// Validate checks if the operation is valid.
func (o *UpdateBridgeOp) Validate() error {
	if o.BridgeID == "" {
		return ErrInvalidBridgeID{BridgeID: o.BridgeID, Reason: "bridge ID is required"}
	}
	if o.Updates == nil {
		return ErrInvalidOperation{Operation: string(OpTypeUpdateBridge), Reason: "updates are required"}
	}
	return nil
}

// Timestamp returns when the operation was created.
func (o *UpdateBridgeOp) Timestamp() time.Time {
	return o.timestamp
}

// NodeID returns the node that originated this operation.
func (o *UpdateBridgeOp) NodeID() uint64 {
	return o.nodeID
}

// DeleteBridgeOp represents an operation to delete a bridge.
type DeleteBridgeOp struct {
	// BridgeID is the ID of the bridge to delete
	BridgeID string

	// ExpectedVersion is used for optimistic locking
	ExpectedVersion uint64

	// timestamp is when the operation was created
	timestamp time.Time

	// nodeID is the node that originated this operation
	nodeID uint64
}

// NewDeleteBridgeOp creates a new bridge deletion operation.
func NewDeleteBridgeOp(bridgeID string, expectedVersion uint64, nodeID uint64) *DeleteBridgeOp {
	return &DeleteBridgeOp{
		BridgeID:        bridgeID,
		ExpectedVersion: expectedVersion,
		timestamp:       time.Now(),
		nodeID:          nodeID,
	}
}

// Type returns the operation type.
func (o *DeleteBridgeOp) Type() OperationType {
	return OpTypeDeleteBridge
}

// Execute applies the operation to the local state.
func (o *DeleteBridgeOp) Execute(ctx context.Context, state StateManager) error {
	return state.DeleteBridge(ctx, o.BridgeID, o.ExpectedVersion)
}

// Validate checks if the operation is valid.
func (o *DeleteBridgeOp) Validate() error {
	if o.BridgeID == "" {
		return ErrInvalidBridgeID{BridgeID: o.BridgeID, Reason: "bridge ID is required"}
	}
	return nil
}

// Timestamp returns when the operation was created.
func (o *DeleteBridgeOp) Timestamp() time.Time {
	return o.timestamp
}

// NodeID returns the node that originated this operation.
func (o *DeleteBridgeOp) NodeID() uint64 {
	return o.nodeID
}

// CreatePortOp represents an operation to create a new port.
type CreatePortOp struct {
	// Port is the port configuration to create
	Port *PortState

	// timestamp is when the operation was created
	timestamp time.Time

	// nodeID is the node that originated this operation
	nodeID uint64
}

// NewCreatePortOp creates a new port creation operation.
func NewCreatePortOp(port *PortState, nodeID uint64) *CreatePortOp {
	return &CreatePortOp{
		Port:      port,
		timestamp: time.Now(),
		nodeID:    nodeID,
	}
}

// Type returns the operation type.
func (o *CreatePortOp) Type() OperationType {
	return OpTypeCreatePort
}

// Execute applies the operation to the local state.
func (o *CreatePortOp) Execute(ctx context.Context, state StateManager) error {
	return state.CreatePort(ctx, o.Port)
}

// Validate checks if the operation is valid.
func (o *CreatePortOp) Validate() error {
	if o.Port == nil {
		return ErrInvalidOperation{Operation: string(OpTypeCreatePort), Reason: "port is nil"}
	}
	if o.Port.ID == "" {
		return ErrInvalidPortID{PortID: o.Port.ID, Reason: "port ID is required"}
	}
	if o.Port.Name == "" {
		return ErrInvalidOperation{Operation: string(OpTypeCreatePort), Reason: "port name is required"}
	}
	if o.Port.BridgeID == "" {
		return ErrInvalidOperation{Operation: string(OpTypeCreatePort), Reason: "bridge ID is required"}
	}
	return nil
}

// Timestamp returns when the operation was created.
func (o *CreatePortOp) Timestamp() time.Time {
	return o.timestamp
}

// NodeID returns the node that originated this operation.
func (o *CreatePortOp) NodeID() uint64 {
	return o.nodeID
}

// UpdatePortOp represents an operation to update a port.
type UpdatePortOp struct {
	// PortID is the ID of the port to update
	PortID string

	// Updates contains the fields to update
	Updates *PortState

	// ExpectedVersion is used for optimistic locking
	ExpectedVersion uint64

	// timestamp is when the operation was created
	timestamp time.Time

	// nodeID is the node that originated this operation
	nodeID uint64
}

// NewUpdatePortOp creates a new port update operation.
func NewUpdatePortOp(portID string, updates *PortState, expectedVersion uint64, nodeID uint64) *UpdatePortOp {
	return &UpdatePortOp{
		PortID:          portID,
		Updates:         updates,
		ExpectedVersion: expectedVersion,
		timestamp:       time.Now(),
		nodeID:          nodeID,
	}
}

// Type returns the operation type.
func (o *UpdatePortOp) Type() OperationType {
	return OpTypeUpdatePort
}

// Execute applies the operation to the local state.
func (o *UpdatePortOp) Execute(ctx context.Context, state StateManager) error {
	return state.UpdatePort(ctx, o.PortID, o.Updates, o.ExpectedVersion)
}

// Validate checks if the operation is valid.
func (o *UpdatePortOp) Validate() error {
	if o.PortID == "" {
		return ErrInvalidPortID{PortID: o.PortID, Reason: "port ID is required"}
	}
	if o.Updates == nil {
		return ErrInvalidOperation{Operation: string(OpTypeUpdatePort), Reason: "updates are required"}
	}
	return nil
}

// Timestamp returns when the operation was created.
func (o *UpdatePortOp) Timestamp() time.Time {
	return o.timestamp
}

// NodeID returns the node that originated this operation.
func (o *UpdatePortOp) NodeID() uint64 {
	return o.nodeID
}

// DeletePortOp represents an operation to delete a port.
type DeletePortOp struct {
	// PortID is the ID of the port to delete
	PortID string

	// ExpectedVersion is used for optimistic locking
	ExpectedVersion uint64

	// timestamp is when the operation was created
	timestamp time.Time

	// nodeID is the node that originated this operation
	nodeID uint64
}

// NewDeletePortOp creates a new port deletion operation.
func NewDeletePortOp(portID string, expectedVersion uint64, nodeID uint64) *DeletePortOp {
	return &DeletePortOp{
		PortID:          portID,
		ExpectedVersion: expectedVersion,
		timestamp:       time.Now(),
		nodeID:          nodeID,
	}
}

// Type returns the operation type.
func (o *DeletePortOp) Type() OperationType {
	return OpTypeDeletePort
}

// Execute applies the operation to the local state.
func (o *DeletePortOp) Execute(ctx context.Context, state StateManager) error {
	return state.DeletePort(ctx, o.PortID, o.ExpectedVersion)
}

// Validate checks if the operation is valid.
func (o *DeletePortOp) Validate() error {
	if o.PortID == "" {
		return ErrInvalidPortID{PortID: o.PortID, Reason: "port ID is required"}
	}
	return nil
}

// Timestamp returns when the operation was created.
func (o *DeletePortOp) Timestamp() time.Time {
	return o.timestamp
}

// NodeID returns the node that originated this operation.
func (o *DeletePortOp) NodeID() uint64 {
	return o.nodeID
}

// CreateFlowOp represents an operation to create a new flow.
type CreateFlowOp struct {
	// Flow is the flow configuration to create
	Flow *FlowState

	// timestamp is when the operation was created
	timestamp time.Time

	// nodeID is the node that originated this operation
	nodeID uint64
}

// NewCreateFlowOp creates a new flow creation operation.
func NewCreateFlowOp(flow *FlowState, nodeID uint64) *CreateFlowOp {
	return &CreateFlowOp{
		Flow:      flow,
		timestamp: time.Now(),
		nodeID:    nodeID,
	}
}

// Type returns the operation type.
func (o *CreateFlowOp) Type() OperationType {
	return OpTypeCreateFlow
}

// Execute applies the operation to the local state.
func (o *CreateFlowOp) Execute(ctx context.Context, state StateManager) error {
	return state.CreateFlow(ctx, o.Flow)
}

// Validate checks if the operation is valid.
func (o *CreateFlowOp) Validate() error {
	if o.Flow == nil {
		return ErrInvalidOperation{Operation: string(OpTypeCreateFlow), Reason: "flow is nil"}
	}
	if o.Flow.ID == "" {
		return ErrInvalidFlowID{FlowID: o.Flow.ID, Reason: "flow ID is required"}
	}
	if o.Flow.BridgeID == "" {
		return ErrInvalidOperation{Operation: string(OpTypeCreateFlow), Reason: "bridge ID is required"}
	}
	if o.Flow.Match == nil {
		return ErrInvalidOperation{Operation: string(OpTypeCreateFlow), Reason: "match criteria is required"}
	}
	if len(o.Flow.Actions) == 0 {
		return ErrInvalidOperation{Operation: string(OpTypeCreateFlow), Reason: "at least one action is required"}
	}
	return nil
}

// Timestamp returns when the operation was created.
func (o *CreateFlowOp) Timestamp() time.Time {
	return o.timestamp
}

// NodeID returns the node that originated this operation.
func (o *CreateFlowOp) NodeID() uint64 {
	return o.nodeID
}

// UpdateFlowOp represents an operation to update a flow.
type UpdateFlowOp struct {
	// FlowID is the ID of the flow to update
	FlowID string

	// BridgeID is the ID of the bridge containing the flow
	BridgeID string

	// Updates contains the fields to update
	Updates *FlowState

	// ExpectedVersion is used for optimistic locking
	ExpectedVersion uint64

	// timestamp is when the operation was created
	timestamp time.Time

	// nodeID is the node that originated this operation
	nodeID uint64
}

// NewUpdateFlowOp creates a new flow update operation.
func NewUpdateFlowOp(bridgeID, flowID string, updates *FlowState, expectedVersion uint64, nodeID uint64) *UpdateFlowOp {
	return &UpdateFlowOp{
		FlowID:          flowID,
		BridgeID:        bridgeID,
		Updates:         updates,
		ExpectedVersion: expectedVersion,
		timestamp:       time.Now(),
		nodeID:          nodeID,
	}
}

// Type returns the operation type.
func (o *UpdateFlowOp) Type() OperationType {
	return OpTypeUpdateFlow
}

// Execute applies the operation to the local state.
func (o *UpdateFlowOp) Execute(ctx context.Context, state StateManager) error {
	return state.UpdateFlow(ctx, o.BridgeID, o.FlowID, o.Updates, o.ExpectedVersion)
}

// Validate checks if the operation is valid.
func (o *UpdateFlowOp) Validate() error {
	if o.FlowID == "" {
		return ErrInvalidFlowID{FlowID: o.FlowID, Reason: "flow ID is required"}
	}
	if o.BridgeID == "" {
		return ErrInvalidOperation{Operation: string(OpTypeUpdateFlow), Reason: "bridge ID is required"}
	}
	if o.Updates == nil {
		return ErrInvalidOperation{Operation: string(OpTypeUpdateFlow), Reason: "updates are required"}
	}
	return nil
}

// Timestamp returns when the operation was created.
func (o *UpdateFlowOp) Timestamp() time.Time {
	return o.timestamp
}

// NodeID returns the node that originated this operation.
func (o *UpdateFlowOp) NodeID() uint64 {
	return o.nodeID
}

// DeleteFlowOp represents an operation to delete a flow.
type DeleteFlowOp struct {
	// FlowID is the ID of the flow to delete
	FlowID string

	// BridgeID is the ID of the bridge containing the flow
	BridgeID string

	// ExpectedVersion is used for optimistic locking
	ExpectedVersion uint64

	// timestamp is when the operation was created
	timestamp time.Time

	// nodeID is the node that originated this operation
	nodeID uint64
}

// NewDeleteFlowOp creates a new flow deletion operation.
func NewDeleteFlowOp(bridgeID, flowID string, expectedVersion uint64, nodeID uint64) *DeleteFlowOp {
	return &DeleteFlowOp{
		FlowID:          flowID,
		BridgeID:        bridgeID,
		ExpectedVersion: expectedVersion,
		timestamp:       time.Now(),
		nodeID:          nodeID,
	}
}

// Type returns the operation type.
func (o *DeleteFlowOp) Type() OperationType {
	return OpTypeDeleteFlow
}

// Execute applies the operation to the local state.
func (o *DeleteFlowOp) Execute(ctx context.Context, state StateManager) error {
	return state.DeleteFlow(ctx, o.BridgeID, o.FlowID, o.ExpectedVersion)
}

// Validate checks if the operation is valid.
func (o *DeleteFlowOp) Validate() error {
	if o.FlowID == "" {
		return ErrInvalidFlowID{FlowID: o.FlowID, Reason: "flow ID is required"}
	}
	if o.BridgeID == "" {
		return ErrInvalidOperation{Operation: string(OpTypeDeleteFlow), Reason: "bridge ID is required"}
	}
	return nil
}

// Timestamp returns when the operation was created.
func (o *DeleteFlowOp) Timestamp() time.Time {
	return o.timestamp
}

// NodeID returns the node that originated this operation.
func (o *DeleteFlowOp) NodeID() uint64 {
	return o.nodeID
}

// CreateVLANOp represents an operation to create a new VLAN.
type CreateVLANOp struct {
	// VLAN is the VLAN configuration to create
	VLAN *VLANState

	// timestamp is when the operation was created
	timestamp time.Time

	// nodeID is the node that originated this operation
	nodeID uint64
}

// NewCreateVLANOp creates a new VLAN creation operation.
func NewCreateVLANOp(vlan *VLANState, nodeID uint64) *CreateVLANOp {
	return &CreateVLANOp{
		VLAN:      vlan,
		timestamp: time.Now(),
		nodeID:    nodeID,
	}
}

// Type returns the operation type.
func (o *CreateVLANOp) Type() OperationType {
	return OpTypeCreateVLAN
}

// Execute applies the operation to the local state.
func (o *CreateVLANOp) Execute(ctx context.Context, state StateManager) error {
	return state.CreateVLAN(ctx, o.VLAN)
}

// Validate checks if the operation is valid.
func (o *CreateVLANOp) Validate() error {
	if o.VLAN == nil {
		return ErrInvalidOperation{Operation: string(OpTypeCreateVLAN), Reason: "VLAN is nil"}
	}
	if o.VLAN.ID < 1 || o.VLAN.ID > 4094 {
		return ErrInvalidVLANID{VLANID: o.VLAN.ID, Reason: "VLAN ID must be 1-4094"}
	}
	if o.VLAN.Name == "" {
		return ErrInvalidOperation{Operation: string(OpTypeCreateVLAN), Reason: "VLAN name is required"}
	}
	return nil
}

// Timestamp returns when the operation was created.
func (o *CreateVLANOp) Timestamp() time.Time {
	return o.timestamp
}

// NodeID returns the node that originated this operation.
func (o *CreateVLANOp) NodeID() uint64 {
	return o.nodeID
}

// UpdateVLANOp represents an operation to update a VLAN.
type UpdateVLANOp struct {
	// VLANID is the ID of the VLAN to update
	VLANID uint16

	// Updates contains the fields to update
	Updates *VLANState

	// ExpectedVersion is used for optimistic locking
	ExpectedVersion uint64

	// timestamp is when the operation was created
	timestamp time.Time

	// nodeID is the node that originated this operation
	nodeID uint64
}

// NewUpdateVLANOp creates a new VLAN update operation.
func NewUpdateVLANOp(vlanID uint16, updates *VLANState, expectedVersion uint64, nodeID uint64) *UpdateVLANOp {
	return &UpdateVLANOp{
		VLANID:          vlanID,
		Updates:         updates,
		ExpectedVersion: expectedVersion,
		timestamp:       time.Now(),
		nodeID:          nodeID,
	}
}

// Type returns the operation type.
func (o *UpdateVLANOp) Type() OperationType {
	return OpTypeUpdateVLAN
}

// Execute applies the operation to the local state.
func (o *UpdateVLANOp) Execute(ctx context.Context, state StateManager) error {
	return state.UpdateVLAN(ctx, o.VLANID, o.Updates, o.ExpectedVersion)
}

// Validate checks if the operation is valid.
func (o *UpdateVLANOp) Validate() error {
	if o.VLANID < 1 || o.VLANID > 4094 {
		return ErrInvalidVLANID{VLANID: o.VLANID, Reason: "VLAN ID must be 1-4094"}
	}
	if o.Updates == nil {
		return ErrInvalidOperation{Operation: string(OpTypeUpdateVLAN), Reason: "updates are required"}
	}
	return nil
}

// Timestamp returns when the operation was created.
func (o *UpdateVLANOp) Timestamp() time.Time {
	return o.timestamp
}

// NodeID returns the node that originated this operation.
func (o *UpdateVLANOp) NodeID() uint64 {
	return o.nodeID
}

// DeleteVLANOp represents an operation to delete a VLAN.
type DeleteVLANOp struct {
	// VLANID is the ID of the VLAN to delete
	VLANID uint16

	// ExpectedVersion is used for optimistic locking
	ExpectedVersion uint64

	// timestamp is when the operation was created
	timestamp time.Time

	// nodeID is the node that originated this operation
	nodeID uint64
}

// NewDeleteVLANOp creates a new VLAN deletion operation.
func NewDeleteVLANOp(vlanID uint16, expectedVersion uint64, nodeID uint64) *DeleteVLANOp {
	return &DeleteVLANOp{
		VLANID:          vlanID,
		ExpectedVersion: expectedVersion,
		timestamp:       time.Now(),
		nodeID:          nodeID,
	}
}

// Type returns the operation type.
func (o *DeleteVLANOp) Type() OperationType {
	return OpTypeDeleteVLAN
}

// Execute applies the operation to the local state.
func (o *DeleteVLANOp) Execute(ctx context.Context, state StateManager) error {
	return state.DeleteVLAN(ctx, o.VLANID, o.ExpectedVersion)
}

// Validate checks if the operation is valid.
func (o *DeleteVLANOp) Validate() error {
	if o.VLANID < 1 || o.VLANID > 4094 {
		return ErrInvalidVLANID{VLANID: o.VLANID, Reason: "VLAN ID must be 1-4094"}
	}
	return nil
}

// Timestamp returns when the operation was created.
func (o *DeleteVLANOp) Timestamp() time.Time {
	return o.timestamp
}

// NodeID returns the node that originated this operation.
func (o *DeleteVLANOp) NodeID() uint64 {
	return o.nodeID
}

// StateManager is the interface for managing cluster-replicated SDN state.
// This interface is implemented by the actual state manager that uses QuicBaaS.
type StateManager interface {
	// Bridge operations
	CreateBridge(ctx context.Context, bridge *BridgeState) error
	UpdateBridge(ctx context.Context, bridgeID string, updates *BridgeState, expectedVersion uint64) error
	DeleteBridge(ctx context.Context, bridgeID string, expectedVersion uint64) error
	GetBridge(ctx context.Context, bridgeID string) (*BridgeState, error)
	ListBridges(ctx context.Context) ([]*BridgeState, error)

	// Port operations
	CreatePort(ctx context.Context, port *PortState) error
	UpdatePort(ctx context.Context, portID string, updates *PortState, expectedVersion uint64) error
	DeletePort(ctx context.Context, portID string, expectedVersion uint64) error
	GetPort(ctx context.Context, portID string) (*PortState, error)
	ListPorts(ctx context.Context, bridgeID string) ([]*PortState, error)

	// Flow operations
	CreateFlow(ctx context.Context, flow *FlowState) error
	UpdateFlow(ctx context.Context, bridgeID, flowID string, updates *FlowState, expectedVersion uint64) error
	DeleteFlow(ctx context.Context, bridgeID, flowID string, expectedVersion uint64) error
	GetFlow(ctx context.Context, bridgeID, flowID string) (*FlowState, error)
	ListFlows(ctx context.Context, bridgeID string) ([]*FlowState, error)

	// VLAN operations
	CreateVLAN(ctx context.Context, vlan *VLANState) error
	UpdateVLAN(ctx context.Context, vlanID uint16, updates *VLANState, expectedVersion uint64) error
	DeleteVLAN(ctx context.Context, vlanID uint16, expectedVersion uint64) error
	GetVLAN(ctx context.Context, vlanID uint16) (*VLANState, error)
	ListVLANs(ctx context.Context) ([]*VLANState, error)
}
