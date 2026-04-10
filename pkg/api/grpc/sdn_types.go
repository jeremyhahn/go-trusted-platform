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

package grpc

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
)

// SDNService defines the interface for SDN operations.
// This interface is implemented by SDN service providers and used by the gRPC service.
type SDNService interface {
	// Bridge operations
	CreateBridge(ctx context.Context, name string) (*ovs.Bridge, error)
	DeleteBridge(ctx context.Context, name string) error
	GetBridge(ctx context.Context, name string) (*ovs.Bridge, error)
	ListBridges(ctx context.Context) ([]*ovs.Bridge, error)

	// Port operations
	AddPort(ctx context.Context, bridge, port string) (*ovs.Port, error)
	RemovePort(ctx context.Context, bridge, port string) error
	GetPort(ctx context.Context, name string) (*ovs.Port, error)
	ListPorts(ctx context.Context, bridge string) ([]*ovs.Port, error)
	SetPortVLAN(ctx context.Context, port string, vlan int64) error
	GetInterface(ctx context.Context, name string) (*ovs.Interface, error)

	// Flow operations
	AddFlow(ctx context.Context, bridge string, flow *ovs.FlowMod) error
	DeleteFlow(ctx context.Context, bridge, match string) error
	ListFlows(ctx context.Context, bridge string) ([]*ovs.Flow, error)
	GetFlowStats(ctx context.Context, bridge, match string) ([]*ovs.Flow, error)
}

// =============================================================================
// SDN Error Types
// =============================================================================

// ErrSDNBridgeNotFound is returned when a bridge is not found.
type ErrSDNBridgeNotFound struct {
	BridgeName string
}

func (e ErrSDNBridgeNotFound) Error() string {
	return "bridge not found: " + e.BridgeName
}

// ErrSDNPortNotFound is returned when a port is not found.
type ErrSDNPortNotFound struct {
	PortName string
}

func (e ErrSDNPortNotFound) Error() string {
	return "port not found: " + e.PortName
}

// ErrSDNBridgeAlreadyExists is returned when a bridge already exists.
type ErrSDNBridgeAlreadyExists struct {
	BridgeName string
}

func (e ErrSDNBridgeAlreadyExists) Error() string {
	return "bridge already exists: " + e.BridgeName
}

// ErrSDNPortAlreadyExists is returned when a port already exists.
type ErrSDNPortAlreadyExists struct {
	PortName string
}

func (e ErrSDNPortAlreadyExists) Error() string {
	return "port already exists: " + e.PortName
}

// ErrSDNInvalidRequest is returned when an invalid request is made.
type ErrSDNInvalidRequest struct {
	Reason string
}

func (e ErrSDNInvalidRequest) Error() string {
	return "invalid request: " + e.Reason
}

// ErrSDNOperationFailed is returned when an SDN operation fails.
type ErrSDNOperationFailed struct {
	Operation string
	Cause     error
}

func (e ErrSDNOperationFailed) Error() string {
	if e.Cause != nil {
		return "SDN operation " + e.Operation + " failed: " + e.Cause.Error()
	}
	return "SDN operation " + e.Operation + " failed"
}
