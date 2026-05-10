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

package ovs

import "context"

// ClientInterface defines the interface for OVS client operations.
// This interface allows for mocking in unit tests while the concrete
// Client type provides the actual OVSDB implementation.
type ClientInterface interface {
	// Connection management
	Connect(ctx context.Context) error
	Disconnect() error
	IsConnected() bool
	Close() error

	// Bridge operations
	CreateBridge(ctx context.Context, name string) (*Bridge, error)
	DeleteBridge(ctx context.Context, name string) error
	GetBridge(ctx context.Context, name string) (*Bridge, error)
	ListBridges(ctx context.Context) ([]*Bridge, error)
	UpdateBridge(ctx context.Context, name string, updates map[string]interface{}) error
	SetBridgeFailMode(ctx context.Context, name string, failMode string) error
	SetBridgeProtocols(ctx context.Context, name string, protocols []string) error

	// Port operations
	AddPort(ctx context.Context, bridgeName, portName string) (*Port, error)
	AddBond(ctx context.Context, bridgeName, bondName string, members []string, mode string, lacp string) (*Port, error)
	DeletePort(ctx context.Context, bridgeName, portName string) error
	GetPort(ctx context.Context, name string) (*Port, error)
	ListPorts(ctx context.Context, bridgeName string) ([]*Port, error)
	UpdatePort(ctx context.Context, name string, updates map[string]interface{}) error
	SetPortVLAN(ctx context.Context, portName string, tag int64) error
	SetPortTrunks(ctx context.Context, portName string, trunks []int64) error
	SetPortState(ctx context.Context, portName string, state PortState) error

	// Interface operations
	GetInterface(ctx context.Context, name string) (*Interface, error)
	GetOFPort(ctx context.Context, portName string) (int32, error)
	GetInterfaceOptions(ctx context.Context, name string) (map[string]string, error)

	// VXLAN operations
	AddVXLANPort(ctx context.Context, bridgeName string, cfg *VXLANPortConfig) (*VXLANPort, error)
	AddVXLANPortWithName(ctx context.Context, bridgeName, portName string, cfg *VXLANPortConfig) (*VXLANPort, error)
	DeleteVXLANPort(ctx context.Context, bridgeName, portName string) error
	ListVXLANPorts(ctx context.Context, bridgeName string) ([]*VXLANPort, error)
	GetVXLANPort(ctx context.Context, bridgeName, portName string) (*VXLANPort, error)
	GetVXLANPortWithOptions(ctx context.Context, bridgeName, portName string) (*VXLANPort, error)
	UpdateVXLANPort(ctx context.Context, bridgeName, portName string, cfg *VXLANPortConfig) error

	// Flow operations
	AddFlow(ctx context.Context, bridgeName string, flow *FlowMod) error
	DeleteFlow(ctx context.Context, bridgeName string, match string) error
	ListFlows(ctx context.Context, bridgeName string) ([]*Flow, error)
	DeleteAllFlows(ctx context.Context, bridgeName string) error
	ModifyFlow(ctx context.Context, bridgeName string, flow *FlowMod) error
	GetFlowStats(ctx context.Context, bridgeName string, match string) ([]*Flow, error)

	// OVSDB operations
	ListDatabases(ctx context.Context) ([]string, error)
	GetSchema(ctx context.Context) (*GetSchemaResult, error)
	Echo(ctx context.Context, data []interface{}) ([]interface{}, error)
	Transact(ctx context.Context, operations ...Operation) (TransactResponse, error)
	Select(ctx context.Context, table string, where []Condition, columns []string) ([]map[string]interface{}, error)
}

// Verify that Client implements ClientInterface at compile time
var _ ClientInterface = (*Client)(nil)
