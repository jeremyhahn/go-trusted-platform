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

package daemon

import (
	"context"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
)

// ConfigurableMockOVSClient implements ovs.ClientInterface for testing purposes.
// It allows configuring return values and errors per method using functional options
// and tracks all method calls for verification in tests.
// This is distinct from MockOVSClient in quic_sdn_unit_test.go which uses error
// injection fields.
type ConfigurableMockOVSClient struct {
	mu sync.RWMutex

	// Connection state
	connected atomic.Bool

	// Method call tracking
	calls map[string][]ConfigurableMockCall

	// Configurable return values and errors per method
	connectFunc              func(ctx context.Context) error
	disconnectFunc           func() error
	isConnectedFunc          func() bool
	closeFunc                func() error
	createBridgeFunc         func(ctx context.Context, name string) (*ovs.Bridge, error)
	deleteBridgeFunc         func(ctx context.Context, name string) error
	getBridgeFunc            func(ctx context.Context, name string) (*ovs.Bridge, error)
	listBridgesFunc          func(ctx context.Context) ([]*ovs.Bridge, error)
	updateBridgeFunc         func(ctx context.Context, name string, updates map[string]interface{}) error
	setBridgeFailModeFunc    func(ctx context.Context, name string, failMode string) error
	setBridgeProtocolsFunc   func(ctx context.Context, name string, protocols []string) error
	addPortFunc              func(ctx context.Context, bridgeName, portName string) (*ovs.Port, error)
	deletePortFunc           func(ctx context.Context, bridgeName, portName string) error
	getPortFunc              func(ctx context.Context, name string) (*ovs.Port, error)
	listPortsFunc            func(ctx context.Context, bridgeName string) ([]*ovs.Port, error)
	updatePortFunc           func(ctx context.Context, name string, updates map[string]interface{}) error
	setPortVLANFunc          func(ctx context.Context, portName string, tag int64) error
	setPortTrunksFunc        func(ctx context.Context, portName string, trunks []int64) error
	setPortStateFunc         func(ctx context.Context, portName string, state ovs.PortState) error
	setIngressPolicingFunc   func(ctx context.Context, name string, rateBps, burstBits uint64) error
	setEgressShapingFunc     func(ctx context.Context, name string, rateBps, burstBits uint64) error
	getInterfaceFunc         func(ctx context.Context, name string) (*ovs.Interface, error)
	getOFPortFunc            func(ctx context.Context, portName string) (int32, error)
	getInterfaceOptionsFunc  func(ctx context.Context, name string) (map[string]string, error)
	createBridgeWithOptsFunc func(ctx context.Context, name string, opts *ovs.BridgeOptions) (*ovs.Bridge, error)
	setBridgeDatapathFunc    func(ctx context.Context, name string, datapathType string) error
	setBridgeOtherConfigFunc func(ctx context.Context, name string, config map[string]string) error
	setInterfaceTypeFunc     func(ctx context.Context, name, ifType string) error
	setInterfaceOptionsFunc  func(ctx context.Context, name string, options map[string]string) error
	setIfaceOtherConfigFunc  func(ctx context.Context, name string, config map[string]string) error
	setOVSOtherConfigFunc    func(ctx context.Context, config map[string]string) error
	getOVSOtherConfigFunc    func(ctx context.Context) (map[string]string, error)
	deleteOVSOtherConfigFunc func(ctx context.Context, keys []string) error
	addVXLANPortFunc         func(ctx context.Context, bridgeName string, cfg *ovs.VXLANPortConfig) (*ovs.VXLANPort, error)
	addVXLANPortWithNameFunc func(ctx context.Context, bridgeName, portName string, cfg *ovs.VXLANPortConfig) (*ovs.VXLANPort, error)
	deleteVXLANPortFunc      func(ctx context.Context, bridgeName, portName string) error
	listVXLANPortsFunc       func(ctx context.Context, bridgeName string) ([]*ovs.VXLANPort, error)
	getVXLANPortFunc         func(ctx context.Context, bridgeName, portName string) (*ovs.VXLANPort, error)
	getVXLANPortWithOptsFunc func(ctx context.Context, bridgeName, portName string) (*ovs.VXLANPort, error)
	updateVXLANPortFunc      func(ctx context.Context, bridgeName, portName string, cfg *ovs.VXLANPortConfig) error
	addFlowFunc              func(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error
	addFlowsFunc             func(ctx context.Context, bridgeName string, flows []*ovs.FlowMod) error
	deleteFlowFunc           func(ctx context.Context, bridgeName string, match string) error
	deleteFlowsByCookieFunc  func(ctx context.Context, bridgeName string, cookie, cookieMask uint64) error
	listFlowsFunc            func(ctx context.Context, bridgeName string) ([]*ovs.Flow, error)
	deleteAllFlowsFunc       func(ctx context.Context, bridgeName string) error
	modifyFlowFunc           func(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error
	getFlowStatsFunc         func(ctx context.Context, bridgeName string, match string) ([]*ovs.Flow, error)
	listDatabasesFunc        func(ctx context.Context) ([]string, error)
	getSchemaFunc            func(ctx context.Context) (*ovs.GetSchemaResult, error)
	echoFunc                 func(ctx context.Context, data []interface{}) ([]interface{}, error)
	transactFunc             func(ctx context.Context, operations ...ovs.Operation) (ovs.TransactResponse, error)
	selectFunc               func(ctx context.Context, table string, where []ovs.Condition, columns []string) ([]map[string]interface{}, error)
}

// ConfigurableMockCall records information about a method call
type ConfigurableMockCall struct {
	Method string
	Args   []interface{}
}

// NewConfigurableMockOVSClient creates a new configurable mock OVS client with default implementations
func NewConfigurableMockOVSClient() *ConfigurableMockOVSClient {
	return &ConfigurableMockOVSClient{
		calls: make(map[string][]ConfigurableMockCall),
	}
}

// recordCall records a method call for later verification
func (m *ConfigurableMockOVSClient) recordCall(method string, args ...interface{}) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls[method] = append(m.calls[method], ConfigurableMockCall{Method: method, Args: args})
}

// GetCalls returns all recorded calls for a specific method
func (m *ConfigurableMockOVSClient) GetCalls(method string) []ConfigurableMockCall {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.calls[method]
}

// GetCallCount returns the number of times a method was called
func (m *ConfigurableMockOVSClient) GetCallCount(method string) int {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return len(m.calls[method])
}

// Reset clears all recorded calls
func (m *ConfigurableMockOVSClient) Reset() {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.calls = make(map[string][]ConfigurableMockCall)
	m.connected.Store(false)
}

// Connection management

// AddBond is a no-op stub satisfying the ovs.ClientInterface for tests that
// don't exercise bond creation.
func (m *ConfigurableMockOVSClient) AddBond(_ context.Context, _, _ string, _ []string, _, _ string) (*ovs.Port, error) {
	return nil, nil
}

func (m *ConfigurableMockOVSClient) Connect(ctx context.Context) error {
	m.recordCall("Connect")
	if m.connectFunc != nil {
		return m.connectFunc(ctx)
	}
	m.connected.Store(true)
	return nil
}

func (m *ConfigurableMockOVSClient) Disconnect() error {
	m.recordCall("Disconnect")
	if m.disconnectFunc != nil {
		return m.disconnectFunc()
	}
	m.connected.Store(false)
	return nil
}

func (m *ConfigurableMockOVSClient) IsConnected() bool {
	m.recordCall("IsConnected")
	if m.isConnectedFunc != nil {
		return m.isConnectedFunc()
	}
	return m.connected.Load()
}

func (m *ConfigurableMockOVSClient) Close() error {
	m.recordCall("Close")
	if m.closeFunc != nil {
		return m.closeFunc()
	}
	m.connected.Store(false)
	return nil
}

// Bridge operations

func (m *ConfigurableMockOVSClient) CreateBridge(ctx context.Context, name string) (*ovs.Bridge, error) {
	m.recordCall("CreateBridge", name)
	if m.createBridgeFunc != nil {
		return m.createBridgeFunc(ctx, name)
	}
	return &ovs.Bridge{
		UUID: "mock-bridge-uuid-" + name,
		Name: name,
	}, nil
}

func (m *ConfigurableMockOVSClient) DeleteBridge(ctx context.Context, name string) error {
	m.recordCall("DeleteBridge", name)
	if m.deleteBridgeFunc != nil {
		return m.deleteBridgeFunc(ctx, name)
	}
	return nil
}

func (m *ConfigurableMockOVSClient) GetBridge(ctx context.Context, name string) (*ovs.Bridge, error) {
	m.recordCall("GetBridge", name)
	if m.getBridgeFunc != nil {
		return m.getBridgeFunc(ctx, name)
	}
	return &ovs.Bridge{
		UUID:        "mock-bridge-uuid-" + name,
		Name:        name,
		ExternalIDs: map[string]string{},
		OtherConfig: map[string]string{},
	}, nil
}

func (m *ConfigurableMockOVSClient) ListBridges(ctx context.Context) ([]*ovs.Bridge, error) {
	m.recordCall("ListBridges")
	if m.listBridgesFunc != nil {
		return m.listBridgesFunc(ctx)
	}
	return []*ovs.Bridge{}, nil
}

func (m *ConfigurableMockOVSClient) UpdateBridge(ctx context.Context, name string, updates map[string]interface{}) error {
	m.recordCall("UpdateBridge", name, updates)
	if m.updateBridgeFunc != nil {
		return m.updateBridgeFunc(ctx, name, updates)
	}
	return nil
}

func (m *ConfigurableMockOVSClient) SetBridgeFailMode(ctx context.Context, name string, failMode string) error {
	m.recordCall("SetBridgeFailMode", name, failMode)
	if m.setBridgeFailModeFunc != nil {
		return m.setBridgeFailModeFunc(ctx, name, failMode)
	}
	return nil
}

func (m *ConfigurableMockOVSClient) SetBridgeProtocols(ctx context.Context, name string, protocols []string) error {
	m.recordCall("SetBridgeProtocols", name, protocols)
	if m.setBridgeProtocolsFunc != nil {
		return m.setBridgeProtocolsFunc(ctx, name, protocols)
	}
	return nil
}

// Port operations

func (m *ConfigurableMockOVSClient) AddPort(ctx context.Context, bridgeName, portName string) (*ovs.Port, error) {
	m.recordCall("AddPort", bridgeName, portName)
	if m.addPortFunc != nil {
		return m.addPortFunc(ctx, bridgeName, portName)
	}
	return &ovs.Port{
		UUID:        "mock-port-uuid-" + portName,
		Name:        portName,
		ExternalIDs: map[string]string{},
	}, nil
}

func (m *ConfigurableMockOVSClient) DeletePort(ctx context.Context, bridgeName, portName string) error {
	m.recordCall("DeletePort", bridgeName, portName)
	if m.deletePortFunc != nil {
		return m.deletePortFunc(ctx, bridgeName, portName)
	}
	return nil
}

func (m *ConfigurableMockOVSClient) GetPort(ctx context.Context, name string) (*ovs.Port, error) {
	m.recordCall("GetPort", name)
	if m.getPortFunc != nil {
		return m.getPortFunc(ctx, name)
	}
	return &ovs.Port{
		UUID:        "mock-port-uuid-" + name,
		Name:        name,
		ExternalIDs: map[string]string{},
	}, nil
}

func (m *ConfigurableMockOVSClient) ListPorts(ctx context.Context, bridgeName string) ([]*ovs.Port, error) {
	m.recordCall("ListPorts", bridgeName)
	if m.listPortsFunc != nil {
		return m.listPortsFunc(ctx, bridgeName)
	}
	return []*ovs.Port{}, nil
}

func (m *ConfigurableMockOVSClient) UpdatePort(ctx context.Context, name string, updates map[string]interface{}) error {
	m.recordCall("UpdatePort", name, updates)
	if m.updatePortFunc != nil {
		return m.updatePortFunc(ctx, name, updates)
	}
	return nil
}

func (m *ConfigurableMockOVSClient) SetPortVLAN(ctx context.Context, portName string, tag int64) error {
	m.recordCall("SetPortVLAN", portName, tag)
	if m.setPortVLANFunc != nil {
		return m.setPortVLANFunc(ctx, portName, tag)
	}
	return nil
}

func (m *ConfigurableMockOVSClient) SetPortTrunks(ctx context.Context, portName string, trunks []int64) error {
	m.recordCall("SetPortTrunks", portName, trunks)
	if m.setPortTrunksFunc != nil {
		return m.setPortTrunksFunc(ctx, portName, trunks)
	}
	return nil
}

func (m *ConfigurableMockOVSClient) SetPortState(ctx context.Context, portName string, state ovs.PortState) error {
	m.recordCall("SetPortState", portName, state)
	if m.setPortStateFunc != nil {
		return m.setPortStateFunc(ctx, portName, state)
	}
	return nil
}

func (m *ConfigurableMockOVSClient) SetIngressPolicing(ctx context.Context, name string, rateBps, burstBits uint64) error {
	m.recordCall("SetIngressPolicing", name, rateBps, burstBits)
	if m.setIngressPolicingFunc != nil {
		return m.setIngressPolicingFunc(ctx, name, rateBps, burstBits)
	}
	return nil
}

func (m *ConfigurableMockOVSClient) SetEgressShaping(ctx context.Context, name string, rateBps, burstBits uint64) error {
	m.recordCall("SetEgressShaping", name, rateBps, burstBits)
	if m.setEgressShapingFunc != nil {
		return m.setEgressShapingFunc(ctx, name, rateBps, burstBits)
	}
	return nil
}

// Interface operations

func (m *ConfigurableMockOVSClient) GetInterface(ctx context.Context, name string) (*ovs.Interface, error) {
	m.recordCall("GetInterface", name)
	if m.getInterfaceFunc != nil {
		return m.getInterfaceFunc(ctx, name)
	}
	return &ovs.Interface{
		UUID:   "mock-iface-uuid-" + name,
		Name:   name,
		OFPort: 1,
		Statistics: map[string]int64{
			"rx_packets": 1000,
			"tx_packets": 2000,
			"rx_bytes":   100000,
			"tx_bytes":   200000,
			"rx_errors":  0,
			"tx_errors":  0,
			"rx_dropped": 5,
			"tx_dropped": 10,
		},
	}, nil
}

func (m *ConfigurableMockOVSClient) GetOFPort(ctx context.Context, portName string) (int32, error) {
	m.recordCall("GetOFPort", portName)
	if m.getOFPortFunc != nil {
		return m.getOFPortFunc(ctx, portName)
	}
	return 1, nil
}

func (m *ConfigurableMockOVSClient) GetInterfaceOptions(ctx context.Context, name string) (map[string]string, error) {
	m.recordCall("GetInterfaceOptions", name)
	if m.getInterfaceOptionsFunc != nil {
		return m.getInterfaceOptionsFunc(ctx, name)
	}
	return map[string]string{}, nil
}

func (m *ConfigurableMockOVSClient) CreateBridgeWithOptions(ctx context.Context, name string, opts *ovs.BridgeOptions) (*ovs.Bridge, error) {
	m.recordCall("CreateBridgeWithOptions", name, opts)
	if m.createBridgeWithOptsFunc != nil {
		return m.createBridgeWithOptsFunc(ctx, name, opts)
	}
	bridge := &ovs.Bridge{
		UUID: "mock-bridge-uuid-" + name,
		Name: name,
	}
	if opts != nil {
		bridge.DatapathType = opts.DatapathType
		bridge.FailMode = opts.FailMode
		bridge.FlowProtocols = opts.Protocols
	}
	return bridge, nil
}

func (m *ConfigurableMockOVSClient) SetBridgeDatapath(ctx context.Context, name string, datapathType string) error {
	m.recordCall("SetBridgeDatapath", name, datapathType)
	if m.setBridgeDatapathFunc != nil {
		return m.setBridgeDatapathFunc(ctx, name, datapathType)
	}
	return nil
}

func (m *ConfigurableMockOVSClient) SetBridgeOtherConfig(ctx context.Context, name string, config map[string]string) error {
	m.recordCall("SetBridgeOtherConfig", name, config)
	if m.setBridgeOtherConfigFunc != nil {
		return m.setBridgeOtherConfigFunc(ctx, name, config)
	}
	return nil
}

func (m *ConfigurableMockOVSClient) SetInterfaceType(ctx context.Context, name, ifType string) error {
	m.recordCall("SetInterfaceType", name, ifType)
	if m.setInterfaceTypeFunc != nil {
		return m.setInterfaceTypeFunc(ctx, name, ifType)
	}
	return nil
}

func (m *ConfigurableMockOVSClient) SetInterfaceOptions(ctx context.Context, name string, options map[string]string) error {
	m.recordCall("SetInterfaceOptions", name, options)
	if m.setInterfaceOptionsFunc != nil {
		return m.setInterfaceOptionsFunc(ctx, name, options)
	}
	return nil
}

func (m *ConfigurableMockOVSClient) SetInterfaceOtherConfig(ctx context.Context, name string, config map[string]string) error {
	m.recordCall("SetInterfaceOtherConfig", name, config)
	if m.setIfaceOtherConfigFunc != nil {
		return m.setIfaceOtherConfigFunc(ctx, name, config)
	}
	return nil
}

func (m *ConfigurableMockOVSClient) SetOVSOtherConfig(ctx context.Context, config map[string]string) error {
	m.recordCall("SetOVSOtherConfig", config)
	if m.setOVSOtherConfigFunc != nil {
		return m.setOVSOtherConfigFunc(ctx, config)
	}
	return nil
}

func (m *ConfigurableMockOVSClient) GetOVSOtherConfig(ctx context.Context) (map[string]string, error) {
	m.recordCall("GetOVSOtherConfig")
	if m.getOVSOtherConfigFunc != nil {
		return m.getOVSOtherConfigFunc(ctx)
	}
	return map[string]string{}, nil
}

func (m *ConfigurableMockOVSClient) DeleteOVSOtherConfig(ctx context.Context, keys []string) error {
	m.recordCall("DeleteOVSOtherConfig", keys)
	if m.deleteOVSOtherConfigFunc != nil {
		return m.deleteOVSOtherConfigFunc(ctx, keys)
	}
	return nil
}

// VXLAN operations

func (m *ConfigurableMockOVSClient) AddVXLANPort(ctx context.Context, bridgeName string, cfg *ovs.VXLANPortConfig) (*ovs.VXLANPort, error) {
	m.recordCall("AddVXLANPort", bridgeName, cfg)
	if m.addVXLANPortFunc != nil {
		return m.addVXLANPortFunc(ctx, bridgeName, cfg)
	}
	return &ovs.VXLANPort{
		Port: ovs.Port{
			UUID:        "mock-vxlan-port-uuid",
			Name:        "vxlan0",
			ExternalIDs: map[string]string{},
		},
		RemoteIP: cfg.RemoteIP,
		LocalIP:  cfg.LocalIP,
		Key:      cfg.Key,
		DstPort:  cfg.DstPort,
		Options:  map[string]string{},
	}, nil
}

func (m *ConfigurableMockOVSClient) AddVXLANPortWithName(ctx context.Context, bridgeName, portName string, cfg *ovs.VXLANPortConfig) (*ovs.VXLANPort, error) {
	m.recordCall("AddVXLANPortWithName", bridgeName, portName, cfg)
	if m.addVXLANPortWithNameFunc != nil {
		return m.addVXLANPortWithNameFunc(ctx, bridgeName, portName, cfg)
	}
	return &ovs.VXLANPort{
		Port: ovs.Port{
			UUID:        "mock-vxlan-port-uuid-" + portName,
			Name:        portName,
			ExternalIDs: map[string]string{},
		},
		RemoteIP: cfg.RemoteIP,
		LocalIP:  cfg.LocalIP,
		Key:      cfg.Key,
		DstPort:  cfg.DstPort,
		Options:  map[string]string{},
	}, nil
}

func (m *ConfigurableMockOVSClient) DeleteVXLANPort(ctx context.Context, bridgeName, portName string) error {
	m.recordCall("DeleteVXLANPort", bridgeName, portName)
	if m.deleteVXLANPortFunc != nil {
		return m.deleteVXLANPortFunc(ctx, bridgeName, portName)
	}
	return nil
}

func (m *ConfigurableMockOVSClient) ListVXLANPorts(ctx context.Context, bridgeName string) ([]*ovs.VXLANPort, error) {
	m.recordCall("ListVXLANPorts", bridgeName)
	if m.listVXLANPortsFunc != nil {
		return m.listVXLANPortsFunc(ctx, bridgeName)
	}
	return []*ovs.VXLANPort{}, nil
}

func (m *ConfigurableMockOVSClient) GetVXLANPort(ctx context.Context, bridgeName, portName string) (*ovs.VXLANPort, error) {
	m.recordCall("GetVXLANPort", bridgeName, portName)
	if m.getVXLANPortFunc != nil {
		return m.getVXLANPortFunc(ctx, bridgeName, portName)
	}
	return &ovs.VXLANPort{
		Port: ovs.Port{
			UUID:        "mock-vxlan-port-uuid-" + portName,
			Name:        portName,
			ExternalIDs: map[string]string{},
		},
		RemoteIP: netip.MustParseAddr("10.0.0.2"),
		LocalIP:  netip.MustParseAddr("10.0.0.1"),
		Key:      100,
		DstPort:  4789,
		Options:  map[string]string{},
	}, nil
}

func (m *ConfigurableMockOVSClient) GetVXLANPortWithOptions(ctx context.Context, bridgeName, portName string) (*ovs.VXLANPort, error) {
	m.recordCall("GetVXLANPortWithOptions", bridgeName, portName)
	if m.getVXLANPortWithOptsFunc != nil {
		return m.getVXLANPortWithOptsFunc(ctx, bridgeName, portName)
	}
	return &ovs.VXLANPort{
		Port: ovs.Port{
			UUID:        "mock-vxlan-port-uuid-" + portName,
			Name:        portName,
			ExternalIDs: map[string]string{},
		},
		RemoteIP: netip.MustParseAddr("10.0.0.2"),
		LocalIP:  netip.MustParseAddr("10.0.0.1"),
		Key:      100,
		DstPort:  4789,
		Options: map[string]string{
			"remote_ip": "10.0.0.2",
			"local_ip":  "10.0.0.1",
			"key":       "100",
			"dst_port":  "4789",
		},
	}, nil
}

func (m *ConfigurableMockOVSClient) UpdateVXLANPort(ctx context.Context, bridgeName, portName string, cfg *ovs.VXLANPortConfig) error {
	m.recordCall("UpdateVXLANPort", bridgeName, portName, cfg)
	if m.updateVXLANPortFunc != nil {
		return m.updateVXLANPortFunc(ctx, bridgeName, portName, cfg)
	}
	return nil
}

// Flow operations

func (m *ConfigurableMockOVSClient) AddFlow(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
	m.recordCall("AddFlow", bridgeName, flow)
	if m.addFlowFunc != nil {
		return m.addFlowFunc(ctx, bridgeName, flow)
	}
	return nil
}

func (m *ConfigurableMockOVSClient) AddFlows(ctx context.Context, bridgeName string, flows []*ovs.FlowMod) error {
	m.recordCall("AddFlows", bridgeName, flows)
	if m.addFlowsFunc != nil {
		return m.addFlowsFunc(ctx, bridgeName, flows)
	}
	return nil
}

func (m *ConfigurableMockOVSClient) DeleteFlow(ctx context.Context, bridgeName string, match string) error {
	m.recordCall("DeleteFlow", bridgeName, match)
	if m.deleteFlowFunc != nil {
		return m.deleteFlowFunc(ctx, bridgeName, match)
	}
	return nil
}

func (m *ConfigurableMockOVSClient) ListFlows(ctx context.Context, bridgeName string) ([]*ovs.Flow, error) {
	m.recordCall("ListFlows", bridgeName)
	if m.listFlowsFunc != nil {
		return m.listFlowsFunc(ctx, bridgeName)
	}
	return []*ovs.Flow{}, nil
}

func (m *ConfigurableMockOVSClient) DeleteFlowsByCookie(ctx context.Context, bridgeName string, cookie, cookieMask uint64) error {
	m.recordCall("DeleteFlowsByCookie", bridgeName, cookie, cookieMask)
	if m.deleteFlowsByCookieFunc != nil {
		return m.deleteFlowsByCookieFunc(ctx, bridgeName, cookie, cookieMask)
	}
	return nil
}

func (m *ConfigurableMockOVSClient) DeleteFlowStrict(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
	m.recordCall("DeleteFlowStrict", bridgeName, flow)
	return nil
}

func (m *ConfigurableMockOVSClient) SetBridgeExternalIDs(ctx context.Context, name string, ids map[string]string) error {
	m.recordCall("SetBridgeExternalIDs", name, ids)
	return nil
}

func (m *ConfigurableMockOVSClient) GetBridgeExternalIDs(ctx context.Context, name string) (map[string]string, error) {
	m.recordCall("GetBridgeExternalIDs", name)
	return map[string]string{}, nil
}

func (m *ConfigurableMockOVSClient) DeleteAllFlows(ctx context.Context, bridgeName string) error {
	m.recordCall("DeleteAllFlows", bridgeName)
	if m.deleteAllFlowsFunc != nil {
		return m.deleteAllFlowsFunc(ctx, bridgeName)
	}
	return nil
}

func (m *ConfigurableMockOVSClient) ModifyFlow(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error {
	m.recordCall("ModifyFlow", bridgeName, flow)
	if m.modifyFlowFunc != nil {
		return m.modifyFlowFunc(ctx, bridgeName, flow)
	}
	return nil
}

func (m *ConfigurableMockOVSClient) GetFlowStats(ctx context.Context, bridgeName string, match string) ([]*ovs.Flow, error) {
	m.recordCall("GetFlowStats", bridgeName, match)
	if m.getFlowStatsFunc != nil {
		return m.getFlowStatsFunc(ctx, bridgeName, match)
	}
	return []*ovs.Flow{
		{
			Cookie:      match,
			PacketCount: 1000,
			ByteCount:   100000,
			Duration:    3600,
		},
	}, nil
}

// OVSDB operations

func (m *ConfigurableMockOVSClient) ListDatabases(ctx context.Context) ([]string, error) {
	m.recordCall("ListDatabases")
	if m.listDatabasesFunc != nil {
		return m.listDatabasesFunc(ctx)
	}
	return []string{"Open_vSwitch"}, nil
}

func (m *ConfigurableMockOVSClient) GetSchema(ctx context.Context) (*ovs.GetSchemaResult, error) {
	m.recordCall("GetSchema")
	if m.getSchemaFunc != nil {
		return m.getSchemaFunc(ctx)
	}
	return &ovs.GetSchemaResult{}, nil
}

func (m *ConfigurableMockOVSClient) Echo(ctx context.Context, data []interface{}) ([]interface{}, error) {
	m.recordCall("Echo", data)
	if m.echoFunc != nil {
		return m.echoFunc(ctx, data)
	}
	return data, nil
}

func (m *ConfigurableMockOVSClient) Transact(ctx context.Context, operations ...ovs.Operation) (ovs.TransactResponse, error) {
	m.recordCall("Transact", operations)
	if m.transactFunc != nil {
		return m.transactFunc(ctx, operations...)
	}
	return ovs.TransactResponse{}, nil
}

func (m *ConfigurableMockOVSClient) Select(ctx context.Context, table string, where []ovs.Condition, columns []string) ([]map[string]interface{}, error) {
	m.recordCall("Select", table, where, columns)
	if m.selectFunc != nil {
		return m.selectFunc(ctx, table, where, columns)
	}
	return []map[string]interface{}{}, nil
}

// Setter methods for configuring mock behavior

func (m *ConfigurableMockOVSClient) OnConnect(fn func(ctx context.Context) error) *ConfigurableMockOVSClient {
	m.connectFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnDisconnect(fn func() error) *ConfigurableMockOVSClient {
	m.disconnectFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnIsConnected(fn func() bool) *ConfigurableMockOVSClient {
	m.isConnectedFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnClose(fn func() error) *ConfigurableMockOVSClient {
	m.closeFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnCreateBridge(fn func(ctx context.Context, name string) (*ovs.Bridge, error)) *ConfigurableMockOVSClient {
	m.createBridgeFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnDeleteBridge(fn func(ctx context.Context, name string) error) *ConfigurableMockOVSClient {
	m.deleteBridgeFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnGetBridge(fn func(ctx context.Context, name string) (*ovs.Bridge, error)) *ConfigurableMockOVSClient {
	m.getBridgeFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnListBridges(fn func(ctx context.Context) ([]*ovs.Bridge, error)) *ConfigurableMockOVSClient {
	m.listBridgesFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnUpdateBridge(fn func(ctx context.Context, name string, updates map[string]interface{}) error) *ConfigurableMockOVSClient {
	m.updateBridgeFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnSetBridgeFailMode(fn func(ctx context.Context, name string, failMode string) error) *ConfigurableMockOVSClient {
	m.setBridgeFailModeFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnSetBridgeProtocols(fn func(ctx context.Context, name string, protocols []string) error) *ConfigurableMockOVSClient {
	m.setBridgeProtocolsFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnAddPort(fn func(ctx context.Context, bridgeName, portName string) (*ovs.Port, error)) *ConfigurableMockOVSClient {
	m.addPortFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnDeletePort(fn func(ctx context.Context, bridgeName, portName string) error) *ConfigurableMockOVSClient {
	m.deletePortFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnGetPort(fn func(ctx context.Context, name string) (*ovs.Port, error)) *ConfigurableMockOVSClient {
	m.getPortFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnListPorts(fn func(ctx context.Context, bridgeName string) ([]*ovs.Port, error)) *ConfigurableMockOVSClient {
	m.listPortsFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnUpdatePort(fn func(ctx context.Context, name string, updates map[string]interface{}) error) *ConfigurableMockOVSClient {
	m.updatePortFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnSetPortVLAN(fn func(ctx context.Context, portName string, tag int64) error) *ConfigurableMockOVSClient {
	m.setPortVLANFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnSetPortTrunks(fn func(ctx context.Context, portName string, trunks []int64) error) *ConfigurableMockOVSClient {
	m.setPortTrunksFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnSetPortState(fn func(ctx context.Context, portName string, state ovs.PortState) error) *ConfigurableMockOVSClient {
	m.setPortStateFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnSetIngressPolicing(fn func(ctx context.Context, name string, rateBps, burstBits uint64) error) *ConfigurableMockOVSClient {
	m.setIngressPolicingFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnSetEgressShaping(fn func(ctx context.Context, name string, rateBps, burstBits uint64) error) *ConfigurableMockOVSClient {
	m.setEgressShapingFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnGetInterface(fn func(ctx context.Context, name string) (*ovs.Interface, error)) *ConfigurableMockOVSClient {
	m.getInterfaceFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnGetOFPort(fn func(ctx context.Context, portName string) (int32, error)) *ConfigurableMockOVSClient {
	m.getOFPortFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnGetInterfaceOptions(fn func(ctx context.Context, name string) (map[string]string, error)) *ConfigurableMockOVSClient {
	m.getInterfaceOptionsFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnCreateBridgeWithOptions(fn func(ctx context.Context, name string, opts *ovs.BridgeOptions) (*ovs.Bridge, error)) *ConfigurableMockOVSClient {
	m.createBridgeWithOptsFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnSetBridgeDatapath(fn func(ctx context.Context, name string, datapathType string) error) *ConfigurableMockOVSClient {
	m.setBridgeDatapathFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnSetBridgeOtherConfig(fn func(ctx context.Context, name string, config map[string]string) error) *ConfigurableMockOVSClient {
	m.setBridgeOtherConfigFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnSetInterfaceType(fn func(ctx context.Context, name, ifType string) error) *ConfigurableMockOVSClient {
	m.setInterfaceTypeFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnSetInterfaceOptions(fn func(ctx context.Context, name string, options map[string]string) error) *ConfigurableMockOVSClient {
	m.setInterfaceOptionsFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnSetInterfaceOtherConfig(fn func(ctx context.Context, name string, config map[string]string) error) *ConfigurableMockOVSClient {
	m.setIfaceOtherConfigFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnSetOVSOtherConfig(fn func(ctx context.Context, config map[string]string) error) *ConfigurableMockOVSClient {
	m.setOVSOtherConfigFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnGetOVSOtherConfig(fn func(ctx context.Context) (map[string]string, error)) *ConfigurableMockOVSClient {
	m.getOVSOtherConfigFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnDeleteOVSOtherConfig(fn func(ctx context.Context, keys []string) error) *ConfigurableMockOVSClient {
	m.deleteOVSOtherConfigFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnAddVXLANPort(fn func(ctx context.Context, bridgeName string, cfg *ovs.VXLANPortConfig) (*ovs.VXLANPort, error)) *ConfigurableMockOVSClient {
	m.addVXLANPortFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnAddVXLANPortWithName(fn func(ctx context.Context, bridgeName, portName string, cfg *ovs.VXLANPortConfig) (*ovs.VXLANPort, error)) *ConfigurableMockOVSClient {
	m.addVXLANPortWithNameFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnDeleteVXLANPort(fn func(ctx context.Context, bridgeName, portName string) error) *ConfigurableMockOVSClient {
	m.deleteVXLANPortFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnListVXLANPorts(fn func(ctx context.Context, bridgeName string) ([]*ovs.VXLANPort, error)) *ConfigurableMockOVSClient {
	m.listVXLANPortsFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnGetVXLANPort(fn func(ctx context.Context, bridgeName, portName string) (*ovs.VXLANPort, error)) *ConfigurableMockOVSClient {
	m.getVXLANPortFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnGetVXLANPortWithOptions(fn func(ctx context.Context, bridgeName, portName string) (*ovs.VXLANPort, error)) *ConfigurableMockOVSClient {
	m.getVXLANPortWithOptsFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnUpdateVXLANPort(fn func(ctx context.Context, bridgeName, portName string, cfg *ovs.VXLANPortConfig) error) *ConfigurableMockOVSClient {
	m.updateVXLANPortFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnAddFlows(fn func(ctx context.Context, bridgeName string, flows []*ovs.FlowMod) error) *ConfigurableMockOVSClient {
	m.addFlowsFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnAddFlow(fn func(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error) *ConfigurableMockOVSClient {
	m.addFlowFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnDeleteFlow(fn func(ctx context.Context, bridgeName string, match string) error) *ConfigurableMockOVSClient {
	m.deleteFlowFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnDeleteFlowsByCookie(fn func(ctx context.Context, bridgeName string, cookie, cookieMask uint64) error) *ConfigurableMockOVSClient {
	m.deleteFlowsByCookieFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnListFlows(fn func(ctx context.Context, bridgeName string) ([]*ovs.Flow, error)) *ConfigurableMockOVSClient {
	m.listFlowsFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnDeleteAllFlows(fn func(ctx context.Context, bridgeName string) error) *ConfigurableMockOVSClient {
	m.deleteAllFlowsFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnModifyFlow(fn func(ctx context.Context, bridgeName string, flow *ovs.FlowMod) error) *ConfigurableMockOVSClient {
	m.modifyFlowFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnGetFlowStats(fn func(ctx context.Context, bridgeName string, match string) ([]*ovs.Flow, error)) *ConfigurableMockOVSClient {
	m.getFlowStatsFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnListDatabases(fn func(ctx context.Context) ([]string, error)) *ConfigurableMockOVSClient {
	m.listDatabasesFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnGetSchema(fn func(ctx context.Context) (*ovs.GetSchemaResult, error)) *ConfigurableMockOVSClient {
	m.getSchemaFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnEcho(fn func(ctx context.Context, data []interface{}) ([]interface{}, error)) *ConfigurableMockOVSClient {
	m.echoFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnTransact(fn func(ctx context.Context, operations ...ovs.Operation) (ovs.TransactResponse, error)) *ConfigurableMockOVSClient {
	m.transactFunc = fn
	return m
}

func (m *ConfigurableMockOVSClient) OnSelect(fn func(ctx context.Context, table string, where []ovs.Condition, columns []string) ([]map[string]interface{}, error)) *ConfigurableMockOVSClient {
	m.selectFunc = fn
	return m
}

// Verify that ConfigurableMockOVSClient implements ovs.ClientInterface
var _ ovs.ClientInterface = (*ConfigurableMockOVSClient)(nil)
