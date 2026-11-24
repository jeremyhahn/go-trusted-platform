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
	"errors"
	"fmt"
	"hash/fnv"
	"math"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netlink"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// SDNService implements privileged SDN operations for the daemon
type SDNService struct {
	platformv1.UnimplementedSDNServiceServer

	ovsClient      ovs.ClientInterface
	netlinkManager *netlink.Manager
	zoneSvc        gateway.ZoneService
	mu             sync.RWMutex
	// policyMu is held for the whole of ApplyPolicy and DeletePolicy, from
	// the snapshot of the prior record to the record write, so a policy's
	// flows and its record change together. It is taken before mu, never
	// while holding it.
	policyMu sync.Mutex

	// Track created resources for cleanup
	bridges  map[string]*bridgeResource
	ports    map[string]*portResource
	taps     map[string]*tapResource
	vlans    map[string]*vlanResource
	policies map[string]*policyResource
}

type bridgeResource struct {
	id         string
	name       string
	bridgeType platformv1.BridgeType
	mtu        uint32
	createdAt  time.Time
}

type portResource struct {
	id        string
	name      string
	bridgeID  string
	portType  platformv1.PortType
	createdAt time.Time
}

type tapResource struct {
	name      string
	createdAt time.Time
}

type vlanResource struct {
	id        string
	vlanID    uint32
	bridgeID  string
	name      string
	ports     []string
	createdAt time.Time
}

type policyResource struct {
	id          string
	name        string
	description string
	policyType  string
	priority    int32
	enabled     bool
	status      string
	rules       []*platformv1.PolicyRule
	targets     []*platformv1.PolicyTarget
	// bridgeNames are the bridges the targets resolved to when the policy
	// was applied: its flows were installed there, so withdrawal and
	// rollback use them rather than resolving the targets again.
	bridgeNames []string
	schedule    *platformv1.PolicySchedule
	hitCount    uint64
	byteCount   uint64
	createdAt   time.Time
	updatedAt   time.Time
	// flowIDs tracks OpenFlow rules installed for this policy
	flowIDs []string
	// pendingFlows are flows that may still be on the switch beyond what
	// the record's enabled rules install: an old or attempted flow whose
	// removal failed. Withdrawal and conflict checks include them until a
	// removal is confirmed.
	pendingFlows []policyFlow
}

// SDNServiceOption is a functional option for configuring the SDNService
type SDNServiceOption func(*SDNService)

// WithOVSClient sets a custom OVS client (useful for testing with mocks)
func WithOVSClient(client ovs.ClientInterface) SDNServiceOption {
	return func(s *SDNService) {
		s.ovsClient = client
	}
}

// NewSDNService creates a new SDN service
func NewSDNService(ovsSocketPath string, opts ...SDNServiceOption) (*SDNService, error) {
	svc := &SDNService{
		netlinkManager: netlink.NewManager(),
		bridges:        make(map[string]*bridgeResource),
		ports:          make(map[string]*portResource),
		taps:           make(map[string]*tapResource),
		vlans:          make(map[string]*vlanResource),
		policies:       make(map[string]*policyResource),
	}

	// Apply options first (may set ovsClient)
	for _, opt := range opts {
		opt(svc)
	}

	// Create OVS client if not provided via options
	if svc.ovsClient == nil {
		ovsClient, err := ovs.NewClient(ovsSocketPath)
		if err != nil {
			return nil, &WrappedError{Msg: "failed to create OVS client", Err: err}
		}
		svc.ovsClient = ovsClient
	}

	return svc, nil
}

// OVSClient returns the OVS client for testing purposes
func (s *SDNService) OVSClient() ovs.ClientInterface {
	return s.ovsClient
}

// Connect establishes connection to OVS.
// Returns ErrOVSNotConfigured when no OVS client has been wired in
// (zone-only stub mode).
func (s *SDNService) Connect(ctx context.Context) error {
	s.mu.RLock()
	client := s.ovsClient
	s.mu.RUnlock()

	if client == nil {
		return ErrOVSNotConfigured{}
	}
	if err := client.Connect(ctx); err != nil {
		return &WrappedError{Msg: "failed to connect to OVS", Err: err}
	}

	return nil
}

// Disconnect closes connection to OVS.
// Returns ErrOVSNotConfigured when no OVS client has been wired in
// (zone-only stub mode).
func (s *SDNService) Disconnect() error {
	s.mu.RLock()
	client := s.ovsClient
	s.mu.RUnlock()

	if client == nil {
		return ErrOVSNotConfigured{}
	}
	return client.Disconnect()
}

// CreateBridge creates an OVS bridge (requires root)
func (s *SDNService) CreateBridge(ctx context.Context, req *platformv1.CreateBridgeRequest) (*platformv1.CreateBridgeResponse, error) {
	if req.GetConfig() == nil {
		return nil, status.Error(codes.InvalidArgument, "config is required")
	}

	config := req.GetConfig()
	if config.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "bridge name is required")
	}

	// Check if bridge already exists under read lock
	s.mu.RLock()
	_, exists := s.bridges[config.GetName()]
	s.mu.RUnlock()

	if exists {
		return nil, status.Error(codes.AlreadyExists, "bridge already exists")
	}

	client := s.getOVSClient()

	// Create the bridge with its fail mode in one OVS transaction, without
	// holding the lock: setting the fail mode afterwards costs a second
	// ovs-vswitchd reconfiguration and leaves a "secure" bridge running as a
	// standalone learning switch in between.
	opts := &ovs.BridgeOptions{FailMode: config.GetOptions()["fail_mode"]}
	ovsBridge, err := client.CreateBridgeWithOptions(ctx, config.GetName(), opts)
	if err != nil {
		var invalidFailMode *ovs.ErrInvalidFailMode
		if errors.As(err, &invalidFailMode) {
			return nil, status.Error(codes.InvalidArgument, err.Error())
		}
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to create bridge: %v", err))
	}

	// Track the bridge under write lock
	s.mu.Lock()
	s.bridges[config.GetName()] = &bridgeResource{
		id:         ovsBridge.UUID,
		name:       config.GetName(),
		bridgeType: config.GetType(),
		createdAt:  time.Now(),
		mtu:        config.GetMtu(),
	}
	s.mu.Unlock()

	// Convert OVS bridge to proto bridge
	bridge := s.ovsBridgeToPb(ovsBridge)

	return &platformv1.CreateBridgeResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "bridge created successfully",
		},
		Bridge: bridge,
	}, nil
}

// DeleteBridge deletes an OVS bridge (requires root)
func (s *SDNService) DeleteBridge(ctx context.Context, req *platformv1.DeleteBridgeRequest) (*platformv1.DeleteBridgeResponse, error) {
	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "bridge id or name is required")
	}

	bridgeName, found := s.findBridgeName(req.GetId())
	if !found {
		return nil, status.Error(codes.NotFound, "bridge not found")
	}

	client := s.getOVSClient()

	// Delete the bridge via OVS without holding the lock
	if err := client.DeleteBridge(ctx, bridgeName); err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to delete bridge: %v", err))
	}

	// Remove from tracking under write lock
	s.mu.Lock()
	delete(s.bridges, bridgeName)
	s.mu.Unlock()

	return &platformv1.DeleteBridgeResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "bridge deleted successfully",
		},
	}, nil
}

// GetBridge retrieves bridge information
func (s *SDNService) GetBridge(ctx context.Context, req *platformv1.GetBridgeRequest) (*platformv1.GetBridgeResponse, error) {
	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, "bridge id or name is required")
	}

	bridgeName, found := s.findBridgeName(req.GetId())
	if !found {
		return nil, status.Error(codes.NotFound, "bridge not found")
	}

	client := s.getOVSClient()

	// Get bridge from OVS without holding the lock
	ovsBridge, err := client.GetBridge(ctx, bridgeName)
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to get bridge: %v", err))
	}

	return &platformv1.GetBridgeResponse{
		Bridge: s.ovsBridgeToPb(ovsBridge),
	}, nil
}

// ListBridges lists all bridges
func (s *SDNService) ListBridges(ctx context.Context, req *platformv1.ListBridgesRequest) (*platformv1.ListBridgesResponse, error) {
	client := s.getOVSClient()

	// List bridges from OVS without holding the lock
	ovsBridges, err := client.ListBridges(ctx)
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to list bridges: %v", err))
	}

	bridges := make([]*platformv1.Bridge, 0, len(ovsBridges))
	for _, ovsBridge := range ovsBridges {
		bridges = append(bridges, s.ovsBridgeToPb(ovsBridge))
	}

	return &platformv1.ListBridgesResponse{
		Bridges: bridges,
	}, nil
}

// portInterfaceTypes maps a requested port type to the Open vSwitch Interface
// type that implements it. Every other type is "" (system): an existing kernel
// device of the port's name, which for PORT_TYPE_TAP AddPort creates first.
var portInterfaceTypes = map[platformv1.PortType]string{
	platformv1.PortType_PORT_TYPE_INTERNAL: "internal",
	platformv1.PortType_PORT_TYPE_VXLAN:    "vxlan",
	platformv1.PortType_PORT_TYPE_GRE:      "gre",
}

// AddPort adds a port to a bridge (requires root)
func (s *SDNService) AddPort(ctx context.Context, req *platformv1.AddPortRequest) (*platformv1.AddPortResponse, error) {
	if req.GetBridgeId() == "" {
		return nil, status.Error(codes.InvalidArgument, "bridge_id is required")
	}
	if req.GetConfig() == nil {
		return nil, status.Error(codes.InvalidArgument, "config is required")
	}

	config := req.GetConfig()
	if config.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "port name is required")
	}

	bridgeName, found := s.findBridgeName(req.GetBridgeId())
	if !found {
		return nil, status.Error(codes.NotFound, "bridge not found")
	}

	client := s.getOVSClient()

	// Create TAP device if port type is TAP (netlink ops are independent of OVS lock)
	if config.GetType() == platformv1.PortType_PORT_TYPE_TAP {
		tapConfig := &netlink.TAPConfig{
			Name:       config.GetName(),
			Owner:      0, // root
			Group:      0, // root
			MultiQueue: false,
			Persist:    true,
			MTU:        int(config.GetMtu()),
		}
		if err := s.netlinkManager.CreateTAP(tapConfig); err != nil {
			return nil, status.Error(codes.Internal, fmt.Sprintf("failed to create TAP device: %v", err))
		}

		// Track TAP device under write lock
		s.mu.Lock()
		s.taps[config.GetName()] = &tapResource{
			name:      config.GetName(),
			createdAt: time.Now(),
		}
		s.mu.Unlock()

		// Bring TAP up
		// Non-fatal: best-effort TAP interface activation
		_ = s.netlinkManager.SetTAPUp(config.GetName())
	}

	// Add port to bridge via OVS without holding the lock, its interface
	// typed in the same transaction
	ovsPort, err := client.AddPortWithType(ctx, bridgeName, config.GetName(), portInterfaceTypes[config.GetType()])
	if err != nil {
		// Clean up TAP if we created it
		if config.GetType() == platformv1.PortType_PORT_TYPE_TAP {
			_ = s.netlinkManager.DeleteTAP(config.GetName())
			s.mu.Lock()
			delete(s.taps, config.GetName())
			s.mu.Unlock()
		}
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to add port: %v", err))
	}

	// Set VLAN if specified (best-effort, no lock needed for OVS call)
	if config.GetVlan() > 0 {
		_ = client.SetPortVLAN(ctx, config.GetName(), int64(config.GetVlan()))
	}

	// Track the port under write lock
	s.mu.Lock()
	s.ports[config.GetName()] = &portResource{
		id:        ovsPort.UUID,
		name:      config.GetName(),
		bridgeID:  req.GetBridgeId(),
		portType:  config.GetType(),
		createdAt: time.Now(),
	}
	s.mu.Unlock()

	portStatus, err := s.portStatus(ctx, client, ovsPort.Name)
	if err != nil {
		return nil, err
	}
	port := s.ovsPortToPb(ovsPort, req.GetBridgeId(), portStatus)

	return &platformv1.AddPortResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "port added successfully",
		},
		Port: port,
	}, nil
}

// DeletePort removes a port from a bridge (requires root)
func (s *SDNService) DeletePort(ctx context.Context, req *platformv1.DeletePortRequest) (*platformv1.DeletePortResponse, error) {
	if req.GetBridgeId() == "" {
		return nil, status.Error(codes.InvalidArgument, "bridge_id is required")
	}
	if req.GetPortId() == "" {
		return nil, status.Error(codes.InvalidArgument, "port_id is required")
	}

	bridgeName, found := s.findBridgeName(req.GetBridgeId())
	if !found {
		return nil, status.Error(codes.NotFound, "bridge not found")
	}

	portName, portType, portFound := s.findPortName(req.GetPortId())
	if !portFound {
		return nil, status.Error(codes.NotFound, "port not found")
	}

	client := s.getOVSClient()

	// Delete port from bridge via OVS without holding the lock
	if err := client.DeletePort(ctx, bridgeName, portName); err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to delete port: %v", err))
	}

	// Delete TAP device if it was a TAP port (netlink ops are independent)
	if portType == platformv1.PortType_PORT_TYPE_TAP {
		_ = s.netlinkManager.DeleteTAP(portName)
	}

	// Remove from tracking under write lock
	s.mu.Lock()
	if portType == platformv1.PortType_PORT_TYPE_TAP {
		delete(s.taps, portName)
	}
	delete(s.ports, portName)
	s.mu.Unlock()

	return &platformv1.DeletePortResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "port deleted successfully",
		},
	}, nil
}

// GetPort retrieves port information
func (s *SDNService) GetPort(ctx context.Context, req *platformv1.GetPortRequest) (*platformv1.GetPortResponse, error) {
	if req.GetBridgeId() == "" {
		return nil, status.Error(codes.InvalidArgument, "bridge_id is required")
	}
	if req.GetPortId() == "" {
		return nil, status.Error(codes.InvalidArgument, "port_id is required")
	}

	portName, _, found := s.findPortName(req.GetPortId())
	if !found {
		return nil, status.Error(codes.NotFound, "port not found")
	}

	client := s.getOVSClient()

	// Get port from OVS without holding the lock
	ovsPort, err := client.GetPort(ctx, portName)
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to get port: %v", err))
	}

	portStatus, err := s.portStatus(ctx, client, ovsPort.Name)
	if err != nil {
		return nil, err
	}

	return &platformv1.GetPortResponse{
		Port: s.ovsPortToPb(ovsPort, req.GetBridgeId(), portStatus),
	}, nil
}

// ListPorts lists ports on a bridge
func (s *SDNService) ListPorts(ctx context.Context, req *platformv1.ListPortsRequest) (*platformv1.ListPortsResponse, error) {
	if req.GetBridgeId() == "" {
		return nil, status.Error(codes.InvalidArgument, "bridge_id is required")
	}

	bridgeName, found := s.findBridgeName(req.GetBridgeId())
	if !found {
		return nil, status.Error(codes.NotFound, "bridge not found")
	}

	client := s.getOVSClient()

	// List ports from OVS without holding the lock
	ovsPorts, err := client.ListPorts(ctx, bridgeName)
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to list ports: %v", err))
	}

	ports := make([]*platformv1.Port, 0, len(ovsPorts))
	for _, ovsPort := range ovsPorts {
		portStatus, err := s.portStatus(ctx, client, ovsPort.Name)
		if err != nil {
			return nil, err
		}
		ports = append(ports, s.ovsPortToPb(ovsPort, req.GetBridgeId(), portStatus))
	}

	return &platformv1.ListPortsResponse{
		Ports: ports,
	}, nil
}

// AddFlow adds an OpenFlow rule (requires root for OVS control)
func (s *SDNService) AddFlow(ctx context.Context, req *platformv1.AddFlowRequest) (*platformv1.AddFlowResponse, error) {
	if req.GetConfig() == nil {
		return nil, status.Error(codes.InvalidArgument, "config is required")
	}

	config := req.GetConfig()
	if config.GetBridgeId() == "" {
		return nil, status.Error(codes.InvalidArgument, "bridge_id is required")
	}

	bridgeName, found := s.findBridgeName(config.GetBridgeId())
	if !found {
		return nil, status.Error(codes.NotFound, "bridge not found")
	}

	client := s.getOVSClient()

	// Convert proto flow config to OVS flow mod. The flow's cookie is its
	// identity: the ID returned below is the cookie, so DeleteFlow removes
	// exactly this flow and ListFlows reports the same ID.
	flowMod, err := s.pbToOvsFlowMod(config)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	cookie, err := ovs.NewAPIFlowCookie()
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to allocate a flow cookie: %v", err))
	}
	flowMod.Cookie = fmt.Sprintf("0x%x", cookie)

	// Add flow via OVS without holding the lock
	if err := client.AddFlow(ctx, bridgeName, flowMod); err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to add flow: %v", err))
	}

	flow := &platformv1.Flow{
		Id:        ovs.FlowID(cookie),
		Config:    config,
		CreatedAt: timestamppb.New(time.Now()),
	}

	return &platformv1.AddFlowResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "flow added successfully",
		},
		Flow: flow,
	}, nil
}

// DeleteFlow deletes an OpenFlow rule (requires root)
func (s *SDNService) DeleteFlow(ctx context.Context, req *platformv1.DeleteFlowRequest) (*platformv1.DeleteFlowResponse, error) {
	if req.GetBridgeId() == "" {
		return nil, status.Error(codes.InvalidArgument, "bridge_id is required")
	}
	if req.GetFlowId() == "" {
		return nil, status.Error(codes.InvalidArgument, "flow_id is required")
	}

	bridgeName, found := s.findBridgeName(req.GetBridgeId())
	if !found {
		return nil, status.Error(codes.NotFound, "bridge not found")
	}

	// The ID is the flow's cookie (AddFlow, ListFlows). It used to be
	// handed to OVS as a match string, which the encoder skipped term by
	// term until the match was empty, and an empty-match delete across
	// every table removed every flow on the bridge (#614).
	cookie, err := ovs.ParseFlowID(req.GetFlowId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	client := s.getOVSClient()

	// Delete flow via OVS without holding the lock
	if err := client.DeleteFlowsByCookie(ctx, bridgeName, cookie, ^uint64(0)); err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to delete flow: %v", err))
	}

	return &platformv1.DeleteFlowResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "flow deleted successfully",
		},
	}, nil
}

// ListFlows lists flows on a bridge
func (s *SDNService) ListFlows(ctx context.Context, req *platformv1.ListFlowsRequest) (*platformv1.ListFlowsResponse, error) {
	if req.GetBridgeId() == "" {
		return nil, status.Error(codes.InvalidArgument, "bridge_id is required")
	}

	bridgeName, found := s.findBridgeName(req.GetBridgeId())
	if !found {
		return nil, status.Error(codes.NotFound, "bridge not found")
	}

	client := s.getOVSClient()

	// List flows from OVS without holding the lock
	ovsFlows, err := client.ListFlows(ctx, bridgeName)
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to list flows: %v", err))
	}

	flows := make([]*platformv1.Flow, 0, len(ovsFlows))
	for _, ovsFlow := range ovsFlows {
		flows = append(flows, s.ovsFlowToPb(ovsFlow, req.GetBridgeId()))
	}

	return &platformv1.ListFlowsResponse{
		Flows: flows,
	}, nil
}

// FlushFlows removes all flows from a table
func (s *SDNService) FlushFlows(ctx context.Context, req *platformv1.FlushFlowsRequest) (*platformv1.FlushFlowsResponse, error) {
	if req.GetBridgeId() == "" {
		return nil, status.Error(codes.InvalidArgument, "bridge_id is required")
	}

	bridgeName, found := s.findBridgeName(req.GetBridgeId())
	if !found {
		return nil, status.Error(codes.NotFound, "bridge not found")
	}

	client := s.getOVSClient()

	// Get current flow count before deletion (without holding the lock)
	flows, err := client.ListFlows(ctx, bridgeName)
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to list flows: %v", err))
	}
	deletedCount := uint32(len(flows))

	// Delete all flows via OVS
	if err := client.DeleteAllFlows(ctx, bridgeName); err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to flush flows: %v", err))
	}

	return &platformv1.FlushFlowsResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "flows flushed successfully",
		},
		DeletedCount: deletedCount,
	}, nil
}

// CreateVLAN creates a VLAN configuration
func (s *SDNService) CreateVLAN(ctx context.Context, req *platformv1.CreateVLANRequest) (*platformv1.CreateVLANResponse, error) {
	if req.GetConfig() == nil {
		return nil, status.Error(codes.InvalidArgument, "config is required")
	}

	config := req.GetConfig()
	if config.GetBridgeId() == "" {
		return nil, status.Error(codes.InvalidArgument, "bridge_id is required")
	}
	if config.GetVlanId() == 0 || config.GetVlanId() > 4095 {
		return nil, status.Error(codes.InvalidArgument, "vlan_id must be between 1 and 4095")
	}

	bridgeName, found := s.findBridgeName(config.GetBridgeId())
	if !found {
		return nil, status.Error(codes.NotFound, "bridge not found")
	}

	// Check if VLAN already exists under read lock
	vlanKey := fmt.Sprintf("%s:%d", bridgeName, config.GetVlanId())
	s.mu.RLock()
	_, exists := s.vlans[vlanKey]
	s.mu.RUnlock()

	if exists {
		return nil, status.Error(codes.AlreadyExists, "VLAN already exists on this bridge")
	}

	client := s.getOVSClient()

	// Configure VLAN on the specified ports without holding the lock
	for _, portName := range config.GetPorts() {
		if err := client.SetPortVLAN(ctx, portName, int64(config.GetVlanId())); err != nil {
			return nil, status.Error(codes.Internal, fmt.Sprintf("failed to set VLAN on port %s: %v", portName, err))
		}
	}

	// Track the VLAN under write lock
	vlanID := fmt.Sprintf("vlan-%s-%d", bridgeName, config.GetVlanId())
	s.mu.Lock()
	s.vlans[vlanKey] = &vlanResource{
		id:        vlanID,
		vlanID:    config.GetVlanId(),
		bridgeID:  config.GetBridgeId(),
		name:      config.GetName(),
		ports:     config.GetPorts(),
		createdAt: time.Now(),
	}
	s.mu.Unlock()

	vlan := &platformv1.VLAN{
		Id:     vlanID,
		Config: config,
		Stats: &platformv1.VLANStats{
			PortCount: uint32(len(config.GetPorts())),
		},
		CreatedAt: timestamppb.New(time.Now()),
	}

	return &platformv1.CreateVLANResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "VLAN created successfully",
		},
		Vlan: vlan,
	}, nil
}

// SeedVLAN registers a single VLAN entry on the supplied bridge in the
// in-memory map WITHOUT applying any OVS port tags. Use this for
// reconciling configured (declarative) VLAN definitions at startup so
// the ListVLANs surface reflects what the operator intended, without
// pre-binding ports. Idempotent: a second seed for the same
// (bridgeName, vlanID) pair is a no-op and returns the existing entry.
//
// Ports are wired separately, either by the operator via CreateVLAN
// against a real port list or by a controller that watches for newly
// attached ports and applies the right tag.
func (s *SDNService) SeedVLAN(bridgeName, bridgeID string, vlanID uint32, name string) (*platformv1.VLAN, error) {
	if bridgeName == "" {
		return nil, &MessageError{Msg: "bridgeName is required"}
	}
	if vlanID == 0 || vlanID > 4095 {
		return nil, &MessageError{Msg: fmt.Sprintf("vlanID must be 1..4095, got %d", vlanID)}
	}

	vlanKey := fmt.Sprintf("%s:%d", bridgeName, vlanID)
	s.mu.Lock()
	defer s.mu.Unlock()
	if existing, ok := s.vlans[vlanKey]; ok {
		return seedVLANToProto(existing, bridgeID), nil
	}

	res := &vlanResource{
		id:        fmt.Sprintf("vlan-%s-%d", bridgeName, vlanID),
		vlanID:    vlanID,
		bridgeID:  bridgeID,
		name:      name,
		ports:     nil,
		createdAt: time.Now(),
	}
	s.vlans[vlanKey] = res
	return seedVLANToProto(res, bridgeID), nil
}

func seedVLANToProto(r *vlanResource, bridgeID string) *platformv1.VLAN {
	return &platformv1.VLAN{
		Id: r.id,
		Config: &platformv1.VLANConfig{
			BridgeId: bridgeID,
			VlanId:   r.vlanID,
			Name:     r.name,
		},
		Stats: &platformv1.VLANStats{
			PortCount: uint32(len(r.ports)),
		},
		CreatedAt: timestamppb.New(r.createdAt),
	}
}

// DeleteVLAN deletes a VLAN configuration
func (s *SDNService) DeleteVLAN(ctx context.Context, req *platformv1.DeleteVLANRequest) (*platformv1.DeleteVLANResponse, error) {
	if req.GetBridgeId() == "" {
		return nil, status.Error(codes.InvalidArgument, "bridge_id is required")
	}
	if req.GetVlanId() == 0 || req.GetVlanId() > 4095 {
		return nil, status.Error(codes.InvalidArgument, "vlan_id must be between 1 and 4095")
	}

	bridgeName, found := s.findBridgeName(req.GetBridgeId())
	if !found {
		return nil, status.Error(codes.NotFound, "bridge not found")
	}

	// Check if VLAN exists and snapshot the port list under read lock
	vlanKey := fmt.Sprintf("%s:%d", bridgeName, req.GetVlanId())
	s.mu.RLock()
	vlanRes, exists := s.vlans[vlanKey]
	var ports []string
	if exists {
		ports = make([]string, len(vlanRes.ports))
		copy(ports, vlanRes.ports)
	}
	s.mu.RUnlock()

	if !exists {
		return nil, status.Error(codes.NotFound, "VLAN not found")
	}

	client := s.getOVSClient()

	// Remove VLAN from all ports without holding the lock
	for _, portName := range ports {
		if err := client.SetPortVLAN(ctx, portName, 0); err != nil {
			continue // port may no longer exist
		}
	}

	// Remove from tracking under write lock
	s.mu.Lock()
	delete(s.vlans, vlanKey)
	s.mu.Unlock()

	return &platformv1.DeleteVLANResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "VLAN deleted successfully",
		},
	}, nil
}

// ListVLANs lists VLAN configurations
func (s *SDNService) ListVLANs(ctx context.Context, req *platformv1.ListVLANsRequest) (*platformv1.ListVLANsResponse, error) {
	if req.GetBridgeId() == "" {
		return nil, status.Error(codes.InvalidArgument, "bridge_id is required")
	}

	bridgeName, found := s.findBridgeName(req.GetBridgeId())
	if !found {
		return nil, status.Error(codes.NotFound, "bridge not found")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	// Collect all VLANs for this bridge
	vlans := make([]*platformv1.VLAN, 0)
	for key, vlanRes := range s.vlans {
		// Check if this VLAN belongs to the requested bridge
		if strings.HasPrefix(key, bridgeName+":") {
			vlan := &platformv1.VLAN{
				Id: vlanRes.id,
				Config: &platformv1.VLANConfig{
					VlanId:   vlanRes.vlanID,
					Name:     vlanRes.name,
					BridgeId: vlanRes.bridgeID,
					Ports:    vlanRes.ports,
				},
				Stats: &platformv1.VLANStats{
					PortCount: uint32(len(vlanRes.ports)),
				},
				CreatedAt: timestamppb.New(vlanRes.createdAt),
			}
			vlans = append(vlans, vlan)
		}
	}

	return &platformv1.ListVLANsResponse{
		Vlans: vlans,
	}, nil
}

// AuthenticatePort refuses with policy.ErrPortAuthNotEnforced
// (FailedPrecondition): the switch does not enforce port authentication, so
// no certificate is checked and nothing is recorded (#304).
func (s *SDNService) AuthenticatePort(_ context.Context, _ *platformv1.AuthenticatePortRequest) (*platformv1.AuthenticatePortResponse, error) {
	return nil, policy.ErrPortAuthNotEnforced{Operation: "AuthenticatePort"}
}

// RevokePortAuth refuses with policy.ErrPortAuthNotEnforced
// (FailedPrecondition), for the same reason as AuthenticatePort.
func (s *SDNService) RevokePortAuth(_ context.Context, _ *platformv1.RevokePortAuthRequest) (*platformv1.RevokePortAuthResponse, error) {
	return nil, policy.ErrPortAuthNotEnforced{Operation: "RevokePortAuth"}
}

// GetPortStats retrieves port statistics
func (s *SDNService) GetPortStats(ctx context.Context, req *platformv1.GetPortStatsRequest) (*platformv1.GetPortStatsResponse, error) {
	if req.GetBridgeId() == "" {
		return nil, status.Error(codes.InvalidArgument, "bridge_id is required")
	}
	if req.GetPortId() == "" {
		return nil, status.Error(codes.InvalidArgument, "port_id is required")
	}

	portName, _, found := s.findPortName(req.GetPortId())
	if !found {
		return nil, status.Error(codes.NotFound, "port not found")
	}

	client := s.getOVSClient()

	// Get interface statistics from OVS without holding the lock
	iface, err := client.GetInterface(ctx, portName)
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to get interface: %v", err))
	}

	stats := &platformv1.PortStats{
		PacketsReceived: uint64(iface.Statistics["rx_packets"]),
		PacketsSent:     uint64(iface.Statistics["tx_packets"]),
		BytesReceived:   uint64(iface.Statistics["rx_bytes"]),
		BytesSent:       uint64(iface.Statistics["tx_bytes"]),
		Errors:          uint64(iface.Statistics["rx_errors"] + iface.Statistics["tx_errors"]),
		Dropped:         uint64(iface.Statistics["rx_dropped"] + iface.Statistics["tx_dropped"]),
	}

	return &platformv1.GetPortStatsResponse{
		Stats: stats,
	}, nil
}

// GetFlowStats retrieves flow statistics
func (s *SDNService) GetFlowStats(ctx context.Context, req *platformv1.GetFlowStatsRequest) (*platformv1.GetFlowStatsResponse, error) {
	if req.GetBridgeId() == "" {
		return nil, status.Error(codes.InvalidArgument, "bridge_id is required")
	}
	if req.GetFlowId() == "" {
		return nil, status.Error(codes.InvalidArgument, "flow_id is required")
	}

	bridgeName, found := s.findBridgeName(req.GetBridgeId())
	if !found {
		return nil, status.Error(codes.NotFound, "bridge not found")
	}

	// The ID is the flow's cookie; the stats request is scoped to exactly
	// that cookie. Handed to OVS as a match, the ID used to be emptied by
	// the encoder and the "stats" were the bridge's first flow's (#614).
	cookie, err := ovs.ParseFlowID(req.GetFlowId())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	client := s.getOVSClient()

	// Get flow statistics from OVS without holding the lock
	flows, err := client.GetFlowStats(ctx, bridgeName, fmt.Sprintf("cookie=0x%x/0x%x", cookie, ^uint64(0)))
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to get flow stats: %v", err))
	}

	if len(flows) == 0 {
		return nil, status.Error(codes.NotFound, "flow not found")
	}

	// Return stats from the first matching flow
	flow := flows[0]
	stats := &platformv1.FlowStats{
		PacketCount:     uint64(flow.PacketCount),
		ByteCount:       uint64(flow.ByteCount),
		DurationSeconds: uint32(flow.Duration),
	}

	return &platformv1.GetFlowStatsResponse{
		Stats: stats,
	}, nil
}

// StreamFlowLogs streams flow log entries
func (s *SDNService) StreamFlowLogs(req *platformv1.StreamFlowLogsRequest, stream platformv1.SDNService_StreamFlowLogsServer) error {
	if req.GetBridgeId() == "" {
		return status.Error(codes.InvalidArgument, "bridge_id is required")
	}

	s.mu.RLock()
	// Find bridge name from ID
	var bridgeName string
	for name, res := range s.bridges {
		if res.id == req.GetBridgeId() || name == req.GetBridgeId() {
			bridgeName = name
			break
		}
	}
	s.mu.RUnlock()

	if bridgeName == "" {
		return status.Error(codes.NotFound, "bridge not found")
	}

	client := s.getOVSClient()
	ctx := stream.Context()

	// Poll for flow updates periodically
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			// Get current flows
			flows, err := client.ListFlows(ctx, bridgeName)
			if err != nil {
				continue
			}

			// Send flow log entries for each flow
			for _, flow := range flows {
				entry := &platformv1.FlowLogEntry{
					Timestamp: timestamppb.New(time.Now()),
					BridgeId:  req.GetBridgeId(),
					FlowId:    flow.Cookie,
					Action:    flow.Actions,
					Bytes:     uint64(flow.ByteCount),
				}

				if err := stream.Send(entry); err != nil {
					return err
				}
			}
		}
	}
}

// SetPortState sets the administrative state of a port
func (s *SDNService) SetPortState(ctx context.Context, req *platformv1.SetPortStateRequest) (*platformv1.SetPortStateResponse, error) {
	if req.GetBridgeId() == "" {
		return nil, status.Error(codes.InvalidArgument, "bridge_id is required")
	}
	if req.GetPortId() == "" {
		return nil, status.Error(codes.InvalidArgument, "port_id is required")
	}
	if req.GetAdminState() == "" {
		return nil, status.Error(codes.InvalidArgument, "admin_state is required")
	}
	if err := ovs.ValidateIngressPolicing(req.GetIngressRate(), req.GetIngressBurst()); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := ovs.ValidateEgressShaping(req.GetEgressRate(), req.GetEgressBurst()); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	portName, _, found := s.findPortName(req.GetPortId())
	if !found {
		return nil, status.Error(codes.NotFound, "port not found")
	}

	// Map admin_state string to OVS PortState
	var portState ovs.PortState
	switch strings.ToLower(req.GetAdminState()) {
	case "up":
		portState = ovs.PortStateUp
	case "down":
		portState = ovs.PortStateDown
	default:
		return nil, status.Error(codes.InvalidArgument, "admin_state must be 'up' or 'down'")
	}

	client := s.getOVSClient()

	// Set port state via OVS without holding the lock
	if err := client.SetPortState(ctx, portName, portState); err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to set port state: %v", err))
	}

	// A zero ingress rate leaves the port's policing as it is.
	if req.GetIngressRate() > 0 {
		err := client.SetIngressPolicing(ctx, portName, req.GetIngressRate(), req.GetIngressBurst())
		if errors.Is(err, ovs.ErrInterfaceNotFound) {
			return nil, status.Error(codes.NotFound, "port interface not found")
		}
		if err != nil {
			return nil, status.Error(codes.Internal, fmt.Sprintf("failed to set ingress policing: %v", err))
		}
	}

	// A zero egress rate leaves the port's shaping as it is.
	if req.GetEgressRate() > 0 {
		err := client.SetEgressShaping(ctx, portName, req.GetEgressRate(), req.GetEgressBurst())
		if errors.Is(err, ovs.ErrPortNotFound) {
			return nil, status.Error(codes.NotFound, "port not found")
		}
		if err != nil {
			return nil, status.Error(codes.Internal, fmt.Sprintf("failed to set egress shaping: %v", err))
		}
	}

	// Retrieve updated port information
	ovsPort, err := client.GetPort(ctx, portName)
	if err != nil {
		return nil, status.Error(codes.Internal, fmt.Sprintf("failed to get updated port: %v", err))
	}

	// The port reports the state the transaction above committed.
	portStatus := platformv1.PortStatus_PORT_STATUS_DOWN
	if portState == ovs.PortStateUp {
		portStatus = platformv1.PortStatus_PORT_STATUS_UP
	}
	port := s.ovsPortToPb(ovsPort, req.GetBridgeId(), portStatus)

	return &platformv1.SetPortStateResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "port state updated successfully",
		},
		Port: port,
	}, nil
}

// ApplyPolicy applies a network policy by translating it into OpenFlow rules
// on its bridge targets. Every effective priority (the rule's, else the
// policy's) must fit OpenFlow's 16 bits, or the call is InvalidArgument
// before anything changes. Every flow of an enabled policy must encode (its
// cookie, match and actions convert to an OpenFlow flow mod), or the call
// is InvalidArgument with the record and switch untouched. An enabled
// policy whose flow install fails
// returns Internal: every flow this call attempted, the failing one
// included, is removed and the prior enabled record's rules re-added
// (OFPFC_ADD replaces a same-match flow; every one is attempted), and the prior record stays in
// place, marked "error" only if that rollback failed; a new policy whose
// rollback failed is stored "error". Either way the attempted flows whose
// removal failed join the record's pending flows.
// A record's pending flows are those that may still be on the switch
// beyond what its enabled rules install (old or attempted flows whose
// removal failed); every withdrawal and conflict check includes them, and
// they are dropped only once their removal is confirmed.
// An enabled reapply that succeeds removes the prior record's enabled and
// pending flows the new set does not replace (another bridge, priority or
// match); if that fails the new record is stored "error" with the flows not
// removed pending, and the call returns Internal.
// Reapplying with enabled=false removes the prior record's enabled and
// pending flows and stores the policy "inactive"; if the removal fails the
// call returns Internal and the prior record stays, marked "error" with the
// flows not removed pending. Withdrawal and rollback use the bridges the
// prior record's flows were installed on.
// A target bridge that does not exist is NotFound; a bridge lookup that
// fails is Unavailable. An enabled policy whose flow (bridge, table,
// priority, match) another policy already installs or has pending is refused
// FailedPrecondition, so withdrawing one never deletes the other's flow;
// the key compares the table and priority as encoded on the wire.
// Every policy flow carries the policy's cookie (policyFlowCookie) and every
// strict delete of a rollback or withdrawal is restricted to it, so only the
// policy's own entries are removed. Before any write the installed flows of
// each target entry are read: an entry held by a flow with another cookie
// (one SDNService.AddFlow installed, say) is refused FailedPrecondition, and
// a read that fails is Unavailable. The rollback's restore of the prior
// record's rules attempts every prior flow and joins the errors.
// The whole call runs under policyMu.
func (s *SDNService) ApplyPolicy(ctx context.Context, req *platformv1.ApplyPolicyRequest) (*platformv1.ApplyPolicyResponse, error) {
	if req.GetConfig() == nil {
		return nil, status.Error(codes.InvalidArgument, "config is required")
	}

	config := req.GetConfig()
	if config.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "policy name is required")
	}

	// Determine policy ID
	policyID := req.GetPolicyId()
	if policyID == "" {
		// Random, not a timestamp: two policies applied within the clock's
		// resolution would otherwise share an ID (#284).
		policyID = "policy-" + uuid.NewString()
	}

	// OpenFlow priorities are 16-bit: refuse an effective priority (the
	// rule's, else the policy's) the wire encoding would truncate, before
	// any lock or switch change (#2234).
	for _, rule := range config.GetRules() {
		priority := rule.GetPriority()
		if priority == 0 {
			priority = config.GetPriority()
		}
		if priority < 0 || priority > math.MaxUint16 {
			return nil, status.Errorf(codes.InvalidArgument,
				"rule %q priority %d is outside the OpenFlow range 0..%d", rule.GetRuleId(), priority, math.MaxUint16)
		}
	}

	// Serialize the whole transaction: snapshot, OVS changes and record
	// write, so a concurrent disable and reapply cannot interleave (#2234).
	s.policyMu.Lock()
	defer s.policyMu.Unlock()

	// Check for duplicate policy name and snapshot the prior record and the
	// other enabled policies under read lock: a reapply that fails must
	// restore what it replaced, and no flow may replace another policy's.
	s.mu.RLock()
	var prior *policyResource
	if p, ok := s.policies[policyID]; ok {
		snapshot := *p
		prior = &snapshot
	}
	var others []policyResource
	for id, p := range s.policies {
		if p.name == config.GetName() && id != policyID {
			s.mu.RUnlock()
			return nil, status.Error(codes.AlreadyExists, "policy with this name already exists")
		}
		if id != policyID && (p.enabled || len(p.pendingFlows) > 0) {
			others = append(others, *p)
		}
	}
	s.mu.RUnlock()

	// Convert PolicyType enum to string for internal tracking
	policyType := strings.ToLower(strings.TrimPrefix(config.GetType().String(), "POLICY_TYPE_"))

	client := s.getOVSClient()

	// Validate every target before any flow is installed: a non-bridge
	// target or an unresolved bridge fails the whole call (#2234).
	bridgeNames := make([]string, 0, len(config.GetTargets()))
	for _, target := range config.GetTargets() {
		if target.GetType() != platformv1.PolicyTargetType_POLICY_TARGET_TYPE_BRIDGE {
			return nil, status.Errorf(codes.InvalidArgument, "policy target %q is not a bridge", target.GetId())
		}
		bridgeName, found, err := s.lookupBridgeName(ctx, target.GetId())
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "look up bridge %q: %v", target.GetId(), err)
		}
		if !found {
			return nil, status.Errorf(codes.NotFound, "bridge %q not found", target.GetId())
		}
		bridgeNames = append(bridgeNames, bridgeName)
	}

	// Install or withdraw OpenFlow rules without holding the lock.
	var flowIDs []string
	policyStatus := "inactive"
	if config.GetEnabled() {
		policyStatus = "active"
		flows, err := s.policyFlows(policyID, bridgeNames, config.GetRules(), config.GetPriority())
		if err != nil {
			// A rule whose match cannot carry its OpenFlow prerequisites
			// is refused before the conflict check and before any install.
			return nil, status.Errorf(codes.InvalidArgument, "%v", err)
		}
		if owner, flow, ok := s.conflictingPolicyFlow(flows, others); ok {
			return nil, status.Errorf(codes.FailedPrecondition,
				"policy %q already installs a flow on bridge %s with priority %d and match %q",
				owner, flow.bridge, flow.mod.Priority, flow.mod.Match)
		}
		// A flow that does not encode fails locally, in AddFlow and in the
		// strict delete of a rollback alike: refuse it before anything is
		// installed or stored, so an error never means an uncertain write.
		for _, flow := range flows {
			if err := ovs.ValidateFlowMod(flow.mod); err != nil {
				return nil, status.Errorf(codes.InvalidArgument, "rule %q does not encode as an OpenFlow flow: %v", flow.ruleID, err)
			}
		}
		// OFPFC_ADD replaces whatever holds an entry, whatever its cookie:
		// refuse an entry a flow with another cookie (SDNService.AddFlow,
		// another owner) holds, before any write, so the policy never
		// replaces, and its strict deletes never meet, a flow it does not own.
		occupied, occupant, err := s.occupiedPolicyFlow(ctx, client, flows)
		if err != nil {
			return nil, status.Errorf(codes.Unavailable, "%v", err)
		}
		if occupant != nil {
			return nil, status.Errorf(codes.FailedPrecondition,
				"a flow with cookie %s already holds bridge %s priority %d match %q",
				occupant.Cookie, occupied.bridge, occupied.mod.Priority, occupied.mod.Match)
		}
		attempted, err := s.installPolicyFlows(ctx, client, flows)
		if err != nil {
			// The failing AddFlow may have reached the switch (a barrier
			// can time out after the write), so every attempted flow is
			// removed. Policy flows carry the policy's cookie and the
			// strict deletes are restricted to it, so a flow another owner
			// installed at the same entry (one the pre-check could not
			// see) survives. OFPFC_ADD replaced any prior flow of this
			// policy with the same table, priority and match, so removing
			// them can remove a prior rule too: remove them, then re-add
			// the prior enabled rules, attempting every one even when one
			// fails. The rollback runs on a context detached from the
			// request: a canceled or timed-out request must still restore
			// every prior flow.
			rbCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), policyRollbackTimeout)
			defer cancel()
			failed, rollbackErr := s.removePolicyFlows(rbCtx, client, flows[:attempted])
			if prior != nil && prior.enabled {
				// The prior rules were accepted when stored, so every one
				// encodes; one that did not would add no flow here.
				priorFlows, _ := s.policyFlows(policyID, prior.bridgeNames, prior.rules, prior.priority)
				if reErr := s.restorePolicyFlows(rbCtx, client, priorFlows); reErr != nil {
					rollbackErr = errors.Join(rollbackErr, reErr)
				}
			}
			if rollbackErr == nil {
				return nil, status.Errorf(codes.Internal, "install policy flows: %v", err)
			}
			if prior != nil {
				// Keep the prior configuration and add the attempted
				// flows whose removal failed to its pending inventory.
				s.markPolicyError(policyID, mergePolicyFlows(prior.pendingFlows, failed))
			} else {
				// Keep a record of the flows that may still be installed,
				// so a later disable or delete can remove them.
				s.storePolicy(policyID, policyType, config, bridgeNames, "error", nil, failed)
			}
			return nil, status.Errorf(codes.Internal, "install policy flows: %v; rollback: %v", err, rollbackErr)
		}
		for _, flow := range flows {
			flowIDs = append(flowIDs, fmt.Sprintf("policy-%s-rule-%s-%s", policyID, flow.ruleID, uuid.NewString()))
		}
		// Withdraw the prior record's flows (enabled and pending) the new
		// set does not replace (another bridge, priority or match): once
		// the prior record is overwritten nothing would remove them.
		if prior != nil {
			if failed, err := s.removePolicyFlows(ctx, client, stalePolicyFlows(s.recordFlows(*prior), flows)); err != nil {
				s.storePolicy(policyID, policyType, config, bridgeNames, "error", flowIDs, failed)
				return nil, status.Errorf(codes.Internal, "remove replaced policy flows: %v", err)
			}
		}
	} else if prior != nil {
		// Withdraw every flow the prior record may have on the switch; if
		// that fails they stay enforced, so the record must not say
		// inactive, and the flows not removed stay pending.
		if failed, err := s.removePolicyFlows(ctx, client, s.recordFlows(*prior)); err != nil {
			s.markPolicyError(policyID, failed)
			return nil, status.Errorf(codes.Internal, "remove policy flows: %v", err)
		}
	}

	policy := s.storePolicy(policyID, policyType, config, bridgeNames, policyStatus, flowIDs, nil)

	return &platformv1.ApplyPolicyResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "policy applied successfully",
		},
		Policy: policy,
	}, nil
}

// GetPolicy retrieves a policy by ID
func (s *SDNService) GetPolicy(ctx context.Context, req *platformv1.GetPolicyRequest) (*platformv1.GetPolicyResponse, error) {
	if req.GetPolicyId() == "" {
		return nil, status.Error(codes.InvalidArgument, "policy_id is required")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	// Find policy by ID or name
	var foundID string
	var foundPolicy *policyResource
	for id, p := range s.policies {
		if id == req.GetPolicyId() || p.name == req.GetPolicyId() {
			foundID = id
			foundPolicy = p
			break
		}
	}

	if foundPolicy == nil {
		return nil, status.Error(codes.NotFound, "policy not found")
	}

	return &platformv1.GetPolicyResponse{
		Policy: s.policyResourceToPb(foundID, foundPolicy),
	}, nil
}

// ListPolicies lists all policies with optional filtering
func (s *SDNService) ListPolicies(ctx context.Context, req *platformv1.ListPoliciesRequest) (*platformv1.ListPoliciesResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	policies := make([]*platformv1.Policy, 0, len(s.policies))
	for id, p := range s.policies {
		// Filter by type if specified
		if req.GetType() != "" && p.policyType != strings.ToLower(req.GetType()) {
			continue
		}

		// Filter by target ID if specified
		if req.GetTargetId() != "" {
			found := false
			for _, t := range p.targets {
				if t.GetId() == req.GetTargetId() {
					found = true
					break
				}
			}
			if !found {
				continue
			}
		}

		policies = append(policies, s.policyResourceToPb(id, p))
	}

	return &platformv1.ListPoliciesResponse{
		Policies: policies,
	}, nil
}

// DeletePolicy removes a policy and its associated OpenFlow rules
func (s *SDNService) DeletePolicy(ctx context.Context, req *platformv1.DeletePolicyRequest) (*platformv1.DeletePolicyResponse, error) {
	if req.GetPolicyId() == "" {
		return nil, status.Error(codes.InvalidArgument, "policy_id is required")
	}

	// Serialize with ApplyPolicy from snapshot to record removal.
	s.policyMu.Lock()
	defer s.policyMu.Unlock()

	// Find policy by ID or name and snapshot its data under read lock
	s.mu.RLock()
	var foundID string
	var record policyResource
	for id, p := range s.policies {
		if id == req.GetPolicyId() || p.name == req.GetPolicyId() {
			foundID = id
			record = *p
			break
		}
	}
	s.mu.RUnlock()

	if foundID == "" {
		return nil, status.Error(codes.NotFound, "policy not found")
	}

	// Remove exactly the flows the record may have on the switch (its
	// enabled rules' flows and any pending ones), by their strict key, on
	// the bridges they were installed on: a match-based delete would remove
	// another policy's flow with the same match (#2234). A disabled record
	// with no pending flows has none.
	flows := s.recordFlows(record)
	if failed, err := s.removePolicyFlows(ctx, s.getOVSClient(), flows); err != nil {
		s.markPolicyError(foundID, failed)
		return nil, status.Errorf(codes.Internal, "remove policy flows: %v", err)
	}

	// Remove from tracking under write lock
	s.mu.Lock()
	delete(s.policies, foundID)
	s.mu.Unlock()

	return &platformv1.DeletePolicyResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "policy deleted successfully",
		},
	}, nil
}

// policyRuleToFlowMod converts a policy rule to an OVS FlowMod
//
// The match is built through the flow codec (flowMatchToOVS), so every
// address, protocol or port term carries the OpenFlow prerequisites a switch
// requires (dl_type for an address or protocol, nw_proto for a port). A rule
// whose match cannot carry them is an error naming the field.
func (s *SDNService) policyRuleToFlowMod(rule *platformv1.PolicyRule, policyPriority int32) (*ovs.FlowMod, error) {
	flowMod := &ovs.FlowMod{
		Priority: int(rule.GetPriority()),
	}
	if flowMod.Priority == 0 {
		flowMod.Priority = int(policyPriority)
	}

	flowMatch, err := policyRuleFlowMatch(rule.GetMatch())
	if err != nil {
		return nil, err
	}
	if flowMod.Match, err = flowMatchToOVS(flowMatch); err != nil {
		return nil, err
	}

	// Map policy action to OpenFlow action
	switch rule.GetAction() {
	case platformv1.PolicyRuleAction_POLICY_RULE_ACTION_ALLOW:
		flowMod.Actions = "normal"
	case platformv1.PolicyRuleAction_POLICY_RULE_ACTION_DENY:
		flowMod.Actions = "drop"
	case platformv1.PolicyRuleAction_POLICY_RULE_ACTION_RATE_LIMIT:
		flowMod.Actions = "normal"
	case platformv1.PolicyRuleAction_POLICY_RULE_ACTION_REDIRECT:
		if rule.GetActionValue() != "" {
			flowMod.Actions = fmt.Sprintf("output:%s", rule.GetActionValue())
		}
	case platformv1.PolicyRuleAction_POLICY_RULE_ACTION_LOG:
		flowMod.Actions = "controller"
	default:
		flowMod.Actions = "normal"
	}

	return flowMod, nil
}

// policyRuleFlowMatch maps a policy rule's match to the flow API's match, so
// the policy path shares the flow codec's encoding. Ports are only matched
// under tcp or udp; icmp is pinned to IPv4 and icmpv6 to IPv6, so the codec
// refuses an address of the other family. Protocol 0 is refused: ip_proto 0
// means unset in FlowMatch, so it would encode no nw_proto term.
func policyRuleFlowMatch(match *platformv1.PolicyRuleMatch) (*platformv1.FlowMatch, error) {
	if match == nil {
		return nil, nil
	}
	flowMatch := &platformv1.FlowMatch{
		IpSrc:  match.GetSourceIp(),
		IpDst:  match.GetDestinationIp(),
		VlanId: match.GetVlanId(),
	}
	if protocol := match.GetProtocol(); protocol != "" {
		number := policyProtocolNumber(protocol)
		proto, err := strconv.ParseUint(number, 10, 8)
		if err != nil {
			return nil, ErrUnencodableFlow{Field: "match.protocol", Reason: fmt.Sprintf("%q is not a known protocol or a protocol number", protocol)}
		}
		if proto == 0 {
			return nil, ErrUnencodableFlow{Field: "match.protocol", Reason: fmt.Sprintf("%q is IP protocol 0, which the flow match cannot tell from no protocol; leave protocol empty to match any protocol", protocol)}
		}
		flowMatch.IpProto = uint32(proto)
		switch proto {
		case ipProtoICMP:
			flowMatch.EthType = etherTypeIPv4
		case ipProtoICMPv6:
			flowMatch.EthType = etherTypeIPv6
		}
	}

	srcPort, dstPort := match.GetSourcePort(), match.GetDestinationPort()
	if srcPort == 0 && dstPort == 0 {
		return flowMatch, nil
	}
	field := "match.destination_port"
	if srcPort > 0 {
		field = "match.source_port"
	}
	switch {
	case match.GetProtocol() == "":
		return nil, ErrUnencodableFlow{Field: field, Reason: "a port needs protocol tcp or udp"}
	case flowMatch.GetIpProto() == ipProtoTCP:
		flowMatch.TcpSrc, flowMatch.TcpDst = srcPort, dstPort
	case flowMatch.GetIpProto() == ipProtoUDP:
		flowMatch.UdpSrc, flowMatch.UdpDst = srcPort, dstPort
	default:
		return nil, ErrUnencodableFlow{Field: field, Reason: fmt.Sprintf("protocol %q has no ports; a port needs protocol tcp or udp", match.GetProtocol())}
	}
	return flowMatch, nil
}

const (
	ipProtoICMP   = 1
	ipProtoICMPv6 = 58
)

// policyRuleToMatchString converts a policy rule to an OVS match string for deletion
// policyFlow is one OpenFlow rule a policy rule installs on one bridge.
// policyProtocolNumber returns the IP protocol number nw_proto encodes for
// a policy rule's protocol: the OpenFlow match takes a number, so a name
// (tcp, udp, icmp, icmpv6, sctp) is translated; anything else is returned as
// given, and a value that is not a number fails flow validation. A value
// that parses to 0 is refused by policyRuleFlowMatch, because ip_proto 0
// means unset in FlowMatch and would encode no nw_proto term.
func policyProtocolNumber(protocol string) string {
	switch strings.ToLower(protocol) {
	case "icmp":
		return "1"
	case "tcp":
		return "6"
	case "udp":
		return "17"
	case "icmpv6", "ipv6-icmp":
		return "58"
	case "sctp":
		return "132"
	}
	return protocol
}

type policyFlow struct {
	bridge string
	ruleID string
	mod    *ovs.FlowMod
}

// policyFlowCookieOwner marks a flow a policy installs. It is distinct from
// ovs.APIFlowCookieOwner (flows SDNService.AddFlow adds) and from the
// gateway's 0xF1BE family, so no other owner's flow carries a policy cookie.
const policyFlowCookieOwner uint64 = 0xA9F2 << 48

// policyFlowCookie is the cookie every flow of the policy carries: the
// owner prefix in the high 16 bits and the low 48 bits of an FNV-1a hash of
// the policy ID below. A strict delete with it removes only the policy's
// own entry, never a flow another owner installed at the same table,
// priority and match.
func policyFlowCookie(policyID string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(policyID))
	return policyFlowCookieOwner | h.Sum64()&(1<<48-1)
}

// policyFlows lists the flows the rules install on each bridge, bridge by
// bridge in rule order. Each flow carries the policy's cookie.
func (s *SDNService) policyFlows(policyID string, bridgeNames []string, rules []*platformv1.PolicyRule, priority int32) ([]policyFlow, error) {
	mods := make([]*ovs.FlowMod, len(rules))
	var errs []error
	for i, rule := range rules {
		mod, err := s.policyRuleToFlowMod(rule, priority)
		if err != nil {
			errs = append(errs, fmt.Errorf("rule %q: %w", rule.GetRuleId(), err))
			continue
		}
		mod.Cookie = fmt.Sprintf("0x%x", policyFlowCookie(policyID))
		mods[i] = mod
	}
	flows := make([]policyFlow, 0, len(bridgeNames)*len(rules))
	for _, bridgeName := range bridgeNames {
		for i, rule := range rules {
			if mods[i] == nil {
				continue
			}
			flows = append(flows, policyFlow{
				bridge: bridgeName,
				ruleID: rule.GetRuleId(),
				mod:    mods[i],
			})
		}
	}
	return flows, errors.Join(errs...)
}

// policyFlowKey identifies the OpenFlow entry a flow occupies: OFPFC_ADD
// replaces, and DeleteFlowStrict removes, whatever shares it.
type policyFlowKey struct {
	bridge   string
	table    uint8
	priority uint16
	match    string
}

// flowKey holds the table and priority as the wire encodes them (uint8 and
// uint16), so two flows that land on the same entry share a key.
func flowKey(flow policyFlow) policyFlowKey {
	// Key on the OXM match the switch receives, so match strings that
	// encode the same entry (host bits under a CIDR, a /32 against the bare
	// address) collide. An unparseable match keys on its raw text: AddFlow
	// refuses it as before.
	match := flow.mod.Match
	if canonical, err := ovs.CanonicalMatch(flow.mod.Match); err == nil {
		match = canonical
	}
	return policyFlowKey{
		bridge:   flow.bridge,
		table:    uint8(flow.mod.Table),
		priority: uint16(flow.mod.Priority),
		match:    match,
	}
}

// stalePolicyFlows returns the flows of old whose key no flow of current
// shares: an OFPFC_ADD of current did not replace them.
func stalePolicyFlows(old, current []policyFlow) []policyFlow {
	keep := make(map[policyFlowKey]struct{}, len(current))
	for _, flow := range current {
		keep[flowKey(flow)] = struct{}{}
	}
	var stale []policyFlow
	for _, flow := range old {
		if _, ok := keep[flowKey(flow)]; !ok {
			stale = append(stale, flow)
		}
	}
	return stale
}

// recordFlows lists every flow a record may have on the switch: its enabled
// rules' flows, then its pending flows, one per key.
func (s *SDNService) recordFlows(p policyResource) []policyFlow {
	var flows []policyFlow
	if p.enabled {
		// Stored rules were accepted by ApplyPolicy, so every one encodes;
		// a rule that did not would add no flow to the record.
		flows, _ = s.policyFlows(p.id, p.bridgeNames, p.rules, p.priority)
	}
	return mergePolicyFlows(flows, p.pendingFlows)
}

// mergePolicyFlows concatenates the lists in order, keeping the first flow
// of each key.
func mergePolicyFlows(lists ...[]policyFlow) []policyFlow {
	seen := make(map[policyFlowKey]struct{})
	var out []policyFlow
	for _, list := range lists {
		for _, flow := range list {
			key := flowKey(flow)
			if _, ok := seen[key]; ok {
				continue
			}
			seen[key] = struct{}{}
			out = append(out, flow)
		}
	}
	return out
}

// conflictingPolicyFlow returns the ID of the first of others (policies
// other than the one being applied that are enabled or have pending flows)
// whose installed or pending flows share a key with flows, and the flow
// that collides.
func (s *SDNService) conflictingPolicyFlow(flows []policyFlow, others []policyResource) (string, policyFlow, bool) {
	if len(flows) == 0 {
		return "", policyFlow{}, false
	}
	wanted := make(map[policyFlowKey]policyFlow, len(flows))
	for _, flow := range flows {
		wanted[flowKey(flow)] = flow
	}
	for _, other := range others {
		for _, theirs := range s.recordFlows(other) {
			if flow, ok := wanted[flowKey(theirs)]; ok {
				return other.id, flow, true
			}
		}
	}
	return "", policyFlow{}, false
}

// occupiedPolicyFlow reads the installed flows of each flow's entry and
// returns the first of flows whose entry (bridge, table, priority,
// canonical match) a flow with a different cookie holds, with that
// occupant; nil when none does. The stats filter is not strict, so the
// flows it returns are keyed here.
func (s *SDNService) occupiedPolicyFlow(ctx context.Context, client ovs.ClientInterface, flows []policyFlow) (policyFlow, *ovs.Flow, error) {
	for _, flow := range flows {
		filter := fmt.Sprintf("table=%d", flow.mod.Table)
		if flow.mod.Match != "" {
			filter += "," + flow.mod.Match
		}
		installed, err := client.GetFlowStats(ctx, flow.bridge, filter)
		if err != nil {
			return policyFlow{}, nil, fmt.Errorf("read installed flows on bridge %s: %v", flow.bridge, err)
		}
		want := flowKey(flow)
		for _, fl := range installed {
			if fl == nil || fl.Cookie == flow.mod.Cookie {
				continue
			}
			// A cookie-0 flow with the same actions is this flow installed before policy cookies.
			if zeroFlowCookie(fl.Cookie) && fl.Actions == flow.mod.Actions {
				continue
			}
			theirs := policyFlow{bridge: flow.bridge, mod: &ovs.FlowMod{Table: fl.Table, Priority: fl.Priority, Match: fl.Match}}
			if flowKey(theirs) == want {
				return flow, fl, nil
			}
		}
	}
	return policyFlow{}, nil, nil
}

// zeroFlowCookie reports whether an installed flow's cookie is empty or zero.
func zeroFlowCookie(cookie string) bool {
	v := strings.TrimPrefix(strings.ToLower(strings.TrimSpace(cookie)), "0x")
	if v == "" {
		return true
	}
	n, err := strconv.ParseUint(v, 16, 64)
	return err == nil && n == 0
}

// storePolicy writes the policy record under the write lock and returns
// its protobuf form. pendingFlows are the flows that may still be on the
// switch beyond what the config's enabled rules install.
func (s *SDNService) storePolicy(policyID, policyType string, config *platformv1.PolicyConfig, bridgeNames []string, policyStatus string, flowIDs []string, pendingFlows []policyFlow) *platformv1.Policy {
	now := time.Now()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.policies[policyID] = &policyResource{
		id:          policyID,
		name:        config.GetName(),
		description: config.GetDescription(),
		policyType:  policyType,
		priority:    config.GetPriority(),
		enabled:     config.GetEnabled(),
		status:      policyStatus,
		rules:       config.GetRules(),
		targets:     config.GetTargets(),
		bridgeNames: bridgeNames,
		schedule:    config.GetSchedule(),
		createdAt:   now,
		updatedAt:   now,
		flowIDs:     flowIDs,

		pendingFlows: pendingFlows,
	}
	return s.policyResourceToPb(policyID, s.policies[policyID])
}

// policyRollbackTimeout bounds the ApplyPolicy rollback. The rollback runs
// on a context detached from the request, so it finishes when the request
// is canceled or timed out; the bound keeps a dead switch from holding
// policyMu forever.
const policyRollbackTimeout = 30 * time.Second

// installPolicyFlows adds the flows in order and stops at the first failure.
// It returns how many flows it attempted, the failing one included: an
// AddFlow that returns an error may still have installed its flow.
func (s *SDNService) installPolicyFlows(ctx context.Context, client ovs.ClientInterface, flows []policyFlow) (int, error) {
	for i, flow := range flows {
		if err := client.AddFlow(ctx, flow.bridge, flow.mod); err != nil {
			return i + 1, fmt.Errorf("bridge %s rule %s: %w", flow.bridge, flow.ruleID, err)
		}
	}
	return len(flows), nil
}

// restorePolicyFlows re-adds every flow, attempting each one even when an
// earlier one fails, and returns the joined per-flow errors: a failed
// restore on one bridge must not leave later rules absent.
func (s *SDNService) restorePolicyFlows(ctx context.Context, client ovs.ClientInterface, flows []policyFlow) error {
	var errs []error
	for _, flow := range flows {
		if err := client.AddFlow(ctx, flow.bridge, flow.mod); err != nil {
			errs = append(errs, fmt.Errorf("bridge %s rule %s: %w", flow.bridge, flow.ruleID, err))
		}
	}
	return errors.Join(errs...)
}

// removePolicyFlows deletes each flow by its exact table, priority and match
// (the key OFPFC_ADD replaces on); a strict delete also handles a rule with
// no match criteria, which a non-strict DeleteFlow refuses. It tries every
// flow and returns the flows whose delete failed, which may still be
// installed, with the joined errors.
func (s *SDNService) removePolicyFlows(ctx context.Context, client ovs.ClientInterface, flows []policyFlow) ([]policyFlow, error) {
	var failed []policyFlow
	var errs []error
	gone := &bridgeGone{client: client}
	for _, flow := range flows {
		if err := client.DeleteFlowStrict(ctx, flow.bridge, flow.mod); err != nil {
			// A bridge the switch confirms is gone took its flows with it.
			if gone.check(ctx, flow.bridge) {
				continue
			}
			failed = append(failed, flow)
			errs = append(errs, fmt.Errorf("bridge %s rule %s: %w", flow.bridge, flow.ruleID, err))
		}
	}
	return failed, errors.Join(errs...)
}

// bridgeGone answers whether a bridge is absent from the switch, listing the
// bridges at most once.
type bridgeGone struct {
	client ovs.ClientInterface
	listed bool
	names  map[string]bool
}

// check reports true only when the bridge list succeeds and lacks name.
func (g *bridgeGone) check(ctx context.Context, name string) bool {
	if !g.listed {
		g.listed = true
		bridges, err := g.client.ListBridges(ctx)
		if err != nil {
			return false
		}
		g.names = make(map[string]bool, len(bridges))
		for _, b := range bridges {
			if b != nil {
				g.names[b.Name] = true
			}
		}
	}
	return g.names != nil && !g.names[name]
}

// markPolicyError marks a stored policy "error" when its flows on the switch
// no longer match its record, and records pendingFlows as the flows that
// may still be installed beyond its enabled rules; a policy not stored is
// left alone.
func (s *SDNService) markPolicyError(policyID string, pendingFlows []policyFlow) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if p, ok := s.policies[policyID]; ok {
		p.status = "error"
		p.pendingFlows = pendingFlows
		p.updatedAt = time.Now()
	}
}

// policyResourceToPb converts a policyResource to a protobuf Policy message
func (s *SDNService) policyResourceToPb(id string, p *policyResource) *platformv1.Policy {
	policyType := platformv1.PolicyType_POLICY_TYPE_UNSPECIFIED
	switch p.policyType {
	case "acl":
		policyType = platformv1.PolicyType_POLICY_TYPE_ACL
	case "qos":
		policyType = platformv1.PolicyType_POLICY_TYPE_QOS
	case "nat":
		policyType = platformv1.PolicyType_POLICY_TYPE_NAT
	case "firewall":
		policyType = platformv1.PolicyType_POLICY_TYPE_FIREWALL
	case "routing":
		policyType = platformv1.PolicyType_POLICY_TYPE_ROUTING
	}

	policyStatus := platformv1.PolicyStatus_POLICY_STATUS_UNSPECIFIED
	switch p.status {
	case "active":
		policyStatus = platformv1.PolicyStatus_POLICY_STATUS_ACTIVE
	case "inactive":
		policyStatus = platformv1.PolicyStatus_POLICY_STATUS_INACTIVE
	case "error":
		policyStatus = platformv1.PolicyStatus_POLICY_STATUS_ERROR
	case "pending":
		policyStatus = platformv1.PolicyStatus_POLICY_STATUS_PENDING
	}

	return &platformv1.Policy{
		Id: id,
		Config: &platformv1.PolicyConfig{
			Name:        p.name,
			Description: p.description,
			Type:        policyType,
			Priority:    p.priority,
			Enabled:     p.enabled,
			Rules:       p.rules,
			Targets:     p.targets,
			Schedule:    p.schedule,
		},
		Status:    policyStatus,
		HitCount:  p.hitCount,
		ByteCount: p.byteCount,
		CreatedAt: timestamppb.New(p.createdAt),
		UpdatedAt: timestamppb.New(p.updatedAt),
	}
}

// findBridgeName looks up a bridge name from a bridge ID or name under a read lock.
// Returns the bridge name and true if found, or empty string and false if not
// found or if the OVS lookup failed.
func (s *SDNService) findBridgeName(id string) (string, bool) {
	name, found, _ := s.lookupBridgeName(context.Background(), id)
	return name, found
}

// lookupBridgeName is findBridgeName that tells a failed OVS lookup (an
// error) apart from a confirmed absence (false, nil).
func (s *SDNService) lookupBridgeName(ctx context.Context, id string) (string, bool, error) {
	s.mu.RLock()
	for name, res := range s.bridges {
		if res.id == id || name == id {
			s.mu.RUnlock()
			return name, true, nil
		}
	}
	s.mu.RUnlock()

	// Fall back to OVS so bridges created out-of-band (e.g. by an
	// upstream provisioner before the service started) are still
	// addressable for VLAN/Port operations.
	client := s.getOVSClient()
	if client == nil {
		return "", false, nil
	}
	ovsBridges, err := client.ListBridges(ctx)
	if err != nil {
		return "", false, err
	}
	for _, b := range ovsBridges {
		if b.UUID == id || b.Name == id {
			return b.Name, true, nil
		}
	}
	return "", false, nil
}

// findPortName looks up a port name from a port ID or name under a read lock.
// Returns the port name, port type, and true if found.
func (s *SDNService) findPortName(id string) (string, platformv1.PortType, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for name, res := range s.ports {
		if res.id == id || name == id {
			return name, res.portType, true
		}
	}
	return "", platformv1.PortType_PORT_TYPE_UNSPECIFIED, false
}

// FindPortBridge looks up the bridge ID associated with a port by port ID or name.
// Returns the bridge ID and true if found, or empty string and false if not found.
func (s *SDNService) FindPortBridge(portID string) (string, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	for name, res := range s.ports {
		if res.id == portID || name == portID {
			return res.bridgeID, true
		}
	}
	return "", false
}

// getOVSClient returns the OVS client reference.
// The OVS client handles lazy connection internally: operations
// establish or re-establish the connection transparently on first use.
func (s *SDNService) getOVSClient() ovs.ClientInterface {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.ovsClient
}

// Helper conversion functions

func (s *SDNService) ovsBridgeToPb(ovsBridge *ovs.Bridge) *platformv1.Bridge {
	// Look up stored MTU from bridge resource (RLock must be held by caller
	// or this is called from a context where the map is not being mutated).
	var mtu uint32
	s.mu.RLock()
	if res, ok := s.bridges[ovsBridge.Name]; ok {
		mtu = res.mtu
	}
	s.mu.RUnlock()

	return &platformv1.Bridge{
		Id: ovsBridge.UUID,
		Config: &platformv1.BridgeConfig{
			Name:       ovsBridge.Name,
			Type:       platformv1.BridgeType_BRIDGE_TYPE_OVS,
			DatapathId: ovsBridge.UUID,
			StpEnabled: ovsBridge.STP,
			Mtu:        mtu,
			Options:    ovsBridge.OtherConfig,
			Labels:     ovsBridge.ExternalIDs,
		},
		Status:    platformv1.BridgeStatus_BRIDGE_STATUS_UP,
		CreatedAt: timestamppb.New(time.Now()), // OVS doesn't track creation time
		UpdatedAt: timestamppb.New(time.Now()),
	}
}

func (s *SDNService) ovsPortToPb(ovsPort *ovs.Port, bridgeID string, portStatus platformv1.PortStatus) *platformv1.Port {
	return &platformv1.Port{
		Id:       ovsPort.UUID,
		BridgeId: bridgeID,
		Config: &platformv1.PortConfig{
			Name:   ovsPort.Name,
			Type:   platformv1.PortType_PORT_TYPE_INTERNAL,
			Vlan:   uint32(ovsPort.Tag),
			Labels: ovsPort.ExternalIDs,
		},
		Status:    portStatus,
		CreatedAt: timestamppb.New(time.Now()),
		UpdatedAt: timestamppb.New(time.Now()),
	}
}

// portAdminStatus maps an OVSDB Interface admin_state to the port status it
// reports. A state OVS has not recorded yet is PORT_STATUS_UNSPECIFIED.
var portAdminStatus = map[string]platformv1.PortStatus{
	"up":   platformv1.PortStatus_PORT_STATUS_UP,
	"down": platformv1.PortStatus_PORT_STATUS_DOWN,
}

// portStatus reads a port's status from the admin_state of its interface,
// the column SetPortState writes. A port with no interface of its own name
// (a bond) has no single state and is PORT_STATUS_UNSPECIFIED.
func (s *SDNService) portStatus(ctx context.Context, client ovs.ClientInterface, portName string) (platformv1.PortStatus, error) {
	iface, err := client.GetInterface(ctx, portName)
	if errors.Is(err, ovs.ErrPortNotFound) {
		return platformv1.PortStatus_PORT_STATUS_UNSPECIFIED, nil
	}
	if err != nil {
		return platformv1.PortStatus_PORT_STATUS_UNSPECIFIED, status.Error(codes.Internal, fmt.Sprintf("failed to read port state: %v", err))
	}
	return portAdminStatus[iface.AdminState], nil
}

func (s *SDNService) ovsFlowToPb(ovsFlow *ovs.Flow, bridgeID string) *platformv1.Flow {
	return &platformv1.Flow{
		Id: ovs.FlowIDPrefix + ovsFlow.Cookie,
		Config: &platformv1.FlowConfig{
			BridgeId: bridgeID,
			// The inverse of pbToOvsFlowMod's table mapping.
			Table:       platformv1.FlowTable(ovsFlow.Table),
			Priority:    uint32(ovsFlow.Priority),
			Match:       ovsMatchToPb(ovsFlow.Match),
			Actions:     ovsActionsToPb(ovsFlow.Actions),
			IdleTimeout: uint32(ovsFlow.IdleAge),
			HardTimeout: uint32(ovsFlow.HardAge),
		},
		Stats: &platformv1.FlowStats{
			PacketCount:     uint64(ovsFlow.PacketCount),
			ByteCount:       uint64(ovsFlow.ByteCount),
			DurationSeconds: uint32(ovsFlow.Duration),
		},
		CreatedAt: timestamppb.New(time.Now()),
	}
}

func (s *SDNService) pbToOvsFlowMod(config *platformv1.FlowConfig) (*ovs.FlowMod, error) {
	table := int(config.GetTable())
	match, actions, err := flowConfigToOVSTerms(config, table)
	if err != nil {
		return nil, err
	}
	return &ovs.FlowMod{
		Table:       table,
		Priority:    int(config.GetPriority()),
		Match:       match,
		Actions:     actions,
		IdleTimeout: int(config.GetIdleTimeout()),
		HardTimeout: int(config.GetHardTimeout()),
	}, nil
}

// =============================================================================
// Zone Service wiring
// =============================================================================

// WithZoneService sets the zone service on the SDNService.
func (s *SDNService) WithZoneService(svc gateway.ZoneService) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.zoneSvc = svc
}

// requireZoneService returns a gRPC error when the zone service is unavailable.
func (s *SDNService) requireZoneService() error {
	if s.zoneSvc == nil {
		return status.Error(codes.FailedPrecondition, "zone service is not available")
	}
	return nil
}

// =============================================================================
// Network Zone gRPC Implementations
// =============================================================================

// CreateNetworkZone creates a new SDN network trust zone.
func (s *SDNService) CreateNetworkZone(
	ctx context.Context,
	req *platformv1.CreateNetworkZoneRequest,
) (*platformv1.CreateNetworkZoneResponse, error) {
	if err := s.requireZoneService(); err != nil {
		return nil, err
	}
	if req.GetConfig() == nil {
		return nil, status.Error(codes.InvalidArgument, "zone config is required")
	}
	cfg := sdnProtoToZoneConfig(req.GetConfig())
	rec, restartRequired, err := s.zoneSvc.Create(ctx, cfg)
	if err != nil {
		return nil, sdnMapZoneError(err)
	}
	pz := sdnZoneRecordToProto(rec)
	pz.RestartRequired = restartRequired
	return &platformv1.CreateNetworkZoneResponse{
		Zone: pz,
	}, nil
}

// UpdateNetworkZone updates an existing SDN network trust zone.
func (s *SDNService) UpdateNetworkZone(
	ctx context.Context,
	req *platformv1.UpdateNetworkZoneRequest,
) (*platformv1.UpdateNetworkZoneResponse, error) {
	if err := s.requireZoneService(); err != nil {
		return nil, err
	}
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "zone name is required")
	}
	var cfg zone.ZoneConfig
	if req.GetConfig() != nil {
		cfg = sdnProtoToZoneConfig(req.GetConfig())
	}
	cfg.Name = zone.Zone(req.GetName())
	rec, restartRequired, err := s.zoneSvc.Update(ctx, zone.Zone(req.GetName()), cfg)
	if err != nil {
		return nil, sdnMapZoneError(err)
	}
	pz := sdnZoneRecordToProto(rec)
	pz.RestartRequired = restartRequired
	return &platformv1.UpdateNetworkZoneResponse{
		Zone: pz,
	}, nil
}

// DeleteNetworkZone deletes an SDN network trust zone.
func (s *SDNService) DeleteNetworkZone(
	ctx context.Context,
	req *platformv1.DeleteNetworkZoneRequest,
) (*platformv1.DeleteNetworkZoneResponse, error) {
	if err := s.requireZoneService(); err != nil {
		return nil, err
	}
	if req.GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, "zone name is required")
	}
	restartRequired, err := s.zoneSvc.Delete(ctx, zone.Zone(req.GetName()))
	if err != nil {
		return nil, sdnMapZoneError(err)
	}
	return &platformv1.DeleteNetworkZoneResponse{
		RestartRequired: restartRequired,
	}, nil
}

// ListNetworkZones lists SDN network trust zones, optionally filtered by lifecycle role.
func (s *SDNService) ListNetworkZones(
	ctx context.Context,
	req *platformv1.ListNetworkZonesRequest,
) (*platformv1.ListNetworkZonesResponse, error) {
	if err := s.requireZoneService(); err != nil {
		return nil, err
	}
	recs, err := s.zoneSvc.List(ctx, zone.LifecycleRole(req.GetLifecycleRole()))
	if err != nil {
		return nil, status.Errorf(codes.Internal, "list zones: %v", err)
	}
	zones := make([]*platformv1.NetworkZone, 0, len(recs))
	for _, r := range recs {
		zones = append(zones, sdnZoneRecordToProto(r))
	}
	return &platformv1.ListNetworkZonesResponse{
		Zones: zones,
	}, nil
}

// =============================================================================
// Zone proto helpers (daemon-local copies; mirrors grpc.SDNGRPCService helpers)
// =============================================================================

// sdnProtoToZoneConfig converts a protobuf NetworkZoneConfig to a zone.ZoneConfig.
func sdnProtoToZoneConfig(p *platformv1.NetworkZoneConfig) zone.ZoneConfig {
	cfg := zone.ZoneConfig{
		Name:            zone.Zone(p.GetName()),
		Offset:          zone.Offset(p.GetOffset()),
		InternetIngress: p.GetInternetIngress(),
		Services:        p.GetServices(),
		Isolate:         p.GetIsolate(),
		OOB:             p.GetOob(),
		LifecycleRole:   zone.LifecycleRole(p.GetLifecycleRole()),
		Omit:            p.GetOmit(),
	}
	for _, c := range p.GetPortClasses() {
		cfg.PortClasses = append(cfg.PortClasses, zone.PortClass(c))
	}
	for _, z := range p.GetIsolateFrom() {
		cfg.IsolateFrom = append(cfg.IsolateFrom, zone.Zone(z))
	}
	for _, pt := range p.GetAllowTo() {
		cfg.AllowTo = append(cfg.AllowTo, zone.ZonePath{
			Zone:     zone.Zone(pt.GetZone()),
			Services: pt.GetServices(),
		})
	}
	if pa := p.GetPrivilegedAccess(); pa != nil {
		cfg.PrivilegedAccess = &zone.PrivilegedAccess{
			Reason:     pa.GetReason(),
			ApprovedBy: pa.GetApprovedBy(),
		}
	}
	return cfg
}

// sdnZoneRecordToProto converts a gateway.ZoneRecord to a platformv1.NetworkZone.
func sdnZoneRecordToProto(r *gateway.ZoneRecord) *platformv1.NetworkZone {
	isolateFrom := make([]string, 0, len(r.Config.IsolateFrom))
	for _, z := range r.Config.IsolateFrom {
		isolateFrom = append(isolateFrom, string(z))
	}
	allowTo := make([]*platformv1.NetworkZonePath, 0, len(r.Config.AllowTo))
	for _, p := range r.Config.AllowTo {
		allowTo = append(allowTo, &platformv1.NetworkZonePath{
			Zone:     string(p.Zone),
			Services: p.Services,
		})
	}
	portClasses := make([]string, 0, len(r.Config.PortClasses))
	for _, c := range r.Config.PortClasses {
		portClasses = append(portClasses, string(c))
	}
	out := &platformv1.NetworkZone{
		Config: &platformv1.NetworkZoneConfig{
			Name:            string(r.Config.Name),
			Offset:          uint32(r.Config.Offset),
			PortClasses:     portClasses,
			InternetIngress: r.Config.InternetIngress,
			IsolateFrom:     isolateFrom,
			AllowTo:         allowTo,
			Services:        r.Config.Services,
			Isolate:         r.Config.Isolate,
			Oob:             r.Config.OOB,
			LifecycleRole:   string(r.Config.LifecycleRole),
			Omit:            r.Config.Omit,
		},
		CreatedAt: timestamppb.New(r.CreatedAt),
		UpdatedAt: timestamppb.New(r.UpdatedAt),
	}
	if pa := r.Config.PrivilegedAccess; pa != nil {
		out.Config.PrivilegedAccess = &platformv1.NetworkZonePrivilegedAccess{
			Reason:     pa.Reason,
			ApprovedBy: pa.ApprovedBy,
		}
	}
	if n := r.NumberingView(); n != nil {
		out.Numbering = &platformv1.NetworkZoneNumbering{
			Vlan:    uint32(n.VLAN),
			Subnet4: n.Subnet4,
			Subnet6: n.Subnet6,
			Gateway: n.Gateway,
		}
	}
	return out
}

// sdnMapZoneError maps gateway zone errors to gRPC status errors.
func sdnMapZoneError(err error) error {
	switch err.(type) {
	case gateway.ErrZoneNotFound:
		return status.Error(codes.NotFound, err.Error())
	case gateway.ErrZoneAlreadyExists:
		return status.Error(codes.AlreadyExists, err.Error())
	case gateway.ErrZoneValidation:
		return status.Error(codes.InvalidArgument, err.Error())
	default:
		return status.Errorf(codes.Internal, "zone operation: %v", err)
	}
}
