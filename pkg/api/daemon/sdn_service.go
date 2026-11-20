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
	"net"
	"sort"
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

	// Track created resources for cleanup
	bridges  map[string]*bridgeResource
	ports    map[string]*portResource
	taps     map[string]*tapResource
	vlans    map[string]*vlanResource
	policies map[string]*policyResource
	// policySeq numbers policy applies, so a rollback can tell which of
	// two policies with the same flow entry was applied last.
	policySeq uint64

	// applyMu serializes the switch writes of policy applies and deletes
	// from the first flow-mod until the policy is recorded or the rollback
	// has finished: a concurrent apply's rollback would otherwise remove an
	// entry another apply installed but has not yet published.
	applyMu sync.Mutex
	// strandedFlows holds, under applyMu, the entries a rollback failed to
	// remove: they are on the switch but no policy owns them, so the next
	// apply removes them first.
	strandedFlows map[flowEntryKey]attemptedFlow
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
	schedule    *platformv1.PolicySchedule
	hitCount    uint64
	byteCount   uint64
	createdAt   time.Time
	updatedAt   time.Time
	// flowIDs tracks OpenFlow rules installed for this policy
	flowIDs []string
	// applySeq is SDNService.policySeq at this policy's last apply: of two
	// policies with the same flow entry, the higher one's entry is in force.
	applySeq uint64
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

	// One apply or delete at a time writes the switch, until its policy is
	// recorded or rolled back (see applyMu).
	s.applyMu.Lock()
	defer s.applyMu.Unlock()

	// Check for duplicate policy name under read lock
	s.mu.RLock()
	for id, p := range s.policies {
		if p.name == config.GetName() && id != policyID {
			s.mu.RUnlock()
			return nil, status.Error(codes.AlreadyExists, "policy with this name already exists")
		}
	}
	s.mu.RUnlock()

	// Convert PolicyType enum to string for internal tracking
	policyType := strings.ToLower(strings.TrimPrefix(config.GetType().String(), "POLICY_TYPE_"))

	// The policy priority is the default for every rule without its own,
	// and is stored for later rollbacks: refuse one outside 0-65535 even
	// when every rule carries its own priority.
	if err := checkFlowPriority(int(config.GetPriority())); err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "policy priority: %v", err)
	}

	// Translate every rule before any flow is installed, so a rule the flow
	// grammar cannot carry is refused with nothing applied.
	flowMods := make([]*ovs.FlowMod, len(config.GetRules()))
	for i, rule := range config.GetRules() {
		flowMod, err := s.policyRuleToFlowMod(rule, config.GetPriority())
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "rule %q: %v", rule.GetRuleId(), err)
		}
		flowMods[i] = flowMod
	}

	client := s.getOVSClient()

	// Entries an earlier rollback could not remove go first.
	s.removeStrandedFlows(ctx, client)

	// Policy flows carry no cookie: a flow whose table, priority and match
	// equal an entry another owner installed (the gateway pipeline) would
	// replace it, and a rollback would delete it. Refuse before installing.
	if err := s.checkForeignFlowCollisions(ctx, client, config.GetTargets(), flowMods); err != nil {
		return nil, err
	}

	// Install OpenFlow rules for each target bridge without holding the lock.
	// A flow the switch refuses fails the apply: the flows this call
	// attempted are removed and no policy is recorded.
	var attempted []attemptedFlow
	var flowIDs []string
	// The policy this call updates, if any: a failed update restores its flows.
	s.mu.RLock()
	old := s.policies[policyID]
	s.mu.RUnlock()
	for _, target := range config.GetTargets() {
		if target.GetType() != platformv1.PolicyTargetType_POLICY_TARGET_TYPE_BRIDGE {
			continue
		}

		bridgeName, found := s.findBridgeName(target.GetId())
		if !found {
			continue
		}

		for i, rule := range config.GetRules() {
			flowMod := flowMods[i]
			// Record the flow before the call: an AddFlow error does not
			// prove the switch refused it (the flow-mod is written before
			// its barrier is awaited), so the rollback removes it too.
			attempted = append(attempted, attemptedFlow{bridge: bridgeName, flow: flowMod})
			if err := client.AddFlow(ctx, bridgeName, flowMod); err != nil {
				attempted[len(attempted)-1].refused = errors.Is(err, ovs.ErrInvalidFlow)
				if rbErr := s.rollbackPolicyApply(ctx, client, policyID, old, attempted); rbErr != nil {
					return nil, status.Errorf(codes.Internal, "install flow for rule %q on bridge %q: %v; rollback: %v", rule.GetRuleId(), bridgeName, err, rbErr)
				}
				return nil, status.Errorf(codes.Internal, "install flow for rule %q on bridge %q: %v", rule.GetRuleId(), bridgeName, err)
			}
			flowID := fmt.Sprintf("policy-%s-rule-%s-%s", policyID, rule.GetRuleId(), uuid.NewString())
			flowIDs = append(flowIDs, flowID)
		}
	}

	now := time.Now()

	// Track the policy under write lock
	s.mu.Lock()
	s.policySeq++
	s.policies[policyID] = &policyResource{
		applySeq:    s.policySeq,
		id:          policyID,
		name:        config.GetName(),
		description: config.GetDescription(),
		policyType:  policyType,
		priority:    config.GetPriority(),
		enabled:     config.GetEnabled(),
		status:      "active",
		rules:       config.GetRules(),
		targets:     config.GetTargets(),
		schedule:    config.GetSchedule(),
		createdAt:   now,
		updatedAt:   now,
		flowIDs:     flowIDs,
	}

	policy := s.policyResourceToPb(policyID, s.policies[policyID])
	s.mu.Unlock()

	// An entry this policy now owns is no longer stranded: removing it
	// later would take this policy's flow off the switch.
	for _, f := range attempted {
		delete(s.strandedFlows, newFlowEntryKey(f.bridge, f.flow))
	}

	return &platformv1.ApplyPolicyResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "policy applied successfully",
		},
		Policy: policy,
	}, nil
}

// restorePolicyFlows re-installs a recorded policy's flows on its bridge
// targets, after a failed update's rollback deleted the flows that had
// replaced them. It reports whether every flow was installed.
// policyRollbackTimeout bounds the flow clean-up after a failed apply.
const policyRollbackTimeout = 30 * time.Second

// attemptedFlow is a flow an apply sent to a bridge, whether or not the
// switch confirmed it.
type attemptedFlow struct {
	bridge string
	flow   *ovs.FlowMod
	// refused is set when AddFlow failed before the flow-mod was sent
	// (ovs.ErrInvalidFlow): the switch never saw it, so the rollback must
	// not delete the entry with its match, which may be another owner's.
	refused bool
}

// rollbackPolicyApply undoes a failed apply of policyID: it deletes every
// flow the apply attempted (including the one whose AddFlow failed) and
// re-installs the entries those flows may have replaced, the previous
// version of the policy (old, nil for a new policy) included.

func (s *SDNService) rollbackPolicyApply(ctx context.Context, client ovs.ClientInterface, policyID string, old *policyResource, attempted []attemptedFlow) error {
	// The request may already be cancelled (a barrier timeout often is the
	// caller going away): clean up on a context of its own, bounded.
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), policyRollbackTimeout)
	defer cancel()

	// A delete that fails leaves the entry on the switch: it is reported and
	// kept in strandedFlows for the next apply. A policy entry it may have
	// replaced is still restored over it (an OpenFlow ADD replaces the
	// same-match entry); an entry restored that way is no longer stranded.
	// A flow refused before it was sent is not deleted: the entry with its
	// match was never this apply's.
	var errs []error
	removed := make(map[flowEntryKey]bool, len(attempted))
	for _, f := range attempted {
		if f.refused {
			continue
		}
		key := newFlowEntryKey(f.bridge, f.flow)
		removed[key] = true
		if err := client.DeleteFlowStrict(cctx, f.bridge, f.flow); err != nil {
			errs = append(errs, fmt.Errorf("remove flow %q on bridge %q: %w", f.flow.Match, f.bridge, err))
			if s.strandedFlows == nil {
				s.strandedFlows = make(map[flowEntryKey]attemptedFlow)
			}
			s.strandedFlows[key] = f
		}
	}

	skipID := policyID
	if old != nil {
		// An update's flows replaced the previous policy's flows with the
		// same match: every entry of the previous policy goes back, in
		// apply order with the other policies sharing its entries.
		skipID = ""
		for _, target := range old.targets {
			if target.GetType() != platformv1.PolicyTargetType_POLICY_TARGET_TYPE_BRIDGE {
				continue
			}
			bridgeName, found := s.findBridgeName(target.GetId())
			if !found {
				continue
			}
			for _, rule := range old.rules {
				flowMod, err := s.policyRuleToFlowMod(rule, old.priority)
				if err != nil {
					s.mu.Lock()
					old.status = "error"
					s.mu.Unlock()
					continue
				}
				removed[newFlowEntryKey(bridgeName, flowMod)] = true
			}
		}
	}
	// A flow this call attempted may also have replaced another policy's
	// entry with the same table, priority and match: put those back. A
	// policy whose entry cannot be put back is marked "error".
	for key := range s.restoreOverwrittenFlows(cctx, client, skipID, removed) {
		delete(s.strandedFlows, key)
	}
	return errors.Join(errs...)
}

// checkForeignFlowCollisions refuses an apply whose flow has the table,
// priority and match of an entry on the bridge that no policy owns: the
// apply would replace that entry, and its rollback would delete it.
func (s *SDNService) checkForeignFlowCollisions(ctx context.Context, client ovs.ClientInterface, targets []*platformv1.PolicyTarget, flowMods []*ovs.FlowMod) error {
	owned := s.policyOwnedFlowKeys()
	listed := make(map[string]map[flowEntryKey]bool)
	for _, target := range targets {
		if target.GetType() != platformv1.PolicyTargetType_POLICY_TARGET_TYPE_BRIDGE {
			continue
		}
		bridgeName, found := s.findBridgeName(target.GetId())
		if !found {
			continue
		}
		present, seen := listed[bridgeName]
		if !seen {
			flows, err := client.ListFlows(ctx, bridgeName)
			if err != nil {
				return status.Errorf(codes.Unavailable, "list flows on bridge %q: %v", bridgeName, err)
			}
			present = make(map[flowEntryKey]bool, len(flows))
			for _, f := range flows {
				present[flowEntryKey{bridge: bridgeName, table: f.Table, priority: f.Priority, match: normalizeFlowMatch(f.Match)}] = true
			}
			listed[bridgeName] = present
		}
		for _, flowMod := range flowMods {
			key := newFlowEntryKey(bridgeName, flowMod)
			if !present[key] || owned[key] {
				continue
			}
			if _, stranded := s.strandedFlows[key]; stranded {
				continue
			}
			return status.Errorf(codes.FailedPrecondition, "flow %q at table %d, priority %d on bridge %q collides with an entry no policy owns", flowMod.Match, flowMod.Table, flowMod.Priority, bridgeName)
		}
	}
	return nil
}

// policyOwnedFlowKeys returns the entries the recorded policies install.
func (s *SDNService) policyOwnedFlowKeys() map[flowEntryKey]bool {
	s.mu.RLock()
	policies := make([]*policyResource, 0, len(s.policies))
	for _, p := range s.policies {
		policies = append(policies, p)
	}
	s.mu.RUnlock()

	// findBridgeName takes s.mu itself, so resolve outside the lock.
	owned := make(map[flowEntryKey]bool)
	for _, p := range policies {
		for _, target := range p.targets {
			if target.GetType() != platformv1.PolicyTargetType_POLICY_TARGET_TYPE_BRIDGE {
				continue
			}
			bridgeName, found := s.findBridgeName(target.GetId())
			if !found {
				continue
			}
			for _, rule := range p.rules {
				if flowMod, err := s.policyRuleToFlowMod(rule, p.priority); err == nil {
					owned[newFlowEntryKey(bridgeName, flowMod)] = true
				}
			}
		}
	}
	return owned
}

// removeStrandedFlows removes, with applyMu held, the entries an earlier
// rollback failed to remove, and puts back the published policies' flows
// for the entries it removed. An entry whose delete fails again stays
// tracked.
func (s *SDNService) removeStrandedFlows(ctx context.Context, client ovs.ClientInterface) {
	if len(s.strandedFlows) == 0 {
		return
	}
	cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), policyRollbackTimeout)
	defer cancel()

	removed := make(map[flowEntryKey]bool, len(s.strandedFlows))
	for key, f := range s.strandedFlows {
		if err := client.DeleteFlowStrict(cctx, f.bridge, f.flow); err != nil {
			continue
		}
		delete(s.strandedFlows, key)
		removed[key] = true
	}
	if len(removed) > 0 {
		s.restoreOverwrittenFlows(cctx, client, "", removed)
	}
}

// flowEntryKey identifies a switch entry: OpenFlow keeps one flow per bridge,
// table, priority and match, so a flow with the same key replaces another.
type flowEntryKey struct {
	bridge   string
	table    int
	priority int
	match    string
}

func newFlowEntryKey(bridge string, f *ovs.FlowMod) flowEntryKey {
	return flowEntryKey{bridge: bridge, table: f.Table, priority: f.Priority, match: normalizeFlowMatch(f.Match)}
}

// flowMatchShorthands expands the ovs-ofctl protocol shorthands to the fields
// the switch parses them into, so "tcp" and "ip,nw_proto=6" compare equal.
var flowMatchShorthands = map[string][]string{
	"ip":    {"dl_type=2048"},
	"ipv6":  {"dl_type=34525"},
	"arp":   {"dl_type=2054"},
	"icmp":  {"dl_type=2048", "nw_proto=1"},
	"tcp":   {"dl_type=2048", "nw_proto=6"},
	"udp":   {"dl_type=2048", "nw_proto=17"},
	"sctp":  {"dl_type=2048", "nw_proto=132"},
	"icmp6": {"dl_type=34525", "nw_proto=58"},
	"tcp6":  {"dl_type=34525", "nw_proto=6"},
	"udp6":  {"dl_type=34525", "nw_proto=17"},
	"sctp6": {"dl_type=34525", "nw_proto=132"},
}

// normalizeFlowMatch returns a canonical form of an OpenFlow match: protocol
// shorthands expanded to their fields, numeric values in decimal, fields
// de-duplicated and sorted, so two spellings of one switch entry are equal.
func normalizeFlowMatch(match string) string {
	fields := make(map[string]struct{})
	for _, part := range strings.Split(match, ",") {
		part = strings.ToLower(strings.TrimSpace(part))
		if part == "" {
			continue
		}
		if expanded, ok := flowMatchShorthands[part]; ok {
			for _, f := range expanded {
				fields[f] = struct{}{}
			}
			continue
		}
		if k, v, ok := strings.Cut(part, "="); ok {
			k, v = strings.TrimSpace(k), strings.TrimSpace(v)
			if k == "ip_proto" {
				k = "nw_proto"
			}
			if n, err := strconv.ParseUint(v, 0, 64); err == nil {
				v = strconv.FormatUint(n, 10)
			} else if _, prefix, err := net.ParseCIDR(v); err == nil {
				// The OpenFlow encoder writes a prefix's masked network
				// (10.0.0.1/24 and 10.0.0.0/24 are one switch entry), and
				// a full-length prefix is the plain address.
				if ones, bits := prefix.Mask.Size(); ones == bits {
					v = prefix.IP.String()
				} else {
					v = prefix.String()
				}
			}
			part = k + "=" + v
		}
		fields[part] = struct{}{}
	}
	out := make([]string, 0, len(fields))
	for f := range fields {
		out = append(out, f)
	}
	sort.Strings(out)
	return strings.Join(out, ",")
}

// restoreOverwrittenFlows re-installs the flows of every recorded policy other
// than skipID whose switch entry is in removed: a failed apply replaced those
// entries and its rollback deleted them. A policy whose flow cannot be put back
// is marked "error".
func (s *SDNService) restoreOverwrittenFlows(ctx context.Context, client ovs.ClientInterface, skipID string, removed map[flowEntryKey]bool) map[flowEntryKey]bool {
	type restore struct {
		p      *policyResource
		bridge string
		flow   *ovs.FlowMod
	}
	var others []*policyResource
	s.mu.RLock()
	for id, p := range s.policies {
		if id != skipID {
			others = append(others, p)
		}
	}
	// Map order is random: walk the policies in the order they were applied,
	// so of two policies with the same entry the later one's is restored.
	sort.SliceStable(others, func(i, j int) bool {
		if others[i].applySeq != others[j].applySeq {
			return others[i].applySeq < others[j].applySeq
		}
		return others[i].id < others[j].id
	})
	s.mu.RUnlock()

	// findBridgeName takes s.mu itself, so resolve outside the lock.
	var restores []restore
	for _, p := range others {
		for _, target := range p.targets {
			if target.GetType() != platformv1.PolicyTargetType_POLICY_TARGET_TYPE_BRIDGE {
				continue
			}
			bridgeName, found := s.findBridgeName(target.GetId())
			if !found {
				continue
			}
			for _, rule := range p.rules {
				flowMod, err := s.policyRuleToFlowMod(rule, p.priority)
				if err != nil || !removed[newFlowEntryKey(bridgeName, flowMod)] {
					continue
				}
				restores = append(restores, restore{p: p, bridge: bridgeName, flow: flowMod})
			}
		}
	}

	// Per entry, only the last applied policy's flow was in force: install
	// that one alone, in apply order.
	latest := make(map[flowEntryKey]int, len(restores))
	for i, r := range restores {
		latest[newFlowEntryKey(r.bridge, r.flow)] = i
	}
	restored := make(map[flowEntryKey]bool, len(latest))
	for i, r := range restores {
		key := newFlowEntryKey(r.bridge, r.flow)
		if latest[key] != i {
			continue
		}
		if err := client.AddFlow(ctx, r.bridge, r.flow); err != nil {
			s.mu.Lock()
			r.p.status = "error"
			s.mu.Unlock()
			continue
		}
		restored[key] = true
	}
	return restored
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

	// Serialized with applies (see applyMu).
	s.applyMu.Lock()
	defer s.applyMu.Unlock()

	// Find policy by ID or name and snapshot its data under read lock
	s.mu.RLock()
	var foundID string
	var policyTargets []*platformv1.PolicyTarget
	var policyRules []*platformv1.PolicyRule
	var policyPriority int32
	for id, p := range s.policies {
		if id == req.GetPolicyId() || p.name == req.GetPolicyId() {
			foundID = id
			policyTargets = p.targets
			policyRules = p.rules
			policyPriority = p.priority
			break
		}
	}
	s.mu.RUnlock()

	if foundID == "" {
		return nil, status.Error(codes.NotFound, "policy not found")
	}

	client := s.getOVSClient()

	// Remove the policy's own entries from target bridges without holding
	// the lock. A non-strict delete would remove every entry whose match
	// overlaps, at any priority, including other policies' enforcement
	// rules: delete each translated flow strictly, at its own priority.
	removed := make(map[flowEntryKey]bool)
	for _, target := range policyTargets {
		if target.GetType() != platformv1.PolicyTargetType_POLICY_TARGET_TYPE_BRIDGE {
			continue
		}
		bridgeName, found := s.findBridgeName(target.GetId())
		if !found {
			continue
		}
		for _, rule := range policyRules {
			flowMod, err := s.policyRuleToFlowMod(rule, policyPriority)
			if err != nil {
				// The stored rule no longer translates, so no flow of it
				// can be matched for removal.
				continue
			}
			// Best-effort cleanup of flow rules
			if err := client.DeleteFlowStrict(ctx, bridgeName, flowMod); err == nil {
				removed[newFlowEntryKey(bridgeName, flowMod)] = true
			}
		}
	}

	// Remove from tracking under write lock
	s.mu.Lock()
	delete(s.policies, foundID)
	s.mu.Unlock()

	// A surviving policy with the same entry (bridge, table, priority and
	// match) lost its flow with the strict delete: put it back.
	if len(removed) > 0 {
		cctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), policyRollbackTimeout)
		s.restoreOverwrittenFlows(cctx, client, foundID, removed)
		cancel()
	}

	return &platformv1.DeletePolicyResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "policy deleted successfully",
		},
	}, nil
}

// policyRuleToFlowMod converts a policy rule to an OVS FlowMod
// maxFlowPriority is the largest OpenFlow priority (a 16-bit field).
const maxFlowPriority = 65535

// checkFlowPriority refuses a priority the switch cannot carry unchanged.
func checkFlowPriority(priority int) error {
	if priority < 0 || priority > maxFlowPriority {
		return fmt.Errorf("priority %d is outside 0-%d", priority, maxFlowPriority)
	}
	return nil
}

func (s *SDNService) policyRuleToFlowMod(rule *platformv1.PolicyRule, policyPriority int32) (*ovs.FlowMod, error) {
	flowMod := &ovs.FlowMod{
		Priority: int(rule.GetPriority()),
	}
	if flowMod.Priority == 0 {
		flowMod.Priority = int(policyPriority)
	}
	// OpenFlow priorities are 16 bits and the switch client truncates a
	// wider value, so 65636 would replace the entry at 100 under a
	// different ownership and rollback key. Refuse it here, before any
	// switch operation.
	if err := checkFlowPriority(flowMod.Priority); err != nil {
		return nil, err
	}

	match, err := policyRuleMatch(rule)
	if err != nil {
		return nil, err
	}
	flowMod.Match = match

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

// policyRuleToMatchString converts a policy rule to an OVS match string for deletion
func (s *SDNService) policyRuleToMatchString(rule *platformv1.PolicyRule) (string, error) {
	return policyRuleMatch(rule)
}

// policyProtocolMatch renders a policy protocol as the head of an OVS match the
// flow grammar parses: tcp, udp, icmp and sctp as their shorthands (which also
// set the IPv4 eth_type that nw_src, nw_dst and tp_* need), and a decimal
// protocol number 0-255 as "ip,nw_proto=<n>". An empty protocol renders as "".
func policyProtocolMatch(p string) (string, error) {
	v := strings.ToLower(strings.TrimSpace(p))
	switch v {
	case "":
		return "", nil
	case "tcp", "udp", "icmp", "sctp":
		return v, nil
	}
	n, err := strconv.ParseUint(v, 10, 8)
	if err != nil {
		return "", fmt.Errorf("protocol %q is not tcp, udp, icmp, sctp or a number 0-255", p)
	}
	return fmt.Sprintf("ip,nw_proto=%d", n), nil
}

// policyRuleMatch builds the OVS match a policy rule installs. ApplyPolicy and
// DeletePolicy both use it, so a delete removes exactly what the apply added.
func policyRuleMatch(rule *platformv1.PolicyRule) (string, error) {
	match := rule.GetMatch()
	if match == nil {
		return "", nil
	}
	var parts []string
	proto, err := policyProtocolMatch(match.GetProtocol())
	if err != nil {
		return "", err
	}
	switch {
	case proto != "":
		parts = append(parts, proto)
	case match.GetSourceIp() != "" || match.GetDestinationIp() != "":
		parts = append(parts, "ip")
	}
	if match.GetSourceIp() != "" {
		parts = append(parts, fmt.Sprintf("nw_src=%s", match.GetSourceIp()))
	}
	if match.GetDestinationIp() != "" {
		parts = append(parts, fmt.Sprintf("nw_dst=%s", match.GetDestinationIp()))
	}
	if match.GetSourcePort() > 0 {
		parts = append(parts, fmt.Sprintf("tp_src=%d", match.GetSourcePort()))
	}
	if match.GetDestinationPort() > 0 {
		parts = append(parts, fmt.Sprintf("tp_dst=%d", match.GetDestinationPort()))
	}
	// A VLAN ID is 12 bits: the switch encodes 4097 as VLAN 1, which would
	// alias another entry under a different ownership and rollback key.
	if match.GetVlanId() > 4095 {
		return "", status.Errorf(codes.InvalidArgument, "vlan_id %d is outside 0-4095", match.GetVlanId())
	}
	if match.GetVlanId() > 0 {
		parts = append(parts, fmt.Sprintf("dl_vlan=%d", match.GetVlanId()))
	}
	return strings.Join(parts, ","), nil
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
// Returns the bridge name and true if found, or empty string and false if not found.
func (s *SDNService) findBridgeName(id string) (string, bool) {
	s.mu.RLock()
	for name, res := range s.bridges {
		if res.id == id || name == id {
			s.mu.RUnlock()
			return name, true
		}
	}
	s.mu.RUnlock()

	// Fall back to OVS so bridges created out-of-band (e.g. by an
	// upstream provisioner before the service started) are still
	// addressable for VLAN/Port operations.
	client := s.getOVSClient()
	if client == nil {
		return "", false
	}
	ovsBridges, err := client.ListBridges(context.Background())
	if err != nil {
		return "", false
	}
	for _, b := range ovsBridges {
		if b.UUID == id || b.Name == id {
			return b.Name, true
		}
	}
	return "", false
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
