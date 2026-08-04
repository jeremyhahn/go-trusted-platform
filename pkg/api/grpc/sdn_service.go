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
	"crypto/x509"
	"encoding/pem"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// SDN gRPC service error types.

// ErrNilSDNService is returned when the SDN service is nil.
type ErrNilSDNService struct{}

func (e ErrNilSDNService) Error() string {
	return "sdn service is nil"
}

// ErrMissingBridgeID is returned when a bridge ID is required but not provided.
type ErrMissingBridgeID struct{}

func (e ErrMissingBridgeID) Error() string {
	return "bridge ID is required"
}

// ErrMissingBridgeConfig is returned when bridge configuration is required but not provided.
type ErrMissingBridgeConfig struct{}

func (e ErrMissingBridgeConfig) Error() string {
	return "bridge configuration is required"
}

// ErrMissingBridgeName is returned when bridge name is required but not provided.
type ErrMissingBridgeName struct{}

func (e ErrMissingBridgeName) Error() string {
	return "bridge name is required"
}

// ErrMissingPortID is returned when a port ID is required but not provided.
type ErrMissingPortID struct{}

func (e ErrMissingPortID) Error() string {
	return "port ID is required"
}

// ErrMissingPortConfig is returned when port configuration is required but not provided.
type ErrMissingPortConfig struct{}

func (e ErrMissingPortConfig) Error() string {
	return "port configuration is required"
}

// ErrMissingPortName is returned when port name is required but not provided.
type ErrMissingPortName struct{}

func (e ErrMissingPortName) Error() string {
	return "port name is required"
}

// ErrMissingFlowID is returned when a flow ID is required but not provided.
type ErrMissingFlowID struct{}

func (e ErrMissingFlowID) Error() string {
	return "flow ID is required"
}

// ErrMissingFlowConfig is returned when flow configuration is required but not provided.
type ErrMissingFlowConfig struct{}

func (e ErrMissingFlowConfig) Error() string {
	return "flow configuration is required"
}

// ErrMissingVLANConfig is returned when VLAN configuration is required but not provided.
type ErrMissingVLANConfig struct{}

func (e ErrMissingVLANConfig) Error() string {
	return "VLAN configuration is required"
}

// ErrInvalidVLANID is returned when an invalid VLAN ID is provided.
type ErrInvalidVLANID struct{}

func (e ErrInvalidVLANID) Error() string {
	return "VLAN ID must be between 1 and 4094"
}

// ErrMissingPortCertificate is returned when a certificate is required but not provided for port auth.
type ErrMissingPortCertificate struct{}

func (e ErrMissingPortCertificate) Error() string {
	return "certificate is required"
}

// ErrInvalidPortCertificateFormat is returned when the certificate format is invalid for port auth.
type ErrInvalidPortCertificateFormat struct{}

func (e ErrInvalidPortCertificateFormat) Error() string {
	return "invalid certificate format"
}

// SDNGRPCService implements the gRPC SDNService server interface.
// It wraps the SDNService interface to provide gRPC access to SDN operations.
type SDNGRPCService struct {
	platformv1.UnimplementedSDNServiceServer
	logger  *logging.Logger
	service SDNService
	zoneSvc gateway.ZoneService

	// In-memory storage for entities not directly mapped to OVS
	mu          sync.RWMutex
	bridges     map[string]*platformv1.Bridge
	ports       map[string]*platformv1.Port
	flows       map[string]*platformv1.Flow
	vlans       map[string]*platformv1.VLAN
	portAuth    map[string]*platformv1.PortAuth
	flowLogSubs map[string]chan *platformv1.FlowLogEntry
	bridgeIDGen uint64
	portIDGen   uint64
	flowIDGen   uint64
	vlanIDGen   uint64
}

// NewSDNGRPCService creates a new SDNGRPCService instance.
func NewSDNGRPCService(
	logger *logging.Logger,
	service SDNService,
) *SDNGRPCService {
	return &SDNGRPCService{
		logger:      logger,
		service:     service,
		bridges:     make(map[string]*platformv1.Bridge),
		ports:       make(map[string]*platformv1.Port),
		flows:       make(map[string]*platformv1.Flow),
		vlans:       make(map[string]*platformv1.VLAN),
		portAuth:    make(map[string]*platformv1.PortAuth),
		flowLogSubs: make(map[string]chan *platformv1.FlowLogEntry),
	}
}

// CreateBridge creates a new bridge.
func (s *SDNGRPCService) CreateBridge(
	ctx context.Context,
	req *platformv1.CreateBridgeRequest,
) (*platformv1.CreateBridgeResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilSDNService{}.Error())
	}

	if req.GetConfig() == nil {
		return nil, status.Error(codes.InvalidArgument, ErrMissingBridgeConfig{}.Error())
	}

	if req.GetConfig().GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingBridgeName{}.Error())
	}

	ovsBridge, err := s.service.CreateBridge(ctx, req.GetConfig().GetName())
	if err != nil {
		return nil, s.mapError("CreateBridge", err)
	}

	now := timestamppb.Now()
	s.mu.Lock()
	s.bridgeIDGen++
	bridgeID := ovsBridge.UUID
	if bridgeID == "" {
		bridgeID = req.GetConfig().GetName()
	}

	bridge := &platformv1.Bridge{
		Id:        bridgeID,
		Config:    req.GetConfig(),
		Status:    platformv1.BridgeStatus_BRIDGE_STATUS_UP,
		CreatedAt: now,
		UpdatedAt: now,
		Ports:     []*platformv1.Port{},
		Stats:     &platformv1.BridgeStats{},
	}
	s.bridges[bridgeID] = bridge
	s.mu.Unlock()

	return &platformv1.CreateBridgeResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "bridge created successfully",
		},
		Bridge: bridge,
	}, nil
}

// DeleteBridge deletes a bridge.
func (s *SDNGRPCService) DeleteBridge(
	ctx context.Context,
	req *platformv1.DeleteBridgeRequest,
) (*platformv1.DeleteBridgeResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilSDNService{}.Error())
	}

	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingBridgeID{}.Error())
	}

	s.mu.RLock()
	bridge, exists := s.bridges[req.GetId()]
	s.mu.RUnlock()

	bridgeName := req.GetId()
	if exists && bridge.GetConfig() != nil {
		bridgeName = bridge.GetConfig().GetName()
	}

	if err := s.service.DeleteBridge(ctx, bridgeName); err != nil {
		return nil, s.mapError("DeleteBridge", err)
	}

	s.mu.Lock()
	delete(s.bridges, req.GetId())
	// Clean up associated ports
	for portID, port := range s.ports {
		if port.GetBridgeId() == req.GetId() {
			delete(s.ports, portID)
		}
	}
	// Clean up associated flows
	for flowID, flow := range s.flows {
		if flow.GetConfig() != nil && flow.GetConfig().GetBridgeId() == req.GetId() {
			delete(s.flows, flowID)
		}
	}
	s.mu.Unlock()

	return &platformv1.DeleteBridgeResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "bridge deleted successfully",
		},
	}, nil
}

// GetBridge retrieves a bridge by ID.
func (s *SDNGRPCService) GetBridge(
	ctx context.Context,
	req *platformv1.GetBridgeRequest,
) (*platformv1.GetBridgeResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilSDNService{}.Error())
	}

	if req.GetId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingBridgeID{}.Error())
	}

	ovsBridge, err := s.service.GetBridge(ctx, req.GetId())
	if err != nil {
		return nil, s.mapError("GetBridge", err)
	}

	s.mu.RLock()
	bridge, exists := s.bridges[req.GetId()]
	s.mu.RUnlock()

	if !exists {
		bridge = s.ovsBridgeToProto(ovsBridge)
	} else {
		bridge = s.mergeBridgeWithOVS(bridge, ovsBridge)
	}

	return &platformv1.GetBridgeResponse{
		Bridge: bridge,
	}, nil
}

// ListBridges lists all bridges.
func (s *SDNGRPCService) ListBridges(
	ctx context.Context,
	req *platformv1.ListBridgesRequest,
) (*platformv1.ListBridgesResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilSDNService{}.Error())
	}

	ovsBridges, err := s.service.ListBridges(ctx)
	if err != nil {
		return nil, s.mapError("ListBridges", err)
	}

	bridges := make([]*platformv1.Bridge, 0, len(ovsBridges))
	s.mu.RLock()
	for _, ovsBridge := range ovsBridges {
		bridgeID := ovsBridge.UUID
		if bridgeID == "" {
			bridgeID = ovsBridge.Name
		}

		if cached, exists := s.bridges[bridgeID]; exists {
			bridges = append(bridges, s.mergeBridgeWithOVS(cached, ovsBridge))
		} else {
			bridges = append(bridges, s.ovsBridgeToProto(ovsBridge))
		}
	}
	s.mu.RUnlock()

	// Apply pagination if requested
	totalItems := uint64(len(bridges))
	page := req.GetPagination().GetPage()
	pageSize := req.GetPagination().GetPageSize()
	if pageSize > 0 {
		start := page * pageSize
		if uint64(start) < totalItems {
			end := start + pageSize
			if uint64(end) > totalItems {
				end = uint32(totalItems)
			}
			bridges = bridges[start:end]
		} else {
			bridges = []*platformv1.Bridge{}
		}
	}

	return &platformv1.ListBridgesResponse{
		Bridges: bridges,
		Pagination: &platformv1.PaginationResponse{
			Page:       page,
			PageSize:   pageSize,
			TotalItems: totalItems,
		},
	}, nil
}

// AddPort adds a port to a bridge.
func (s *SDNGRPCService) AddPort(
	ctx context.Context,
	req *platformv1.AddPortRequest,
) (*platformv1.AddPortResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilSDNService{}.Error())
	}

	if req.GetBridgeId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingBridgeID{}.Error())
	}

	if req.GetConfig() == nil {
		return nil, status.Error(codes.InvalidArgument, ErrMissingPortConfig{}.Error())
	}

	if req.GetConfig().GetName() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingPortName{}.Error())
	}

	// Get bridge name from cache or use ID as name
	s.mu.RLock()
	bridge, exists := s.bridges[req.GetBridgeId()]
	s.mu.RUnlock()

	bridgeName := req.GetBridgeId()
	if exists && bridge.GetConfig() != nil {
		bridgeName = bridge.GetConfig().GetName()
	}

	ovsPort, err := s.service.AddPort(ctx, bridgeName, req.GetConfig().GetName())
	if err != nil {
		return nil, s.mapError("AddPort", err)
	}

	now := timestamppb.Now()
	s.mu.Lock()
	s.portIDGen++
	portID := ovsPort.UUID
	if portID == "" {
		portID = req.GetConfig().GetName()
	}

	port := &platformv1.Port{
		Id:        portID,
		BridgeId:  req.GetBridgeId(),
		Config:    req.GetConfig(),
		Status:    platformv1.PortStatus_PORT_STATUS_UP,
		CreatedAt: now,
		UpdatedAt: now,
		Stats:     &platformv1.PortStats{},
	}
	s.ports[portID] = port

	// Update bridge with port
	if exists {
		bridge.Ports = append(bridge.Ports, port)
		if bridge.Stats != nil {
			bridge.Stats.TotalPorts++
		}
	}
	s.mu.Unlock()

	return &platformv1.AddPortResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "port added successfully",
		},
		Port: port,
	}, nil
}

// DeletePort removes a port from a bridge.
func (s *SDNGRPCService) DeletePort(
	ctx context.Context,
	req *platformv1.DeletePortRequest,
) (*platformv1.DeletePortResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilSDNService{}.Error())
	}

	if req.GetBridgeId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingBridgeID{}.Error())
	}

	if req.GetPortId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingPortID{}.Error())
	}

	// Get bridge name from cache or use ID as name
	s.mu.RLock()
	bridge, bridgeExists := s.bridges[req.GetBridgeId()]
	port, portExists := s.ports[req.GetPortId()]
	s.mu.RUnlock()

	bridgeName := req.GetBridgeId()
	if bridgeExists && bridge.GetConfig() != nil {
		bridgeName = bridge.GetConfig().GetName()
	}

	portName := req.GetPortId()
	if portExists && port.GetConfig() != nil {
		portName = port.GetConfig().GetName()
	}

	if err := s.service.RemovePort(ctx, bridgeName, portName); err != nil {
		return nil, s.mapError("DeletePort", err)
	}

	s.mu.Lock()
	delete(s.ports, req.GetPortId())
	delete(s.portAuth, req.GetPortId())

	// Update bridge ports list
	if bridgeExists {
		newPorts := make([]*platformv1.Port, 0)
		for _, p := range bridge.Ports {
			if p.GetId() != req.GetPortId() {
				newPorts = append(newPorts, p)
			}
		}
		bridge.Ports = newPorts
		if bridge.Stats != nil && bridge.Stats.TotalPorts > 0 {
			bridge.Stats.TotalPorts--
		}
	}
	s.mu.Unlock()

	return &platformv1.DeletePortResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "port deleted successfully",
		},
	}, nil
}

// GetPort retrieves a port by ID.
func (s *SDNGRPCService) GetPort(
	ctx context.Context,
	req *platformv1.GetPortRequest,
) (*platformv1.GetPortResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilSDNService{}.Error())
	}

	if req.GetPortId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingPortID{}.Error())
	}

	ovsPort, err := s.service.GetPort(ctx, req.GetPortId())
	if err != nil {
		return nil, s.mapError("GetPort", err)
	}

	s.mu.RLock()
	port, exists := s.ports[req.GetPortId()]
	auth := s.portAuth[req.GetPortId()]
	s.mu.RUnlock()

	if !exists {
		port = s.ovsPortToProto(ovsPort, req.GetBridgeId())
	} else {
		port = s.mergePortWithOVS(port, ovsPort)
	}

	if auth != nil {
		port.Auth = auth
	}

	return &platformv1.GetPortResponse{
		Port: port,
	}, nil
}

// ListPorts lists all ports on a bridge.
func (s *SDNGRPCService) ListPorts(
	ctx context.Context,
	req *platformv1.ListPortsRequest,
) (*platformv1.ListPortsResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilSDNService{}.Error())
	}

	if req.GetBridgeId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingBridgeID{}.Error())
	}

	// Get bridge name from cache or use ID as name
	s.mu.RLock()
	bridge, exists := s.bridges[req.GetBridgeId()]
	s.mu.RUnlock()

	bridgeName := req.GetBridgeId()
	if exists && bridge.GetConfig() != nil {
		bridgeName = bridge.GetConfig().GetName()
	}

	ovsPorts, err := s.service.ListPorts(ctx, bridgeName)
	if err != nil {
		return nil, s.mapError("ListPorts", err)
	}

	ports := make([]*platformv1.Port, 0, len(ovsPorts))
	s.mu.RLock()
	for _, ovsPort := range ovsPorts {
		portID := ovsPort.UUID
		if portID == "" {
			portID = ovsPort.Name
		}

		if cached, cacheExists := s.ports[portID]; cacheExists {
			port := s.mergePortWithOVS(cached, ovsPort)
			if auth, authExists := s.portAuth[portID]; authExists {
				port.Auth = auth
			}
			ports = append(ports, port)
		} else {
			ports = append(ports, s.ovsPortToProto(ovsPort, req.GetBridgeId()))
		}
	}
	s.mu.RUnlock()

	// Apply pagination if requested
	totalItems := uint64(len(ports))
	page := req.GetPagination().GetPage()
	pageSize := req.GetPagination().GetPageSize()
	if pageSize > 0 {
		start := page * pageSize
		if uint64(start) < totalItems {
			end := start + pageSize
			if uint64(end) > totalItems {
				end = uint32(totalItems)
			}
			ports = ports[start:end]
		} else {
			ports = []*platformv1.Port{}
		}
	}

	return &platformv1.ListPortsResponse{
		Ports: ports,
		Pagination: &platformv1.PaginationResponse{
			Page:       page,
			PageSize:   pageSize,
			TotalItems: totalItems,
		},
	}, nil
}

// AddFlow adds a flow rule to a bridge.
func (s *SDNGRPCService) AddFlow(
	ctx context.Context,
	req *platformv1.AddFlowRequest,
) (*platformv1.AddFlowResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilSDNService{}.Error())
	}

	if req.GetConfig() == nil {
		return nil, status.Error(codes.InvalidArgument, ErrMissingFlowConfig{}.Error())
	}

	if req.GetConfig().GetBridgeId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingBridgeID{}.Error())
	}

	// Get bridge name from cache or use ID as name
	s.mu.RLock()
	bridge, exists := s.bridges[req.GetConfig().GetBridgeId()]
	s.mu.RUnlock()

	bridgeName := req.GetConfig().GetBridgeId()
	if exists && bridge.GetConfig() != nil {
		bridgeName = bridge.GetConfig().GetName()
	}

	flowMod := s.protoFlowConfigToOVS(req.GetConfig())
	if err := s.service.AddFlow(ctx, bridgeName, flowMod); err != nil {
		return nil, s.mapError("AddFlow", err)
	}

	now := timestamppb.Now()
	s.mu.Lock()
	s.flowIDGen++
	flowID := s.generateFlowID(req.GetConfig())

	flow := &platformv1.Flow{
		Id:        flowID,
		Config:    req.GetConfig(),
		CreatedAt: now,
		Stats:     &platformv1.FlowStats{},
	}
	s.flows[flowID] = flow

	// Update bridge flow count
	if exists && bridge.Stats != nil {
		bridge.Stats.TotalFlows++
	}
	s.mu.Unlock()

	return &platformv1.AddFlowResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "flow added successfully",
		},
		Flow: flow,
	}, nil
}

// DeleteFlow removes a flow rule from a bridge.
func (s *SDNGRPCService) DeleteFlow(
	ctx context.Context,
	req *platformv1.DeleteFlowRequest,
) (*platformv1.DeleteFlowResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilSDNService{}.Error())
	}

	if req.GetBridgeId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingBridgeID{}.Error())
	}

	if req.GetFlowId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingFlowID{}.Error())
	}

	// Get bridge name from cache or use ID as name
	s.mu.RLock()
	bridge, bridgeExists := s.bridges[req.GetBridgeId()]
	flow, flowExists := s.flows[req.GetFlowId()]
	s.mu.RUnlock()

	bridgeName := req.GetBridgeId()
	if bridgeExists && bridge.GetConfig() != nil {
		bridgeName = bridge.GetConfig().GetName()
	}

	match := req.GetFlowId()
	if flowExists && flow.GetConfig() != nil && flow.GetConfig().GetMatch() != nil {
		match = s.buildMatchString(flow.GetConfig().GetMatch())
	}

	if err := s.service.DeleteFlow(ctx, bridgeName, match); err != nil {
		return nil, s.mapError("DeleteFlow", err)
	}

	s.mu.Lock()
	delete(s.flows, req.GetFlowId())
	if bridgeExists && bridge.Stats != nil && bridge.Stats.TotalFlows > 0 {
		bridge.Stats.TotalFlows--
	}
	s.mu.Unlock()

	return &platformv1.DeleteFlowResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "flow deleted successfully",
		},
	}, nil
}

// ListFlows lists all flow rules on a bridge.
func (s *SDNGRPCService) ListFlows(
	ctx context.Context,
	req *platformv1.ListFlowsRequest,
) (*platformv1.ListFlowsResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilSDNService{}.Error())
	}

	if req.GetBridgeId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingBridgeID{}.Error())
	}

	// Get bridge name from cache or use ID as name
	s.mu.RLock()
	bridge, exists := s.bridges[req.GetBridgeId()]
	s.mu.RUnlock()

	bridgeName := req.GetBridgeId()
	if exists && bridge.GetConfig() != nil {
		bridgeName = bridge.GetConfig().GetName()
	}

	ovsFlows, err := s.service.ListFlows(ctx, bridgeName)
	if err != nil {
		return nil, s.mapError("ListFlows", err)
	}

	flows := make([]*platformv1.Flow, 0, len(ovsFlows))
	for _, ovsFlow := range ovsFlows {
		flows = append(flows, s.ovsFlowToProto(ovsFlow, req.GetBridgeId()))
	}

	// Apply pagination if requested
	totalItems := uint64(len(flows))
	page := req.GetPagination().GetPage()
	pageSize := req.GetPagination().GetPageSize()
	if pageSize > 0 {
		start := page * pageSize
		if uint64(start) < totalItems {
			end := start + pageSize
			if uint64(end) > totalItems {
				end = uint32(totalItems)
			}
			flows = flows[start:end]
		} else {
			flows = []*platformv1.Flow{}
		}
	}

	return &platformv1.ListFlowsResponse{
		Flows: flows,
		Pagination: &platformv1.PaginationResponse{
			Page:       page,
			PageSize:   pageSize,
			TotalItems: totalItems,
		},
	}, nil
}

// FlushFlows removes all flows from a bridge.
func (s *SDNGRPCService) FlushFlows(
	ctx context.Context,
	req *platformv1.FlushFlowsRequest,
) (*platformv1.FlushFlowsResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilSDNService{}.Error())
	}

	if req.GetBridgeId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingBridgeID{}.Error())
	}

	// Get current flow count
	s.mu.RLock()
	bridge, bridgeExists := s.bridges[req.GetBridgeId()]
	s.mu.RUnlock()

	bridgeName := req.GetBridgeId()
	if bridgeExists && bridge.GetConfig() != nil {
		bridgeName = bridge.GetConfig().GetName()
	}

	// List flows before deletion to get count
	ovsFlows, err := s.service.ListFlows(ctx, bridgeName)
	if err != nil {
		return nil, s.mapError("FlushFlows", err)
	}

	deletedCount := uint32(len(ovsFlows))

	// Delete all flows by deleting with empty match
	if err := s.service.DeleteFlow(ctx, bridgeName, ""); err != nil {
		return nil, s.mapError("FlushFlows", err)
	}

	// Clean up cached flows
	s.mu.Lock()
	for flowID, flow := range s.flows {
		if flow.GetConfig() != nil && flow.GetConfig().GetBridgeId() == req.GetBridgeId() {
			delete(s.flows, flowID)
		}
	}
	if bridgeExists && bridge.Stats != nil {
		bridge.Stats.TotalFlows = 0
	}
	s.mu.Unlock()

	return &platformv1.FlushFlowsResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "flows flushed successfully",
		},
		DeletedCount: deletedCount,
	}, nil
}

// CreateVLAN creates a VLAN on a bridge.
func (s *SDNGRPCService) CreateVLAN(
	ctx context.Context,
	req *platformv1.CreateVLANRequest,
) (*platformv1.CreateVLANResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilSDNService{}.Error())
	}

	if req.GetConfig() == nil {
		return nil, status.Error(codes.InvalidArgument, ErrMissingVLANConfig{}.Error())
	}

	if req.GetConfig().GetVlanId() == 0 || req.GetConfig().GetVlanId() > 4094 {
		return nil, status.Error(codes.InvalidArgument, ErrInvalidVLANID{}.Error())
	}

	if req.GetConfig().GetBridgeId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingBridgeID{}.Error())
	}

	// Apply VLAN to ports
	for _, portName := range req.GetConfig().GetPorts() {
		if err := s.service.SetPortVLAN(ctx, portName, int64(req.GetConfig().GetVlanId())); err != nil {
			return nil, s.mapError("CreateVLAN", err)
		}
	}

	now := timestamppb.Now()
	s.mu.Lock()
	s.vlanIDGen++
	vlanID := s.generateVLANID(req.GetConfig().GetBridgeId(), req.GetConfig().GetVlanId())

	vlan := &platformv1.VLAN{
		Id:        vlanID,
		Config:    req.GetConfig(),
		CreatedAt: now,
		Stats: &platformv1.VLANStats{
			PortCount: uint32(len(req.GetConfig().GetPorts())),
		},
	}
	s.vlans[vlanID] = vlan
	s.mu.Unlock()

	return &platformv1.CreateVLANResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "VLAN created successfully",
		},
		Vlan: vlan,
	}, nil
}

// DeleteVLAN removes a VLAN from a bridge.
func (s *SDNGRPCService) DeleteVLAN(
	ctx context.Context,
	req *platformv1.DeleteVLANRequest,
) (*platformv1.DeleteVLANResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilSDNService{}.Error())
	}

	if req.GetBridgeId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingBridgeID{}.Error())
	}

	if req.GetVlanId() == 0 || req.GetVlanId() > 4094 {
		return nil, status.Error(codes.InvalidArgument, ErrInvalidVLANID{}.Error())
	}

	vlanID := s.generateVLANID(req.GetBridgeId(), req.GetVlanId())

	s.mu.Lock()
	vlan, exists := s.vlans[vlanID]
	if exists {
		// Remove VLAN from ports by setting to 0 (untagged)
		for _, portName := range vlan.GetConfig().GetPorts() {
			if err := s.service.SetPortVLAN(ctx, portName, 0); err != nil {
				s.mu.Unlock()
				return nil, s.mapError("DeleteVLAN", err)
			}
		}
		delete(s.vlans, vlanID)
	}
	s.mu.Unlock()

	return &platformv1.DeleteVLANResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "VLAN deleted successfully",
		},
	}, nil
}

// ListVLANs lists all VLANs on a bridge.
func (s *SDNGRPCService) ListVLANs(
	ctx context.Context,
	req *platformv1.ListVLANsRequest,
) (*platformv1.ListVLANsResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilSDNService{}.Error())
	}

	if req.GetBridgeId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingBridgeID{}.Error())
	}

	vlans := make([]*platformv1.VLAN, 0)
	s.mu.RLock()
	for _, vlan := range s.vlans {
		if vlan.GetConfig() != nil && vlan.GetConfig().GetBridgeId() == req.GetBridgeId() {
			vlans = append(vlans, vlan)
		}
	}
	s.mu.RUnlock()

	return &platformv1.ListVLANsResponse{
		Vlans: vlans,
	}, nil
}

// AuthenticatePort authenticates a port using x509 certificate.
func (s *SDNGRPCService) AuthenticatePort(
	ctx context.Context,
	req *platformv1.AuthenticatePortRequest,
) (*platformv1.AuthenticatePortResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilSDNService{}.Error())
	}

	if req.GetBridgeId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingBridgeID{}.Error())
	}

	if req.GetPortId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingPortID{}.Error())
	}

	if len(req.GetCertificate()) == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrMissingPortCertificate{}.Error())
	}

	// Parse certificate
	var cert *x509.Certificate
	var err error

	certData := req.GetCertificate()
	format := req.GetFormat()

	switch format {
	case "PEM", "":
		block, _ := pem.Decode(certData)
		if block == nil {
			return nil, status.Error(codes.InvalidArgument, ErrInvalidPortCertificateFormat{}.Error())
		}
		cert, err = x509.ParseCertificate(block.Bytes)
	case "DER":
		cert, err = x509.ParseCertificate(certData)
	default:
		return nil, status.Error(codes.InvalidArgument, ErrInvalidPortCertificateFormat{}.Error())
	}

	if err != nil {
		return nil, status.Error(codes.InvalidArgument, ErrInvalidPortCertificateFormat{}.Error())
	}

	now := timestamppb.Now()
	auth := &platformv1.PortAuth{
		Authenticated:   true,
		CertificateCn:   cert.Subject.CommonName,
		Certificate:     certData,
		AuthenticatedAt: now,
		ExpiresAt:       timestamppb.New(cert.NotAfter),
		AuthorizedVlans: []uint32{},
	}

	s.mu.Lock()
	s.portAuth[req.GetPortId()] = auth
	if port, exists := s.ports[req.GetPortId()]; exists {
		port.Auth = auth
		port.Status = platformv1.PortStatus_PORT_STATUS_FORWARDING
	}
	s.mu.Unlock()

	return &platformv1.AuthenticatePortResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "port authenticated successfully",
		},
		Auth: auth,
	}, nil
}

// RevokePortAuth revokes port authentication.
func (s *SDNGRPCService) RevokePortAuth(
	ctx context.Context,
	req *platformv1.RevokePortAuthRequest,
) (*platformv1.RevokePortAuthResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilSDNService{}.Error())
	}

	if req.GetBridgeId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingBridgeID{}.Error())
	}

	if req.GetPortId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingPortID{}.Error())
	}

	s.mu.Lock()
	delete(s.portAuth, req.GetPortId())
	if port, exists := s.ports[req.GetPortId()]; exists {
		port.Auth = nil
		port.Status = platformv1.PortStatus_PORT_STATUS_BLOCKED
	}
	s.mu.Unlock()

	return &platformv1.RevokePortAuthResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "port authentication revoked",
		},
	}, nil
}

// GetPortStats retrieves statistics for a port.
func (s *SDNGRPCService) GetPortStats(
	ctx context.Context,
	req *platformv1.GetPortStatsRequest,
) (*platformv1.GetPortStatsResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilSDNService{}.Error())
	}

	if req.GetBridgeId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingBridgeID{}.Error())
	}

	if req.GetPortId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingPortID{}.Error())
	}

	// Get interface stats from OVS
	iface, err := s.service.GetInterface(ctx, req.GetPortId())
	if err != nil {
		return nil, s.mapError("GetPortStats", err)
	}

	stats := &platformv1.PortStats{}
	if iface != nil && iface.Statistics != nil {
		stats.PacketsReceived = uint64(iface.Statistics["rx_packets"])
		stats.PacketsSent = uint64(iface.Statistics["tx_packets"])
		stats.BytesReceived = uint64(iface.Statistics["rx_bytes"])
		stats.BytesSent = uint64(iface.Statistics["tx_bytes"])
		stats.Errors = uint64(iface.Statistics["rx_errors"] + iface.Statistics["tx_errors"])
		stats.Dropped = uint64(iface.Statistics["rx_dropped"] + iface.Statistics["tx_dropped"])
	}

	return &platformv1.GetPortStatsResponse{
		Stats: stats,
	}, nil
}

// GetFlowStats retrieves statistics for a flow.
func (s *SDNGRPCService) GetFlowStats(
	ctx context.Context,
	req *platformv1.GetFlowStatsRequest,
) (*platformv1.GetFlowStatsResponse, error) {

	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilSDNService{}.Error())
	}

	if req.GetBridgeId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingBridgeID{}.Error())
	}

	if req.GetFlowId() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingFlowID{}.Error())
	}

	// Get bridge name from cache or use ID as name
	s.mu.RLock()
	bridge, bridgeExists := s.bridges[req.GetBridgeId()]
	flow, flowExists := s.flows[req.GetFlowId()]
	s.mu.RUnlock()

	bridgeName := req.GetBridgeId()
	if bridgeExists && bridge.GetConfig() != nil {
		bridgeName = bridge.GetConfig().GetName()
	}

	match := req.GetFlowId()
	if flowExists && flow.GetConfig() != nil && flow.GetConfig().GetMatch() != nil {
		match = s.buildMatchString(flow.GetConfig().GetMatch())
	}

	ovsFlows, err := s.service.GetFlowStats(ctx, bridgeName, match)
	if err != nil {
		return nil, s.mapError("GetFlowStats", err)
	}

	stats := &platformv1.FlowStats{}
	if len(ovsFlows) > 0 {
		stats.PacketCount = uint64(ovsFlows[0].PacketCount)
		stats.ByteCount = uint64(ovsFlows[0].ByteCount)
		stats.DurationSeconds = uint32(ovsFlows[0].Duration)
	}

	return &platformv1.GetFlowStatsResponse{
		Stats: stats,
	}, nil
}

// StreamFlowLogs streams flow log entries.
func (s *SDNGRPCService) StreamFlowLogs(
	req *platformv1.StreamFlowLogsRequest,
	stream grpc.ServerStreamingServer[platformv1.FlowLogEntry],
) error {

	if s.service == nil {
		return status.Error(codes.FailedPrecondition, ErrNilSDNService{}.Error())
	}

	if req.GetBridgeId() == "" {
		return status.Error(codes.InvalidArgument, ErrMissingBridgeID{}.Error())
	}

	// Create subscription channel
	subID := s.generateSubscriptionID()
	logChan := make(chan *platformv1.FlowLogEntry, 100)

	s.mu.Lock()
	s.flowLogSubs[subID] = logChan
	s.mu.Unlock()

	defer func() {
		s.mu.Lock()
		delete(s.flowLogSubs, subID)
		close(logChan)
		s.mu.Unlock()
	}()

	ctx := stream.Context()
	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case entry, ok := <-logChan:
			if !ok {
				return nil
			}
			if err := stream.Send(entry); err != nil {
				return err
			}
		}
	}
}

// Helper functions

func (s *SDNGRPCService) ovsBridgeToProto(b *ovs.Bridge) *platformv1.Bridge {
	if b == nil {
		return nil
	}

	now := timestamppb.Now()
	bridgeID := b.UUID
	if bridgeID == "" {
		bridgeID = b.Name
	}

	bridgeType := platformv1.BridgeType_BRIDGE_TYPE_OVS
	if b.DatapathType == "netdev" {
		bridgeType = platformv1.BridgeType_BRIDGE_TYPE_LINUX
	}

	return &platformv1.Bridge{
		Id: bridgeID,
		Config: &platformv1.BridgeConfig{
			Name:        b.Name,
			Type:        bridgeType,
			DatapathId:  b.UUID,
			StpEnabled:  b.STP,
			Controllers: []string{},
			Options:     b.OtherConfig,
			Labels:      b.ExternalIDs,
		},
		Status:    platformv1.BridgeStatus_BRIDGE_STATUS_UP,
		CreatedAt: now,
		UpdatedAt: now,
		Ports:     []*platformv1.Port{},
		Stats: &platformv1.BridgeStats{
			TotalPorts: uint64(len(b.Ports)),
		},
	}
}

func (s *SDNGRPCService) mergeBridgeWithOVS(cached *platformv1.Bridge, ovsBridge *ovs.Bridge) *platformv1.Bridge {
	if cached == nil {
		return s.ovsBridgeToProto(ovsBridge)
	}
	if ovsBridge == nil {
		return cached
	}

	// Update with live OVS data
	cached.Stats.TotalPorts = uint64(len(ovsBridge.Ports))
	cached.UpdatedAt = timestamppb.Now()
	return cached
}

func (s *SDNGRPCService) ovsPortToProto(p *ovs.Port, bridgeID string) *platformv1.Port {
	if p == nil {
		return nil
	}

	now := timestamppb.Now()
	portID := p.UUID
	if portID == "" {
		portID = p.Name
	}

	portType := platformv1.PortType_PORT_TYPE_PHYSICAL
	if p.VLANMode == "access" || p.Tag > 0 {
		portType = platformv1.PortType_PORT_TYPE_INTERNAL
	}

	trunks := make([]uint32, len(p.Trunks))
	for i, t := range p.Trunks {
		trunks[i] = uint32(t)
	}

	return &platformv1.Port{
		Id:       portID,
		BridgeId: bridgeID,
		Config: &platformv1.PortConfig{
			Name:       p.Name,
			Type:       portType,
			Vlan:       uint32(p.Tag),
			TrunkVlans: trunks,
			MacAddress: p.MAC,
			Options:    p.OtherConfig,
			Labels:     p.ExternalIDs,
		},
		Status:    platformv1.PortStatus_PORT_STATUS_UP,
		CreatedAt: now,
		UpdatedAt: now,
		Stats:     &platformv1.PortStats{},
	}
}

func (s *SDNGRPCService) mergePortWithOVS(cached *platformv1.Port, ovsPort *ovs.Port) *platformv1.Port {
	if cached == nil {
		return s.ovsPortToProto(ovsPort, "")
	}
	if ovsPort == nil {
		return cached
	}

	// Update with live OVS data
	if cached.Config != nil {
		cached.Config.Vlan = uint32(ovsPort.Tag)
		trunks := make([]uint32, len(ovsPort.Trunks))
		for i, t := range ovsPort.Trunks {
			trunks[i] = uint32(t)
		}
		cached.Config.TrunkVlans = trunks
	}
	cached.UpdatedAt = timestamppb.Now()
	return cached
}

func (s *SDNGRPCService) ovsFlowToProto(f *ovs.Flow, bridgeID string) *platformv1.Flow {
	if f == nil {
		return nil
	}

	now := timestamppb.Now()
	flowID := f.Cookie
	if flowID == "" {
		flowID = f.Match
	}

	return &platformv1.Flow{
		Id: flowID,
		Config: &platformv1.FlowConfig{
			BridgeId: bridgeID,
			Table:    s.intToFlowTable(f.Table),
			Priority: uint32(f.Priority),
			Match: &platformv1.FlowMatch{
				Metadata: map[string]string{"raw_match": f.Match},
			},
			Actions:     []*platformv1.FlowAction{},
			IdleTimeout: uint32(f.IdleAge),
			HardTimeout: uint32(f.HardAge),
		},
		CreatedAt: now,
		Stats: &platformv1.FlowStats{
			PacketCount:     uint64(f.PacketCount),
			ByteCount:       uint64(f.ByteCount),
			DurationSeconds: uint32(f.Duration),
		},
	}
}

func (s *SDNGRPCService) protoFlowConfigToOVS(config *platformv1.FlowConfig) *ovs.FlowMod {
	if config == nil {
		return nil
	}

	return &ovs.FlowMod{
		Table:       s.flowTableToInt(config.GetTable()),
		Priority:    int(config.GetPriority()),
		Match:       s.buildMatchString(config.GetMatch()),
		Actions:     s.buildActionsString(config.GetActions()),
		Cookie:      "",
		IdleTimeout: int(config.GetIdleTimeout()),
		HardTimeout: int(config.GetHardTimeout()),
	}
}

func (s *SDNGRPCService) buildMatchString(match *platformv1.FlowMatch) string {
	if match == nil {
		return ""
	}

	parts := []string{}
	if match.GetInPort() != "" {
		parts = append(parts, "in_port="+match.GetInPort())
	}
	if match.GetVlanId() != 0 {
		parts = append(parts, "dl_vlan="+sdnItoa(int(match.GetVlanId())))
	}
	if match.GetEthSrc() != "" {
		parts = append(parts, "dl_src="+match.GetEthSrc())
	}
	if match.GetEthDst() != "" {
		parts = append(parts, "dl_dst="+match.GetEthDst())
	}
	if match.GetEthType() != 0 {
		parts = append(parts, "dl_type="+sdnItoa(int(match.GetEthType())))
	}
	if match.GetIpSrc() != "" {
		parts = append(parts, "nw_src="+match.GetIpSrc())
	}
	if match.GetIpDst() != "" {
		parts = append(parts, "nw_dst="+match.GetIpDst())
	}
	if match.GetIpProto() != 0 {
		parts = append(parts, "nw_proto="+sdnItoa(int(match.GetIpProto())))
	}
	if match.GetTcpSrc() != 0 {
		parts = append(parts, "tcp_src="+sdnItoa(int(match.GetTcpSrc())))
	}
	if match.GetTcpDst() != 0 {
		parts = append(parts, "tcp_dst="+sdnItoa(int(match.GetTcpDst())))
	}
	if match.GetUdpSrc() != 0 {
		parts = append(parts, "udp_src="+sdnItoa(int(match.GetUdpSrc())))
	}
	if match.GetUdpDst() != 0 {
		parts = append(parts, "udp_dst="+sdnItoa(int(match.GetUdpDst())))
	}

	result := ""
	for i, part := range parts {
		if i > 0 {
			result += ","
		}
		result += part
	}
	return result
}

func (s *SDNGRPCService) buildActionsString(actions []*platformv1.FlowAction) string {
	if len(actions) == 0 {
		return "NORMAL"
	}

	parts := []string{}
	for _, action := range actions {
		switch action.GetType() {
		case platformv1.FlowActionType_FLOW_ACTION_OUTPUT:
			parts = append(parts, "output:"+action.GetPort())
		case platformv1.FlowActionType_FLOW_ACTION_DROP:
			parts = append(parts, "drop")
		case platformv1.FlowActionType_FLOW_ACTION_SET_VLAN:
			parts = append(parts, "mod_vlan_vid:"+sdnItoa(int(action.GetVlanId())))
		case platformv1.FlowActionType_FLOW_ACTION_STRIP_VLAN:
			parts = append(parts, "strip_vlan")
		case platformv1.FlowActionType_FLOW_ACTION_SET_FIELD:
			parts = append(parts, "set_field:"+action.GetValue()+"->"+action.GetField())
		case platformv1.FlowActionType_FLOW_ACTION_GOTO_TABLE:
			parts = append(parts, "goto_table:"+sdnItoa(int(action.GetTableId())))
		case platformv1.FlowActionType_FLOW_ACTION_CONTROLLER:
			parts = append(parts, "CONTROLLER")
		}
	}

	result := ""
	for i, part := range parts {
		if i > 0 {
			result += ","
		}
		result += part
	}
	return result
}

func (s *SDNGRPCService) flowTableToInt(table platformv1.FlowTable) int {
	switch table {
	case platformv1.FlowTable_FLOW_TABLE_0:
		return 0
	case platformv1.FlowTable_FLOW_TABLE_1:
		return 1
	case platformv1.FlowTable_FLOW_TABLE_2:
		return 2
	case platformv1.FlowTable_FLOW_TABLE_3:
		return 3
	case platformv1.FlowTable_FLOW_TABLE_DROP:
		return 255
	default:
		return 0
	}
}

func (s *SDNGRPCService) intToFlowTable(table int) platformv1.FlowTable {
	switch table {
	case 0:
		return platformv1.FlowTable_FLOW_TABLE_0
	case 1:
		return platformv1.FlowTable_FLOW_TABLE_1
	case 2:
		return platformv1.FlowTable_FLOW_TABLE_2
	case 3:
		return platformv1.FlowTable_FLOW_TABLE_3
	case 255:
		return platformv1.FlowTable_FLOW_TABLE_DROP
	default:
		return platformv1.FlowTable_FLOW_TABLE_UNSPECIFIED
	}
}

func (s *SDNGRPCService) generateFlowID(config *platformv1.FlowConfig) string {
	if config == nil {
		return ""
	}
	return config.GetBridgeId() + "-" + sdnItoa(s.flowTableToInt(config.GetTable())) + "-" + sdnItoa(int(config.GetPriority())) + "-" + sdnItoa64(int64(s.flowIDGen))
}

func (s *SDNGRPCService) generateVLANID(bridgeID string, vlanID uint32) string {
	return bridgeID + "-vlan-" + sdnItoa(int(vlanID))
}

func (s *SDNGRPCService) generateSubscriptionID() string {
	return sdnItoa64(time.Now().UnixNano())
}

// mapError maps SDN errors to appropriate gRPC status codes.
func (s *SDNGRPCService) mapError(operation string, err error) error {
	if err == nil {
		return nil
	}

	s.logger.Error(err, "sdn operation failed", "operation", operation)

	// Check for specific SDN error types
	switch e := err.(type) {
	case ErrSDNBridgeNotFound:
		return status.Errorf(codes.NotFound, "bridge not found: %s", e.BridgeName)
	case ErrSDNPortNotFound:
		return status.Errorf(codes.NotFound, "port not found: %s", e.PortName)
	case ErrSDNBridgeAlreadyExists:
		return status.Errorf(codes.AlreadyExists, "bridge already exists: %s", e.BridgeName)
	case ErrSDNPortAlreadyExists:
		return status.Errorf(codes.AlreadyExists, "port already exists: %s", e.PortName)
	case ErrSDNInvalidRequest:
		return status.Errorf(codes.InvalidArgument, "invalid request: %s", e.Reason)
	case ErrSDNOperationFailed:
		return status.Errorf(codes.Internal, "sdn operation %s failed: %v", e.Operation, e.Cause)
	}

	// Default to internal error
	return status.Error(codes.Internal, err.Error())
}

// sdnItoa converts int to string without importing strconv
func sdnItoa(i int) string {
	if i == 0 {
		return "0"
	}

	negative := false
	if i < 0 {
		negative = true
		i = -i
	}

	digits := make([]byte, 0, 20)
	for i > 0 {
		digits = append(digits, byte('0'+i%10))
		i /= 10
	}

	if negative {
		digits = append(digits, '-')
	}

	// Reverse
	for left, right := 0, len(digits)-1; left < right; left, right = left+1, right-1 {
		digits[left], digits[right] = digits[right], digits[left]
	}

	return string(digits)
}

// sdnItoa64 converts int64 to string without importing strconv
func sdnItoa64(i int64) string {
	if i == 0 {
		return "0"
	}

	negative := false
	if i < 0 {
		negative = true
		i = -i
	}

	digits := make([]byte, 0, 20)
	for i > 0 {
		digits = append(digits, byte('0'+i%10))
		i /= 10
	}

	if negative {
		digits = append(digits, '-')
	}

	// Reverse
	for left, right := 0, len(digits)-1; left < right; left, right = left+1, right-1 {
		digits[left], digits[right] = digits[right], digits[left]
	}

	return string(digits)
}

// WithZoneService sets the ZoneService on an SDNGRPCService.
func (s *SDNGRPCService) WithZoneService(svc gateway.ZoneService) {
	s.zoneSvc = svc
}

// requireZoneService returns a gRPC error when the zone service is unavailable.
func (s *SDNGRPCService) requireZoneService() error {
	if s.zoneSvc == nil {
		return status.Error(codes.FailedPrecondition, "zone service is not available")
	}
	return nil
}

// =============================================================================
// Network Zone RPC Implementations
// =============================================================================

// CreateNetworkZone creates a new SDN network trust zone.
func (s *SDNGRPCService) CreateNetworkZone(
	ctx context.Context,
	req *platformv1.CreateNetworkZoneRequest,
) (*platformv1.CreateNetworkZoneResponse, error) {
	if err := s.requireZoneService(); err != nil {
		return nil, err
	}
	if req.GetConfig() == nil {
		return nil, status.Error(codes.InvalidArgument, "zone config is required")
	}
	cfg := protoToZoneConfig(req.GetConfig())
	rec, _, err := s.zoneSvc.Create(ctx, cfg)
	if err != nil {
		return nil, mapZoneError(err)
	}
	return &platformv1.CreateNetworkZoneResponse{
		Zone: zoneRecordToProto(rec),
	}, nil
}

// UpdateNetworkZone updates an existing SDN network trust zone.
func (s *SDNGRPCService) UpdateNetworkZone(
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
		cfg = protoToZoneConfig(req.GetConfig())
	}
	cfg.Name = zone.Zone(req.GetName())
	rec, restartRequired, err := s.zoneSvc.Update(ctx, zone.Zone(req.GetName()), cfg)
	if err != nil {
		return nil, mapZoneError(err)
	}
	pz := zoneRecordToProto(rec)
	pz.RestartRequired = restartRequired
	return &platformv1.UpdateNetworkZoneResponse{
		Zone: pz,
	}, nil
}

// DeleteNetworkZone deletes an SDN network trust zone.
func (s *SDNGRPCService) DeleteNetworkZone(
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
		return nil, mapZoneError(err)
	}
	return &platformv1.DeleteNetworkZoneResponse{
		RestartRequired: restartRequired,
	}, nil
}

// ListNetworkZones lists SDN network trust zones.
func (s *SDNGRPCService) ListNetworkZones(
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
		zones = append(zones, zoneRecordToProto(r))
	}
	return &platformv1.ListNetworkZonesResponse{
		Zones: zones,
	}, nil
}

// AssignNetworkZone assigns a network segment to a trust zone.
func (s *SDNGRPCService) AssignNetworkZone(
	ctx context.Context,
	req *platformv1.AssignNetworkZoneRequest,
) (*platformv1.AssignNetworkZoneResponse, error) {
	if err := s.requireZoneService(); err != nil {
		return nil, err
	}
	if req.GetNetwork() == "" {
		return nil, status.Error(codes.InvalidArgument, "network name is required")
	}
	if req.GetZone() == "" {
		return nil, status.Error(codes.InvalidArgument, "zone name is required")
	}
	restartRequired, err := s.zoneSvc.AssignNetwork(ctx, req.GetNetwork(), zone.Zone(req.GetZone()))
	if err != nil {
		return nil, mapZoneError(err)
	}
	return &platformv1.AssignNetworkZoneResponse{
		RestartRequired: restartRequired,
	}, nil
}

// =============================================================================
// Zone proto helpers
// =============================================================================

// protoToZoneConfig converts a protobuf NetworkZoneConfig to a zone.ZoneConfig.
func protoToZoneConfig(p *platformv1.NetworkZoneConfig) zone.ZoneConfig {
	cfg := zone.ZoneConfig{
		Name:             zone.Zone(p.GetName()),
		InternetIngress:  p.GetInternetIngress(),
		Isolate:          p.GetIsolate(),
		IsolatePerTenant: p.GetIsolatePerTenant(),
		OOB:              p.GetOob(),
		LifecycleRole:    zone.LifecycleRole(p.GetLifecycleRole()),
		Omit:             p.GetOmit(),
	}
	if len(p.GetIsolateFrom()) > 0 {
		cfg.IsolateFrom = make([]zone.Zone, 0, len(p.GetIsolateFrom()))
		for _, z := range p.GetIsolateFrom() {
			cfg.IsolateFrom = append(cfg.IsolateFrom, zone.Zone(z))
		}
	}
	if len(p.GetAllowTo()) > 0 {
		cfg.AllowTo = make([]zone.ZonePath, 0, len(p.GetAllowTo()))
		for _, pt := range p.GetAllowTo() {
			cfg.AllowTo = append(cfg.AllowTo, zone.ZonePath{
				Zone:     zone.Zone(pt.GetZone()),
				Services: pt.GetServices(),
			})
		}
	}
	return cfg
}

// zoneRecordToProto converts a gateway.ZoneRecord to a platformv1.NetworkZone.
func zoneRecordToProto(r *gateway.ZoneRecord) *platformv1.NetworkZone {
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
	return &platformv1.NetworkZone{
		Config: &platformv1.NetworkZoneConfig{
			Name:             string(r.Config.Name),
			InternetIngress:  r.Config.InternetIngress,
			IsolateFrom:      isolateFrom,
			AllowTo:          allowTo,
			Isolate:          r.Config.Isolate,
			IsolatePerTenant: r.Config.IsolatePerTenant,
			Oob:              r.Config.OOB,
			LifecycleRole:    string(r.Config.LifecycleRole),
			Omit:             r.Config.Omit,
		},
		CreatedAt: timestamppb.New(r.CreatedAt),
		UpdatedAt: timestamppb.New(r.UpdatedAt),
	}
}

// mapZoneError maps gateway.Zone*Error types to gRPC status errors.
func mapZoneError(err error) error {
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

// Ensure SDNGRPCService implements the SDNServiceServer interface.
var _ platformv1.SDNServiceServer = (*SDNGRPCService)(nil)
