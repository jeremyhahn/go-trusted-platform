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
	"net"
	"net/netip"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/overlay"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// OverlayControllerInterface abstracts overlay controller operations for testing.
type OverlayControllerInterface interface {
	// State and lifecycle
	IsRunning() bool
	GetState() *overlay.State
	GetConfig() *overlay.Config
	Uptime() time.Duration

	// VTEP operations
	ListVTEPs(ctx context.Context) ([]overlay.VTEPInfo, error)
	GetVTEP(ctx context.Context, ip netip.Addr) (*overlay.VTEPInfo, error)

	// VNI operations
	AddVNI(ctx context.Context, config *overlay.VNIConfig) error
	RemoveVNI(ctx context.Context, vni uint32) error
	ListVNIs(ctx context.Context) ([]overlay.VNIInfo, error)
	GetVNI(ctx context.Context, vni uint32) (*overlay.VNIInfo, error)

	// MAC operations
	GetRemoteMACs(ctx context.Context, vni uint32) ([]overlay.RemoteMACEntry, error)
	ForgetMAC(ctx context.Context, mac net.HardwareAddr, vni uint32) error
}

// Ensure overlay.Controller implements OverlayControllerInterface.
var _ OverlayControllerInterface = (*overlay.Controller)(nil)

// OverlayService implements the OverlayService gRPC API for overlay network operations.
type OverlayService struct {
	platformv1.UnimplementedOverlayServiceServer

	controller OverlayControllerInterface
	mu         sync.RWMutex
}

// OverlayServiceOption is a functional option for configuring the OverlayService.
type OverlayServiceOption func(*OverlayService)

// WithOverlayController sets the overlay controller for the service.
func WithOverlayController(ctrl OverlayControllerInterface) OverlayServiceOption {
	return func(s *OverlayService) {
		s.controller = ctrl
	}
}

// NewOverlayService creates a new overlay gRPC service with the given options.
func NewOverlayService(opts ...OverlayServiceOption) *OverlayService {
	svc := &OverlayService{}
	for _, opt := range opts {
		opt(svc)
	}
	return svc
}

// Controller returns the underlying overlay controller for testing purposes.
func (s *OverlayService) Controller() OverlayControllerInterface {
	return s.controller
}

// SetController sets the overlay controller (useful for testing).
func (s *OverlayService) SetController(ctrl OverlayControllerInterface) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.controller = ctrl
}

// ListVTEPs returns all known VTEP endpoints.
func (s *OverlayService) ListVTEPs(ctx context.Context, req *platformv1.ListVTEPsRequest) (*platformv1.ListVTEPsResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.controller == nil {
		return nil, status.Error(codes.Unavailable, "overlay controller not configured")
	}

	if !s.controller.IsRunning() {
		return nil, status.Error(codes.Unavailable, "overlay controller is not running")
	}

	vteps, err := s.controller.ListVTEPs(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list VTEPs: %v", err)
	}

	// Get VNIs to build a map of which VNIs each VTEP participates in
	state := s.controller.GetState()
	vtepVNIs := make(map[string][]uint32)
	if state != nil {
		for _, vni := range state.VNIs {
			// For each VTEP, add this VNI to their list
			for i := range vteps {
				vtepVNIs[vteps[i].NodeID] = append(vtepVNIs[vteps[i].NodeID], vni.VNI)
			}
		}
	}

	result := make([]*platformv1.VTEPInfo, 0, len(vteps))
	for i := range vteps {
		vnis := vtepVNIs[vteps[i].NodeID]
		if vnis == nil {
			vnis = []uint32{} // Ensure non-nil slice
		}
		result = append(result, vtepInfoToProtoWithVNIs(&vteps[i], vnis))
	}

	return &platformv1.ListVTEPsResponse{Vteps: result}, nil
}

// GetVTEP retrieves information about a specific VTEP by node ID.
func (s *OverlayService) GetVTEP(ctx context.Context, req *platformv1.GetVTEPRequest) (*platformv1.GetVTEPResponse, error) {
	if req.GetNodeId() == "" {
		return nil, status.Error(codes.InvalidArgument, "node_id is required")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.controller == nil {
		return nil, status.Error(codes.Unavailable, "overlay controller not configured")
	}

	if !s.controller.IsRunning() {
		return nil, status.Error(codes.Unavailable, "overlay controller is not running")
	}

	// List all VTEPs and find by node ID
	vteps, err := s.controller.ListVTEPs(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list VTEPs: %v", err)
	}

	// Build VNI list for the requested VTEP from state
	var vnis []uint32
	state := s.controller.GetState()
	if state != nil {
		for _, vni := range state.VNIs {
			vnis = append(vnis, vni.VNI)
		}
	}
	if vnis == nil {
		vnis = []uint32{} // Ensure non-nil slice
	}

	for i := range vteps {
		if vteps[i].NodeID == req.GetNodeId() {
			return &platformv1.GetVTEPResponse{
				Vtep: vtepInfoToProtoWithVNIs(&vteps[i], vnis),
			}, nil
		}
	}

	return nil, status.Error(codes.NotFound, "VTEP not found")
}

// CreateVNI creates a new VNI on the overlay network.
func (s *OverlayService) CreateVNI(ctx context.Context, req *platformv1.CreateVNIRequest) (*platformv1.CreateVNIResponse, error) {
	if req.GetConfig() == nil {
		return nil, status.Error(codes.InvalidArgument, "config is required")
	}

	config := req.GetConfig()
	if config.GetVni() == 0 {
		return nil, status.Error(codes.InvalidArgument, "vni is required and must be greater than 0")
	}

	if config.GetVni() > overlay.MaxVNI {
		return nil, status.Errorf(codes.InvalidArgument, "vni must not exceed %d", overlay.MaxVNI)
	}

	if config.GetVlan() > overlay.MaxVLAN {
		return nil, status.Errorf(codes.InvalidArgument, "vlan must not exceed %d", overlay.MaxVLAN)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.controller == nil {
		return nil, status.Error(codes.Unavailable, "overlay controller not configured")
	}

	if !s.controller.IsRunning() {
		return nil, status.Error(codes.Unavailable, "overlay controller is not running")
	}

	vniConfig := &overlay.VNIConfig{
		VNI:  config.GetVni(),
		VLAN: uint16(config.GetVlan()),
	}

	if err := s.controller.AddVNI(ctx, vniConfig); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to create VNI: %v", err)
	}

	// Retrieve the created VNI info
	vniInfo, err := s.controller.GetVNI(ctx, config.GetVni())
	if err != nil {
		// VNI was created but we couldn't retrieve it; return success with minimal info
		return &platformv1.CreateVNIResponse{
			Status: &platformv1.Status{
				Success: true,
				Message: "VNI created successfully",
			},
			Vni: &platformv1.VNI{
				Id:        formatVNIID(config.GetVni()),
				Config:    config,
				CreatedAt: timestamppb.Now(),
			},
		}, nil
	}

	return &platformv1.CreateVNIResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "VNI created successfully",
		},
		Vni: vniInfoToProto(vniInfo),
	}, nil
}

// DeleteVNI removes a VNI from the overlay network.
func (s *OverlayService) DeleteVNI(ctx context.Context, req *platformv1.DeleteVNIRequest) (*platformv1.DeleteVNIResponse, error) {
	if req.GetVni() == 0 {
		return nil, status.Error(codes.InvalidArgument, "vni is required and must be greater than 0")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.controller == nil {
		return nil, status.Error(codes.Unavailable, "overlay controller not configured")
	}

	if !s.controller.IsRunning() {
		return nil, status.Error(codes.Unavailable, "overlay controller is not running")
	}

	if err := s.controller.RemoveVNI(ctx, req.GetVni()); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to delete VNI: %v", err)
	}

	return &platformv1.DeleteVNIResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "VNI deleted successfully",
		},
	}, nil
}

// ListVNIs returns all configured VNIs.
func (s *OverlayService) ListVNIs(ctx context.Context, req *platformv1.ListVNIsRequest) (*platformv1.ListVNIsResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.controller == nil {
		return nil, status.Error(codes.Unavailable, "overlay controller not configured")
	}

	if !s.controller.IsRunning() {
		return nil, status.Error(codes.Unavailable, "overlay controller is not running")
	}

	vnis, err := s.controller.ListVNIs(ctx)
	if err != nil {
		return nil, status.Errorf(codes.Internal, "failed to list VNIs: %v", err)
	}

	result := make([]*platformv1.VNI, 0, len(vnis))
	for i := range vnis {
		result = append(result, vniInfoToProto(&vnis[i]))
	}

	return &platformv1.ListVNIsResponse{Vnis: result}, nil
}

// ListTunnels returns all VXLAN tunnels, optionally filtered by VNI.
func (s *OverlayService) ListTunnels(ctx context.Context, req *platformv1.ListTunnelsRequest) (*platformv1.ListTunnelsResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.controller == nil {
		return nil, status.Error(codes.Unavailable, "overlay controller not configured")
	}

	if !s.controller.IsRunning() {
		return nil, status.Error(codes.Unavailable, "overlay controller is not running")
	}

	state := s.controller.GetState()
	if state == nil {
		return &platformv1.ListTunnelsResponse{Tunnels: []*platformv1.TunnelInfo{}}, nil
	}

	result := make([]*platformv1.TunnelInfo, 0, len(state.Tunnels))
	for i := range state.Tunnels {
		tunnel := &state.Tunnels[i]
		// Filter by VNI if specified
		if req.GetVni() != 0 && tunnel.VNI != req.GetVni() {
			continue
		}
		result = append(result, tunnelInfoToProto(tunnel))
	}

	return &platformv1.ListTunnelsResponse{Tunnels: result}, nil
}

// GetTunnelStats retrieves statistics for a specific tunnel.
func (s *OverlayService) GetTunnelStats(ctx context.Context, req *platformv1.GetTunnelStatsRequest) (*platformv1.GetTunnelStatsResponse, error) {
	if req.GetRemoteVtep() == "" {
		return nil, status.Error(codes.InvalidArgument, "remote_vtep is required")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.controller == nil {
		return nil, status.Error(codes.Unavailable, "overlay controller not configured")
	}

	if !s.controller.IsRunning() {
		return nil, status.Error(codes.Unavailable, "overlay controller is not running")
	}

	state := s.controller.GetState()
	if state == nil {
		return nil, status.Error(codes.NotFound, "tunnel not found")
	}

	remoteVTEP, err := netip.ParseAddr(req.GetRemoteVtep())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid remote_vtep address: %v", err)
	}

	tunnel := findOverlayTunnel(state, remoteVTEP, req.GetVni())
	if tunnel == nil {
		return nil, status.Error(codes.NotFound, "tunnel not found")
	}

	return &platformv1.GetTunnelStatsResponse{
		Tunnel: tunnelInfoToProto(tunnel),
	}, nil
}

// findOverlayTunnel returns the first tunnel to remote that carries vni, or
// the first tunnel to remote when vni is 0. Every transport's tunnel
// statistics verb selects its tunnel here, so they all answer alike.
func findOverlayTunnel(state *overlay.State, remote netip.Addr, vni uint32) *overlay.TunnelInfo {
	if state == nil {
		return nil
	}
	for i := range state.Tunnels {
		tunnel := &state.Tunnels[i]
		if tunnel.RemoteVTEP == remote && (vni == 0 || tunnel.VNI == vni) {
			return tunnel
		}
	}
	return nil
}

// ListRemoteMACs returns learned remote MAC addresses, optionally filtered by VNI.
func (s *OverlayService) ListRemoteMACs(ctx context.Context, req *platformv1.ListRemoteMACsRequest) (*platformv1.ListRemoteMACsResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.controller == nil {
		return nil, status.Error(codes.Unavailable, "overlay controller not configured")
	}

	if !s.controller.IsRunning() {
		return nil, status.Error(codes.Unavailable, "overlay controller is not running")
	}

	state := s.controller.GetState()
	if state == nil {
		return &platformv1.ListRemoteMACsResponse{Macs: []*platformv1.RemoteMACEntry{}}, nil
	}

	result := make([]*platformv1.RemoteMACEntry, 0, len(state.RemoteMACs))
	for i := range state.RemoteMACs {
		mac := &state.RemoteMACs[i]
		// Filter by VNI if specified
		if req.GetVni() != 0 && mac.VNI != req.GetVni() {
			continue
		}
		result = append(result, remoteMACEntryToProto(mac))
	}

	return &platformv1.ListRemoteMACsResponse{Macs: result}, nil
}

// ForgetMAC removes a learned MAC address from the forwarding table.
func (s *OverlayService) ForgetMAC(ctx context.Context, req *platformv1.ForgetMACRequest) (*platformv1.ForgetMACResponse, error) {
	if req.GetMac() == "" {
		return nil, status.Error(codes.InvalidArgument, "mac is required")
	}

	if req.GetVni() == 0 {
		return nil, status.Error(codes.InvalidArgument, "vni is required and must be greater than 0")
	}

	mac, err := net.ParseMAC(req.GetMac())
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid MAC address: %v", err)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if s.controller == nil {
		return nil, status.Error(codes.Unavailable, "overlay controller not configured")
	}

	if !s.controller.IsRunning() {
		return nil, status.Error(codes.Unavailable, "overlay controller is not running")
	}

	if err := s.controller.ForgetMAC(ctx, mac, req.GetVni()); err != nil {
		return nil, status.Errorf(codes.Internal, "failed to forget MAC: %v", err)
	}

	return &platformv1.ForgetMACResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "MAC address removed successfully",
		},
	}, nil
}

// GetOverlayStatus returns the current status of the overlay network.
func (s *OverlayService) GetOverlayStatus(ctx context.Context, req *platformv1.GetOverlayStatusRequest) (*platformv1.GetOverlayStatusResponse, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	if s.controller == nil {
		return nil, status.Error(codes.Unavailable, "overlay controller not configured")
	}

	state := s.controller.GetState()
	config := s.controller.GetConfig()

	nodeID := ""
	vtepIP := ""
	var vxlanPort uint32
	var underlayMTU uint32
	if config != nil {
		nodeID = config.NodeID
		if config.VTEPIP.IsValid() {
			vtepIP = config.VTEPIP.String()
		}
		vxlanPort = uint32(config.VXLANPort)
		underlayMTU = uint32(config.UnderlayMTU)
	}

	var vtepCount, vniCount, tunnelCount, remoteMACCount uint32
	healthy := s.controller.IsRunning()

	if state != nil {
		vtepCount = uint32(len(state.VTEPs))
		vniCount = uint32(len(state.VNIs))
		tunnelCount = uint32(len(state.Tunnels))
		remoteMACCount = uint32(len(state.RemoteMACs))
	}

	return &platformv1.GetOverlayStatusResponse{
		Status: &platformv1.OverlayStatus{
			NodeId:         nodeID,
			VtepIp:         vtepIP,
			VtepCount:      vtepCount,
			VniCount:       vniCount,
			TunnelCount:    tunnelCount,
			RemoteMacCount: remoteMACCount,
			Healthy:        healthy,
			VxlanPort:      vxlanPort,
			UnderlayMtu:    underlayMTU,
		},
	}, nil
}

// Helper conversion functions

func vtepInfoToProto(v *overlay.VTEPInfo) *platformv1.VTEPInfo {
	if v == nil {
		return nil
	}
	return &platformv1.VTEPInfo{
		NodeId:   v.NodeID,
		Ip:       v.IP.String(),
		Healthy:  v.Healthy,
		LastSeen: timestamppb.New(v.LastSeen),
		Vnis:     []uint32{}, // Empty but non-nil slice
	}
}

func vtepInfoToProtoWithVNIs(v *overlay.VTEPInfo, vnis []uint32) *platformv1.VTEPInfo {
	if v == nil {
		return nil
	}
	return &platformv1.VTEPInfo{
		NodeId:   v.NodeID,
		Ip:       v.IP.String(),
		Healthy:  v.Healthy,
		LastSeen: timestamppb.New(v.LastSeen),
		Vnis:     vnis,
	}
}

func vniInfoToProto(v *overlay.VNIInfo) *platformv1.VNI {
	if v == nil {
		return nil
	}
	return &platformv1.VNI{
		Id: formatVNIID(v.VNI),
		Config: &platformv1.VNIConfig{
			Vni:  v.VNI,
			Vlan: uint32(v.VLAN),
		},
		CreatedAt: timestamppb.New(v.CreatedAt),
		MacCount:  uint32(v.MACCount),
	}
}

func tunnelInfoToProto(t *overlay.TunnelInfo) *platformv1.TunnelInfo {
	if t == nil {
		return nil
	}
	return &platformv1.TunnelInfo{
		LocalVtep:  t.LocalVTEP.String(),
		RemoteVtep: t.RemoteVTEP.String(),
		Vni:        t.VNI,
		State:      t.State.String(),
		BytesTx:    t.BytesTx,
		BytesRx:    t.BytesRx,
	}
}

func remoteMACEntryToProto(m *overlay.RemoteMACEntry) *platformv1.RemoteMACEntry {
	if m == nil {
		return nil
	}
	return &platformv1.RemoteMACEntry{
		Mac:        m.MAC.String(),
		Vni:        m.VNI,
		RemoteVtep: m.RemoteVTEP.String(),
		LearnedAt:  timestamppb.New(m.LearnedAt),
	}
}

func formatVNIID(vni uint32) string {
	// Format VNI as a string identifier
	const maxDigits = 10
	buf := make([]byte, maxDigits)
	i := len(buf)
	for vni > 0 {
		i--
		buf[i] = byte(vni%10) + '0'
		vni /= 10
	}
	if i == len(buf) {
		return "vni-0"
	}
	return "vni-" + string(buf[i:])
}
