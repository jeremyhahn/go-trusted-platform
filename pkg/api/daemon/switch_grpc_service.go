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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	switchmgmt "github.com/jeremyhahn/go-trusted-platform/pkg/switch"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/device"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// SwitchGRPCService implements the gRPC SwitchService.
// It delegates all operations to the SwitchServiceProvider interface
// which resolves a Manager per switch name.
type SwitchGRPCService struct {
	platformv1.UnimplementedSwitchServiceServer

	logger        *logging.Logger
	switchService device.SwitchServiceProvider
}

// NewSwitchGRPCService creates a new SwitchGRPCService.
func NewSwitchGRPCService(
	logger *logging.Logger,
	switchService device.SwitchServiceProvider,
) *SwitchGRPCService {
	return &SwitchGRPCService{
		logger:        logger,
		switchService: switchService,
	}
}

// SetSwitchService sets the switch service after construction.
func (s *SwitchGRPCService) SetSwitchService(svc device.SwitchServiceProvider) {
	s.switchService = svc
}

// ListPorts returns the status of all physical ports on the named switch.
func (s *SwitchGRPCService) ListPorts(
	ctx context.Context,
	req *platformv1.ListSwitchPortsRequest,
) (*platformv1.ListSwitchPortsResponse, error) {
	if s.switchService == nil {
		return nil, status.Error(codes.FailedPrecondition, "switch service not initialized")
	}

	switchName := req.GetSwitchName()
	if switchName == "" {
		return nil, status.Error(codes.InvalidArgument, "switch_name is required")
	}

	mgr, err := s.switchService.Manager(switchName)
	if err != nil {
		return nil, s.mapSwitchError(err, "list ports")
	}

	ports, err := mgr.ListPorts(ctx)
	if err != nil {
		s.logger.Errorf("switch grpc: list ports failed: switch=%s error=%v", switchName, err)
		return nil, status.Errorf(codes.Internal, "list ports failed: %s", err.Error())
	}

	pbPorts := make([]*platformv1.SwitchPortStatus, 0, len(ports))
	for _, p := range ports {
		pbPorts = append(pbPorts, portStatusToProto(p))
	}

	return &platformv1.ListSwitchPortsResponse{
		Ports: pbPorts,
	}, nil
}

// GetPortStatus returns the full observable state of a single port.
func (s *SwitchGRPCService) GetPortStatus(
	ctx context.Context,
	req *platformv1.GetSwitchPortStatusRequest,
) (*platformv1.GetSwitchPortStatusResponse, error) {
	if s.switchService == nil {
		return nil, status.Error(codes.FailedPrecondition, "switch service not initialized")
	}

	switchName := req.GetSwitchName()
	if switchName == "" {
		return nil, status.Error(codes.InvalidArgument, "switch_name is required")
	}

	portName := req.GetPortName()
	if portName == "" {
		return nil, status.Error(codes.InvalidArgument, "port_name is required")
	}

	mgr, err := s.switchService.Manager(switchName)
	if err != nil {
		return nil, s.mapSwitchError(err, "get port status")
	}

	portStatus, err := mgr.GetPortStatus(ctx, portName)
	if err != nil {
		s.logger.Errorf("switch grpc: get port status failed: switch=%s port=%s error=%v",
			switchName, portName, err)
		return nil, s.mapPortError(err, portName)
	}

	return &platformv1.GetSwitchPortStatusResponse{
		Port: portStatusToProto(portStatus),
	}, nil
}

// SetPortVLAN moves an access-mode port to the specified VLAN.
func (s *SwitchGRPCService) SetPortVLAN(
	ctx context.Context,
	req *platformv1.SetSwitchPortVLANRequest,
) (*platformv1.SetSwitchPortVLANResponse, error) {
	if s.switchService == nil {
		return nil, status.Error(codes.FailedPrecondition, "switch service not initialized")
	}

	switchName := req.GetSwitchName()
	if switchName == "" {
		return nil, status.Error(codes.InvalidArgument, "switch_name is required")
	}

	portName := req.GetPortName()
	if portName == "" {
		return nil, status.Error(codes.InvalidArgument, "port_name is required")
	}

	vlanID := req.GetVlanId()
	if vlanID == 0 || vlanID > 4094 {
		return nil, status.Errorf(codes.InvalidArgument, "vlan_id must be between 1 and 4094, got %d", vlanID)
	}

	mgr, err := s.switchService.Manager(switchName)
	if err != nil {
		return nil, s.mapSwitchError(err, "set port vlan")
	}

	if err := mgr.SetPortVLAN(ctx, portName, uint16(vlanID)); err != nil {
		s.logger.Errorf("switch grpc: set port vlan failed: switch=%s port=%s vlan=%d error=%v",
			switchName, portName, vlanID, err)
		return nil, status.Errorf(codes.Internal, "set port vlan failed: %s", err.Error())
	}

	return &platformv1.SetSwitchPortVLANResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "port VLAN updated successfully",
		},
	}, nil
}

// EnablePort administratively enables a port.
func (s *SwitchGRPCService) EnablePort(
	ctx context.Context,
	req *platformv1.EnableSwitchPortRequest,
) (*platformv1.EnableSwitchPortResponse, error) {
	if s.switchService == nil {
		return nil, status.Error(codes.FailedPrecondition, "switch service not initialized")
	}

	switchName := req.GetSwitchName()
	if switchName == "" {
		return nil, status.Error(codes.InvalidArgument, "switch_name is required")
	}

	portName := req.GetPortName()
	if portName == "" {
		return nil, status.Error(codes.InvalidArgument, "port_name is required")
	}

	mgr, err := s.switchService.Manager(switchName)
	if err != nil {
		return nil, s.mapSwitchError(err, "enable port")
	}

	if err := mgr.EnablePort(ctx, portName); err != nil {
		s.logger.Errorf("switch grpc: enable port failed: switch=%s port=%s error=%v",
			switchName, portName, err)
		return nil, status.Errorf(codes.Internal, "enable port failed: %s", err.Error())
	}

	return &platformv1.EnableSwitchPortResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "port enabled successfully",
		},
	}, nil
}

// DisablePort administratively shuts down a port.
func (s *SwitchGRPCService) DisablePort(
	ctx context.Context,
	req *platformv1.DisableSwitchPortRequest,
) (*platformv1.DisableSwitchPortResponse, error) {
	if s.switchService == nil {
		return nil, status.Error(codes.FailedPrecondition, "switch service not initialized")
	}

	switchName := req.GetSwitchName()
	if switchName == "" {
		return nil, status.Error(codes.InvalidArgument, "switch_name is required")
	}

	portName := req.GetPortName()
	if portName == "" {
		return nil, status.Error(codes.InvalidArgument, "port_name is required")
	}

	mgr, err := s.switchService.Manager(switchName)
	if err != nil {
		return nil, s.mapSwitchError(err, "disable port")
	}

	if err := mgr.DisablePort(ctx, portName); err != nil {
		s.logger.Errorf("switch grpc: disable port failed: switch=%s port=%s error=%v",
			switchName, portName, err)
		return nil, status.Errorf(codes.Internal, "disable port failed: %s", err.Error())
	}

	return &platformv1.DisableSwitchPortResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "port disabled successfully",
		},
	}, nil
}

// portStatusToProto converts a switchmgmt.PortStatus to a protobuf SwitchPortStatus.
func portStatusToProto(ps *switchmgmt.PortStatus) *platformv1.SwitchPortStatus {
	if ps == nil {
		return nil
	}

	trunkVLANs := make([]uint32, 0, len(ps.TrunkVLANs))
	for _, v := range ps.TrunkVLANs {
		trunkVLANs = append(trunkVLANs, uint32(v))
	}

	return &platformv1.SwitchPortStatus{
		Port:        ps.Port,
		Mode:        string(ps.Mode),
		AccessVlan:  uint32(ps.AccessVLAN),
		TrunkVlans:  trunkVLANs,
		Enabled:     ps.Enabled,
		LinkUp:      ps.LinkUp,
		Description: ps.Description,
	}
}

// mapSwitchError maps switch service errors to gRPC status errors.
func (s *SwitchGRPCService) mapSwitchError(err error, operation string) error {
	if err == nil {
		return nil
	}

	switch err.(type) {
	case switchmgmt.ErrManagerNotFound:
		return status.Errorf(codes.NotFound, "switch not found: %s", err.Error())
	default:
		return status.Errorf(codes.Internal, "failed to %s: %s", operation, err.Error())
	}
}

// mapPortError maps port-related errors to gRPC status errors.
func (s *SwitchGRPCService) mapPortError(err error, portName string) error {
	if err == nil {
		return nil
	}

	switch err.(type) {
	case switchmgmt.ErrPortNotFound:
		return status.Errorf(codes.NotFound, "port %q not found", portName)
	default:
		return status.Errorf(codes.Internal, "port operation failed: %s", err.Error())
	}
}
