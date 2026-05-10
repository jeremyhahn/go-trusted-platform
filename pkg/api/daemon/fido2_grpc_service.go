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
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// FIDO2GRPCService implements the FIDO2 gRPC service.
type FIDO2GRPCService struct {
	platformv1.UnimplementedFIDO2ServiceServer

	logger  *logging.Logger
	service *FIDO2Service
}

// NewFIDO2GRPCService constructs a new FIDO2 gRPC service.
func NewFIDO2GRPCService(logger *logging.Logger, svc *FIDO2Service) *FIDO2GRPCService {
	return &FIDO2GRPCService{logger: logger, service: svc}
}

// fido2RoleProtoToService maps a proto role to service-layer role.
var fido2RoleProtoToService = map[platformv1.FIDO2Role]FIDO2Role{
	platformv1.FIDO2Role_FIDO2_ROLE_UNSPECIFIED: FIDO2RoleUnspecified,
	platformv1.FIDO2Role_FIDO2_ROLE_SO:          FIDO2RoleSO,
	platformv1.FIDO2Role_FIDO2_ROLE_ADMIN:       FIDO2RoleAdmin,
	platformv1.FIDO2Role_FIDO2_ROLE_USER:        FIDO2RoleUser,
}

func fido2ErrorToGRPC(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, ErrFIDO2NotConfigured):
		return status.Error(codes.Unavailable, err.Error())
	case errors.Is(err, ErrFIDO2DeviceRequired),
		errors.Is(err, ErrFIDO2UsernameRequired),
		errors.Is(err, ErrFIDO2CredentialRequired):
		return status.Error(codes.InvalidArgument, err.Error())
	}
	return status.Error(codes.Internal, err.Error())
}

func fido2DeviceToProto(d FIDO2Device) *platformv1.FIDO2Device {
	return &platformv1.FIDO2Device{
		Id:           d.ID,
		Path:         d.Path,
		Manufacturer: d.Manufacturer,
		Product:      d.Product,
		ProductId:    d.ProductID,
		VendorId:     d.VendorID,
	}
}

// ListDevices implements platformv1.FIDO2ServiceServer.
func (s *FIDO2GRPCService) ListDevices(ctx context.Context, _ *platformv1.FIDO2ListDevicesRequest) (*platformv1.FIDO2ListDevicesResponse, error) {
	devices, err := s.service.ListDevices(ctx)
	if err != nil {
		return nil, fido2ErrorToGRPC(err)
	}
	resp := &platformv1.FIDO2ListDevicesResponse{
		Devices: make([]*platformv1.FIDO2Device, 0, len(devices)),
	}
	for _, d := range devices {
		resp.Devices = append(resp.Devices, fido2DeviceToProto(d))
	}
	return resp, nil
}

// WaitDevice implements platformv1.FIDO2ServiceServer.
func (s *FIDO2GRPCService) WaitDevice(ctx context.Context, req *platformv1.FIDO2WaitDeviceRequest) (*platformv1.FIDO2WaitDeviceResponse, error) {
	var timeout time.Duration
	if req.GetTimeoutSeconds() > 0 {
		timeout = time.Duration(req.GetTimeoutSeconds()) * time.Second
	}
	dev, err := s.service.WaitDevice(ctx, timeout)
	if err != nil {
		return nil, fido2ErrorToGRPC(err)
	}
	return &platformv1.FIDO2WaitDeviceResponse{Device: fido2DeviceToProto(*dev)}, nil
}

// Info implements platformv1.FIDO2ServiceServer.
func (s *FIDO2GRPCService) Info(ctx context.Context, req *platformv1.FIDO2InfoRequest) (*platformv1.FIDO2InfoResponse, error) {
	out, err := s.service.Info(ctx, req.GetDevice())
	if err != nil {
		return nil, fido2ErrorToGRPC(err)
	}
	return &platformv1.FIDO2InfoResponse{
		Info: &platformv1.FIDO2DeviceInfo{
			Device:          fido2DeviceToProto(out.Device),
			Aaguid:          out.AAGUID,
			FirmwareVersion: out.FirmwareVersion,
			Extensions:      out.Extensions,
			Options:         out.Options,
			MaxMsgSize:      out.MaxMsgSize,
		},
	}, nil
}

// Register implements platformv1.FIDO2ServiceServer.
func (s *FIDO2GRPCService) Register(ctx context.Context, req *platformv1.FIDO2RegisterRequest) (*platformv1.FIDO2RegisterResponse, error) {
	in := &FIDO2RegisterRequest{
		Username:   req.GetUsername(),
		Role:       fido2RoleProtoToService[req.GetRole()],
		RequirePIN: req.GetRequirePin(),
		RequireUV:  req.GetRequireUv(),
		RPID:       req.GetRpId(),
	}
	out, err := s.service.Register(ctx, in)
	if err != nil {
		return nil, fido2ErrorToGRPC(err)
	}
	return &platformv1.FIDO2RegisterResponse{
		CredentialId: out.CredentialID,
		Aaguid:       out.AAGUID,
		PublicKeyPem: out.PublicKeyPEM,
	}, nil
}

// Authenticate implements platformv1.FIDO2ServiceServer.
func (s *FIDO2GRPCService) Authenticate(ctx context.Context, req *platformv1.FIDO2AuthenticateRequest) (*platformv1.FIDO2AuthenticateResponse, error) {
	out, err := s.service.Authenticate(ctx, req.GetCredentialId())
	if err != nil {
		return nil, fido2ErrorToGRPC(err)
	}
	return &platformv1.FIDO2AuthenticateResponse{
		Authenticated: out.Authenticated,
		Counter:       out.Counter,
	}, nil
}
