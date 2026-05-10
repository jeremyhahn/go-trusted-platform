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

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// PIVGRPCService implements the PIV gRPC service.
type PIVGRPCService struct {
	platformv1.UnimplementedPIVServiceServer

	logger  *logging.Logger
	service *PIVService
}

// NewPIVGRPCService constructs a new PIV gRPC service.
func NewPIVGRPCService(logger *logging.Logger, svc *PIVService) *PIVGRPCService {
	return &PIVGRPCService{logger: logger, service: svc}
}

// pivAlgorithmProtoToService maps a proto algorithm to the service-layer value.
var pivAlgorithmProtoToService = map[platformv1.PIVAlgorithm]PIVAlgorithm{
	platformv1.PIVAlgorithm_PIV_ALGORITHM_UNSPECIFIED: PIVAlgorithmUnspecified,
	platformv1.PIVAlgorithm_PIV_ALGORITHM_RSA:         PIVAlgorithmRSA,
	platformv1.PIVAlgorithm_PIV_ALGORITHM_ECDSA:       PIVAlgorithmECDSA,
	platformv1.PIVAlgorithm_PIV_ALGORITHM_ED25519:     PIVAlgorithmEd25519,
}

// pivAlgorithmServiceToProto maps a service-layer algorithm to proto.
var pivAlgorithmServiceToProto = map[PIVAlgorithm]platformv1.PIVAlgorithm{
	PIVAlgorithmUnspecified: platformv1.PIVAlgorithm_PIV_ALGORITHM_UNSPECIFIED,
	PIVAlgorithmRSA:         platformv1.PIVAlgorithm_PIV_ALGORITHM_RSA,
	PIVAlgorithmECDSA:       platformv1.PIVAlgorithm_PIV_ALGORITHM_ECDSA,
	PIVAlgorithmEd25519:     platformv1.PIVAlgorithm_PIV_ALGORITHM_ED25519,
}

// pivErrorToGRPC translates PIV service errors to gRPC status.
func pivErrorToGRPC(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, ErrPIVNotConfigured):
		return status.Error(codes.Unavailable, err.Error())
	case errors.Is(err, ErrPIVSlotRequired),
		errors.Is(err, ErrPIVDeviceRequired),
		errors.Is(err, ErrPIVPayloadRequired),
		errors.Is(err, ErrPIVPrivateKeyRequired):
		return status.Error(codes.InvalidArgument, err.Error())
	}
	return status.Error(codes.Internal, err.Error())
}

func pivDeviceToProto(d PIVDevice) *platformv1.PIVDevice {
	return &platformv1.PIVDevice{
		Id:              d.ID,
		Name:            d.Name,
		Manufacturer:    d.Manufacturer,
		Model:           d.Model,
		Serial:          d.Serial,
		FirmwareVersion: d.FirmwareVersion,
	}
}

func pivSlotToProto(sl PIVSlot) *platformv1.PIVSlot {
	return &platformv1.PIVSlot{
		Id:             sl.ID,
		Name:           sl.Name,
		Algorithm:      pivAlgorithmServiceToProto[sl.Algorithm],
		HasKey:         sl.HasKey,
		HasCertificate: sl.HasCertificate,
	}
}

// ListDevices implements platformv1.PIVServiceServer.
func (s *PIVGRPCService) ListDevices(ctx context.Context, _ *platformv1.PIVListDevicesRequest) (*platformv1.PIVListDevicesResponse, error) {
	devices, err := s.service.ListDevices(ctx)
	if err != nil {
		return nil, pivErrorToGRPC(err)
	}
	resp := &platformv1.PIVListDevicesResponse{
		Devices: make([]*platformv1.PIVDevice, 0, len(devices)),
	}
	for _, d := range devices {
		resp.Devices = append(resp.Devices, pivDeviceToProto(d))
	}
	return resp, nil
}

// ListSlots implements platformv1.PIVServiceServer.
func (s *PIVGRPCService) ListSlots(ctx context.Context, req *platformv1.PIVListSlotsRequest) (*platformv1.PIVListSlotsResponse, error) {
	slots, err := s.service.ListSlots(ctx, req.GetDevice())
	if err != nil {
		return nil, pivErrorToGRPC(err)
	}
	resp := &platformv1.PIVListSlotsResponse{
		Slots: make([]*platformv1.PIVSlot, 0, len(slots)),
	}
	for _, sl := range slots {
		resp.Slots = append(resp.Slots, pivSlotToProto(sl))
	}
	return resp, nil
}

// SlotInfo implements platformv1.PIVServiceServer.
func (s *PIVGRPCService) SlotInfo(ctx context.Context, req *platformv1.PIVSlotInfoRequest) (*platformv1.PIVSlotInfoResponse, error) {
	out, err := s.service.SlotInfo(ctx, req.GetDevice(), req.GetSlot())
	if err != nil {
		return nil, pivErrorToGRPC(err)
	}
	return &platformv1.PIVSlotInfoResponse{
		Slot:           pivSlotToProto(out.Slot),
		PublicKeyPem:   out.PublicKeyPEM,
		CertificatePem: out.CertificatePEM,
	}, nil
}

// Generate implements platformv1.PIVServiceServer.
func (s *PIVGRPCService) Generate(ctx context.Context, req *platformv1.PIVGenerateRequest) (*platformv1.PIVGenerateResponse, error) {
	in := &PIVGenerateRequest{
		Slot:      req.GetSlot(),
		Algorithm: pivAlgorithmProtoToService[req.GetAlgorithm()],
		PIN:       req.GetPin(),
	}
	out, err := s.service.Generate(ctx, in)
	if err != nil {
		return nil, pivErrorToGRPC(err)
	}
	return &platformv1.PIVGenerateResponse{PublicKeyPem: out.PublicKeyPEM}, nil
}

// Import implements platformv1.PIVServiceServer.
func (s *PIVGRPCService) Import(ctx context.Context, req *platformv1.PIVImportRequest) (*platformv1.PIVImportResponse, error) {
	in := &PIVImportRequest{
		Slot:          req.GetSlot(),
		PrivateKeyPEM: req.GetPrivateKeyPem(),
		PIN:           req.GetPin(),
	}
	if err := s.service.Import(ctx, in); err != nil {
		return nil, pivErrorToGRPC(err)
	}
	return &platformv1.PIVImportResponse{Imported: true}, nil
}

// Sign implements platformv1.PIVServiceServer.
func (s *PIVGRPCService) Sign(ctx context.Context, req *platformv1.PIVSignRequest) (*platformv1.PIVSignResponse, error) {
	in := &PIVSignRequest{
		Slot:    req.GetSlot(),
		Payload: req.GetPayload(),
		PIN:     req.GetPin(),
	}
	sig, err := s.service.Sign(ctx, in)
	if err != nil {
		return nil, pivErrorToGRPC(err)
	}
	return &platformv1.PIVSignResponse{Signature: sig}, nil
}

// Attest implements platformv1.PIVServiceServer.
func (s *PIVGRPCService) Attest(ctx context.Context, req *platformv1.PIVAttestRequest) (*platformv1.PIVAttestResponse, error) {
	out, err := s.service.Attest(ctx, req.GetSlot())
	if err != nil {
		return nil, pivErrorToGRPC(err)
	}
	return &platformv1.PIVAttestResponse{
		AttestationCertPem:  out.AttestationCertPEM,
		AttestationChainPem: out.AttestationChainPEM,
	}, nil
}

// Reset implements platformv1.PIVServiceServer.
func (s *PIVGRPCService) Reset(ctx context.Context, req *platformv1.PIVResetRequest) (*platformv1.PIVResetResponse, error) {
	if err := s.service.Reset(ctx, req.GetDevice()); err != nil {
		return nil, pivErrorToGRPC(err)
	}
	return &platformv1.PIVResetResponse{Reset_: true}, nil
}
