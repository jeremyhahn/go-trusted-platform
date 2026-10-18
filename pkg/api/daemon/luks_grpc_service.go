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

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// LUKSGRPCService implements the LUKS gRPC service.
type LUKSGRPCService struct {
	platformv1.UnimplementedLUKSServiceServer

	logger  *logging.Logger
	service *LUKSService
}

// NewLUKSGRPCService constructs a new LUKS gRPC service.
func NewLUKSGRPCService(logger *logging.Logger, svc *LUKSService) *LUKSGRPCService {
	return &LUKSGRPCService{logger: logger, service: svc}
}

// luksKeyTypeServiceToProto maps a service-layer key type to proto.
var luksKeyTypeServiceToProto = map[LUKSKeyType]platformv1.LUKSKeyType{
	LUKSKeyTypeUnspecified: platformv1.LUKSKeyType_LUKS_KEY_TYPE_UNSPECIFIED,
	LUKSKeyTypePassphrase:  platformv1.LUKSKeyType_LUKS_KEY_TYPE_PASSPHRASE,
	LUKSKeyTypeFIDO2:       platformv1.LUKSKeyType_LUKS_KEY_TYPE_FIDO2,
	LUKSKeyTypeTPM:         platformv1.LUKSKeyType_LUKS_KEY_TYPE_TPM,
	LUKSKeyTypeRecovery:    platformv1.LUKSKeyType_LUKS_KEY_TYPE_RECOVERY,
}

func luksErrorToGRPC(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, ErrLUKSNotConfigured):
		return status.Error(codes.Unavailable, err.Error())
	case errors.Is(err, ErrLUKSRootRequired):
		return status.Error(codes.PermissionDenied, err.Error())
	case errors.Is(err, ErrLUKSDeviceRequired),
		errors.Is(err, ErrLUKSPassphraseRequired),
		errors.Is(err, ErrLUKSNewPassphraseRequired),
		errors.Is(err, ErrLUKSCredentialIDRequired),
		errors.Is(err, ErrLUKSSlotRequired):
		return status.Error(codes.InvalidArgument, err.Error())
	case errors.Is(err, ErrLUKSTestUnlockUnverified):
		return status.Error(codes.Unimplemented, err.Error())
	}
	return status.Error(codes.Internal, err.Error())
}

// ErrLUKSOperation carries a LUKS service error out of the MCP provider
// with the class luksErrorToGRPC gives it, so an MCP caller reads the same
// class a gRPC caller does while errors.Is still reaches the sentinel.
type ErrLUKSOperation struct {
	Cause error
}

func (e ErrLUKSOperation) Error() string {
	return e.Cause.Error()
}

func (e ErrLUKSOperation) Unwrap() error {
	return e.Cause
}

// GRPCStatus classifies the cause the way the gRPC LUKSService does.
func (e ErrLUKSOperation) GRPCStatus() *status.Status {
	return status.Convert(luksErrorToGRPC(e.Cause))
}

func luksKeyslotToProto(k LUKSKeyslot) *platformv1.LUKSKeyslot {
	return &platformv1.LUKSKeyslot{
		Slot:     k.Slot,
		Type:     luksKeyTypeServiceToProto[k.Type],
		KeySize:  k.KeySize,
		Priority: k.Priority,
	}
}

// Status implements platformv1.LUKSServiceServer.
func (s *LUKSGRPCService) Status(ctx context.Context, req *platformv1.LUKSStatusRequest) (*platformv1.LUKSStatusResponse, error) {
	out, err := s.service.Status(ctx, req.GetDevice())
	if err != nil {
		return nil, luksErrorToGRPC(err)
	}
	return &platformv1.LUKSStatusResponse{
		Device:      out.Device,
		IsLuks:      out.IsLUKS,
		Version:     out.Version,
		Uuid:        out.UUID,
		Label:       out.Label,
		Cipher:      out.Cipher,
		ActiveSlots: out.ActiveSlots,
	}, nil
}

// ListSlots implements platformv1.LUKSServiceServer.
func (s *LUKSGRPCService) ListSlots(ctx context.Context, req *platformv1.LUKSListSlotsRequest) (*platformv1.LUKSListSlotsResponse, error) {
	out, err := s.service.ListSlots(ctx, req.GetDevice())
	if err != nil {
		return nil, luksErrorToGRPC(err)
	}
	resp := &platformv1.LUKSListSlotsResponse{
		Device: out.Device,
		Slots:  make([]*platformv1.LUKSKeyslot, 0, len(out.Slots)),
	}
	for _, k := range out.Slots {
		resp.Slots = append(resp.Slots, luksKeyslotToProto(k))
	}
	return resp, nil
}

// Info implements platformv1.LUKSServiceServer.
func (s *LUKSGRPCService) Info(ctx context.Context, req *platformv1.LUKSInfoRequest) (*platformv1.LUKSInfoResponse, error) {
	out, err := s.service.Info(ctx, req.GetDevice())
	if err != nil {
		return nil, luksErrorToGRPC(err)
	}
	resp := &platformv1.LUKSInfoResponse{
		Device:       out.Device,
		Uuid:         out.UUID,
		Label:        out.Label,
		Version:      out.Version,
		Cipher:       out.Cipher,
		KeySize:      out.KeySize,
		SectorSize:   out.SectorSize,
		MetadataJson: out.MetadataJSON,
		Slots:        make([]*platformv1.LUKSKeyslot, 0, len(out.Slots)),
	}
	for _, k := range out.Slots {
		resp.Slots = append(resp.Slots, luksKeyslotToProto(k))
	}
	return resp, nil
}

// EnrollPassphrase implements platformv1.LUKSServiceServer.
func (s *LUKSGRPCService) EnrollPassphrase(ctx context.Context, req *platformv1.LUKSEnrollPassphraseRequest) (*platformv1.LUKSEnrollPassphraseResponse, error) {
	in := &LUKSEnrollPassphraseRequest{
		Device:             req.GetDevice(),
		ExistingPassphrase: req.GetExistingPassphrase(),
		NewPassphrase:      req.GetNewPassphrase(),
	}
	out, err := s.service.EnrollPassphrase(ctx, in)
	if err != nil {
		return nil, luksErrorToGRPC(err)
	}
	return &platformv1.LUKSEnrollPassphraseResponse{Slot: out.Slot}, nil
}

// EnrollFIDO2 implements platformv1.LUKSServiceServer.
func (s *LUKSGRPCService) EnrollFIDO2(ctx context.Context, req *platformv1.LUKSEnrollFIDO2Request) (*platformv1.LUKSEnrollFIDO2Response, error) {
	in := &LUKSEnrollFIDO2Request{
		Device:             req.GetDevice(),
		ExistingPassphrase: req.GetExistingPassphrase(),
		CredentialID:       req.GetCredentialId(),
		RequirePIN:         req.GetRequirePin(),
		RequireUV:          req.GetRequireUv(),
	}
	out, err := s.service.EnrollFIDO2(ctx, in)
	if err != nil {
		return nil, luksErrorToGRPC(err)
	}
	return &platformv1.LUKSEnrollFIDO2Response{Slot: out.Slot, TokenId: out.TokenID}, nil
}

// EnrollTPM implements platformv1.LUKSServiceServer.
func (s *LUKSGRPCService) EnrollTPM(ctx context.Context, req *platformv1.LUKSEnrollTPMRequest) (*platformv1.LUKSEnrollTPMResponse, error) {
	in := &LUKSEnrollTPMRequest{
		Device:             req.GetDevice(),
		ExistingPassphrase: req.GetExistingPassphrase(),
		PCRs:               req.GetPcrs(),
	}
	out, err := s.service.EnrollTPM(ctx, in)
	if err != nil {
		return nil, luksErrorToGRPC(err)
	}
	return &platformv1.LUKSEnrollTPMResponse{Slot: out.Slot, TokenId: out.TokenID}, nil
}

// EnrollRecovery implements platformv1.LUKSServiceServer.
func (s *LUKSGRPCService) EnrollRecovery(ctx context.Context, req *platformv1.LUKSEnrollRecoveryRequest) (*platformv1.LUKSEnrollRecoveryResponse, error) {
	in := &LUKSEnrollRecoveryRequest{
		Device:             req.GetDevice(),
		ExistingPassphrase: req.GetExistingPassphrase(),
	}
	out, err := s.service.EnrollRecovery(ctx, in)
	if err != nil {
		return nil, luksErrorToGRPC(err)
	}
	return &platformv1.LUKSEnrollRecoveryResponse{
		Slot:        out.Slot,
		RecoveryKey: out.RecoveryKey,
	}, nil
}

// RemoveKey implements platformv1.LUKSServiceServer.
func (s *LUKSGRPCService) RemoveKey(ctx context.Context, req *platformv1.LUKSRemoveKeyRequest) (*platformv1.LUKSRemoveKeyResponse, error) {
	in := &LUKSRemoveKeyRequest{
		Device: req.GetDevice(),
		Slot:   req.GetSlot(),
	}
	if err := s.service.RemoveKey(ctx, in); err != nil {
		return nil, luksErrorToGRPC(err)
	}
	return &platformv1.LUKSRemoveKeyResponse{Removed: true}, nil
}

// TestUnlock implements platformv1.LUKSServiceServer.
func (s *LUKSGRPCService) TestUnlock(ctx context.Context, req *platformv1.LUKSTestUnlockRequest) (*platformv1.LUKSTestUnlockResponse, error) {
	in := &LUKSTestUnlockRequest{
		Device: req.GetDevice(),
		Slot:   req.GetSlot(),
	}
	ok, err := s.service.TestUnlock(ctx, in)
	if err != nil {
		return nil, luksErrorToGRPC(err)
	}
	return &platformv1.LUKSTestUnlockResponse{Unlocked: ok}, nil
}

// ChangePassphrase implements platformv1.LUKSServiceServer.
func (s *LUKSGRPCService) ChangePassphrase(ctx context.Context, req *platformv1.LUKSChangePassphraseRequest) (*platformv1.LUKSChangePassphraseResponse, error) {
	in := &LUKSChangePassphraseRequest{
		Device:        req.GetDevice(),
		Slot:          req.GetSlot(),
		OldPassphrase: req.GetOldPassphrase(),
		NewPassphrase: req.GetNewPassphrase(),
	}
	if err := s.service.ChangePassphrase(ctx, in); err != nil {
		return nil, luksErrorToGRPC(err)
	}
	return &platformv1.LUKSChangePassphraseResponse{Changed: true}, nil
}
