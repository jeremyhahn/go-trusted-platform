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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// =============================================================================
// Helpers
// =============================================================================

// loadBMCConfigForRestorer resolves a *bmc.Config for the given profileID using
// the DeviceProfileService. It mirrors loadBMCConfig from bmc_enroll_grpc.go but
// accepts a BMCRestorer instead of a BMCEnroller for the TLS provider source.
func loadBMCConfigForRestorer(ctx context.Context, profileSvc device.DeviceProfileService, profileID uint64, restorer BMCRestorer) (*bmc.Config, error) {
	if profileSvc == nil {
		return nil, ErrBMCServiceNotConfigured{}
	}
	profile, err := profileSvc.Get(ctx, profileID)
	if err != nil {
		return nil, bmc.ErrProfileNotFound{ProfileID: profileID}
	}
	if profile.BMC == nil {
		return nil, bmc.ErrProfileNotFound{ProfileID: profileID}
	}
	var tlsProvider bmc.TLSProvider
	if restorer != nil {
		tlsProvider = restorer.BMCTLSProvider()
	}
	return profileBMCToConfig(profile, tlsProvider), nil
}

// =============================================================================
// Restore wiring on BMCGRPCService
// =============================================================================

// SetRestorer injects the BMCRestorer and DeviceProfileService into the gRPC
// service after construction. The daemon calls this once the App has been
// initialized so all four transports share the same restorer.
func (s *BMCGRPCService) SetRestorer(restorer BMCRestorer, profileSvc device.DeviceProfileService) {
	s.restorer = restorer
	if s.profileSvc == nil {
		s.profileSvc = profileSvc
	}
}

// RestoreFactoryCert performs the BMC factory-certificate restore ceremony for
// the device profile identified by req.ProfileId.
func (s *BMCGRPCService) RestoreFactoryCert(ctx context.Context, req *platformv1.BMCRestoreRequest) (*platformv1.BMCRestoreResponse, error) {
	if s.restorer == nil {
		return nil, bmcNotConfigured(ErrBMCRestorerNotConfigured{})
	}
	if req.GetProfileId() == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrInvalidProfileID{}.Error())
	}

	bmcCfg, err := loadBMCConfigForRestorer(ctx, s.profileSvc, req.GetProfileId(), s.restorer)
	if err != nil {
		return nil, s.toGRPCError("restore_factory_cert", err)
	}

	result, err := s.restorer.RestoreBMC(ctx, req.GetProfileId(), bmcCfg)
	if err != nil {
		return nil, toRestoreGRPCError(err)
	}

	return restoreResultToProto(result), nil
}

// =============================================================================
// Proto serializer
// =============================================================================

// restoreResultToProto serializes an app.BMCRestoreResult into the proto wire
// response. PEM bytes are passed through as-is; timestamps use timestamppb.
func restoreResultToProto(r *app.BMCRestoreResult) *platformv1.BMCRestoreResponse {
	if r == nil {
		return &platformv1.BMCRestoreResponse{}
	}

	meta := &platformv1.BMCFactoryCertMeta{
		Subject:      r.NewCertMeta.Subject,
		Issuer:       r.NewCertMeta.Issuer,
		SerialNumber: r.NewCertMeta.SerialNumber,
		SpkiSha256:   r.NewCertMeta.SPKISHA256,
		Sha256:       r.NewCertMeta.SHA256,
	}
	if !r.NewCertMeta.NotBefore.IsZero() {
		meta.NotBefore = timestamppb.New(r.NewCertMeta.NotBefore)
	}
	if !r.NewCertMeta.NotAfter.IsZero() {
		meta.NotAfter = timestamppb.New(r.NewCertMeta.NotAfter)
	}
	if !r.NewCertMeta.CapturedAt.IsZero() {
		meta.CapturedAt = timestamppb.New(r.NewCertMeta.CapturedAt)
	}

	steps := make([]*platformv1.BMCEnrollStep, len(r.Steps))
	for i, s := range r.Steps {
		steps[i] = &platformv1.BMCEnrollStep{
			Name:   s.Name,
			Ok:     s.OK,
			Detail: s.Detail,
		}
	}

	return &platformv1.BMCRestoreResponse{
		DeviceId:    r.DeviceID,
		Endpoint:    r.Endpoint,
		Hostname:    r.Hostname,
		NewCertMeta: meta,
		NewCertPem:  r.NewCertPEM,
		Steps:       steps,
	}
}

// =============================================================================
// Error mapping
// =============================================================================

// toRestoreGRPCError maps restore-specific errors to gRPC status codes.
// Falls through to the existing toGRPCError for generic BMC errors.
func toRestoreGRPCError(err error) error {
	if err == nil {
		return nil
	}
	var noCertRestorer app.ErrBMCRestoreNoCertRestorer
	if errors.As(err, &noCertRestorer) {
		return status.Error(codes.FailedPrecondition, noCertRestorer.Error())
	}
	var restoreCert app.ErrBMCRestoreCert
	if errors.As(err, &restoreCert) {
		return status.Error(codes.Internal, restoreCert.Error())
	}
	var devLoad app.ErrBMCEnrollDeviceLoad
	if errors.As(err, &devLoad) {
		return status.Error(codes.NotFound, devLoad.Error())
	}
	var devSave app.ErrBMCEnrollDeviceSave
	if errors.As(err, &devSave) {
		return status.Error(codes.Internal, devSave.Error())
	}
	return status.Error(codes.Internal, err.Error())
}
