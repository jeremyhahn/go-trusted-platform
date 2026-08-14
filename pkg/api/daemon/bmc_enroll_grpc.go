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
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// =============================================================================
// Enrollment wiring on BMCGRPCService
// =============================================================================

// SetEnroller injects the BMCEnroller and DeviceProfileService into the gRPC
// service after construction. The daemon calls this once the App has been
// initialized so all four transports share the same enroller.
func (s *BMCGRPCService) SetEnroller(enroller BMCEnroller, profileSvc device.DeviceProfileService) {
	s.enroller = enroller
	s.profileSvc = profileSvc
}

// EnrollBMC performs the BMC enrollment ceremony for the device profile.
func (s *BMCGRPCService) EnrollBMC(ctx context.Context, req *platformv1.BMCEnrollRequest) (*platformv1.BMCEnrollResponse, error) {
	if s.enroller == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBMCEnrollerNotConfigured{}.Error())
	}
	if req.GetProfileId() == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrInvalidProfileID{}.Error())
	}

	bmcCfg, err := loadBMCConfig(ctx, s.profileSvc, req.GetProfileId(), s.enroller)
	if err != nil {
		return nil, s.toGRPCError("enroll_bmc", err)
	}

	opts := protoEnrollOptsToApp(req)
	result, err := s.enroller.EnrollBMC(ctx, req.GetProfileId(), bmcCfg, opts)
	if err != nil {
		return nil, s.toGRPCError("enroll_bmc", err)
	}

	return enrollResultToProto(result), nil
}

// =============================================================================
// Helpers shared across transports
// =============================================================================

// loadBMCConfig resolves a *bmc.Config for the given profileID using the
// DeviceProfileService. When profileSvc is nil (daemon started without a
// device profile service), returns ErrBMCServiceNotConfigured.
func loadBMCConfig(ctx context.Context, profileSvc device.DeviceProfileService, profileID uint64, enroller BMCEnroller) (*bmc.Config, error) {
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
	if enroller != nil {
		tlsProvider = enroller.BMCTLSProvider()
	}
	return profileBMCToConfig(profile, tlsProvider), nil
}

// protoEnrollOptsToApp converts the optional proto booleans in
// BMCEnrollRequest into app.BMCEnrollOptions. Only non-nil pointer
// fields are passed through so profile defaults remain in effect when
// the caller omits a flag.
func protoEnrollOptsToApp(req *platformv1.BMCEnrollRequest) *app.BMCEnrollOptions {
	opts := &app.BMCEnrollOptions{}
	if req.ReplaceCertificate != nil {
		v := req.GetReplaceCertificate()
		opts.ReplaceCertificate = &v
	}
	if req.RotatePassword != nil {
		v := req.GetRotatePassword()
		opts.RotatePassword = &v
	}
	if req.DnsRegister != nil {
		v := req.GetDnsRegister()
		opts.DNSRegister = &v
	}
	if req.DanePublish != nil {
		v := req.GetDanePublish()
		opts.DANEPublish = &v
	}
	return opts
}

// enrollResultToProto serializes an app.BMCEnrollResult into the proto wire
// response. PEM bytes are passed through as-is; timestamps use timestamppb.
func enrollResultToProto(r *app.BMCEnrollResult) *platformv1.BMCEnrollResponse {
	if r == nil {
		return &platformv1.BMCEnrollResponse{}
	}

	meta := &platformv1.BMCFactoryCertMeta{
		Subject:      r.FactoryCertMeta.Subject,
		Issuer:       r.FactoryCertMeta.Issuer,
		SerialNumber: r.FactoryCertMeta.SerialNumber,
		SpkiSha256:   r.FactoryCertMeta.SPKISHA256,
		Sha256:       r.FactoryCertMeta.SHA256,
	}
	if !r.FactoryCertMeta.NotBefore.IsZero() {
		meta.NotBefore = timestamppb.New(r.FactoryCertMeta.NotBefore)
	}
	if !r.FactoryCertMeta.NotAfter.IsZero() {
		meta.NotAfter = timestamppb.New(r.FactoryCertMeta.NotAfter)
	}
	if !r.FactoryCertMeta.CapturedAt.IsZero() {
		meta.CapturedAt = timestamppb.New(r.FactoryCertMeta.CapturedAt)
	}

	steps := make([]*platformv1.BMCEnrollStep, len(r.Steps))
	for i, s := range r.Steps {
		steps[i] = &platformv1.BMCEnrollStep{
			Name:   s.Name,
			Ok:     s.OK,
			Detail: s.Detail,
		}
	}

	return &platformv1.BMCEnrollResponse{
		DeviceId:        r.DeviceID,
		Endpoint:        r.Endpoint,
		Hostname:        r.Hostname,
		DnsName:         r.DNSName,
		PinSpkiSha256:   r.PinSPKISHA256,
		FactoryCertPem:  r.FactoryCertPEM,
		FactoryCertMeta: meta,
		NewCertPem:      r.NewCertPEM,
		CaCertPem:       r.CACertPEM,
		Steps:           steps,
	}
}
