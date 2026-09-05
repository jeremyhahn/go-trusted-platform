// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"log/slog"
	"strconv"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// AttestCertRecorder is the device operation behind
// DeviceService.RecordAttestationCertificate on every transport. The single
// implementation is device.AttestCertRecorder; the interface exists so the
// transports can be tested against a stand-in.
type AttestCertRecorder interface {
	Record(ctx context.Context, deviceID uint64, reissue bool) (*device.AttestCertRecord, error)
}

// WithDeviceAttestCertRecorder supplies the attestation-certificate
// recorder. Without it RecordAttestationCertificate answers Unavailable: a
// deployment with no CA has nothing to chain a certificate to.
func WithDeviceAttestCertRecorder(recorder AttestCertRecorder) DeviceGRPCOption {
	return func(s *DeviceGRPCService) { s.attestCertRecorder = recorder }
}

// newDeviceAttestCertRecorder builds the recorder from the daemon
// configuration: the device service, the platform CA and, when the
// attestation service is wired, its event log as the audit sink. It returns
// nil when the CA or the device service is absent.
func newDeviceAttestCertRecorder(config *Config, logger *slog.Logger) AttestCertRecorder {
	if config == nil || config.DeviceService == nil || config.CAService == nil {
		return nil
	}
	opts := []device.AttestCertRecorderOption{device.WithAttestCertLogger(logger)}
	if config.AttestationService != nil {
		if sink, ok := config.AttestationService.(verdict.AttestCertSink); ok {
			opts = append(opts, device.WithAttestCertAuditor(sink))
		}
	}
	recorder, err := device.NewAttestCertRecorder(config.DeviceService, config.CAService, opts...)
	if err != nil {
		// Both dependencies were checked above; a constructor error here is
		// a programming error worth a loud log, not a silent nil surface.
		if logger != nil {
			logger.Error("attestation certificate recorder could not be built", "error", err)
		}
		return nil
	}
	return recorder
}

// RecordAttestationCertificate records the device's attestation certificate
// through the shared recorder. See device.AttestCertRecorder for the
// fail-closed preflight; here the outcome is only mapped onto the wire.
func (s *DeviceGRPCService) RecordAttestationCertificate(
	ctx context.Context,
	req *platformv1.RecordAttestationCertificateRequest,
) (*platformv1.RecordAttestationCertificateResponse, error) {
	if s.attestCertRecorder == nil {
		return nil, status.Error(codes.Unavailable, "attestation certificate recording is not available: no certificate authority is configured")
	}
	if req.GetDeviceId() == "" {
		return nil, status.Error(codes.InvalidArgument, "device_id is required")
	}
	deviceID, err := strconv.ParseUint(req.GetDeviceId(), 10, 64)
	if err != nil || deviceID == 0 {
		return nil, status.Error(codes.InvalidArgument, "invalid device ID")
	}

	rec, err := s.attestCertRecorder.Record(ctx, deviceID, req.GetReissue())
	if err != nil {
		return nil, attestCertErrorToGRPC(err)
	}

	s.logger.Info("device attestation certificate recorded",
		"device_id", rec.DeviceID,
		"serial", rec.Serial,
		"source", rec.Source,
		"changed", rec.Changed,
		"reissued", rec.Reissued,
		"subject", rec.Subject,
	)

	return &platformv1.RecordAttestationCertificateResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "attestation certificate recorded",
		},
		DeviceId:          rec.DeviceID,
		Serial:            rec.Serial,
		Model:             rec.Model,
		Changed:           rec.Changed,
		Source:            string(rec.Source),
		SourceDetail:      rec.SourceDetail,
		Reissued:          rec.Reissued,
		Subject:           rec.Subject,
		CertificateSerial: rec.CertificateSerial,
		NotAfter:          timestamppb.New(rec.NotAfter),
		AttestCert:        rec.CertificatePEM,
	}, nil
}

// attestCertErrorToGRPC maps the recorder's typed errors onto gRPC codes.
// A refusal is FailedPrecondition: the request was well formed and the
// device exists, but the state of the certificates does not permit the
// write. The message carries every attempt so the operator sees why.
func attestCertErrorToGRPC(err error) error {
	if errors.Is(err, device.ErrInvalidDeviceID) {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	var revokeFailed device.ErrAttestCertReissuedRevokeFailed
	if errors.As(err, &revokeFailed) {
		// The refusal is wrapped inside, but the operator has a certificate
		// to revoke by hand: that is the actionable condition.
		return status.Error(codes.Internal, err.Error())
	}
	var (
		refused       device.ErrAttestCertRefused
		noPub         device.ErrAttestCertNoAttestPub
		badPub        device.ErrAttestCertAttestPubInvalid
		notRestricted device.ErrAttestCertPublicAreaNotRestricted
		anchor        device.ErrAttestCertTrustAnchorUnavailable
		reissue       device.ErrAttestCertReissueFailed
		write         device.ErrAttestCertWriteFailed
	)
	switch {
	case errors.As(err, &refused), errors.As(err, &noPub), errors.As(err, &badPub), errors.As(err, &notRestricted):
		return status.Error(codes.FailedPrecondition, err.Error())
	case errors.As(err, &anchor):
		return status.Error(codes.Unavailable, err.Error())
	case errors.As(err, &reissue), errors.As(err, &write):
		return status.Error(codes.Internal, err.Error())
	case containsNotFound(err.Error()):
		return status.Error(codes.NotFound, err.Error())
	default:
		return status.Error(codes.Internal, err.Error())
	}
}

// recordAttestCertForMCP is the MCP half shared by both service providers.
// It goes through the gRPC method so the argument validation, the error
// codes and the response shape are the ones every other transport uses; the
// pb response marshals with proto field names, which is what the SDK's MCP
// transport decodes.
func recordAttestCertForMCP(ctx context.Context, recorder AttestCertRecorder, deviceID string, reissue bool, logger *slog.Logger) (interface{}, error) {
	svc := &DeviceGRPCService{attestCertRecorder: recorder, logger: logger}
	if svc.logger == nil {
		svc.logger = slog.Default()
	}
	resp, err := svc.RecordAttestationCertificate(ctx, &platformv1.RecordAttestationCertificateRequest{
		DeviceId: deviceID,
		Reissue:  reissue,
	})
	if err != nil {
		return nil, err
	}
	return resp, nil
}
