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

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/calleradmission"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/reporting"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// CallerPolicyDescriber reports a node's compiled caller-admission policy.
// *calleradmission.Policy satisfies it.
type CallerPolicyDescriber interface {
	Describe() calleradmission.Description
}

// ReportingHandles is what the attestation reporting service hands the
// transports: the read-only report view, the refresh trigger and the caller
// policy. Every field is optional. None of them can reach a device — the
// Viewer and Refresher are the seams pkg/attestation/reporting keeps
// deliberately narrow, and the transports get nothing else.
type ReportingHandles struct {
	Reports   reporting.Viewer
	Refresher reporting.Refresher
	Policy    CallerPolicyDescriber
}

// reportingHandles is the atomically swapped handle set on the gRPC server.
// It is set after construction because the collector is wired after the
// gRPC services exist, and it is read on every RPC without a lock.
type reportingHandles struct {
	h *ReportingHandles
}

// SetReporting attaches (or replaces) the reporting handles. Safe to call
// while serving.
func (s *AttestationServiceServer) SetReporting(h *ReportingHandles) {
	if s == nil {
		return
	}
	s.reporting.Store(&reportingHandles{h: h})
}

func (s *AttestationServiceServer) reportingHandles() *ReportingHandles {
	if s == nil {
		return nil
	}
	v := s.reporting.Load()
	if v == nil {
		return nil
	}
	return v.h
}

// ErrReportingNotConfigured is the gRPC-facing "no reporting service on
// this node". FailedPrecondition, like the other unconfigured backends.
var errReportingNotConfigured = status.Error(codes.FailedPrecondition,
	"attestation reporting service is not configured on this node")

// GetDeviceReport implements AttestationServiceServer.
func (s *AttestationServiceServer) GetDeviceReport(_ context.Context, req *platformv1.GetDeviceReportRequest) (*platformv1.GetDeviceReportResponse, error) {
	h := s.reportingHandles()
	if h == nil || h.Reports == nil {
		return nil, errReportingNotConfigured
	}
	id := req.GetDeviceId()
	if id == "" {
		return nil, status.Error(codes.InvalidArgument, "device_id is required")
	}
	view, ok := h.Reports.View(id)
	if !ok {
		return nil, status.Errorf(codes.NotFound, "no report has been collected for device %s", id)
	}
	return &platformv1.GetDeviceReportResponse{
		Status: &platformv1.Status{Success: true, Message: "report served from cache"},
		Report: viewToProto(view),
	}, nil
}

// ListDeviceReports implements AttestationServiceServer.
func (s *AttestationServiceServer) ListDeviceReports(_ context.Context, _ *platformv1.ListDeviceReportsRequest) (*platformv1.ListDeviceReportsResponse, error) {
	h := s.reportingHandles()
	if h == nil || h.Reports == nil {
		return nil, errReportingNotConfigured
	}
	views := h.Reports.Views()
	out := make([]*platformv1.DeviceAttestationReport, 0, len(views))
	for _, v := range views {
		out = append(out, viewToProto(v))
	}
	return &platformv1.ListDeviceReportsResponse{
		Status:  &platformv1.Status{Success: true, Message: "reports served from cache"},
		Reports: out,
		Total:   int32(len(out)),
	}, nil
}

// RefreshDeviceReport implements AttestationServiceServer. It enqueues; it
// never quotes.
func (s *AttestationServiceServer) RefreshDeviceReport(_ context.Context, req *platformv1.RefreshDeviceReportRequest) (*platformv1.RefreshDeviceReportResponse, error) {
	h := s.reportingHandles()
	if h == nil || h.Refresher == nil {
		return nil, errReportingNotConfigured
	}
	id := req.GetDeviceId()
	if id == "" {
		return nil, status.Error(codes.InvalidArgument, "device_id is required")
	}
	if err := h.Refresher.Refresh(id); err != nil {
		var stopped reporting.ErrCollectorStopped
		if errors.As(err, &stopped) {
			return nil, status.Error(codes.Unavailable, err.Error())
		}
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	return &platformv1.RefreshDeviceReportResponse{
		Status:   &platformv1.Status{Success: true, Message: "collection enqueued"},
		DeviceId: id,
		Enqueued: true,
		Note:     "collection enqueued with the collector; read the report for the verdict and its age",
	}, nil
}

// DescribeCallerPolicy implements AttestationServiceServer. With no policy
// the answer is a policy that admits nobody, which is the truth.
func (s *AttestationServiceServer) DescribeCallerPolicy(_ context.Context, _ *platformv1.DescribeCallerPolicyRequest) (*platformv1.DescribeCallerPolicyResponse, error) {
	h := s.reportingHandles()
	desc := calleradmission.Description{AdmitsNobody: true}
	if h != nil && h.Policy != nil {
		desc = h.Policy.Describe()
	}
	return &platformv1.DescribeCallerPolicyResponse{
		Status: &platformv1.Status{Success: true, Message: "effective caller policy"},
		Policy: descriptionToProto(desc),
	}, nil
}

func viewToProto(v reporting.View) *platformv1.DeviceAttestationReport {
	out := &platformv1.DeviceAttestationReport{
		DeviceId:              v.DeviceID,
		Serial:                v.Serial,
		Model:                 v.Model,
		Verified:              v.Verified,
		AkCertificateVerified: v.AKCertificateVerified,
		SignatureValid:        v.SignatureValid,
		NonceValid:            v.NonceValid,
		PcrsValid:             v.PCRsValid,
		CryptographicFailure:  v.CryptographicFailure,
		PcrBaselineSource:     v.PCRBaselineSource,
		PcrBaselineCaptured:   v.PCRBaselineCaptured,
		Status:                v.Status,
		Message:               v.Message,
		Fresh:                 v.Fresh,
		AgeSeconds:            v.AgeSeconds,
		AsOf:                  timestamppb.New(v.AsOf),
		CollectedAt:           timestamppb.New(v.CollectedAt),
	}
	if !v.AttestedAt.IsZero() {
		out.AttestedAt = timestamppb.New(v.AttestedAt)
	}
	if !v.PCRBaselineRecordedAt.IsZero() {
		out.PcrBaselineRecordedAt = timestamppb.New(v.PCRBaselineRecordedAt)
	}
	return out
}

func descriptionToProto(d calleradmission.Description) *platformv1.CallerPolicyDescription {
	return &platformv1.CallerPolicyDescription{
		Strategy:               string(d.Strategy),
		Identities:             d.Identities,
		IdentitiesSource:       d.IdentitiesSource,
		ListValid:              d.ListValid,
		InvalidEntries:         d.InvalidEntries,
		AnchorsConfigured:      d.AnchorsConfigured,
		AnchorSource:           d.AnchorSource,
		AttestedPeersAvailable: d.AttestedPeersAvailable,
		AdmitsNobody:           d.AdmitsNobody,
	}
}
