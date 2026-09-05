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
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/calleradmission"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/reporting"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

type stubRefresh struct {
	ids []string
	err error
}

func (s *stubRefresh) Refresh(id string) error {
	s.ids = append(s.ids, id)
	return s.err
}

type stubDescriber struct{ d calleradmission.Description }

func (s stubDescriber) Describe() calleradmission.Description { return s.d }

func reportingCache(t *testing.T) *reporting.Cache {
	t.Helper()
	c := reporting.NewCache(time.Hour)
	c.Store(&reporting.Report{DeviceID: "42", Serial: "SN-42", Verified: true, Status: "verified", PCRBaselineSource: "signed",
		PCRBaselineRecordedAt: time.Unix(1_700_000_000, 0).UTC(), AttestedAt: time.Now().Add(-time.Minute), CollectedAt: time.Now().Add(-time.Minute)})
	c.Store(&reporting.Report{DeviceID: "7", Verified: false, Cryptographic: true, Status: "failed", Message: "nonce", CollectedAt: time.Now().Add(-3 * time.Hour)})
	return c
}

func TestAttestationReporting_NotConfiguredIsFailedPrecondition(t *testing.T) {
	s := NewAttestationServiceServer(nil, slog.Default())
	_, err := s.GetDeviceReport(context.Background(), &platformv1.GetDeviceReportRequest{DeviceId: "1"})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	_, err = s.ListDeviceReports(context.Background(), &platformv1.ListDeviceReportsRequest{})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	_, err = s.RefreshDeviceReport(context.Background(), &platformv1.RefreshDeviceReportRequest{DeviceId: "1"})
	assert.Equal(t, codes.FailedPrecondition, status.Code(err))
	resp, err := s.DescribeCallerPolicy(context.Background(), &platformv1.DescribeCallerPolicyRequest{})
	require.NoError(t, err)
	assert.True(t, resp.GetPolicy().GetAdmitsNobody())

	var nilServer *AttestationServiceServer
	nilServer.SetReporting(nil)
	assert.Nil(t, nilServer.reportingHandles())
}

func TestAttestationReporting_GetAndList(t *testing.T) {
	s := NewAttestationServiceServer(nil, slog.Default())
	s.SetReporting(&ReportingHandles{Reports: reportingCache(t)})

	resp, err := s.GetDeviceReport(context.Background(), &platformv1.GetDeviceReportRequest{DeviceId: "42"})
	require.NoError(t, err)
	r := resp.GetReport()
	assert.Equal(t, "42", r.GetDeviceId())
	assert.True(t, r.GetVerified())
	assert.True(t, r.GetFresh())
	assert.Equal(t, "signed", r.GetPcrBaselineSource())
	assert.NotNil(t, r.GetPcrBaselineRecordedAt())
	assert.NotNil(t, r.GetAttestedAt())
	assert.NotNil(t, r.GetCollectedAt())
	assert.NotNil(t, r.GetAsOf())
	assert.GreaterOrEqual(t, r.GetAgeSeconds(), int64(59))

	_, err = s.GetDeviceReport(context.Background(), &platformv1.GetDeviceReportRequest{DeviceId: "never"})
	assert.Equal(t, codes.NotFound, status.Code(err))
	_, err = s.GetDeviceReport(context.Background(), &platformv1.GetDeviceReportRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	list, err := s.ListDeviceReports(context.Background(), &platformv1.ListDeviceReportsRequest{})
	require.NoError(t, err)
	assert.Equal(t, int32(2), list.GetTotal())
	assert.Equal(t, "42", list.GetReports()[0].GetDeviceId())
	assert.Equal(t, "7", list.GetReports()[1].GetDeviceId())
	assert.False(t, list.GetReports()[1].GetFresh())
	assert.True(t, list.GetReports()[1].GetCryptographicFailure())
	assert.Nil(t, list.GetReports()[1].GetAttestedAt(), "a zero time is not a timestamp")
}

func TestAttestationReporting_Refresh(t *testing.T) {
	s := NewAttestationServiceServer(nil, slog.Default())
	refresh := &stubRefresh{}
	s.SetReporting(&ReportingHandles{Refresher: refresh})

	resp, err := s.RefreshDeviceReport(context.Background(), &platformv1.RefreshDeviceReportRequest{DeviceId: "42"})
	require.NoError(t, err)
	assert.True(t, resp.GetEnqueued())
	assert.Equal(t, "42", resp.GetDeviceId())
	assert.Equal(t, []string{"42"}, refresh.ids)

	_, err = s.RefreshDeviceReport(context.Background(), &platformv1.RefreshDeviceReportRequest{})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	refresh.err = reporting.ErrCollectorStopped{}
	_, err = s.RefreshDeviceReport(context.Background(), &platformv1.RefreshDeviceReportRequest{DeviceId: "42"})
	assert.Equal(t, codes.Unavailable, status.Code(err))

	refresh.err = reporting.ErrDeviceIDRequired{}
	_, err = s.RefreshDeviceReport(context.Background(), &platformv1.RefreshDeviceReportRequest{DeviceId: "42"})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

func TestAttestationReporting_DescribeCallerPolicy(t *testing.T) {
	s := NewAttestationServiceServer(nil, slog.Default())
	s.SetReporting(&ReportingHandles{Policy: stubDescriber{d: calleradmission.Description{
		Strategy: calleradmission.StrategyAllowlist, Identities: []string{"a"}, ListValid: true, AnchorsConfigured: true, AnchorSource: "x",
	}}})
	resp, err := s.DescribeCallerPolicy(context.Background(), &platformv1.DescribeCallerPolicyRequest{})
	require.NoError(t, err)
	p := resp.GetPolicy()
	assert.Equal(t, "allowlist", p.GetStrategy())
	assert.Equal(t, []string{"a"}, p.GetIdentities())
	assert.True(t, p.GetListValid())
	assert.True(t, p.GetAnchorsConfigured())
	assert.Equal(t, "x", p.GetAnchorSource())
	assert.False(t, p.GetAdmitsNobody())
}

func TestMCPAttestationReports(t *testing.T) {
	p := &MCPServiceProvider{}
	_, _, err := p.AttestationDeviceReport(context.Background(), "1")
	require.Error(t, err)
	_, err = p.AttestationDeviceReports(context.Background())
	require.Error(t, err)
	require.Error(t, p.AttestationRefreshDevice(context.Background(), "1"))
	desc, err := p.AttestationCallerPolicy(context.Background())
	require.NoError(t, err)
	assert.True(t, desc.(calleradmission.Description).AdmitsNobody)

	refresh := &stubRefresh{}
	p = &MCPServiceProvider{attestationReporting: &ReportingHandles{
		Reports: reportingCache(t), Refresher: refresh,
		Policy: stubDescriber{d: calleradmission.Description{Strategy: calleradmission.StrategyReportingServers}},
	}}
	report, ok, err := p.AttestationDeviceReport(context.Background(), "42")
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, "42", report.(reporting.View).DeviceID)
	_, ok, err = p.AttestationDeviceReport(context.Background(), "never")
	require.NoError(t, err)
	assert.False(t, ok)
	reports, err := p.AttestationDeviceReports(context.Background())
	require.NoError(t, err)
	assert.Len(t, reports, 2)
	require.NoError(t, p.AttestationRefreshDevice(context.Background(), "42"))
	assert.Equal(t, []string{"42"}, refresh.ids)
	desc, err = p.AttestationCallerPolicy(context.Background())
	require.NoError(t, err)
	assert.Equal(t, calleradmission.StrategyReportingServers, desc.(calleradmission.Description).Strategy)
}
