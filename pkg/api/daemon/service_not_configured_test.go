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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning/baremetal"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// notConfiguredServiceName returns the service named by the status's
// SERVICE_NOT_CONFIGURED ErrorInfo detail, failing the test when the
// status does not carry one. It is the assertion counterpart to
// protorest's notConfiguredService, so a change that drops the detail
// fails here rather than silently degrading the REST envelope.
func notConfiguredServiceName(t *testing.T, st *status.Status) string {
	t.Helper()
	for _, detail := range st.Details() {
		info, ok := detail.(*errdetails.ErrorInfo)
		if !ok {
			continue
		}
		if info.GetReason() != response.ReasonServiceNotConfigured {
			continue
		}
		require.Equal(t, response.ErrorInfoDomain, info.GetDomain())
		return info.GetMetadata()["service"]
	}
	t.Fatalf("status %q carries no %s ErrorInfo detail",
		st.Message(), response.ReasonServiceNotConfigured)
	return ""
}

func TestErrServiceNotConfigured_Error(t *testing.T) {
	assert.Equal(t, "gateway is dark here",
		ErrServiceNotConfigured{Service: "gateway", Detail: "gateway is dark here"}.Error())

	// Without prose the error still names the service, so a log line is
	// never empty.
	assert.Equal(t, "pxe is not configured on this node",
		ErrServiceNotConfigured{Service: "pxe"}.Error())
}

func TestErrServiceNotConfigured_GRPCStatus(t *testing.T) {
	st := ErrServiceNotConfigured{Service: "pxe", Detail: "PXE is dark"}.GRPCStatus()

	// Unavailable, not FailedPrecondition: the REST layer maps
	// FailedPrecondition to 409, a conflict with the resource's state,
	// not a service that is absent on this node.
	assert.Equal(t, codes.Unavailable, st.Code())
	assert.Equal(t, "PXE is dark", st.Message())
	assert.Equal(t, "pxe", notConfiguredServiceName(t, st))
}

func TestServiceNotConfigured_ProducesTheSameStatus(t *testing.T) {
	err := serviceNotConfigured("gateway", "gateway not configured on this node")

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Unavailable, st.Code())
	assert.Equal(t, "gateway", notConfiguredServiceName(t, st))
}

// TestInfraServiceNotConfigured_AnswersUnavailable holds every BMC and switch
// servicer path to the platform-wide not-configured answer, one row per
// error: Unavailable with the SERVICE_NOT_CONFIGURED reason, so REST answers
// 503, QUIC StatusUnavailable, and MCP and the embedded transport pass the
// same class through.
func TestInfraServiceNotConfigured_AnswersUnavailable(t *testing.T) {
	ctx := context.Background()
	bmcNoBackend := NewBMCGRPCService(nil, nil, nil)
	bmcNoProfiles := NewBMCGRPCService(&fakeBMCService{}, nil, nil)
	bmcNoProfiles.SetEnroller(&fakeBMCEnroller{}, nil)
	switches := NewSwitchGRPCService(logging.DefaultLogger(), nil)

	cases := []struct {
		name    string
		service string
		call    func() error
	}{
		{"ErrBMCServiceNotConfigured", "bmc", func() error {
			_, err := bmcNoBackend.PowerStatus(ctx, &platformv1.BMCPowerStatusRequest{ProfileId: 1})
			return err
		}},
		{"ErrBMCServiceNotConfigured from the profile lookup", "bmc", func() error {
			_, err := bmcNoProfiles.EnrollBMC(ctx, &platformv1.BMCEnrollRequest{ProfileId: 1})
			return err
		}},
		{"ErrBaremetalServiceNotConfigured", "bmc", func() error {
			_, err := bmcNoBackend.ProvisionStatus(ctx, &platformv1.BMCProvisionStatusRequest{ProfileId: 1})
			return err
		}},
		{"ErrBMCEnrollerNotConfigured", "bmc", func() error {
			_, err := bmcNoBackend.EnrollBMC(ctx, &platformv1.BMCEnrollRequest{ProfileId: 1})
			return err
		}},
		{"ErrBMCRestorerNotConfigured", "bmc", func() error {
			_, err := bmcNoBackend.RestoreFactoryCert(ctx, &platformv1.BMCRestoreRequest{ProfileId: 1})
			return err
		}},
		{"switch service not configured", "switch", func() error {
			_, err := switches.ListPorts(ctx, &platformv1.ListSwitchPortsRequest{SwitchName: "core"})
			return err
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			st, ok := status.FromError(tc.call())
			require.True(t, ok)
			assert.Equal(t, codes.Unavailable, st.Code(), st.Message())
			assert.Equal(t, tc.service, notConfiguredServiceName(t, st))
		})
	}
}

// TestInfraServiceNotConfigured_ConfiguredRefusalKeepsItsClass proves the
// not-configured answer is not a catch-all: a wired service that refuses
// for its own reason keeps that class and carries no not-configured reason.
func TestInfraServiceNotConfigured_ConfiguredRefusalKeepsItsClass(t *testing.T) {
	bm := &fakeBaremetalService{provisionErr: baremetal.ErrProfileNoBMC{ProfileID: 1}}
	svc := NewBMCGRPCService(&fakeBMCService{}, bm, nil)

	_, err := svc.Provision(context.Background(), &platformv1.BMCProvisionRequest{ProfileId: 1})

	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.FailedPrecondition, st.Code())
	assert.Empty(t, st.Details())
}
