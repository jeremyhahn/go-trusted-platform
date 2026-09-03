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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
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
	// FailedPrecondition to 400, which is indistinguishable from a
	// malformed request.
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
