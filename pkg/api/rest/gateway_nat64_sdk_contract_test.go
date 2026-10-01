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

package rest

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	sdkgateway "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/gateway"
)

// TestNAT64StatusResponse_DecodesThroughTheSDK pins the contract between the
// NAT64 route and the Go SDK. The route serves the bare status object; the
// SDK's REST and MCP adapters decode it with DecodeNAT64StatusJSON into the
// gRPC reply. A field renamed or retyped here and not there would reach a
// CLI user as a silently empty status, which is how #661's first cut
// shipped (review 4316).
func TestNAT64StatusResponse_DecodesThroughTheSDK(t *testing.T) {
	served := &NAT64StatusResponse{
		Active:          true,
		InstancePresent: true,
		Prefix:          "64:ff9b::/96",
		Instance:        "tp-nat64",
		Sessions:        12,
		Pool4Used:       7,
		ModuleVersion:   "4.1.14",
		FlowCount:       5,
		LastReconcile:   time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC),
		LastError:       "pool4 display: busy",
	}
	_, router := setupGatewayTestHandler(&mockGatewayService{nat64Resp: served})
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	resp, err := http.Get(server.URL + "/api/v1/sdn/gateway/nat64/status")
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	decoded, err := sdkgateway.DecodeNAT64StatusJSON(body)
	require.NoError(t, err)
	s := decoded.GetStatus()
	require.NotNil(t, s)
	require.Equal(t, served.Active, s.GetActive())
	require.Equal(t, served.InstancePresent, s.GetInstancePresent())
	require.Equal(t, served.Prefix, s.GetPrefix())
	require.Equal(t, served.Instance, s.GetInstance())
	require.Equal(t, served.Sessions, s.GetSessions())
	require.Equal(t, served.Pool4Used, s.GetPool4Used())
	require.Equal(t, served.ModuleVersion, s.GetModuleVersion())
	require.Equal(t, uint32(served.FlowCount), s.GetFlowCount())
	require.True(t, served.LastReconcile.Equal(s.GetLastReconcile().AsTime()))
	require.Equal(t, served.LastError, s.GetLastError())
}

// TestNAT64StatusResponse_AnErrorIsNotAStatus: a refusal must never decode
// as an all-false status, which a caller would read as "translator down"
// rather than "unreachable".
func TestNAT64StatusResponse_AnErrorIsNotAStatus(t *testing.T) {
	_, err := sdkgateway.DecodeNAT64StatusJSON([]byte("service unavailable"))
	var typed *sdkgateway.ErrNAT64StatusDecodeFailed
	require.True(t, errors.As(err, &typed), "got %v", err)
}

// TestNAT64Status_HTTPStatusFollowsTheCause pins the NAT64 error contract
// on REST: a translator that is not running is 503 (retryable, maybe
// starting), a kernel that cannot carry it is 412 (operator action on the
// host), and anything else is a daemon fault. The 412 case answered 500
// before the #661 review, which told a REST caller to retry or escalate a
// missing kernel module.
func TestNAT64Status_HTTPStatusFollowsTheCause(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want int
	}{
		"not running":        {ErrNAT64NotConfigured{}, http.StatusServiceUnavailable},
		"module unavailable": {ErrNAT64ModuleUnavailable{Detail: "module jool not found"}, http.StatusPreconditionFailed},
		"anything else":      {errors.New("boom"), http.StatusInternalServerError},
	} {
		t.Run(name, func(t *testing.T) {
			_, router := setupGatewayTestHandler(&mockGatewayService{nat64Err: tc.err})
			req := httptest.NewRequest(http.MethodGet, "/api/v1/sdn/gateway/nat64/status", nil)
			rec := httptest.NewRecorder()
			router.ServeHTTP(rec, req)
			require.Equal(t, tc.want, rec.Code, rec.Body.String())
		})
	}

	_, router := setupGatewayTestHandler(&mockGatewayService{nat64Err: ErrNAT64ModuleUnavailable{Detail: "module jool not found"}})
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/sdn/gateway/nat64/status", nil))
	require.Contains(t, rec.Body.String(), "module jool not found", "the operator needs the kernel's own reason")
}
