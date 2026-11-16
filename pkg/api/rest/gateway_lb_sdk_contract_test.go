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
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	sdkgateway "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/gateway"
)

// getServed fetches path from the gateway router backed by svc and returns
// the 200 body.
func getServed(t *testing.T, svc *mockGatewayService, path string) []byte {
	t.Helper()
	_, router := setupGatewayTestHandler(svc)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	resp, err := http.Get(server.URL + path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = resp.Body.Close() })
	require.Equal(t, http.StatusOK, resp.StatusCode)
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)
	return body
}

// TestLBVIPResponse_DecodesThroughTheSDK pins the contract between the lb
// VIP routes and the Go SDK. The routes serve the flat VIP document; the
// SDK's REST adapter folds it into VIPStatus, the config nested under vip.
// A field renamed or retyped here and not there would reach a CLI user as
// a silently empty VIP.
func TestLBVIPResponse_DecodesThroughTheSDK(t *testing.T) {
	served := &LBVIPResponse{
		Address:   "10.100.0.10",
		Port:      443,
		Protocol:  "tcp",
		Algorithm: "hash",
		CTZone:    7,
		GroupID:   12,
		Backends: []LBBackendStatus{
			{Backend: LBBackend{Address: "10.0.1.5", Port: 8443, Weight: 2}, Healthy: true},
		},
	}
	body := getServed(t, &mockGatewayService{getVIPResp: served}, "/api/v1/sdn/gateway/lb/vips/tcp/10.100.0.10/443")

	vip, err := sdkgateway.DecodeVIPStatusJSON(body)
	require.NoError(t, err)
	cfg := vip.GetVip()
	require.Equal(t, served.Address, cfg.GetAddress())
	require.Equal(t, uint32(served.Port), cfg.GetPort())
	require.Equal(t, served.Protocol, cfg.GetProtocol())
	require.Equal(t, served.Algorithm, cfg.GetAlgorithm())
	require.Equal(t, uint32(served.CTZone), vip.GetCtZone())
	require.Equal(t, served.GroupID, vip.GetGroupId())
	require.Len(t, vip.GetBackends(), 1)
	be := vip.GetBackends()[0]
	require.True(t, be.GetHealthy())
	require.Equal(t, "10.0.1.5", be.GetBackend().GetAddress())
	require.Equal(t, uint32(8443), be.GetBackend().GetPort())
	require.Equal(t, uint32(2), be.GetBackend().GetWeight())

	list := getServed(t, &mockGatewayService{listVIPsResp: []LBVIPResponse{*served}}, "/api/v1/sdn/gateway/lb/vips")
	decoded, err := sdkgateway.DecodeListVIPsJSON(list)
	require.NoError(t, err)
	require.Len(t, decoded.GetVips(), 1)
	require.Equal(t, uint32(443), decoded.GetVips()[0].GetVip().GetPort())
}

// TestLBStatusResponse_DecodesThroughTheSDK: the status route serves the
// bare status object, which the SDK wraps under GetLBStatusResponse.status.
func TestLBStatusResponse_DecodesThroughTheSDK(t *testing.T) {
	served := &LBStatusResponse{
		Active:          true,
		VIPCount:        2,
		HealthyBackends: 3,
		TotalBackends:   4,
		LastReconcile:   time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC),
	}
	body := getServed(t, &mockGatewayService{lbStatusResp: served}, "/api/v1/sdn/gateway/lb/status")

	decoded, err := sdkgateway.DecodeLBStatusJSON(body)
	require.NoError(t, err)
	s := decoded.GetStatus()
	require.NotNil(t, s)
	require.True(t, s.GetActive())
	require.Equal(t, uint32(served.VIPCount), s.GetVipCount())
	require.Equal(t, uint32(served.HealthyBackends), s.GetHealthyBackends())
	require.Equal(t, uint32(served.TotalBackends), s.GetTotalBackends())
	require.True(t, served.LastReconcile.Equal(s.GetLastReconcile().AsTime()))
}
