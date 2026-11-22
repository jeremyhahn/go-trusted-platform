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
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// sdkLBAgainstRoutes serves the daemon's gateway routes, lb included, backed
// by svc and returns the SDK gateway client a CLI caller gets for
// --protocol rest.
func sdkLBAgainstRoutes(t *testing.T, svc *mockGatewayService) platformv1.GatewayServiceClient {
	t.Helper()
	_, router := setupGatewayTestHandler(svc)
	router.HandleFunc("/health/live", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	server := httptest.NewTLSServer(router)
	t.Cleanup(server.Close)

	// The SDK refuses plaintext REST; trust the test server's certificate.
	trustServer := platform.WithTLSConfig(server.Client().Transport.(*http.Transport).TLSClientConfig.Clone())
	adapter, err := sdkrest.Connect(context.Background(), platform.NewOptions(platform.WithRESTAddr(server.URL), trustServer))
	require.NoError(t, err)
	t.Cleanup(func() { _ = adapter.Close() })
	return platformv1.NewGatewayServiceClient(adapter.Connection())
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
	client := sdkLBAgainstRoutes(t, &mockGatewayService{getVIPResp: served, listVIPsResp: []LBVIPResponse{*served}})
	ctx := context.Background()

	got, err := client.GetVIP(ctx, &platformv1.GetVIPRequest{Protocol: "tcp", Address: "10.100.0.10", Port: 443})
	require.NoError(t, err)
	vip := got.GetVip()
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

	list, err := client.ListVIPs(ctx, &platformv1.ListVIPsRequest{})
	require.NoError(t, err)
	require.Len(t, list.GetVips(), 1)
	require.Equal(t, uint32(443), list.GetVips()[0].GetVip().GetPort())
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
	client := sdkLBAgainstRoutes(t, &mockGatewayService{lbStatusResp: served})

	decoded, err := client.GetLBStatus(context.Background(), &platformv1.GetLBStatusRequest{})
	require.NoError(t, err)
	s := decoded.GetStatus()
	require.NotNil(t, s)
	require.True(t, s.GetActive())
	require.Equal(t, uint32(served.VIPCount), s.GetVipCount())
	require.Equal(t, uint32(served.HealthyBackends), s.GetHealthyBackends())
	require.Equal(t, uint32(served.TotalBackends), s.GetTotalBackends())
	require.True(t, served.LastReconcile.Equal(s.GetLastReconcile().AsTime()))
}
