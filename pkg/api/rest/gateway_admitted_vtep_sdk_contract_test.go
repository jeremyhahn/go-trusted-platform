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

package rest

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkgateway "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/gateway"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// admittedVTEPService answers the admitted-VTEP reads with fixed records and
// records the gateway and VTEP each call named.
type admittedVTEPService struct {
	*mockGatewayService
	vteps     []GatewayAdmittedVTEPResponse
	err       error
	gatewayID string
	vtep      string
}

func (s *admittedVTEPService) GetAdmittedVTEP(_ context.Context, gatewayID, vtep string) (*GatewayAdmittedVTEPResponse, error) {
	s.gatewayID, s.vtep = gatewayID, vtep
	if s.err != nil {
		return nil, s.err
	}
	for i := range s.vteps {
		if s.vteps[i].VTEP == vtep {
			return &s.vteps[i], nil
		}
	}
	return nil, ErrGatewayAdmittedVTEPNotFound{VTEP: vtep}
}

func (s *admittedVTEPService) ListAdmittedVTEPs(_ context.Context, gatewayID string) ([]GatewayAdmittedVTEPResponse, error) {
	s.gatewayID = gatewayID
	return s.vteps, s.err
}

// sdkGatewayAgainstRoutes serves the real gateway routes and returns the SDK
// gateway client a CLI caller gets for --protocol rest.
func sdkGatewayAgainstRoutes(t *testing.T, svc *admittedVTEPService) *sdkgateway.Client {
	t.Helper()
	router := mux.NewRouter()
	router.HandleFunc("/health", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	NewGatewayHandlers(svc, slog.Default()).RegisterRoutes(router)
	server := httptest.NewServer(router)
	t.Cleanup(server.Close)

	adapter, err := sdkrest.Connect(context.Background(), platform.NewOptions(platform.WithRESTAddr(server.URL)))
	require.NoError(t, err)
	t.Cleanup(func() { _ = adapter.Close() })
	return sdkgateway.NewClientFromGRPC(platformv1.NewGatewayServiceClient(adapter.Connection()))
}

// TestAdmittedVTEPRoutes_ServeTheSDK pins the contract between the
// admitted-VTEP routes and the Go SDK's REST transport, which used to POST
// to a path no server registers.
func TestAdmittedVTEPRoutes_ServeTheSDK(t *testing.T) {
	verdictAt := time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)
	svc := &admittedVTEPService{mockGatewayService: &mockGatewayService{}, vteps: []GatewayAdmittedVTEPResponse{
		{VTEP: "2001:db8::10", DeviceID: 42, HostID: "host-42", Serial: "SN42", Hostname: "edge-42",
			AllocationID: "alloc-42", BaselineSource: "signed", ProfileID: 9, VerdictAt: &verdictAt},
		{VTEP: "198.51.100.11"},
	}}
	client := sdkGatewayAgainstRoutes(t, svc)

	got, err := client.GetAdmittedVTEP(context.Background(), "gw-01", "2001:db8::10")
	require.NoError(t, err)
	require.Equal(t, "gw-01", svc.gatewayID)
	require.Equal(t, "2001:db8::10", svc.vtep)
	require.Equal(t, "2001:db8::10", got.GetVtep())
	require.Equal(t, uint64(42), got.GetDeviceId())
	require.Equal(t, "host-42", got.GetHostId())
	require.Equal(t, "SN42", got.GetSerial())
	require.Equal(t, "edge-42", got.GetHostname())
	require.Equal(t, "alloc-42", got.GetAllocationId())
	require.Equal(t, "signed", got.GetBaselineSource())
	require.Equal(t, uint64(9), got.GetProfileId())
	require.True(t, verdictAt.Equal(got.GetVerdictAt().AsTime()))

	list, err := client.ListAdmittedVTEPs(context.Background(), "")
	require.NoError(t, err)
	require.Empty(t, svc.gatewayID, "no gateway named must reach the server as this node's own gateway")
	require.Len(t, list, 2)
	require.Equal(t, "198.51.100.11", list[1].GetVtep())
	require.Nil(t, list[1].GetVerdictAt())
}

// TestAdmittedVTEPRoutes_SDKSeesTheRefusalCodes: an unknown VTEP must reach
// an SDK caller as NotFound and a gateway with no overlay as Unavailable,
// not as an empty record.
func TestAdmittedVTEPRoutes_SDKSeesTheRefusalCodes(t *testing.T) {
	client := sdkGatewayAgainstRoutes(t, &admittedVTEPService{mockGatewayService: &mockGatewayService{}})
	_, err := client.GetAdmittedVTEP(context.Background(), "", "198.51.100.99")
	require.Equal(t, codes.NotFound, status.Code(err), "got %v", err)

	client = sdkGatewayAgainstRoutes(t, &admittedVTEPService{
		mockGatewayService: &mockGatewayService{},
		err:                ErrGatewayFeatureNotConfigured{Feature: "gateway overlay admission"},
	})
	_, err = client.ListAdmittedVTEPs(context.Background(), "")
	require.Equal(t, codes.Unavailable, status.Code(err), "got %v", err)
}
