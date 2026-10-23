// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.
package rest

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdksdn "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/sdn"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// sdkSDNAgainstRoutes serves the real SDN routes over TLS and returns the SDK
// SDN client talking to them through the SDK REST adapter, so a route the SDK
// names and the server does not serve fails here (#730).
func sdkSDNAgainstRoutes(t *testing.T) (*mockSDNService, *sdksdn.Client) {
	t.Helper()
	svc, router := portStateRouter()
	router.HandleFunc("/health/live", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	server := httptest.NewTLSServer(router)
	t.Cleanup(server.Close)

	// The SDK refuses plaintext REST; trust the test server's certificate.
	trustServer := platform.WithTLSConfig(server.Client().Transport.(*http.Transport).TLSClientConfig.Clone())
	adapter, err := sdkrest.Connect(context.Background(), platform.NewOptions(platform.WithRESTAddr(server.URL), trustServer))
	require.NoError(t, err)
	t.Cleanup(func() { _ = adapter.Close() })
	return svc, sdksdn.NewClientFromGRPC(platformv1.NewSDNServiceClient(adapter.Connection()))
}

func TestSDNPortStateRoute_SDKSetPortStateReachesTheHandler(t *testing.T) {
	svc, client := sdkSDNAgainstRoutes(t)

	port, err := client.SetPortState(context.Background(), &platformv1.SetPortStateRequest{
		BridgeId:     "br-int",
		PortId:       "eth0",
		AdminState:   "down",
		IngressRate:  10_000_000,
		IngressBurst: 1_000_000,
		EgressRate:   20_000_000,
		EgressBurst:  2_000_000,
	})
	require.NoError(t, err)

	require.Equal(t, ovs.PortStateDown, svc.portStates["eth0"])
	require.Equal(t, [2]uint64{10_000_000, 1_000_000}, svc.policing["eth0"])
	require.Equal(t, [2]uint64{20_000_000, 2_000_000}, svc.shaping["eth0"])
	require.Equal(t, "eth0", port.GetConfig().GetName())
	require.Equal(t, "br-int", port.GetBridgeId())
	require.Equal(t, platformv1.PortStatus_PORT_STATUS_DOWN, port.GetStatus())
}

func TestSDNPortStateRoute_SDKSeesTheRefusalCodes(t *testing.T) {
	svc, client := sdkSDNAgainstRoutes(t)

	_, err := client.SetPortState(context.Background(), &platformv1.SetPortStateRequest{
		BridgeId: "br-int", PortId: "eth0", AdminState: "sideways",
	})
	require.Equal(t, codes.InvalidArgument, status.Code(err), "got %v", err)
	require.Empty(t, svc.portStates, "a refused state reached Open vSwitch")

	_, err = client.SetPortState(context.Background(), &platformv1.SetPortStateRequest{
		BridgeId: "br-int", PortId: "eth9", AdminState: "up",
	})
	require.Equal(t, codes.NotFound, status.Code(err), "got %v", err)
}
