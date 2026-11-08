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
package daemon

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdksdn "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/sdn"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
)

// portStateOVS records what the SDN service asked Open vSwitch to do to each
// port.
type portStateOVS struct {
	portStates map[string]ovs.PortState
	policing   map[string][2]uint64
	shaping    map[string][2]uint64
}

// portStateCalls reads the recorded calls back off the OVS mock.
func portStateCalls(t *testing.T, mock *ConfigurableMockOVSClient) portStateOVS {
	t.Helper()
	got := portStateOVS{
		portStates: map[string]ovs.PortState{},
		policing:   map[string][2]uint64{},
		shaping:    map[string][2]uint64{},
	}
	for _, call := range mock.GetCalls("SetPortState") {
		got.portStates[call.Args[0].(string)] = call.Args[1].(ovs.PortState)
	}
	for _, call := range mock.GetCalls("SetIngressPolicing") {
		got.policing[call.Args[0].(string)] = [2]uint64{call.Args[1].(uint64), call.Args[2].(uint64)}
	}
	for _, call := range mock.GetCalls("SetEgressShaping") {
		got.shaping[call.Args[0].(string)] = [2]uint64{call.Args[1].(uint64), call.Args[2].(uint64)}
	}
	return got
}

// sdkSDNAgainstRoutes serves the daemon's REST router, wired to an SDN service
// over the OVS mock holding port eth0 on br-int, over TLS, and returns the
// SDK SDN client talking to it through the SDK REST adapter, so a route or
// wire shape the SDK uses and the daemon does not serve fails here (#730,
// #445).
func sdkSDNAgainstRoutes(t *testing.T) (*ConfigurableMockOVSClient, *sdksdn.Client) {
	t.Helper()
	mock := NewConfigurableMockOVSClient()
	svc := newTestSDNService(mock)
	svc.bridges["br-int"] = &bridgeResource{id: "br-int", name: "br-int", createdAt: time.Now()}
	svc.ports["eth0"] = &portResource{
		id: "eth0", name: "eth0", bridgeID: "br-int",
		portType: platformv1.PortType_PORT_TYPE_INTERNAL, createdAt: time.Now(),
	}
	rest := newTestRESTServerForPhase35(t)
	require.NoError(t, rest.SetSDNService(svc, sdnRESTGuard()))
	rest.router.HandleFunc("/health/live", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	server := httptest.NewTLSServer(rest.router)
	t.Cleanup(server.Close)

	// The SDK refuses plaintext REST; trust the test server's certificate.
	trustServer := platform.WithTLSConfig(server.Client().Transport.(*http.Transport).TLSClientConfig.Clone())
	adapter, err := sdkrest.Connect(context.Background(), platform.NewOptions(platform.WithRESTAddr(server.URL), trustServer,
		platform.WithBearerToken("sdn-operator")))
	require.NoError(t, err)
	t.Cleanup(func() { _ = adapter.Close() })
	return mock, sdksdn.NewClientFromGRPC(platformv1.NewSDNServiceClient(adapter.Connection()))
}

func TestSDNPortStateRoute_SDKSetPortStateReachesTheHandler(t *testing.T) {
	mock, client := sdkSDNAgainstRoutes(t)

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
	svc := portStateCalls(t, mock)

	require.Equal(t, ovs.PortStateDown, svc.portStates["eth0"])
	require.Equal(t, [2]uint64{10_000_000, 1_000_000}, svc.policing["eth0"])
	require.Equal(t, [2]uint64{20_000_000, 2_000_000}, svc.shaping["eth0"])
	require.Equal(t, "eth0", port.GetConfig().GetName())
	require.Equal(t, "br-int", port.GetBridgeId())
	require.Equal(t, platformv1.PortStatus_PORT_STATUS_DOWN, port.GetStatus())
}

func TestSDNPortStateRoute_SDKSeesTheRefusalCodes(t *testing.T) {
	mock, client := sdkSDNAgainstRoutes(t)

	_, err := client.SetPortState(context.Background(), &platformv1.SetPortStateRequest{
		BridgeId: "br-int", PortId: "eth0", AdminState: "sideways",
	})
	require.Equal(t, codes.InvalidArgument, status.Code(err), "got %v", err)
	require.Empty(t, portStateCalls(t, mock).portStates, "a refused state reached Open vSwitch")

	_, err = client.SetPortState(context.Background(), &platformv1.SetPortStateRequest{
		BridgeId: "br-int", PortId: "eth9", AdminState: "up",
	})
	require.Equal(t, codes.NotFound, status.Code(err), "got %v", err)
}
