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
package switchapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	switchmgmt "github.com/jeremyhahn/go-trusted-platform/pkg/switch"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkrest "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/rest"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/switchwire"
)

// The switch and port the round trips address. The port carries a slash, so
// it only reaches the handler as one segment if the SDK escapes it.
const (
	sdkSwitch = "tor-1"
	sdkPort   = "Eth1/3"
)

// portCall is what the manager behind the router was asked to do.
type portCall struct {
	action string
	port   string
	vlan   uint16
}

// recordingManager is a mockManager that records each port operation and
// knows only sdkPort.
func recordingManager(calls *[]portCall) *mockManager {
	known := func(port string) error {
		if port != sdkPort {
			return switchmgmt.ErrPortNotFound{Port: port}
		}
		return nil
	}
	return &mockManager{
		listPortsFunc: func(context.Context) ([]*switchwire.PortStatus, error) {
			*calls = append(*calls, portCall{action: "list"})
			return []*switchwire.PortStatus{{Port: sdkPort, Mode: switchwire.PortModeAccess, AccessVLAN: 100}}, nil
		},
		getPortStatusFunc: func(_ context.Context, port string) (*switchwire.PortStatus, error) {
			*calls = append(*calls, portCall{action: "status", port: port})
			if err := known(port); err != nil {
				return nil, err
			}
			return &switchwire.PortStatus{
				Port: port, Mode: switchwire.PortModeTrunk, TrunkVLANs: []uint16{100, 200},
				NativeVLAN: 1, Enabled: true, LinkUp: true,
			}, nil
		},
		setPortVLANFunc: func(_ context.Context, port string, vlan uint16) error {
			*calls = append(*calls, portCall{action: "vlan", port: port, vlan: vlan})
			return known(port)
		},
		enablePortFunc: func(_ context.Context, port string) error {
			*calls = append(*calls, portCall{action: "enable", port: port})
			return known(port)
		},
		disablePortFunc: func(_ context.Context, port string) error {
			*calls = append(*calls, portCall{action: "disable", port: port})
			return known(port)
		},
	}
}

// connectSwitchSDK serves the real switch router over TLS, with sdkSwitch
// backed by a recording manager, and returns the SDK's REST client for it
// (#452).
func connectSwitchSDK(t *testing.T) (platformv1.SwitchServiceClient, *[]portCall) {
	t.Helper()
	calls := &[]portCall{}
	svc := &mockSwitchService{managers: map[string]switchmgmt.Manager{sdkSwitch: recordingManager(calls)}}

	root := mux.NewRouter()
	root.HandleFunc("/health/live", func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) })
	NewSwitchRouter(newTestLogger(), svc, newTestResponseWriter()).
		RegisterRoutes(root.PathPrefix("/api/v1").Subrouter())

	server := httptest.NewTLSServer(root)
	t.Cleanup(server.Close)
	tlsConfig := server.Client().Transport.(*http.Transport).TLSClientConfig.Clone()
	adapter, err := sdkrest.Connect(context.Background(), platform.NewOptions(
		platform.WithRESTAddr(server.URL), platform.WithTLSConfig(tlsConfig)))
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, adapter.Close()) })
	return platformv1.NewSwitchServiceClient(adapter.Connection()), calls
}

func TestSwitchPorts_SDKReachesTheHandlerWithTheNamesFromThePath(t *testing.T) {
	client, calls := connectSwitchSDK(t)
	ctx := context.Background()

	t.Run("GetPortStatus", func(t *testing.T) {
		*calls = nil
		resp, err := client.GetPortStatus(ctx, &platformv1.GetSwitchPortStatusRequest{SwitchName: sdkSwitch, PortName: sdkPort})
		require.NoError(t, err)
		assert.Equal(t, []portCall{{action: "status", port: sdkPort}}, *calls)
		port := resp.GetPort()
		assert.Equal(t, sdkPort, port.GetPort())
		assert.Equal(t, "trunk", port.GetMode())
		assert.Equal(t, []uint32{100, 200}, port.GetTrunkVlans())
		assert.True(t, port.GetLinkUp())
	})
	t.Run("SetPortVLAN", func(t *testing.T) {
		*calls = nil
		resp, err := client.SetPortVLAN(ctx, &platformv1.SetSwitchPortVLANRequest{SwitchName: sdkSwitch, PortName: sdkPort, VlanId: 200})
		require.NoError(t, err)
		assert.Equal(t, []portCall{{action: "vlan", port: sdkPort, vlan: 200}}, *calls)
		assert.True(t, resp.GetStatus().GetSuccess())
	})
	t.Run("ListPorts", func(t *testing.T) {
		*calls = nil
		resp, err := client.ListPorts(ctx, &platformv1.ListSwitchPortsRequest{SwitchName: sdkSwitch})
		require.NoError(t, err)
		assert.Equal(t, []portCall{{action: "list"}}, *calls)
		require.Len(t, resp.GetPorts(), 1)
		assert.Equal(t, uint32(100), resp.GetPorts()[0].GetAccessVlan())
	})
	t.Run("EnablePort", func(t *testing.T) {
		*calls = nil
		resp, err := client.EnablePort(ctx, &platformv1.EnableSwitchPortRequest{SwitchName: sdkSwitch, PortName: sdkPort})
		require.NoError(t, err)
		assert.Equal(t, []portCall{{action: "enable", port: sdkPort}}, *calls)
		assert.True(t, resp.GetStatus().GetSuccess())
	})
	t.Run("DisablePort", func(t *testing.T) {
		*calls = nil
		resp, err := client.DisablePort(ctx, &platformv1.DisableSwitchPortRequest{SwitchName: sdkSwitch, PortName: sdkPort})
		require.NoError(t, err)
		assert.Equal(t, []portCall{{action: "disable", port: sdkPort}}, *calls)
		assert.True(t, resp.GetStatus().GetSuccess())
	})
}

func TestSwitchPorts_SDKSurfacesAnUnknownSwitchOrPortAsNotFound(t *testing.T) {
	client, calls := connectSwitchSDK(t)
	ctx := context.Background()

	_, err := client.GetPortStatus(ctx, &platformv1.GetSwitchPortStatusRequest{SwitchName: sdkSwitch, PortName: "Eth9/9"})
	assert.Equal(t, codes.NotFound, status.Code(err), "unknown port: %v", err)
	_, err = client.SetPortVLAN(ctx, &platformv1.SetSwitchPortVLANRequest{SwitchName: sdkSwitch, PortName: "Eth9/9", VlanId: 200})
	assert.Equal(t, codes.NotFound, status.Code(err), "unknown port: %v", err)
	_, err = client.EnablePort(ctx, &platformv1.EnableSwitchPortRequest{SwitchName: sdkSwitch, PortName: "Eth9/9"})
	assert.Equal(t, codes.NotFound, status.Code(err), "unknown port: %v", err)

	*calls = nil
	_, err = client.SetPortVLAN(ctx, &platformv1.SetSwitchPortVLANRequest{SwitchName: "tor-9", PortName: sdkPort, VlanId: 200})
	assert.Equal(t, codes.NotFound, status.Code(err), "unknown switch: %v", err)
	_, err = client.GetPortStatus(ctx, &platformv1.GetSwitchPortStatusRequest{SwitchName: "tor-9", PortName: sdkPort})
	assert.Equal(t, codes.NotFound, status.Code(err), "unknown switch: %v", err)
	assert.Empty(t, *calls, "an unknown switch reached a manager")
}

func TestSwitchPorts_SDKSurfacesAnInvalidVLANAsInvalidArgument(t *testing.T) {
	client, calls := connectSwitchSDK(t)

	_, err := client.SetPortVLAN(context.Background(), &platformv1.SetSwitchPortVLANRequest{SwitchName: sdkSwitch, PortName: sdkPort, VlanId: 5000})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "VLAN 5000: %v", err)
	assert.Empty(t, *calls, "an invalid VLAN reached the manager")
}
