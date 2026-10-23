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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/ipc"
	gwstate "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/state"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// gatewayIPCNode is the minimal running gateway behind the test datapath
// server; the gateway-services RPCs do not consult it.
type gatewayIPCNode struct{}

func (gatewayIPCNode) GetState() gateway.GatewayState                      { return gateway.GatewayStateRunning }
func (gatewayIPCNode) ServiceReports() []gateway.ServiceReport             { return nil }
func (gatewayIPCNode) Snapshot() *gwstate.Snapshot                         { return &gwstate.Snapshot{} }
func (gatewayIPCNode) Apply(context.Context, *gwstate.DesiredConfig) error { return nil }
func (gatewayIPCNode) DesiredConfigState() gwstate.DesiredConfigState {
	var state gwstate.DesiredConfigState
	return state
}

// gatewayDatapathFakes are the gatewayd-resident services the test
// datapath child hosts.
type gatewayDatapathFakes struct {
	lb    *fakeGatewayLB
	nat64 *fakeGatewayNAT64
	perf  *fakeGatewayPerf
}

// serveGatewayDatapath starts a real gatewayd IPC server hosting fakes on a
// socket under t.TempDir and returns the socket path.
func serveGatewayDatapath(t *testing.T) (string, *gatewayDatapathFakes) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "d.sock")
	fakes := &gatewayDatapathFakes{
		lb:    newFakeGatewayLB(),
		nat64: &fakeGatewayNAT64{health: nat64TestHealth()},
		perf:  &fakeGatewayPerf{},
	}
	uid := uint32(os.Getuid())
	srv := ipc.NewServer(gatewayIPCNode{}, ipc.Policy{ControlUIDs: []uint32{uid}})
	srv.SetServices(ipc.Services{LoadBalancer: fakes.lb, NAT64: fakes.nat64, Perf: fakes.perf})
	require.NoError(t, srv.Listen(path, 0o600, -1))
	served := make(chan error, 1)
	go func() { served <- srv.Serve() }()
	t.Cleanup(func() {
		srv.Stop()
		assert.NoError(t, <-served)
	})
	return path, fakes
}

func TestGatewayBackendOptions_NoSocketNoLocalPerfWiresNothing(t *testing.T) {
	opts, client, err := gatewayBackendOptions("", nil)
	require.NoError(t, err)
	assert.Nil(t, client)
	assert.Empty(t, opts)

	_, err = NewGatewayService(opts...).GetLBStatus(context.Background(), &platformv1.GetLBStatusRequest{})
	assert.Equal(t, codes.Unavailable, status.Code(err))
}

func TestGatewayBackendOptions_NoSocketKeepsTheLocalPerf(t *testing.T) {
	local := &fakeGatewayPerf{}
	opts, client, err := gatewayBackendOptions("", local)
	require.NoError(t, err)
	assert.Nil(t, client)

	svc := NewGatewayService(opts...)
	assert.Same(t, local, svc.Perf())
	assert.Nil(t, svc.LoadBalancer(), "no datapath socket, no load balancer")
	assert.Nil(t, svc.NAT64(), "no datapath socket, no NAT64")
}

func TestGatewayBackendOptions_SocketServesEveryBackendOverIPC(t *testing.T) {
	path, fakes := serveGatewayDatapath(t)
	local := &fakeGatewayPerf{}

	opts, client, err := gatewayBackendOptions(path, local)
	require.NoError(t, err)
	require.NotNil(t, client)
	t.Cleanup(func() { assert.NoError(t, client.Close()) })

	svc := NewGatewayService(opts...)
	ctx := context.Background()
	_, err = svc.GetPerfFlows(ctx, &platformv1.GetPerfFlowsRequest{Bridge: "br-ipc"})
	require.NoError(t, err)
	assert.Equal(t, "br-ipc", fakes.perf.lastBridge, "the gatewayd perf service measured it")
	assert.Empty(t, local.lastBridge, "the IPC perf replaces the local one")

	_, err = svc.GetLBStatus(ctx, &platformv1.GetLBStatusRequest{})
	require.NoError(t, err)
	_, err = svc.GetNAT64Status(ctx, &platformv1.GetNAT64StatusRequest{})
	require.NoError(t, err)
}

func TestGatewayBackendOptions_SocketWithNoServerIsUnavailable(t *testing.T) {
	path := filepath.Join(t.TempDir(), "absent.sock")
	opts, client, err := gatewayBackendOptions(path, nil)
	require.NoError(t, err, "the dial is lazy; gatewayd may start after platformd")
	require.NotNil(t, client)
	t.Cleanup(func() { assert.NoError(t, client.Close()) })

	svc := NewGatewayService(opts...)
	ctx := context.Background()
	_, err = svc.GetLBStatus(ctx, &platformv1.GetLBStatusRequest{})
	assert.Equal(t, codes.Unavailable, status.Code(err), "LB: %v", err)
	_, err = svc.GetNAT64Status(ctx, &platformv1.GetNAT64StatusRequest{})
	assert.Equal(t, codes.Unavailable, status.Code(err), "NAT64: %v", err)
	_, err = svc.GetPerfDatapath(ctx, &platformv1.GetPerfDatapathRequest{Bridge: "br-ipc"})
	assert.Equal(t, codes.Unavailable, status.Code(err), "perf: %v", err)
}

func TestCloseGatewayIPC_NoClientIsANoOp(t *testing.T) {
	d := &Daemon{}
	assert.NotPanics(t, d.closeGatewayIPC)
}

func TestCloseGatewayIPC_ClosesTheClient(t *testing.T) {
	path, _ := serveGatewayDatapath(t)
	client, err := ipc.Dial(path)
	require.NoError(t, err)
	d := &Daemon{gatewayIPC: client}

	d.closeGatewayIPC()

	_, err = client.LBStatus(context.Background())
	var unreachable *ipc.ErrServiceUnreachable
	assert.ErrorAs(t, err, &unreachable, "a closed client no longer reaches gatewayd")
}

// TestNew_ServesGatewayBackendsOverIPC is the #660 verification: the
// production daemon wiring, given a datapath socket with gatewayd's
// services running behind it, answers the load-balancer, perf and NAT64
// verbs instead of unavailable.
func TestNew_ServesGatewayBackendsOverIPC(t *testing.T) {
	path, fakes := serveGatewayDatapath(t)
	config := testConfig(filepath.Join(t.TempDir(), "p.sock"))
	config.GatewayDatapathSocket = path

	d, err := New(config)
	require.NoError(t, err)
	t.Cleanup(d.closeGatewayIPC)
	svc := d.gatewayGRPCService
	ctx := context.Background()

	lb, err := svc.GetLBStatus(ctx, &platformv1.GetLBStatusRequest{})
	require.NoError(t, err, "GetLBStatus")
	assert.NotNil(t, lb)

	nat, err := svc.GetNAT64Status(ctx, &platformv1.GetNAT64StatusRequest{})
	require.NoError(t, err, "GetNAT64Status")
	assert.Equal(t, "tp-nat64", nat.GetStatus().GetInstance())

	_, err = svc.GetPerfFlows(ctx, &platformv1.GetPerfFlowsRequest{Bridge: "br-ipc"})
	require.NoError(t, err, "GetPerfFlows")
	assert.Equal(t, "br-ipc", fakes.perf.lastBridge)
	_, err = svc.GetPerfDatapath(ctx, &platformv1.GetPerfDatapathRequest{Bridge: "br-ipc"})
	require.NoError(t, err, "GetPerfDatapath")
	_, err = svc.GetPerfConntrack(ctx, &platformv1.GetPerfConntrackRequest{})
	require.NoError(t, err, "GetPerfConntrack")
}
