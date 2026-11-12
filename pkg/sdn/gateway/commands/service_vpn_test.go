package commands

import (
	"context"
	"log/slog"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/ipc"
	ipcv1 "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/ipc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/process"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
)

// fakeVPNPlane stands in for a kernel data plane the datapath child hosts.
// It is a MASQUE plane so the test runs in every build.
type fakeVPNPlane struct {
	mu        sync.Mutex
	started   bool
	stopped   bool
	installed []vpn.LeaseID
}

func (p *fakeVPNPlane) Kind() vpn.DataPlaneKind { return vpn.DataPlaneMASQUE }

func (p *fakeVPNPlane) Start(context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.started = true
	return nil
}

func (p *fakeVPNPlane) Stop(context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.stopped = true
	return nil
}

func (p *fakeVPNPlane) InstallPeer(_ context.Context, lease *vpn.Lease) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.installed = append(p.installed, lease.ID)
	return nil
}

func (p *fakeVPNPlane) RemovePeer(context.Context, vpn.LeaseID) error { return nil }

func (p *fakeVPNPlane) state() (started, stopped bool, installed []vpn.LeaseID) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.started, p.stopped, append([]vpn.LeaseID(nil), p.installed...)
}

// vpnPlaneFactory records the calls of the datapath's plane factory and
// hands out its planes.
type vpnPlaneFactory struct {
	planes []vpn.ManagedDataPlane
	calls  int
}

func (f *vpnPlaneFactory) build(_ *ServeConfig, _ *gateway.Gateway, _ *slog.Logger) ([]vpn.ManagedDataPlane, error) {
	f.calls++
	return f.planes, nil
}

// newDatapathRun is a run of the datapath child: the firewall is its hosted
// service, and the management VPN is enabled or not.
func newDatapathRun(vpnEnabled bool) *serviceRun {
	run := newServiceRun()
	run.handler = &fakeServiceHandler{name: gateway.ServiceFirewall}
	run.loaded = &ServeConfig{Gateway: &gateway.GatewayConfig{
		Enabled:       true,
		Firewall:      &gateway.FirewallConfig{Enabled: true, DefaultPolicy: "deny"},
		ManagementVPN: &gateway.ManagementVPNServiceConfig{Enabled: vpnEnabled},
	}}
	return run
}

// startDatapathProcess runs the datapath child with factory as its plane
// factory, admitting the test's own uid as the datapath caller.
func startDatapathProcess(t *testing.T, run *serviceRun, factory *vpnPlaneFactory) (serviceOptions, context.CancelFunc, <-chan error) {
	t.Helper()
	opts := serviceTestOptions(t)
	opts.uid = uint32(os.Getuid())
	deps := run.deps()
	deps.vpnDataPlanes = factory.build
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveProcess(ctx, "datapath", opts, deps, testLogger()) }()
	t.Cleanup(cancel)
	return opts, cancel, done
}

// installVPNPeer asks the datapath child to install a peer, as the vpn
// process's DatapathPlane does.
func installVPNPeer(t *testing.T, socket string) (*ipcv1.InstallVPNPeerResponse, error) {
	t.Helper()
	client, err := ipc.Dial(socket)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return client.InstallVPNPeer(ctx, &ipcv1.InstallVPNPeerRequest{Peer: &ipcv1.VPNPeer{
		LeaseId:   "lease-1",
		DataPlane: string(vpn.DataPlaneMASQUE),
		Address:   "100.64.0.2/32",
	}})
}

func TestServeProcess_DatapathHostsVPNPlanes(t *testing.T) {
	plane := &fakeVPNPlane{}
	factory := &vpnPlaneFactory{planes: []vpn.ManagedDataPlane{plane}}
	opts, cancel, done := startDatapathProcess(t, newDatapathRun(true), factory)

	var resp *ipcv1.InstallVPNPeerResponse
	require.Eventually(t, func() bool {
		var err error
		resp, err = installVPNPeer(t, opts.socket)
		return err == nil
	}, 5*time.Second, 10*time.Millisecond, "the datapath child must answer InstallVPNPeer")
	assert.Nil(t, resp.GetRefusal(), "a hosted plane installs the peer")

	started, _, installed := plane.state()
	assert.True(t, started, "the plane starts with the child")
	assert.Equal(t, []vpn.LeaseID{"lease-1"}, installed)
	assert.Equal(t, 1, factory.calls)

	cancel()
	require.NoError(t, <-done)
	_, stopped, _ := plane.state()
	assert.True(t, stopped, "the plane stops with the child")
}

func TestDatapathVPNPlanes_DisabledLeavesRefusal(t *testing.T) {
	factory := &vpnPlaneFactory{planes: []vpn.ManagedDataPlane{&fakeVPNPlane{}}}
	opts, cancel, done := startDatapathProcess(t, newDatapathRun(false), factory)

	var resp *ipcv1.InstallVPNPeerResponse
	require.Eventually(t, func() bool {
		var err error
		resp, err = installVPNPeer(t, opts.socket)
		return err == nil
	}, 5*time.Second, 10*time.Millisecond, "the datapath child must answer InstallVPNPeer")
	require.NotNil(t, resp.GetRefusal(), "with the VPN disabled the child hosts no plane")
	assert.Equal(t, ipcv1.VPNPeerRefusalClass_VPN_PEER_REFUSAL_CLASS_UNAVAILABLE, resp.GetRefusal().GetClass())
	assert.Zero(t, factory.calls, "a disabled VPN builds no plane")

	cancel()
	require.NoError(t, <-done)
}

func TestDatapathVPNPlanes_NonKernelClassNone(t *testing.T) {
	def, err := process.DefinitionByName("routing")
	require.NoError(t, err)
	require.NotEqual(t, process.ClassKernel, def.Class)

	factory := &vpnPlaneFactory{planes: []vpn.ManagedDataPlane{&fakeVPNPlane{}}}
	deps := newServiceRun().deps()
	deps.vpnDataPlanes = factory.build
	cfg := newDatapathRun(true).loaded
	gw, err := gateway.NewGateway(&gateway.GatewayConfig{Enabled: true, ID: "gw-test"})
	require.NoError(t, err)

	host, err := deps.datapathVPNPlanes(def, cfg, gw, testLogger())
	require.NoError(t, err)
	assert.Nil(t, host, "only the kernel-class child hosts VPN planes")
	assert.Zero(t, factory.calls)
}
