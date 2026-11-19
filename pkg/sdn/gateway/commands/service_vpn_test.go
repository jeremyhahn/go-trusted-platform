package commands

import (
	"context"
	"errors"
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
	startErr  error
	started   bool
	stopped   bool
	installed []vpn.LeaseID
}

func (p *fakeVPNPlane) Kind() vpn.DataPlaneKind { return vpn.DataPlaneMASQUE }

func (p *fakeVPNPlane) Start(context.Context) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.started = true
	return p.startErr
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

// newWireGuardRun is a run of the datapath child: the firewall is its hosted
// service, and the management VPN is enabled or not.
func newWireGuardRun(vpnEnabled bool) *serviceRun {
	run := newServiceRun()
	run.handler = &fakeServiceHandler{name: gateway.ServiceVPNWireGuard}
	run.loaded = &ServeConfig{Gateway: &gateway.GatewayConfig{
		Enabled:       true,
		ManagementVPN: &gateway.ManagementVPNServiceConfig{Enabled: vpnEnabled},
	}}
	return run
}

// startWireGuardProcess runs the datapath child with factory as its plane
// factory, admitting the test's own uid as the datapath caller.
func startWireGuardProcess(t *testing.T, run *serviceRun, factory *vpnPlaneFactory) (serviceOptions, context.CancelFunc, <-chan error) {
	t.Helper()
	opts := serviceTestOptions(t)
	opts.uid = uint32(os.Getuid())
	deps := run.deps()
	deps.vpnDataPlanes = factory.build
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- serveProcess(ctx, process.WireGuardProcess, opts, deps, testLogger()) }()
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

// withdrawVPNPeers asks the child to withdraw every peer of the WireGuard
// plane, as the supervisor does for a given-up vpn child.
func withdrawVPNPeers(t *testing.T, socket string) (*ipcv1.ReconcileVPNPeersResponse, error) {
	t.Helper()
	client, err := ipc.Dial(socket)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	return client.ReconcileVPNPeers(ctx, &ipcv1.ReconcileVPNPeersRequest{DataPlane: "wireguard"})
}

func TestServeProcess_WireGuardChildHostsThePlanes(t *testing.T) {
	plane := &fakeVPNPlane{}
	factory := &vpnPlaneFactory{planes: []vpn.ManagedDataPlane{plane}}
	opts, cancel, done := startWireGuardProcess(t, newWireGuardRun(true), factory)

	var resp *ipcv1.InstallVPNPeerResponse
	require.Eventually(t, func() bool {
		var err error
		resp, err = installVPNPeer(t, opts.socket)
		return err == nil
	}, 5*time.Second, 10*time.Millisecond, "the wireguard child must answer InstallVPNPeer")
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

// A plane that fails to start (an unresolvable key, a hub that cannot be
// created) keeps the child's hosted services from starting: the
// supervisor accepts an active service before it reads the start error,
// so a started datapath would report ready while refusing every peer RPC.
func TestServeProcess_PlaneFailureKeepsServicesInactive(t *testing.T) {
	plane := &fakeVPNPlane{startErr: errors.New("wireguard hub key unresolvable")}
	factory := &vpnPlaneFactory{planes: []vpn.ManagedDataPlane{plane}}
	run := newWireGuardRun(true)
	opts, cancel, done := startWireGuardProcess(t, run, factory)

	var startErr string
	var active map[string]bool
	require.Eventually(t, func() bool {
		var ok bool
		startErr, active, ok = processStatus(t, opts.socket)
		return ok && startErr != ""
	}, 5*time.Second, 10*time.Millisecond, "the child must report the plane's start error")
	assert.Contains(t, startErr, "wireguard hub key unresolvable")
	for name, on := range active {
		assert.False(t, on, "service %s must not be active after a plane failure", name)
	}
	assert.False(t, run.handler.active.Load(), "the gateway's services must not start after a plane failure")
	withdrawn, err := withdrawVPNPeers(t, opts.socket)
	require.NoError(t, err)
	assert.Equal(t, ipcv1.VPNPeerRefusalClass_VPN_PEER_REFUSAL_CLASS_UNAVAILABLE, withdrawn.GetRefusal().GetClass(),
		"a failed plane start must not confirm a peer withdrawal")

	cancel()
	<-done
}

func TestDatapathVPNPlanes_DisabledLeavesRefusal(t *testing.T) {
	factory := &vpnPlaneFactory{planes: []vpn.ManagedDataPlane{&fakeVPNPlane{}}}
	opts, cancel, done := startWireGuardProcess(t, newWireGuardRun(false), factory)

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

func TestDatapathVPNPlanes_OnlyTheWireGuardRow(t *testing.T) {
	// The datapath child is kernel-class too, but hosts no VPN plane: the
	// hub belongs to the wireguard row alone (ruling 942).
	for _, name := range []string{"datapath", "routing"} {
		t.Run(name, func(t *testing.T) {
			def, err := process.DefinitionByName(name)
			require.NoError(t, err)

			factory := &vpnPlaneFactory{planes: []vpn.ManagedDataPlane{&fakeVPNPlane{}}}
			deps := newServiceRun().deps()
			deps.vpnDataPlanes = factory.build
			cfg := newWireGuardRun(true).loaded
			gw, err := gateway.NewGateway(&gateway.GatewayConfig{Enabled: true, ID: "gw-test"})
			require.NoError(t, err)

			host, err := deps.datapathVPNPlanes(def, cfg, gw, testLogger())
			require.NoError(t, err)
			assert.Nil(t, host, "only the wireguard child hosts VPN planes")
			assert.Zero(t, factory.calls)
		})
	}
}

// A predecessor killed with SIGKILL leaves the hub device, and every peer
// it installed, in the kernel. When the restarted datapath builds no plane
// (the VPN disabled, or no key-ref, address or resolver for the hub), no
// hub's Up runs to remove it, so the child removes it itself; otherwise
// those peers would pass traffic past their leases while every removal RPC
// is refused. A removal failure keeps the child from starting.
func TestServeProcess_WireGuardChildRemovesStaleHubFirst(t *testing.T) {
	// A killed predecessor's hub and peers pass traffic past their leases
	// until removed, so the wireguard child removes them before any
	// startup step that can fail (Codex #1717 round 2).
	t.Run("the gateway does not assemble", func(t *testing.T) {
		run := newWireGuardRun(true)
		run.buildErr = errors.New("ovsdb unavailable")
		removals := 0
		deps := run.deps()
		deps.removeStaleVPNHub = func(*slog.Logger) error { removals++; return nil }
		err := serveProcess(context.Background(), process.WireGuardProcess, serviceTestOptions(t), deps, testLogger())
		require.ErrorIs(t, err, run.buildErr)
		assert.Equal(t, 1, removals, "the stale hub goes before assembly can fail")
	})

	t.Run("the configuration is unreadable", func(t *testing.T) {
		run := newWireGuardRun(true)
		run.readErr = os.ErrPermission
		removals := 0
		deps := run.deps()
		deps.removeStaleVPNHub = func(*slog.Logger) error { removals++; return nil }
		err := serveProcess(context.Background(), process.WireGuardProcess, serviceTestOptions(t), deps, testLogger())
		var unreadable *ErrServiceConfigUnreadable
		require.ErrorAs(t, err, &unreadable)
		assert.Equal(t, 1, removals, "the stale hub goes before the configuration is read")
	})

	t.Run("the removal fails", func(t *testing.T) {
		run := newWireGuardRun(true)
		boom := errors.New("link busy")
		deps := run.deps()
		deps.removeStaleVPNHub = func(*slog.Logger) error { return boom }
		err := serveProcess(context.Background(), process.WireGuardProcess, serviceTestOptions(t), deps, testLogger())
		require.ErrorIs(t, err, boom)
		assert.Zero(t, run.readCalls, "nothing runs after a failed removal")
		assert.Nil(t, run.built, "no gateway is assembled after a failed removal")
	})

	for _, name := range []string{"datapath", "routing"} {
		t.Run("the "+name+" child leaves the hub", func(t *testing.T) {
			run := newServiceRun()
			failure := errors.New("injected")
			run.buildErr = failure
			removals := 0
			deps := run.deps()
			deps.removeStaleVPNHub = func(*slog.Logger) error { removals++; return nil }
			err := serveProcess(context.Background(), name, serviceTestOptions(t), deps, testLogger())
			require.ErrorIs(t, err, failure)
			assert.Zero(t, removals, "only the wireguard child owns the hub device")
		})
	}
}
