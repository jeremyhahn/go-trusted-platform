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

package fabric

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// portCall records one port operation on a mock driver.
type portCall struct {
	op      string
	port    PortRef
	allowed []uint16
	native  uint16
	mtu     int
}

// mockDriver records every operation for verification.
type mockDriver struct {
	mu         sync.Mutex
	connectErr error
	pingErr    error
	vlanErr    error
	lagErr     error
	portErr    error
	closeErr   error
	vlans      map[uint16]string
	lags       []LAGConfig
	ports      []portCall
}

func newMock() *mockDriver { return &mockDriver{vlans: map[uint16]string{}} }

func (m *mockDriver) Connect(context.Context) error { return m.connectErr }
func (m *mockDriver) Close() error                  { return m.closeErr }
func (m *mockDriver) Ping(context.Context) error    { return m.pingErr }

func (m *mockDriver) EnsureVLAN(_ context.Context, vlan uint16, name string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.vlanErr != nil {
		return m.vlanErr
	}
	m.vlans[vlan] = name
	return nil
}

func (m *mockDriver) EnsureLAG(_ context.Context, lag LAGConfig) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.lagErr != nil {
		return m.lagErr
	}
	m.lags = append(m.lags, lag)
	return nil
}

func (m *mockDriver) record(c portCall) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.portErr != nil {
		return m.portErr
	}
	m.ports = append(m.ports, c)
	return nil
}

func (m *mockDriver) SetPortAccess(_ context.Context, port PortRef, vlan uint16, mtu int) error {
	return m.record(portCall{op: "access", port: port, native: vlan, mtu: mtu})
}

func (m *mockDriver) SetPortTrunk(_ context.Context, port PortRef, allowed []uint16, native uint16, mtu int) error {
	return m.record(portCall{op: "trunk", port: port, allowed: allowed, native: native, mtu: mtu})
}

func (m *mockDriver) DisablePort(_ context.Context, port PortRef) error {
	return m.record(portCall{op: "disable", port: port})
}

func (m *mockDriver) call(port string) (portCall, bool) {
	for _, c := range m.ports {
		if c.port.Port == port {
			return c, true
		}
	}
	return portCall{}, false
}

func quietLogger() *slog.Logger { return slog.New(slog.NewTextHandler(io.Discard, nil)) }

func testPlan(t *testing.T, user ...zone.ZoneConfig) *netplan.Plan {
	t.Helper()
	zones, err := zone.Resolve(user)
	require.NoError(t, err)
	p, err := netplan.New(netplan.Environment{ID: 4}, zones)
	require.NoError(t, err)
	return p
}

func newTestManager(t *testing.T) (Manager, *mockDriver, *mockDriver) {
	t.Helper()
	a, b := newMock(), newMock()
	mgr, err := NewManagerWithDrivers(validFabricConfig(), testPlan(t), quietLogger(),
		map[string]Driver{"sw-01": a, "sw-02": b})
	require.NoError(t, err)
	return mgr, a, b
}

// TestApplyFabric programs every zone VLAN, the LAG, the peer-link and each
// port's class from the plan.
func TestApplyFabric(t *testing.T) {
	mgr, a, b := newTestManager(t)
	require.NoError(t, mgr.ApplyFabric(context.Background()))

	for _, d := range []*mockDriver{a, b} {
		assert.Len(t, d.vlans, 9)
		assert.Equal(t, "control-plane", d.vlans[406])
		assert.Equal(t, "transit", d.vlans[400])
	}
	require.Len(t, a.lags, 1)

	gw, ok := a.call("Ethernet1/3")
	require.True(t, ok)
	assert.Equal(t, portCall{op: "trunk", port: PortRef{SwitchID: "sw-01", Port: "Ethernet1/3"},
		allowed: []uint16{400, 401, 404, 405, 406, 408}, mtu: 9216}, gw)

	hv, _ := a.call("Ethernet1/25")
	assert.Equal(t, []uint16{401, 403, 404, 405, 406, 407, 408}, hv.allowed)
	assert.Equal(t, uint16(405), hv.native)

	bmc, ok := b.call("Ethernet1/41")
	require.True(t, ok)
	assert.Equal(t, "access", bmc.op)
	assert.Equal(t, uint16(402), bmc.native)

	for _, d := range []*mockDriver{a, b} {
		peer, ok := d.call("Ethernet1/49")
		require.True(t, ok, "peer-link on both switches")
		assert.Len(t, peer.allowed, 9)
	}
	_, onPeer := b.call("Ethernet1/25")
	assert.False(t, onPeer, "ApplyFabric applies a port only on the switch it is listed on")
}

// TestApplyFabric_Errors covers connect, VLAN, LAG and port failures and a
// class the plan cannot carry.
func TestApplyFabric_Errors(t *testing.T) {
	boom := errors.New("boom")
	tests := []struct {
		name  string
		setup func(a *mockDriver)
		check func(t *testing.T, err error)
	}{
		{"connect", func(a *mockDriver) { a.connectErr = boom }, func(t *testing.T, err error) {
			var target ErrDriverConnect
			require.True(t, errors.As(err, &target))
		}},
		{"vlan", func(a *mockDriver) { a.vlanErr = boom }, opErr("EnsureVLAN")},
		{"lag", func(a *mockDriver) { a.lagErr = boom }, opErr("EnsureLAG")},
		{"port", func(a *mockDriver) { a.portErr = boom }, opErr("ApplyPortClass")},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			a, b := newMock(), newMock()
			tc.setup(a)
			mgr, err := NewManagerWithDrivers(validFabricConfig(), testPlan(t), quietLogger(),
				map[string]Driver{"sw-01": a, "sw-02": b})
			require.NoError(t, err)
			tc.check(t, mgr.ApplyFabric(context.Background()))
		})
	}

	t.Run("bmc class without management", func(t *testing.T) {
		plan := testPlan(t, zone.ZoneConfig{Name: zone.ZoneManagement, Omit: true})
		mgr, err := NewManagerWithDrivers(validFabricConfig(), plan, quietLogger(),
			map[string]Driver{"sw-01": newMock(), "sw-02": newMock()})
		require.NoError(t, err)
		err = mgr.ApplyFabric(context.Background())
		var target ErrPortClassPlan
		require.True(t, errors.As(err, &target), "got %v", err)
		assert.Equal(t, zone.PortClassBMC, target.Class)
		var empty netplan.ErrEmptyPortClass
		assert.True(t, errors.As(err, &empty))
	})

	t.Run("lag on a switch without a driver", func(t *testing.T) {
		mgr, err := NewManagerWithDrivers(validFabricConfig(), testPlan(t), quietLogger(),
			map[string]Driver{"sw-02": newMock()})
		require.NoError(t, err)
		var target ErrUnknownSwitch
		require.True(t, errors.As(mgr.ApplyFabric(context.Background()), &target))
	})
}

func opErr(op string) func(t *testing.T, err error) {
	return func(t *testing.T, err error) {
		t.Helper()
		var target ErrDriverOperation
		require.True(t, errors.As(err, &target), "got %v", err)
		assert.Equal(t, op, target.Operation)
	}
}

// TestLifecycle walks a hypervisor port through provisioning, its class,
// quarantine and down, on both MC-LAG peers.
func TestLifecycle(t *testing.T) {
	mgr, a, b := newTestManager(t)
	ctx := context.Background()
	port := PortRef{SwitchID: "sw-01", Port: "Ethernet1/26"}

	require.NoError(t, mgr.ProvisionPort(ctx, port))
	require.NoError(t, mgr.ActivatePort(ctx, port, zone.PortClassHypervisor))
	require.NoError(t, mgr.QuarantinePort(ctx, port))
	require.NoError(t, mgr.DisablePort(ctx, port))

	for _, d := range []*mockDriver{a, b} {
		require.Len(t, d.ports, 4)
		assert.Equal(t, []uint16{405}, d.ports[0].allowed)
		assert.Equal(t, uint16(405), d.ports[0].native)
		assert.Equal(t, 9216, d.ports[0].mtu)
		assert.Len(t, d.ports[1].allowed, 7)
		assert.Equal(t, uint16(405), d.ports[1].native)
		assert.Equal(t, []uint16{404}, d.ports[2].allowed)
		assert.Equal(t, uint16(404), d.ports[2].native)
		assert.Equal(t, "disable", d.ports[3].op)
	}
	assert.Equal(t, "sw-02", b.ports[0].port.SwitchID, "the peer gets the same port on its own switch")
}

// TestLifecycle_Errors covers bad port refs, unknown switches, unknown
// classes, a zone missing from the plan and driver failures (on the switch
// and on the peer).
func TestLifecycle_Errors(t *testing.T) {
	ctx := context.Background()
	mgr, a, b := newTestManager(t)

	var badRef ErrInvalidPortRef
	require.True(t, errors.As(mgr.ProvisionPort(ctx, PortRef{Port: "p"}), &badRef))
	require.True(t, errors.As(mgr.ActivatePort(ctx, PortRef{Port: "p"}, zone.PortClassGateway), &badRef))
	require.True(t, errors.As(mgr.DisablePort(ctx, PortRef{Port: "p"}), &badRef))

	var unknown ErrUnknownSwitch
	require.True(t, errors.As(mgr.QuarantinePort(ctx, PortRef{SwitchID: "sw-09", Port: "p"}), &unknown))

	var planErr ErrPortClassPlan
	err := mgr.ActivatePort(ctx, PortRef{SwitchID: "sw-01", Port: "p"}, "uplink")
	require.True(t, errors.As(err, &planErr), "got %v", err)

	b.portErr = errors.New("peer down")
	var op ErrDriverOperation
	err = mgr.DisablePort(ctx, PortRef{SwitchID: "sw-01", Port: "p"})
	require.True(t, errors.As(err, &op))
	assert.Equal(t, "sw-02", op.SwitchID)

	a.portErr = errors.New("down")
	err = mgr.ActivatePort(ctx, PortRef{SwitchID: "sw-01", Port: "p"}, zone.PortClassGateway)
	require.True(t, errors.As(err, &op))
	assert.Equal(t, "sw-01", op.SwitchID)
	assert.Equal(t, "ActivatePort", op.Operation)
}

// TestNewManager covers construction: a nil plan, an invalid config and a
// vendor with no driver.
func TestNewManager(t *testing.T) {
	plan := testPlan(t)
	var nilPlan ErrNilPlan
	_, err := NewManager(validFabricConfig(), nil, quietLogger())
	require.True(t, errors.As(err, &nilPlan))
	_, err = NewManagerWithDrivers(validFabricConfig(), nil, quietLogger(), nil)
	require.True(t, errors.As(err, &nilPlan))

	_, err = NewManager(&FabricConfig{}, plan, quietLogger())
	var invalid ErrInvalidFabricConfig
	require.True(t, errors.As(err, &invalid))
	_, err = NewManagerWithDrivers(&FabricConfig{}, plan, quietLogger(), nil)
	require.True(t, errors.As(err, &invalid))

	_, err = NewManager(validFabricConfig(), plan, quietLogger())
	var noDriver ErrDriverConnect
	require.True(t, errors.As(err, &noDriver), "vendor mock has no registered driver")

	RegisterDriver("fabric-test", func(SwitchConfig, *slog.Logger) (Driver, error) { return newMock(), nil })
	cfg := validFabricConfig()
	for i := range cfg.Switches {
		cfg.Switches[i].Vendor = "fabric-test"
	}
	mgr, err := NewManager(cfg, plan, quietLogger())
	require.NoError(t, err)
	require.NoError(t, mgr.Close())
}

// TestSwitchStatus reports connected, disconnected and unknown switches.
func TestSwitchStatus(t *testing.T) {
	mgr, _, b := newTestManager(t)
	ctx := context.Background()

	st, err := mgr.SwitchStatus(ctx, "sw-01")
	require.NoError(t, err)
	assert.True(t, st.Connected)
	assert.Equal(t, "192.0.2.10", st.MgmtIP)

	b.pingErr = errors.New("unreachable")
	st, err = mgr.SwitchStatus(ctx, "sw-02")
	require.NoError(t, err)
	assert.False(t, st.Connected)

	_, err = mgr.SwitchStatus(ctx, "sw-09")
	var unknown ErrUnknownSwitch
	require.True(t, errors.As(err, &unknown))
}

// TestClose returns the last driver close error.
func TestClose(t *testing.T) {
	mgr, a, _ := newTestManager(t)
	require.NoError(t, mgr.Close())
	a.closeErr = errors.New("close failed")
	require.Error(t, mgr.Close())
}

// TestDriverFor covers a registered and an unregistered vendor.
func TestDriverFor(t *testing.T) {
	RegisterDriver("fabric-test-2", func(SwitchConfig, *slog.Logger) (Driver, error) { return newMock(), nil })
	_, err := DriverFor(SwitchConfig{Vendor: "fabric-test-2"}, quietLogger())
	require.NoError(t, err)
	_, err = DriverFor(SwitchConfig{Vendor: "none"}, quietLogger())
	var target ErrDriverNotFound
	require.True(t, errors.As(err, &target))
}
