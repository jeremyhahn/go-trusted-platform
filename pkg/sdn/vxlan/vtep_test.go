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

package vxlan

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
)

// fakeOVS is an in-memory bridge holding VXLAN ports by name, standing in
// for *ovs.Client.
type fakeOVS struct {
	ports    map[string]*ovs.VXLANPort
	ofPorts  map[string]int32
	created  []*ovs.VXLANPortConfig
	nextPort int32

	addErr    error
	getErr    error
	deleteErr error
	ofPortErr error
}

func newFakeOVS() *fakeOVS {
	return &fakeOVS{
		ports:    make(map[string]*ovs.VXLANPort),
		ofPorts:  make(map[string]int32),
		nextPort: 7,
	}
}

// preload puts a port on the bridge as a previous run would have left it.
func (f *fakeOVS) preload(port string, p *ovs.VXLANPort) {
	p.Name = port
	f.ports[port] = p
	f.ofPorts[port] = f.nextPort
}

func (f *fakeOVS) AddVXLANPortWithName(_ context.Context, _, port string, cfg *ovs.VXLANPortConfig) (*ovs.VXLANPort, error) {
	if f.addErr != nil {
		return nil, f.addErr
	}
	if _, ok := f.ports[port]; ok {
		return nil, ovs.ErrVXLANPortExists
	}
	f.created = append(f.created, cfg)
	p := &ovs.VXLANPort{
		IsFlowRemote: cfg.RemoteFlow,
		IsFlowKey:    cfg.Key == 0,
		DstPort:      cfg.DstPort,
	}
	f.preload(port, p)
	return p, nil
}

func (f *fakeOVS) GetVXLANPortWithOptions(_ context.Context, _, port string) (*ovs.VXLANPort, error) {
	if f.getErr != nil {
		return nil, f.getErr
	}
	p, ok := f.ports[port]
	if !ok {
		return nil, ovs.ErrPortNotFound
	}
	return p, nil
}

func (f *fakeOVS) DeleteVXLANPort(_ context.Context, _, port string) error {
	if f.deleteErr != nil {
		return f.deleteErr
	}
	delete(f.ports, port)
	delete(f.ofPorts, port)
	return nil
}

func (f *fakeOVS) GetOFPort(_ context.Context, port string) (int32, error) {
	if f.ofPortErr != nil {
		return 0, f.ofPortErr
	}
	ofPort, ok := f.ofPorts[port]
	if !ok {
		return 0, ovs.ErrPortNotFound
	}
	return ofPort, nil
}

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func validVTEPConfig() VTEPConfig {
	return VTEPConfig{
		LocalIP:       netip.MustParseAddr("10.0.0.1"),
		UnderlayIface: "eth0",
		UnderlayMTU:   9216,
		VXLANPort:     DefaultVXLANPort,
	}
}

func newTestManager(t *testing.T, client OVSClient, opts ...VTEPManagerOption) *VTEPManager {
	t.Helper()
	m, err := NewVTEPManager(validVTEPConfig(), client, "br-int", testLogger(), opts...)
	require.NoError(t, err)
	return m
}

func TestNewVTEPManager(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		m := newTestManager(t, newFakeOVS())
		assert.Equal(t, DefaultPortName, m.PortName())
		assert.Equal(t, "br-int", m.GetBridgeName())
		assert.Equal(t, netip.MustParseAddr("10.0.0.1"), m.GetLocalVTEP())
		assert.Equal(t, validVTEPConfig(), m.GetConfig())
		assert.False(t, m.IsStarted())
	})

	t.Run("port name option", func(t *testing.T) {
		m := newTestManager(t, newFakeOVS(), WithPortName("vxlan-test"))
		assert.Equal(t, "vxlan-test", m.PortName())
	})

	refusals := map[string]struct {
		config VTEPConfig
		client OVSClient
		bridge string
		logger *slog.Logger
		opts   []VTEPManagerOption
		want   error
	}{
		"invalid config": {VTEPConfig{}, newFakeOVS(), "br-int", testLogger(), nil, ErrInvalidVTEPIP},
		"underlay too small": {func() VTEPConfig { c := validVTEPConfig(); c.UnderlayMTU = 9000; return c }(),
			newFakeOVS(), "br-int", testLogger(), nil, ErrMTUTooSmall},
		"nil client":      {validVTEPConfig(), nil, "br-int", testLogger(), nil, ErrOVSClientNil},
		"empty bridge":    {validVTEPConfig(), newFakeOVS(), "", testLogger(), nil, ErrBridgeNameEmpty},
		"nil logger":      {validVTEPConfig(), newFakeOVS(), "br-int", nil, nil, ErrLoggerNil},
		"empty port name": {validVTEPConfig(), newFakeOVS(), "br-int", testLogger(), []VTEPManagerOption{WithPortName("")}, ErrInvalidPortName},
	}
	for name, tc := range refusals {
		t.Run(name, func(t *testing.T) {
			_, err := NewVTEPManager(tc.config, tc.client, tc.bridge, tc.logger, tc.opts...)
			assert.ErrorIs(t, err, tc.want)
		})
	}
}

func TestVTEPManager_StartCreatesOneFlowBasedPort(t *testing.T) {
	client := newFakeOVS()
	m := newTestManager(t, client)

	require.NoError(t, m.Start(context.Background()))

	require.Len(t, client.created, 1)
	cfg := client.created[0]
	assert.True(t, cfg.RemoteFlow, "remote_ip=flow: each flow picks the remote VTEP")
	assert.False(t, cfg.RemoteIP.IsValid())
	assert.Zero(t, cfg.Key, "key=flow: each flow picks the VNI")
	assert.Equal(t, netip.MustParseAddr("10.0.0.1"), cfg.LocalIP)
	assert.Equal(t, DefaultVXLANPort, cfg.DstPort)

	ofPort, err := m.OFPort()
	require.NoError(t, err)
	assert.Equal(t, uint32(7), ofPort)
	assert.True(t, m.IsStarted())
}

func TestVTEPManager_StartAdoptsMatchingPort(t *testing.T) {
	client := newFakeOVS()
	first := newTestManager(t, client)
	require.NoError(t, first.Start(context.Background()))

	// A restarted daemon finds its own port still on the bridge.
	second := newTestManager(t, client)
	require.NoError(t, second.Start(context.Background()))
	assert.Len(t, client.created, 1)

	ofPort, err := second.OFPort()
	require.NoError(t, err)
	assert.Equal(t, uint32(7), ofPort)
}

func TestVTEPManager_StartRefusesForeignPort(t *testing.T) {
	tests := map[string]*ovs.VXLANPort{
		"fixed remote":   {IsFlowRemote: false, IsFlowKey: true, RemoteIP: netip.MustParseAddr("10.0.0.9")},
		"fixed key":      {IsFlowRemote: true, IsFlowKey: false, Key: 100},
		"other UDP port": {IsFlowRemote: true, IsFlowKey: true, DstPort: 8472},
	}
	for name, existing := range tests {
		t.Run(name, func(t *testing.T) {
			client := newFakeOVS()
			client.preload(DefaultPortName, existing)
			m := newTestManager(t, client)

			err := m.Start(context.Background())
			var conflict *ErrPortConflict
			require.ErrorAs(t, err, &conflict)
			assert.Equal(t, DefaultPortName, conflict.Port)
			assert.False(t, m.IsStarted())
		})
	}
}

func TestVTEPManager_StartFailures(t *testing.T) {
	boom := errors.New("ovsdb down")

	t.Run("create fails", func(t *testing.T) {
		client := newFakeOVS()
		client.addErr = boom
		err := newTestManager(t, client).Start(context.Background())
		assert.ErrorIs(t, err, boom)
	})

	t.Run("reading the existing port fails", func(t *testing.T) {
		client := newFakeOVS()
		client.preload(DefaultPortName, &ovs.VXLANPort{})
		client.getErr = boom
		err := newTestManager(t, client).Start(context.Background())
		assert.ErrorIs(t, err, boom)
	})

	t.Run("no ofport", func(t *testing.T) {
		client := newFakeOVS()
		client.ofPortErr = ovs.ErrPortNotFound
		m := newTestManager(t, client)
		assert.ErrorIs(t, m.Start(context.Background()), ovs.ErrPortNotFound)
		assert.False(t, m.IsStarted())
	})

	t.Run("already started", func(t *testing.T) {
		m := newTestManager(t, newFakeOVS())
		require.NoError(t, m.Start(context.Background()))
		assert.ErrorIs(t, m.Start(context.Background()), ErrManagerAlreadyStarted)
	})
}

func TestVTEPManager_Stop(t *testing.T) {
	t.Run("removes the port", func(t *testing.T) {
		client := newFakeOVS()
		m := newTestManager(t, client)
		require.NoError(t, m.Start(context.Background()))

		require.NoError(t, m.Stop(context.Background()))
		assert.NotContains(t, client.ports, DefaultPortName)
		assert.False(t, m.IsStarted())
		_, err := m.OFPort()
		assert.ErrorIs(t, err, ErrManagerNotStarted)
	})

	t.Run("not started is a no-op", func(t *testing.T) {
		client := newFakeOVS()
		client.deleteErr = errors.New("must not be called")
		assert.NoError(t, newTestManager(t, client).Stop(context.Background()))
	})

	t.Run("delete fails", func(t *testing.T) {
		client := newFakeOVS()
		m := newTestManager(t, client)
		require.NoError(t, m.Start(context.Background()))
		boom := errors.New("ovsdb down")
		client.deleteErr = boom
		assert.ErrorIs(t, m.Stop(context.Background()), boom)
	})

	t.Run("port already gone is stopped", func(t *testing.T) {
		client := newFakeOVS()
		m := newTestManager(t, client)
		require.NoError(t, m.Start(context.Background()))
		client.deleteErr = ovs.ErrVXLANPortNotFound

		require.NoError(t, m.Stop(context.Background()))
		assert.False(t, m.IsStarted())
	})
}

func TestVTEPManager_OFPortBeforeStart(t *testing.T) {
	_, err := newTestManager(t, newFakeOVS()).OFPort()
	assert.ErrorIs(t, err, ErrManagerNotStarted)
}

func TestVTEPManager_StartRefusesAPortWithoutANumber(t *testing.T) {
	client := newFakeOVS()
	client.nextPort = -1
	m := newTestManager(t, client)

	assert.ErrorIs(t, m.Start(context.Background()), ErrOFPortUnassigned)
	assert.False(t, m.IsStarted())
}

func TestVTEPManager_ResolveOFPortRereadsTheNumber(t *testing.T) {
	client := newFakeOVS()
	m := newTestManager(t, client)
	require.NoError(t, m.Start(context.Background()))
	client.ofPorts[DefaultPortName] = 17 // a switch that recreated its datapath

	ofPort, err := m.ResolveOFPort(context.Background())

	require.NoError(t, err)
	assert.Equal(t, uint32(17), ofPort)
	cached, err := m.OFPort()
	require.NoError(t, err)
	assert.Equal(t, uint32(17), cached)
}

func TestVTEPManager_ResolveOFPortFailures(t *testing.T) {
	t.Run("before start", func(t *testing.T) {
		_, err := newTestManager(t, newFakeOVS()).ResolveOFPort(context.Background())
		assert.ErrorIs(t, err, ErrManagerNotStarted)
	})

	t.Run("unreadable", func(t *testing.T) {
		client := newFakeOVS()
		m := newTestManager(t, client)
		require.NoError(t, m.Start(context.Background()))
		boom := errors.New("ovsdb down")
		client.ofPortErr = boom

		_, err := m.ResolveOFPort(context.Background())

		assert.ErrorIs(t, err, boom)
	})

	t.Run("without a number", func(t *testing.T) {
		client := newFakeOVS()
		m := newTestManager(t, client)
		require.NoError(t, m.Start(context.Background()))
		client.ofPorts[DefaultPortName] = -1

		_, err := m.ResolveOFPort(context.Background())

		assert.ErrorIs(t, err, ErrOFPortUnassigned)
	})
}
