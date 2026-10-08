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

package gateway

import (
	"bytes"
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/tunnel"
)

// recordingTunnels is the fake tunnel manager plus the full configuration of
// every EnsureTunnel call and a shared, ordered event log.
type recordingTunnels struct {
	*fakeTunnelManager
	log     *eventLog
	configs []tunnel.TunnelConfig
}

func (r *recordingTunnels) EnsureTunnel(ctx context.Context, cfg tunnel.TunnelConfig) error {
	if err := r.fakeTunnelManager.EnsureTunnel(ctx, cfg); err != nil {
		return err
	}
	r.configs = append(r.configs, cfg)
	r.log.add("tunnel:" + cfg.Name)
	return nil
}

// fakeUplinkManager records the routing uplinks the service programs.
type fakeUplinkManager struct {
	log       *eventLog
	configs   []tunnel.UplinkConfig
	ensureErr error
	closed    int
}

func (f *fakeUplinkManager) EnsureUplink(_ context.Context, cfg tunnel.UplinkConfig) error {
	if f.ensureErr != nil {
		return f.ensureErr
	}
	f.configs = append(f.configs, cfg)
	f.log.add("uplink:" + cfg.Name)
	return nil
}

func (f *fakeUplinkManager) Close() error {
	f.closed++
	f.log.add("uplinks-closed")
	return nil
}

type eventLog struct {
	mu     sync.Mutex
	events []string
}

func (l *eventLog) add(e string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.events = append(l.events, e)
}

func (l *eventLog) snapshot() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]string(nil), l.events...)
}

// tunnelsDoc is a gatewayd `gateway:` section using every key the tunnels
// feature promises: the ipsec transport with a key reference, an uplink pin,
// the carrier knobs, and the routing-uplinks the pin resolves against.
const tunnelsDoc = `
gateway:
  enabled: true
  id: tunnels-yaml
  routing-uplinks:
    - name: isp-a
      interface: eth0
      table: 101
      gateway-v4: 198.51.100.1
      gateway-v6: "2001:db8:a::1"
      addresses: ["198.51.100.6/29"]
      priority: 1100
  tunnels:
    - name: ipsec-relay-a
      type: gre
      transport: ipsec
      uplink: isp-a
      local: 198.51.100.6
      remote: 203.0.113.100
      tunnel-ip: 10.4.128.2/31
      tunnel-ipv6: "2001:db8:0:1::/127"
      mtu: 1380
      ttl: 32
      key: 7
      ipsec:
        key-ref: kms://tunnel/relay-a/out
        peer-key-ref: kms://tunnel/relay-a/in
        spi-out: 256
        spi-in: 257
        replay-window: 256
        rekey-interval: 4h
`

func decodeGatewayDoc(t *testing.T, doc string) *GatewayConfig {
	t.Helper()
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(bytes.NewReader([]byte(doc))))
	cfg := &GatewayConfig{}
	require.NoError(t, v.UnmarshalKey("gateway", cfg))
	return cfg
}

// TestTunnelsSection_DecodesEveryKeyAndReachesTheManager is the
// config-reachability test for #606: every key the section documents must
// survive the decode and arrive, unchanged, at the tunnel manager.
func TestTunnelsSection_DecodesEveryKeyAndReachesTheManager(t *testing.T) {
	cfg := decodeGatewayDoc(t, tunnelsDoc)
	require.NoError(t, cfg.Validate())

	log := &eventLog{}
	tunnels := &recordingTunnels{fakeTunnelManager: &fakeTunnelManager{}, log: log}
	uplinks := &fakeUplinkManager{log: log}
	cfg.Host = &HostRuntime{TunnelManager: tunnels, UplinkManager: uplinks}
	gw := startGateway(t, cfg)

	require.Len(t, tunnels.configs, 1)
	got := tunnels.configs[0]
	assert.Equal(t, "ipsec-relay-a", got.Name)
	assert.Equal(t, tunnel.TransportIPsec, got.Transport)
	assert.Equal(t, "isp-a", got.Uplink, "the uplink pin must reach the manager")
	assert.Equal(t, "2001:db8:0:1::/127", got.TunnelIPv6)
	assert.Equal(t, 1380, got.MTU)
	assert.Equal(t, 32, got.TTL)
	assert.Equal(t, uint32(7), got.Key)
	require.NotNil(t, got.IPsec)
	assert.Equal(t, "kms://tunnel/relay-a/out", got.IPsec.KeyRef)
	assert.Equal(t, "kms://tunnel/relay-a/in", got.IPsec.PeerKeyRef)
	assert.Equal(t, uint32(256), got.IPsec.SPIOut)
	assert.Equal(t, uint32(257), got.IPsec.SPIIn)
	assert.Equal(t, 256, got.IPsec.ReplayWindow)
	assert.Equal(t, 4*time.Hour, got.IPsec.RekeyInterval)

	require.Len(t, uplinks.configs, 1)
	assert.Equal(t, tunnel.UplinkConfig{
		Name: "isp-a", Interface: "eth0", Table: 101,
		GatewayV4: "198.51.100.1", GatewayV6: "2001:db8:a::1",
		Addresses: []string{"198.51.100.6/29"}, Priority: 1100,
	}, uplinks.configs[0])

	assert.Equal(t, []string{"uplink:isp-a", "tunnel:ipsec-relay-a"}, log.snapshot(),
		"the uplink's table exists before a tunnel is pinned to it")

	require.NoError(t, gw.Stop(context.Background()))
	assert.Equal(t, 1, uplinks.closed, "Stop closes the uplink manager")
	assert.True(t, tunnels.closed)
	assert.Equal(t, "uplinks-closed", log.snapshot()[len(log.snapshot())-1],
		"the uplinks are removed after the tunnels pinned to them")
}

func TestGatewayConfig_Validate_Tunnels(t *testing.T) {
	uplinkA := tunnel.UplinkConfig{Name: "isp-a", Interface: "eth0", Table: 101, GatewayV4: "198.51.100.1", Addresses: []string{"198.51.100.6/29"}}
	uplinkB := tunnel.UplinkConfig{Name: "isp-b", Interface: "eth1", Table: 102, GatewayV4: "192.0.2.1", Addresses: []string{"192.0.2.6/29"}}
	gre := func(name, uplink string) TunnelConfig {
		return TunnelConfig{Name: name, Type: "gre", Uplink: uplink, Local: "198.51.100.6", Remote: "203.0.113.100", TunnelIP: "10.4.128.2/31"}
	}

	t.Run("a tunnel pinned to a declared uplink is valid", func(t *testing.T) {
		cfg := baseGatewayConfig("ok")
		cfg.RoutingUplinks = []RoutingUplinkConfig{uplinkA, uplinkB}
		cfg.Tunnels = []TunnelConfig{gre("gre-a", "isp-a"), gre("gre-b", "")}
		require.NoError(t, cfg.Validate())
	})

	t.Run("a tunnel naming an undeclared uplink is refused", func(t *testing.T) {
		cfg := baseGatewayConfig("undeclared")
		cfg.RoutingUplinks = []RoutingUplinkConfig{uplinkA}
		cfg.Tunnels = []TunnelConfig{gre("gre-a", "isp-z")}
		var unknown *tunnel.ErrUplinkUnknown
		require.True(t, errors.As(cfg.Validate(), &unknown))
		assert.Equal(t, "gre-a", unknown.Name)
		assert.Equal(t, "isp-z", unknown.Uplink)
	})

	t.Run("an uplink pin with no routing-uplinks section is refused", func(t *testing.T) {
		cfg := baseGatewayConfig("no-section")
		cfg.Tunnels = []TunnelConfig{gre("gre-a", "isp-a")}
		var unknown *tunnel.ErrUplinkUnknown
		require.True(t, errors.As(cfg.Validate(), &unknown))
	})

	t.Run("a routing uplink that fails its own validation is refused", func(t *testing.T) {
		bad := uplinkA
		bad.Table = 7
		cfg := baseGatewayConfig("bad-uplink")
		cfg.RoutingUplinks = []RoutingUplinkConfig{bad}
		var invalid *tunnel.ErrInvalidUplinkConfig
		require.True(t, errors.As(cfg.Validate(), &invalid))
		assert.Equal(t, "isp-a", invalid.Name)
	})

	t.Run("a duplicate uplink name is refused", func(t *testing.T) {
		dup := uplinkB
		dup.Name = "isp-a"
		cfg := baseGatewayConfig("dup-name")
		cfg.RoutingUplinks = []RoutingUplinkConfig{uplinkA, dup}
		var invalid *tunnel.ErrInvalidUplinkConfig
		require.True(t, errors.As(cfg.Validate(), &invalid))
		assert.Contains(t, invalid.Reason, "more than once")
	})

	t.Run("a table shared by two uplinks is refused", func(t *testing.T) {
		dup := uplinkB
		dup.Table = 101
		cfg := baseGatewayConfig("dup-table")
		cfg.RoutingUplinks = []RoutingUplinkConfig{uplinkA, dup}
		var invalid *tunnel.ErrInvalidUplinkConfig
		require.True(t, errors.As(cfg.Validate(), &invalid))
		assert.Contains(t, invalid.Reason, "isp-a")
	})

	t.Run("an ipsec tunnel without a key reference is refused with the tunnel package's error", func(t *testing.T) {
		cfg := baseGatewayConfig("no-key")
		tun := gre("ipsec-a", "")
		tun.Transport = tunnel.TransportIPsec
		tun.IPsec = &tunnel.IPsecConfig{SPIOut: 1, SPIIn: 2}
		cfg.Tunnels = []TunnelConfig{tun}
		var invalid *tunnel.ErrInvalidTunnelConfig
		require.True(t, errors.As(cfg.Validate(), &invalid))
		assert.Contains(t, invalid.Reason, "key-ref")
	})
}

func TestGatewayConfig_EnabledServices_RoutingUplinksAloneStartTheTunnelsService(t *testing.T) {
	cfg := baseGatewayConfig("uplinks-only")
	assert.NotContains(t, cfg.EnabledServices(), ServiceTunnels)
	cfg.RoutingUplinks = []RoutingUplinkConfig{{Name: "isp-a"}}
	assert.Contains(t, cfg.EnabledServices(), ServiceTunnels,
		"a routing-uplinks section that no service programs would be accepted and dropped")
}

func TestTunnelsService_UplinkFailureStartsNothing(t *testing.T) {
	log := &eventLog{}
	tunnels := &recordingTunnels{fakeTunnelManager: &fakeTunnelManager{}, log: log}
	uplinks := &fakeUplinkManager{log: log, ensureErr: &tunnel.ErrUplinkOperationFailed{Name: "isp-a", Operation: "resolve interface eth0", Cause: errors.New("no such device")}}
	cfg := decodeGatewayDoc(t, tunnelsDoc)
	cfg.Host = &HostRuntime{TunnelManager: tunnels, UplinkManager: uplinks}

	gw, err := NewGateway(cfg)
	require.NoError(t, err)
	gw.SetNodeMetrics(validNodeMetrics())
	err = gw.Start(context.Background())

	var failed *ErrServiceStartFailed
	require.True(t, errors.As(err, &failed), "got %v", err)
	var opFailed *tunnel.ErrUplinkOperationFailed
	require.True(t, errors.As(err, &opFailed), "the uplink error is the one the operator acts on: %v", err)
	assert.Empty(t, tunnels.configs, "no tunnel is created against a table that does not exist")
	assert.Equal(t, 1, uplinks.closed, "whatever the uplink manager installed is removed")
}

func TestTunnelsService_TunnelFailureRemovesTheUplinks(t *testing.T) {
	log := &eventLog{}
	tunnels := &recordingTunnels{
		fakeTunnelManager: &fakeTunnelManager{ensureErr: map[string]error{"ipsec-relay-a": errors.New("EPERM")}},
		log:               log,
	}
	uplinks := &fakeUplinkManager{log: log}
	cfg := decodeGatewayDoc(t, tunnelsDoc)
	cfg.Host = &HostRuntime{TunnelManager: tunnels, UplinkManager: uplinks}

	gw, err := NewGateway(cfg)
	require.NoError(t, err)
	gw.SetNodeMetrics(validNodeMetrics())
	require.Error(t, gw.Start(context.Background()))

	assert.Equal(t, 1, uplinks.closed, "a failed start leaves no policy routing behind")
}

func TestBuildTunnels_InjectedManagerWithoutUplinkManagerIsRefused(t *testing.T) {
	cfg := decodeGatewayDoc(t, tunnelsDoc)
	cfg.Host = &HostRuntime{TunnelManager: &fakeTunnelManager{}}

	_, err := buildTunnels(&Gateway{config: cfg})

	var unavailable *ErrServiceUnavailable
	require.True(t, errors.As(err, &unavailable), "got %v", err)
	assert.Equal(t, ServiceTunnels, unavailable.Service)
}

func TestBuildTunnels_NetlinkManagerGetsTheNetlinkUplinkManager(t *testing.T) {
	cfg := decodeGatewayDoc(t, tunnelsDoc)

	svc, err := buildTunnels(&Gateway{config: cfg})
	require.NoError(t, err)

	backend, ok := svc.(*tunnelsBackend)
	require.True(t, ok)
	_, isNetlink := backend.uplinks.(*tunnel.UplinkManager)
	assert.True(t, isNetlink, "the uplink manager the tunnels are pinned against is the one this service programs")
	assert.Equal(t, cfg.RoutingUplinks, backend.uplinkConfigs)
	assert.Equal(t, cfg.Tunnels, backend.configs)
}
