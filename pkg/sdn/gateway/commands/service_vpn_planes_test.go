//go:build !fips

package commands

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/hostfw"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
)

// stubSecrets is a SecretResolver that counts its calls; building the plane
// must not resolve the key (the hub resolves it when it comes up).
type stubSecrets struct{ calls int }

func (s *stubSecrets) resolve(_ context.Context, _ string) ([]byte, error) {
	s.calls++
	return make([]byte, 32), nil
}

// wireGuardPlaneRun returns a VPN configuration offering wireguard with the
// given key reference and hub address, and a gateway whose host runtime
// carries resolver (none when resolver is nil).
func wireGuardPlaneRun(t *testing.T, offered []vpn.DataPlaneKind, keyRef string, address netip.Prefix, resolver *stubSecrets) (*ServeConfig, *vpnHubKey) {
	t.Helper()
	cfg := newWireGuardRun(true).loaded
	cfg.Gateway.ManagementVPN.DataPlanes = offered
	cfg.Gateway.ManagementVPN.WireGuard.KeyRef = keyRef
	cfg.Gateway.ManagementVPN.WireGuard.Address = address
	var resolve bgp.SecretResolver
	if resolver != nil {
		resolve = resolver.resolve
	}
	return cfg, resolveVPNHubKeyWith(context.Background(), cfg, resolve)
}

var hubAddress = netip.MustParsePrefix("100.64.0.1/24")

// withHubZoneEnforced installs a destination-zone enforcement for the test
// (#2093), so vpnDataPlanes builds the hub; the production install needs the
// management-VPN zone in the SDN zones.
func withHubZoneEnforced(t *testing.T) {
	t.Helper()
	withHubZoneInstall(t, installedHubZones(newVPNHubZoneEnforcement(hubZoneMatrix())))
}

// assertErased checks every byte of held is zero.
func assertErased(t *testing.T, held []byte) {
	t.Helper()
	require.NotEmpty(t, held)
	assert.Equal(t, make([]byte, len(held)), held, "the held hub key is erased")
}

// TestVPNDataPlanes_RefusesTheHubWithoutZoneEnforcement checks Codex #2029
// round 2 P1 1: with no destination-zone enforcement the factory builds no
// hub plane, so every peer RPC keeps its refusal, and the held key goes.
func TestVPNDataPlanes_RefusesTheHubWithoutZoneEnforcement(t *testing.T) {
	cfg, hubKey := wireGuardPlaneRun(t, []vpn.DataPlaneKind{vpn.DataPlaneWireGuard}, "kms://vpn/hub0", hubAddress, &stubSecrets{})
	require.NotNil(t, hubKey)
	held := hubKey.key
	copy(held, bytes.Repeat([]byte{0xa5}, len(held)))

	planes, err := vpnDataPlanes(cfg, hubKey, testLogger())
	// Codex #2029 round 3 P1: a configured hub the guard refuses fails the
	// child's start instead of reporting a healthy child with no plane.
	var unenforced *ErrVPNHubZoneUnenforced
	require.ErrorAs(t, err, &unenforced)
	assert.Equal(t, "kms://vpn/hub0", unenforced.KeyRef)
	assert.Empty(t, planes, "no zone enforcement, no hub plane")
	assertErased(t, held)
}

// TestVPNHubKey_EraseClearsTheHeldKey checks Codex #2029 round 2 P1 2.
func TestVPNHubKey_EraseClearsTheHeldKey(t *testing.T) {
	hubKey := &vpnHubKey{ref: "kms://vpn/hub0", key: bytes.Repeat([]byte{0xa5}, 32)}
	held := hubKey.key

	hubKey.erase()
	assertErased(t, held)
	_, err := hubKey.Key(context.Background(), "kms://vpn/hub0")
	assert.Error(t, err, "an erased key is not handed out")
	hubKey.erase()

	assert.NotPanics(t, func() { (*vpnHubKey)(nil).erase() })
}

func TestVPNDataPlanes_BuildsWireGuardHubPlane(t *testing.T) {
	withHubZoneEnforced(t)
	secrets := &stubSecrets{}
	cfg, hubKey := wireGuardPlaneRun(t, []vpn.DataPlaneKind{vpn.DataPlaneWireGuard}, "kms://vpn/hub0", hubAddress, secrets)

	planes, err := vpnDataPlanes(cfg, hubKey, testLogger())
	require.NoError(t, err)
	require.Len(t, planes, 1, "the factory builds the WireGuard hub plane")
	assert.Equal(t, vpn.DataPlaneWireGuard, planes[0].Kind())
	assert.Equal(t, 1, secrets.calls, "the key is resolved once, before the child hardens, and held for the hub")
}

func TestVPNDataPlanes_MissingKeyRefBuildsNone(t *testing.T) {
	cfg, hubKey := wireGuardPlaneRun(t, []vpn.DataPlaneKind{vpn.DataPlaneWireGuard}, "", hubAddress, &stubSecrets{})

	planes, err := vpnDataPlanes(cfg, hubKey, testLogger())
	require.NoError(t, err)
	assert.Empty(t, planes, "no wireguard.key-ref, no plane")
}

func TestVPNDataPlanes_InvalidAddressBuildsNone(t *testing.T) {
	cfg, hubKey := wireGuardPlaneRun(t, []vpn.DataPlaneKind{vpn.DataPlaneWireGuard}, "kms://vpn/hub0", netip.Prefix{}, &stubSecrets{})

	planes, err := vpnDataPlanes(cfg, hubKey, testLogger())
	require.NoError(t, err)
	assert.Empty(t, planes, "no valid wireguard.address, no plane")
}

func TestVPNDataPlanes_NoSecretResolverBuildsNone(t *testing.T) {
	cfg, hubKey := wireGuardPlaneRun(t, []vpn.DataPlaneKind{vpn.DataPlaneWireGuard}, "kms://vpn/hub0", hubAddress, nil)

	planes, err := vpnDataPlanes(cfg, hubKey, testLogger())
	require.NoError(t, err)
	assert.Empty(t, planes, "without a secret resolver the hub key cannot be resolved")
}

func TestVPNDataPlanes_WireGuardNotOfferedBuildsNone(t *testing.T) {
	cfg, hubKey := wireGuardPlaneRun(t, []vpn.DataPlaneKind{vpn.DataPlaneMASQUE}, "kms://vpn/hub0", hubAddress, &stubSecrets{})

	planes, err := vpnDataPlanes(cfg, hubKey, testLogger())
	require.NoError(t, err)
	assert.Empty(t, planes, "wireguard not in data-planes, no plane")
}

// outsideHubNetwork is the first address past the hub's network.
func outsideHubNetwork() netip.Addr {
	network := hubAddress.Masked()
	addr := network.Addr()
	for network.Contains(addr) {
		addr = addr.Next()
	}
	return addr
}

// TestHubNetworkPlane_RefusesAPeerOutsideTheHubNetwork checks Codex #2029
// round 1 P1 1: a lease address outside the hub prefix (SPEC.md:80) or
// equal to the hub's own is refused before the plane installs a peer, and
// one inside the pool is installed.
func TestHubNetworkPlane_RefusesAPeerOutsideTheHubNetwork(t *testing.T) {
	inner := &fakeVPNPlane{}
	plane := hubNetworkPlane{ManagedDataPlane: inner, network: hubAddress.Masked(), hub: hubAddress.Addr()}
	ctx := context.Background()

	for name, addr := range map[string]netip.Addr{
		"outside the pool": outsideHubNetwork(),
		"the hub's own":    hubAddress.Addr(),
	} {
		err := plane.InstallPeer(ctx, &vpn.Lease{ID: vpn.LeaseID(name), Address: netip.PrefixFrom(addr, 32)})
		var invalid *vpn.ErrPeerKeyInvalid
		require.ErrorAs(t, err, &invalid, name)
	}
	_, _, installed := inner.state()
	assert.Empty(t, installed, "a refused address reaches no peer")

	require.NoError(t, plane.InstallPeer(ctx, &vpn.Lease{ID: "in-pool", Address: netip.PrefixFrom(hubAddress.Addr().Next(), 32), ExpiresAt: time.Now().Add(time.Hour)}))
	_, _, installed = inner.state()
	assert.Equal(t, []vpn.LeaseID{"in-pool"}, installed, "an in-pool address is installed")
}

// TestVPNDataPlanes_WrapsTheHubInItsNetwork checks the built WireGuard plane
// carries the hub-network check.
func TestVPNDataPlanes_WrapsTheHubInItsNetwork(t *testing.T) {
	withHubZoneEnforced(t)
	cfg, hubKey := wireGuardPlaneRun(t, []vpn.DataPlaneKind{vpn.DataPlaneWireGuard}, "kms://vpn/hub0", hubAddress, &stubSecrets{})

	planes, err := vpnDataPlanes(cfg, hubKey, testLogger())
	require.NoError(t, err)
	require.Len(t, planes, 1)
	wrapped, ok := planes[0].(hubNetworkPlane)
	require.True(t, ok, "the hub plane refuses addresses outside its network")
	assert.Equal(t, hubAddress.Masked(), wrapped.network)
	assert.Equal(t, hubAddress.Addr(), wrapped.hub)
}

// TestVPNHubKey_HoldsTheResolvedKey checks Codex #2029 round 1 P1 4: the
// key is resolved once, up front, and the hub reads the held copy; a
// key-store failure is held and reported when the hub asks.
func TestVPNHubKey_HoldsTheResolvedKey(t *testing.T) {
	secrets := &stubSecrets{}
	_, hubKey := wireGuardPlaneRun(t, []vpn.DataPlaneKind{vpn.DataPlaneWireGuard}, "kms://vpn/hub0", hubAddress, secrets)
	require.NotNil(t, hubKey)
	require.Equal(t, 1, secrets.calls)

	first, err := hubKey.Key(context.Background(), "kms://vpn/hub0")
	require.NoError(t, err)
	require.NotEmpty(t, first)
	first[0] ^= 0xff
	second, err := hubKey.Key(context.Background(), "kms://vpn/hub0")
	require.NoError(t, err)
	assert.NotEqual(t, first, second, "each caller gets its own copy")
	assert.Equal(t, 1, secrets.calls, "the hub reads the held key, never the key store")

	failure := errors.New("key store unreachable")
	failed := resolveVPNHubKeyWith(context.Background(), wireGuardPlaneRunConfig(t), func(context.Context, string) ([]byte, error) { return nil, failure })
	_, err = failed.Key(context.Background(), "kms://vpn/hub0")
	assert.ErrorIs(t, err, failure, "a key-store failure is reported when the hub starts")
}

func wireGuardPlaneRunConfig(t *testing.T) *ServeConfig {
	t.Helper()
	cfg, _ := wireGuardPlaneRun(t, []vpn.DataPlaneKind{vpn.DataPlaneWireGuard}, "kms://vpn/hub0", hubAddress, nil)
	return cfg
}

// hostRuntimeWithHub is a configuration whose datapath builds the
// WireGuard hub: a secret store (so the host has a resolver) and the
// hub's key-ref and address.
func hostRuntimeWithHub(t *testing.T) *ServeConfig {
	t.Helper()
	cfg, _ := secretStoreFixture(t)
	cfg.Gateway = newWireGuardRun(true).loaded.Gateway
	cfg.Gateway.ManagementVPN.DataPlanes = []vpn.DataPlaneKind{vpn.DataPlaneWireGuard}
	cfg.Gateway.ManagementVPN.WireGuard.KeyRef = "secret://vpn/hub"
	cfg.Gateway.ManagementVPN.WireGuard.Address = hubAddress
	return cfg
}

// The hub's UDP port is a daemon-owned listener: the host filter's
// default-drop input chain admits it from the inventory, so an operator
// need not repeat it in hostfw.extra.
func TestBuildHostRuntime_ListsTheWireGuardHubPort(t *testing.T) {
	cfg := hostRuntimeWithHub(t)
	anchor, err := buildPlatformAnchor(cfg)
	require.NoError(t, err)
	host, err := buildHostRuntime(cfg, anchor, testLogger())
	require.NoError(t, err)
	require.NotNil(t, host.Listeners, "the hub's port must be in the inventory")
	assert.Contains(t, host.Listeners.Listeners(), hostfw.Listener{
		Protocol: hostfw.ProtocolUDP,
		Port:     vpn.DefaultWireGuardListenPort,
		Comment:  "management-vpn wireguard hub",
	})
	rendered, err := hostfw.Render(hostfw.Ruleset{Listeners: host.Listeners.Listeners()})
	require.NoError(t, err)
	assert.Contains(t, rendered.Text, "udp dport 51820 accept")

	// A configured listen-port is the one admitted.
	cfg.Gateway.ManagementVPN.WireGuard.ListenPort = 51900
	host, err = buildHostRuntime(cfg, anchor, testLogger())
	require.NoError(t, err)
	rendered, err = hostfw.Render(hostfw.Ruleset{Listeners: host.Listeners.Listeners()})
	require.NoError(t, err)
	assert.Contains(t, rendered.Text, "udp dport 51900 accept")
	assert.NotContains(t, rendered.Text, "udp dport 51820 accept")
}

// No hub, no port: WireGuard not offered, or the hub's key unset, leaves
// the inventory without it.
func TestBuildHostRuntime_NoHubNoWireGuardPort(t *testing.T) {
	cfg := hostRuntimeWithHub(t)
	cfg.Gateway.ManagementVPN.WireGuard.KeyRef = ""
	anchor, err := buildPlatformAnchor(cfg)
	require.NoError(t, err)
	host, err := buildHostRuntime(cfg, anchor, testLogger())
	require.NoError(t, err)
	if host.Listeners != nil {
		for _, l := range host.Listeners.Listeners() {
			assert.NotEqual(t, hostfw.ProtocolUDP, l.Protocol, "no hub, no UDP listener: %+v", l)
		}
	}
}

// An operator who already declared the hub's port in hostfw.extra (on an
// interface, say) keeps that declaration: the inventory does not add a
// second, wider one, which the ruleset would also refuse as a duplicate.
func TestBuildHostRuntime_OperatorDeclaredHubPortKept(t *testing.T) {
	cfg := hostRuntimeWithHub(t)
	cfg.Gateway.HostFW = &hostfw.Config{Enabled: true, Extra: []hostfw.Listener{
		{Interface: "wan0", Protocol: hostfw.ProtocolUDP, Port: vpn.DefaultWireGuardListenPort},
	}}
	anchor, err := buildPlatformAnchor(cfg)
	require.NoError(t, err)
	host, err := buildHostRuntime(cfg, anchor, testLogger())
	require.NoError(t, err)
	if host.Listeners != nil {
		for _, l := range host.Listeners.Listeners() {
			assert.NotEqual(t, hostfw.ProtocolUDP, l.Protocol, "the operator's declaration stands: %+v", l)
		}
	}
}

// Codex #2029 round 2 P1, Tenant Agent ruling 1028 Q2 (b): B2 is preparatory
// wiring. With the production default (no withHubZoneEnforced), a fully
// configured WireGuard hub refuses to start with ErrVPNHubZoneUnenforced and
// builds no plane until destination-zone enforcement (#2093) lands.
func TestVPNDataPlanes_ProductionDefaultRefusesTheHubUntilZoneEnforcement(t *testing.T) {
	cfg, hubKey := wireGuardPlaneRun(t, []vpn.DataPlaneKind{vpn.DataPlaneWireGuard}, "kms://vpn/hub0", hubAddress, &stubSecrets{})
	require.NotNil(t, hubKey, "a valid key-ref and a secret resolver resolve a hub key")

	planes, err := vpnDataPlanes(cfg, hubKey, testLogger())
	var unenforced *ErrVPNHubZoneUnenforced
	require.ErrorAs(t, err, &unenforced, "the production default refuses the configured hub")
	assert.Equal(t, "kms://vpn/hub0", unenforced.KeyRef)
	assert.Nil(t, planes, "the production default builds no WireGuard plane")
}
