//go:build !fips

package commands

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
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
func wireGuardPlaneRun(t *testing.T, offered []vpn.DataPlaneKind, keyRef string, address netip.Prefix, resolver *stubSecrets) (*ServeConfig, *gateway.Gateway) {
	t.Helper()
	cfg := newDatapathRun(true).loaded
	cfg.Gateway.ManagementVPN.DataPlanes = offered
	cfg.Gateway.ManagementVPN.WireGuard.KeyRef = keyRef
	cfg.Gateway.ManagementVPN.WireGuard.Address = address
	gwCfg := &gateway.GatewayConfig{Enabled: true, ID: "gw-test"}
	if resolver != nil {
		gwCfg.Host = &gateway.HostRuntime{SecretResolver: resolver.resolve}
	}
	gw, err := gateway.NewGateway(gwCfg)
	require.NoError(t, err)
	return cfg, gw
}

var hubAddress = netip.MustParsePrefix("100.64.0.1/24")

func TestVPNDataPlanes_BuildsWireGuardHubPlane(t *testing.T) {
	secrets := &stubSecrets{}
	cfg, gw := wireGuardPlaneRun(t, []vpn.DataPlaneKind{vpn.DataPlaneWireGuard}, "kms://vpn/hub0", hubAddress, secrets)

	planes, err := vpnDataPlanes(cfg, gw, testLogger())
	require.NoError(t, err)
	require.Len(t, planes, 1, "the factory builds the WireGuard hub plane")
	assert.Equal(t, vpn.DataPlaneWireGuard, planes[0].Kind())
	assert.Zero(t, secrets.calls, "the plane is not started: the key is resolved only when the hub comes up")
}

func TestVPNDataPlanes_MissingKeyRefBuildsNone(t *testing.T) {
	cfg, gw := wireGuardPlaneRun(t, []vpn.DataPlaneKind{vpn.DataPlaneWireGuard}, "", hubAddress, &stubSecrets{})

	planes, err := vpnDataPlanes(cfg, gw, testLogger())
	require.NoError(t, err)
	assert.Empty(t, planes, "no wireguard.key-ref, no plane")
}

func TestVPNDataPlanes_InvalidAddressBuildsNone(t *testing.T) {
	cfg, gw := wireGuardPlaneRun(t, []vpn.DataPlaneKind{vpn.DataPlaneWireGuard}, "kms://vpn/hub0", netip.Prefix{}, &stubSecrets{})

	planes, err := vpnDataPlanes(cfg, gw, testLogger())
	require.NoError(t, err)
	assert.Empty(t, planes, "no valid wireguard.address, no plane")
}

func TestVPNDataPlanes_NoSecretResolverBuildsNone(t *testing.T) {
	cfg, gw := wireGuardPlaneRun(t, []vpn.DataPlaneKind{vpn.DataPlaneWireGuard}, "kms://vpn/hub0", hubAddress, nil)

	planes, err := vpnDataPlanes(cfg, gw, testLogger())
	require.NoError(t, err)
	assert.Empty(t, planes, "without a secret resolver the hub key cannot be resolved")
}

func TestVPNDataPlanes_WireGuardNotOfferedBuildsNone(t *testing.T) {
	cfg, gw := wireGuardPlaneRun(t, []vpn.DataPlaneKind{vpn.DataPlaneMASQUE}, "kms://vpn/hub0", hubAddress, &stubSecrets{})

	planes, err := vpnDataPlanes(cfg, gw, testLogger())
	require.NoError(t, err)
	assert.Empty(t, planes, "wireguard not in data-planes, no plane")
}

// hostRuntimeWithHub is a configuration whose datapath builds the
// WireGuard hub: a secret store (so the host has a resolver) and the
// hub's key-ref and address.
func hostRuntimeWithHub(t *testing.T) *ServeConfig {
	t.Helper()
	cfg, _ := secretStoreFixture(t)
	cfg.Gateway = newDatapathRun(true).loaded.Gateway
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
