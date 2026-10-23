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

package commands

import (
	"bytes"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/hostfw"
)

// TestLoadServeConfig_ShippedGatewaydTemplateDecodes reads the reference
// gatewayd configuration the bring-up runbook tells an operator to copy
// (docs/operations/gateway-bringup.md) and asserts every section it names
// actually arrives in the ServeConfig.
//
// A template is a promise: the runbook says "copy this and the gateway comes
// up beside the upstream routers announcing nothing". The promise is only worth making if
// the daemon decodes it, so a key renamed in the schema — or a key invented
// in the template — fails here rather than on the hardware at 02:00.
func TestLoadServeConfig_ShippedGatewaydTemplateDecodes(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "configs", "platform", "templates",
		"dedicated", "supermicro", "x10", "gatewayd.yaml")
	raw, err := os.ReadFile(path)
	require.NoError(t, err, "template must exist at %s", path)

	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(bytes.NewReader(raw)))
	cfg, err := LoadServeConfig(v)
	require.NoError(t, err)

	require.NotNil(t, cfg.Gateway, "gateway section")
	g := cfg.Gateway
	assert.True(t, g.Enabled)
	assert.Equal(t, "gw-01-gateway", g.ID)
	assert.Equal(t, "10.4.6.1", g.AnycastIP,
		"the gateway answers for the control-plane zone's gateway address .1")

	// Both WAN uplinks (the 1G ports), as the NAT egress selection reads them;
	// the 10G ports are the data trunk on br-fabric.
	require.Len(t, g.Uplinks, 2)
	assert.Equal(t, "eth0", g.Uplinks[0].Name)
	assert.Equal(t, []string{"198.51.100.6/29"}, g.Uplinks[0].IPAddresses)

	// One tunnel per uplink to the relay, inner addresses from the tunnel
	// point-to-point range (never its reserved first /31).
	require.Len(t, g.Tunnels, 2, "one tunnel per uplink")
	assert.Equal(t, "gre-relay-ispa", g.Tunnels[0].Name)
	assert.Equal(t, "gre", g.Tunnels[0].Type)
	assert.Equal(t, "203.0.113.100", g.Tunnels[0].Remote, "the relay")
	assert.Equal(t, "10.4.128.2/31", g.Tunnels[0].TunnelIP)
	tunnelRange := netip.MustParsePrefix("10.4.128.0/22")
	haSync := netip.MustParsePrefix("10.4.128.0/31")
	for _, tun := range g.Tunnels {
		p := netip.MustParsePrefix(tun.TunnelIP)
		assert.True(t, tunnelRange.Contains(p.Addr()), "%s: tunnel /31 from the tunnel point-to-point range", tun.Name)
		assert.False(t, haSync.Overlaps(p), "%s: the HA sync /31 is reserved", tun.Name)
	}

	// Return-path symmetry (#606): each tunnel is pinned to the routing table
	// of the ISP its outer packets are sourced from, and the template's whole
	// section satisfies the gateway's own validation (an undeclared uplink
	// would fail it).
	require.Len(t, g.RoutingUplinks, 2, "one routing table per ISP")
	assert.Equal(t, "isp-a", g.Tunnels[0].Uplink)
	assert.Equal(t, "isp-b", g.Tunnels[1].Uplink)
	assert.Equal(t, "eth0", g.RoutingUplinks[0].Interface)
	assert.Equal(t, 101, g.RoutingUplinks[0].Table)
	assert.Equal(t, "198.51.100.1", g.RoutingUplinks[0].GatewayV4)
	assert.Equal(t, []string{"198.51.100.6/29"}, g.RoutingUplinks[0].Addresses)
	require.NoError(t, g.RoutingUplinks[0].Validate())
	require.NoError(t, g.RoutingUplinks[1].Validate())

	// enabledServices turns on transit whenever a `bgp:` section exists,
	// transit starts the speaker, and the speaker installs its policy set
	// during Start (the per-family prefix split, #619/#620, keeps that safe).
	require.NotNil(t, g.Transit, "transit runs the speaker")
	assert.True(t, g.Transit.Enabled)
	require.NotNil(t, g.BGP, "the bgp: block is live")
	require.Len(t, g.BGP.Neighbors, 2, "one session per tunnel")

	// local-pref on IMPORT ranks the sessions; the template prefers ISP A.
	wantLocalPref := map[string]uint32{"relay-ispa": 200, "relay-ispb": 100}
	for _, n := range g.BGP.Neighbors {
		want, known := wantLocalPref[n.Name]
		require.True(t, known, "unexpected peer %q", n.Name)
		require.NotNil(t, n.Policy.Import, "%s: no import attributes", n.Name)
		require.NotNil(t, n.Policy.Import.LocalPref, "%s: no local-pref", n.Name)
		assert.Equal(t, want, *n.Policy.Import.LocalPref, "%s", n.Name)
		// A prepend toward the relays would lengthen every path the relay
		// re-announces; inbound steering is the relay's own eBGP policy.
		if n.Policy.Export != nil {
			assert.Nil(t, n.Policy.Export.Prepend, "%s: the gateway must not prepend", n.Name)
		}
	}

	// The whole configuration must satisfy its own validation, which is what
	// refuses an attribute the speaker cannot program. Decoding is
	// build-neutral; whether these MD5 sessions VALIDATE is not (#598), so
	// each build asserts its own half of the contract.
	assertShippedTemplateValidateContract(t, g.BGP)

	// PAST DECODE. Asserting the YAML fields arrived says nothing about
	// whether the daemon can start from them. Service selection is the first
	// point where the difference shows, and its rule is
	//
	//	add(c.BGP != nil || (c.Transit != nil && c.Transit.Enabled), ServiceTransit)
	//
	// in GatewayConfig.enabledServices — note the OR. Both of its inputs are
	// now set, so the speaker does start from this file; what makes that safe
	// is the per-family prefix set (#620), covered against a real GoBGP server
	// in pkg/sdn/bgp. What this asserts here is that the shipped file enables
	// something, so a template that starts nothing cannot pass by emptying
	// itself.
	assert.True(t, g.HasEnabledServices(),
		"a shipped reference config an operator cannot start is worse than no config")

	require.NotNil(t, g.Firewall)
	assert.True(t, g.Firewall.Enabled)
	assert.Equal(t, "deny", g.Firewall.DefaultPolicy)

	// The host filter: GRE only from the relays, BGP/BFD only on tunnels.
	require.NotNil(t, g.HostFW)
	assert.True(t, g.HostFW.Enabled)
	require.Len(t, g.HostFW.Peers, 2, "one allowance per WAN link")
	assert.Equal(t, hostfw.PeerProtocolGRE, g.HostFW.Peers[0].Protocol)
	assert.Equal(t, []netip.Addr{netip.MustParseAddr("203.0.113.100")}, g.HostFW.Peers[0].Addresses)
	assert.Len(t, g.HostFW.Tunnels, 2, "179 and 3784 are allowed on the tunnels only")

	// The translator ships as a commented example: it needs addresses and an
	// OVS port only the operator knows (TestShippedGatewaydTemplate_NAT64ExampleValidates).
	assert.Nil(t, g.NAT64, "nat64 ships commented out")

	require.NotNil(t, cfg.SDN, "sdn section supplies the OVS runtime")
	require.NotNil(t, cfg.SDN.OVS)
	assert.Equal(t, "br-fabric", cfg.SDN.OVS.Bridge, "the gateway datapath rides the trunk bridge")
	require.NoError(t, cfg.SDN.Validate(), "the sdn section validates and derives the plan")
	require.NotNil(t, cfg.SDN.Plan())
	assert.Equal(t, uint16(4), cfg.SDN.Plan().Environment().ID)

	require.NotNil(t, cfg.ControlPlane, "control-plane section")
	assert.True(t, cfg.ControlPlane.Enabled)
	assert.Equal(t, "gw-01-gateway", cfg.ControlPlane.GatewayID)
	assert.NotEmpty(t, cfg.ControlPlane.CertFile)
}

// TestShippedGatewaydTemplate_OverlayExampleValidates: the README tells an
// operator to enable the disabled overlay example, so enabled it must pass
// the overlay's own validation, VNIs included.
func TestShippedGatewaydTemplate_OverlayExampleValidates(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "configs", "platform", "templates",
		"dedicated", "supermicro", "x10", "gatewayd.yaml")
	raw, err := os.ReadFile(path)
	require.NoError(t, err, "template must exist at %s", path)

	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(bytes.NewReader(raw)))
	cfg, err := LoadServeConfig(v)
	require.NoError(t, err)

	require.NotNil(t, cfg.Gateway)
	overlay := cfg.Gateway.Overlay
	require.NotNil(t, overlay, "the template carries an overlay example")
	require.False(t, overlay.Enabled, "the example ships disabled")
	require.NotEmpty(t, overlay.VNIs, "the overlay joins its VNIs at start")
	// The combination that failed with "address in use": the transit speaker
	// holds TCP 179 and the overlay speaker dials its route reflectors.
	require.NotNil(t, cfg.Gateway.BGP, "the template runs a transit speaker")
	require.NotEmpty(t, overlay.RRPeers, "the overlay runs its own EVPN speaker")
	// The symmetric IRB example decodes: a routed VNI's subnet, the anycast
	// gateway MAC and the L3VNI.
	require.Equal(t, netip.MustParsePrefix("10.4.192.0/24"), overlay.VNIs[0].Subnet)
	require.NotEmpty(t, overlay.AnycastGatewayMAC)
	require.NotZero(t, overlay.L3VNI)

	overlay.Enabled = true
	require.NoError(t, overlay.Validate())
}

// TestShippedGatewaydTemplate_CarriesNoSecrets: every credential in the
// template is a reference the key store resolves at start. A literal key
// committed here would be a secret in git history, which is a rotation, not
// a revert (handbook conventions/configuration.md §4).
func TestShippedGatewaydTemplate_CarriesNoSecrets(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "configs", "platform", "templates",
		"dedicated", "supermicro", "x10", "gatewayd.yaml")
	raw, err := os.ReadFile(path)
	require.NoError(t, err)

	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(bytes.NewReader(raw)))
	cfg, err := LoadServeConfig(v)
	require.NoError(t, err)

	require.NotNil(t, cfg.Gateway.BGP, "the bgp: block is live since #619")
	assert.NotContains(t, string(raw), "auth-key: ", "no literal key may appear anywhere in the file")
	assert.Contains(t, string(raw), "auth-key-ref: kms://", "credentials are references only")
	for _, n := range cfg.Gateway.BGP.Neighbors {
		require.NotEmpty(t, n.AuthKeyRef, "%s", n.Name)
		assert.Regexp(t, `^(kms|secret)://`, n.AuthKeyRef, "%s: references only", n.Name)
	}
	for _, kc := range cfg.Gateway.BGP.Keychains {
		for _, k := range kc.Keys {
			assert.Regexp(t, `^(kms|secret)://`, k.MasterKeyRef, "%s", kc.Name)
			assert.Nil(t, k.MasterKey)
		}
	}
}

// TestShippedGatewaydTemplate_NAT64ExampleValidates uncomments the template's
// `nat64:` example the way an operator enables it — one comment level off
// the `# nat64:` line and the lines indented under it — and loads the result
// as gatewayd does. A shipped example the gateway or the nat64 service
// refuses is worse than none: the operator meets the error on a live node.
func TestShippedGatewaydTemplate_NAT64ExampleValidates(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "configs", "platform", "templates",
		"dedicated", "supermicro", "x10", "gatewayd.yaml")
	raw, err := os.ReadFile(path)
	require.NoError(t, err)

	enabled, uncommented := uncommentNAT64Example(raw)
	require.Greater(t, uncommented, 1, "the template carries a commented nat64: example under gateway:")

	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(bytes.NewReader(enabled)))
	cfg, err := LoadServeConfig(v)
	require.NoError(t, err)

	nat := cfg.Gateway.NAT64
	require.NotNil(t, nat, "the example is the gateway's nat64 section")
	assert.True(t, nat.Enabled)
	require.NoError(t, nat.Validate(), "the gateway accepts the section")
	svc := nat.ServiceConfig(cfg.SDN.OVS.Bridge)
	require.NoError(t, svc.Validate(), "nat64.Config accepts it")
}

// uncommentNAT64Example strips one comment level ("  # ") from the
// template's `  # nat64:` line and from every line indented under it, and
// reports how many lines it uncommented.
func uncommentNAT64Example(raw []byte) ([]byte, int) {
	lines := strings.Split(string(raw), "\n")
	uncommented := 0
	inExample := false
	for i, line := range lines {
		if line == "  # nat64:" {
			inExample = true
		} else if !strings.HasPrefix(line, "  #   ") {
			inExample = false
		}
		if !inExample {
			continue
		}
		lines[i] = "  " + strings.TrimPrefix(line, "  # ")
		uncommented++
	}
	return []byte(strings.Join(lines, "\n")), uncommented
}
