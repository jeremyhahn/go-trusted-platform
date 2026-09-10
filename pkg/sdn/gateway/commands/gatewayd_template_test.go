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
// up beside the ASRs announcing nothing". The promise is only worth making if
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
	assert.Equal(t, "lab-node-1-gateway", g.ID)
	assert.Equal(t, "198.18.0.2", g.AnycastIP,
		"ruling R2: the gateway takes .1 only at the Phase 5 cutover")

	// Both WAN uplinks, as the NAT egress selection reads them.
	require.Len(t, g.Uplinks, 2)
	assert.Equal(t, "eth6", g.Uplinks[0].Name)
	assert.Equal(t, []string{"99.12.246.38/29"}, g.Uplinks[0].IPAddresses)

	// One tunnel per POP per ISP, the full mesh the ASRs run today.
	require.Len(t, g.Tunnels, 4, "two relays over two uplinks")
	assert.Equal(t, "gre-mia-att", g.Tunnels[0].Name)
	assert.Equal(t, "gre", g.Tunnels[0].Type)
	assert.Equal(t, "45.63.110.165", g.Tunnels[0].Remote, "the Miami relay")
	assert.Equal(t, "10.255.0.33/30", g.Tunnels[0].TunnelIP)

	// Transit and BGP are commented out in the shipped file on purpose, and
	// this is the assertion that keeps them that way. Uncommenting them makes
	// the daemon fail to START: enabledServices turns on transit whenever a
	// `bgp:` section exists, transit starts the speaker, and the speaker
	// installs its policy set during Start, where a peer whose import-allow
	// names both an IPv4 and an IPv6 prefix is refused with "multiple
	// families" (#620, fixed by #619).
	assert.Nil(t, g.BGP, "the bgp: block stays commented until #619 lands")
	assert.Nil(t, g.Transit, "transit is not gated by its own enabled flag")

	// PAST DECODE. Asserting the YAML fields arrived says nothing about
	// whether the daemon can start from them. Service selection is the first
	// point where the difference shows, and its rule is
	//
	//	add(c.BGP != nil || (c.Transit != nil && c.Transit.Enabled), ServiceTransit)
	//
	// in GatewayConfig.enabledServices — note the OR. The two assertions above
	// pin both of its inputs to nil, which is what keeps the speaker out of a
	// start; the rule itself is covered by the gateway package's own tests,
	// where it is reachable. What this asserts here is that the shipped file
	// still enables something, so a template that starts nothing at all cannot
	// pass by having emptied itself.
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
	assert.Equal(t, []netip.Addr{
		netip.MustParseAddr("45.63.110.165"),
		netip.MustParseAddr("66.42.90.190"),
	}, g.HostFW.Peers[0].Addresses)
	assert.Len(t, g.HostFW.Tunnels, 4, "179 and 3784 are allowed on the tunnels only")

	require.NotNil(t, cfg.SDN, "sdn section supplies the OVS runtime")
	require.NotNil(t, cfg.SDN.OVS)
	assert.Equal(t, "trusted0", cfg.SDN.OVS.Bridge)

	require.NotNil(t, cfg.ControlPlane, "control-plane section")
	assert.True(t, cfg.ControlPlane.Enabled)
	assert.Equal(t, "lab-node-1-gateway", cfg.ControlPlane.GatewayID)
	assert.NotEmpty(t, cfg.ControlPlane.CertFile)
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

	if cfg.Gateway.BGP == nil {
		// The bgp: block is commented out until #619 lands. When it is
		// restored this test must still hold, so it fails loudly rather than
		// passing vacuously if the block returns without references.
		raw, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.NotContains(t, string(raw), "auth-key: ", "no literal key may appear even in a commented block")
		assert.Contains(t, string(raw), "auth-key-ref: kms://", "the commented block still shows references only")
		return
	}
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
