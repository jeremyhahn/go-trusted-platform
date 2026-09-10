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
	"time"

	"github.com/spf13/viper"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
)

// TestLoadServeConfig_BGPHyphenatedKeysDecode pins #556: the shipped gateway
// template writes `router-id`, `listen-port` and `peers`, which mapstructure
// dropped silently while bgp.BGPConfig carried no tags.
func TestLoadServeConfig_BGPHyphenatedKeysDecode(t *testing.T) {
	yaml := []byte(`
gateway:
  enabled: true
  id: gw-test
  bgp:
    asn: 401870
    router-id: 23.143.36.4
    listen-port: 179
    graceful-restart-time: 90
    keychains:
      - name: vps
        keys:
          - send-id: 1
            receive-id: 1
            algorithm: hmac-sha256-128
            master-key-ref: kms://platform/bgp/vps-key-1
    peers:
      - name: miami-att
        address: 10.255.0.2
        asn: 401870
        auth-type: md5
        auth-key-ref: kms://platform/bgp/miami-att
        hold-time: 30
        keepalive-interval: 10
        max-prefixes: 10
        families:
          - ipv4-unicast
          - ipv6-unicast
        bfd:
          enabled: true
          desired-min-tx-interval: 300ms
          required-min-rx-interval: 300ms
          detection-multiplier: 3
        policy:
          import-allow:
            - prefix: 0.0.0.0/0
            - prefix: ::/0
      - name: atlanta-comcast
        address: 10.255.0.18
        asn: 401870
        auth-type: tcp-ao
        keychain: vps
        families: [ipv4-unicast]
    announce:
      ipv4: [23.143.36.0/24]
      ipv6: [2602:F5BB::/36]
`)
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(bytes.NewReader(yaml)))
	cfg, err := LoadServeConfig(v)
	require.NoError(t, err)
	require.NotNil(t, cfg.Gateway)
	b := cfg.Gateway.BGP
	require.NotNil(t, b, "bgp section")

	assert.Equal(t, uint32(401870), b.ASN)
	assert.Equal(t, netip.MustParseAddr("23.143.36.4"), b.RouterID, "router-id must decode")
	assert.Equal(t, uint16(179), b.ListenPort, "listen-port must decode")
	assert.Equal(t, uint16(90), b.GracefulRestartTime)
	assert.True(t, b.GracefulRestartEnabled(), "graceful restart defaults on")
	require.Len(t, b.Neighbors, 2, "peers must decode")

	miami := b.Neighbors[0]
	assert.Equal(t, "miami-att", miami.Name)
	assert.Equal(t, netip.MustParseAddr("10.255.0.2"), miami.Address)
	assert.Equal(t, bgp.AuthTypeMD5, miami.AuthType)
	assert.Equal(t, "kms://platform/bgp/miami-att", miami.AuthKeyRef)
	assert.Empty(t, miami.AuthKey, "a secret is never decoded from configuration")
	assert.Equal(t, uint16(30), miami.HoldTime)
	assert.Equal(t, uint32(10), miami.MaxPrefixes)
	assert.Equal(t, []bgp.AddressFamily{bgp.AFamilyIPv4Unicast, bgp.AFamilyIPv6Unicast}, miami.EnabledFamilies)
	require.NotNil(t, miami.BFD)
	assert.True(t, miami.BFD.Enabled)
	assert.Equal(t, 300*time.Millisecond, miami.BFD.DesiredMinTxInterval)
	require.Len(t, miami.Policy.ImportAllow, 2)
	assert.Equal(t, netip.MustParsePrefix("::/0"), miami.Policy.ImportAllow[1].Prefix)

	atlanta := b.Neighbors[1]
	assert.Equal(t, bgp.AuthTypeTCPAO, atlanta.AuthType)
	assert.Equal(t, "vps", atlanta.Keychain)

	require.Len(t, b.Keychains, 1)
	assert.Equal(t, "kms://platform/bgp/vps-key-1", b.Keychains[0].Keys[0].MasterKeyRef)
	assert.Equal(t, bgp.TCPAOAlgorithmHMACSHA256_128, b.Keychains[0].Keys[0].Algorithm)
	assert.Nil(t, b.Keychains[0].Keys[0].MasterKey)

	require.NotNil(t, b.Announce)
	assert.Equal(t, []string{"23.143.36.0/24"}, b.Announce.IPv4Prefixes)

	// Decoding is build-neutral; whether an md5 neighbour VALIDATES is not
	// (#598): the !fips build accepts the compat option, the fips build
	// refuses it with a typed error. Each build asserts its own contract.
	assertMD5NeighborValidateContract(t, b)
}

// TestLoadServeConfig_ShippedX10TemplateBGPBlockDecodes reads the real
// template so a template edit that breaks decoding fails here.
func TestLoadServeConfig_ShippedX10TemplateBGPBlockDecodes(t *testing.T) {
	path := filepath.Join("..", "..", "..", "..", "configs", "platform", "templates", "dedicated", "supermicro", "x10", "gateway.yaml")
	raw, err := os.ReadFile(path)
	require.NoError(t, err, "template must exist at %s", path)

	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(bytes.NewReader(raw)))
	cfg, err := LoadServeConfig(v)
	require.NoError(t, err)
	require.NotNil(t, cfg.Gateway)
	require.NotNil(t, cfg.Gateway.BGP)
	b := cfg.Gateway.BGP
	assert.NotZero(t, b.ASN)
	assert.True(t, b.RouterID.IsValid(), "router-id from the template must decode")
	assert.NotZero(t, b.ListenPort, "listen-port from the template must decode")
	assert.NotEmpty(t, b.Neighbors, "peers from the template must decode")
	for _, n := range b.Neighbors {
		assert.True(t, n.Address.IsValid(), "peer %q address", n.Name)
		assert.NotEmpty(t, n.EnabledFamilies, "peer %q families", n.Name)
	}
}

// TestLoadServeConfig_BGPRejectsUnknownEnumSpellings: a typo in an enum is
// a decode error, not a silently zeroed field.
func TestLoadServeConfig_BGPRejectsUnknownEnumSpellings(t *testing.T) {
	for name, yaml := range map[string]string{
		"auth-type": "gateway:\n  bgp:\n    asn: 1\n    peers:\n      - address: 10.0.0.1\n        asn: 2\n        auth-type: sha1\n",
		"family":    "gateway:\n  bgp:\n    asn: 1\n    peers:\n      - address: 10.0.0.1\n        asn: 2\n        families: [ipv7]\n",
		"tier":      "gateway:\n  bgp:\n    asn: 1\n    tier: core\n",
		"algorithm": "gateway:\n  bgp:\n    asn: 1\n    keychains:\n      - name: k\n        keys:\n          - algorithm: md5\n            master-key-ref: kms://x\n",
	} {
		t.Run(name, func(t *testing.T) {
			v := viper.New()
			v.SetConfigType("yaml")
			require.NoError(t, v.ReadConfig(bytes.NewReader([]byte(yaml))))
			_, err := LoadServeConfig(v)
			require.Error(t, err)
			var sec *ErrConfigSection
			assert.ErrorAs(t, err, &sec)
		})
	}
}

// TestLoadServeConfig_BGPTrafficEngineeringDecodes pins #607: the whole
// per-neighbour traffic-engineering ladder the ASRs apply today must arrive
// in the ServeConfig. Every key here is hyphenated, which is the spelling
// mapstructure drops when a field carries no tag — the defect class that
// produced #556 and this issue both.
func TestLoadServeConfig_BGPTrafficEngineeringDecodes(t *testing.T) {
	yaml := []byte(`
gateway:
  enabled: true
  id: gw-test
  bgp:
    asn: 401870
    router-id: 23.143.36.4
    peers:
      - name: miami-att
        address: 10.255.0.34
        asn: 401870
        families: [ipv4-unicast]
        policy:
          import-allow:
            - prefix: 0.0.0.0/0
          import:
            local-pref: 200
            large-communities:
              action: add
              values: ["401870:1:200"]
          export:
            med: 50
            prepend:
              count: 3
              asn: 401870
            communities:
              action: add
              values: ["no-export"]
      - name: atlanta-att
        address: 10.255.0.46
        asn: 401870
        families: [ipv4-unicast]
        policy:
          import:
            local-pref: 50
          export:
            large-communities:
              action: remove
              values: ["^401870:1:"]
`)
	v := viper.New()
	v.SetConfigType("yaml")
	require.NoError(t, v.ReadConfig(bytes.NewReader(yaml)))
	cfg, err := LoadServeConfig(v)
	require.NoError(t, err)
	require.NotNil(t, cfg.Gateway)
	b := cfg.Gateway.BGP
	require.NotNil(t, b)
	require.Len(t, b.Neighbors, 2)

	miami := b.Neighbors[0].Policy
	require.NotNil(t, miami.Import, "the import attribute block must decode")
	require.NotNil(t, miami.Import.LocalPref, "local-pref must decode")
	assert.Equal(t, uint32(200), *miami.Import.LocalPref)
	require.NotNil(t, miami.Import.LargeCommunities)
	assert.Equal(t, bgp.CommunityOpAdd, miami.Import.LargeCommunities.Action)
	assert.Equal(t, []string{"401870:1:200"}, miami.Import.LargeCommunities.Values)

	require.NotNil(t, miami.Export, "the export attribute block must decode")
	require.NotNil(t, miami.Export.MED, "med must decode")
	assert.Equal(t, uint32(50), *miami.Export.MED)
	require.NotNil(t, miami.Export.Prepend, "prepend must decode")
	assert.Equal(t, uint32(3), miami.Export.Prepend.Count)
	assert.Equal(t, uint32(401870), miami.Export.Prepend.ASN)
	require.NotNil(t, miami.Export.Communities)
	assert.Equal(t, []string{"no-export"}, miami.Export.Communities.Values)

	atlanta := b.Neighbors[1].Policy
	require.NotNil(t, atlanta.Import.LocalPref)
	assert.Equal(t, uint32(50), *atlanta.Import.LocalPref,
		"the ladder's least preferred path")
	assert.Nil(t, atlanta.Import.MED, "an unset attribute stays unset, it does not become zero")
	require.NotNil(t, atlanta.Export.LargeCommunities)
	assert.Equal(t, bgp.CommunityOpRemove, atlanta.Export.LargeCommunities.Action)
}

// TestLoadServeConfig_BGPTrafficEngineeringRefusesTheUnprogrammable is the
// other half of the contract: configuration the speaker cannot turn into a
// GoBGP action is an error at load, not a field that reads as applied and
// is silently dropped on the wire.
func TestLoadServeConfig_BGPTrafficEngineeringRefusesTheUnprogrammable(t *testing.T) {
	tests := []struct {
		name   string
		policy string
	}{
		{
			name: "a prepend count past the bound",
			policy: `
          export:
            prepend:
              count: 40`,
		},
		{
			name: "local-pref zero, which gobgp drops",
			policy: `
          import:
            local-pref: 0`,
		},
		{
			name: "a 32-bit asn in a standard community",
			policy: `
          export:
            communities:
              action: add
              values: ["401870:100"]`,
		},
		{
			name: "a community action with no values",
			policy: `
          export:
            communities:
              action: add`,
		},
		{
			name: "an unknown community action",
			policy: `
          export:
            large-communities:
              action: set
              values: ["401870:1:1"]`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			yaml := []byte(`
gateway:
  enabled: true
  id: gw-test
  bgp:
    asn: 401870
    router-id: 23.143.36.4
    peers:
      - name: miami-att
        address: 10.255.0.34
        asn: 401870
        families: [ipv4-unicast]
        policy:` + tt.policy + "\n")
			v := viper.New()
			v.SetConfigType("yaml")
			require.NoError(t, v.ReadConfig(bytes.NewReader(yaml)))
			cfg, err := LoadServeConfig(v)
			if err != nil {
				assert.NotEmpty(t, err.Error())
				return
			}
			// LoadServeConfig may decode without validating; the refusal
			// must then come from the configuration's own Validate.
			require.NotNil(t, cfg.Gateway)
			require.NotNil(t, cfg.Gateway.BGP)
			require.Error(t, cfg.Gateway.BGP.Validate(),
				"the daemon must refuse what it cannot program")
		})
	}
}
