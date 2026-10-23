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

package state

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const validDesiredJSON = `{
  "gateway_id": "gw-1",
  "version": "rev-3",
  "load_balancer": {"vips": [
    {"address": "10.0.200.10", "port": 443, "protocol": "TCP", "algorithm": "hash",
     "backends": [{"address": "10.0.100.11", "port": 8443, "weight": 2}, {"address": "10.0.100.12", "port": 8443}]}
  ]},
  "nat": {"snat_internal_cidr": "10.0.100.0/24",
          "dnat": [{"protocol": "tcp", "external": "203.0.113.10:2222", "internal": "10.0.100.5:22"}]},
  "vpn": {"peers": [{"tenant_id": "tenant-a", "device_id": "laptop-1", "zones": ["management"]}],
          "posture_policies": [{"tenant_id": "tenant-a", "name": "vpn_posture", "module": "package vpn.posture"}],
          "leases": [{"id": "lease-1", "tenant_id": "tenant-a", "device_id": "laptop-1", "address": "100.64.0.2/32",
                      "zones": ["management"], "data_plane": "wireguard",
                      "issued_at": "2026-10-13T10:00:00Z", "expires_at": "2026-10-13T11:00:00Z",
                      "verdict": {"passed": true, "cryptographic": true, "profile_id": 7}}]}
}`

func TestDecodeDesiredConfig_RoundTrip(t *testing.T) {
	cfg, err := DecodeDesiredConfig([]byte(validDesiredJSON))
	require.NoError(t, err)
	assert.Equal(t, "gw-1", cfg.GatewayID)
	assert.Equal(t, "rev-3", cfg.Version)
	require.NotNil(t, cfg.LoadBalancer)
	require.Len(t, cfg.LoadBalancer.VIPs, 1)
	assert.Equal(t, "tcp/10.0.200.10:443", cfg.LoadBalancer.VIPs[0].Key())
	require.NotNil(t, cfg.NAT)
	assert.Equal(t, "tcp/203.0.113.10:2222", cfg.NAT.DNAT[0].Key())
	require.NotNil(t, cfg.VPN)
	assert.Equal(t, []DesiredVPNPeer{{TenantID: "tenant-a", DeviceID: "laptop-1", Zones: []string{"management"}}}, cfg.VPN.Peers)
	require.Len(t, cfg.VPN.PosturePolicies, 1)

	out, err := json.Marshal(cfg)
	require.NoError(t, err)
	again, err := DecodeDesiredConfig(out)
	require.NoError(t, err)
	assert.Equal(t, cfg, again)
}

func TestDecodeDesiredConfig_RefusesUnknownSection(t *testing.T) {
	_, err := DecodeDesiredConfig([]byte(`{"gateway_id":"gw-1","bgp":{"asn":65001}}`))
	var unsupported *ErrDesiredSectionUnsupported
	require.True(t, errors.As(err, &unsupported), "got %v", err)
	assert.Equal(t, "bgp", unsupported.Section)
	assert.True(t, IsDesiredConfigRejection(err))
}

func TestDecodeDesiredConfig_RefusesMalformed(t *testing.T) {
	for name, doc := range map[string]string{
		"not json":        `{"gateway_id":`,
		"wrong type":      `{"gateway_id":"gw-1","nat":{"dnat":"nope"}}`,
		"unknown vip key": `{"gateway_id":"gw-1","load_balancer":{"vips":[{"address":"10.0.0.1","port":80,"protocol":"tcp","backends":[{"address":"10.0.0.2","port":80}],"sticky":true}]}}`,
		"array":           `[]`,
	} {
		t.Run(name, func(t *testing.T) {
			_, err := DecodeDesiredConfig([]byte(doc))
			var malformed *ErrDesiredConfigMalformed
			require.True(t, errors.As(err, &malformed), "got %v", err)
			assert.True(t, IsDesiredConfigRejection(err))
		})
	}
}

func TestDesiredConfig_Validate(t *testing.T) {
	base := func() *DesiredConfig {
		cfg, err := DecodeDesiredConfig([]byte(validDesiredJSON))
		require.NoError(t, err)
		return cfg
	}
	cases := map[string]struct {
		mutate func(*DesiredConfig)
		field  string
	}{
		"bad vip address":   {func(c *DesiredConfig) { c.LoadBalancer.VIPs[0].Address = "x" }, "load_balancer.vips[0].address"},
		"zero vip port":     {func(c *DesiredConfig) { c.LoadBalancer.VIPs[0].Port = 0 }, "load_balancer.vips[0].port"},
		"bad protocol":      {func(c *DesiredConfig) { c.LoadBalancer.VIPs[0].Protocol = "sctp" }, "load_balancer.vips[0].protocol"},
		"no backends":       {func(c *DesiredConfig) { c.LoadBalancer.VIPs[0].Backends = nil }, "load_balancer.vips[0].backends"},
		"bad backend":       {func(c *DesiredConfig) { c.LoadBalancer.VIPs[0].Backends[1].Address = "" }, "load_balancer.vips[0].backends[1].address"},
		"zero backend port": {func(c *DesiredConfig) { c.LoadBalancer.VIPs[0].Backends[0].Port = 0 }, "load_balancer.vips[0].backends[0].port"},
		"duplicate vip": {func(c *DesiredConfig) {
			c.LoadBalancer.VIPs = append(c.LoadBalancer.VIPs, c.LoadBalancer.VIPs[0])
		}, "load_balancer.vips[1].address"},
		"bad snat":           {func(c *DesiredConfig) { c.NAT.SNATInternalCIDR = "10.0.0.0" }, "nat.snat_internal_cidr"},
		"bad dnat protocol":  {func(c *DesiredConfig) { c.NAT.DNAT[0].Protocol = "icmp" }, "nat.dnat[0].protocol"},
		"bad dnat external":  {func(c *DesiredConfig) { c.NAT.DNAT[0].External = "203.0.113.10" }, "nat.dnat[0].external"},
		"bad dnat internal":  {func(c *DesiredConfig) { c.NAT.DNAT[0].Internal = ":22" }, "nat.dnat[0].internal"},
		"duplicate dnat":     {func(c *DesiredConfig) { c.NAT.DNAT = append(c.NAT.DNAT, c.NAT.DNAT[0]) }, "nat.dnat[1].external"},
		"vpn peer no tenant": {func(c *DesiredConfig) { c.VPN.Peers[0].TenantID = "" }, "vpn.peers[0].tenant_id"},
		"vpn peer no device": {func(c *DesiredConfig) { c.VPN.Peers[0].DeviceID = "" }, "vpn.peers[0].device_id"},
		"duplicate vpn peer": {func(c *DesiredConfig) { c.VPN.Peers = append(c.VPN.Peers, c.VPN.Peers[0]) }, "vpn.peers[1]"},
		"policy no tenant":   {func(c *DesiredConfig) { c.VPN.PosturePolicies[0].TenantID = "" }, "vpn.posture_policies[0].tenant_id"},
		"policy no name":     {func(c *DesiredConfig) { c.VPN.PosturePolicies[0].Name = "" }, "vpn.posture_policies[0].name"},
		"policy no module":   {func(c *DesiredConfig) { c.VPN.PosturePolicies[0].Module = "" }, "vpn.posture_policies[0].module"},
		"duplicate policy": {func(c *DesiredConfig) {
			c.VPN.PosturePolicies = append(c.VPN.PosturePolicies, c.VPN.PosturePolicies[0])
		}, "vpn.posture_policies[1]"},
		"lease no id":         {func(c *DesiredConfig) { c.VPN.Leases[0].ID = "" }, "vpn.leases[0].id"},
		"lease no tenant":     {func(c *DesiredConfig) { c.VPN.Leases[0].TenantID = "" }, "vpn.leases[0].tenant_id"},
		"lease no device":     {func(c *DesiredConfig) { c.VPN.Leases[0].DeviceID = "" }, "vpn.leases[0].device_id"},
		"lease no data plane": {func(c *DesiredConfig) { c.VPN.Leases[0].DataPlane = "" }, "vpn.leases[0].data_plane"},
		"lease bad address":   {func(c *DesiredConfig) { c.VPN.Leases[0].Address = "100.64.0.2" }, "vpn.leases[0].address"},
		"lease expiry not after issue": {func(c *DesiredConfig) {
			c.VPN.Leases[0].ExpiresAt = c.VPN.Leases[0].IssuedAt
		}, "vpn.leases[0].expires_at"},
		"duplicate lease": {func(c *DesiredConfig) { c.VPN.Leases = append(c.VPN.Leases, c.VPN.Leases[0]) }, "vpn.leases[1]"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := base()
			c.mutate(cfg)
			err := cfg.Validate()
			var invalid *ErrDesiredConfigInvalid
			require.True(t, errors.As(err, &invalid), "got %v", err)
			assert.Equal(t, c.field, invalid.Field)
		})
	}
	var nilCfg *DesiredConfig
	assert.Error(t, nilCfg.Validate())
	assert.NoError(t, (&DesiredConfig{}).Validate(), "an empty document is valid")
}

func TestDesiredVPN_SeparatorInAnIDIsNotADuplicate(t *testing.T) {
	vpn := &DesiredVPN{
		Peers: []DesiredVPNPeer{{TenantID: "a/b", DeviceID: "c"}, {TenantID: "a", DeviceID: "b/c"}},
		PosturePolicies: []DesiredVPNPosturePolicy{
			{TenantID: "a/b", Name: "c", Module: "package vpn.posture"},
			{TenantID: "a", Name: "b/c", Module: "package vpn.posture"},
		},
	}
	require.NoError(t, vpn.validate(), "distinct peers and policies are not duplicates")

	vpn.Peers = append(vpn.Peers, DesiredVPNPeer{TenantID: "a", DeviceID: "b/c"})
	var invalid *ErrDesiredConfigInvalid
	require.True(t, errors.As(vpn.validate(), &invalid))
	assert.Equal(t, "vpn.peers[2]", invalid.Field, "a true duplicate is still refused")
}

func TestDesiredConfig_Versions(t *testing.T) {
	cfg, err := DecodeDesiredConfig([]byte(validDesiredJSON))
	require.NoError(t, err)
	assert.Equal(t, "rev-3", cfg.EffectiveVersion())

	cfg.Version = ""
	content := cfg.ContentVersion()
	assert.Contains(t, content, "sha256:")
	assert.Equal(t, content, cfg.EffectiveVersion())
	assert.Equal(t, content, cfg.ContentVersion(), "stable across calls")

	other, _ := DecodeDesiredConfig([]byte(validDesiredJSON))
	other.Version = "anything"
	assert.Equal(t, content, other.ContentVersion(), "the version field is excluded from the content hash")

	other.NAT.SNATInternalCIDR = ""
	assert.NotEqual(t, content, other.ContentVersion(), "content changes change the version")
}

func TestDesiredConfig_ContentVersionLeavesOutLeases(t *testing.T) {
	cfg, err := DecodeDesiredConfig([]byte(validDesiredJSON))
	require.NoError(t, err)
	content := cfg.ContentVersion()

	cfg.VPN.Leases = append(cfg.VPN.Leases, cfg.VPN.Leases[0])
	cfg.VPN.Leases[1].ID = "lease-2"
	assert.Equal(t, content, cfg.ContentVersion(), "a gateway's lease write-through is not a config change")
	assert.Len(t, cfg.VPN.Leases, 2, "hashing must not drop the caller's leases")

	cfg.VPN.Peers = nil
	assert.NotEqual(t, content, cfg.ContentVersion(), "the rest of the VPN section still versions the config")
}

func TestDesiredConfigErrors_Messages(t *testing.T) {
	assert.Contains(t, (&ErrDesiredSectionUnsupported{Section: "bgp"}).Error(), "bgp")
	assert.Contains(t, (&ErrDesiredConfigInvalid{Field: "nat", Reason: "x"}).Error(), "nat: x")
	cause := errors.New("eof")
	e := &ErrDesiredConfigMalformed{Cause: cause}
	assert.Contains(t, e.Error(), "eof")
	assert.ErrorIs(t, e, cause)
	assert.False(t, IsDesiredConfigRejection(errors.New("transport")))
}
