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
          "dnat": [{"protocol": "tcp", "external": "203.0.113.10:2222", "internal": "10.0.100.5:22"}]}
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
		"bad snat":          {func(c *DesiredConfig) { c.NAT.SNATInternalCIDR = "10.0.0.0" }, "nat.snat_internal_cidr"},
		"bad dnat protocol": {func(c *DesiredConfig) { c.NAT.DNAT[0].Protocol = "icmp" }, "nat.dnat[0].protocol"},
		"bad dnat external": {func(c *DesiredConfig) { c.NAT.DNAT[0].External = "203.0.113.10" }, "nat.dnat[0].external"},
		"bad dnat internal": {func(c *DesiredConfig) { c.NAT.DNAT[0].Internal = ":22" }, "nat.dnat[0].internal"},
		"duplicate dnat":    {func(c *DesiredConfig) { c.NAT.DNAT = append(c.NAT.DNAT, c.NAT.DNAT[0]) }, "nat.dnat[1].external"},
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

func TestDesiredConfigErrors_Messages(t *testing.T) {
	assert.Contains(t, (&ErrDesiredSectionUnsupported{Section: "bgp"}).Error(), "bgp")
	assert.Contains(t, (&ErrDesiredConfigInvalid{Field: "nat", Reason: "x"}).Error(), "nat: x")
	cause := errors.New("eof")
	e := &ErrDesiredConfigMalformed{Cause: cause}
	assert.Contains(t, e.Error(), "eof")
	assert.ErrorIs(t, e, cause)
	assert.False(t, IsDesiredConfigRejection(errors.New("transport")))
}
