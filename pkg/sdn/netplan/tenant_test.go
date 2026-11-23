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

package netplan_test

import (
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
)

// TestCheckTenantSubnet_Accepts takes tenant subnets that leave room for
// the anycast gateway and a workload and keep clear of the plan's reserved
// ranges and the service VIP pool, inside and outside the tenant default
// range, in both address families.
func TestCheckTenantSubnet_Accepts(t *testing.T) {
	p := referencePlan(t)
	for _, s := range []string{
		"172.16.0.0/24",
		"10.4.192.0/24",
		"10.4.200.0/30",
		"fd00:1::/64",
		"fd00:1::/56",
	} {
		t.Run(s, func(t *testing.T) {
			assert.NoError(t, p.CheckTenantSubnet(netip.MustParsePrefix(s)))
		})
	}
}

// TestCheckTenantSubnet_Refuses names the reason for each refused subnet.
func TestCheckTenantSubnet_Refuses(t *testing.T) {
	p := referencePlan(t)
	cases := []struct {
		name   string
		prefix netip.Prefix
		reason string
	}{
		{"zero", netip.Prefix{}, "not a valid prefix"},
		{"host bits set", netip.MustParsePrefix("10.4.200.1/24"), "not a network prefix"},
		{"ipv4 /31", netip.MustParsePrefix("10.4.200.0/31"), "anycast gateway"},
		{"ipv4 /32", netip.MustParsePrefix("10.4.200.0/32"), "anycast gateway"},
		{"ipv6 /80", netip.MustParsePrefix("fd00:1::/80"), "anycast gateway"},
		{"loopback", netip.MustParsePrefix("127.0.0.0/8"), "not a unicast"},
		{"multicast", netip.MustParsePrefix("224.0.0.0/24"), "not a unicast"},
		{"ipv6 link-local", netip.MustParsePrefix("fe80::/64"), "not a unicast"},
		{"gateway HA sync", netip.MustParsePrefix("10.4.128.0/24"), "reserved 10.4.128.0/31"},
		{"host services v4", netip.MustParsePrefix("169.254.169.0/24"), "reserved 169.254.169.253/32"},
		{"host services v6", netip.MustParsePrefix("fd12:3456:789a:ffff::/64"), "reserved fd12:3456:789a:ffff::/64"},
		{"zone gateway", netip.MustParsePrefix("10.4.1.0/24"), "reserved 10.4.1.1/32"},
		{"service VIPs", netip.MustParsePrefix("10.4.136.0/24"), "service-vips 10.4.136.0/21"},
		{"whole environment", netip.MustParsePrefix("10.4.0.0/16"), "reserved"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := p.CheckTenantSubnet(tc.prefix)
			var e netplan.ErrTenantSubnet
			require.ErrorAs(t, err, &e)
			assert.Equal(t, tc.prefix, e.Subnet)
			assert.Contains(t, e.Error(), tc.reason)
		})
	}
}
