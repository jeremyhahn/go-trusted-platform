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

//go:build !fips

package commands

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// hubCtRules is the rules of a batch that hold a conntrack match.
func hubCtRules(rules []*nftables.Rule) []*nftables.Rule {
	var out []*nftables.Rule
	for _, r := range rules {
		for _, x := range r.Exprs {
			if _, ok := x.(*expr.Ct); ok {
				out = append(out, r)
				break
			}
		}
	}
	return out
}

// hubRuleComparesAddr reports whether a rule compares a network-header
// address field against addr.
func hubRuleComparesAddr(r *nftables.Rule, offset uint32, addr netip.Addr) bool {
	var off uint32
	for _, x := range r.Exprs {
		switch v := x.(type) {
		case *expr.Payload:
			off = 0
			if v.Base == expr.PayloadBaseNetworkHeader {
				off = v.Offset
			}
		case *expr.Cmp:
			if a, ok := netip.AddrFromSlice(v.Data); ok && off == offset && a == addr {
				return true
			}
			off = 0
		}
	}
	return false
}

func TestVPNHubForward_NoReplyAcceptOutsideALease(t *testing.T) {
	e := newVPNHubZoneEnforcement(hubZoneMatrix())
	lease := &vpn.Lease{Address: netip.MustParsePrefix("10.99.0.7/32"), Zones: []string{string(zone.ZoneManagement)}}
	rules, err := compileVPNHubForwardRules(e, hubForwardNetworks(), []*vpn.Lease{lease})
	require.NoError(t, err)
	texts := hubForwardTexts(rules)

	assert.NotContains(t, texts, `iifname "vpn-hub0" ct state established,related accept`,
		"no established/related accept is bound to the interface alone")
	for _, r := range rules {
		if r.Drop {
			continue
		}
		require.True(t, r.Source.IsValid(), "every accept names a lease's address: %s", r.text())
		assert.Equal(t, netip.MustParsePrefix("10.99.0.7/32"), r.Source, r.text())
	}
	assert.Contains(t, texts, `iifname "vpn-hub0" ct direction reply ct state established,related ip saddr 10.99.0.7/32 ip daddr 10.4.10.0/24 accept comment "vpn lease replies from management"`)
}

func TestVPNHubForward_ServiceScopedRepliesCarryNoPort(t *testing.T) {
	e := newVPNHubZoneEnforcement(zone.CompileMatrix([]zone.ZoneConfig{
		{Name: vpnHubZone, AllowTo: []zone.ZonePath{
			{Zone: zone.ZoneControlPlane, Services: []string{"dns"}},
		}},
		{Name: zone.ZoneControlPlane},
	}))
	lease := &vpn.Lease{Address: netip.MustParsePrefix("10.99.0.8/32"), Zones: []string{string(zone.ZoneControlPlane)}}
	rules, err := compileVPNHubForwardRules(e, hubForwardNetworks(), []*vpn.Lease{lease})
	require.NoError(t, err)

	var replies, ports []string
	for _, s := range hubForwardTexts(rules) {
		switch {
		case strings.Contains(s, "ct direction reply"):
			replies = append(replies, s)
		case strings.Contains(s, "dport"):
			ports = append(ports, s)
		}
	}
	require.Len(t, replies, 1, "one reply accept for the one opened subnet")
	assert.Contains(t, replies[0], "ip daddr 10.4.20.0/24")
	assert.NotContains(t, replies[0], "dport")
	assert.NotContains(t, replies[0], "sport")
	assert.Len(t, ports, 6, "the six dns port accepts stay")
}

func TestVPNHubNFT_ReplyRuleMatchesReplyDirectionAndTheLease(t *testing.T) {
	e := newVPNHubZoneEnforcement(hubZoneMatrix())
	lease := &vpn.Lease{Address: netip.MustParsePrefix("10.99.0.7/32"), Zones: []string{string(zone.ZoneManagement)}}
	rules, err := compileVPNHubForwardRules(e, hubForwardNetworks(), []*vpn.Lease{lease})
	require.NoError(t, err)
	conn := &recordingHubConn{}
	require.NoError(t, (&vpnHubForwardProgrammer{conn: conn}).program(context.Background(), rules))

	ct := hubCtRules(hubChainRules(conn.lastBatch(), vpnHubChainIngress))
	require.Len(t, ct, 1, "one reply accept for the lease's one opened subnet")
	x := ct[0].Exprs
	require.Len(t, x, 16)
	assertHubIfname(t, x)
	dir, ok := x[2].(*expr.Ct)
	require.True(t, ok)
	assert.Equal(t, expr.CtKeyDIRECTION, dir.Key)
	dirCmp, ok := x[3].(*expr.Cmp)
	require.True(t, ok)
	assert.Equal(t, expr.CmpOpEq, dirCmp.Op)
	assert.Equal(t, []byte{1}, dirCmp.Data, "IP_CT_DIR_REPLY")
	state, ok := x[4].(*expr.Ct)
	require.True(t, ok)
	assert.Equal(t, expr.CtKeySTATE, state.Key)
	_, ok = x[5].(*expr.Bitwise)
	require.True(t, ok)
	stateCmp, ok := x[6].(*expr.Cmp)
	require.True(t, ok)
	assert.Equal(t, expr.CmpOpNeq, stateCmp.Op)
	assertMetaCmp(t, x[7:], expr.MetaKeyNFPROTO, []byte{unix.NFPROTO_IPV4})
	assertAddrMatch(t, x[9:], 12, 4, ones(4), "10.99.0.7")
	assertAddrMatch(t, x[12:], 16, 4, []byte{0xff, 0xff, 0xff, 0}, "10.4.10.0")
	assertVerdict(t, x[15], expr.VerdictAccept)
}

func TestVPNHubForwardFilter_AReusedAddressGetsOnlyTheNewLeasesZones(t *testing.T) {
	e := newVPNHubZoneEnforcement(zone.CompileMatrix([]zone.ZoneConfig{
		{Name: vpnHubZone, AllowTo: []zone.ZonePath{
			{Zone: zone.ZoneManagement},
			{Zone: zone.ZoneStorage},
		}},
		{Name: zone.ZoneManagement},
		{Name: zone.ZoneStorage},
	}))
	e.nets = hubForwardNetworks()
	conn := &recordingHubConn{}
	f := newVPNHubForwardFilter(e, conn)
	ctx := context.Background()
	storage := netip.MustParseAddr("10.4.30.0")

	require.NoError(t, f.admit(ctx, &vpn.Lease{
		ID:      "a",
		Address: netip.MustParsePrefix("10.99.0.7/32"),
		Zones:   []string{string(zone.ZoneManagement), string(zone.ZoneStorage)},
	}))
	sawStorageReply := false
	for _, r := range hubCtRules(conn.lastBatch()) {
		if hubRuleComparesAddr(r, 16, storage) {
			sawStorageReply = true
		}
	}
	require.True(t, sawStorageReply, "lease a opens storage, so its replies from storage pass")

	require.NoError(t, f.forget(ctx, "a"))
	require.NoError(t, f.admit(ctx, &vpn.Lease{
		ID:      "b",
		Address: netip.MustParsePrefix("10.99.0.7/32"),
		Zones:   []string{string(zone.ZoneManagement)},
	}))
	last := conn.lastBatch()
	for _, r := range last {
		assert.False(t, hubRuleComparesAddr(r, 16, storage),
			"lease b reuses the address without storage: no rule reaches storage, so a surviving conntrack entry hits the drop")
	}
	ct := hubCtRules(last)
	require.NotEmpty(t, ct)
	for _, r := range ct {
		assert.True(t, hubRuleComparesAddr(r, 12, netip.MustParseAddr("10.99.0.7")), "a conntrack accept is bound to the lease's address")
		assert.True(t, hubRuleComparesAddr(r, 16, netip.MustParseAddr("10.4.10.0")), "a conntrack accept is bound to the lease's opened zone")
	}
}
