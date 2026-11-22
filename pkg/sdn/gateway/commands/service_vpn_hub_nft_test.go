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
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// recordingHubConn stands in for the netlink connection: it records what
// the programmer queues and groups the queued rules into one batch per
// Flush. No socket is opened.
type recordingHubConn struct {
	tables   []*nftables.Table
	flushed  []string
	deleted  []string
	chains   []*nftables.Chain
	rules    []*nftables.Rule
	pending  []*nftables.Rule
	batches  [][]*nftables.Rule
	flushes  int
	flushErr error
}

func (r *recordingHubConn) AddTable(t *nftables.Table) *nftables.Table {
	r.tables = append(r.tables, t)
	return t
}

func (r *recordingHubConn) FlushTable(t *nftables.Table) { r.flushed = append(r.flushed, t.Name) }

func (r *recordingHubConn) DelTable(t *nftables.Table) { r.deleted = append(r.deleted, t.Name) }

func (r *recordingHubConn) AddChain(c *nftables.Chain) *nftables.Chain {
	r.chains = append(r.chains, c)
	return c
}

func (r *recordingHubConn) AddRule(rule *nftables.Rule) *nftables.Rule {
	r.rules = append(r.rules, rule)
	r.pending = append(r.pending, rule)
	return rule
}

func (r *recordingHubConn) Flush() error {
	r.flushes++
	r.batches = append(r.batches, r.pending)
	r.pending = nil
	return r.flushErr
}

// lastBatch is the rules of the most recent Flush.
func (r *recordingHubConn) lastBatch() []*nftables.Rule {
	if len(r.batches) == 0 {
		return nil
	}
	return r.batches[len(r.batches)-1]
}

// withHubNFTConn makes newVPNHubNFTConn return conn for one test.
func withHubNFTConn(t *testing.T, conn vpnHubNFTConn) {
	t.Helper()
	prev := newVPNHubNFTConn
	newVPNHubNFTConn = func() (vpnHubNFTConn, error) { return conn, nil }
	t.Cleanup(func() { newVPNHubNFTConn = prev })
}

// hubAccepts renders each rule's network-header source and destination
// compares as "source->destination".
func hubAccepts(rules []*nftables.Rule) []string {
	var out []string
	for _, r := range rules {
		var src, dst netip.Addr
		var off uint32
		for _, x := range r.Exprs {
			switch v := x.(type) {
			case *expr.Payload:
				off = 0
				if v.Base == expr.PayloadBaseNetworkHeader {
					off = v.Offset
				}
			case *expr.Cmp:
				if a, ok := netip.AddrFromSlice(v.Data); ok {
					switch off {
					case 8, 12:
						src = a
					case 16, 24:
						dst = a
					}
				}
				off = 0
			}
		}
		if src.IsValid() && dst.IsValid() {
			out = append(out, src.String()+"->"+dst.String())
		}
	}
	return out
}

func hubIfnameData() []byte {
	d := make([]byte, unix.IFNAMSIZ)
	copy(d, vpnHubInterface)
	return d
}

// assertHubIfname checks the rule starts with the vpn-hub0 ingress match.
func assertHubIfname(t *testing.T, e []expr.Any) {
	t.Helper()
	require.GreaterOrEqual(t, len(e), 2)
	meta, ok := e[0].(*expr.Meta)
	require.True(t, ok)
	assert.Equal(t, expr.MetaKeyIIFNAME, meta.Key)
	cmp, ok := e[1].(*expr.Cmp)
	require.True(t, ok)
	assert.Equal(t, expr.CmpOpEq, cmp.Op)
	assert.Equal(t, hubIfnameData(), cmp.Data)
}

func assertMetaCmp(t *testing.T, e []expr.Any, key expr.MetaKey, data []byte) {
	t.Helper()
	meta, ok := e[0].(*expr.Meta)
	require.True(t, ok)
	assert.Equal(t, key, meta.Key)
	cmp, ok := e[1].(*expr.Cmp)
	require.True(t, ok)
	assert.Equal(t, data, cmp.Data)
}

func assertAddrMatch(t *testing.T, e []expr.Any, offset, length uint32, mask []byte, addr string) {
	t.Helper()
	p, ok := e[0].(*expr.Payload)
	require.True(t, ok)
	assert.Equal(t, expr.PayloadBaseNetworkHeader, p.Base)
	assert.Equal(t, offset, p.Offset)
	assert.Equal(t, length, p.Len)
	b, ok := e[1].(*expr.Bitwise)
	require.True(t, ok)
	assert.Equal(t, mask, b.Mask)
	cmp, ok := e[2].(*expr.Cmp)
	require.True(t, ok)
	assert.Equal(t, netip.MustParseAddr(addr).AsSlice(), cmp.Data)
}

func assertVerdict(t *testing.T, x expr.Any, kind expr.VerdictKind) {
	t.Helper()
	v, ok := x.(*expr.Verdict)
	require.True(t, ok)
	assert.Equal(t, kind, v.Kind)
}

func ones(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = 0xff
	}
	return b
}

func hubLease(id, addr string) *vpn.Lease {
	return &vpn.Lease{ID: vpn.LeaseID(id), Address: netip.MustParsePrefix(addr), Zones: []string{string(zone.ZoneManagement)}}
}

func TestVPNHubNFT_ProgramIsOneBatchInItsOwnForwardChain(t *testing.T) {
	e := newVPNHubZoneEnforcement(hubZoneMatrix())
	rules, err := compileVPNHubForwardRules(e, hubForwardNetworks(), []*vpn.Lease{hubLease("a", "10.99.0.7/32")})
	require.NoError(t, err)

	conn := &recordingHubConn{}
	prog := &vpnHubForwardProgrammer{conn: conn}
	require.NoError(t, prog.program(context.Background(), rules))

	require.Len(t, conn.tables, 1)
	assert.Equal(t, vpnHubTableName, conn.tables[0].Name)
	assert.Equal(t, "tp_vpn_hub", conn.tables[0].Name)
	assert.Equal(t, nftables.TableFamilyINet, conn.tables[0].Family)
	assert.Equal(t, []string{"tp_vpn_hub"}, conn.flushed, "only the hub's own table is flushed")
	require.Len(t, conn.chains, 1)
	c := conn.chains[0]
	assert.Equal(t, "forward", c.Name)
	assert.Equal(t, nftables.ChainTypeFilter, c.Type)
	require.NotNil(t, c.Hooknum)
	assert.Equal(t, *nftables.ChainHookForward, *c.Hooknum)
	require.NotNil(t, c.Policy)
	assert.Equal(t, nftables.ChainPolicyAccept, *c.Policy)
	require.Len(t, conn.rules, len(rules))
	for _, r := range conn.rules {
		assert.Equal(t, "forward", r.Chain.Name)
		assert.Equal(t, "tp_vpn_hub", r.Table.Name)
	}
	assert.Equal(t, 1, conn.flushes, "the whole program is one batch")
	assert.Equal(t, []string{"10.99.0.7->10.4.10.0"}, hubAccepts(conn.rules))

	failing := &recordingHubConn{flushErr: errors.New("netlink refused")}
	require.Error(t, (&vpnHubForwardProgrammer{conn: failing}).program(context.Background(), rules))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	idle := &recordingHubConn{}
	err = (&vpnHubForwardProgrammer{conn: idle}).program(ctx, rules)
	require.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, idle.flushes)
}

func TestVPNHubNFT_LeaseRuleMatchesIngressFamilySourceAndDestination(t *testing.T) {
	e := vpnHubForwardExprs(vpnHubForwardRule{
		Family:      4,
		Source:      netip.MustParsePrefix("10.99.0.7/32"),
		Destination: netip.MustParsePrefix("10.4.10.0/24"),
	})
	require.Len(t, e, 11)
	assertHubIfname(t, e)
	assertMetaCmp(t, e[2:], expr.MetaKeyNFPROTO, []byte{unix.NFPROTO_IPV4})
	assertAddrMatch(t, e[4:], 12, 4, ones(4), "10.99.0.7")
	assertAddrMatch(t, e[7:], 16, 4, []byte{0xff, 0xff, 0xff, 0}, "10.4.10.0")
	assertVerdict(t, e[10], expr.VerdictAccept)

	e6 := vpnHubForwardExprs(vpnHubForwardRule{
		Family:      6,
		Source:      netip.MustParsePrefix("fd00:99::7/128"),
		Destination: netip.MustParsePrefix("fd00:10::/64"),
	})
	require.Len(t, e6, 11)
	assertHubIfname(t, e6)
	assertMetaCmp(t, e6[2:], expr.MetaKeyNFPROTO, []byte{unix.NFPROTO_IPV6})
	assertAddrMatch(t, e6[4:], 8, 16, ones(16), "fd00:99::7")
	assertAddrMatch(t, e6[7:], 24, 16, append(ones(8), make([]byte, 8)...), "fd00:10::")
	assertVerdict(t, e6[10], expr.VerdictAccept)
}

func TestVPNHubNFT_PortRuleMatchesProtocolAndPort(t *testing.T) {
	base := vpnHubForwardRule{
		Family:      4,
		Source:      netip.MustParsePrefix("10.99.0.7/32"),
		Destination: netip.MustParsePrefix("10.4.10.0/24"),
	}
	for _, tc := range []struct {
		protocol string
		number   byte
	}{{"udp", unix.IPPROTO_UDP}, {"tcp", unix.IPPROTO_TCP}} {
		r := base
		r.Protocol, r.Port = tc.protocol, 53
		e := vpnHubForwardExprs(r)
		require.Len(t, e, 15, tc.protocol)
		assertMetaCmp(t, e[10:], expr.MetaKeyL4PROTO, []byte{tc.number})
		p, ok := e[12].(*expr.Payload)
		require.True(t, ok)
		assert.Equal(t, expr.PayloadBaseTransportHeader, p.Base)
		assert.Equal(t, uint32(2), p.Offset)
		assert.Equal(t, uint32(2), p.Len)
		cmp, ok := e[13].(*expr.Cmp)
		require.True(t, ok)
		port := make([]byte, 2)
		binary.BigEndian.PutUint16(port, 53)
		assert.Equal(t, port, cmp.Data)
		assertVerdict(t, e[14], expr.VerdictAccept)
	}
}

func TestVPNHubNFT_EndsInADropOfTheHubInterface(t *testing.T) {
	drop := vpnHubForwardExprs(vpnHubForwardRule{Drop: true})
	require.Len(t, drop, 3)
	assertHubIfname(t, drop)
	assertVerdict(t, drop[2], expr.VerdictDrop)

	reply := vpnHubForwardExprs(vpnHubForwardRule{})
	require.Len(t, reply, 6)
	assertHubIfname(t, reply)
	ct, ok := reply[2].(*expr.Ct)
	require.True(t, ok)
	assert.Equal(t, expr.CtKeySTATE, ct.Key)
	b, ok := reply[3].(*expr.Bitwise)
	require.True(t, ok)
	mask := make([]byte, 4)
	binary.LittleEndian.PutUint32(mask, expr.CtStateBitESTABLISHED|expr.CtStateBitRELATED)
	assert.Equal(t, mask, b.Mask)
	cmp, ok := reply[4].(*expr.Cmp)
	require.True(t, ok)
	assert.Equal(t, expr.CmpOpNeq, cmp.Op)
	assert.Equal(t, []byte{0, 0, 0, 0}, cmp.Data)
	assertVerdict(t, reply[5], expr.VerdictAccept)
}

// hubPlaneWithFilter builds a hub plane whose enforcement carries a forward
// filter over conn.
func hubPlaneWithFilter(conn *recordingHubConn) (hubNetworkPlane, *fakeVPNPlane) {
	inner := &fakeVPNPlane{}
	zones := newVPNHubZoneEnforcement(hubZoneMatrix())
	zones.nets = hubForwardNetworks()
	zones.forward = newVPNHubForwardFilter(zones, conn)
	return hubNetworkPlane{
		ManagedDataPlane: inner,
		network:          netip.MustParsePrefix("10.99.0.0/24"),
		hub:              netip.MustParseAddr("10.99.0.1"),
		zones:            zones,
	}, inner
}

func TestHubNetworkPlane_InstallPeerProgramsTheLeasesRules(t *testing.T) {
	conn := &recordingHubConn{}
	plane, inner := hubPlaneWithFilter(conn)

	require.NoError(t, plane.InstallPeer(context.Background(), hubLease("a", "10.99.0.7/32")))
	assert.Equal(t, []string{"10.99.0.7->10.4.10.0"}, hubAccepts(conn.lastBatch()))
	_, _, installed := inner.state()
	assert.Equal(t, []vpn.LeaseID{"a"}, installed)
}

func TestHubNetworkPlane_RemovePeerAndReconcileWithdrawTheRules(t *testing.T) {
	conn := &recordingHubConn{}
	plane, _ := hubPlaneWithFilter(conn)
	ctx := context.Background()

	require.NoError(t, plane.InstallPeer(ctx, hubLease("a", "10.99.0.7/32")))
	require.NoError(t, plane.InstallPeer(ctx, hubLease("b", "10.99.0.8/32")))
	assert.Equal(t, []string{"10.99.0.7->10.4.10.0", "10.99.0.8->10.4.10.0"}, hubAccepts(conn.lastBatch()))

	require.NoError(t, plane.RemovePeer(ctx, "a"))
	assert.Equal(t, []string{"10.99.0.8->10.4.10.0"}, hubAccepts(conn.lastBatch()))

	require.NoError(t, plane.ReconcilePeers(ctx, []vpn.LeaseID{}))
	last := conn.lastBatch()
	assert.Empty(t, hubAccepts(last))
	require.Len(t, last, 2, "only the reply accept and the closing drop are left")
	assertVerdict(t, last[1].Exprs[len(last[1].Exprs)-1], expr.VerdictDrop)

	require.NoError(t, plane.Stop(ctx))
	assert.Equal(t, []string{"tp_vpn_hub"}, conn.deleted)
}

func TestHubNetworkPlane_AFailedProgramRefusesThePeer(t *testing.T) {
	conn := &recordingHubConn{flushErr: errors.New("netlink refused")}
	plane, inner := hubPlaneWithFilter(conn)

	require.Error(t, plane.InstallPeer(context.Background(), hubLease("a", "10.99.0.7/32")))
	_, _, installed := inner.state()
	assert.Empty(t, installed, "no peer is installed without its forwarding rules")
}

func TestVPNHubZone_ProductionFilterProgramsAnEmptyChainAtInstall(t *testing.T) {
	conn := &recordingHubConn{}
	withHubNFTConn(t, conn)

	e, err := installVPNHubZones(hubZoneDeclarations(), hubForwardNetworks(), discardLogger())
	require.NoError(t, err)
	require.NotNil(t, e.forward)
	last := conn.lastBatch()
	require.Len(t, last, 2)
	_, ok := last[0].Exprs[2].(*expr.Ct)
	assert.True(t, ok, "the chain opens with the reply accept")
	assertVerdict(t, last[1].Exprs[len(last[1].Exprs)-1], expr.VerdictDrop)
}
