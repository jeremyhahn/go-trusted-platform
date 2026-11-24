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
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"

	ipcv1 "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/ipc/gen"
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
		reply := false
		for _, x := range r.Exprs {
			switch v := x.(type) {
			case *expr.Ct:
				reply = true
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
		if !reply && src.IsValid() && dst.IsValid() {
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
	return &vpn.Lease{ID: vpn.LeaseID(id), Address: netip.MustParsePrefix(addr), Zones: []string{string(zone.ZoneManagement)}, ExpiresAt: time.Now().Add(time.Hour)}
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
	require.Len(t, conn.chains, 3)
	c := hubChain(t, conn, "forward")
	assert.Equal(t, nftables.ChainTypeFilter, c.Type)
	require.NotNil(t, c.Hooknum)
	assert.Equal(t, *nftables.ChainHookForward, *c.Hooknum)
	require.NotNil(t, c.Policy)
	assert.Equal(t, nftables.ChainPolicyAccept, *c.Policy)
	require.Len(t, conn.rules, len(rules)+2)
	for _, r := range conn.rules {
		assert.Equal(t, "tp_vpn_hub", r.Table.Name)
	}
	ingress := hubChainRules(conn.rules, "ingress")
	assert.Len(t, ingress, len(rules), "the compiled rules are in the ingress chain")
	assert.Equal(t, 1, conn.flushes, "the whole program is one batch")
	assert.Equal(t, []string{"10.99.0.7->10.4.10.0"}, hubAccepts(ingress))

	failing := &recordingHubConn{flushErr: errors.New("netlink refused")}
	require.Error(t, (&vpnHubForwardProgrammer{conn: failing}).program(context.Background(), rules))

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	idle := &recordingHubConn{}
	err = (&vpnHubForwardProgrammer{conn: idle}).program(ctx, rules)
	require.ErrorIs(t, err, context.Canceled)
	assert.Zero(t, idle.flushes)
}

// hubChain is the recorded chain called name.
func hubChain(t *testing.T, conn *recordingHubConn, name string) *nftables.Chain {
	t.Helper()
	for _, c := range conn.chains {
		if c.Name == name {
			return c
		}
	}
	require.Failf(t, "no chain", "chain %q was not added", name)
	return nil
}

// hubChainRules is the rules among rules that sit in the chain called name.
func hubChainRules(rules []*nftables.Rule, name string) []*nftables.Rule {
	var out []*nftables.Rule
	for _, r := range rules {
		if r.Chain != nil && r.Chain.Name == name {
			out = append(out, r)
		}
	}
	return out
}

// assertHubJumpToIngress checks the one rule of a hook chain: vpn-hub0
// ingress jumps to the ingress chain.
func assertHubJumpToIngress(t *testing.T, rules []*nftables.Rule) {
	t.Helper()
	require.Len(t, rules, 1)
	e := rules[0].Exprs
	assertHubIfname(t, e)
	assert.Equal(t, &expr.Verdict{Kind: expr.VerdictJump, Chain: "ingress"}, e[len(e)-1])
}

func TestVPNHubNFT_HostLocalHubTrafficPassesTheSameRules(t *testing.T) {
	e := newVPNHubZoneEnforcement(hubZoneMatrix())
	rules, err := compileVPNHubForwardRules(e, hubForwardNetworks(), []*vpn.Lease{hubLease("a", "10.99.0.7/32")})
	require.NoError(t, err)

	conn := &recordingHubConn{}
	require.NoError(t, (&vpnHubForwardProgrammer{conn: conn}).program(context.Background(), rules))

	require.Len(t, conn.chains, 3)
	ingress := hubChain(t, conn, "ingress")
	assert.Nil(t, ingress.Hooknum, "ingress is a regular chain")
	in := hubChainRules(conn.rules, "ingress")
	require.Len(t, in, len(rules), "every compiled rule is in ingress")
	assert.Equal(t, []string{"10.99.0.7->10.4.10.0"}, hubAccepts(in))
	lastExprs := in[len(in)-1].Exprs
	assertVerdict(t, lastExprs[len(lastExprs)-1], expr.VerdictDrop)

	for name, hook := range map[string]nftables.ChainHook{
		"forward": *nftables.ChainHookForward,
		"input":   *nftables.ChainHookInput,
	} {
		c := hubChain(t, conn, name)
		assert.Equal(t, nftables.ChainTypeFilter, c.Type, name)
		require.NotNil(t, c.Hooknum, name)
		assert.Equal(t, hook, *c.Hooknum, name)
		require.NotNil(t, c.Policy, name)
		assert.Equal(t, nftables.ChainPolicyAccept, *c.Policy, name)
		assertHubJumpToIngress(t, hubChainRules(conn.rules, name))
	}
	assert.Equal(t, 1, conn.flushes, "the whole program is one batch")

	planeConn := &recordingHubConn{}
	plane, _ := hubPlaneWithFilter(planeConn)
	require.NoError(t, plane.InstallPeer(context.Background(), hubLease("a", "10.99.0.7/32")))
	var names []string
	for _, r := range planeConn.lastBatch() {
		names = append(names, r.Chain.Name)
	}
	assert.Contains(t, names, "ingress")
	assert.Contains(t, names, "forward")
	assert.Contains(t, names, "input")
	assertHubJumpToIngress(t, hubChainRules(planeConn.lastBatch(), "input"))
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

// wirePeers is the datapath IPC without the socket: every request is
// marshalled and unmarshalled into a fresh message before it reaches the
// child's PlaneHost, so only what the VPNPeer message carries arrives.
type wirePeers struct {
	host *vpn.PlaneHost
}

func overTheWire[M proto.Message](req M, fresh M) (M, error) {
	b, err := proto.Marshal(req)
	if err != nil {
		return fresh, err
	}
	return fresh, proto.Unmarshal(b, fresh)
}

func (w wirePeers) InstallVPNPeer(ctx context.Context, req *ipcv1.InstallVPNPeerRequest) (*ipcv1.InstallVPNPeerResponse, error) {
	got, err := overTheWire(req, &ipcv1.InstallVPNPeerRequest{})
	if err != nil {
		return nil, err
	}
	return w.host.InstallVPNPeer(ctx, got), nil
}

func (w wirePeers) RemoveVPNPeer(ctx context.Context, req *ipcv1.RemoveVPNPeerRequest) (*ipcv1.RemoveVPNPeerResponse, error) {
	got, err := overTheWire(req, &ipcv1.RemoveVPNPeerRequest{})
	if err != nil {
		return nil, err
	}
	return w.host.RemoveVPNPeer(ctx, got), nil
}

func (w wirePeers) ReconcileVPNPeers(ctx context.Context, req *ipcv1.ReconcileVPNPeersRequest) (*ipcv1.ReconcileVPNPeersResponse, error) {
	got, err := overTheWire(req, &ipcv1.ReconcileVPNPeersRequest{})
	if err != nil {
		return nil, err
	}
	return w.host.ReconcileVPNPeers(ctx, got), nil
}

// A peer installed over the datapath IPC gets the same forwarding accepts
// in tp_vpn_hub as a peer installed in-process: its lease zones survive the
// VPNPeer message.
func TestHubNetworkPlane_AnIPCInstallProgramsTheLeasesRules(t *testing.T) {
	ctx := context.Background()
	conn := &recordingHubConn{}
	plane, _ := hubPlaneWithFilter(conn)
	host, err := vpn.NewPlaneHost(plane)
	require.NoError(t, err)
	dp, err := vpn.NewDatapathPlane(vpn.DataPlaneMASQUE, wirePeers{host: host})
	require.NoError(t, err)

	require.NoError(t, dp.InstallPeer(ctx, hubLease("a", "10.99.0.7/32")))
	assert.Equal(t, []string{"10.99.0.7->10.4.10.0"}, hubAccepts(conn.lastBatch()))
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
	require.Len(t, last, 3, "only the closing drop and the two hook jumps are left")
	assertVerdict(t, last[0].Exprs[len(last[0].Exprs)-1], expr.VerdictDrop)

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
	require.Len(t, last, 3, "closing drop and the forward and input jumps")
	for _, r := range last {
		for _, x := range r.Exprs {
			_, ok := x.(*expr.Ct)
			assert.False(t, ok, "an empty lease set leaves no conntrack accept")
		}
	}
	assertVerdict(t, last[0].Exprs[len(last[0].Exprs)-1], expr.VerdictDrop)
}
