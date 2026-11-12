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

package hostfw

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"
)

// recordingConn stands in for *nftables.Conn: it records the batch and
// reports what a kernel would about the table's presence.
type recordingConn struct {
	tables   []*nftables.Table
	flushed  []string
	deleted  []string
	chains   []*nftables.Chain
	rules    []*nftables.Rule
	flushes  int
	flushErr error
	present  bool
	listErr  error
}

func (c *recordingConn) AddTable(t *nftables.Table) *nftables.Table {
	c.tables = append(c.tables, t)
	return t
}
func (c *recordingConn) FlushTable(t *nftables.Table) { c.flushed = append(c.flushed, t.Name) }
func (c *recordingConn) DelTable(t *nftables.Table)   { c.deleted = append(c.deleted, t.Name) }
func (c *recordingConn) AddChain(ch *nftables.Chain) *nftables.Chain {
	c.chains = append(c.chains, ch)
	return ch
}
func (c *recordingConn) AddRule(r *nftables.Rule) *nftables.Rule {
	c.rules = append(c.rules, r)
	return r
}
func (c *recordingConn) ListTableOfFamily(name string, family nftables.TableFamily) (*nftables.Table, error) {
	if c.listErr != nil {
		return nil, c.listErr
	}
	if !c.present || name != TableName || family != nftables.TableFamilyINet {
		return nil, unix.ENOENT
	}
	return hostTable(), nil
}
func (c *recordingConn) Flush() error {
	c.flushes++
	if c.flushErr != nil {
		return c.flushErr
	}
	c.present = len(c.deleted) == 0 || len(c.tables) > len(c.deleted)
	return nil
}

func TestNetlinkApplier_ApplyIsOneBatchScopedToTheTable(t *testing.T) {
	conn := &recordingConn{}
	a := newNetlinkApplierWithConn(conn)
	rendered, err := Render(fixtureRuleset())
	require.NoError(t, err)

	require.NoError(t, a.Apply(context.Background(), rendered))
	require.Len(t, conn.tables, 1)
	assert.Equal(t, TableName, conn.tables[0].Name)
	assert.Equal(t, nftables.TableFamilyINet, conn.tables[0].Family)
	assert.Equal(t, []string{TableName}, conn.flushed, "only our table is flushed")
	require.Len(t, conn.chains, 1)
	assert.Equal(t, ChainInput, conn.chains[0].Name)
	assert.Equal(t, nftables.ChainTypeFilter, conn.chains[0].Type)
	assert.Equal(t, nftables.ChainHookInput, conn.chains[0].Hooknum)
	assert.Equal(t, nftables.ChainPolicyDrop, *conn.chains[0].Policy)
	assert.Len(t, conn.rules, len(rendered.Rules))
	assert.Equal(t, 1, conn.flushes, "one transaction")
	for i, r := range conn.rules {
		assert.Same(t, conn.chains[0], r.Chain)
		assert.Equal(t, userData(rendered.Rules[i].Comment), r.UserData)
	}
	present, err := a.Installed(context.Background())
	require.NoError(t, err)
	assert.True(t, present)
}

func TestNetlinkApplier_ApplyErrors(t *testing.T) {
	rendered, err := Render(Ruleset{})
	require.NoError(t, err)
	t.Run("flush failure", func(t *testing.T) {
		a := newNetlinkApplierWithConn(&recordingConn{flushErr: errors.New("EPERM")})
		err := a.Apply(context.Background(), rendered)
		var op *OpError
		require.True(t, errors.As(err, &op))
		assert.Equal(t, "apply", op.Op)
	})
	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		conn := &recordingConn{}
		err := newNetlinkApplierWithConn(conn).Apply(ctx, rendered)
		assert.ErrorIs(t, err, context.Canceled)
		assert.Zero(t, conn.flushes)
	})
	t.Run("unknown rule kind", func(t *testing.T) {
		bad := &Rendered{Rules: []Rule{{Kind: RuleKind(99)}}}
		err := newNetlinkApplierWithConn(&recordingConn{}).Apply(context.Background(), bad)
		assert.ErrorIs(t, err, ErrUnknownProtocol)
	})
}

func TestNetlinkApplier_RemoveAndInstalled(t *testing.T) {
	t.Run("absent table is not an error", func(t *testing.T) {
		conn := &recordingConn{}
		require.NoError(t, newNetlinkApplierWithConn(conn).Remove(context.Background()))
		assert.Empty(t, conn.deleted)
	})
	t.Run("present table is deleted", func(t *testing.T) {
		conn := &recordingConn{present: true}
		require.NoError(t, newNetlinkApplierWithConn(conn).Remove(context.Background()))
		assert.Equal(t, []string{TableName}, conn.deleted)
		assert.Equal(t, 1, conn.flushes)
	})
	t.Run("delete flush failure", func(t *testing.T) {
		conn := &recordingConn{present: true, flushErr: errors.New("busy")}
		err := newNetlinkApplierWithConn(conn).Remove(context.Background())
		var op *OpError
		require.True(t, errors.As(err, &op))
		assert.Equal(t, "remove", op.Op)
	})
	t.Run("inspect failure", func(t *testing.T) {
		conn := &recordingConn{listErr: errors.New("netlink down")}
		_, err := newNetlinkApplierWithConn(conn).Installed(context.Background())
		var op *OpError
		require.True(t, errors.As(err, &op))
		assert.Equal(t, "inspect", op.Op)
		assert.Error(t, newNetlinkApplierWithConn(conn).Remove(context.Background()))
	})
	t.Run("cancelled context", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := newNetlinkApplierWithConn(&recordingConn{}).Installed(ctx)
		assert.ErrorIs(t, err, context.Canceled)
		assert.ErrorIs(t, newNetlinkApplierWithConn(&recordingConn{}).Remove(ctx), context.Canceled)
	})
}

// exprKinds summarises an expression list by type name so the shape of a
// compiled rule can be asserted without re-deriving every byte.
func exprKinds(exprs []expr.Any) []string {
	var out []string
	for _, e := range exprs {
		switch e.(type) {
		case *expr.Meta:
			out = append(out, "meta")
		case *expr.Cmp:
			out = append(out, "cmp")
		case *expr.Payload:
			out = append(out, "payload")
		case *expr.Bitwise:
			out = append(out, "bitwise")
		case *expr.Ct:
			out = append(out, "ct")
		case *expr.Limit:
			out = append(out, "limit")
		case *expr.Range:
			out = append(out, "range")
		case *expr.Verdict:
			out = append(out, "verdict")
		default:
			out = append(out, "?")
		}
	}
	return out
}

func TestBuildExprs_Shapes(t *testing.T) {
	icmp := DefaultICMPRateLimit
	cases := map[string]struct {
		rule Rule
		want []string
	}{
		"loopback":    {Rule{Kind: RuleLoopback, Interface: "lo"}, []string{"meta", "cmp", "verdict"}},
		"established": {Rule{Kind: RuleEstablished}, []string{"meta", "cmp", "cmp", "ct", "bitwise", "cmp", "verdict"}},
		"invalid":     {Rule{Kind: RuleInvalid}, []string{"ct", "bitwise", "cmp", "verdict"}},
		"unfiltered":  {Rule{Kind: RuleUnfiltered, Interface: "eth1"}, []string{"meta", "cmp", "verdict"}},
		"icmpv4":      {Rule{Kind: RuleICMPv4}, []string{"meta", "cmp", "meta", "cmp", "limit", "verdict"}},
		"icmpv6 nd":   {Rule{Kind: RuleICMPv6ND}, []string{"meta", "cmp", "meta", "cmp", "payload", "range", "verdict"}},
		"icmpv6":      {Rule{Kind: RuleICMPv6}, []string{"meta", "cmp", "meta", "cmp", "limit", "verdict"}},
		"listener any source": {Rule{Kind: RuleListener, Interface: "eth0", Protocol: ProtocolTCP, Port: 8443},
			[]string{"meta", "cmp", "meta", "cmp", "payload", "cmp", "verdict"}},
		"listener v4 source": {Rule{Kind: RuleListener, Interface: "eth0", Family: 4, Protocol: ProtocolTCP, Port: 22, Source: netip.MustParsePrefix("10.4.6.0/24")},
			[]string{"meta", "cmp", "meta", "cmp", "payload", "bitwise", "cmp", "meta", "cmp", "payload", "cmp", "verdict"}},
		"peer v6": {Rule{Kind: RulePeer, Interface: "wan0", Family: 6, Peer: netip.MustParseAddr("2001:db8::1"), IPProto: ipProtoESP},
			[]string{"meta", "cmp", "meta", "cmp", "payload", "bitwise", "cmp", "meta", "cmp", "verdict"}},
		"tunnel bfd": {Rule{Kind: RuleTunnelPort, Interface: "gre1", Protocol: ProtocolUDP, Port: PortBFD},
			[]string{"meta", "cmp", "meta", "cmp", "payload", "cmp", "verdict"}},
		"vrrp": {Rule{Kind: RuleVRRP, Interface: "eth1", IPProto: ipProtoVRRP}, []string{"meta", "cmp", "meta", "cmp", "verdict"}},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			exprs, err := buildExprs(c.rule, icmp)
			require.NoError(t, err)
			assert.Equal(t, c.want, exprKinds(exprs))
		})
	}
}

func TestBuildExprs_Values(t *testing.T) {
	t.Run("ifname is NUL-padded to IFNAMSIZ", func(t *testing.T) {
		e := exprIfname("eth0")
		cmp := e[1].(*expr.Cmp)
		assert.Len(t, cmp.Data, unix.IFNAMSIZ)
		assert.Equal(t, "eth0", string(cmp.Data[:4]))
		assert.Equal(t, byte(0), cmp.Data[4])
	})
	t.Run("dport is big-endian", func(t *testing.T) {
		e := exprDport(8443)
		assert.Equal(t, []byte{0x20, 0xfb}, e[1].(*expr.Cmp).Data)
		assert.Equal(t, uint32(2), e[0].(*expr.Payload).Offset)
	})
	t.Run("v4 prefix mask", func(t *testing.T) {
		e := exprSaddrPrefix(netip.MustParsePrefix("10.20.30.40/20"))
		p := e[0].(*expr.Payload)
		assert.Equal(t, uint32(12), p.Offset)
		assert.Equal(t, uint32(4), p.Len)
		assert.Equal(t, []byte{255, 255, 240, 0}, e[1].(*expr.Bitwise).Mask)
		assert.Equal(t, []byte{10, 20, 16, 0}, e[2].(*expr.Cmp).Data, "compared against the masked prefix")
	})
	t.Run("v6 prefix mask", func(t *testing.T) {
		e := exprSaddrPrefix(netip.MustParsePrefix("fd00:101::/64"))
		p := e[0].(*expr.Payload)
		assert.Equal(t, uint32(8), p.Offset)
		assert.Equal(t, uint32(16), p.Len)
		mask := e[1].(*expr.Bitwise).Mask
		assert.Equal(t, byte(0xff), mask[7])
		assert.Equal(t, byte(0), mask[8])
	})
	t.Run("host address is a full-length prefix", func(t *testing.T) {
		e := exprSaddrPrefix(netip.PrefixFrom(netip.MustParseAddr("198.51.100.100"), 32))
		assert.Equal(t, []byte{255, 255, 255, 255}, e[1].(*expr.Bitwise).Mask)
	})
	t.Run("nfproto", func(t *testing.T) {
		assert.Equal(t, []byte{unix.NFPROTO_IPV4}, exprNFProto(4)[1].(*expr.Cmp).Data)
		assert.Equal(t, []byte{unix.NFPROTO_IPV6}, exprNFProto(6)[1].(*expr.Cmp).Data)
	})
	t.Run("ct state bits", func(t *testing.T) {
		e := exprCtState(expr.CtStateBitESTABLISHED | expr.CtStateBitRELATED)
		assert.Equal(t, []byte{6, 0, 0, 0}, e[1].(*expr.Bitwise).Mask)
		assert.Equal(t, expr.CmpOpNeq, e[2].(*expr.Cmp).Op)
	})
	t.Run("limit", func(t *testing.T) {
		l := exprLimit(RateLimit{Rate: 5, Burst: 7}).(*expr.Limit)
		assert.Equal(t, uint64(5), l.Rate)
		assert.Equal(t, uint32(7), l.Burst)
		assert.Equal(t, expr.LimitTypePkts, l.Type)
	})
	t.Run("nd range", func(t *testing.T) {
		exprs, err := buildExprs(Rule{Kind: RuleICMPv6ND}, DefaultICMPRateLimit)
		require.NoError(t, err)
		r := exprs[5].(*expr.Range)
		assert.Equal(t, []byte{133}, r.FromData)
		assert.Equal(t, []byte{137}, r.ToData)
	})
	t.Run("conntrack never admits tunnel encapsulation", func(t *testing.T) {
		// A host that has sent GRE or ESP to an address holds a conntrack
		// entry for it, so that address's GRE or ESP is "established". Only
		// the peer allowance may admit it.
		exprs, err := buildExprs(Rule{Kind: RuleEstablished}, DefaultICMPRateLimit)
		require.NoError(t, err)
		assert.Equal(t, expr.MetaKeyL4PROTO, exprs[0].(*expr.Meta).Key)
		for i, proto := range []byte{ipProtoGRE, ipProtoESP} {
			cmp := exprs[1+i].(*expr.Cmp)
			assert.Equal(t, expr.CmpOpNeq, cmp.Op)
			assert.Equal(t, []byte{proto}, cmp.Data)
		}
	})
	t.Run("gre peer protocol", func(t *testing.T) {
		exprs, err := buildExprs(Rule{Kind: RulePeer, Interface: "wan0", Family: 4, Peer: netip.MustParseAddr("192.0.2.100"), IPProto: ipProtoGRE}, DefaultICMPRateLimit)
		require.NoError(t, err)
		assert.Equal(t, []byte{47}, exprs[8].(*expr.Cmp).Data)
	})
}

func TestUserData(t *testing.T) {
	assert.Nil(t, userData(""))
	got := userData("bgp on gre1")
	assert.Equal(t, byte(0), got[0])
	assert.Equal(t, byte(len("bgp on gre1")+1), got[1])
	assert.Equal(t, "bgp on gre1", string(got[2:len(got)-1]))
	assert.Equal(t, byte(0), got[len(got)-1])
	long := userData(string(make([]byte, 300)))
	assert.Len(t, long, 127+3, "comments are capped at the libnftnl limit")
}
