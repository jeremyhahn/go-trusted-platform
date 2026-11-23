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
	"cmp"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"sync"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
)

const (
	// vpnHubTableName is the hub's own inet table, so programming it never
	// touches the host filter's or the IPsec filter's tables (#2093).
	vpnHubTableName = "tp_vpn_hub"
	// vpnHubChainForward is the table's forward-hook chain: forwarded
	// vpn-hub0 traffic jumps from it to the ingress chain.
	vpnHubChainForward = "forward"
	// vpnHubChainInput is the table's input-hook chain: vpn-hub0 traffic
	// addressed to the gateway's own addresses jumps from it to the ingress
	// chain, so locally delivered traffic is held to the same lease rules.
	vpnHubChainInput = "input"
	// vpnHubChainIngress is the table's regular chain holding the compiled
	// lease rules, the one rule set that decides both forwarded and locally
	// delivered vpn-hub0 traffic.
	vpnHubChainIngress = "ingress"
)

// vpnHubNFTConn is the part of *nftables.Conn the hub's forward chain uses.
type vpnHubNFTConn interface {
	AddTable(t *nftables.Table) *nftables.Table
	FlushTable(t *nftables.Table)
	DelTable(t *nftables.Table)
	AddChain(c *nftables.Chain) *nftables.Chain
	AddRule(r *nftables.Rule) *nftables.Rule
	Flush() error
}

// newVPNHubNFTConn opens the netlink connection the forward chain is
// programmed over. A variable so tests can stand a recorder in.
var newVPNHubNFTConn = func() (vpnHubNFTConn, error) { return nftables.New() }

func vpnHubTable() *nftables.Table {
	return &nftables.Table{Name: vpnHubTableName, Family: nftables.TableFamilyINet}
}

// vpnHubForwardProgrammer writes compiled vpn-hub0 forwarding rules into the
// hub's table.
type vpnHubForwardProgrammer struct {
	conn vpnHubNFTConn
}

// program replaces the hub table's rules with rules in one netlink batch.
// The rules sit in the regular ingress chain; the forward and input hook
// chains each jump there for traffic entering on vpn-hub0, so forwarded and
// locally delivered hub traffic are decided by the one rule set. The hook
// chains' policy is accept, as in the IPsec filter's forward chain: only
// traffic entering on vpn-hub0 reaches the closing drop.
func (p *vpnHubForwardProgrammer) program(ctx context.Context, rules []vpnHubForwardRule) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	for _, r := range rules {
		if r.Port != 0 {
			if _, ok := vpnHubL4Proto(r.Protocol); !ok {
				return fmt.Errorf("vpn hub forward rule %q: unknown protocol %q", r.Comment, r.Protocol)
			}
		}
	}
	table := p.conn.AddTable(vpnHubTable())
	p.conn.FlushTable(table)
	ingress := p.conn.AddChain(&nftables.Chain{Name: vpnHubChainIngress, Table: table})
	policy := nftables.ChainPolicyAccept
	forward := p.conn.AddChain(&nftables.Chain{
		Name:     vpnHubChainForward,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookForward,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policy,
	})
	input := p.conn.AddChain(&nftables.Chain{
		Name:     vpnHubChainInput,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policy,
	})
	for _, r := range rules {
		p.conn.AddRule(&nftables.Rule{Table: table, Chain: ingress, Exprs: vpnHubForwardExprs(r), UserData: vpnHubUserData(r.Comment)})
	}
	for _, hook := range []*nftables.Chain{forward, input} {
		p.conn.AddRule(&nftables.Rule{
			Table:    table,
			Chain:    hook,
			Exprs:    append(vpnHubExprIfname(vpnHubInterface), &expr.Verdict{Kind: expr.VerdictJump, Chain: vpnHubChainIngress}),
			UserData: vpnHubUserData("vpn-hub0 traffic passes the lease rules"),
		})
	}
	if err := p.conn.Flush(); err != nil {
		return fmt.Errorf("program the %s chains: %w", vpnHubInterface, err)
	}
	return nil
}

// remove deletes the hub's table.
func (p *vpnHubForwardProgrammer) remove(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	p.conn.DelTable(vpnHubTable())
	if err := p.conn.Flush(); err != nil {
		return fmt.Errorf("delete the %s forward chain: %w", vpnHubInterface, err)
	}
	return nil
}

// vpnHubForwardExprs renders r as nftables expressions: the vpn-hub0
// ingress match, then the closing drop, the established/related accept, or
// the lease's family, source, destination and optional port, and accept.
// The rules sit in the ingress chain, so they decide both forwarded and
// locally delivered vpn-hub0 traffic.
func vpnHubForwardExprs(r vpnHubForwardRule) []expr.Any {
	e := vpnHubExprIfname(vpnHubInterface)
	if r.Drop {
		return append(e, &expr.Verdict{Kind: expr.VerdictDrop})
	}
	if r.Family == 0 {
		e = append(e, vpnHubExprCtState(expr.CtStateBitESTABLISHED|expr.CtStateBitRELATED)...)
		return append(e, &expr.Verdict{Kind: expr.VerdictAccept})
	}
	e = append(e, vpnHubExprNFProto(r.Family)...)
	e = append(e, vpnHubExprAddrPrefix(r.Source, false)...)
	e = append(e, vpnHubExprAddrPrefix(r.Destination, true)...)
	if r.Port != 0 {
		// program refuses an unknown protocol; 255 is reserved and never
		// matches, so a rule rendered without that check opens nothing.
		proto, ok := vpnHubL4Proto(r.Protocol)
		if !ok {
			proto = 255
		}
		e = append(e,
			&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
		)
		port := make([]byte, 2)
		binary.BigEndian.PutUint16(port, r.Port)
		e = append(e,
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: port},
		)
	}
	return append(e, &expr.Verdict{Kind: expr.VerdictAccept})
}

func vpnHubL4Proto(protocol string) (uint8, bool) {
	switch protocol {
	case "tcp":
		return unix.IPPROTO_TCP, true
	case "udp":
		return unix.IPPROTO_UDP, true
	}
	return 0, false
}

// vpnHubUserData encodes a rule comment as nft's comment TLV.
func vpnHubUserData(comment string) []byte {
	if comment == "" {
		return nil
	}
	if len(comment) > 127 {
		comment = comment[:127]
	}
	b := make([]byte, 0, len(comment)+3)
	b = append(b, 0, byte(len(comment)+1))
	b = append(b, comment...)
	return append(b, 0)
}

func vpnHubExprIfname(name string) []expr.Any {
	data := make([]byte, unix.IFNAMSIZ)
	copy(data, name)
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: data},
	}
}

func vpnHubExprNFProto(family int) []expr.Any {
	proto := byte(unix.NFPROTO_IPV4)
	if family == 6 {
		proto = unix.NFPROTO_IPV6
	}
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
	}
}

func vpnHubExprCtState(bits uint32) []expr.Any {
	mask := make([]byte, 4)
	binary.LittleEndian.PutUint32(mask, bits)
	return []expr.Any{
		&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: mask, Xor: []byte{0, 0, 0, 0}},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
	}
}

// vpnHubExprAddrPrefix matches the network-layer source (or, with dst, the
// destination) address against a prefix: load it, mask it, compare it to
// the masked prefix.
func vpnHubExprAddrPrefix(p netip.Prefix, dst bool) []expr.Any {
	addr := p.Masked().Addr().Unmap()
	var offset, length uint32 = 12, 4
	if addr.Is6() {
		offset, length = 8, 16
	}
	if dst {
		offset += length
	}
	bits := p.Bits()
	if p.Addr().Is4In6() && addr.Is4() {
		bits -= 96
	}
	mask := make([]byte, length)
	for i := range mask {
		switch {
		case bits >= 8:
			mask[i] = 0xff
			bits -= 8
		case bits > 0:
			mask[i] = byte(0xff << (8 - bits))
			bits = 0
		}
	}
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: length},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: length, Mask: mask, Xor: make([]byte, length)},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: addr.AsSlice()},
	}
}

// vpnHubForwardFilter keeps the hub's forward chain in step with its peers:
// every change recompiles the rules for the whole lease set from the
// enforcement's matrix and networks and programs them. The lease set is
// recorded only once its program succeeds. A nil filter is a no-op.
type vpnHubForwardFilter struct {
	mu     sync.Mutex
	e      *vpnHubZoneEnforcement
	prog   *vpnHubForwardProgrammer
	leases map[vpn.LeaseID]*vpn.Lease
}

func newVPNHubForwardFilter(e *vpnHubZoneEnforcement, conn vpnHubNFTConn) *vpnHubForwardFilter {
	return &vpnHubForwardFilter{e: e, prog: &vpnHubForwardProgrammer{conn: conn}, leases: map[vpn.LeaseID]*vpn.Lease{}}
}

// apply programs the candidate lease set and records it on success. The
// caller holds f.mu.
func (f *vpnHubForwardFilter) apply(ctx context.Context, candidate map[vpn.LeaseID]*vpn.Lease) error {
	if f.e == nil {
		return errors.New("no destination-zone enforcement for the " + vpnHubInterface + " forward chain")
	}
	leases := make([]*vpn.Lease, 0, len(candidate))
	for _, l := range candidate {
		leases = append(leases, l)
	}
	slices.SortFunc(leases, func(a, b *vpn.Lease) int { return cmp.Compare(a.ID, b.ID) })
	rules, err := compileVPNHubForwardRules(f.e, f.e.nets, leases)
	if err != nil {
		return err
	}
	if err := f.prog.program(ctx, rules); err != nil {
		return err
	}
	f.leases = candidate
	return nil
}

func (f *vpnHubForwardFilter) candidate() map[vpn.LeaseID]*vpn.Lease {
	c := make(map[vpn.LeaseID]*vpn.Lease, len(f.leases)+1)
	for id, l := range f.leases {
		c[id] = l
	}
	return c
}

// admit adds the lease's accepts. On failure the lease is left out.
func (f *vpnHubForwardFilter) admit(ctx context.Context, lease *vpn.Lease) error {
	if f == nil || lease == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.candidate()
	c[lease.ID] = lease
	return f.apply(ctx, c)
}

// forget withdraws the lease's accepts.
func (f *vpnHubForwardFilter) forget(ctx context.Context, id vpn.LeaseID) error {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.leases[id]; !ok {
		return nil
	}
	c := f.candidate()
	delete(c, id)
	return f.apply(ctx, c)
}

// keep withdraws the accepts of every lease not in ids and reprograms the
// chain.
func (f *vpnHubForwardFilter) keep(ctx context.Context, ids []vpn.LeaseID) error {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	c := make(map[vpn.LeaseID]*vpn.Lease, len(ids))
	for _, id := range ids {
		if l, ok := f.leases[id]; ok {
			c[id] = l
		}
	}
	return f.apply(ctx, c)
}

// remove deletes the hub's table.
func (f *vpnHubForwardFilter) remove(ctx context.Context) error {
	if f == nil {
		return nil
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if err := f.prog.remove(ctx); err != nil {
		return err
	}
	f.leases = map[vpn.LeaseID]*vpn.Lease{}
	return nil
}
