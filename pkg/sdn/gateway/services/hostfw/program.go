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
	"encoding/binary"
	"errors"
	"net/netip"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

// Applier programs the host filter into the kernel. Apply replaces the
// whole table in one transaction; Remove deletes it; Installed reports
// whether it is present. The Service is written against this interface so
// it is exercised without CAP_NET_ADMIN, and NetlinkApplier is the one
// implementation that talks to the kernel.
type Applier interface {
	Apply(ctx context.Context, r *Rendered) error
	Remove(ctx context.Context) error
	Installed(ctx context.Context) (bool, error)
}

// nftConn is the slice of *nftables.Conn the applier uses, so tests can
// substitute a recorder.
type nftConn interface {
	AddTable(t *nftables.Table) *nftables.Table
	FlushTable(t *nftables.Table)
	DelTable(t *nftables.Table)
	AddChain(c *nftables.Chain) *nftables.Chain
	AddRule(r *nftables.Rule) *nftables.Rule
	ListTableOfFamily(name string, family nftables.TableFamily) (*nftables.Table, error)
	Flush() error
}

// NetlinkApplier programs `inet tp_host` over netlink. Every Apply is one
// batch — add-or-keep the table, flush it, add the chain, add the rules —
// committed by a single Flush, so the kernel never observes a half-written
// table and nothing outside the table is ever addressed.
type NetlinkApplier struct {
	conn nftConn
}

// NewNetlinkApplier opens a netlink connection to nf_tables. It needs
// CAP_NET_ADMIN. Options are passed through to the library, which is how
// a caller pins the connection to a network namespace
// (nftables.WithNetNSFd).
func NewNetlinkApplier(opts ...nftables.ConnOption) (*NetlinkApplier, error) {
	conn, err := nftables.New(opts...)
	if err != nil {
		return nil, &OpError{Op: "connect", Err: err}
	}
	return &NetlinkApplier{conn: conn}, nil
}

func newNetlinkApplierWithConn(conn nftConn) *NetlinkApplier {
	return &NetlinkApplier{conn: conn}
}

func hostTable() *nftables.Table {
	return &nftables.Table{Name: TableName, Family: nftables.TableFamilyINet}
}

// Apply implements Applier.
func (a *NetlinkApplier) Apply(ctx context.Context, r *Rendered) error {
	if err := ctx.Err(); err != nil {
		return &OpError{Op: "apply", Err: err}
	}
	table := a.conn.AddTable(hostTable())
	a.conn.FlushTable(table)
	policy := nftables.ChainPolicyDrop
	chain := a.conn.AddChain(&nftables.Chain{
		Name:     ChainInput,
		Table:    table,
		Type:     nftables.ChainTypeFilter,
		Hooknum:  nftables.ChainHookInput,
		Priority: nftables.ChainPriorityFilter,
		Policy:   &policy,
	})
	for _, rule := range r.Rules {
		exprs, err := buildExprs(rule, r.ICMP)
		if err != nil {
			return &OpError{Op: "apply", Err: err}
		}
		a.conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: exprs, UserData: userData(rule.Comment)})
	}
	if err := a.conn.Flush(); err != nil {
		return &OpError{Op: "apply", Err: err}
	}
	return nil
}

// Remove implements Applier. A table that is already gone is not an error.
func (a *NetlinkApplier) Remove(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return &OpError{Op: "remove", Err: err}
	}
	present, err := a.Installed(ctx)
	if err != nil {
		return err
	}
	if !present {
		return nil
	}
	a.conn.DelTable(hostTable())
	if err := a.conn.Flush(); err != nil {
		return &OpError{Op: "remove", Err: err}
	}
	return nil
}

// Installed implements Applier.
func (a *NetlinkApplier) Installed(ctx context.Context) (bool, error) {
	if err := ctx.Err(); err != nil {
		return false, &OpError{Op: "inspect", Err: err}
	}
	_, err := a.conn.ListTableOfFamily(TableName, nftables.TableFamilyINet)
	if err != nil {
		if errors.Is(err, unix.ENOENT) {
			return false, nil
		}
		return false, &OpError{Op: "inspect", Err: err}
	}
	return true, nil
}

// userData encodes a rule comment the way nft(8) does (NFTNL_UDATA_RULE_COMMENT).
func userData(comment string) []byte {
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

// buildExprs turns one Rule into the nf_tables expression list the kernel
// evaluates. Register 1 carries every loaded value; each comparison
// short-circuits the rule on mismatch, so the expressions are ANDed.
func buildExprs(r Rule, icmp RateLimit) ([]expr.Any, error) {
	var e []expr.Any
	if r.Interface != "" {
		e = append(e, exprIfname(r.Interface)...)
	}
	switch r.Kind {
	case RuleLoopback, RuleUnfiltered:
		e = append(e, accept())
	case RuleEstablished:
		e = append(e, exprNotL4Proto(ipProtoGRE, ipProtoESP)...)
		e = append(e, exprCtState(expr.CtStateBitESTABLISHED|expr.CtStateBitRELATED)...)
		e = append(e, accept())
	case RuleInvalid:
		e = append(e, exprCtState(expr.CtStateBitINVALID)...)
		e = append(e, drop())
	case RuleICMPv4:
		e = append(e, exprNFProto(4)...)
		e = append(e, exprL4Proto(ipProtoICMP)...)
		e = append(e, exprLimit(icmp), accept())
	case RuleICMPv6ND:
		e = append(e, exprNFProto(6)...)
		e = append(e, exprL4Proto(ipProtoIPv6ICMP)...)
		e = append(e,
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1},
			&expr.Range{Op: expr.CmpOpEq, Register: 1, FromData: []byte{icmpv6NDFirst}, ToData: []byte{icmpv6NDLast}},
			accept())
	case RuleICMPv6:
		e = append(e, exprNFProto(6)...)
		e = append(e, exprL4Proto(ipProtoIPv6ICMP)...)
		e = append(e, exprLimit(icmp), accept())
	case RuleListener, RuleTunnelPort:
		if r.Source.IsValid() {
			e = append(e, exprNFProto(r.Family)...)
			e = append(e, exprSaddrPrefix(r.Source)...)
		}
		proto := ipProtoTCP
		if r.Protocol == ProtocolUDP {
			proto = ipProtoUDP
		}
		e = append(e, exprL4Proto(proto)...)
		e = append(e, exprDport(r.Port)...)
		e = append(e, accept())
	case RulePeer:
		e = append(e, exprNFProto(r.Family)...)
		e = append(e, exprSaddrPrefix(netip.PrefixFrom(r.Peer, r.Peer.BitLen()))...)
		e = append(e, exprL4Proto(r.IPProto)...)
		e = append(e, accept())
	case RuleVRRP:
		e = append(e, exprL4Proto(ipProtoVRRP)...)
		e = append(e, accept())
	case RuleVIPDeny:
		e = append(e, exprNFProto(r.Family)...)
		e = append(e, exprDaddr(r.Destination)...)
		if r.Family == 6 {
			e = append(e, exprNotL4Proto(ipProtoIPv6ICMP)...)
		}
		e = append(e, drop())
	case RuleVIPDenyICMPv6:
		e = append(e, exprNFProto(6)...)
		e = append(e, exprDaddr(r.Destination)...)
		e = append(e, exprL4Proto(ipProtoIPv6ICMP)...)
		e = append(e,
			&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{icmpv6NeighborSolicit}},
			&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{icmpv6NeighborAdvert}},
			drop())
	default:
		return nil, ErrUnknownProtocol
	}
	return e, nil
}

func accept() expr.Any { return &expr.Verdict{Kind: expr.VerdictAccept} }
func drop() expr.Any   { return &expr.Verdict{Kind: expr.VerdictDrop} }

func exprIfname(name string) []expr.Any {
	data := make([]byte, unix.IFNAMSIZ)
	copy(data, name)
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyIIFNAME, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: data},
	}
}

func exprNFProto(family int) []expr.Any {
	proto := byte(unix.NFPROTO_IPV4)
	if family == 6 {
		proto = unix.NFPROTO_IPV6
	}
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyNFPROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
	}
}

func exprL4Proto(proto uint8) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{proto}},
	}
}

// exprNotL4Proto matches a packet whose layer-4 protocol is none of protos.
func exprNotL4Proto(protos ...uint8) []expr.Any {
	e := []expr.Any{&expr.Meta{Key: expr.MetaKeyL4PROTO, Register: 1}}
	for _, proto := range protos {
		e = append(e, &expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{proto}})
	}
	return e
}

func exprDport(port uint16) []expr.Any {
	data := make([]byte, 2)
	binary.BigEndian.PutUint16(data, port)
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 2, Len: 2},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: data},
	}
}

func exprCtState(bits uint32) []expr.Any {
	mask := make([]byte, 4)
	binary.LittleEndian.PutUint32(mask, bits)
	return []expr.Any{
		&expr.Ct{Key: expr.CtKeySTATE, Register: 1},
		&expr.Bitwise{SourceRegister: 1, DestRegister: 1, Len: 4, Mask: mask, Xor: []byte{0, 0, 0, 0}},
		&expr.Cmp{Op: expr.CmpOpNeq, Register: 1, Data: []byte{0, 0, 0, 0}},
	}
}

func exprLimit(l RateLimit) expr.Any {
	return &expr.Limit{Type: expr.LimitTypePkts, Rate: l.Rate, Unit: expr.LimitTimeSecond, Burst: l.Burst}
}

// exprSaddrPrefix matches the network-layer source address against a
// prefix: load the address, mask it, compare to the masked prefix.
func exprSaddrPrefix(p netip.Prefix) []expr.Any {
	addr := p.Masked().Addr()
	var offset, length uint32 = 12, 4
	if addr.Is6() {
		offset, length = 8, 16
	}
	raw := addr.AsSlice()
	mask := make([]byte, length)
	bits := p.Bits()
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
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: raw},
	}
}

// exprDaddr matches the destination address exactly.
func exprDaddr(a netip.Addr) []expr.Any {
	var offset, length uint32 = 16, 4
	if a.Is6() {
		offset, length = 24, 16
	}
	return []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: length},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: a.AsSlice()},
	}
}
