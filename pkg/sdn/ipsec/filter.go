// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package ipsec

import (
	"context"
	"encoding/binary"
	"errors"
	"maps"
	"net/netip"
	"slices"
	"sync"
	"time"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"golang.org/x/sys/unix"
)

const (
	// TableName is the nftables table the fail-closed filter owns.
	TableName = "tp_ipsec"

	chainInput   = "fabric_in"
	chainForward = "fabric_fwd"
	chainOutput  = "fabric_out"
	setEvicted   = "evicted"
	setIKEMeter  = "ike_meter"
	ikeMeterSize = 65535

	// ikeMeterTimeout is how long a source's IKE rate state outlives its
	// last packet.
	ikeMeterTimeout = time.Minute

	// filterPriority runs the filter's chains just before the host
	// filter's (tp_host, at filter priority). Both must accept a packet;
	// this table only ever narrows.
	filterPriority = -10

	ikePort     = 500
	ikeNATTPort = 4500

	// The ICMPv6 types the link needs before any SA exists (RFC 4861,
	// RFC 2710, RFC 3810). Redirect (137) is deliberately absent.
	icmpv6MLDQuery    = 130
	icmpv6MLDReport   = 131
	icmpv6MLDDone     = 132
	icmpv6RouterSol   = 133
	icmpv6RouterAdv   = 134
	icmpv6NeighSol    = 135
	icmpv6NeighAdv    = 136
	icmpv6MLDv2Report = 143

	// metaKeySecpath and rtKeyXFRM are NFT_META_SECPATH and NFT_RT_XFRM
	// (linux/netfilter/nf_tables.h), which neither x/sys/unix nor the
	// nftables library names: the packet was decrypted by an SA, or is
	// routed into one.
	metaKeySecpath = expr.MetaKey(25)
	rtKeyXFRM      = expr.RtKey(4)
)

// nftConn is the slice of *nftables.Conn the filter uses, so tests can
// substitute a recorder.
type nftConn interface {
	AddTable(t *nftables.Table) *nftables.Table
	DelTable(t *nftables.Table)
	AddSet(s *nftables.Set, vals []nftables.SetElement) error
	SetAddElements(s *nftables.Set, vals []nftables.SetElement) error
	SetDeleteElements(s *nftables.Set, vals []nftables.SetElement) error
	AddChain(c *nftables.Chain) *nftables.Chain
	AddRule(r *nftables.Rule) *nftables.Rule
	ListTableOfFamily(name string, family nftables.TableFamily) (*nftables.Table, error)
	Flush() error
}

// Filter is the nftables half of the fail-closed floor. On the fabric
// interface it passes, in both directions, only ESP, IKE between ports
// 500 and 4500, traffic an SA decrypted or is about to encrypt, and the
// ICMPv6 the link needs (linkICMPv6). Traffic routed through the node to or
// from the fabric passes only as ESP or once an SA decrypted it.
// Everything else is dropped, so a stopped charon leaves no cleartext path.
// IKE is accepted per source address only while it stays within the rate,
// and evicted peers are dropped outright, IKE included. It implements
// Dropper.
type Filter struct {
	iface string
	local netip.Addr
	rate  uint32
	burst uint32
	slaac bool

	mu      sync.Mutex
	conn    nftConn
	evicted map[netip.Addr]struct{}
	applied bool
}

// NewFilter opens a netlink connection to nf_tables for an enabled
// configuration. It needs CAP_NET_ADMIN. Options are passed through to
// the library, which is how a caller pins the connection to a network
// namespace (nftables.WithNetNSFd).
func NewFilter(cfg *Config, opts ...nftables.ConnOption) (*Filter, error) {
	conn, err := nftables.New(opts...)
	if err != nil {
		return nil, &OpError{Op: "nftables connect", Err: err}
	}
	return newFilter(cfg, conn)
}

func newFilter(cfg *Config, conn nftConn) (*Filter, error) {
	local, err := enabledLocal(cfg)
	if err != nil {
		return nil, err
	}
	return &Filter{
		iface:   cfg.FabricInterface,
		local:   local,
		rate:    cfg.EffectiveIKERate(),
		burst:   cfg.EffectiveIKEBurst(),
		slaac:   cfg.UnderlaySLAAC,
		conn:    conn,
		evicted: make(map[netip.Addr]struct{}),
	}, nil
}

// Apply writes the whole table in one transaction: an existing table is
// replaced, never edited, so the kernel moves from the old filter to the
// new one with nothing in between. Peers dropped so far are carried over.
func (f *Filter) Apply(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return &OpError{Op: "nftables apply", Err: err}
	}
	f.mu.Lock()
	defer f.mu.Unlock()

	// Adding the table before deleting it makes the delete safe when no
	// table exists yet; the batch still leaves only the new table.
	f.conn.AddTable(f.table())
	f.conn.DelTable(f.table())
	table := f.conn.AddTable(f.table())

	evicted := f.evictedSet(table)
	if err := f.conn.AddSet(evicted, f.elements(slices.Collect(maps.Keys(f.evicted)))); err != nil {
		return &OpError{Op: "nftables apply", Err: err}
	}
	meter := &nftables.Set{
		Table:      table,
		Name:       setIKEMeter,
		KeyType:    f.addrType(),
		Dynamic:    true,
		HasTimeout: true,
		Timeout:    ikeMeterTimeout,
		Size:       ikeMeterSize,
	}
	if err := f.conn.AddSet(meter, nil); err != nil {
		return &OpError{Op: "nftables apply", Err: err}
	}

	accept := nftables.ChainPolicyAccept
	prio := nftables.ChainPriorityRef(filterPriority)
	chains := []struct {
		name  string
		hook  *nftables.ChainHook
		rules [][]expr.Any
	}{
		{chainInput, nftables.ChainHookInput, f.inputRules(evicted, meter)},
		{chainForward, nftables.ChainHookForward, f.forwardRules(evicted)},
		{chainOutput, nftables.ChainHookOutput, f.outputRules(evicted)},
	}
	for _, c := range chains {
		chain := f.conn.AddChain(&nftables.Chain{
			Name: c.name, Table: table, Type: nftables.ChainTypeFilter,
			Hooknum: c.hook, Priority: prio, Policy: &accept,
		})
		for _, r := range c.rules {
			f.conn.AddRule(&nftables.Rule{Table: table, Chain: chain, Exprs: r})
		}
	}
	if err := f.conn.Flush(); err != nil {
		return &OpError{Op: "nftables apply", Err: err}
	}
	f.applied = true
	return nil
}

// Remove deletes the table. A table that is already gone is not an error.
func (f *Filter) Remove(ctx context.Context) error {
	if err := ctx.Err(); err != nil {
		return &OpError{Op: "nftables remove", Err: err}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, err := f.conn.ListTableOfFamily(TableName, nftables.TableFamilyINet); err != nil {
		if errors.Is(err, unix.ENOENT) {
			f.applied = false
			return nil
		}
		return &OpError{Op: "nftables remove", Err: err}
	}
	f.conn.DelTable(f.table())
	if err := f.conn.Flush(); err != nil {
		return &OpError{Op: "nftables remove", Err: err}
	}
	f.applied = false
	return nil
}

// Drop implements Dropper: peer's packets are dropped on the fabric in
// both directions. A drop recorded before Apply is installed with the
// table.
func (f *Filter) Drop(ctx context.Context, peer netip.Addr) error {
	return f.setEvicted(ctx, peer, true)
}

// Undrop implements Dropper.
func (f *Filter) Undrop(ctx context.Context, peer netip.Addr) error {
	return f.setEvicted(ctx, peer, false)
}

func (f *Filter) setEvicted(ctx context.Context, peer netip.Addr, evict bool) error {
	if err := ctx.Err(); err != nil {
		return &OpError{Op: "nftables evicted set", Err: err}
	}
	peer = peer.Unmap()
	if !peer.IsValid() || peer.Is4() != f.local.Is4() {
		return &PeerError{Peer: peer, Op: "evicted set", Err: ErrFamilyMismatch}
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, present := f.evicted[peer]; present == evict {
		return nil
	}
	if f.applied {
		set := f.evictedSet(f.table())
		elems := f.elements([]netip.Addr{peer})
		var err error
		if evict {
			err = f.conn.SetAddElements(set, elems)
		} else {
			err = f.conn.SetDeleteElements(set, elems)
		}
		if err == nil {
			err = f.conn.Flush()
		}
		if err != nil {
			return &PeerError{Peer: peer, Op: "evicted set", Err: err}
		}
	}
	if evict {
		f.evicted[peer] = struct{}{}
	} else {
		delete(f.evicted, peer)
	}
	return nil
}

func (f *Filter) table() *nftables.Table {
	return &nftables.Table{Name: TableName, Family: nftables.TableFamilyINet}
}

func (f *Filter) evictedSet(table *nftables.Table) *nftables.Set {
	return &nftables.Set{Table: table, Name: setEvicted, KeyType: f.addrType()}
}

func (f *Filter) addrType() nftables.SetDatatype {
	if f.local.Is4() {
		return nftables.TypeIPAddr
	}
	return nftables.TypeIP6Addr
}

func (f *Filter) elements(addrs []netip.Addr) []nftables.SetElement {
	slices.SortFunc(addrs, netip.Addr.Compare)
	out := make([]nftables.SetElement, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, nftables.SetElement{Key: a.AsSlice()})
	}
	return out
}

// inputRules is the fabric_in chain. Register 1 carries every loaded
// value; the expressions of a rule are ANDed.
//
// An IKE packet is accepted only by a meter update that succeeds within
// the rate. Over the rate the limit fails to match, and with the meter full
// a new source cannot be added and the update fails: either way the packet
// falls through to the final drop, so a flood of sources cannot open the
// limiter.
func (f *Filter) inputRules(evicted, meter *nftables.Set) [][]expr.Any {
	rules := [][]expr.Any{join(f.ifname(expr.MetaKeyIIFNAME, expr.CmpOpNeq), verdict(expr.VerdictAccept))}
	rules = append(rules, f.linkRules()...)
	rules = append(rules,
		join(f.family(), f.addr(srcOffset), lookup(evicted), verdict(expr.VerdictDrop)),
		join(f.family(), l4proto(unix.IPPROTO_ESP), verdict(expr.VerdictAccept)),
	)
	for _, port := range []uint16{ikePort, ikeNATTPort} {
		rules = append(rules,
			join(f.family(), ikePorts(port), f.addr(srcOffset), f.withinRate(meter), verdict(expr.VerdictAccept)))
	}
	return append(rules,
		join(meta(metaKeySecpath, []byte{1}), verdict(expr.VerdictAccept)),
		verdict(expr.VerdictDrop),
	)
}

// forwardRules is the fabric_fwd chain: traffic routed through the node
// that enters or leaves by the fabric passes only as ESP or once an SA has
// decrypted it. Evicted peers are dropped either way.
func (f *Filter) forwardRules(evicted *nftables.Set) [][]expr.Any {
	return [][]expr.Any{
		join(f.ifname(expr.MetaKeyIIFNAME, expr.CmpOpNeq), f.ifname(expr.MetaKeyOIFNAME, expr.CmpOpNeq),
			verdict(expr.VerdictAccept)),
		join(f.family(), f.addr(srcOffset), lookup(evicted), verdict(expr.VerdictDrop)),
		join(f.family(), f.addr(dstOffset), lookup(evicted), verdict(expr.VerdictDrop)),
		join(f.family(), l4proto(unix.IPPROTO_ESP), verdict(expr.VerdictAccept)),
		join(meta(metaKeySecpath, []byte{1}), verdict(expr.VerdictAccept)),
		verdict(expr.VerdictDrop),
	}
}

// outputRules is the fabric_out chain.
func (f *Filter) outputRules(evicted *nftables.Set) [][]expr.Any {
	rules := [][]expr.Any{join(f.ifname(expr.MetaKeyOIFNAME, expr.CmpOpNeq), verdict(expr.VerdictAccept))}
	rules = append(rules, f.linkRules()...)
	return append(rules,
		join(f.family(), f.addr(dstOffset), lookup(evicted), verdict(expr.VerdictDrop)),
		join(f.family(), l4proto(unix.IPPROTO_ESP), verdict(expr.VerdictAccept)),
		join(f.family(), ikePorts(ikePort), verdict(expr.VerdictAccept)),
		join(f.family(), ikePorts(ikeNATTPort), verdict(expr.VerdictAccept)),
		join([]expr.Any{
			&expr.Rt{Register: 1, Key: rtKeyXFRM},
			&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{1}},
		}, verdict(expr.VerdictAccept)),
		verdict(expr.VerdictDrop),
	)
}

func join(parts ...[]expr.Any) []expr.Any {
	return slices.Concat(parts...)
}

func verdict(kind expr.VerdictKind) []expr.Any {
	return []expr.Any{&expr.Verdict{Kind: kind}}
}

func meta(key expr.MetaKey, want []byte) []expr.Any {
	return []expr.Any{
		&expr.Meta{Key: key, Register: 1},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: want},
	}
}

func (f *Filter) ifname(key expr.MetaKey, op expr.CmpOp) []expr.Any {
	data := make([]byte, unix.IFNAMSIZ)
	copy(data, f.iface)
	return []expr.Any{
		&expr.Meta{Key: key, Register: 1},
		&expr.Cmp{Op: op, Register: 1, Data: data},
	}
}

// family matches the local address family, the only one an SA can carry.
func (f *Filter) family() []expr.Any {
	proto := byte(unix.NFPROTO_IPV4)
	if f.local.Is6() {
		proto = unix.NFPROTO_IPV6
	}
	return meta(expr.MetaKeyNFPROTO, []byte{proto})
}

func l4proto(proto byte) []expr.Any {
	return meta(expr.MetaKeyL4PROTO, []byte{proto})
}

type addrField int

const (
	srcOffset addrField = iota
	dstOffset
)

// addr loads the source or destination address into register 1.
func (f *Filter) addr(field addrField) []expr.Any {
	offset, length := uint32(12), uint32(4)
	if f.local.Is6() {
		offset, length = 8, 16
	}
	if field == dstOffset {
		offset += length
	}
	return []expr.Any{&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseNetworkHeader, Offset: offset, Len: length}}
}

func lookup(set *nftables.Set) []expr.Any {
	return []expr.Any{&expr.Lookup{SourceRegister: 1, SetName: set.Name, SetID: set.ID}}
}

// withinRate matches when the source in register 1 has sent IKE within the
// configured rate. It fails when the source is over the rate, and when the
// meter is full and cannot take the source.
func (f *Filter) withinRate(meter *nftables.Set) []expr.Any {
	return []expr.Any{&expr.Dynset{
		SrcRegKey: 1,
		SetName:   meter.Name,
		SetID:     meter.ID,
		Operation: uint32(unix.NFT_DYNSET_OP_UPDATE),
		Timeout:   ikeMeterTimeout,
		Exprs: []expr.Any{&expr.Limit{
			Type: expr.LimitTypePkts, Rate: uint64(f.rate), Unit: expr.LimitTimeSecond,
			Burst: f.burst,
		}},
	}}
}

// ikePorts matches UDP from port to port: charon talks to charon, so IKE
// on the fabric never uses any other pair.
func ikePorts(port uint16) []expr.Any {
	ports := make([]byte, 4)
	binary.BigEndian.PutUint16(ports[0:2], port)
	binary.BigEndian.PutUint16(ports[2:4], port)
	return join(l4proto(unix.IPPROTO_UDP), []expr.Any{
		&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 4},
		&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: ports},
	})
}

// linkICMPv6 is the ICMPv6 the link needs before any SA exists: neighbour
// solicitation and advertisement, and MLD, which multicast snooping on the
// fabric switches relies on. Router solicitation and advertisement are added
// only for an underlay addressed by SLAAC. Redirects are never exempt: an
// unauthenticated redirect could steer the underlay.
func linkICMPv6(slaac bool) []uint8 {
	types := []uint8{icmpv6MLDQuery, icmpv6MLDReport, icmpv6MLDDone, icmpv6NeighSol, icmpv6NeighAdv, icmpv6MLDv2Report}
	if slaac {
		types = append(types, icmpv6RouterSol, icmpv6RouterAdv)
	}
	return types
}

// linkRules accepts the linkICMPv6 types, one rule each.
func (f *Filter) linkRules() [][]expr.Any {
	types := linkICMPv6(f.slaac)
	rules := make([][]expr.Any, 0, len(types))
	for _, typ := range types {
		rules = append(rules, join(
			meta(expr.MetaKeyNFPROTO, []byte{unix.NFPROTO_IPV6}),
			l4proto(unix.IPPROTO_ICMPV6),
			[]expr.Any{
				&expr.Payload{DestRegister: 1, Base: expr.PayloadBaseTransportHeader, Offset: 0, Len: 1},
				&expr.Cmp{Op: expr.CmpOpEq, Register: 1, Data: []byte{typ}},
			},
			verdict(expr.VerdictAccept),
		))
	}
	return rules
}
