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
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"net/netip"
	"testing"

	"github.com/google/nftables"
	"github.com/google/nftables/expr"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipsec/config"
	"golang.org/x/sys/unix"
)

// fakeNFT stands in for nf_tables: operations queue until Flush commits
// them all, or a failing Flush discards them all, as the kernel's batch
// transaction does.
type fakeNFT struct {
	pending  []func()
	present  bool
	sets     map[string]*fakeSet
	chains   map[string]*nftables.Chain
	rules    map[string][][]expr.Any
	flushErr error
	listErr  error
	flushes  int
}

type fakeSet struct {
	set   *nftables.Set
	elems map[string]struct{}
}

func newFakeNFT() *fakeNFT {
	n := &fakeNFT{}
	n.reset()
	return n
}

func (n *fakeNFT) reset() {
	n.sets = make(map[string]*fakeSet)
	n.chains = make(map[string]*nftables.Chain)
	n.rules = make(map[string][][]expr.Any)
}

func (n *fakeNFT) AddTable(t *nftables.Table) *nftables.Table {
	n.pending = append(n.pending, func() { n.present = true })
	return t
}

func (n *fakeNFT) DelTable(*nftables.Table) {
	n.pending = append(n.pending, func() { n.present = false; n.reset() })
}

func (n *fakeNFT) AddSet(s *nftables.Set, vals []nftables.SetElement) error {
	n.pending = append(n.pending, func() {
		fs := &fakeSet{set: s, elems: make(map[string]struct{})}
		for _, v := range vals {
			fs.elems[string(v.Key)] = struct{}{}
		}
		n.sets[s.Name] = fs
	})
	return nil
}

func (n *fakeNFT) SetAddElements(s *nftables.Set, vals []nftables.SetElement) error {
	n.pending = append(n.pending, func() {
		for _, v := range vals {
			n.sets[s.Name].elems[string(v.Key)] = struct{}{}
		}
	})
	return nil
}

func (n *fakeNFT) SetDeleteElements(s *nftables.Set, vals []nftables.SetElement) error {
	n.pending = append(n.pending, func() {
		for _, v := range vals {
			delete(n.sets[s.Name].elems, string(v.Key))
		}
	})
	return nil
}

func (n *fakeNFT) AddChain(c *nftables.Chain) *nftables.Chain {
	n.pending = append(n.pending, func() { n.chains[c.Name] = c })
	return c
}

func (n *fakeNFT) AddRule(r *nftables.Rule) *nftables.Rule {
	n.pending = append(n.pending, func() { n.rules[r.Chain.Name] = append(n.rules[r.Chain.Name], r.Exprs) })
	return r
}

func (n *fakeNFT) ListTableOfFamily(string, nftables.TableFamily) (*nftables.Table, error) {
	if n.listErr != nil {
		return nil, n.listErr
	}
	if !n.present {
		return nil, unix.ENOENT
	}
	return &nftables.Table{Name: TableName, Family: nftables.TableFamilyINet}, nil
}

func (n *fakeNFT) Flush() error {
	pending := n.pending
	n.pending = nil
	n.flushes++
	if n.flushErr != nil {
		return n.flushErr
	}
	for _, op := range pending {
		op()
	}
	return nil
}

// packet is what the evaluator needs of a packet.
type packet struct {
	iif, oif     string
	src, dst     netip.Addr
	l4           byte
	sport, dport uint16
	icmpType     byte
	secpath      bool // decrypted by an SA
	xfrm         bool // routed into an SA
}

// verdict runs p through chain the way nf_tables does: register 1 holds
// loaded values, a failed match ends the rule, and the chain policy
// (accept) applies when no rule decides. Dynamic-set meters count packets
// per key against the burst.
func (n *fakeNFT) verdict(t *testing.T, chain string, p packet, meters map[string]int) expr.VerdictKind {
	t.Helper()
	for _, rule := range n.rules[chain] {
		if kind, decided := n.evalRule(t, rule, p, meters); decided {
			return kind
		}
	}
	return expr.VerdictAccept
}

func (n *fakeNFT) evalRule(t *testing.T, rule []expr.Any, p packet, meters map[string]int) (expr.VerdictKind, bool) {
	t.Helper()
	var reg []byte
	for _, e := range rule {
		switch e := e.(type) {
		case *expr.Meta:
			reg = p.meta(t, e.Key)
		case *expr.Rt:
			reg = []byte{boolByte(p.xfrm)}
		case *expr.Payload:
			reg = p.payload(e)
		case *expr.Cmp:
			if bytes.Equal(reg, e.Data) != (e.Op == expr.CmpOpEq) {
				return 0, false
			}
		case *expr.Range:
			if bytes.Compare(reg, e.FromData) < 0 || bytes.Compare(reg, e.ToData) > 0 {
				return 0, false
			}
		case *expr.Lookup:
			if _, ok := n.sets[e.SetName].elems[string(reg)]; !ok {
				return 0, false
			}
		case *expr.Dynset:
			// The update fails, ending the rule, when the set is full and
			// cannot take a new key; the limit fails it over the burst.
			meter, declared := n.sets[e.SetName]
			if !declared || len(e.Exprs) != 1 {
				t.Fatalf("meter %q is not declared or has no single limit", e.SetName)
			}
			limit, ok := e.Exprs[0].(*expr.Limit)
			if !ok || limit.Over {
				t.Fatalf("meter %q does not match within the rate", e.SetName)
			}
			key := string(reg)
			if _, tracked := meters[key]; !tracked && len(meters) >= int(meter.set.Size) {
				return 0, false
			}
			meters[key]++
			if meters[key] > int(limit.Burst) {
				return 0, false
			}
		case *expr.Verdict:
			return e.Kind, true
		default:
			t.Fatalf("evaluator does not know %T", e)
		}
	}
	return 0, false
}

func (p packet) meta(t *testing.T, key expr.MetaKey) []byte {
	t.Helper()
	switch key {
	case expr.MetaKeyIIFNAME, expr.MetaKeyOIFNAME:
		name := p.iif
		if key == expr.MetaKeyOIFNAME {
			name = p.oif
		}
		data := make([]byte, unix.IFNAMSIZ)
		copy(data, name)
		return data
	case expr.MetaKeyNFPROTO:
		if p.src.Is4() {
			return []byte{unix.NFPROTO_IPV4}
		}
		return []byte{unix.NFPROTO_IPV6}
	case expr.MetaKeyL4PROTO:
		return []byte{p.l4}
	case metaKeySecpath:
		return []byte{boolByte(p.secpath)}
	}
	t.Fatalf("evaluator does not know meta key %d", key)
	return nil
}

func (p packet) payload(e *expr.Payload) []byte {
	var hdr []byte
	if e.Base == expr.PayloadBaseNetworkHeader {
		if p.src.Is4() {
			hdr = make([]byte, 20)
			copy(hdr[12:], p.src.AsSlice())
			copy(hdr[16:], p.dst.AsSlice())
		} else {
			hdr = make([]byte, 40)
			copy(hdr[8:], p.src.AsSlice())
			copy(hdr[24:], p.dst.AsSlice())
		}
	} else {
		hdr = make([]byte, 8)
		if p.l4 == unix.IPPROTO_ICMPV6 {
			hdr[0] = p.icmpType
		} else {
			binary.BigEndian.PutUint16(hdr[0:], p.sport)
			binary.BigEndian.PutUint16(hdr[2:], p.dport)
		}
	}
	return hdr[e.Offset : e.Offset+e.Len]
}

func boolByte(b bool) byte {
	if b {
		return 1
	}
	return 0
}

func newTestFilter(t *testing.T, cfg *config.Config) (*Filter, *fakeNFT) {
	t.Helper()
	conn := newFakeNFT()
	f, err := newFilter(cfg, conn)
	if err != nil {
		t.Fatalf("newFilter: %v", err)
	}
	return f, conn
}

func appliedFilter(t *testing.T, cfg *config.Config) (*Filter, *fakeNFT) {
	t.Helper()
	f, conn := newTestFilter(t, cfg)
	if err := f.Apply(context.Background()); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	return f, conn
}

const (
	local4 = "10.20.0.11"
	peer4  = "10.20.0.30"
)

func udp(src, dst string, sport, dport uint16) packet {
	return packet{src: addr(src), dst: addr(dst), l4: unix.IPPROTO_UDP, sport: sport, dport: dport}
}

func tcp(src, dst string, sport, dport uint16) packet {
	return packet{src: addr(src), dst: addr(dst), l4: unix.IPPROTO_TCP, sport: sport, dport: dport}
}

func esp(src, dst string) packet {
	return packet{src: addr(src), dst: addr(dst), l4: unix.IPPROTO_ESP}
}

func (p packet) on(iif string) packet  { p.iif = iif; return p }
func (p packet) out(oif string) packet { p.oif = oif; return p }
func (p packet) decrypted() packet     { p.secpath = true; return p }
func (p packet) encrypted() packet     { p.xfrm = true; return p }

// TestFilterFailsClosed is the fail-closed contract with charon stopped:
// no SA exists, so nothing is decrypted or routed into an SA, and only
// ESP and IKE cross the fabric.
func TestFilterFailsClosed(t *testing.T) {
	_, conn := appliedFilter(t, validConfig())
	accept, drop := expr.VerdictAccept, expr.VerdictDrop

	inbound := []struct {
		name string
		p    packet
		want expr.VerdictKind
	}{
		{"cleartext VXLAN", udp(peer4, local4, 49152, 4789).on("bond0"), drop},
		{"cleartext BGP", tcp(peer4, local4, 40000, 179).on("bond0"), drop},
		{"ESP", esp(peer4, local4).on("bond0"), accept},
		{"IKE", udp(peer4, local4, 500, 500).on("bond0"), accept},
		{"IKE NAT-T port", udp(peer4, local4, 4500, 4500).on("bond0"), accept},
		{"UDP 500 from another port", udp(peer4, local4, 40000, 500).on("bond0"), drop},
		{"VXLAN an SA decrypted", udp(peer4, local4, 49152, 4789).on("bond0").decrypted(), accept},
		{"cleartext on another interface", udp(peer4, local4, 49152, 4789).on("eth9"), accept},
	}
	for _, tt := range inbound {
		t.Run("in/"+tt.name, func(t *testing.T) {
			if got := conn.verdict(t, chainInput, tt.p, map[string]int{}); got != tt.want {
				t.Fatalf("verdict = %v, want %v", got, tt.want)
			}
		})
	}

	outbound := []struct {
		name string
		p    packet
		want expr.VerdictKind
	}{
		{"cleartext VXLAN", udp(local4, peer4, 49152, 4789).out("bond0"), drop},
		{"cleartext BGP", tcp(local4, peer4, 179, 40000).out("bond0"), drop},
		{"VXLAN routed into an SA", udp(local4, peer4, 49152, 4789).out("bond0").encrypted(), accept},
		{"ESP", esp(local4, peer4).out("bond0"), accept},
		{"IKE", udp(local4, peer4, 500, 500).out("bond0"), accept},
		{"UDP to 4500 from an unprivileged port", udp(local4, peer4, 40000, 4500).out("bond0"), drop},
		{"cleartext on another interface", udp(local4, peer4, 49152, 4789).out("eth9"), accept},
	}
	for _, tt := range outbound {
		t.Run("out/"+tt.name, func(t *testing.T) {
			if got := conn.verdict(t, chainOutput, tt.p, map[string]int{}); got != tt.want {
				t.Fatalf("verdict = %v, want %v", got, tt.want)
			}
		})
	}

	forwarded := []struct {
		name string
		p    packet
		want expr.VerdictKind
	}{
		{"cleartext VXLAN from the fabric", udp(peer4, "10.30.0.5", 49152, 4789).on("bond0").out("eth9"), drop},
		{"cleartext VXLAN into the fabric", udp("10.30.0.5", peer4, 49152, 4789).on("eth9").out("bond0"), drop},
		{"cleartext BGP across the fabric", tcp(peer4, "10.20.0.31", 40000, 179).on("bond0").out("bond0"), drop},
		{"IKE is not routed", udp(peer4, "10.30.0.5", 500, 500).on("bond0").out("eth9"), drop},
		// The VTEP's own ESP is local; ESP routed through the node is another
		// tunnel, which the XFRM forward block drops out of the fabric too.
		{"ESP is not routed from the fabric", esp(peer4, "10.30.0.5").on("bond0").out("eth9"), drop},
		{"ESP is not routed into the fabric", esp("10.30.0.5", peer4).on("eth9").out("bond0"), drop},
		{"traffic an SA decrypted", udp(peer4, "10.30.0.5", 49152, 4789).on("bond0").out("eth9").decrypted(), accept},
		{"between other interfaces", udp("10.30.0.5", "10.40.0.5", 49152, 4789).on("eth9").out("eth8"), accept},
	}
	for _, tt := range forwarded {
		t.Run("fwd/"+tt.name, func(t *testing.T) {
			if got := conn.verdict(t, chainForward, tt.p, map[string]int{}); got != tt.want {
				t.Fatalf("verdict = %v, want %v", got, tt.want)
			}
		})
	}
}

func icmpv6(typ byte) packet {
	return packet{src: addr("fe80::1"), dst: addr("ff02::1"), l4: unix.IPPROTO_ICMPV6, icmpType: typ}
}

// TestFilterLinkICMPv6 is the ICMPv6 the fabric passes without an SA:
// neighbour discovery and MLD, router discovery only for a SLAAC underlay,
// and never a redirect.
func TestFilterLinkICMPv6(t *testing.T) {
	accept, drop := expr.VerdictAccept, expr.VerdictDrop
	tests := []struct {
		name          string
		typ           byte
		want, slaacOn expr.VerdictKind
	}{
		{"MLD query", 130, accept, accept},
		{"MLD report", 131, accept, accept},
		{"MLD done", 132, accept, accept},
		{"MLDv2 report", 143, accept, accept},
		{"neighbour solicitation", 135, accept, accept},
		{"neighbour advertisement", 136, accept, accept},
		{"router solicitation", 133, drop, accept},
		{"router advertisement", 134, drop, accept},
		{"redirect", 137, drop, drop},
		{"echo request", 128, drop, drop},
	}
	slaac := validConfig()
	slaac.UnderlaySLAAC = true
	_, plain := appliedFilter(t, validConfig())
	_, withSLAAC := appliedFilter(t, slaac)
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for chain, p := range map[string]packet{
				chainInput:  icmpv6(tt.typ).on("bond0"),
				chainOutput: icmpv6(tt.typ).out("bond0"),
			} {
				if got := plain.verdict(t, chain, p, map[string]int{}); got != tt.want {
					t.Errorf("%s: verdict = %v, want %v", chain, got, tt.want)
				}
				if got := withSLAAC.verdict(t, chain, p, map[string]int{}); got != tt.slaacOn {
					t.Errorf("%s with underlay-slaac: verdict = %v, want %v", chain, got, tt.slaacOn)
				}
			}
		})
	}
}

func TestLinkICMPv6(t *testing.T) {
	plain, slaac := linkICMPv6(false), linkICMPv6(true)
	for _, typ := range []uint8{icmpv6RouterSol, icmpv6RouterAdv} {
		if bytes.IndexByte(plain, typ) >= 0 {
			t.Errorf("router discovery type %d exempt without SLAAC", typ)
		}
		if bytes.IndexByte(slaac, typ) < 0 {
			t.Errorf("router discovery type %d not exempt with SLAAC", typ)
		}
	}
	for _, list := range [][]uint8{plain, slaac} {
		if bytes.IndexByte(list, 137) >= 0 {
			t.Error("redirect is exempt")
		}
		if bytes.IndexByte(list, icmpv6NeighSol) < 0 || bytes.IndexByte(list, icmpv6MLDv2Report) < 0 {
			t.Errorf("%v lacks neighbour solicitation or MLDv2", list)
		}
	}
}

func TestFilterIPv6Underlay(t *testing.T) {
	cfg := validConfig()
	cfg.LocalAddress = "fd00:20::11"
	cfg.StaticPeers = []string{"fd00:20::1"}
	f, conn := appliedFilter(t, cfg)

	if got := conn.verdict(t, chainInput, esp("fd00:20::30", "fd00:20::11").on("bond0"), map[string]int{}); got != expr.VerdictAccept {
		t.Fatalf("IPv6 ESP: %v", got)
	}
	if got := conn.verdict(t, chainInput, esp(peer4, local4).on("bond0"), map[string]int{}); got != expr.VerdictDrop {
		t.Fatalf("IPv4 ESP on an IPv6 underlay: %v", got)
	}
	if err := f.Drop(context.Background(), addr("fd00:20::30")); err != nil {
		t.Fatalf("Drop: %v", err)
	}
	if got := conn.verdict(t, chainOutput, esp("fd00:20::11", "fd00:20::30").out("bond0"), map[string]int{}); got != expr.VerdictDrop {
		t.Fatalf("ESP to an evicted IPv6 peer: %v", got)
	}
}

func TestFilterIKERateLimit(t *testing.T) {
	cfg := validConfig()
	cfg.IKERate, cfg.IKEBurst = 5, 8
	_, conn := appliedFilter(t, cfg)

	meters := map[string]int{}
	ike := udp(peer4, local4, 500, 500).on("bond0")
	for i := range 8 {
		if got := conn.verdict(t, chainInput, ike, meters); got != expr.VerdictAccept {
			t.Fatalf("packet %d within the burst: %v", i, got)
		}
	}
	if got := conn.verdict(t, chainInput, ike, meters); got != expr.VerdictDrop {
		t.Fatalf("packet past the burst: %v", got)
	}
	other := udp("10.20.0.31", local4, 4500, 4500).on("bond0")
	if got := conn.verdict(t, chainInput, other, meters); got != expr.VerdictAccept {
		t.Fatalf("another source was limited by the first one's rate: %v", got)
	}
}

// TestFilterIKERateLimitFullMeter floods the meter with sources: once it
// is full, a new source's IKE is dropped rather than passed unmetered.
func TestFilterIKERateLimitFullMeter(t *testing.T) {
	_, conn := appliedFilter(t, validConfig())
	meters := make(map[string]int, ikeMeterSize)
	known := addr(peer4).AsSlice()
	meters[string(known)] = 0
	for i := 1; len(meters) < ikeMeterSize; i++ {
		key := []byte{10, 99, byte(i >> 8), byte(i)}
		meters[string(key)] = 0
	}

	if got := conn.verdict(t, chainInput, udp("10.20.0.31", local4, 500, 500).on("bond0"), meters); got != expr.VerdictDrop {
		t.Fatalf("IKE from a new source with the meter full: %v", got)
	}
	if got := conn.verdict(t, chainInput, udp(peer4, local4, 500, 500).on("bond0"), meters); got != expr.VerdictAccept {
		t.Fatalf("IKE from a metered source with the meter full: %v", got)
	}
}

func TestFilterEviction(t *testing.T) {
	ctx := context.Background()
	f, conn := newTestFilter(t, validConfig())
	peer := addr(peer4)

	// A drop recorded before the table exists is installed with it.
	if err := f.Drop(ctx, peer); err != nil {
		t.Fatalf("Drop before Apply: %v", err)
	}
	if conn.flushes != 0 {
		t.Fatal("Drop before Apply touched the kernel")
	}
	if err := f.Apply(ctx); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	for _, p := range []packet{
		esp(peer4, local4).on("bond0"),
		udp(peer4, local4, 500, 500).on("bond0"),
		udp(peer4, local4, 49152, 4789).on("bond0").decrypted(),
	} {
		if got := conn.verdict(t, chainInput, p, map[string]int{}); got != expr.VerdictDrop {
			t.Fatalf("%+v from an evicted peer: %v", p, got)
		}
	}
	if got := conn.verdict(t, chainOutput, udp(local4, peer4, 500, 500).out("bond0"), map[string]int{}); got != expr.VerdictDrop {
		t.Fatalf("IKE to an evicted peer: %v", got)
	}
	for _, p := range []packet{
		udp(peer4, "10.30.0.5", 49152, 4789).on("bond0").out("eth9").decrypted(),
		udp("10.30.0.5", peer4, 49152, 4789).on("eth9").out("bond0").decrypted(),
	} {
		if got := conn.verdict(t, chainForward, p, map[string]int{}); got != expr.VerdictDrop {
			t.Fatalf("%+v routed to or from an evicted peer: %v", p, got)
		}
	}

	if err := f.Undrop(ctx, peer); err != nil {
		t.Fatalf("Undrop: %v", err)
	}
	if got := conn.verdict(t, chainInput, esp(peer4, local4).on("bond0"), map[string]int{}); got != expr.VerdictAccept {
		t.Fatalf("ESP after Undrop: %v", got)
	}

	// Repeats change nothing in the kernel.
	flushes := conn.flushes
	if err := f.Undrop(ctx, peer); err != nil {
		t.Fatalf("Undrop again: %v", err)
	}
	if err := f.Drop(ctx, peer); err != nil {
		t.Fatalf("Drop: %v", err)
	}
	if err := f.Drop(ctx, peer); err != nil {
		t.Fatalf("Drop again: %v", err)
	}
	if conn.flushes != flushes+1 {
		t.Fatalf("flushes = %d, want one for the one real change", conn.flushes-flushes)
	}

	// Apply carries the drop over into the replacement table.
	if err := f.Apply(ctx); err != nil {
		t.Fatalf("re-Apply: %v", err)
	}
	if got := conn.verdict(t, chainInput, esp(peer4, local4).on("bond0"), map[string]int{}); got != expr.VerdictDrop {
		t.Fatalf("ESP after re-Apply: %v", got)
	}
}

func TestFilterEvictionFailures(t *testing.T) {
	ctx := context.Background()
	f, conn := appliedFilter(t, validConfig())

	var peerErr *PeerError
	if err := f.Drop(ctx, addr("fd00::30")); !errors.As(err, &peerErr) || !errors.Is(err, config.ErrFamilyMismatch) {
		t.Fatalf("Drop of the other family: err = %v", err)
	}
	conn.flushErr = errInjected
	if err := f.Drop(ctx, addr(peer4)); !errors.As(err, &peerErr) || !errors.Is(err, errInjected) {
		t.Fatalf("Drop with a failing kernel: err = %v", err)
	}
	conn.flushErr = nil
	// The failed drop was not recorded, so a retry reaches the kernel.
	if err := f.Drop(ctx, addr(peer4)); err != nil {
		t.Fatalf("Drop retry: %v", err)
	}
	if got := conn.verdict(t, chainInput, esp(peer4, local4).on("bond0"), map[string]int{}); got != expr.VerdictDrop {
		t.Fatalf("ESP after the retried drop: %v", got)
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	var opErr *OpError
	if err := f.Undrop(cancelled, addr(peer4)); !errors.As(err, &opErr) || !errors.Is(err, context.Canceled) {
		t.Fatalf("Undrop with a cancelled context: err = %v", err)
	}
}

func TestFilterApplyIsAReplacement(t *testing.T) {
	ctx := context.Background()
	f, conn := appliedFilter(t, validConfig())
	rules := len(conn.rules[chainInput])
	if err := f.Apply(ctx); err != nil {
		t.Fatalf("second Apply: %v", err)
	}
	if got := len(conn.rules[chainInput]); got != rules {
		t.Fatalf("input chain has %d rules after a second Apply, want %d", got, rules)
	}
	in, fwd, out := conn.chains[chainInput], conn.chains[chainForward], conn.chains[chainOutput]
	if in.Hooknum != nftables.ChainHookInput || fwd.Hooknum != nftables.ChainHookForward ||
		out.Hooknum != nftables.ChainHookOutput {
		t.Fatal("chains are not on the input, forward and output hooks")
	}
	if *in.Priority != nftables.ChainPriority(filterPriority) || *in.Policy != nftables.ChainPolicyAccept {
		t.Fatalf("input chain priority %d policy %d", *in.Priority, *in.Policy)
	}

	// A failed Apply leaves the table that was there.
	conn.flushErr = errInjected
	var opErr *OpError
	if err := f.Apply(ctx); !errors.As(err, &opErr) || !errors.Is(err, errInjected) {
		t.Fatalf("Apply with a failing kernel: err = %v", err)
	}
	if !conn.present || len(conn.rules[chainInput]) != rules {
		t.Fatal("a failed Apply disturbed the installed table")
	}

	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := f.Apply(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("Apply with a cancelled context: err = %v", err)
	}
}

func TestFilterRemove(t *testing.T) {
	ctx := context.Background()
	f, conn := appliedFilter(t, validConfig())
	if err := f.Remove(ctx); err != nil {
		t.Fatalf("Remove: %v", err)
	}
	if conn.present {
		t.Fatal("table still present")
	}
	if err := f.Remove(ctx); err != nil {
		t.Fatalf("Remove of an absent table: %v", err)
	}
	// With the table gone a drop is only recorded, not sent.
	flushes := conn.flushes
	if err := f.Drop(ctx, addr(peer4)); err != nil || conn.flushes != flushes {
		t.Fatalf("Drop after Remove: err = %v, flushes %d", err, conn.flushes-flushes)
	}

	var opErr *OpError
	conn.listErr = errInjected
	if err := f.Remove(ctx); !errors.As(err, &opErr) || !errors.Is(err, errInjected) {
		t.Fatalf("Remove with a failing list: err = %v", err)
	}
	conn.listErr = nil
	if err := f.Apply(ctx); err != nil {
		t.Fatalf("Apply: %v", err)
	}
	conn.flushErr = errInjected
	if err := f.Remove(ctx); !errors.As(err, &opErr) || !errors.Is(err, errInjected) {
		t.Fatalf("Remove with a failing flush: err = %v", err)
	}
	cancelled, cancel := context.WithCancel(ctx)
	cancel()
	if err := f.Remove(cancelled); !errors.Is(err, context.Canceled) {
		t.Fatalf("Remove with a cancelled context: err = %v", err)
	}
}

func TestNewFilterRejects(t *testing.T) {
	invalid := validConfig()
	invalid.FabricInterface = ""
	for _, tt := range []struct {
		name string
		cfg  *config.Config
		want error
	}{
		{"absent", nil, config.ErrNotEnabled},
		{"disabled", &config.Config{}, config.ErrNotEnabled},
		{"invalid", invalid, config.ErrRequired},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := newFilter(tt.cfg, newFakeNFT()); !errors.Is(err, tt.want) {
				t.Fatalf("err = %v, want %v", err, tt.want)
			}
		})
	}
}

// TestUnnamedKernelKeys pins the two keys the libraries do not name to
// their neighbours in nf_tables.h, which they do.
func TestUnnamedKernelKeys(t *testing.T) {
	if metaKeySecpath != expr.MetaKey(unix.NFT_META_PRANDOM)+1 {
		t.Errorf("NFT_META_SECPATH = %d, want NFT_META_PRANDOM+1", metaKeySecpath)
	}
	if rtKeyXFRM != expr.RtKey(unix.NFT_RT_TCPMSS)+1 {
		t.Errorf("NFT_RT_XFRM = %d, want NFT_RT_TCPMSS+1", rtKeyXFRM)
	}
}
