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

package firewall

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/modes"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
)

// NAT pipeline priorities. Diversion flows live in table 20 between the
// firewall's per-zone ct gates (priority 100) and its non-IP bypass
// (priority 1); commit flows live in table 25.
const (
	// prioDNATDivert diverts uplink traffic addressed to a DNAT binding
	// into the NAT conntrack zone. It outranks the firewall zone gates so
	// inbound public traffic is translated before zone policy applies.
	prioDNATDivert = 200

	// prioSNATDivert diverts egress traffic from the internal prefix into
	// the NAT conntrack zone when no firewall zone gate claimed it.
	prioSNATDivert = 90

	// prioNATInvalid drops invalid tracked connections in table 25.
	prioNATInvalid = 400

	// prioNATEstRel fast-paths established/related connections in table 25
	// (NAT is applied automatically to tracked connections).
	prioNATEstRel = 300

	// prioNATCommitDNAT commits new DNAT connections.
	prioNATCommitDNAT = 200

	// prioNATCommitSNAT commits new SNAT connections.
	prioNATCommitSNAT = 100

	// prioNATMiss continues the pipeline for table 25 misses.
	prioNATMiss = 0

	// prioSNATSelect outranks the default SNAT divert: an uplink's
	// destination prefix picks that uplink's pool (#586).
	prioSNATSelect = 95

	// prioStaticDivert diverts a static translation's inside address on
	// egress and its outside address on ingress; it outranks pool SNAT so a
	// 1:1 host never falls into the pool.
	prioStaticDivert = 210

	// prioHairpinDivert diverts an internal client addressing a static
	// external address; it outranks the uplink-ingress divert because the
	// match is stricter (source prefix plus destination).
	prioHairpinDivert = 220

	// prioNATCommitStatic commits static translations, above pool SNAT
	// and DNAT commits.
	prioNATCommitStatic = 250

	// prioNATCommitHairpin commits hairpin translations.
	prioNATCommitHairpin = 260

	// prioIPv6Pass passes IPv6 through the NAT gate untranslated: the
	// service is NAT44 only, and a v6 frame must never be dropped for
	// lacking a translation (#586).
	prioIPv6Pass = 80
)

// Allocator owner/key for the NAT conntrack zone.
const (
	// AllocatorOwnerNAT is the ct.ZoneAllocator owner name for NAT.
	AllocatorOwnerNAT = "nat"

	// natZoneKey is the allocator key for the single NAT conntrack zone.
	natZoneKey = "default"
)

// IP protocol numbers for DNAT match strings.
const (
	protoTCP = 6
	protoUDP = 17
)

// natProtocols maps DNAT protocol names to IP protocol numbers (map-based
// dispatch keeps the lookup O(1) and the validation in one place).
var natProtocols = map[string]uint8{
	"tcp": protoTCP,
	"udp": protoUDP,
}

// dnatKey identifies a DNAT binding.
type dnatKey struct {
	proto    string
	external netip.AddrPort
}

// dnatBinding is one installed port-forward: its target and the flows
// that implement it.
type dnatBinding struct {
	internal netip.AddrPort
	rules    []zoneflows.FlowRule
}

// DNATRule is one installed port-forward as reported to callers that
// reconcile the NAT state (#555).
type DNATRule struct {
	Protocol string
	External netip.AddrPort
	Internal netip.AddrPort
}

// NATHealth is a point-in-time snapshot of the NAT service state.
type NATHealth struct {
	// Active reports whether the service is started.
	Active bool

	// SNATEnabled reports whether source NAT is installed.
	SNATEnabled bool

	// DNATRules is the number of installed DNAT bindings.
	DNATRules int

	// CTZone is the conntrack zone carrying NAT state.
	CTZone uint16

	// Uplinks reports each configured SNAT pool. Empty in single-address
	// mode. OVS exposes no per-pool exhaustion counter — see the
	// PoolExhaustion field doc — so the entries describe configuration,
	// not utilisation.
	Uplinks []NATUplinkHealth
}

// NATUplinkHealth describes one uplink's translation resources.
type NATUplinkHealth struct {
	// Name is the uplink name.
	Name string

	// Default reports whether this uplink carries unclaimed destinations.
	Default bool

	// PoolAddresses is the number of IPv4 addresses across the pools.
	PoolAddresses int

	// Ports is the number of L4 ports per pool address.
	Ports int

	// Static is the number of 1:1 translations bound to this uplink.
	Static int

	// PoolExhaustion is always false: the OVS conntrack NAT datapath does
	// not expose a per-range allocation counter (ovs-dpctl ct-stats counts
	// entries, not free ports), so exhaustion is observable only as new
	// connections failing to commit. Recorded here so the gap is explicit.
	PoolExhaustion bool
}

// NAT is the OVS-native NAT gateway. All translation happens in the OVS
// datapath via ct(nat(...)) commits in table 25; this type only manages the
// flows. It shares Deps with the firewall Service but owns a distinct
// cookie, gate priority, and conntrack zone, so both services start and
// stop independently.
type NAT struct {
	deps     Deps
	cfg      NATConfig
	cookie   string
	external netip.Addr
	internal netip.Prefix

	// plan is the validated multi-uplink configuration, nil in
	// single-address mode.
	plan *natPlan

	mu           sync.Mutex
	active       bool
	ctZone       uint16
	uplinkOFPort int32
	// uplinkPorts caches the OpenFlow port of each named uplink port.
	uplinkPorts map[string]int32
	snatRules   []zoneflows.FlowRule
	snatPrefix  netip.Prefix
	staticRules []zoneflows.FlowRule
	dnats       map[dnatKey]dnatBinding
}

// NewNAT creates a NAT service, validating dependencies and configuration.
// The firewall Config carried inside deps is not used; NAT validates its
// own NATConfig.
func NewNAT(deps Deps, cfg NATConfig) (*NAT, error) {
	if deps.Controller == nil {
		return nil, ErrNilController
	}
	if deps.OVS == nil {
		return nil, ErrNilOVSClient
	}
	if deps.Allocator == nil {
		return nil, ErrNilAllocator
	}
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}

	external, internal, err := cfg.Validate()
	if err != nil {
		return nil, err
	}
	plan, err := cfg.plan()
	if err != nil {
		return nil, err
	}

	return &NAT{
		deps:        deps,
		cfg:         cfg,
		cookie:      fmt.Sprintf("0x%x", CookieNAT),
		external:    external,
		internal:    internal,
		plan:        plan,
		uplinkPorts: make(map[string]int32),
		dnats:       make(map[dnatKey]dnatBinding),
	}, nil
}

// stamp sets the NAT cookie on every rule and returns the slice.
func (n *NAT) stamp(rules []zoneflows.FlowRule) []zoneflows.FlowRule {
	for i := range rules {
		rules[i].Cookie = n.cookie
	}
	return rules
}

// baseRules returns the NAT gate and the table 25 scaffolding.
func (n *NAT) baseRules() []zoneflows.FlowRule {
	return n.stamp([]zoneflows.FlowRule{
		{
			Table:    gateTable,
			Priority: natGatePriority,
			Actions:  fmt.Sprintf("goto_table:%d", modes.TableCTGate),
		},
		{
			Table:    int(modes.TableNAT),
			Priority: prioNATInvalid,
			Match:    "ct_state=+inv+trk",
			Actions:  "drop",
		},
		{
			Table:    int(modes.TableNAT),
			Priority: prioNATEstRel,
			Match:    "ct_state=+est+trk",
			Actions:  fmt.Sprintf("goto_table:%d", modes.TableMACLearning),
		},
		{
			Table:    int(modes.TableNAT),
			Priority: prioNATEstRel,
			Match:    "ct_state=+rel+trk",
			Actions:  fmt.Sprintf("goto_table:%d", modes.TableMACLearning),
		},
		{
			Table:    int(modes.TableNAT),
			Priority: prioNATMiss,
			Actions:  fmt.Sprintf("goto_table:%d", modes.TableMACLearning),
		},
		// NAT44 only: IPv6 — including ICMPv6 neighbour discovery — passes
		// the NAT gate untranslated. NAT66/NPTv6 are out of scope by design.
		{
			Table:    int(modes.TableCTGate),
			Priority: prioIPv6Pass,
			Match:    "dl_type=0x86dd",
			Actions:  fmt.Sprintf("goto_table:%d", modes.TableMACLearning),
		},
	})
}

// snatFlowRules builds the SNAT diversion and commit flows for a prefix.
//
// Single-address mode (no uplinks) is the pre-#586 pair: one divert, one
// commit to ExternalIP. Multi-uplink mode carries the chosen uplink in
// reg0 (index+1, so zero means "unselected"): the default uplink's divert
// loads its selector at prioSNATDivert, every destination prefix another
// uplink claims loads that uplink's selector at prioSNATSelect, and table
// 25 commits each selector to its own pool. Registers survive the ct
// recirculation, which is what lets the table-25 commit see the choice.
func (n *NAT) snatFlowRules(internal netip.Prefix) []zoneflows.FlowRule {
	if n.plan == nil {
		return n.stamp([]zoneflows.FlowRule{
			{
				Table:    int(modes.TableCTGate),
				Priority: prioSNATDivert,
				Match:    fmt.Sprintf("dl_type=0x0800,nw_src=%s", internal),
				Actions:  fmt.Sprintf("ct(table=%d,zone=%d)", modes.TableNAT, n.ctZone),
			},
			{
				Table:    int(modes.TableNAT),
				Priority: prioNATCommitSNAT,
				Match:    fmt.Sprintf("ct_state=+new+trk,dl_type=0x0800,nw_src=%s", internal),
				Actions: fmt.Sprintf("ct(commit,zone=%d,nat(src=%s:%d-%d)),goto_table:%d",
					n.ctZone, n.external, n.cfg.PortRangeStart, n.cfg.PortRangeEnd, modes.TableMACLearning),
			},
		})
	}
	var rules []zoneflows.FlowRule
	for i, u := range n.plan.uplinks {
		selector := i + 1
		divert := fmt.Sprintf("load:%d->NXM_NX_REG0[],ct(table=%d,zone=%d)", selector, modes.TableNAT, n.ctZone)
		if u.isDefault {
			rules = append(rules, zoneflows.FlowRule{
				Table:    int(modes.TableCTGate),
				Priority: prioSNATDivert,
				Match:    fmt.Sprintf("dl_type=0x0800,nw_src=%s", internal),
				Actions:  divert,
			})
		}
		for _, dst := range u.destinations {
			rules = append(rules, zoneflows.FlowRule{
				Table:    int(modes.TableCTGate),
				Priority: prioSNATSelect,
				Match:    fmt.Sprintf("dl_type=0x0800,nw_src=%s,nw_dst=%s", internal, dst),
				Actions:  divert,
			})
		}
		// One commit per pool address range; OVS picks within the range.
		// Several ranges on one uplink are committed in configuration
		// order with the same priority: the first installed wins, so the
		// pool order is the preference order.
		for _, pool := range u.pools {
			rules = append(rules, zoneflows.FlowRule{
				Table:    int(modes.TableNAT),
				Priority: prioNATCommitSNAT,
				Match:    fmt.Sprintf("ct_state=+new+trk,dl_type=0x0800,nw_src=%s,reg0=%d", internal, selector),
				Actions: fmt.Sprintf("ct(commit,zone=%d,nat(src=%s)),goto_table:%d",
					n.ctZone, pool, modes.TableMACLearning),
			})
		}
	}
	return n.stamp(rules)
}

// staticFlowRules builds the 1:1 translation flows for one static entry:
// ingress on the uplink port (external → internal), egress from the inside
// address (internal → external, outranking pool SNAT), and the hairpin for
// internal clients addressing the external address, whose single
// conntrack entry carries both the destination and the source
// translation so the inside server's reply is un-NATed on the way back.
func (n *NAT) staticFlowRules(st natStatic, uplinkPort int32, internal netip.Prefix) []zoneflows.FlowRule {
	ingress := fmt.Sprintf("in_port=%d,dl_type=0x0800,nw_dst=%s", uplinkPort, st.external)
	egress := fmt.Sprintf("dl_type=0x0800,nw_src=%s", st.internal)
	rules := []zoneflows.FlowRule{
		{
			Table:    int(modes.TableCTGate),
			Priority: prioStaticDivert,
			Match:    ingress,
			Actions:  fmt.Sprintf("ct(table=%d,zone=%d)", modes.TableNAT, n.ctZone),
		},
		{
			Table:    int(modes.TableNAT),
			Priority: prioNATCommitStatic,
			Match:    "ct_state=+new+trk," + ingress,
			Actions: fmt.Sprintf("ct(commit,zone=%d,nat(dst=%s)),goto_table:%d",
				n.ctZone, st.internal, modes.TableMACLearning),
		},
		{
			Table:    int(modes.TableCTGate),
			Priority: prioStaticDivert,
			Match:    egress,
			Actions:  fmt.Sprintf("ct(table=%d,zone=%d)", modes.TableNAT, n.ctZone),
		},
		{
			Table:    int(modes.TableNAT),
			Priority: prioNATCommitStatic,
			Match:    "ct_state=+new+trk," + egress,
			Actions: fmt.Sprintf("ct(commit,zone=%d,nat(src=%s)),goto_table:%d",
				n.ctZone, st.external, modes.TableMACLearning),
		},
	}
	if internal.IsValid() {
		hairpin := fmt.Sprintf("dl_type=0x0800,nw_src=%s,nw_dst=%s", internal, st.external)
		rules = append(rules,
			zoneflows.FlowRule{
				Table:    int(modes.TableCTGate),
				Priority: prioHairpinDivert,
				Match:    hairpin,
				Actions:  fmt.Sprintf("ct(table=%d,zone=%d)", modes.TableNAT, n.ctZone),
			},
			zoneflows.FlowRule{
				Table:    int(modes.TableNAT),
				Priority: prioNATCommitHairpin,
				Match:    "ct_state=+new+trk," + hairpin,
				Actions: fmt.Sprintf("ct(commit,zone=%d,nat(dst=%s)),ct(commit,zone=%d,nat(src=%s)),goto_table:%d",
					n.ctZone, st.internal, n.ctZone, st.external, modes.TableMACLearning),
			},
		)
	}
	return n.stamp(rules)
}

// dnatFlowRules builds the DNAT diversion and commit flows for a binding.
func (n *NAT) dnatFlowRules(uplinkPort int32, ipProto uint8, external, internal netip.AddrPort) []zoneflows.FlowRule {
	match := fmt.Sprintf("in_port=%d,dl_type=0x0800,nw_proto=%d,nw_dst=%s,tp_dst=%d",
		uplinkPort, ipProto, external.Addr(), external.Port())
	return n.stamp([]zoneflows.FlowRule{
		{
			Table:    int(modes.TableCTGate),
			Priority: prioDNATDivert,
			Match:    match,
			Actions:  fmt.Sprintf("ct(table=%d,zone=%d)", modes.TableNAT, n.ctZone),
		},
		{
			Table:    int(modes.TableNAT),
			Priority: prioNATCommitDNAT,
			Match:    "ct_state=+new+trk," + match,
			Actions: fmt.Sprintf("ct(commit,zone=%d,nat(dst=%s:%d)),goto_table:%d",
				n.ctZone, internal.Addr(), internal.Port(), modes.TableMACLearning),
		},
	})
}

// deleteStrict strict-deletes a set of previously installed rules.
func (n *NAT) deleteStrict(ctx context.Context, rules []zoneflows.FlowRule) error {
	for _, rule := range rules {
		if err := n.deps.OVS.DeleteFlowStrict(ctx, n.cfg.Bridge, &ovs.FlowMod{
			Table:    rule.Table,
			Priority: rule.Priority,
			Match:    rule.Match,
			Cookie:   rule.Cookie,
		}); err != nil {
			return &OpError{Op: "delete", Err: err}
		}
	}
	return nil
}

// Start allocates the NAT conntrack zone, installs the base pipeline
// (gate + table 25 scaffolding), and enables SNAT when InternalCIDR is
// configured.
//
// Start also reconciles against the flows a process that exited without
// Stop left behind (#557): every flow it installs carries a fresh
// generation under the NAT owner, and once SNAT and the statics are in
// place every NAT flow of an older generation is swept.
//
// A Start that fails leaves the bridge as Stop would: no NAT gate, no NAT
// flow of any generation and no NAT conntrack zone.
func (n *NAT) Start(ctx context.Context) (err error) {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.active {
		return ErrAlreadyStarted
	}

	cookie, err := ovs.NewGenerationCookie(CookieNAT)
	if err != nil {
		return &OpError{Op: "generation", Err: err}
	}
	n.cookie = fmt.Sprintf("0x%x", cookie)

	ctZone, err := n.deps.Allocator.Allocate(ctx, AllocatorOwnerNAT, natZoneKey)
	if err != nil {
		return &OpError{Op: "allocate", Err: err}
	}
	n.ctZone = ctZone

	// Start is transactional. The gateway registers the service only when
	// Start succeeds, so a failed Start has no Stop to clean up after it:
	// whatever it programmed or allocated is taken back here instead of
	// being left live on the bridge.
	defer func() {
		if err == nil {
			return
		}
		if rollbackErr := n.rollbackStartLocked(ctx); rollbackErr != nil {
			err = errors.Join(err, rollbackErr)
		}
	}()

	if err := n.deps.Controller.InstallFlows(n.cfg.Bridge, n.baseRules()); err != nil {
		return &OpError{Op: "install", Err: err}
	}
	n.active = true

	if n.internal.IsValid() {
		if err := n.enableSNATLocked(ctx, n.internal); err != nil {
			return err
		}
	}
	if err := n.installStaticsLocked(ctx); err != nil {
		return err
	}
	if err := ovs.SweepStaleGenerations(ctx, n.deps.OVS, n.cfg.Bridge, cookie); err != nil {
		return &OpError{Op: "sweep", Err: err}
	}

	n.deps.Logger.Info("nat service started",
		slog.String("bridge", n.cfg.Bridge),
		slog.String("external_ip", n.external.String()),
		slog.Int("uplinks", n.uplinkCount()),
		slog.Int("static", len(n.staticRules)),
		slog.Bool("snat", len(n.snatRules) > 0),
	)

	return nil
}

// rollbackStartLocked takes back what a failed Start did and leaves the
// bridge as Stop would: the gate first, so no packet enters a half-removed
// pipeline, then every NAT flow of any generation (a previous process's
// included, which the failed sweep may have left), then the conntrack
// zone. Every step runs even when an earlier one fails.
func (n *NAT) rollbackStartLocked(ctx context.Context) error {
	var errs []error
	if err := n.deleteStrict(ctx, n.baseRules()[:1]); err != nil {
		errs = append(errs, err)
	}
	if err := n.deps.OVS.DeleteFlowsByCookie(ctx, n.cfg.Bridge, CookieNAT, CookieMask); err != nil {
		errs = append(errs, err)
	}
	if err := n.deps.Allocator.Release(ctx, AllocatorOwnerNAT, natZoneKey); err != nil {
		errs = append(errs, err)
	}
	n.active = false
	n.ctZone = 0
	n.snatRules = nil
	n.snatPrefix = netip.Prefix{}
	n.staticRules = nil
	n.uplinkOFPort = 0
	n.uplinkPorts = make(map[string]int32)
	if len(errs) > 0 {
		return &OpError{Op: "rollback", Err: errors.Join(errs...)}
	}
	return nil
}

// uplinkCount is the number of SNAT pools (0 in single-address mode).
func (n *NAT) uplinkCount() int {
	if n.plan == nil {
		return 0
	}
	return len(n.plan.uplinks)
}

// installStaticsLocked installs every static translation; the caller
// holds n.mu. A static whose uplink port cannot be resolved fails the
// start: a 1:1 mapping that silently does not exist is a reachability hole
// nobody sees.
func (n *NAT) installStaticsLocked(ctx context.Context) error {
	if n.plan == nil || len(n.plan.statics) == 0 {
		return nil
	}
	var rules []zoneflows.FlowRule
	for _, st := range n.plan.statics {
		port, err := n.resolveUplinkPortLocked(ctx, n.plan.byName(st.uplink).port)
		if err != nil {
			return err
		}
		rules = append(rules, n.staticFlowRules(st, port, n.internal)...)
	}
	if err := n.deps.Controller.InstallFlows(n.cfg.Bridge, rules); err != nil {
		return &OpError{Op: "install", Err: err}
	}
	n.staticRules = rules
	return nil
}

// resolveUplinkPortLocked returns the OpenFlow port of an OVS port name,
// caching the answer; the caller holds n.mu.
func (n *NAT) resolveUplinkPortLocked(ctx context.Context, portName string) (int32, error) {
	if portName == "" {
		return 0, ErrEmptyUplink
	}
	if port, ok := n.uplinkPorts[portName]; ok {
		return port, nil
	}
	port, err := n.deps.OVS.GetOFPort(ctx, portName)
	if err != nil {
		return 0, &OpError{Op: "resolve-uplink", Err: err}
	}
	n.uplinkPorts[portName] = port
	return port, nil
}

// StaticRules lists the installed 1:1 translations.
func (n *NAT) StaticRules() []StaticNAT {
	n.mu.Lock()
	defer n.mu.Unlock()
	if n.plan == nil || len(n.staticRules) == 0 {
		return nil
	}
	out := make([]StaticNAT, 0, len(n.plan.statics))
	for _, st := range n.plan.statics {
		out = append(out, StaticNAT{Internal: st.internal.String(), External: st.external.String(), Uplink: st.uplink})
	}
	return out
}

// Stop deletes every NAT-owned flow by cookie (the table 10 gate carries
// the same cookie and falls with them) and releases the conntrack zone.
func (n *NAT) Stop(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if !n.active {
		return ErrNotStarted
	}

	if err := n.deps.OVS.DeleteFlowsByCookie(ctx, n.cfg.Bridge, CookieNAT, CookieMask); err != nil {
		return &OpError{Op: "delete", Err: err}
	}

	if err := n.deps.Allocator.Release(ctx, AllocatorOwnerNAT, natZoneKey); err != nil {
		return &OpError{Op: "release", Err: err}
	}

	n.active = false
	n.snatRules = nil
	n.snatPrefix = netip.Prefix{}
	n.staticRules = nil
	n.dnats = make(map[dnatKey]dnatBinding)
	n.uplinkOFPort = 0
	n.uplinkPorts = make(map[string]int32)

	n.deps.Logger.Info("nat service stopped", slog.String("bridge", n.cfg.Bridge))

	return nil
}

// EnableSNAT installs source NAT for the given internal IPv4 prefix,
// translating egress connections to ExternalIP within the configured port
// range.
func (n *NAT) EnableSNAT(ctx context.Context, internal netip.Prefix) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if !n.active {
		return ErrNotStarted
	}
	return n.enableSNATLocked(ctx, internal)
}

// enableSNATLocked implements EnableSNAT; the caller holds n.mu.
func (n *NAT) enableSNATLocked(ctx context.Context, internal netip.Prefix) error {
	if len(n.snatRules) > 0 {
		return ErrSNATAlreadyEnabled
	}
	if !internal.IsValid() || !internal.Addr().Is4() {
		return ErrInvalidInternalCIDR
	}

	rules := n.snatFlowRules(internal)
	if err := n.deps.Controller.InstallFlows(n.cfg.Bridge, rules); err != nil {
		return &OpError{Op: "install", Err: err}
	}
	n.snatRules = rules
	n.snatPrefix = internal

	return nil
}

// DisableSNAT removes the source NAT flows. Existing translated
// connections keep flowing through the established fast-path until they
// expire from the connection tracker.
func (n *NAT) DisableSNAT(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if !n.active {
		return ErrNotStarted
	}
	if len(n.snatRules) == 0 {
		return ErrSNATNotEnabled
	}

	if err := n.deleteStrict(ctx, n.snatRules); err != nil {
		return err
	}
	n.snatRules = nil
	n.snatPrefix = netip.Prefix{}

	return nil
}

// AddDNAT installs a destination NAT binding: proto ("tcp" or "udp")
// traffic arriving on the uplink for external is translated to internal.
func (n *NAT) AddDNAT(ctx context.Context, proto string, external, internal netip.AddrPort) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if !n.active {
		return ErrNotStarted
	}

	ipProto, ok := natProtocols[proto]
	if !ok {
		return ErrInvalidProtocol
	}
	if !external.Addr().Is4() || external.Port() == 0 {
		return ErrInvalidAddrPort
	}
	if !internal.Addr().Is4() || internal.Port() == 0 {
		return ErrInvalidAddrPort
	}
	if n.plan == nil && n.cfg.UplinkPort == "" {
		return ErrEmptyUplink
	}

	binding := dnatKey{proto: proto, external: external}
	if _, exists := n.dnats[binding]; exists {
		return ErrDNATExists
	}

	// The binding lives on the uplink that owns the external address: the
	// pool or static it belongs to, or the default uplink; in
	// single-address mode, the one configured uplink port.
	portName := n.cfg.UplinkPort
	if n.plan != nil {
		portName = n.plan.uplinkFor(external.Addr()).port
	}
	ofPort, err := n.resolveUplinkPortLocked(ctx, portName)
	if err != nil {
		return err
	}
	n.uplinkOFPort = ofPort

	rules := n.dnatFlowRules(ofPort, ipProto, external, internal)
	if err := n.deps.Controller.InstallFlows(n.cfg.Bridge, rules); err != nil {
		return &OpError{Op: "install", Err: err}
	}
	n.dnats[binding] = dnatBinding{internal: internal, rules: rules}

	return nil
}

// RemoveDNAT deletes the destination NAT binding for proto/external.
func (n *NAT) RemoveDNAT(ctx context.Context, proto string, external netip.AddrPort) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if !n.active {
		return ErrNotStarted
	}

	binding := dnatKey{proto: proto, external: external}
	entry, exists := n.dnats[binding]
	if !exists {
		return ErrDNATNotFound
	}

	if err := n.deleteStrict(ctx, entry.rules); err != nil {
		return err
	}
	delete(n.dnats, binding)

	return nil
}

// Active reports whether the service is started.
func (n *NAT) Active() bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.active
}

// Health returns a snapshot of the NAT service state.
// SNATPrefix reports the source prefix SNAT is enabled for, and whether
// SNAT is enabled at all.
func (n *NAT) SNATPrefix() (netip.Prefix, bool) {
	n.mu.Lock()
	defer n.mu.Unlock()
	return n.snatPrefix, len(n.snatRules) > 0
}

// DNATRules lists the installed port-forwards in no particular order.
func (n *NAT) DNATRules() []DNATRule {
	n.mu.Lock()
	defer n.mu.Unlock()
	out := make([]DNATRule, 0, len(n.dnats))
	for key, entry := range n.dnats {
		out = append(out, DNATRule{Protocol: key.proto, External: key.external, Internal: entry.internal})
	}
	return out
}

func (n *NAT) Health() NATHealth {
	n.mu.Lock()
	defer n.mu.Unlock()
	h := NATHealth{
		Active:      n.active,
		SNATEnabled: len(n.snatRules) > 0,
		DNATRules:   len(n.dnats),
		CTZone:      n.ctZone,
	}
	if n.plan != nil {
		for _, u := range n.plan.uplinks {
			uh := NATUplinkHealth{Name: u.name, Default: u.isDefault}
			for _, pool := range u.pools {
				uh.PoolAddresses += poolSize(pool)
				uh.Ports = int(pool.portEnd) - int(pool.portStart) + 1
			}
			for _, st := range n.plan.statics {
				if st.uplink == u.name {
					uh.Static++
				}
			}
			h.Uplinks = append(h.Uplinks, uh)
		}
	}
	return h
}

// poolSize counts the IPv4 addresses in an inclusive pool range.
func poolSize(p natPool) int {
	a, b := p.first.As4(), p.last.As4()
	ai := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3])
	bi := uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
	return int(bi-ai) + 1
}
