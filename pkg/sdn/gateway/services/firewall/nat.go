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

	mu           sync.Mutex
	active       bool
	ctZone       uint16
	uplinkOFPort int32
	snatRules    []zoneflows.FlowRule
	dnats        map[dnatKey][]zoneflows.FlowRule
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

	return &NAT{
		deps:     deps,
		cfg:      cfg,
		cookie:   fmt.Sprintf("0x%x", CookieNAT),
		external: external,
		internal: internal,
		dnats:    make(map[dnatKey][]zoneflows.FlowRule),
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
	})
}

// snatFlowRules builds the SNAT diversion and commit flows for a prefix.
func (n *NAT) snatFlowRules(internal netip.Prefix) []zoneflows.FlowRule {
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

// dnatFlowRules builds the DNAT diversion and commit flows for a binding.
func (n *NAT) dnatFlowRules(ipProto uint8, external, internal netip.AddrPort) []zoneflows.FlowRule {
	match := fmt.Sprintf("in_port=%d,dl_type=0x0800,nw_proto=%d,nw_dst=%s,tp_dst=%d",
		n.uplinkOFPort, ipProto, external.Addr(), external.Port())
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
func (n *NAT) Start(ctx context.Context) error {
	n.mu.Lock()
	defer n.mu.Unlock()

	if n.active {
		return ErrAlreadyStarted
	}

	ctZone, err := n.deps.Allocator.Allocate(ctx, AllocatorOwnerNAT, natZoneKey)
	if err != nil {
		return &OpError{Op: "allocate", Err: err}
	}
	n.ctZone = ctZone

	if err := n.deps.Controller.InstallFlows(n.cfg.Bridge, n.baseRules()); err != nil {
		return &OpError{Op: "install", Err: err}
	}
	n.active = true

	if n.internal.IsValid() {
		if err := n.enableSNATLocked(ctx, n.internal); err != nil {
			return err
		}
	}

	n.deps.Logger.Info("nat service started",
		slog.String("bridge", n.cfg.Bridge),
		slog.String("external_ip", n.external.String()),
		slog.Bool("snat", len(n.snatRules) > 0),
	)

	return nil
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
	n.dnats = make(map[dnatKey][]zoneflows.FlowRule)
	n.uplinkOFPort = 0

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
	if n.cfg.UplinkPort == "" {
		return ErrEmptyUplink
	}

	binding := dnatKey{proto: proto, external: external}
	if _, exists := n.dnats[binding]; exists {
		return ErrDNATExists
	}

	if n.uplinkOFPort == 0 {
		ofPort, err := n.deps.OVS.GetOFPort(ctx, n.cfg.UplinkPort)
		if err != nil {
			return &OpError{Op: "resolve-uplink", Err: err}
		}
		n.uplinkOFPort = ofPort
	}

	rules := n.dnatFlowRules(ipProto, external, internal)
	if err := n.deps.Controller.InstallFlows(n.cfg.Bridge, rules); err != nil {
		return &OpError{Op: "install", Err: err}
	}
	n.dnats[binding] = rules

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
	rules, exists := n.dnats[binding]
	if !exists {
		return ErrDNATNotFound
	}

	if err := n.deleteStrict(ctx, rules); err != nil {
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
func (n *NAT) Health() NATHealth {
	n.mu.Lock()
	defer n.mu.Unlock()
	return NATHealth{
		Active:      n.active,
		SNATEnabled: len(n.snatRules) > 0,
		DNATRules:   len(n.dnats),
		CTZone:      n.ctZone,
	}
}
