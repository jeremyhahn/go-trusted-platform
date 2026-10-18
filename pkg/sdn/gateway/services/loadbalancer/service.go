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

// Package loadbalancer implements the OVS-native L4 load balancer gateway
// service. VIP traffic is diverted from the conntrack gate (table 20) into
// the load balancer dispatch table (table 26), where new connections are
// spread across an OpenFlow select group whose buckets DNAT to the healthy
// backends via ct(commit,zone=Z,nat(dst=...),table=28). Table 28 also
// source-NATs a connection to the VIP, in a second (hairpin) zone, when the
// client is on a hairpin prefix. A backend's replies are steered by their
// source address:port back through ct(nat) in the hairpin zone and then in
// the VIP's zone (table 29), which reverses both translations, so the
// client hears from the VIP it addressed. Selection is hash-based (OVS
// dp_hash) and per-connection sticky through conntrack. See
// docs/gateway/engineering.md ("The load balancer datapath") for the
// table design.
package loadbalancer

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"sync"
	"time"

	"github.com/cespare/xxhash/v2"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ct"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/modes"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
)

// Flow cookie identifying load-balancer-owned flows. The high 32 bits are
// the owner prefix used with CookieMask for bulk deletion, following the
// firewall (0xF1BE0001) and NAT (0xF1BE0002) conventions. The low 32 bits
// carry the flow generation each Start stamps (ovs.NewGenerationCookie).
const (
	// CookieLoadBalancer tags every flow installed by the Service.
	CookieLoadBalancer uint64 = 0xF1BE000300000000

	// CookieMask selects the owner prefix of CookieLoadBalancer.
	CookieMask = ovs.OwnerCookieMask
)

// Table-10 gate priority. The firewall gate uses priority 2 and the NAT
// gate priority 1; the load balancer claims priority 3 so all three gates
// remain distinct flows in OVS and tear down independently (identical
// match+priority would make OFPFC_ADD replace a sibling's gate).
const lbGatePriority = 3

// Load balancer pipeline priorities.
const (
	// prioLBDivert diverts VIP traffic in table 20 into the load balancer
	// conntrack zone. It outranks the NAT DNAT divert (200) so a VIP takes
	// precedence over an overlapping DNAT binding.
	prioLBDivert = 250

	// prioLBInvalid drops invalid tracked connections in table 26.
	prioLBInvalid = 400

	// prioLBEstRel fast-paths established/related connections in table 26
	// (NAT is applied by the bare nat argument on the table 20 divert).
	prioLBEstRel = 300

	// prioLBDispatch sends new connections to the VIP's select group.
	prioLBDispatch = 200

	// prioLBMissT26 drops table 26 misses: VIP traffic must never leak
	// unbalanced past the dispatch table.
	prioLBMissT26 = 0

	// prioLBReplyDivert steers a backend's packets (by source address and
	// port) through the hairpin and VIP conntrack zones in table 20 so a
	// reply is reverse-translated. It outranks the VIP divert so a packet
	// that matches both is classified as a reply.
	prioLBReplyDivert = 260

	// prioLBHairpin source-NATs a connection from a hairpin prefix to the
	// VIP in table 28.
	prioLBHairpin = 200

	// prioLBMissHairpin continues every other connection to table 30.
	prioLBMissHairpin = 0

	// prioLBReplyUnDNAT takes a backend reply, back from the hairpin zone,
	// through ct(nat) in its VIP's zone, in table 29: one flow per backend.
	// It matches ct_zone, so a packet already back from the VIP zone falls
	// through to the verdicts below.
	prioLBReplyUnDNAT = 200

	// prioLBReplyEst forwards a reply of a VIP connection in table 29.
	prioLBReplyEst = 100

	// prioLBReplyMiss hands every other backend-sourced packet back to the
	// table 20 conntrack gate.
	prioLBReplyMiss = 0
)

// The reply mark is register 1 bit 0. The table 20 reply divert sets it
// before the conntrack lookup and only matches packets that do not carry
// it, so a backend packet that is not part of a VIP connection — the
// backend's own traffic from its service port — can be resubmitted to
// table 20 and pass through the firewall and NAT gates exactly as if the
// load balancer were not there. The NAT service owns register 0.
const (
	replyMarkClear = "reg1=0/0x1"
	replyMarkSet   = "load:1->NXM_NX_REG1[0]"
)

// AllocatorOwnerLB is the ct.ZoneAllocator owner name for per-VIP conntrack
// zones. Keys are vipKey strings ("tcp/10.0.0.1:80").
const AllocatorOwnerLB = "lb"

// hairpinZoneKey is the AllocatorOwnerLB key of the one conntrack zone the
// hairpin source NAT shares across VIPs. It cannot collide with a vipKey,
// which always carries a protocol and an address.
const hairpinZoneKey = "hairpin"

// OpenFlow group ID range owned by the load balancer. Group IDs carry no
// cookie, so the service claims a dedicated range ("LB" = 0x4C42) and
// derives IDs deterministically from the VIP key; Start reconciles the
// range against the configured VIPs via GetGroupDesc.
const (
	// GroupIDBase is the first group ID in the load balancer range.
	GroupIDBase uint32 = 0x4C420000

	// GroupIDMask selects the load balancer range prefix.
	GroupIDMask uint32 = 0xFFFF0000
)

// groupIDSpace is the number of IDs in the load balancer group range.
const groupIDSpace = 1 << 16

// Deps carries the load balancer service dependencies.
type Deps struct {
	// Controller installs flows (the shared policy flow path).
	Controller policy.FlowController

	// OVS provides cookie-scoped and strict flow deletion.
	OVS ovs.ClientInterface

	// Groups programs OpenFlow select groups.
	Groups ovs.GroupClient

	// Config is the load balancer configuration.
	Config Config

	// Allocator hands out conntrack zone IDs.
	Allocator *ct.ZoneAllocator

	// Logger receives service lifecycle logs. Defaults to slog.Default.
	Logger *slog.Logger
}

// validate checks that every required dependency is present.
func (d *Deps) validate() error {
	if d.Controller == nil {
		return ErrNilController
	}
	if d.OVS == nil {
		return ErrNilOVSClient
	}
	if d.Groups == nil {
		return ErrNilGroupClient
	}
	if d.Allocator == nil {
		return ErrNilAllocator
	}
	return d.Config.Validate()
}

// vipState is the installed state of one VIP.
type vipState struct {
	vip     VIP
	zone    uint16
	groupID uint32
	healthy map[netip.AddrPort]bool
	flows   []zoneflows.FlowRule
}

// healthyBackends returns the backends currently marked healthy.
func (s *vipState) healthyBackends() []Backend {
	out := make([]Backend, 0, len(s.vip.Backends))
	for _, b := range s.vip.Backends {
		if s.healthy[b.addrPort()] {
			out = append(out, b)
		}
	}
	return out
}

// Service is the OVS-native L4 load balancer. Start installs the dispatch
// pipeline (tables 20/26), one select group per VIP, and the table 10 gate,
// then begins health probing; Stop removes the gate first and then every
// load-balancer-owned flow and group.
type Service struct {
	deps   Deps
	cfg    Config
	cookie string
	prober *prober

	mu            sync.Mutex
	active        bool
	vips          map[vipKey]*vipState
	hairpinZone   uint16
	lastReconcile time.Time

	cancel context.CancelFunc
	wg     sync.WaitGroup
}

// New creates a load balancer Service, validating every dependency.
func New(deps Deps) (*Service, error) {
	if err := deps.validate(); err != nil {
		return nil, err
	}
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	cfg := deps.Config.withDefaults()
	s := &Service{
		deps:   deps,
		cfg:    cfg,
		cookie: fmt.Sprintf("0x%x", CookieLoadBalancer),
		vips:   make(map[vipKey]*vipState),
	}
	s.prober = newProber(proberConfig{
		Interval: cfg.HealthCheckInterval,
		Timeout:  cfg.HealthCheckTimeout,
		Rise:     cfg.Rise,
		Fall:     cfg.Fall,
		Logger:   deps.Logger,
	}, s.probeTargets, s.applyProbeResult)
	return s, nil
}

// stamp sets the load balancer cookie on every rule and returns the slice.
func (s *Service) stamp(rules []zoneflows.FlowRule) []zoneflows.FlowRule {
	for i := range rules {
		rules[i].Cookie = s.cookie
	}
	return rules
}

// gateRule is the table 10 flow diverting traffic into the conntrack gate
// (table 20).
func (s *Service) gateRule() zoneflows.FlowRule {
	return zoneflows.FlowRule{
		Table:    int(modes.TableVXLANDecap),
		Priority: lbGatePriority,
		Actions:  fmt.Sprintf("goto_table:%d", modes.TableCTGate),
		Cookie:   s.cookie,
	}
}

// baseRules returns the table 26 conntrack verdicts, the table 28 miss and
// the table 29 reply verdicts. Non-VIP traffic that the gate admitted to
// table 20 continues to table 30 through the pipeline's own table-20 miss,
// which no service installs (#614).
func (s *Service) baseRules() []zoneflows.FlowRule {
	resubmitToGate := fmt.Sprintf("resubmit(,%d)", modes.TableCTGate)
	return s.stamp([]zoneflows.FlowRule{
		{
			Table:    int(modes.TableLoadBalancer),
			Priority: prioLBInvalid,
			Match:    "ct_state=+inv+trk",
			Actions:  "drop",
		},
		{
			// Established and related request packets pass the hairpin
			// stage too: a hairpin connection's source NAT is applied per
			// packet, not only at commit.
			Table:    int(modes.TableLoadBalancer),
			Priority: prioLBEstRel,
			Match:    "ct_state=+est+trk",
			Actions:  fmt.Sprintf("goto_table:%d", modes.TableLBHairpin),
		},
		{
			Table:    int(modes.TableLoadBalancer),
			Priority: prioLBEstRel,
			Match:    "ct_state=+rel+trk",
			Actions:  fmt.Sprintf("goto_table:%d", modes.TableLBHairpin),
		},
		{
			Table:    int(modes.TableLoadBalancer),
			Priority: prioLBMissT26,
			Actions:  "drop",
		},
		{
			Table:    int(modes.TableLBHairpin),
			Priority: prioLBMissHairpin,
			Actions:  fmt.Sprintf("goto_table:%d", modes.TableMACLearning),
		},
		{
			// A reply of a committed VIP connection: both translations
			// have been reversed.
			Table:    int(modes.TableLBReply),
			Priority: prioLBReplyEst,
			Match:    "ct_state=+est+rpl+trk",
			Actions:  fmt.Sprintf("goto_table:%d", modes.TableMACLearning),
		},
		{
			// Anything else from a backend's address:port — its own
			// traffic, not a VIP reply — goes back to the gate, marked so
			// the reply divert does not take it again.
			Table:    int(modes.TableLBReply),
			Priority: prioLBReplyMiss,
			Actions:  resubmitToGate,
		},
	})
}

// vipFlowRules builds every flow one VIP owns:
//
//   - table 20: the request divert into the VIP's conntrack zone;
//   - table 26: the dispatch of new connections to the select group;
//   - table 28: per hairpin prefix, the source NAT to the VIP in the
//     hairpin zone (committed on the first packet, applied to the rest);
//   - table 20: per backend, the reply divert matching the backend's
//     source address:port, through ct(nat) in the hairpin zone, which
//     reverses a hairpin connection's source NAT;
//   - table 29: per backend, for a packet back from the hairpin zone,
//     ct(nat) in the VIP's zone, which reverses the DNAT so the reply's
//     source is the VIP.
//
// The hairpin flows match ct_zone, which the bucket's conntrack commit
// set: after the DNAT the packet's destination is the backend, so the zone
// is what still says which VIP it is for. The hairpin zone is shared by
// every VIP: its entries are keyed by the backend address:port, which
// belongs to one VIP only.
func (s *Service) vipFlowRules(vip VIP, zone uint16, groupID uint32) []zoneflows.FlowRule {
	proto := ipProtocols[vip.Protocol]
	match := fmt.Sprintf("dl_type=0x0800,nw_proto=%d,nw_dst=%s,tp_dst=%d", proto, vip.Address, vip.Port)
	rules := []zoneflows.FlowRule{
		{
			Table:    int(modes.TableCTGate),
			Priority: prioLBDivert,
			Match:    match,
			Actions:  fmt.Sprintf("ct(table=%d,zone=%d,nat)", modes.TableLoadBalancer, zone),
		},
		{
			Table:    int(modes.TableLoadBalancer),
			Priority: prioLBDispatch,
			Match:    "ct_state=+new+trk," + match,
			Actions:  fmt.Sprintf("group:%d", groupID),
		},
	}
	for _, prefix := range s.cfg.HairpinPrefixes {
		source := fmt.Sprintf("ct_zone=%d,dl_type=0x0800,nw_src=%s", zone, prefix.Masked())
		rules = append(rules,
			zoneflows.FlowRule{
				Table:    int(modes.TableLBHairpin),
				Priority: prioLBHairpin,
				Match:    "ct_state=+new+trk," + source,
				Actions: fmt.Sprintf("ct(commit,zone=%d,nat(src=%s),table=%d)",
					s.hairpinZone, vip.Address, modes.TableMACLearning),
			},
			zoneflows.FlowRule{
				Table:    int(modes.TableLBHairpin),
				Priority: prioLBHairpin,
				Match:    "ct_state=+est+trk," + source,
				Actions:  fmt.Sprintf("ct(zone=%d,nat,table=%d)", s.hairpinZone, modes.TableMACLearning),
			},
		)
	}
	for _, b := range vip.Backends {
		source := fmt.Sprintf("dl_type=0x0800,nw_proto=%d,nw_src=%s,tp_src=%d", proto, b.Address, b.Port)
		rules = append(rules,
			zoneflows.FlowRule{
				Table:    int(modes.TableCTGate),
				Priority: prioLBReplyDivert,
				Match:    replyMarkClear + "," + source,
				Actions: fmt.Sprintf("%s,ct(table=%d,zone=%d,nat)",
					replyMarkSet, modes.TableLBReply, s.hairpinZone),
			},
			zoneflows.FlowRule{
				Table:    int(modes.TableLBReply),
				Priority: prioLBReplyUnDNAT,
				Match:    fmt.Sprintf("ct_zone=%d,%s", s.hairpinZone, source),
				Actions:  fmt.Sprintf("ct(table=%d,zone=%d,nat)", modes.TableLBReply, zone),
			},
		)
	}
	return s.stamp(rules)
}

// groupMod builds the select group for a VIP from its healthy backends.
// Each bucket commits the connection into the VIP's conntrack zone, DNATs
// to the backend, and recirculates into the hairpin stage (table 28) —
// ct(commit,zone=Z,nat(dst=B:P),table=28). Zero healthy backends produce a
// bucketless group: new connections are dropped (fail closed) while
// established connections continue through conntrack.
func (s *Service) groupMod(state *vipState) *openflow.GroupMod {
	g := openflow.NewGroupMod(openflow.OFPGCAdd, openflow.OFPGTSelect, state.groupID)
	for _, b := range state.healthyBackends() {
		g.AddBucket(b.weight(), openflow.NewActionCT(
			openflow.NXCTFCommit,
			state.zone,
			modes.TableLBHairpin,
			openflow.NewActionNATDst(b.Address, b.Port),
		))
	}
	return g
}

// checkBackendsFreeLocked refuses backends any other VIP of the same
// protocol already serves: a backend's replies are steered to its VIP's
// zone by source address:port alone. The caller holds s.mu.
func (s *Service) checkBackendsFreeLocked(self vipKey, protocol string, backends []Backend) error {
	for key, state := range s.vips {
		if key == self || key.proto != protocol {
			continue
		}
		for _, b := range backends {
			if _, serves := state.healthy[b.addrPort()]; serves {
				return ErrBackendInUse
			}
		}
	}
	return nil
}

// groupIDFor derives the deterministic group ID for a key: the low 16 bits
// of the key hash inside the load balancer range, linearly probed past IDs
// already claimed by other VIPs.
func (s *Service) groupIDFor(key vipKey) (uint32, error) {
	inUse := make(map[uint32]struct{}, len(s.vips))
	for _, state := range s.vips {
		inUse[state.groupID] = struct{}{}
	}
	slot := uint32(xxhash.Sum64String(key.String()) & 0xFFFF)
	for i := 0; i < groupIDSpace; i++ {
		id := GroupIDBase | ((slot + uint32(i)) & 0xFFFF)
		if _, taken := inUse[id]; !taken {
			return id, nil
		}
	}
	return 0, ErrGroupIDExhausted
}

// effectiveAlgorithm resolves a VIP's algorithm against the service default.
func (s *Service) effectiveAlgorithm(vip VIP) string {
	if vip.Algorithm != "" {
		return vip.Algorithm
	}
	return s.cfg.Algorithm
}

// installVIPLocked allocates the VIP's conntrack zone and group ID,
// programs the select group, and installs the VIP flows. existingGroups
// lists group IDs already present on the bridge (from Start recovery) so
// the group is modified instead of re-added. The caller holds s.mu.
func (s *Service) installVIPLocked(ctx context.Context, vip VIP, existingGroups map[uint32]struct{}) (err error) {
	key := vip.key()
	if _, exists := s.vips[key]; exists {
		return ErrVIPExists
	}
	if err := s.checkBackendsFreeLocked(key, vip.Protocol, vip.Backends); err != nil {
		return err
	}

	zone, err := s.deps.Allocator.Allocate(ctx, AllocatorOwnerLB, key.String())
	if err != nil {
		return &OpError{Op: "allocate", Err: err}
	}
	// A VIP is installed whole or not at all: every step below that fails
	// takes back what the steps before it put on the switch, so nothing is
	// left behind that no VIP state accounts for.
	var undo []func() error
	undo = append(undo, func() error { return s.deps.Allocator.Release(ctx, AllocatorOwnerLB, key.String()) })
	defer func() {
		if err == nil {
			return
		}
		var undoErrs []error
		for i := len(undo) - 1; i >= 0; i-- {
			if undoErr := undo[i](); undoErr != nil {
				undoErrs = append(undoErrs, undoErr)
			}
		}
		if len(undoErrs) > 0 {
			err = errors.Join(err, &OpError{Op: "rollback", Err: errors.Join(undoErrs...)})
		}
	}()

	groupID, err := s.groupIDFor(key)
	if err != nil {
		return err
	}

	state := &vipState{
		vip:     vip,
		zone:    zone,
		groupID: groupID,
		healthy: make(map[netip.AddrPort]bool, len(vip.Backends)),
	}
	// Backends start healthy; the prober demotes unreachable ones after
	// Fall consecutive failures.
	for _, b := range vip.Backends {
		state.healthy[b.addrPort()] = true
	}

	// The openflow client stamps the group mod command (add vs modify),
	// so recovery reuses a surviving group instead of failing OFPGC_ADD.
	program := s.deps.Groups.AddGroup
	if _, present := existingGroups[groupID]; present {
		program = s.deps.Groups.ModifyGroup
	}
	if err := program(ctx, s.cfg.Bridge, s.groupMod(state)); err != nil {
		return &OpError{Op: "group-add", Err: err}
	}
	undo = append(undo, func() error { return s.deps.Groups.DeleteGroup(ctx, s.cfg.Bridge, groupID) })

	flows := s.vipFlowRules(vip, zone, groupID)
	if err := s.deps.Controller.InstallFlows(s.cfg.Bridge, flows); err != nil {
		// A batch that failed may still have installed some of its flows.
		undo = append(undo, func() error { return s.deleteFlowsLocked(ctx, flows) })
		return &OpError{Op: "install", Err: err}
	}
	state.flows = flows
	s.vips[key] = state

	if vip.Protocol == ProtocolUDP {
		s.deps.Logger.Warn("load balancer VIP is UDP: backends are not health probed and are treated as always healthy",
			slog.String("vip", key.String()))
	}

	return nil
}

// removeVIPLocked tears down a VIP's flows, group, and conntrack zone. The
// caller holds s.mu.
func (s *Service) removeVIPLocked(ctx context.Context, key vipKey) error {
	state, exists := s.vips[key]
	if !exists {
		return ErrVIPNotFound
	}

	if err := s.deleteFlowsLocked(ctx, state.flows); err != nil {
		return err
	}

	if err := s.deps.Groups.DeleteGroup(ctx, s.cfg.Bridge, state.groupID); err != nil {
		return &OpError{Op: "group-delete", Err: err}
	}

	if err := s.deps.Allocator.Release(ctx, AllocatorOwnerLB, key.String()); err != nil {
		return &OpError{Op: "release", Err: err}
	}

	delete(s.vips, key)
	return nil
}

// Start programs the load balancer pipeline: per-VIP select groups first
// (flows referencing a group require it to exist), then the scaffolding and
// VIP flows, and the table 10 gate last so packets never enter the pipeline
// before it is complete. Stale groups left in the load balancer range by a
// previous run are removed, and health probing begins.
//
// The flows a previous run left are reconciled the same way (#557): every
// flow this start installs carries a fresh generation under the load
// balancer owner, and after the gate is in place every load balancer flow
// of an older generation is swept.
func (s *Service) Start(ctx context.Context) (err error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.active {
		return ErrAlreadyStarted
	}

	cookie, err := ovs.NewGenerationCookie(CookieLoadBalancer)
	if err != nil {
		return &OpError{Op: "generation", Err: err}
	}
	s.cookie = fmt.Sprintf("0x%x", cookie)

	// The hairpin zone comes first: every VIP's reply diverts name it.
	hairpinZone, err := s.deps.Allocator.Allocate(ctx, AllocatorOwnerLB, hairpinZoneKey)
	if err != nil {
		return &OpError{Op: "allocate", Err: err}
	}
	s.hairpinZone = hairpinZone

	// Start is transactional. The gateway registers the service only when
	// Start succeeds, so a failed Start has no Stop to clean up after it:
	// whatever it programmed or allocated is taken back here instead of
	// being stranded on the bridge.
	defer func() {
		if err == nil {
			return
		}
		if rollbackErr := s.rollbackStartLocked(ctx); rollbackErr != nil {
			err = errors.Join(err, rollbackErr)
		}
	}()

	// Recover the group table: IDs in the LB range from a previous run.
	descs, err := s.deps.Groups.GetGroupDesc(ctx, s.cfg.Bridge)
	if err != nil {
		return &OpError{Op: "group-desc", Err: err}
	}
	existing := make(map[uint32]struct{})
	for _, d := range descs {
		if d.GroupID&GroupIDMask == GroupIDBase {
			existing[d.GroupID] = struct{}{}
		}
	}

	for _, vip := range s.cfg.VIPs {
		if err := s.installVIPLocked(ctx, vip, existing); err != nil {
			return err
		}
	}

	// Delete stale LB-range groups no configured VIP claimed.
	claimed := make(map[uint32]struct{}, len(s.vips))
	for _, state := range s.vips {
		claimed[state.groupID] = struct{}{}
	}
	for id := range existing {
		if _, ok := claimed[id]; ok {
			continue
		}
		if err := s.deps.Groups.DeleteGroup(ctx, s.cfg.Bridge, id); err != nil {
			return &OpError{Op: "group-delete", Err: err}
		}
	}

	if err := s.deps.Controller.InstallFlows(s.cfg.Bridge, s.baseRules()); err != nil {
		return &OpError{Op: "install", Err: err}
	}
	if err := s.deps.Controller.InstallFlows(s.cfg.Bridge, []zoneflows.FlowRule{s.gateRule()}); err != nil {
		return &OpError{Op: "install", Err: err}
	}
	if err := ovs.SweepStaleGenerations(ctx, s.deps.OVS, s.cfg.Bridge, cookie); err != nil {
		return &OpError{Op: "sweep", Err: err}
	}

	proberCtx, cancel := context.WithCancel(context.Background())
	s.cancel = cancel
	s.wg.Add(1)
	go func() {
		defer s.wg.Done()
		s.prober.run(proberCtx)
	}()

	s.lastReconcile = time.Now()
	s.active = true

	s.deps.Logger.Info("load balancer service started",
		slog.String("bridge", s.cfg.Bridge),
		slog.String("algorithm", s.cfg.Algorithm),
		slog.Int("vips", len(s.vips)),
	)

	return nil
}

// rollbackStartLocked takes back a failed Start: the gate first, on its own,
// so a failed owner-wide delete cannot leave it steering traffic into flows
// nobody manages; then every load-balancer flow (one cookie-masked delete
// covers the scaffolding and VIP flows), the installed VIPs' groups and
// conntrack zones, and the hairpin zone. It carries on past a failed step so
// one refusal does not strand the rest. The caller holds s.mu.
func (s *Service) rollbackStartLocked(ctx context.Context) error {
	var errs []error
	if err := s.deleteGate(ctx); err != nil {
		errs = append(errs, err)
	}
	if err := s.deps.OVS.DeleteFlowsByCookie(ctx, s.cfg.Bridge, CookieLoadBalancer, CookieMask); err != nil {
		errs = append(errs, err)
	}
	for key, state := range s.vips {
		if err := s.deps.Groups.DeleteGroup(ctx, s.cfg.Bridge, state.groupID); err != nil {
			errs = append(errs, err)
		}
		if err := s.deps.Allocator.Release(ctx, AllocatorOwnerLB, key.String()); err != nil {
			errs = append(errs, err)
		}
	}
	if err := s.deps.Allocator.Release(ctx, AllocatorOwnerLB, hairpinZoneKey); err != nil {
		errs = append(errs, err)
	}
	s.vips = make(map[vipKey]*vipState)
	s.hairpinZone = 0
	if len(errs) > 0 {
		return &OpError{Op: "rollback", Err: errors.Join(errs...)}
	}
	return nil
}

// deleteGate removes the table 10 gate that diverts traffic into the
// load-balancer tables.
func (s *Service) deleteGate(ctx context.Context) error {
	gate := s.gateRule()
	return s.deps.OVS.DeleteFlowStrict(ctx, s.cfg.Bridge, &ovs.FlowMod{
		Table:    gate.Table,
		Priority: gate.Priority,
		Match:    gate.Match,
		Cookie:   gate.Cookie,
	})
}

// Stop cancels health probing, removes the table 10 gate first (so traffic
// falls back to the base pipeline), deletes every load-balancer-owned flow
// by cookie, removes the select groups, and releases the conntrack zones.
func (s *Service) Stop(ctx context.Context) error {
	s.mu.Lock()
	if !s.active {
		s.mu.Unlock()
		return ErrNotStarted
	}
	cancel := s.cancel
	s.mu.Unlock()

	cancel()
	s.wg.Wait()

	s.mu.Lock()
	defer s.mu.Unlock()

	if err := s.deleteGate(ctx); err != nil {
		return &OpError{Op: "delete", Err: err}
	}

	if err := s.deps.OVS.DeleteFlowsByCookie(ctx, s.cfg.Bridge, CookieLoadBalancer, CookieMask); err != nil {
		return &OpError{Op: "delete", Err: err}
	}

	var teardownErrs []error
	for key, state := range s.vips {
		if err := s.deps.Groups.DeleteGroup(ctx, s.cfg.Bridge, state.groupID); err != nil {
			teardownErrs = append(teardownErrs, err)
		}
		if err := s.deps.Allocator.Release(ctx, AllocatorOwnerLB, key.String()); err != nil {
			teardownErrs = append(teardownErrs, err)
		}
	}

	if err := s.deps.Allocator.Release(ctx, AllocatorOwnerLB, hairpinZoneKey); err != nil {
		teardownErrs = append(teardownErrs, err)
	}

	s.vips = make(map[vipKey]*vipState)
	s.active = false
	s.cancel = nil

	s.deps.Logger.Info("load balancer service stopped", slog.String("bridge", s.cfg.Bridge))

	if len(teardownErrs) > 0 {
		return &OpError{Op: "release", Err: errors.Join(teardownErrs...)}
	}
	return nil
}

// AddVIP validates and installs a VIP at runtime.
func (s *Service) AddVIP(ctx context.Context, vip VIP) error {
	if err := vip.Validate(s.cfg.MaxBackends); err != nil {
		return err
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.active {
		return ErrNotStarted
	}
	if err := s.installVIPLocked(ctx, vip, nil); err != nil {
		return err
	}
	s.lastReconcile = time.Now()
	return nil
}

// RemoveVIP tears down the VIP identified by protocol and address:port.
// Established connections lose their divert flow and stop being translated.
func (s *Service) RemoveVIP(ctx context.Context, protocol string, addr netip.AddrPort) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.active {
		return ErrNotStarted
	}
	if err := s.removeVIPLocked(ctx, vipKey{proto: protocol, addr: addr.Addr(), port: addr.Port()}); err != nil {
		return err
	}
	s.lastReconcile = time.Now()
	return nil
}

// GetVIP returns the status of one VIP.
func (s *Service) GetVIP(protocol string, addr netip.AddrPort) (VIPStatus, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	state, ok := s.vips[vipKey{proto: protocol, addr: addr.Addr(), port: addr.Port()}]
	if !ok {
		return VIPStatus{}, ErrVIPNotFound
	}
	return s.statusLocked(state), nil
}

// ListVIPs returns the status of every installed VIP.
func (s *Service) ListVIPs() []VIPStatus {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]VIPStatus, 0, len(s.vips))
	for _, state := range s.vips {
		out = append(out, s.statusLocked(state))
	}
	return out
}

// SetBackends replaces the backend set of an installed VIP: the reply
// diverts follow the new set, the select group is rebuilt, and the healthy
// map re-seeded (new backends start healthy; the prober demotes
// unreachable ones). The new flows go in before the group can select a new
// backend, and the flows of removed backends come out after it no longer
// can; a removed backend's established connections stop being translated,
// as a removed VIP's do.
func (s *Service) SetBackends(ctx context.Context, protocol string, addr netip.AddrPort, backends []Backend) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.active {
		return ErrNotStarted
	}
	key := vipKey{proto: protocol, addr: addr.Addr(), port: addr.Port()}
	state, ok := s.vips[key]
	if !ok {
		return ErrVIPNotFound
	}

	candidate := state.vip
	candidate.Backends = backends
	if err := candidate.Validate(s.cfg.MaxBackends); err != nil {
		return err
	}
	if err := s.checkBackendsFreeLocked(key, protocol, backends); err != nil {
		return err
	}
	flows := s.vipFlowRules(candidate, state.zone, state.groupID)
	if err := s.deps.Controller.InstallFlows(s.cfg.Bridge, flows); err != nil {
		return &OpError{Op: "install", Err: err}
	}

	healthy := make(map[netip.AddrPort]bool, len(backends))
	for _, b := range backends {
		ap := b.addrPort()
		if prev, seen := state.healthy[ap]; seen {
			healthy[ap] = prev
		} else {
			healthy[ap] = true
		}
	}

	prevVIP, prevHealthy := state.vip, state.healthy
	state.vip = candidate
	state.healthy = healthy
	if err := s.deps.Groups.ModifyGroup(ctx, s.cfg.Bridge, s.groupMod(state)); err != nil {
		state.vip = prevVIP
		state.healthy = prevHealthy
		// The old backends' flows are all still installed; only the new
		// ones' reply diverts have to come back out.
		if delErr := s.deleteFlowsLocked(ctx, staleFlows(flows, state.flows)); delErr != nil {
			return &OpError{Op: "group-modify", Err: errors.Join(err, delErr)}
		}
		return &OpError{Op: "group-modify", Err: err}
	}
	if err := s.deleteFlowsLocked(ctx, staleFlows(state.flows, flows)); err != nil {
		return err
	}
	state.flows = flows
	s.lastReconcile = time.Now()
	return nil
}

// staleFlows returns the rules in from that keep is not installing again.
// A rule is identified as OVS identifies it for a strict delete: table,
// priority and match.
func staleFlows(from, keep []zoneflows.FlowRule) []zoneflows.FlowRule {
	type identity struct {
		table, priority int
		match           string
	}
	kept := make(map[identity]struct{}, len(keep))
	for _, r := range keep {
		kept[identity{r.Table, r.Priority, r.Match}] = struct{}{}
	}
	var out []zoneflows.FlowRule
	for _, r := range from {
		if _, ok := kept[identity{r.Table, r.Priority, r.Match}]; !ok {
			out = append(out, r)
		}
	}
	return out
}

// deleteFlowsLocked strict-deletes rules. The caller holds s.mu.
func (s *Service) deleteFlowsLocked(ctx context.Context, rules []zoneflows.FlowRule) error {
	for _, rule := range rules {
		if err := s.deps.OVS.DeleteFlowStrict(ctx, s.cfg.Bridge, &ovs.FlowMod{
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

// SetBackendHealth marks a backend healthy or unhealthy and rebuilds the
// VIP's select group from the healthy set. All backends down produces a
// bucketless group: new connections drop (fail closed) while established
// connections continue via conntrack.
func (s *Service) SetBackendHealth(ctx context.Context, protocol string, addr netip.AddrPort, backend netip.AddrPort, healthy bool) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.active {
		return ErrNotStarted
	}
	key := vipKey{proto: protocol, addr: addr.Addr(), port: addr.Port()}
	state, ok := s.vips[key]
	if !ok {
		return ErrVIPNotFound
	}
	current, tracked := state.healthy[backend]
	if !tracked {
		return ErrBackendNotFound
	}
	if current == healthy {
		return nil
	}

	state.healthy[backend] = healthy
	if err := s.deps.Groups.ModifyGroup(ctx, s.cfg.Bridge, s.groupMod(state)); err != nil {
		state.healthy[backend] = current
		return &OpError{Op: "group-modify", Err: err}
	}

	s.deps.Logger.Info("load balancer backend health transition",
		slog.String("vip", key.String()),
		slog.String("backend", backend.String()),
		slog.Bool("healthy", healthy),
		slog.Int("healthy_backends", len(state.healthyBackends())),
	)
	return nil
}

// Reconcile re-converges the datapath against the in-memory VIP set:
// scaffolding and VIP flows are re-installed (OFPFC_ADD replaces identical
// match+priority entries) and every select group is rebuilt from its
// current healthy set.
func (s *Service) Reconcile(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.active {
		return ErrNotStarted
	}

	rules := s.baseRules()
	for _, state := range s.vips {
		rules = append(rules, state.flows...)
	}
	rules = append(rules, s.gateRule())
	if err := s.deps.Controller.InstallFlows(s.cfg.Bridge, rules); err != nil {
		return &OpError{Op: "reconcile", Err: err}
	}

	for _, state := range s.vips {
		if err := s.deps.Groups.ModifyGroup(ctx, s.cfg.Bridge, s.groupMod(state)); err != nil {
			return &OpError{Op: "reconcile", Err: err}
		}
	}

	s.lastReconcile = time.Now()
	s.deps.Logger.Info("load balancer service reconciled",
		slog.String("bridge", s.cfg.Bridge),
		slog.Int("vips", len(s.vips)),
	)
	return nil
}

// Active reports whether the service is started.
func (s *Service) Active() bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.active
}

// Health returns a snapshot of the service state.
func (s *Service) Health() Health {
	s.mu.Lock()
	defer s.mu.Unlock()

	h := Health{
		Active:        s.active,
		VIPCount:      len(s.vips),
		LastReconcile: s.lastReconcile,
	}
	for _, state := range s.vips {
		h.TotalBackends += len(state.vip.Backends)
		h.HealthyBackends += len(state.healthyBackends())
	}
	return h
}

// statusLocked builds the status snapshot for a VIP. The caller holds s.mu.
func (s *Service) statusLocked(state *vipState) VIPStatus {
	vip := state.vip
	vip.Algorithm = s.effectiveAlgorithm(vip)
	status := VIPStatus{
		VIP:      vip,
		CTZone:   state.zone,
		GroupID:  state.groupID,
		Backends: make([]BackendStatus, 0, len(state.vip.Backends)),
	}
	for _, b := range state.vip.Backends {
		status.Backends = append(status.Backends, BackendStatus{
			Backend: b,
			Healthy: state.healthy[b.addrPort()],
		})
	}
	return status
}

// probeTargets snapshots the TCP backends of every VIP for the prober. UDP
// VIPs are excluded: they carry no probeable liveness signal and stay
// always healthy.
func (s *Service) probeTargets() []probeTarget {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.active {
		return nil
	}
	var targets []probeTarget
	for key, state := range s.vips {
		if key.proto != ProtocolTCP {
			continue
		}
		for _, b := range state.vip.Backends {
			targets = append(targets, probeTarget{
				vip:     key,
				backend: b.addrPort(),
			})
		}
	}
	return targets
}

// applyProbeResult is the prober's transition callback: it flips the
// backend's health and rebuilds the VIP group.
func (s *Service) applyProbeResult(ctx context.Context, target probeTarget, healthy bool) {
	err := s.SetBackendHealth(ctx, target.vip.proto,
		netip.AddrPortFrom(target.vip.addr, target.vip.port), target.backend, healthy)
	if err != nil && !errors.Is(err, ErrNotStarted) && !errors.Is(err, ErrVIPNotFound) && !errors.Is(err, ErrBackendNotFound) {
		s.deps.Logger.Error("load balancer health transition failed",
			slog.String("vip", target.vip.String()),
			slog.String("backend", target.backend.String()),
			slog.Bool("healthy", healthy),
			slog.String("error", err.Error()),
		)
	}
}
