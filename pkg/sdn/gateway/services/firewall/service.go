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

// Package firewall implements the OVS-native stateful firewall and NAT
// gateway services. Enforcement is entirely in the OVS datapath via the
// conntrack pipeline (tables 20/21/25); this package only compiles the zone
// matrix into flows and manages their lifecycle. See
// docs/sdn/firewall/architecture.md for the table design.
package firewall

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ct"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/modes"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy/zoneflows"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// Flow cookies identifying firewall-owned and NAT-owned flows. The high 32
// bits are the owner prefix used with CookieMask for bulk deletion; the low
// 32 bits are free for future per-rule tagging.
const (
	// CookieFirewall tags every flow installed by the firewall Service.
	CookieFirewall uint64 = 0xF1BE000100000000

	// CookieNAT tags every flow installed by the NAT service.
	CookieNAT uint64 = 0xF1BE000200000000

	// CookieMask selects the owner prefix of CookieFirewall / CookieNAT.
	CookieMask uint64 = 0xFFFFFFFF00000000
)

// Table-10 gate flows. The overlay pipeline's table 10 default (priority 0)
// continues to table 30; the firewall and NAT services divert traffic into
// the conntrack pipeline by installing higher-priority table 10 flows they
// own, so the base pipeline is never modified. Distinct priorities keep the
// two gates independent flows in OVS (identical match+priority would make
// the second OFPFC_ADD replace the first, breaking per-service teardown).
const (
	gateTable = int(modes.TableVXLANDecap)

	// firewallGatePriority is the table 10 priority of the firewall gate.
	firewallGatePriority = 2

	// natGatePriority is the table 10 priority of the NAT gate.
	natGatePriority = 1
)

// AllocatorOwnerFirewall is the ct.ZoneAllocator owner name for per-zone
// firewall conntrack zones.
const AllocatorOwnerFirewall = "firewall"

// Deps carries the firewall service dependencies.
type Deps struct {
	// Controller installs and deletes flows (the shared policy flow path).
	Controller policy.FlowController

	// OVS provides cookie-scoped and strict flow deletion plus OF port
	// resolution; flow installation goes through Controller.
	OVS ovs.ClientInterface

	// Config is the firewall configuration.
	Config Config

	// Zones returns the current resolved zone set (hot-refreshable; called
	// on every Start and Reconcile).
	Zones func() []zone.ZoneConfig

	// Networks returns the current zone → VLAN/subnet summary map
	// (hot-refreshable; called on every Start and Reconcile).
	Networks func() map[zone.Zone]zoneflows.NetworkSummary

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
	if d.Allocator == nil {
		return ErrNilAllocator
	}
	if d.Zones == nil {
		return ErrNilZones
	}
	if d.Networks == nil {
		return ErrNilNetworks
	}
	return d.Config.Validate()
}

// flowKey identifies an installed flow for reconciliation diffs.
type flowKey struct {
	table    int
	priority int
	match    string
}

// key builds the reconciliation key for a rule.
func key(rule zoneflows.FlowRule) flowKey {
	return flowKey{table: rule.Table, priority: rule.Priority, match: rule.Match}
}

// Health is a point-in-time snapshot of the firewall service state.
type Health struct {
	// Active reports whether the service is started.
	Active bool

	// FlowCount is the number of conntrack pipeline flows currently
	// installed (excluding the table 10 gate).
	FlowCount int

	// LastReconcile is when flows were last compiled and installed.
	LastReconcile time.Time

	// CTZones maps zone names to their allocated conntrack zone IDs.
	CTZones map[string]uint16
}

// Service is the OVS-native stateful firewall. Start compiles the zone
// matrix into the conntrack pipeline (tables 20/21) and diverts table 10
// into it; Stop removes the gate first and then every firewall-owned flow.
type Service struct {
	deps   Deps
	cookie string

	mu            sync.Mutex
	active        bool
	installed     map[flowKey]zoneflows.FlowRule
	ctZones       map[zone.Zone]uint16
	lastReconcile time.Time
}

// New creates a firewall Service, validating every dependency.
func New(deps Deps) (*Service, error) {
	if err := deps.validate(); err != nil {
		return nil, err
	}
	if deps.Logger == nil {
		deps.Logger = slog.Default()
	}
	return &Service{
		deps:   deps,
		cookie: fmt.Sprintf("0x%x", CookieFirewall),
	}, nil
}

// gateRule is the table 10 flow that diverts traffic into the conntrack
// gate (table 20).
func (s *Service) gateRule() zoneflows.FlowRule {
	return zoneflows.FlowRule{
		Table:    gateTable,
		Priority: firewallGatePriority,
		Actions:  fmt.Sprintf("goto_table:%d", modes.TableCTGate),
		Cookie:   s.cookie,
	}
}

// compile derives the current conntrack rule set from the zone providers,
// allocating conntrack zones for any zone not yet seen.
func (s *Service) compile(ctx context.Context) ([]zoneflows.FlowRule, map[zone.Zone]uint16, error) {
	zones := s.deps.Zones()
	networks := s.deps.Networks()

	ctZones := make(map[zone.Zone]uint16, len(zones))
	for _, z := range zones {
		net, ok := networks[z.Name]
		if !ok || net.VLAN == 0 {
			continue
		}
		id, err := s.deps.Allocator.Allocate(ctx, AllocatorOwnerFirewall, string(z.Name))
		if err != nil {
			return nil, nil, &OpError{Op: "allocate", Err: err}
		}
		ctZones[z.Name] = id
	}

	cfg := zoneflows.MatrixRuleConfig{
		Matrix:         zone.CompileMatrix(zones),
		Zones:          zones,
		NetworksByZone: networks,
		DefaultPolicy:  s.deps.Config.DefaultPolicy,
	}

	rules := zoneflows.CompileStatefulMatrixRules(cfg, ctZones)
	for i := range rules {
		rules[i].Cookie = s.cookie
	}

	return rules, ctZones, nil
}

// Start compiles and installs the conntrack pipeline in one batched
// transaction, then flips the table 10 gate so traffic enters it.
func (s *Service) Start(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.active {
		return ErrAlreadyStarted
	}

	rules, ctZones, err := s.compile(ctx)
	if err != nil {
		return err
	}

	// One batch for the whole pipeline, then the gate. The gate goes last
	// so packets never enter table 20 before its rules exist.
	if err := s.deps.Controller.InstallFlows(s.deps.Config.Bridge, rules); err != nil {
		return &OpError{Op: "install", Err: err}
	}
	if err := s.deps.Controller.InstallFlows(s.deps.Config.Bridge, []zoneflows.FlowRule{s.gateRule()}); err != nil {
		return &OpError{Op: "install", Err: err}
	}

	installed := make(map[flowKey]zoneflows.FlowRule, len(rules))
	for _, rule := range rules {
		installed[key(rule)] = rule
	}

	s.installed = installed
	s.ctZones = ctZones
	s.lastReconcile = time.Now()
	s.active = true

	s.deps.Logger.Info("firewall service started",
		slog.String("bridge", s.deps.Config.Bridge),
		slog.String("default_policy", s.deps.Config.DefaultPolicy),
		slog.Int("flows", len(rules)),
		slog.Int("ct_zones", len(ctZones)),
	)

	return nil
}

// Stop removes the table 10 gate first (so traffic falls back to the base
// pipeline), then deletes every firewall-owned flow by cookie and releases
// the conntrack zones.
func (s *Service) Stop(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.active {
		return ErrNotStarted
	}

	gate := s.gateRule()
	if err := s.deps.OVS.DeleteFlowStrict(ctx, s.deps.Config.Bridge, &ovs.FlowMod{
		Table:    gate.Table,
		Priority: gate.Priority,
		Match:    gate.Match,
		Cookie:   gate.Cookie,
	}); err != nil {
		return &OpError{Op: "delete", Err: err}
	}

	if err := s.deps.OVS.DeleteFlowsByCookie(ctx, s.deps.Config.Bridge, CookieFirewall, CookieMask); err != nil {
		return &OpError{Op: "delete", Err: err}
	}

	var releaseErrs []error
	for name := range s.ctZones {
		if err := s.deps.Allocator.Release(ctx, AllocatorOwnerFirewall, string(name)); err != nil {
			releaseErrs = append(releaseErrs, err)
		}
	}

	s.installed = nil
	s.ctZones = nil
	s.active = false

	s.deps.Logger.Info("firewall service stopped", slog.String("bridge", s.deps.Config.Bridge))

	if len(releaseErrs) > 0 {
		return &OpError{Op: "release", Err: errors.Join(releaseErrs...)}
	}
	return nil
}

// Reconcile recompiles the rule set from the current zone state and
// converges the datapath: changed and missing rules are (re)installed in
// one batch (OFPFC_ADD replaces identical match+priority entries), then
// stale rules are strict-deleted so at no point is the pipeline empty.
func (s *Service) Reconcile(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.active {
		return ErrNotStarted
	}

	rules, ctZones, err := s.compile(ctx)
	if err != nil {
		return err
	}

	desired := make(map[flowKey]zoneflows.FlowRule, len(rules))
	var toInstall []zoneflows.FlowRule
	for _, rule := range rules {
		k := key(rule)
		desired[k] = rule
		existing, ok := s.installed[k]
		if !ok || existing.Actions != rule.Actions {
			toInstall = append(toInstall, rule)
		}
	}

	if err := s.deps.Controller.InstallFlows(s.deps.Config.Bridge, toInstall); err != nil {
		return &OpError{Op: "reconcile", Err: err}
	}

	for k, rule := range s.installed {
		if _, ok := desired[k]; ok {
			continue
		}
		if err := s.deps.OVS.DeleteFlowStrict(ctx, s.deps.Config.Bridge, &ovs.FlowMod{
			Table:    rule.Table,
			Priority: rule.Priority,
			Match:    rule.Match,
			Cookie:   rule.Cookie,
		}); err != nil {
			return &OpError{Op: "reconcile", Err: err}
		}
	}

	s.installed = desired
	s.ctZones = ctZones
	s.lastReconcile = time.Now()

	s.deps.Logger.Info("firewall service reconciled",
		slog.String("bridge", s.deps.Config.Bridge),
		slog.Int("installed", len(toInstall)),
		slog.Int("flows", len(desired)),
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

	ctZones := make(map[string]uint16, len(s.ctZones))
	for name, id := range s.ctZones {
		ctZones[string(name)] = id
	}

	return Health{
		Active:        s.active,
		FlowCount:     len(s.installed),
		LastReconcile: s.lastReconcile,
		CTZones:       ctZones,
	}
}
