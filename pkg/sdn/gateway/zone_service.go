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

package gateway

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/netplan"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// Compliance control IDs referenced by zone CRUD audit events.
// SC-7  — Boundary Protection: zone create/update/delete changes inter-zone boundaries.
// AC-4  — Information Flow Enforcement: flow matrix regeneration triggered by zone mutations.
// AU-2  — Event Logging: a privileged path into control-plane or management is opened.
const (
	zoneComplianceSC7 = "SC-7"
	zoneComplianceAC4 = "AC-4"
	zoneComplianceAU2 = "AU-2"
)

// zoneComplianceAttr returns a slog attribute naming the compliance controls
// an audit event satisfies.
func zoneComplianceAttr(controls ...string) slog.Attr {
	v := ""
	for i, c := range controls {
		if i > 0 {
			v += ","
		}
		v += c
	}
	return slog.String("compliance", v)
}

// =============================================================================
// Errors
// =============================================================================

// ErrZoneNotFound is returned when the requested zone does not exist.
type ErrZoneNotFound struct {
	Name zone.Zone
}

// Error implements the error interface.
func (e ErrZoneNotFound) Error() string {
	return fmt.Sprintf("zone: zone %q not found", e.Name)
}

// ErrZoneAlreadyExists is returned when a zone with the given name already
// exists. Built-in zones always exist: tune one with Update instead.
type ErrZoneAlreadyExists struct {
	Name zone.Zone
}

// Error implements the error interface.
func (e ErrZoneAlreadyExists) Error() string {
	return fmt.Sprintf("zone: zone %q already exists", e.Name)
}

// ErrZoneValidation wraps a validation error produced by zone.Resolve,
// zone.Validate or netplan.New on the candidate zone set.
type ErrZoneValidation struct {
	Cause error
}

// Error implements the error interface.
func (e ErrZoneValidation) Error() string {
	return fmt.Sprintf("zone: validation failed: %v", e.Cause)
}

// Unwrap returns the underlying validation error.
func (e ErrZoneValidation) Unwrap() error { return e.Cause }

// =============================================================================
// ZoneRecord holds runtime state for a single zone
// =============================================================================

// ZoneRecord is an in-process zone entry managed by ZoneService. Config is
// the resolved zone (a built-in with its tuned policy, or an owner-defined
// zone). Numbering is the zone's derived numbering; it is nil when the
// service has no environment.
type ZoneRecord struct {
	Config    zone.ZoneConfig
	Numbering *netplan.ZoneNumbering
	CreatedAt time.Time
	UpdatedAt time.Time
}

// =============================================================================
// ZoneService interface
// =============================================================================

// ZoneService manages the runtime zone set: the nine built-in underlay
// zones with their tuned policy, plus owner-defined zones at offsets 9-99.
// Every mutation re-resolves the operator entries onto the built-ins and
// re-runs zone.Validate and, when the service has an environment,
// netplan.New, so a mutation that breaks the policy invariants or the
// numbering is refused. The network plan is derived at daemon startup, so
// every accepted mutation reports restartRequired.
type ZoneService interface {
	// Create adds an owner-defined zone. Returns ErrZoneAlreadyExists when
	// the name is present (built-in zones always are).
	Create(ctx context.Context, cfg zone.ZoneConfig) (*ZoneRecord, bool, error)

	// Update tunes a built-in zone's policy or replaces an owner-defined
	// zone. Returns ErrZoneNotFound when the zone does not exist.
	Update(ctx context.Context, name zone.Zone, cfg zone.ZoneConfig) (*ZoneRecord, bool, error)

	// Delete removes an owner-defined zone, or omits an optional built-in
	// (the built-ins the platform needs cannot be removed). Returns
	// ErrZoneNotFound when the zone does not exist.
	Delete(ctx context.Context, name zone.Zone) (bool, error)

	// List returns all zones in offset order, optionally filtered by
	// lifecycle role. An empty lifecycleRole returns all zones.
	List(ctx context.Context, lifecycleRole zone.LifecycleRole) ([]*ZoneRecord, error)

	// ZoneIndex returns a snapshot of the current zone set keyed by name.
	ZoneIndex() map[zone.Zone]zone.ZoneConfig
}

// =============================================================================
// zoneService implementation
// =============================================================================

// zoneService is the concrete in-process implementation of ZoneService.
// entries are the operator entries (tuned built-ins, omissions and
// owner-defined zones); resolved is entries merged onto the built-ins.
type zoneService struct {
	mu        sync.RWMutex
	env       *netplan.Environment
	entries   []zone.ZoneConfig
	resolved  []zone.ZoneConfig
	plan      *netplan.Plan
	createdAt map[zone.Zone]time.Time
	updatedAt map[zone.Zone]time.Time
	logger    *slog.Logger
}

// Compile-time interface assertion.
var _ ZoneService = (*zoneService)(nil)

// NewZoneService creates a ZoneService seeded with the configured operator
// zone entries (sdn.zones, or the resolved set — resolving a resolved set is
// a no-op). env is the node's environment (sdn.environment); when non-nil
// every candidate set is also numbered with netplan.New and the records
// carry their numbering. A nil seed yields the built-in set.
func NewZoneService(seed []zone.ZoneConfig, env *netplan.Environment) (ZoneService, error) {
	s := &zoneService{
		env:       env,
		createdAt: make(map[zone.Zone]time.Time),
		updatedAt: make(map[zone.Zone]time.Time),
		logger:    slog.Default(),
	}
	entries := cloneZones(seed)
	resolved, plan, err := s.derive(entries)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	s.commit(entries, resolved, plan, now)
	for _, z := range resolved {
		s.createdAt[z.Name] = now
	}
	return s, nil
}

// derive resolves entries onto the built-ins, validates the result and,
// when the service has an environment, derives its plan.
func (s *zoneService) derive(entries []zone.ZoneConfig) ([]zone.ZoneConfig, *netplan.Plan, error) {
	resolved, err := zone.Resolve(entries)
	if err != nil {
		return nil, nil, ErrZoneValidation{Cause: err}
	}
	if err := zone.Validate(resolved); err != nil {
		return nil, nil, ErrZoneValidation{Cause: err}
	}
	if s.env == nil {
		return resolved, nil, nil
	}
	plan, err := netplan.New(*s.env, resolved)
	if err != nil {
		return nil, nil, ErrZoneValidation{Cause: err}
	}
	return resolved, plan, nil
}

// commit installs a validated candidate (caller holds the write lock).
func (s *zoneService) commit(entries, resolved []zone.ZoneConfig, plan *netplan.Plan, now time.Time) {
	s.entries = entries
	s.resolved = resolved
	s.plan = plan
	for _, z := range resolved {
		if _, ok := s.createdAt[z.Name]; !ok {
			s.createdAt[z.Name] = now
		}
	}
}

// Create adds an owner-defined zone.
func (s *zoneService) Create(_ context.Context, cfg zone.ZoneConfig) (*ZoneRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.find(cfg.Name); exists {
		return nil, false, ErrZoneAlreadyExists{Name: cfg.Name}
	}
	if cfg.Omit {
		return nil, false, ErrZoneValidation{Cause: zone.ErrOmitUnknown{Zone: cfg.Name}}
	}

	entries := append(cloneZones(s.entries), cfg)
	resolved, plan, err := s.derive(entries)
	if err != nil {
		return nil, false, err
	}
	now := time.Now()
	s.commit(entries, resolved, plan, now)
	s.createdAt[cfg.Name] = now
	s.updatedAt[cfg.Name] = now

	rec := s.record(cfg.Name)
	s.logger.Info("zone created",
		slog.Bool("audit", true),
		slog.String("zone", string(cfg.Name)),
		slog.Int("offset", int(rec.Config.Offset)),
		slog.Bool("isolate", rec.Config.Isolate),
		slog.Bool("restart_required", true),
		zoneComplianceAttr(zoneComplianceSC7, zoneComplianceAC4))
	s.logPrivileged(rec.Config)
	return rec, true, nil
}

// Update tunes a built-in or replaces an owner-defined zone.
func (s *zoneService) Update(_ context.Context, name zone.Zone, cfg zone.ZoneConfig) (*ZoneRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.find(name); !exists {
		return nil, false, ErrZoneNotFound{Name: name}
	}
	if cfg.Name == "" {
		cfg.Name = name
	}
	if cfg.Name != name {
		return nil, false, ErrZoneValidation{Cause: zone.ErrInvalidZoneName{Name: cfg.Name}}
	}
	if cfg.Omit {
		return nil, false, ErrZoneValidation{Cause: zone.ErrOmitUnknown{Zone: cfg.Name}}
	}

	entries := replaceEntry(s.entries, cfg)
	resolved, plan, err := s.derive(entries)
	if err != nil {
		return nil, false, err
	}
	now := time.Now()
	s.commit(entries, resolved, plan, now)
	s.updatedAt[name] = now

	rec := s.record(name)
	s.logger.Info("zone updated",
		slog.Bool("audit", true),
		slog.String("zone", string(name)),
		slog.Bool("restart_required", true),
		zoneComplianceAttr(zoneComplianceSC7, zoneComplianceAC4))
	s.logPrivileged(rec.Config)
	return rec, true, nil
}

// Delete removes an owner-defined zone or omits an optional built-in.
func (s *zoneService) Delete(_ context.Context, name zone.Zone) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.find(name); !exists {
		return false, ErrZoneNotFound{Name: name}
	}

	var entries []zone.ZoneConfig
	if zone.IsBuiltin(name) {
		entries = replaceEntry(s.entries, zone.ZoneConfig{Name: name, Omit: true})
	} else {
		entries = removeEntry(s.entries, name)
	}
	resolved, plan, err := s.derive(entries)
	if err != nil {
		return false, err
	}
	s.commit(entries, resolved, plan, time.Now())
	delete(s.createdAt, name)
	delete(s.updatedAt, name)

	s.logger.Info("zone deleted",
		slog.Bool("audit", true),
		slog.String("zone", string(name)),
		slog.Bool("restart_required", true),
		zoneComplianceAttr(zoneComplianceSC7, zoneComplianceAC4))
	return true, nil
}

// List returns zone records in offset order matching the optional lifecycle
// role filter.
func (s *zoneService) List(_ context.Context, lifecycleRole zone.LifecycleRole) ([]*ZoneRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]*ZoneRecord, 0, len(s.resolved))
	for _, z := range s.resolved {
		if lifecycleRole != "" && z.LifecycleRole != lifecycleRole {
			continue
		}
		out = append(out, s.record(z.Name))
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Config.Offset < out[j].Config.Offset })
	return out, nil
}

// ZoneIndex returns a snapshot of the current zone set keyed by zone name.
func (s *zoneService) ZoneIndex() map[zone.Zone]zone.ZoneConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()

	idx := make(map[zone.Zone]zone.ZoneConfig, len(s.resolved))
	for _, z := range s.resolved {
		idx[z.Name] = cloneZones([]zone.ZoneConfig{z})[0]
	}
	return idx
}

// =============================================================================
// Internal helpers
// =============================================================================

// find returns the resolved zone named name (caller holds a lock).
func (s *zoneService) find(name zone.Zone) (zone.ZoneConfig, bool) {
	for _, z := range s.resolved {
		if z.Name == name {
			return z, true
		}
	}
	return zone.ZoneConfig{}, false
}

// record builds a detached ZoneRecord for the resolved zone name (caller
// holds a lock; the zone must exist).
func (s *zoneService) record(name zone.Zone) *ZoneRecord {
	cfg, _ := s.find(name)
	rec := &ZoneRecord{
		Config:    cloneZones([]zone.ZoneConfig{cfg})[0],
		CreatedAt: s.createdAt[name],
		UpdatedAt: s.updatedAt[name],
	}
	if rec.UpdatedAt.IsZero() {
		rec.UpdatedAt = rec.CreatedAt
	}
	if s.plan != nil {
		if n, ok := s.plan.Zone(name); ok {
			rec.Numbering = &n
		}
	}
	return rec
}

// logPrivileged writes an audit record for every privileged path the
// resolved zone cfg opens.
func (s *zoneService) logPrivileged(cfg zone.ZoneConfig) {
	for _, p := range zone.PrivilegedPaths([]zone.ZoneConfig{cfg}) {
		s.logger.Warn("zone: privileged path opened by an audited override",
			slog.Bool("audit", true),
			slog.String("from", string(p.From)),
			slog.String("to", string(p.To)),
			slog.Any("services", p.Services),
			slog.String("reason", p.Access.Reason),
			slog.String("approved_by", p.Access.ApprovedBy),
			zoneComplianceAttr(zoneComplianceAU2, zoneComplianceAC4))
	}
}

// replaceEntry returns entries with the entry named cfg.Name replaced by cfg
// (or cfg appended when absent).
func replaceEntry(entries []zone.ZoneConfig, cfg zone.ZoneConfig) []zone.ZoneConfig {
	out := make([]zone.ZoneConfig, 0, len(entries)+1)
	replaced := false
	for _, e := range entries {
		if e.Name == cfg.Name {
			out = append(out, cfg)
			replaced = true
			continue
		}
		out = append(out, e)
	}
	if !replaced {
		out = append(out, cfg)
	}
	return cloneZones(out)
}

// removeEntry returns entries without the entry named name.
func removeEntry(entries []zone.ZoneConfig, name zone.Zone) []zone.ZoneConfig {
	out := make([]zone.ZoneConfig, 0, len(entries))
	for _, e := range entries {
		if e.Name != name {
			out = append(out, e)
		}
	}
	return cloneZones(out)
}

// cloneZones deep-copies a zone slice so callers never alias service state.
func cloneZones(in []zone.ZoneConfig) []zone.ZoneConfig {
	out := make([]zone.ZoneConfig, len(in))
	for i, z := range in {
		c := z
		c.PortClasses = append([]zone.PortClass(nil), z.PortClasses...)
		c.IsolateFrom = append([]zone.Zone(nil), z.IsolateFrom...)
		c.Services = append([]string(nil), z.Services...)
		c.AllowTo = make([]zone.ZonePath, len(z.AllowTo))
		for j, p := range z.AllowTo {
			c.AllowTo[j] = zone.ZonePath{Zone: p.Zone, Services: append([]string(nil), p.Services...)}
		}
		if len(z.AllowTo) == 0 {
			c.AllowTo = z.AllowTo
		}
		if z.PrivilegedAccess != nil {
			pa := *z.PrivilegedAccess
			c.PrivilegedAccess = &pa
		}
		out[i] = c
	}
	return out
}
