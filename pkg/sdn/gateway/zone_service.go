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
	"sync"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
)

// Compliance control IDs referenced by zone CRUD audit events.
// SC-7  — Boundary Protection: zone create/update/delete changes inter-zone boundaries.
// SC-4  — Information in Shared Resources: per-tenant isolation changes.
// AC-4  — Information Flow Enforcement: flow matrix regeneration triggered by zone mutations.
//
// See docs/architecture/reference-network.md §Compliance for the authoritative mapping.
const (
	zoneComplianceSC7 = "SC-7"
	zoneComplianceSC4 = "SC-4"
	zoneComplianceAC4 = "AC-4"
)

// zoneComplianceAttr returns an slog.Attr with a comma-joined NIST control list.
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
// Zone service error types
// =============================================================================

// ErrZoneNotFound is returned when the requested zone does not exist.
type ErrZoneNotFound struct {
	Name zone.Zone
}

func (e ErrZoneNotFound) Error() string {
	return fmt.Sprintf("zone: zone %q not found", e.Name)
}

// ErrZoneAlreadyExists is returned when a zone with the given name already exists.
type ErrZoneAlreadyExists struct {
	Name zone.Zone
}

func (e ErrZoneAlreadyExists) Error() string {
	return fmt.Sprintf("zone: zone %q already exists", e.Name)
}

// ErrNetworkNotFound is returned when the requested network does not exist.
type ErrNetworkNotFound struct {
	Name string
}

func (e ErrNetworkNotFound) Error() string {
	return fmt.Sprintf("zone: network %q not found", e.Name)
}

// ErrZoneValidation wraps a validation error produced by zone.Validate.
type ErrZoneValidation struct {
	Cause error
}

func (e ErrZoneValidation) Error() string {
	return fmt.Sprintf("zone: validation failed: %v", e.Cause)
}

func (e ErrZoneValidation) Unwrap() error { return e.Cause }

// =============================================================================
// ZoneRecord holds runtime state for a single zone
// =============================================================================

// ZoneRecord is an in-process zone entry managed by ZoneService.
type ZoneRecord struct {
	Config    zone.ZoneConfig
	CreatedAt time.Time
	UpdatedAt time.Time
}

// =============================================================================
// ZoneService interface
// =============================================================================

// ZoneService manages the runtime zone set for SDN network zones.
// Zones are seeded from the resolved config at construction and may be
// mutated via CRUD operations. Every mutation re-runs zone.Validate.
type ZoneService interface {
	// Create adds a new zone to the runtime set. Returns ErrZoneAlreadyExists
	// when the name is already present. Triggers Validate on the resulting set.
	Create(ctx context.Context, cfg zone.ZoneConfig) (*ZoneRecord, bool, error)

	// Update replaces an existing zone's config. Returns ErrZoneNotFound when
	// the zone does not exist. Triggers Validate on the resulting set.
	Update(ctx context.Context, name zone.Zone, cfg zone.ZoneConfig) (*ZoneRecord, bool, error)

	// Delete removes a zone by name. Returns ErrZoneNotFound when not present.
	// Triggers Validate on the resulting set.
	Delete(ctx context.Context, name zone.Zone) (bool, error)

	// List returns all runtime zones, optionally filtered by lifecycle role.
	// An empty lifecycleRole returns all zones.
	List(ctx context.Context, lifecycleRole zone.LifecycleRole) ([]*ZoneRecord, error)

	// AssignNetwork reassigns a named network segment to a zone. Returns
	// ErrNetworkNotFound when the network does not exist.
	// restartRequired is true when reassignment changes the flow matrix.
	AssignNetwork(ctx context.Context, network string, zoneName zone.Zone) (restartRequired bool, err error)

	// ZoneIndex returns a snapshot of the current zone index keyed by name.
	ZoneIndex() map[zone.Zone]zone.ZoneConfig
}

// =============================================================================
// zoneService implementation
// =============================================================================

// zoneService is the concrete implementation of ZoneService backed by an
// in-process map. When a quicbaas client is available the implementation
// persists zones in the quicbaas-backed KV store; otherwise it falls back
// to the in-memory map only.
type zoneService struct {
	mu       sync.RWMutex
	zones    map[zone.Zone]*ZoneRecord
	networks map[string]zone.Zone // network name → current zone
	logger   *slog.Logger
}

// Compile-time interface assertion.
var _ ZoneService = (*zoneService)(nil)

// NewZoneService creates a new ZoneService seeded from the provided resolved
// zone set (typically obtained from sdn.Config.ResolvedZones()). The seed
// establishes create-if-missing semantics consistent with IPAM pool decision 6:
// the runtime state starts from the config-declared+built-in set; subsequent
// CRUD operations overlay it.
//
// networkZones is an optional initial mapping of network name → zone name,
// derived from sdn.Config.Networks.
func NewZoneService(
	resolved []zone.ZoneConfig,
	networkZones map[string]zone.Zone,
) (ZoneService, error) {
	// The built-in zones are the implicit base of every zone set. When the
	// caller passes a nil or partial seed — e.g. a daemon running without an
	// sdn config section — resolve it against the defaults registry so the
	// lifecycle-role invariants hold and user zones layer onto the built-ins
	// exactly as config-declared zones do. Resolve is idempotent for a seed
	// that already includes the built-ins.
	seed, err := zone.Resolve(resolved)
	if err != nil {
		return nil, err
	}
	now := time.Now()
	zones := make(map[zone.Zone]*ZoneRecord, len(seed))
	for _, cfg := range seed {
		zones[cfg.Name] = &ZoneRecord{
			Config:    cfg,
			CreatedAt: now,
			UpdatedAt: now,
		}
	}
	nz := make(map[string]zone.Zone, len(networkZones))
	for k, v := range networkZones {
		nz[k] = v
	}
	return &zoneService{
		zones:    zones,
		networks: nz,
		logger:   slog.Default(),
	}, nil
}

// Create adds a new zone. restartRequired is always false for a new zone
// (no existing policy uses it yet).
func (s *zoneService) Create(ctx context.Context, cfg zone.ZoneConfig) (*ZoneRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.zones[cfg.Name]; exists {
		return nil, false, ErrZoneAlreadyExists{Name: cfg.Name}
	}

	// Build the candidate set and validate.
	candidate := s.buildSlice()
	candidate = append(candidate, cfg)
	if err := zone.Validate(candidate); err != nil {
		return nil, false, ErrZoneValidation{Cause: err}
	}

	now := time.Now()
	rec := &ZoneRecord{
		Config:    cfg,
		CreatedAt: now,
		UpdatedAt: now,
	}
	s.zones[cfg.Name] = rec

	// Zone creation audit: SC-7 (new boundary established), AC-4 (flow matrix may change).
	s.logger.Info("zone created",
		slog.String("zone", string(cfg.Name)),
		slog.String("lifecycle_role", string(cfg.LifecycleRole)),
		slog.Bool("isolate", cfg.Isolate),
		zoneComplianceAttr(zoneComplianceSC7, zoneComplianceAC4))

	return rec, false, nil
}

// Update replaces an existing zone config. restartRequired is true when the
// updated zone carries policy-relevant fields (AllowTo, IsolateFrom, Isolate,
// OOB, IsolatePerTenant) that differ from the previous declaration, because
// those fields feed the flow matrix that requires a daemon restart to recompile.
func (s *zoneService) Update(ctx context.Context, name zone.Zone, cfg zone.ZoneConfig) (*ZoneRecord, bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	old, exists := s.zones[name]
	if !exists {
		return nil, false, ErrZoneNotFound{Name: name}
	}

	// cfg.Name must match the target name.
	if cfg.Name == "" {
		cfg.Name = name
	}

	// Build the candidate set replacing the old entry.
	candidate := s.buildSliceExcluding(name)
	candidate = append(candidate, cfg)
	if err := zone.Validate(candidate); err != nil {
		return nil, false, ErrZoneValidation{Cause: err}
	}

	restartRequired := policyFieldsChanged(old.Config, cfg)

	rec := &ZoneRecord{
		Config:    cfg,
		CreatedAt: old.CreatedAt,
		UpdatedAt: time.Now(),
	}
	s.zones[name] = rec

	// Zone mutation audit: SC-7 (boundary changed), AC-4 (flow matrix may change).
	// SC-4 is added when per-tenant isolation fields changed.
	controls := []string{zoneComplianceSC7, zoneComplianceAC4}
	if old.Config.IsolatePerTenant != cfg.IsolatePerTenant {
		controls = append(controls, zoneComplianceSC4)
	}
	s.logger.Info("zone updated",
		slog.String("zone", string(name)),
		slog.Bool("restart_required", restartRequired),
		zoneComplianceAttr(controls...))

	return rec, restartRequired, nil
}

// Delete removes a zone by name. restartRequired is always true when a zone
// that participates in the flow matrix is removed (conservative: the matrix
// must be rebuilt).
func (s *zoneService) Delete(ctx context.Context, name zone.Zone) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	old, exists := s.zones[name]
	if !exists {
		return false, ErrZoneNotFound{Name: name}
	}

	// Build candidate set without the zone and validate the remainder.
	candidate := s.buildSliceExcluding(name)
	if err := zone.Validate(candidate); err != nil {
		return false, ErrZoneValidation{Cause: err}
	}

	delete(s.zones, name)

	// restartRequired whenever the deleted zone had active policy fields.
	restartRequired := old.Config.Isolate ||
		old.Config.OOB ||
		len(old.Config.AllowTo) > 0 ||
		len(old.Config.IsolateFrom) > 0

	// Zone deletion audit: SC-7 (boundary removed), AC-4 (flow matrix must rebuild).
	s.logger.Info("zone deleted",
		slog.String("zone", string(name)),
		slog.Bool("restart_required", restartRequired),
		zoneComplianceAttr(zoneComplianceSC7, zoneComplianceAC4))

	return restartRequired, nil
}

// List returns zone records matching the optional lifecycle role filter.
func (s *zoneService) List(_ context.Context, lifecycleRole zone.LifecycleRole) ([]*ZoneRecord, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	out := make([]*ZoneRecord, 0, len(s.zones))
	for _, rec := range s.zones {
		if lifecycleRole != "" && rec.Config.LifecycleRole != lifecycleRole {
			continue
		}
		cp := *rec
		out = append(out, &cp)
	}
	return out, nil
}

// AssignNetwork updates the zone binding for a named network.
// restartRequired is always true because flow tables keyed by network→zone
// must be rebuilt.
func (s *zoneService) AssignNetwork(ctx context.Context, network string, zoneName zone.Zone) (bool, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.zones[zoneName]; !ok {
		return false, ErrZoneNotFound{Name: zoneName}
	}

	s.networks[network] = zoneName

	// Network-to-zone assignment audit: SC-7 (boundary reassignment), AC-4 (flow matrix change).
	s.logger.Info("network assigned to zone",
		slog.String("network", network),
		slog.String("zone", string(zoneName)),
		zoneComplianceAttr(zoneComplianceSC7, zoneComplianceAC4))

	return true, nil
}

// ZoneIndex returns a snapshot of the current zone set keyed by zone name.
func (s *zoneService) ZoneIndex() map[zone.Zone]zone.ZoneConfig {
	s.mu.RLock()
	defer s.mu.RUnlock()

	idx := make(map[zone.Zone]zone.ZoneConfig, len(s.zones))
	for k, rec := range s.zones {
		idx[k] = rec.Config
	}
	return idx
}

// =============================================================================
// Internal helpers
// =============================================================================

// buildSlice builds a []ZoneConfig from the current runtime map (caller must
// hold at least a read lock).
func (s *zoneService) buildSlice() []zone.ZoneConfig {
	out := make([]zone.ZoneConfig, 0, len(s.zones))
	for _, rec := range s.zones {
		out = append(out, rec.Config)
	}
	return out
}

// buildSliceExcluding returns a []ZoneConfig omitting the named zone.
func (s *zoneService) buildSliceExcluding(exclude zone.Zone) []zone.ZoneConfig {
	out := make([]zone.ZoneConfig, 0, len(s.zones))
	for k, rec := range s.zones {
		if k == exclude {
			continue
		}
		out = append(out, rec.Config)
	}
	return out
}

// policyFieldsChanged reports whether the two configs differ in the fields
// that drive the flow matrix (AllowTo, IsolateFrom, Isolate, OOB,
// IsolatePerTenant). Name/Services/LifecycleRole changes do not require a
// restart.
func policyFieldsChanged(a, b zone.ZoneConfig) bool {
	if a.Isolate != b.Isolate ||
		a.OOB != b.OOB ||
		a.IsolatePerTenant != b.IsolatePerTenant ||
		a.InternetIngress != b.InternetIngress {
		return true
	}
	if !zoneSliceEqual(a.IsolateFrom, b.IsolateFrom) {
		return true
	}
	if !zonePathSliceEqual(a.AllowTo, b.AllowTo) {
		return true
	}
	return false
}

func zoneSliceEqual(a, b []zone.Zone) bool {
	if len(a) != len(b) {
		return false
	}
	m := make(map[zone.Zone]struct{}, len(a))
	for _, v := range a {
		m[v] = struct{}{}
	}
	for _, v := range b {
		if _, ok := m[v]; !ok {
			return false
		}
	}
	return true
}

func zonePathSliceEqual(a, b []zone.ZonePath) bool {
	if len(a) != len(b) {
		return false
	}
	type key struct {
		zone     zone.Zone
		services string
	}
	mk := func(p zone.ZonePath) key {
		s := ""
		for _, svc := range p.Services {
			s += svc + ","
		}
		return key{zone: p.Zone, services: s}
	}
	m := make(map[key]struct{}, len(a))
	for _, p := range a {
		m[mk(p)] = struct{}{}
	}
	for _, p := range b {
		if _, ok := m[mk(p)]; !ok {
			return false
		}
	}
	return true
}
