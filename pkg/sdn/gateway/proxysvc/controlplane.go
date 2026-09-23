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

package proxysvc

import (
	"context"
	"crypto/tls"
	"log/slog"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/proxy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	sdkproxy "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/proxy"
)

// ControlPlaneClient is the narrow surface of the sdk/go proxy client the
// sync loop consumes. *sdkproxy.Client satisfies it; unit tests inject
// fakes.
type ControlPlaneClient interface {
	// Config returns the full merged platformd proxy configuration plus the
	// version counter.
	Config(ctx context.Context) (*platformv1.GetProxyConfigResponse, error)

	// ZoneMatrix returns the SDN zone names and compiled allowed traffic
	// pairs.
	ZoneMatrix(ctx context.Context) (*platformv1.GetProxyZoneMatrixResponse, error)
}

// Compile-time proof the SDK client satisfies the seam.
var _ ControlPlaneClient = (*sdkproxy.Client)(nil)

// Reloader hot-swaps a validated proxy configuration. *proxy.Engine
// satisfies it.
type Reloader interface {
	Reload(cfg proxy.Config) error
}

// Compile-time proof the engine satisfies the seam.
var _ Reloader = (*proxy.Engine)(nil)

// DialFunc establishes the control-plane client on demand. It is invoked
// lazily from the sync loop so gatewayd starts (and serves its static
// configuration) even when platformd is unreachable at boot.
type DialFunc func(ctx context.Context) (ControlPlaneClient, error)

// LazyControlPlaneClient dials platformd on first use and caches the
// client. Dial failures are returned as *ErrDialFailed and retried on the
// next call; established gRPC connections re-dial transparently.
type LazyControlPlaneClient struct {
	dial   DialFunc
	mu     sync.Mutex
	client ControlPlaneClient
}

// NewLazyControlPlaneClient builds a lazy client around the dial function.
func NewLazyControlPlaneClient(dial DialFunc) (*LazyControlPlaneClient, error) {
	if dial == nil {
		return nil, &ErrNilDialFunc{}
	}
	return &LazyControlPlaneClient{dial: dial}, nil
}

// get returns the cached client, dialing when necessary.
func (l *LazyControlPlaneClient) get(ctx context.Context) (ControlPlaneClient, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.client != nil {
		return l.client, nil
	}
	client, err := l.dial(ctx)
	if err != nil {
		return nil, &ErrDialFailed{Cause: err}
	}
	l.client = client
	return client, nil
}

// Config implements ControlPlaneClient.
func (l *LazyControlPlaneClient) Config(ctx context.Context) (*platformv1.GetProxyConfigResponse, error) {
	client, err := l.get(ctx)
	if err != nil {
		return nil, err
	}
	return client.Config(ctx)
}

// ZoneMatrix implements ControlPlaneClient.
func (l *LazyControlPlaneClient) ZoneMatrix(ctx context.Context) (*platformv1.GetProxyZoneMatrixResponse, error) {
	client, err := l.get(ctx)
	if err != nil {
		return nil, err
	}
	return client.ZoneMatrix(ctx)
}

var _ ControlPlaneClient = (*LazyControlPlaneClient)(nil)

// =============================================================================
// Zone matrix provider
// =============================================================================

// ZoneMatrixProvider holds the compiled inter-zone allow matrix behind an
// atomic pointer so the request hot path (proxy.MatrixProvider) never takes
// a lock. The zero-state matrix denies everything — fail-closed until the
// first successful sync.
type ZoneMatrixProvider struct {
	matrix atomic.Pointer[zone.Matrix]
}

// NewZoneMatrixProvider returns a provider holding the deny-all matrix.
func NewZoneMatrixProvider() *ZoneMatrixProvider {
	p := &ZoneMatrixProvider{}
	empty := zone.CompileMatrix(nil)
	p.matrix.Store(&empty)
	return p
}

// Matrix returns the current compiled matrix. It is the proxy.MatrixProvider
// function injected into the auth chain.
func (p *ZoneMatrixProvider) Matrix() zone.Matrix {
	return *p.matrix.Load()
}

// Update recompiles the matrix from a synced zone-matrix response and swaps
// it in atomically. The platformd response carries the already-compiled
// allowed pairs; Update reconstructs them exactly by declaring every zone
// isolated with the pair set as its explicit AllowTo paths (including self
// pairs), so zone.CompileMatrix reproduces the platformd verdict table
// without re-deriving policy locally.
func (p *ZoneMatrixProvider) Update(resp *platformv1.GetProxyZoneMatrixResponse) {
	if resp == nil {
		return
	}
	paths := make(map[string][]zone.ZonePath, len(resp.GetZones()))
	for _, pair := range resp.GetPairs() {
		paths[pair.GetFrom()] = append(paths[pair.GetFrom()], zone.ZonePath{
			Zone:     zone.Zone(pair.GetTo()),
			Services: append([]string(nil), pair.GetServices()...),
		})
	}
	names := make(map[string]struct{}, len(resp.GetZones()))
	zones := make([]zone.ZoneConfig, 0, len(resp.GetZones()))
	for _, name := range resp.GetZones() {
		names[name] = struct{}{}
		zones = append(zones, zone.ZoneConfig{
			Name:    zone.Zone(name),
			Isolate: true,
			AllowTo: paths[name],
		})
	}
	// Pairs may reference zones absent from the name list; declare them too
	// so their outbound paths compile.
	for from := range paths {
		if _, ok := names[from]; !ok {
			zones = append(zones, zone.ZoneConfig{
				Name:    zone.Zone(from),
				Isolate: true,
				AllowTo: paths[from],
			})
		}
	}
	compiled := zone.CompileMatrix(zones)
	p.matrix.Store(&compiled)
}

// =============================================================================
// Trust resolver adapter
// =============================================================================

// Backend trust classes: what a pool's backend server certificate is
// verified against. These are the only values `tls: trust-class:` accepts.
const (
	// BackendTrustPlatform verifies a backend the platform CA issued — a
	// platform service — against the platform anchor.
	BackendTrustPlatform = "platform"

	// BackendTrustBMC verifies a baseboard management controller through
	// the trust resolver's bmc class.
	BackendTrustBMC = string(trust.ClassBMC)
)

// TrustResolverAdapter adapts the platform anchor and trust resolver
// (pkg/trust) to the proxy.TrustResolver seam consumed by backend pool
// transports.
type TrustResolverAdapter struct {
	resolver trust.Resolver
	anchor   *trust.Anchor
}

// NewTrustResolverAdapter wraps the daemon's trust resolver and platform
// anchor. Either may be nil — a gateway with no `trust:` section verifies
// no BMC backends, and one with no `platform-ca-file:` verifies no platform
// backends — but not both, since the adapter could then verify nothing.
func NewTrustResolverAdapter(resolver trust.Resolver, anchor *trust.Anchor) (*TrustResolverAdapter, error) {
	if resolver == nil && anchor == nil {
		return nil, &ErrNilResolver{}
	}
	return &TrustResolverAdapter{resolver: resolver, anchor: anchor}, nil
}

// ClientTLSConfig implements proxy.TrustResolver. An unknown trust class, or
// one whose trust source this gateway was not given, is a typed error —
// never a fallback to other trust.
func (a *TrustResolverAdapter) ClientTLSConfig(ctx context.Context, trustClass, endpoint string) (*tls.Config, error) {
	switch trustClass {
	case BackendTrustPlatform:
		if a.anchor == nil {
			return nil, &ErrTrustSourceMissing{Class: trustClass, Source: "platform-ca-file:"}
		}
		return a.anchor.TLSConfig(ctx)
	case BackendTrustBMC:
		if a.resolver == nil {
			return nil, &ErrTrustSourceMissing{Class: trustClass, Source: "trust: bmc:"}
		}
		return a.resolver.TLSConfig(ctx, trust.ClassBMC, endpoint)
	default:
		return nil, &ErrUnknownTrustClass{Class: trustClass}
	}
}

var _ proxy.TrustResolver = (*TrustResolverAdapter)(nil)

// =============================================================================
// Config merge
// =============================================================================

// MergeConfig layers the platformd runtime routes and pools over the static
// file configuration. Merge semantics, precisely:
//
//   - Listeners and Defaults always come from the static configuration;
//     they are gatewayd-local concerns platformd never owns.
//   - Routes and pools merge by ID: a platformd route/pool with the same ID
//     as a static one replaces it entirely (platformd runtime configuration
//     wins); platformd entries with new IDs are appended.
//   - Static routes/pools with IDs platformd does not know keep serving —
//     deleting a static entry requires a file change, deleting a runtime
//     entry requires a platformd delete.
//
// Ordering is deterministic: static entries first (file order), then new
// platformd entries (platformd order, which is ID-sorted).
func MergeConfig(static proxy.Config, routes []proxy.RouteConfig, pools []proxy.BackendPoolConfig) proxy.Config {
	merged := static
	merged.Routes = mergeRoutes(static.Routes, routes)
	merged.Pools = mergePools(static.Pools, pools)
	return merged
}

func mergeRoutes(static, runtime []proxy.RouteConfig) []proxy.RouteConfig {
	byID := make(map[string]proxy.RouteConfig, len(runtime))
	for _, r := range runtime {
		byID[r.ID] = r
	}
	out := make([]proxy.RouteConfig, 0, len(static)+len(runtime))
	seen := make(map[string]struct{}, len(static))
	for _, r := range static {
		if override, ok := byID[r.ID]; ok {
			out = append(out, override)
		} else {
			out = append(out, r)
		}
		seen[r.ID] = struct{}{}
	}
	for _, r := range runtime {
		if _, ok := seen[r.ID]; !ok {
			out = append(out, r)
		}
	}
	return out
}

func mergePools(static, runtime []proxy.BackendPoolConfig) []proxy.BackendPoolConfig {
	byID := make(map[string]proxy.BackendPoolConfig, len(runtime))
	for _, p := range runtime {
		byID[p.ID] = p
	}
	out := make([]proxy.BackendPoolConfig, 0, len(static)+len(runtime))
	seen := make(map[string]struct{}, len(static))
	for _, p := range static {
		if override, ok := byID[p.ID]; ok {
			out = append(out, override)
		} else {
			out = append(out, p)
		}
		seen[p.ID] = struct{}{}
	}
	for _, p := range runtime {
		if _, ok := seen[p.ID]; !ok {
			out = append(out, p)
		}
	}
	return out
}

// =============================================================================
// Config syncer
// =============================================================================

// SyncStatus is a snapshot of the sync loop's bookkeeping, surfaced through
// the Handler health snapshot.
type SyncStatus struct {
	// Version is the last successfully applied platformd config version.
	Version uint64
	// Synced reports whether at least one platformd configuration has been
	// applied since start.
	Synced bool
	// SyncedAt is the time of the last successful apply.
	SyncedAt time.Time
	// LastAttempt is the time of the last sync attempt.
	LastAttempt time.Time
	// LastError is the string form of the last attempt's error; empty on
	// success.
	LastError string
}

// SyncerConfig configures a ConfigSyncer.
type SyncerConfig struct {
	// Client is the platformd control-plane client (required).
	Client ControlPlaneClient
	// Reloader receives merged configurations (required; the engine).
	Reloader Reloader
	// Static is the base (file) engine configuration for the merge.
	Static proxy.Config
	// Matrix, when non-nil, is refreshed with the synced zone matrix on
	// every cycle.
	Matrix *ZoneMatrixProvider
	// Interval is the poll period; zero defaults to DefaultSyncInterval.
	Interval time.Duration
	// Logger is optional; nil uses slog.Default().
	Logger *slog.Logger
}

// ConfigSyncer polls the platformd proxy configuration and zone matrix,
// hot-reloading the engine when the config version changes. A failed reload
// keeps the running configuration (the engine guarantees this) and surfaces
// through Status; the version is not advanced so the reload is retried on
// the next tick.
type ConfigSyncer struct {
	client   ControlPlaneClient
	reloader Reloader
	static   proxy.Config
	matrix   *ZoneMatrixProvider
	interval time.Duration
	logger   *slog.Logger

	version atomic.Uint64
	synced  atomic.Bool
	status  atomic.Pointer[SyncStatus]
}

// NewConfigSyncer validates the configuration and builds a ConfigSyncer.
func NewConfigSyncer(cfg SyncerConfig) (*ConfigSyncer, error) {
	if cfg.Client == nil {
		return nil, &ErrNilClient{}
	}
	if cfg.Reloader == nil {
		return nil, &ErrNilReloader{}
	}
	if cfg.Interval <= 0 {
		cfg.Interval = DefaultSyncInterval
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	s := &ConfigSyncer{
		client:   cfg.Client,
		reloader: cfg.Reloader,
		static:   cfg.Static,
		matrix:   cfg.Matrix,
		interval: cfg.Interval,
		logger:   cfg.Logger,
	}
	s.status.Store(&SyncStatus{})
	return s, nil
}

// Run executes the poll loop until ctx is cancelled. It syncs immediately on
// entry so a reachable platformd is applied without waiting one interval.
func (s *ConfigSyncer) Run(ctx context.Context) {
	if err := s.SyncOnce(ctx); err != nil {
		s.logger.Warn("proxysvc: control-plane sync failed", "error", err)
	}
	ticker := time.NewTicker(s.interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			if err := s.SyncOnce(ctx); err != nil {
				s.logger.Warn("proxysvc: control-plane sync failed", "error", err)
			}
		}
	}
}

// SyncOnce performs a single sync cycle: refresh the zone matrix, fetch the
// proxy configuration, and reload the engine when the version changed.
func (s *ConfigSyncer) SyncOnce(ctx context.Context) error {
	err := s.syncOnce(ctx)
	s.recordAttempt(err)
	return err
}

func (s *ConfigSyncer) syncOnce(ctx context.Context) error {
	// The zone matrix can change without a proxy config version bump, so it
	// refreshes on every cycle regardless of version gating.
	if s.matrix != nil {
		matrixResp, err := s.client.ZoneMatrix(ctx)
		if err != nil {
			return err
		}
		s.matrix.Update(matrixResp)
	}

	resp, err := s.client.Config(ctx)
	if err != nil {
		return err
	}
	routes, pools, version := sdkproxy.ConfigFromProto(resp)
	if s.synced.Load() && version == s.version.Load() {
		return nil
	}

	merged := MergeConfig(s.static, routes, pools)
	if err := s.reloader.Reload(merged); err != nil {
		// The engine keeps the previous configuration; do not advance the
		// version so the reload retries next tick.
		return err
	}
	s.version.Store(version)
	s.synced.Store(true)
	s.logger.Info("proxysvc: applied platformd proxy configuration",
		"version", version, "routes", len(merged.Routes), "pools", len(merged.Pools))
	return nil
}

// recordAttempt updates the status snapshot after a sync attempt.
func (s *ConfigSyncer) recordAttempt(err error) {
	st := &SyncStatus{
		Version:     s.version.Load(),
		Synced:      s.synced.Load(),
		LastAttempt: time.Now().UTC(),
	}
	prev := s.status.Load()
	if prev != nil {
		st.SyncedAt = prev.SyncedAt
	}
	if err != nil {
		st.LastError = err.Error()
	} else {
		st.SyncedAt = st.LastAttempt
	}
	s.status.Store(st)
}

// Status returns the current sync bookkeeping snapshot.
func (s *ConfigSyncer) Status() SyncStatus {
	return *s.status.Load()
}
