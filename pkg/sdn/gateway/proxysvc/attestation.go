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
	"log/slog"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"

	"github.com/jeremyhahn/go-trusted-platform/pkg/proxy"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// Attestation verdict cache defaults: positive verdicts (the device's newest
// manifest timestamp plus its verification outcome) are reused for
// DefaultAttestationCacheTTL; failed platformd queries are cached for the
// much shorter DefaultAttestationNegativeTTL so a platformd blip neither
// hammers the control plane nor denies traffic longer than necessary.
const (
	DefaultAttestationCacheTTL    = 60 * time.Second
	DefaultAttestationNegativeTTL = 5 * time.Second
)

// AttestationConfig is the proxy `attestation:` section enabling the
// platformd-backed attestation gate for routes that set
// auth.require-attestation. The accepted attestation age is the route's
// auth.attestation-max-age (or defaults.attestation-max-age); this section
// deliberately adds no third max-age knob.
type AttestationConfig struct {
	// Enabled activates the attestation gate.
	Enabled bool `yaml:"enabled" json:"enabled" mapstructure:"enabled"`

	// CacheTTL bounds per-device verdict reuse. Zero defaults to
	// DefaultAttestationCacheTTL (60s).
	CacheTTL time.Duration `yaml:"cache-ttl,omitempty" json:"cache_ttl,omitempty" mapstructure:"cache-ttl"`

	// NegativeCacheTTL bounds failed-query reuse. Zero defaults to
	// DefaultAttestationNegativeTTL (5s).
	NegativeCacheTTL time.Duration `yaml:"negative-cache-ttl,omitempty" json:"negative_cache_ttl,omitempty" mapstructure:"negative-cache-ttl"`
}

// AttestationClient is the narrow surface of the sdk/go attestation client
// the gate consumes. *attestation.Client (sdk/go/services/attestation)
// satisfies it; unit tests inject fakes.
type AttestationClient interface {
	// ListManifests returns manifests matching the filter, newest first.
	ListManifests(ctx context.Context, req *platformv1.ListManifestsRequest) ([]*platformv1.HostManifest, uint32, error)
	// VerifyManifest verifies a manifest through platformd and returns the
	// verification result.
	VerifyManifest(ctx context.Context, req *platformv1.VerifyManifestRequest) (*platformv1.ManifestVerificationResult, error)
}

// AttestationDialFunc lazily establishes the attestation client connection
// to platformd.
type AttestationDialFunc func(ctx context.Context) (AttestationClient, error)

// LazyAttestationClient defers the platformd connection until the first gate
// query and retries on the next query after a failure, mirroring
// LazyControlPlaneClient so gatewayd starts (and fails closed) while
// platformd is down.
type LazyAttestationClient struct {
	dial AttestationDialFunc

	mu     sync.Mutex
	client AttestationClient
}

// NewLazyAttestationClient builds a lazy attestation client around a dial
// function.
func NewLazyAttestationClient(dial AttestationDialFunc) (*LazyAttestationClient, error) {
	if dial == nil {
		return nil, &ErrNilDialFunc{}
	}
	return &LazyAttestationClient{dial: dial}, nil
}

// get returns the connected client, dialing on first use.
func (l *LazyAttestationClient) get(ctx context.Context) (AttestationClient, error) {
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

// ListManifests implements AttestationClient.
func (l *LazyAttestationClient) ListManifests(ctx context.Context, req *platformv1.ListManifestsRequest) ([]*platformv1.HostManifest, uint32, error) {
	client, err := l.get(ctx)
	if err != nil {
		return nil, 0, err
	}
	return client.ListManifests(ctx, req)
}

// VerifyManifest implements AttestationClient.
func (l *LazyAttestationClient) VerifyManifest(ctx context.Context, req *platformv1.VerifyManifestRequest) (*platformv1.ManifestVerificationResult, error) {
	client, err := l.get(ctx)
	if err != nil {
		return nil, err
	}
	return client.VerifyManifest(ctx, req)
}

// SDKAttestationGateConfig configures NewSDKAttestationGate.
type SDKAttestationGateConfig struct {
	// Client queries platformd for manifests and verification (required).
	Client AttestationClient
	// CacheTTL bounds verdict reuse. Zero defaults to
	// DefaultAttestationCacheTTL.
	CacheTTL time.Duration
	// NegativeCacheTTL bounds failed-query reuse. Zero defaults to
	// DefaultAttestationNegativeTTL.
	NegativeCacheTTL time.Duration
	// Clock overrides the time source. Nil uses time.Now. Injected for
	// deterministic tests.
	Clock func() time.Time
	// Logger is optional; nil uses slog.Default().
	Logger *slog.Logger
}

// attestationVerdict is one cached per-device outcome. A nil err carries the
// device's newest manifest timestamp and verification result; a non-nil err
// is a cached query failure (negative entry).
type attestationVerdict struct {
	manifestTime time.Time
	verified     bool
	err          error
	expires      time.Time
}

// SDKAttestationGate is the production proxy.AttestationGate. It resolves a
// device's attestation state from platformd through the sdk/go attestation
// client: the newest stored manifest for the device (manifests are keyed by
// the IDevID CN and carry the AK-signature-anchored collection timestamp)
// plus a platformd VerifyManifest verdict, which also lands in the platform
// attestation event trail. Freshness is then evaluated locally per request
// against the route's max age, so one cached verdict serves routes with
// different age policies.
//
// Concurrency: lookups take an RWMutex read lock and refreshes are
// deduplicated per device with singleflight. The cache operates at
// control-plane rate — at most one platformd round trip per device per
// CacheTTL — so an uncontended RLock on the request path is preferred over a
// lock-free structure whose complexity this rate cannot justify.
type SDKAttestationGate struct {
	client AttestationClient
	ttl    time.Duration
	negTTL time.Duration
	now    func() time.Time
	logger *slog.Logger

	group singleflight.Group

	mu    sync.RWMutex
	cache map[string]*attestationVerdict
}

// NewSDKAttestationGate validates the configuration and builds the gate.
func NewSDKAttestationGate(cfg SDKAttestationGateConfig) (*SDKAttestationGate, error) {
	if cfg.Client == nil {
		return nil, &ErrNilAttestationClient{}
	}
	if cfg.CacheTTL <= 0 {
		cfg.CacheTTL = DefaultAttestationCacheTTL
	}
	if cfg.NegativeCacheTTL <= 0 {
		cfg.NegativeCacheTTL = DefaultAttestationNegativeTTL
	}
	if cfg.Clock == nil {
		cfg.Clock = time.Now
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	return &SDKAttestationGate{
		client: cfg.Client,
		ttl:    cfg.CacheTTL,
		negTTL: cfg.NegativeCacheTTL,
		now:    cfg.Clock,
		logger: cfg.Logger,
		cache:  make(map[string]*attestationVerdict),
	}, nil
}

// Fresh implements proxy.AttestationGate. Definitive verdicts (no manifest,
// verification rejected, manifest older than maxAge) return an error
// wrapping proxy.ErrAttestationStale; query failures return an
// ErrAttestationQueryFailed, which the chain maps to
// "attestation_unavailable". Both deny.
func (g *SDKAttestationGate) Fresh(ctx context.Context, deviceID string, maxAge time.Duration) error {
	if deviceID == "" {
		return &ErrAttestationQueryFailed{DeviceID: deviceID, Cause: &ErrDeviceIDRequired{}}
	}
	verdict, err := g.verdict(ctx, deviceID)
	if err != nil {
		return err
	}
	return g.evaluate(deviceID, verdict, maxAge)
}

// verdict returns the cached verdict for a device, refreshing it through
// singleflight when expired.
func (g *SDKAttestationGate) verdict(ctx context.Context, deviceID string) (*attestationVerdict, error) {
	now := g.now()
	g.mu.RLock()
	v, ok := g.cache[deviceID]
	g.mu.RUnlock()
	if ok && now.Before(v.expires) {
		if v.err != nil {
			return nil, v.err
		}
		return v, nil
	}

	result, err, _ := g.group.Do(deviceID, func() (any, error) {
		// Re-check under the flight: a concurrent caller may have refreshed
		// between the read above and this flight winning the group slot.
		g.mu.RLock()
		cached, fresh := g.cache[deviceID]
		g.mu.RUnlock()
		if fresh && g.now().Before(cached.expires) {
			return cached, nil
		}
		return g.refresh(ctx, deviceID), nil
	})
	if err != nil {
		// singleflight itself never fails here; the closure returns verdicts.
		return nil, &ErrAttestationQueryFailed{DeviceID: deviceID, Cause: err}
	}
	v = result.(*attestationVerdict)
	if v.err != nil {
		return nil, v.err
	}
	return v, nil
}

// refresh queries platformd for the device's newest manifest and its
// verification verdict, caches the outcome, and returns it. Query failures
// are cached with the negative TTL so error storms are rate-limited without
// masking recovery.
func (g *SDKAttestationGate) refresh(ctx context.Context, deviceID string) *attestationVerdict {
	manifests, _, err := g.client.ListManifests(ctx, &platformv1.ListManifestsRequest{
		HostId: deviceID,
		Limit:  1,
	})
	if err != nil {
		return g.store(deviceID, &attestationVerdict{
			err: &ErrAttestationQueryFailed{DeviceID: deviceID, Cause: err},
		}, g.negTTL)
	}
	if len(manifests) == 0 || manifests[0] == nil {
		// A definitive answer: the device has never produced an attestation
		// manifest. Cached with the positive TTL like any other verdict.
		return g.store(deviceID, &attestationVerdict{verified: false}, g.ttl)
	}
	m := manifests[0]
	v := &attestationVerdict{}
	if ts := m.GetTimestamp(); ts != nil {
		v.manifestTime = ts.AsTime()
	}
	result, err := g.client.VerifyManifest(ctx, &platformv1.VerifyManifestRequest{Manifest: m})
	if err != nil {
		return g.store(deviceID, &attestationVerdict{
			err: &ErrAttestationQueryFailed{DeviceID: deviceID, Cause: err},
		}, g.negTTL)
	}
	v.verified = result.GetStatus() == platformv1.ManifestVerificationStatus_MANIFEST_VERIFICATION_STATUS_VERIFIED
	if !v.verified {
		g.logger.Warn("proxysvc: attestation manifest failed platformd verification",
			"device", deviceID, "manifest", m.GetId(), "status", result.GetStatus().String(),
			"errors", result.GetErrors())
	}
	return g.store(deviceID, v, g.ttl)
}

// store caches a verdict with the given TTL and returns it.
func (g *SDKAttestationGate) store(deviceID string, v *attestationVerdict, ttl time.Duration) *attestationVerdict {
	v.expires = g.now().Add(ttl)
	g.mu.Lock()
	g.cache[deviceID] = v
	g.mu.Unlock()
	return v
}

// evaluate applies the route's max-age policy to a verdict.
func (g *SDKAttestationGate) evaluate(deviceID string, v *attestationVerdict, maxAge time.Duration) error {
	if v.manifestTime.IsZero() {
		return &ErrDeviceNotAttested{DeviceID: deviceID, Detail: "no attestation manifest"}
	}
	if !v.verified {
		return &ErrDeviceNotAttested{DeviceID: deviceID, Detail: "manifest verification rejected"}
	}
	if age := g.now().Sub(v.manifestTime); age > maxAge {
		return &ErrDeviceNotAttested{
			DeviceID: deviceID,
			Detail:   "manifest age " + age.Truncate(time.Second).String() + " exceeds max " + maxAge.String(),
		}
	}
	return nil
}

var (
	_ proxy.AttestationGate = (*SDKAttestationGate)(nil)
	_ AttestationClient     = (*LazyAttestationClient)(nil)
)
