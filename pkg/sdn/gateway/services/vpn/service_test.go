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

package vpn

import (
	"context"
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"
)

func TestConfig_DefaultsAndValidation(t *testing.T) {
	cfg := testConfig().WithDefaults()
	require.NoError(t, cfg.Validate())
	assert.Equal(t, DefaultListenerPort, cfg.Listener.Port)
	assert.Equal(t, DefaultLeaseTTL, cfg.LeaseTTL)
	assert.Equal(t, DefaultRenewWindow, cfg.RenewWindow)
	assert.Equal(t, DefaultPosturePolicy, cfg.PosturePolicy)
	assert.Equal(t, DefaultNonceTTL, cfg.NonceTTL)
	assert.True(t, cfg.RequirePersonFactor.OnAdmit)
	assert.True(t, cfg.Offers(DataPlaneMASQUE))
	assert.False(t, cfg.Offers(DataPlaneKind("nope")))

	cases := map[string]struct {
		mutate func(c *Config)
		field  string
	}{
		"port":                {func(c *Config) { c.Listener.Port = 70000 }, "listener.port"},
		"unknown data plane":  {func(c *Config) { c.DataPlanes = []DataPlaneKind{"carrier-pigeon"} }, "data-planes"},
		"duplicate plane":     {func(c *Config) { c.DataPlanes = []DataPlaneKind{DataPlaneMASQUE, DataPlaneMASQUE} }, "data-planes"},
		"no pool":             {func(c *Config) { c.Pool = "" }, "pool"},
		"ttl too short":       {func(c *Config) { c.LeaseTTL = time.Minute }, "lease-ttl"},
		"ttl too long":        {func(c *Config) { c.LeaseTTL = 48 * time.Hour }, "lease-ttl"},
		"renew window":        {func(c *Config) { c.RenewWindow = c.LeaseTTL }, "renew-window"},
		"nonce ttl":           {func(c *Config) { c.NonceTTL = 48 * time.Hour }, "nonce-ttl"},
		"no zones":            {func(c *Config) { c.AllowTo = nil }, "allow-to"},
		"empty zone":          {func(c *Config) { c.AllowTo = []string{""} }, "allow-to"},
		"no masque template":  {func(c *Config) { c.MASQUE.Template = "" }, "masque.template"},
		"bad template":        {func(c *Config) { c.MASQUE.Template = "https://gw/{" }, "masque.template"},
		"template variables":  {func(c *Config) { c.MASQUE.Template = "https://gw/masque/{target}/{ipproto}/" }, "masque.template"},
		"http template":       {func(c *Config) { c.MASQUE.Template = "http://gw/masque/" }, "masque.template"},
		"no template host":    {func(c *Config) { c.MASQUE.Template = "https:///masque/" }, "masque.template"},
		"no template path":    {func(c *Config) { c.MASQUE.Template = "https://gw" }, "masque.template"},
		"no masque routes":    {func(c *Config) { c.MASQUE.Routes = nil }, "masque.routes"},
		"invalid route":       {func(c *Config) { c.MASQUE.Routes = []netip.Prefix{{}} }, "masque.routes"},
		"stray wireguard key": {func(c *Config) { c.WireGuard.ListenPort = 51820 }, "wireguard.listen-port"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := testConfig().WithDefaults()
			c.mutate(&cfg)
			err := cfg.Validate()
			var invalid *ErrInvalidConfig
			require.True(t, errors.As(err, &invalid), "got %v", err)
			assert.Equal(t, c.field, invalid.Field)
		})
	}
}

// TestConfig_PlaneKeysFollowDataPlanes pins that the `wireguard.*` and
// `masque.*` keys are read from YAML, defaulted only for an offered plane
// and refused for a plane the config does not offer.
func TestConfig_PlaneKeysFollowDataPlanes(t *testing.T) {
	t.Run("masque keys are read", func(t *testing.T) {
		cfg := parseVPNConfig(t, `
pool: vpn-clients
allow-to: [management]
data-planes: [masque]
masque:
  template: https://gw.example:4433/.well-known/masque/ip/
  routes: [10.0.0.0/8, "fd00::/8"]
`)
		require.NoError(t, cfg.Validate())
		assert.Equal(t, "https://gw.example:4433/.well-known/masque/ip/", cfg.MASQUE.Template)
		assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8"), netip.MustParsePrefix("fd00::/8")}, cfg.MASQUE.Routes)
		assert.Zero(t, cfg.WireGuard.ListenPort, "no default for a plane that is not offered")
	})
	t.Run("masque is the default plane and needs its keys", func(t *testing.T) {
		cfg := parseVPNConfig(t, `
pool: vpn-clients
allow-to: [management]
`)
		assertInvalidField(t, cfg.Validate(), "masque.template")
	})
	t.Run("wireguard keys without the wireguard plane are refused", func(t *testing.T) {
		cfg := testConfig()
		cfg.WireGuard.ListenPort = 51821
		assertInvalidField(t, cfg.WithDefaults().Validate(), "wireguard.listen-port")
	})
	t.Run("a wireguard key-ref or address on a masque-only gateway is refused", func(t *testing.T) {
		cfg := testConfig()
		cfg.WireGuard.KeyRef = "secret://vpn/hub-key"
		assertInvalidField(t, cfg.WithDefaults().Validate(), "wireguard.key-ref")

		cfg = testConfig()
		cfg.WireGuard.Address = netip.MustParsePrefix("10.99.0.1/24")
		assertInvalidField(t, cfg.WithDefaults().Validate(), "wireguard.address")
	})
	t.Run("an invalid route in YAML is refused", func(t *testing.T) {
		var cfg Config
		err := yaml.Unmarshal([]byte("masque:\n  routes: [not-a-prefix]\n"), &cfg)
		require.Error(t, err)
	})
}

// parseVPNConfig reads a `management_vpn` body as gatewayd does and applies
// the defaults.
func parseVPNConfig(t *testing.T, body string) Config {
	t.Helper()
	var cfg Config
	require.NoError(t, yaml.Unmarshal([]byte(body), &cfg))
	return cfg.WithDefaults()
}

// assertInvalidField requires err to be the typed config error for field.
func assertInvalidField(t *testing.T, err error, field string) {
	t.Helper()
	var invalid *ErrInvalidConfig
	require.True(t, errors.As(err, &invalid), "got %v", err)
	assert.Equal(t, field, invalid.Field)
}

func TestNew_RefusesInvalidConfigAndMissingDeps(t *testing.T) {
	h := newHarness(t, testConfig())
	deps := h.svc.deps

	bad := testConfig()
	bad.Pool = ""
	_, err := New(deps, bad)
	var invalid *ErrInvalidConfig
	assert.True(t, errors.As(err, &invalid))

	for _, tc := range []struct {
		name string
		mut  func(d *Deps)
	}{
		{"Identity", func(d *Deps) { d.Identity = nil }},
		{"Verifier", func(d *Deps) { d.Verifier = nil }},
		{"Posture", func(d *Deps) { d.Posture = nil }},
		{"Factors", func(d *Deps) { d.Factors = nil }},
		{"IPAM", func(d *Deps) { d.IPAM = nil }},
		{"Leases", func(d *Deps) { d.Leases = nil }},
		{"Audit", func(d *Deps) { d.Audit = nil }},
		{"DataPlanes[masque]", func(d *Deps) { d.DataPlanes = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			d := deps
			d.DataPlanes = map[DataPlaneKind]DataPlane{DataPlaneMASQUE: h.plane}
			tc.mut(&d)
			_, err := New(d, testConfig())
			var missing *ErrDepsMissing
			require.True(t, errors.As(err, &missing), "got %v", err)
			assert.Equal(t, tc.name, missing.Dep)
		})
	}

	// Clock and Logger default.
	d := deps
	d.Clock, d.Logger = nil, nil
	svc, err := New(d, testConfig())
	require.NoError(t, err)
	assert.NotNil(t, svc.deps.Clock)
	assert.NotNil(t, svc.deps.Logger)
	assert.Equal(t, DefaultLeaseTTL, svc.Config().LeaseTTL)
}

func TestService_Lifecycle(t *testing.T) {
	h := newHarness(t, testConfig())
	assert.True(t, h.svc.Active())
	var already *ErrAlreadyStarted
	assert.True(t, errors.As(h.svc.Start(context.Background()), &already))

	require.NoError(t, h.svc.Stop(context.Background()))
	assert.False(t, h.svc.Active())
	var notStarted *ErrNotStarted
	assert.True(t, errors.As(h.svc.Stop(context.Background()), &notStarted))
	_, err := h.svc.Challenge()
	assert.True(t, errors.As(err, &notStarted))
	_, err = h.svc.Admit(context.Background(), &AdmissionRequest{})
	assert.True(t, errors.As(err, &notStarted))
	_, err = h.svc.Renew(context.Background(), "x", &Evidence{})
	assert.True(t, errors.As(err, &notStarted))
	assert.True(t, errors.As(h.svc.Revoke(context.Background(), "x", RevokeOperator), &notStarted))

	require.NoError(t, h.svc.Start(context.Background()), "a stopped service starts again")
	assert.True(t, h.svc.Active())
	assert.True(t, h.svc.Health().Active)
}

func TestService_StopHonoursContext(t *testing.T) {
	h := newHarness(t, testConfig())
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	// The sweep goroutine exits promptly, so Stop returns nil even with a
	// cancelled context unless the goroutine is stuck; both outcomes are
	// acceptable as long as Stop returns.
	_ = h.svc.Stop(ctx)
	assert.False(t, h.svc.Active())
}

func TestChallenge_IsFreshAndConsumable(t *testing.T) {
	h := newHarness(t, testConfig())
	a, err := h.svc.Challenge()
	require.NoError(t, err)
	b, err := h.svc.Challenge()
	require.NoError(t, err)
	assert.Len(t, a, nonceBytes)
	assert.NotEqual(t, a, b)
	assert.True(t, h.svc.consumeNonce(a))
	assert.False(t, h.svc.consumeNonce(a), "single use")
	assert.False(t, h.svc.consumeNonce(nil))
	// Expired nonces are forgotten by the sweep.
	h.clock.Advance(DefaultNonceTTL + time.Second)
	h.svc.Sweep(context.Background())
	assert.False(t, h.svc.consumeNonce(b))
}

func TestMemoryLeaseStore(t *testing.T) {
	s := NewMemoryLeaseStore()
	ctx := context.Background()
	var invalid *ErrInvalidRequest
	assert.True(t, errors.As(s.Put(ctx, nil), &invalid))
	assert.True(t, errors.As(s.Put(ctx, &Lease{}), &invalid))

	now := time.Now()
	require.NoError(t, s.Put(ctx, &Lease{ID: "b", DeviceID: "d1", TenantID: "t", IssuedAt: now.Add(time.Second)}))
	require.NoError(t, s.Put(ctx, &Lease{ID: "a", DeviceID: "d2", TenantID: "t", IssuedAt: now}))
	list, err := s.List(ctx)
	require.NoError(t, err)
	require.Len(t, list, 2)
	assert.Equal(t, LeaseID("a"), list[0].ID, "ordered by IssuedAt")

	got, err := s.Get(ctx, "a")
	require.NoError(t, err)
	got.DeviceID = "mutated"
	again, _ := s.Get(ctx, "a")
	assert.Equal(t, "d2", again.DeviceID, "Get returns a copy")

	found, ok, err := s.FindByDevice(ctx, "t", "d1")
	require.NoError(t, err)
	assert.True(t, ok)
	assert.Equal(t, LeaseID("b"), found.ID)
	_, ok, _ = s.FindByDevice(ctx, "other", "d1")
	assert.False(t, ok)

	require.NoError(t, s.Delete(ctx, "a"))
	var nf *ErrLeaseNotFound
	assert.True(t, errors.As(s.Delete(ctx, "a"), &nf))
	_, err = s.Get(ctx, "a")
	assert.True(t, errors.As(err, &nf))
}

func TestErrors_Messages(t *testing.T) {
	assert.True(t, (&ErrPeerRefused{Reason: "untrusted-issuer"}).Unauthenticated())
	assert.False(t, (&ErrPeerRefused{Reason: "not-listed"}).Unauthenticated())
	cause := errors.New("boom")
	for _, e := range []error{
		&ErrPeerRefused{Reason: "x"}, &ErrAttestationFailed{DeviceID: "d", Reason: "r", Cause: cause},
		&ErrAttestationFailed{DeviceID: "d", Reason: "r"}, &ErrPostureViolation{Violations: []string{"a", "b"}},
		&ErrPostureUnavailable{Cause: cause}, &ErrPersonFactorRequired{}, &ErrPersonFactorInvalid{FactorName: "fido2", Cause: cause},
		&ErrPersonFactorInvalid{FactorName: "piv"}, &ErrPoolExhausted{Pool: "p", Cause: cause}, &ErrPoolExhausted{Pool: "p"},
		&ErrDataPlaneUnavailable{Kind: "k", Cause: cause}, &ErrDataPlaneUnavailable{Kind: "k"}, &ErrLeaseExpired{LeaseID: "l"},
		&ErrLeaseNotFound{LeaseID: "l"}, &ErrInvalidConfig{Field: "f", Reason: "r"}, &ErrInvalidRequest{Field: "f", Reason: "r"},
		&ErrNonceUnknown{}, &ErrZoneNotAllowed{Zone: "z"}, &ErrDepsMissing{Dep: "d"}, &ErrAlreadyStarted{}, &ErrNotStarted{},
	} {
		assert.NotEmpty(t, e.Error())
	}
	assert.ErrorIs(t, &ErrAttestationFailed{Cause: cause}, cause)
	assert.ErrorIs(t, &ErrPostureUnavailable{Cause: cause}, cause)
	assert.ErrorIs(t, &ErrPersonFactorInvalid{Cause: cause}, cause)
	assert.ErrorIs(t, &ErrPoolExhausted{Cause: cause}, cause)
	assert.ErrorIs(t, &ErrDataPlaneUnavailable{Cause: cause}, cause)
}
