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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
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
		"port":               {func(c *Config) { c.Listener.Port = 70000 }, "listener.port"},
		"unknown data plane": {func(c *Config) { c.DataPlanes = []DataPlaneKind{"carrier-pigeon"} }, "data-planes"},
		"duplicate plane":    {func(c *Config) { c.DataPlanes = []DataPlaneKind{DataPlaneMASQUE, DataPlaneMASQUE} }, "data-planes"},
		"no pool":            {func(c *Config) { c.Pool = "" }, "pool"},
		"ttl too short":      {func(c *Config) { c.LeaseTTL = time.Minute }, "lease-ttl"},
		"ttl too long":       {func(c *Config) { c.LeaseTTL = 48 * time.Hour }, "lease-ttl"},
		"renew window":       {func(c *Config) { c.RenewWindow = c.LeaseTTL }, "renew-window"},
		"nonce ttl":          {func(c *Config) { c.NonceTTL = 48 * time.Hour }, "nonce-ttl"},
		"no zones":           {func(c *Config) { c.AllowTo = nil }, "allow-to"},
		"empty zone":         {func(c *Config) { c.AllowTo = []string{""} }, "allow-to"},
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
