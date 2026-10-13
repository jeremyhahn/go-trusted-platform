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

package container

import (
	"bytes"
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/orchestration"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

const fleetLocalID uint64 = 42

var (
	goldenPCR0 = []byte{0x00, 0x01}
	goldenPCR7 = []byte{0x07, 0x07}
)

// upstreamError stands in for the quicbaas QBError the runtime attestor
// wraps its failures in: the cause is reachable only through Unwrap.
type upstreamError struct{ cause error }

func (e upstreamError) Error() string { return "upstream: " + e.cause.Error() }
func (e upstreamError) Unwrap() error { return e.cause }

type fakeInnerAttestor struct {
	resp *service.AttestContainerResponse
	err  error
	// quoted, when set, is what the host TPM reads: the fake then checks
	// the expected PCRs the way the SDK does and reports only the
	// lowest-numbered mismatch.
	quoted   map[uint32][]byte
	calls    int
	got      *service.AttestContainerRequest
	expected []map[uint32][]byte
}

func (f *fakeInnerAttestor) AttestContainer(_ context.Context, req *service.AttestContainerRequest) (*service.AttestContainerResponse, error) {
	f.calls++
	f.got = req
	f.expected = append(f.expected, req.ExpectedPCRs)
	if f.quoted != nil {
		if err := lowestPCRMismatch(req.ExpectedPCRs, f.quoted); err != nil {
			return nil, err
		}
	}
	return f.resp, f.err
}

func lowestPCRMismatch(expected, quoted map[uint32][]byte) error {
	indices := make([]uint32, 0, len(expected))
	for index := range expected {
		indices = append(indices, index)
	}
	slices.Sort(indices)
	for _, index := range indices {
		if !bytes.Equal(expected[index], quoted[index]) {
			return &orchestration.PCRMismatchError{Index: index, Expected: expected[index], Actual: quoted[index]}
		}
	}
	return nil
}

type fakeFleetRegistry struct {
	dev     *entities.Device
	err     error
	saveErr error
	saved   []entities.Device
}

func (f *fakeFleetRegistry) Save(_ context.Context, dev *entities.Device) error {
	if f.saveErr != nil {
		return f.saveErr
	}
	f.saved = append(f.saved, *dev)
	f.dev = dev
	return nil
}

func (f *fakeFleetRegistry) Get(_ context.Context, id uint64) (*entities.Device, error) {
	if f.err != nil {
		return nil, f.err
	}
	if f.dev == nil || f.dev.ID != id {
		return nil, nil
	}
	return f.dev, nil
}

type fakeBaselineResolver struct {
	profile *entities.DeviceProfile
	err     error
}

func (f *fakeBaselineResolver) FindProfileForDevice(context.Context, *entities.Device) (*entities.DeviceProfile, error) {
	return f.profile, f.err
}

type fakeVerdictRecorder struct {
	verdicts []verdict.DeviceVerdict
	err      error
	// observe stands in for the attestation observers the verdict reaches.
	observe func()
}

// RecordDeviceVerdict validates like the attestation service does, so a
// verdict the service would reject fails the test.
func (f *fakeVerdictRecorder) RecordDeviceVerdict(_ context.Context, v verdict.DeviceVerdict) error {
	if err := v.Validate(); err != nil {
		return err
	}
	f.verdicts = append(f.verdicts, v)
	if f.observe != nil {
		f.observe()
	}
	return f.err
}

type fakeReattester struct {
	ids []string
	err error
}

func (f *fakeReattester) Refresh(deviceID string) error {
	f.ids = append(f.ids, deviceID)
	return f.err
}

type fleetFixture struct {
	inner     *fakeInnerAttestor
	registry  *fakeFleetRegistry
	baselines *fakeBaselineResolver
	verdicts  *fakeVerdictRecorder
	reattest  *fakeReattester
	now       time.Time
}

func newFleetFixture() *fleetFixture {
	return &fleetFixture{
		inner: &fakeInnerAttestor{resp: &service.AttestContainerResponse{Attested: true, Image: "registry.example/app@sha256:aa"}},
		registry: &fakeFleetRegistry{dev: &entities.Device{
			ID: fleetLocalID, TenantID: "tenant-a", Serial: "SN-42", Hostname: "cp-01", State: entities.DeviceStateAttested,
		}},
		baselines: &fakeBaselineResolver{profile: &entities.DeviceProfile{ID: 9, PCRBaseline: &entities.PCRBaseline{
			Values: map[int][]byte{0: goldenPCR0, 7: goldenPCR7},
			Source: entities.BaselineSourceSigned,
		}}},
		verdicts: &fakeVerdictRecorder{},
		reattest: &fakeReattester{},
		now:      time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC),
	}
}

func (f *fleetFixture) attestor(t *testing.T) *FleetContainerAttestor {
	t.Helper()
	a, err := NewFleetContainerAttestor(FleetAttestorConfig{
		Attestor:      f.inner,
		Devices:       f.registry,
		Baselines:     f.baselines,
		Verdicts:      f.verdicts,
		Reattest:      f.reattest,
		LocalDeviceID: fleetLocalID,
	})
	require.NoError(t, err)
	a.now = func() time.Time { return f.now }
	return a
}

func TestNewFleetContainerAttestor_RequiresEveryDependency(t *testing.T) {
	f := newFleetFixture()
	full := FleetAttestorConfig{
		Attestor: f.inner, Devices: f.registry, Baselines: f.baselines, Verdicts: f.verdicts, LocalDeviceID: fleetLocalID,
	}
	cases := map[string]func(c *FleetAttestorConfig){
		"container attestor": func(c *FleetAttestorConfig) { c.Attestor = nil },
		"device registry":    func(c *FleetAttestorConfig) { c.Devices = nil },
		"baseline resolver":  func(c *FleetAttestorConfig) { c.Baselines = nil },
		"verdict recorder":   func(c *FleetAttestorConfig) { c.Verdicts = nil },
		"local device id":    func(c *FleetAttestorConfig) { c.LocalDeviceID = 0 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			cfg := full
			mutate(&cfg)
			a, err := NewFleetContainerAttestor(cfg)
			assert.Nil(t, a)
			var dep ErrFleetAttestorDependency
			require.ErrorAs(t, err, &dep)
			assert.Equal(t, name, dep.Name)
		})
	}

	a, err := NewFleetContainerAttestor(full)
	require.NoError(t, err, "re-attestation is optional")
	assert.NotNil(t, a)
}

func TestFleetContainerAttestor_PassAppliesTheBaselineAndRecordsNothing(t *testing.T) {
	f := newFleetFixture()
	extra := []byte{0x0b}
	resp, err := f.attestor(t).AttestContainer(context.Background(), &service.AttestContainerRequest{
		Image:        "registry.example/app@sha256:aa",
		ExpectedPCRs: map[uint32][]byte{7: goldenPCR7, 11: extra},
	})
	require.NoError(t, err)
	assert.True(t, resp.Attested)
	assert.Equal(t, "42", resp.DeviceID, "an empty device id means this host")

	require.Equal(t, 2, f.inner.calls)
	assert.Equal(t, "42", f.inner.got.DeviceID)
	assert.Equal(t, []map[uint32][]byte{
		{0: goldenPCR0, 7: goldenPCR7},
		{0: goldenPCR0, 7: goldenPCR7, 11: extra},
	}, f.inner.expected, "the baseline is quoted on its own, then with the registers the request added")
	assert.Empty(t, f.verdicts.verdicts, "a host's quote of itself must not readmit it from quarantine")
	assert.Empty(t, f.reattest.ids)
	assert.Empty(t, f.registry.saved)
}

func TestFleetContainerAttestor_BaselineOnlyRequestQuotesOnce(t *testing.T) {
	f := newFleetFixture()
	_, err := f.attestor(t).AttestContainer(context.Background(), &service.AttestContainerRequest{
		Image: "img", ExpectedPCRs: map[uint32][]byte{7: goldenPCR7},
	})
	require.NoError(t, err)
	assert.Equal(t, []map[uint32][]byte{{0: goldenPCR0, 7: goldenPCR7}}, f.inner.expected,
		"a request that adds nothing to the baseline needs no second quote")
}

func TestFleetContainerAttestor_DriftQuarantinesAndRequestsReattestation(t *testing.T) {
	f := newFleetFixture()
	mismatch := &orchestration.PCRMismatchError{Index: 7, Expected: goldenPCR7, Actual: []byte{0xde, 0xad}}
	f.inner.resp, f.inner.err = nil, upstreamError{cause: mismatch}

	resp, err := f.attestor(t).AttestContainer(context.Background(), &service.AttestContainerRequest{Image: "img", DeviceID: "42"})
	assert.Nil(t, resp)
	var drift ErrFleetHostDrift
	require.ErrorAs(t, err, &drift)
	assert.Equal(t, uint32(7), drift.Index)
	assert.NoError(t, drift.QuarantineErr)
	assert.NoError(t, drift.ReattestErr)
	var pcr *orchestration.PCRMismatchError
	assert.ErrorAs(t, err, &pcr, "the upstream mismatch stays reachable")

	require.Len(t, f.verdicts.verdicts, 1)
	v := f.verdicts.verdicts[0]
	assert.Equal(t, verdict.DeviceVerdict{
		DeviceID: fleetLocalID, TenantID: "tenant-a", HostID: "cp-01", Serial: "SN-42",
		Passed: false, Cryptographic: true,
		Reason:         "container attestation: PCR 7 differs from the profile's golden baseline",
		BaselineSource: "signed", ProfileID: 9, AttestedAt: f.now,
	}, v, "a cryptographic failure is what the quarantine observer acts on")
	assert.Equal(t, []string{"42"}, f.reattest.ids)

	require.Len(t, f.registry.saved, 1, "no observer acted on the verdict, so the attestor quarantines the device itself")
	saved := f.registry.saved[0]
	assert.Equal(t, entities.DeviceStateQuarantined, saved.State)
	assert.Equal(t, entities.DeviceStateAttested, saved.PriorState)
	assert.Equal(t, v.Reason, saved.StateReason)
}

func TestFleetContainerAttestor_RequestPCRCannotMaskBaselineDrift(t *testing.T) {
	f := newFleetFixture()
	// PCR 4 is the request's own and fails too; upstream reports only the
	// lowest-numbered mismatch, which on a merged quote would be PCR 4.
	f.inner.quoted = map[uint32][]byte{0: goldenPCR0, 4: {0x01}, 7: {0xde, 0xad}}

	_, err := f.attestor(t).AttestContainer(context.Background(), &service.AttestContainerRequest{
		Image: "img", ExpectedPCRs: map[uint32][]byte{4: {0x04}},
	})
	var drift ErrFleetHostDrift
	require.ErrorAs(t, err, &drift, "drift in the baseline wins over the request's own policy")
	assert.Equal(t, uint32(7), drift.Index)
	assert.False(t, errors.As(err, &ErrFleetPCRPolicyMismatch{}))
	assert.Equal(t, 1, f.inner.calls, "the request's PCRs are not quoted once the baseline fails")
	assert.Len(t, f.verdicts.verdicts, 1)
	require.Len(t, f.registry.saved, 1)
	assert.Equal(t, entities.DeviceStateQuarantined, f.registry.saved[0].State)
	assert.Equal(t, []string{"42"}, f.reattest.ids)
}

func TestFleetContainerAttestor_DriftLeavesAContainedDeviceAlone(t *testing.T) {
	for _, state := range []entities.DeviceState{
		entities.DeviceStateQuarantined, entities.DeviceStateSuspended, entities.DeviceStateRevoked,
	} {
		t.Run(string(state), func(t *testing.T) {
			f := newFleetFixture()
			f.inner.resp, f.inner.err = nil, &orchestration.PCRMismatchError{Index: 7}
			// The SDN observer acted on the verdict first.
			f.verdicts.observe = func() { f.registry.dev.State = state }

			_, err := f.attestor(t).AttestContainer(context.Background(), &service.AttestContainerRequest{Image: "img"})
			var drift ErrFleetHostDrift
			require.ErrorAs(t, err, &drift)
			assert.NoError(t, drift.QuarantineErr)
			assert.Empty(t, f.registry.saved, "a device already held is not transitioned again")
			assert.Equal(t, state, f.registry.dev.State)
		})
	}
}

func TestFleetContainerAttestor_DriftReportsAQuarantineThatDidNotHappen(t *testing.T) {
	lookup := errors.New("registry offline")
	cases := map[string]func(f *fleetFixture){
		"save fails":   func(f *fleetFixture) { f.registry.saveErr = errors.New("registry read-only") },
		"lookup fails": func(f *fleetFixture) { f.verdicts.observe = func() { f.registry.err = lookup } },
		"device gone":  func(f *fleetFixture) { f.verdicts.observe = func() { f.registry.dev = nil } },
		"no transition": func(f *fleetFixture) {
			f.verdicts.observe = func() { f.registry.dev.State = entities.DeviceStateUnknown }
		},
	}
	for name, arrange := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFleetFixture()
			f.inner.resp, f.inner.err = nil, &orchestration.PCRMismatchError{Index: 7}
			arrange(f)

			_, err := f.attestor(t).AttestContainer(context.Background(), &service.AttestContainerRequest{Image: "img"})
			var drift ErrFleetHostDrift
			require.ErrorAs(t, err, &drift)
			var failed ErrFleetQuarantineFailed
			require.ErrorAs(t, drift.QuarantineErr, &failed, "a quarantine that did not happen is never reported as done")
			assert.Equal(t, fleetLocalID, failed.DeviceID)
			assert.Contains(t, err.Error(), "the device was not quarantined")
			assert.Empty(t, f.registry.saved)
			assert.Equal(t, []string{"42"}, f.reattest.ids, "re-attestation is still requested")
		})
	}
}

func TestFleetContainerAttestor_DriftReportsQuarantineAndReattestFailures(t *testing.T) {
	f := newFleetFixture()
	f.inner.resp, f.inner.err = nil, &orchestration.PCRMismatchError{Index: 0}
	storage := errors.New("verdict store offline")
	registry := errors.New("registry read-only")
	collector := errors.New("collector stopped")
	f.verdicts.err, f.registry.saveErr, f.reattest.err = storage, registry, collector

	_, err := f.attestor(t).AttestContainer(context.Background(), &service.AttestContainerRequest{Image: "img"})
	var drift ErrFleetHostDrift
	require.ErrorAs(t, err, &drift)
	assert.ErrorIs(t, err, storage)
	assert.ErrorIs(t, err, registry)
	assert.ErrorIs(t, err, collector)
	assert.Contains(t, err.Error(), "the drift verdict was not recorded")
	assert.Contains(t, err.Error(), "the device was not quarantined")
	assert.Contains(t, err.Error(), "re-attestation was not requested")
}

func TestFleetContainerAttestor_DriftWithoutReattesterStillQuarantines(t *testing.T) {
	f := newFleetFixture()
	f.inner.resp, f.inner.err = nil, &orchestration.PCRMismatchError{Index: 0}
	a, err := NewFleetContainerAttestor(FleetAttestorConfig{
		Attestor: f.inner, Devices: f.registry, Baselines: f.baselines, Verdicts: f.verdicts, LocalDeviceID: fleetLocalID,
	})
	require.NoError(t, err)

	_, err = a.AttestContainer(context.Background(), &service.AttestContainerRequest{Image: "img"})
	require.ErrorAs(t, err, &ErrFleetHostDrift{})
	assert.Len(t, f.verdicts.verdicts, 1)
}

func TestFleetContainerAttestor_RequestPCRMismatchIsNotDrift(t *testing.T) {
	f := newFleetFixture()
	f.inner.quoted = map[uint32][]byte{0: goldenPCR0, 7: goldenPCR7, 11: {0xff}}

	_, err := f.attestor(t).AttestContainer(context.Background(), &service.AttestContainerRequest{
		Image: "img", ExpectedPCRs: map[uint32][]byte{11: {0x0b}},
	})
	var policy ErrFleetPCRPolicyMismatch
	require.ErrorAs(t, err, &policy)
	assert.Equal(t, uint32(11), policy.Index)
	assert.Equal(t, 2, f.inner.calls, "the baseline held on its own before the request's PCR was quoted")
	assert.Empty(t, f.verdicts.verdicts, "the caller's policy failed, not the host")
	assert.Empty(t, f.reattest.ids)
	assert.Empty(t, f.registry.saved)
}

func TestFleetContainerAttestor_MissingEvidenceIsARefusalNotAVerdict(t *testing.T) {
	cases := map[string]error{
		"quote failed":     &orchestration.ContainerQuoteError{Image: "img", Cause: errors.New("tpm busy")},
		"quote not bound":  &orchestration.QuoteBindingError{Image: "img", Reason: "nonce"},
		"tier unavailable": &orchestration.AttestationUnavailableError{Reason: "no tpm"},
	}
	for name, cause := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFleetFixture()
			f.inner.resp, f.inner.err = nil, upstreamError{cause: cause}
			_, err := f.attestor(t).AttestContainer(context.Background(), &service.AttestContainerRequest{Image: "img"})
			var failed ErrFleetAttestationFailed
			require.ErrorAs(t, err, &failed)
			assert.ErrorIs(t, err, cause)
			assert.Empty(t, f.verdicts.verdicts, "absence of evidence is not failed attestation")
		})
	}

	f := newFleetFixture()
	f.inner.resp = &service.AttestContainerResponse{Attested: false}
	_, err := f.attestor(t).AttestContainer(context.Background(), &service.AttestContainerRequest{Image: "img"})
	require.ErrorAs(t, err, &ErrFleetAttestationFailed{}, "a result that is not attested fails closed")

	f.inner.resp = nil
	_, err = f.attestor(t).AttestContainer(context.Background(), &service.AttestContainerRequest{Image: "img"})
	require.ErrorAs(t, err, &ErrFleetAttestationFailed{}, "no result fails closed")
}

func TestFleetContainerAttestor_RefusesBeforeQuoting(t *testing.T) {
	lookup := errors.New("registry offline")
	cases := map[string]struct {
		mutate func(f *fleetFixture, req *service.AttestContainerRequest)
		target any
	}{
		"device id not decimal": {
			mutate: func(_ *fleetFixture, req *service.AttestContainerRequest) { req.DeviceID = "node-7" },
			target: &ErrFleetDeviceIDInvalid{},
		},
		"another host": {
			mutate: func(_ *fleetFixture, req *service.AttestContainerRequest) { req.DeviceID = "7" },
			target: &ErrFleetDeviceNotLocal{},
		},
		"registry fails": {
			mutate: func(f *fleetFixture, _ *service.AttestContainerRequest) { f.registry.err = lookup },
			target: &ErrFleetDeviceLookup{},
		},
		"not registered": {
			mutate: func(f *fleetFixture, _ *service.AttestContainerRequest) { f.registry.dev = nil },
			target: &ErrFleetDeviceLookup{},
		},
		"quarantined": {
			mutate: func(f *fleetFixture, _ *service.AttestContainerRequest) {
				f.registry.dev.State = entities.DeviceStateQuarantined
			},
			target: &ErrFleetDeviceCannotAttest{},
		},
		"revoked": {
			mutate: func(f *fleetFixture, _ *service.AttestContainerRequest) {
				f.registry.dev.State = entities.DeviceStateRevoked
			},
			target: &ErrFleetDeviceCannotAttest{},
		},
		"pinned tier quotes nothing": {
			mutate: func(_ *fleetFixture, req *service.AttestContainerRequest) {
				req.TrustLevel = orchestration.TrustLevelPinned.String()
			},
			target: &ErrFleetTrustLevelRefused{},
		},
		"unknown tier": {
			mutate: func(_ *fleetFixture, req *service.AttestContainerRequest) { req.TrustLevel = "platinum" },
			target: &ErrFleetTrustLevelRefused{},
		},
		"no profile": {
			mutate: func(f *fleetFixture, _ *service.AttestContainerRequest) {
				f.baselines.profile, f.baselines.err = nil, errors.New("no profile")
			},
			target: &ErrFleetBaselineUnavailable{},
		},
		"profile without baseline": {
			mutate: func(f *fleetFixture, _ *service.AttestContainerRequest) { f.baselines.profile.PCRBaseline = nil },
			target: &ErrFleetBaselineUnavailable{},
		},
		"baseline index out of range": {
			mutate: func(f *fleetFixture, _ *service.AttestContainerRequest) {
				f.baselines.profile.PCRBaseline.Values[orchestration.MaxPCRIndex+1] = []byte{0x01}
			},
			target: &ErrFleetBaselineUnavailable{},
		},
		"baseline value empty": {
			mutate: func(f *fleetFixture, _ *service.AttestContainerRequest) {
				f.baselines.profile.PCRBaseline.Values[4] = nil
			},
			target: &ErrFleetBaselineUnavailable{},
		},
		"request relaxes the baseline": {
			mutate: func(_ *fleetFixture, req *service.AttestContainerRequest) {
				req.ExpectedPCRs = map[uint32][]byte{7: {0xff}}
			},
			target: &ErrFleetBaselineConflict{},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			f := newFleetFixture()
			req := &service.AttestContainerRequest{Image: "img"}
			tc.mutate(f, req)
			resp, err := f.attestor(t).AttestContainer(context.Background(), req)
			assert.Nil(t, resp)
			require.ErrorAs(t, err, tc.target)
			assert.Zero(t, f.inner.calls, "a refused request never reaches the TPM")
			assert.Empty(t, f.verdicts.verdicts)
		})
	}

	f := newFleetFixture()
	_, err := f.attestor(t).AttestContainer(context.Background(), nil)
	require.ErrorAs(t, err, &ErrFleetAttestRequestRequired{})
}

func TestFleetContainerAttestor_AcceptsEveryHostTPMTier(t *testing.T) {
	for _, level := range []string{"", orchestration.TrustLevelAttested.String(), orchestration.TrustLevelMeasured.String()} {
		t.Run(level, func(t *testing.T) {
			f := newFleetFixture()
			f.registry.dev.State = entities.DeviceStateActivated
			_, err := f.attestor(t).AttestContainer(context.Background(), &service.AttestContainerRequest{Image: "img", TrustLevel: level})
			require.NoError(t, err)
			assert.Equal(t, level, f.inner.got.TrustLevel, "the tier is passed through unchanged")
		})
	}
}

func TestFleetErrors_MessagesAndCauses(t *testing.T) {
	cause := errors.New("underlying")
	cases := []struct {
		err  error
		want string
	}{
		{ErrFleetAttestorDependency{Name: "device registry"}, "container fleet attestor: a device registry is required"},
		{ErrFleetAttestRequestRequired{}, "container fleet attestor: the attestation request is required"},
		{ErrFleetTrustLevelRefused{TrustLevel: "pinned"}, `container fleet attestor: trust level "pinned" does not quote the host TPM; request attested or measured`},
		{ErrFleetTrustLevelRefused{TrustLevel: "x", Cause: cause}, `container fleet attestor: trust level "x" is invalid: underlying`},
		{ErrFleetDeviceIDInvalid{DeviceID: "x", Cause: cause}, `container fleet attestor: device id "x" is not a registry id: underlying`},
		{ErrFleetDeviceNotLocal{DeviceID: 7, LocalDeviceID: 42}, "container fleet attestor: device 7 is not this host (device 42); only this host's TPM can be quoted"},
		{ErrFleetDeviceLookup{DeviceID: 7}, "container fleet attestor: device 7 is not in the registry"},
		{ErrFleetDeviceLookup{DeviceID: 7, Cause: cause}, "container fleet attestor: device 7 could not be read: underlying"},
		{ErrFleetDeviceCannotAttest{DeviceID: 7, State: entities.DeviceStateQuarantined}, "container fleet attestor: device 7 is quarantined and may not attest containers"},
		{ErrFleetBaselineUnavailable{DeviceID: 7, Reason: "none"}, "container fleet attestor: no golden PCR baseline for device 7: none"},
		{ErrFleetBaselineUnavailable{DeviceID: 7, Reason: "none", Cause: cause}, "container fleet attestor: no golden PCR baseline for device 7: none: underlying"},
		{ErrFleetBaselineConflict{DeviceID: 7, Index: 4}, "container fleet attestor: the request expects a value for PCR 4 that differs from device 7's golden baseline"},
		{ErrFleetHostDrift{DeviceID: 7, Index: 4}, "container fleet attestor: device 7 drifted from its golden baseline at PCR 4"},
		{ErrFleetQuarantineFailed{DeviceID: 7, Cause: cause}, "container fleet attestor: device 7 could not be moved to quarantine: underlying"},
		{ErrFleetPCRPolicyMismatch{DeviceID: 7, Index: 4, Cause: cause}, "container fleet attestor: device 7 PCR 4 does not match the value the request expects: underlying"},
		{ErrFleetAttestationFailed{DeviceID: 7, Reason: "no quote"}, "container fleet attestor: device 7: no quote"},
		{ErrFleetAttestationFailed{DeviceID: 7, Reason: "no quote", Cause: cause}, "container fleet attestor: device 7: no quote: underlying"},
	}
	for _, tc := range cases {
		assert.Equal(t, tc.want, tc.err.Error())
	}

	for _, wrapped := range []error{
		ErrFleetTrustLevelRefused{Cause: cause},
		ErrFleetDeviceIDInvalid{Cause: cause},
		ErrFleetDeviceLookup{Cause: cause},
		ErrFleetBaselineUnavailable{Cause: cause},
		ErrFleetHostDrift{Mismatch: cause},
		ErrFleetHostDrift{VerdictErr: cause},
		ErrFleetQuarantineFailed{Cause: cause},
		ErrFleetPCRPolicyMismatch{Cause: cause},
		ErrFleetAttestationFailed{Cause: cause},
	} {
		assert.ErrorIs(t, wrapped, cause, "%T keeps its cause", wrapped)
	}
	assert.Empty(t, ErrFleetHostDrift{}.Unwrap(), "a drift with no causes unwraps to nothing")
}
