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

package commands

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/orchestration"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	"github.com/jeremyhahn/go-trusted-platform/pkg/app"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/container"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	platformquicbaas "github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
)

// attestorInitTPM stands in for the host TPM. The runtime attestor in
// these tests is a fake, so the TPM is only passed through, never called.
type attestorInitTPM struct {
	orchestration.HostTPM
}

type attestorInitRuntime struct {
	got *service.AttestContainerRequest
	err error
}

func (r *attestorInitRuntime) AttestContainer(_ context.Context, req *service.AttestContainerRequest) (*service.AttestContainerResponse, error) {
	r.got = req
	if r.err != nil {
		return nil, r.err
	}
	return &service.AttestContainerResponse{Attested: true}, nil
}

type attestorInitDevices struct {
	dev *entities.Device
}

func (d *attestorInitDevices) Get(_ context.Context, id uint64) (*entities.Device, error) {
	if d.dev == nil || d.dev.ID != id {
		return nil, nil
	}
	return d.dev, nil
}

func (d *attestorInitDevices) Save(_ context.Context, dev *entities.Device) error {
	d.dev = dev
	return nil
}

// memFleetRegistry gives the fleet attestor the same in-memory device store
// the SDN quarantine observer reads and writes.
type memFleetRegistry struct {
	store *memDeviceStore
}

func (r memFleetRegistry) Get(ctx context.Context, id uint64) (*entities.Device, error) {
	return r.store.GetDevice(ctx, id)
}

func (r memFleetRegistry) Save(ctx context.Context, dev *entities.Device) error {
	return r.store.SaveDevice(ctx, dev)
}

type attestorInitBaselines struct {
	profile *entities.DeviceProfile
}

func (b *attestorInitBaselines) FindProfileForDevice(context.Context, *entities.Device) (*entities.DeviceProfile, error) {
	return b.profile, nil
}

type attestorInitVerdicts struct{}

func (attestorInitVerdicts) RecordDeviceVerdict(context.Context, verdict.DeviceVerdict) error {
	return nil
}

var errAttestorInitNoRuntime = errors.New("no container runtime binary")

// attestorInitDeps returns complete dependencies for device 42 with a
// golden PCR 0, and the fake runtime attestor they build.
func attestorInitDeps() (containerAttestorDeps, *attestorInitRuntime) {
	runtime := &attestorInitRuntime{}
	deps := containerAttestorDeps{
		TPM:     attestorInitTPM{},
		Devices: &attestorInitDevices{dev: &entities.Device{ID: 42, State: entities.DeviceStateActivated}},
		Baselines: &attestorInitBaselines{profile: &entities.DeviceProfile{ID: 9, PCRBaseline: &entities.PCRBaseline{
			Values: map[int][]byte{0: {0xaa}},
			Source: entities.BaselineSourceSigned,
		}}},
		Verdicts: attestorInitVerdicts{},
		Self:     &controlPlaneSelfDevice{DeviceID: "42"},
		NewRuntimeAttestor: func(orchestration.HostTPM, *slog.Logger) (service.ContainerAttestor, error) {
			return runtime, nil
		},
	}
	return deps, runtime
}

func TestNewFleetContainerAttestor_AttestsThisHostAgainstItsBaseline(t *testing.T) {
	deps, runtime := attestorInitDeps()

	fleet, err := newFleetContainerAttestor(slog.New(slog.DiscardHandler), deps)
	require.NoError(t, err)

	resp, err := fleet.AttestContainer(context.Background(), &service.AttestContainerRequest{Image: "registry.test/app:1"})
	require.NoError(t, err)
	assert.True(t, resp.Attested)
	assert.Equal(t, "42", resp.DeviceID)
	require.NotNil(t, runtime.got)
	assert.Equal(t, []byte{0xaa}, runtime.got.ExpectedPCRs[0])
}

// attestDrift runs one container attestation whose quote drifts from the
// baseline, with the real attestation service as the verdict recorder.
func attestDrift(t *testing.T, deps containerAttestorDeps, runtime *attestorInitRuntime) container.ErrFleetHostDrift {
	t.Helper()
	runtime.err = &orchestration.PCRMismatchError{Index: 0, Expected: []byte{0xaa}, Actual: []byte{0xde, 0xad}}
	fleet, err := newFleetContainerAttestor(slog.New(slog.DiscardHandler), deps)
	require.NoError(t, err)

	_, err = fleet.AttestContainer(context.Background(), &service.AttestContainerRequest{Image: "registry.test/app:1"})
	var drift container.ErrFleetHostDrift
	require.ErrorAs(t, err, &drift)
	assert.NoError(t, drift.VerdictErr)
	assert.NoError(t, drift.QuarantineErr, "the quarantine happened, so none is reported missing")
	return drift
}

func TestContainerAttestor_DriftQuarantinesWithoutSDN(t *testing.T) {
	deps, runtime := attestorInitDeps()
	devices := deps.Devices.(*attestorInitDevices)
	// No SDN policy engine: wireQuarantineObserver registers nothing, so
	// the verdict reaches no observer.
	deps.Verdicts = buildRealAttestationService(t)

	attestDrift(t, deps, runtime)

	assert.Equal(t, entities.DeviceStateQuarantined, devices.dev.State)
	assert.Equal(t, entities.DeviceStateActivated, devices.dev.PriorState)
	assert.Contains(t, devices.dev.StateReason, "PCR 0 differs")
}

func TestContainerAttestor_DriftQuarantinesADeviceWithNoSDNPort(t *testing.T) {
	deps, runtime := attestorInitDeps()
	obs, store := buildTestObserver(t, &entities.Device{ID: 42, State: entities.DeviceStateActivated})
	svc := buildRealAttestationService(t)
	svc.RegisterObserver(obs)
	deps.Verdicts = svc
	deps.Devices = memFleetRegistry{store: store}

	attestDrift(t, deps, runtime)

	dev, err := store.GetDevice(context.Background(), 42)
	require.NoError(t, err)
	assert.Equal(t, entities.DeviceStateQuarantined, dev.State,
		"the observer skips a device with no NetworkPortID; the attestor still quarantines it")
}

func TestContainerAttestor_DriftLeavesTheSDNQuarantineInPlace(t *testing.T) {
	deps, runtime := attestorInitDeps()
	obs, store := buildTestObserver(t, &entities.Device{ID: 42, State: entities.DeviceStateActivated, NetworkPortID: "port-42"})
	svc := buildRealAttestationService(t)
	svc.RegisterObserver(obs)
	deps.Verdicts = svc
	deps.Devices = memFleetRegistry{store: store}

	attestDrift(t, deps, runtime)

	dev, err := store.GetDevice(context.Background(), 42)
	require.NoError(t, err)
	assert.Equal(t, entities.DeviceStateQuarantined, dev.State)
	assert.Equal(t, entities.DeviceStateActivated, dev.PriorState,
		"the SDN quarantine ran first and its record of the prior state stands")
	assert.Equal(t, "container attestation: PCR 0 differs from the profile's golden baseline", dev.StateReason)
}

func TestNewFleetContainerAttestor_Refusals(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*containerAttestorDeps)
		check  func(*testing.T, error)
	}{
		{
			name:   "no own device record",
			mutate: func(d *containerAttestorDeps) { d.Self = nil },
			check:  requirePrerequisite("own device record"),
		},
		{
			name:   "no host TPM",
			mutate: func(d *containerAttestorDeps) { d.TPM = nil },
			check:  requirePrerequisite("host TPM"),
		},
		{
			name:   "no runtime attestor",
			mutate: func(d *containerAttestorDeps) { d.NewRuntimeAttestor = nil },
			check:  requirePrerequisite("runtime attestor"),
		},
		{
			name:   "non-numeric device id",
			mutate: func(d *containerAttestorDeps) { d.Self = &controlPlaneSelfDevice{DeviceID: "cp-1"} },
			check: func(t *testing.T, err error) {
				var bad ErrCollectorDeviceID
				require.ErrorAs(t, err, &bad)
				assert.Equal(t, "cp-1", bad.DeviceID)
			},
		},
		{
			name: "runtime attestor cannot be built",
			mutate: func(d *containerAttestorDeps) {
				d.NewRuntimeAttestor = func(orchestration.HostTPM, *slog.Logger) (service.ContainerAttestor, error) {
					return nil, errAttestorInitNoRuntime
				}
			},
			check: func(t *testing.T, err error) {
				var runtimeErr ErrContainerAttestorRuntime
				require.ErrorAs(t, err, &runtimeErr)
				assert.ErrorIs(t, err, errAttestorInitNoRuntime)
				assert.Contains(t, err.Error(), "runtime attestor unavailable")
			},
		},
		{
			name:   "no device registry",
			mutate: func(d *containerAttestorDeps) { d.Devices = nil },
			check: func(t *testing.T, err error) {
				var missing container.ErrFleetAttestorDependency
				require.ErrorAs(t, err, &missing)
				assert.Equal(t, "device registry", missing.Name)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			deps, _ := attestorInitDeps()
			tt.mutate(&deps)

			fleet, err := newFleetContainerAttestor(slog.New(slog.DiscardHandler), deps)

			assert.Nil(t, fleet)
			require.Error(t, err)
			tt.check(t, err)
		})
	}
}

func requirePrerequisite(missing string) func(*testing.T, error) {
	return func(t *testing.T, err error) {
		t.Helper()
		var prerequisite ErrContainerAttestorPrerequisite
		require.ErrorAs(t, err, &prerequisite)
		assert.Contains(t, prerequisite.Missing, missing)
		assert.Contains(t, err.Error(), missing)
	}
}

func TestInstallContainerAttestor_InstallsIntoTheSeam(t *testing.T) {
	deps, _ := attestorInitDeps()
	adapter := platformquicbaas.NewContainerAttestorAdapter()

	require.NoError(t, installContainerAttestor(slog.New(slog.DiscardHandler), adapter, deps))

	resp, err := adapter.AttestContainer(context.Background(), &service.AttestContainerRequest{Image: "registry.test/app:1"})
	require.NoError(t, err)
	assert.Equal(t, "42", resp.DeviceID)
}

func TestInstallContainerAttestor_FailureLeavesTheSeamRefusing(t *testing.T) {
	deps, _ := attestorInitDeps()
	deps.TPM = nil
	adapter := platformquicbaas.NewContainerAttestorAdapter()

	err := installContainerAttestor(slog.New(slog.DiscardHandler), adapter, deps)
	requirePrerequisite("host TPM")(t, err)

	_, err = adapter.AttestContainer(context.Background(), &service.AttestContainerRequest{Image: "registry.test/app:1"})
	var notAvailable platformquicbaas.ErrContainerAttestorNotAvailable
	assert.ErrorAs(t, err, &notAvailable)
}

func TestInstallContainerAttestor_NoSeam(t *testing.T) {
	deps, _ := attestorInitDeps()

	err := installContainerAttestor(slog.New(slog.DiscardHandler), nil, deps)

	requirePrerequisite("container attestor seam")(t, err)
}

func TestContainerAttestorDepsFrom_CollectsWhatExists(t *testing.T) {
	cfg := &daemon.Config{}
	self := &controlPlaneSelfDevice{DeviceID: "42"}

	deps := containerAttestorDepsFrom(&app.App{}, cfg, &attestationServices{}, self)

	// Absent dependencies must be nil interfaces, not typed nils, so the
	// constructors name them instead of calling through a nil pointer.
	assert.True(t, deps.TPM == nil, "TPM")
	assert.True(t, deps.Devices == nil, "Devices")
	assert.True(t, deps.Baselines == nil, "Baselines")
	assert.True(t, deps.Verdicts == nil, "Verdicts")
	assert.True(t, deps.Reattest == nil, "Reattest")
	assert.Same(t, self, deps.Self)
	assert.NotNil(t, deps.NewRuntimeAttestor)
}

func TestWireContainerAttestor_NothingToWire(t *testing.T) {
	logger := slog.New(slog.DiscardHandler)

	assert.NotPanics(t, func() { wireContainerAttestor(logger, nil, &daemon.Config{}, nil, nil) })
	assert.NotPanics(t, func() { wireContainerAttestor(logger, &app.App{}, nil, nil, nil) })
	assert.NotPanics(t, func() { wireContainerAttestor(logger, &app.App{}, &daemon.Config{}, nil, nil) })
}
