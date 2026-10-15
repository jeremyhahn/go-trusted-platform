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

package compute

import (
	"context"
	"errors"
	"testing"
	"testing/synctest"

	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// fakeMigrateSession records the QMP calls MigrateVM makes and returns a
// scripted migration status so the poll loop terminates without a real VM.
type fakeMigrateSession struct {
	paused       bool
	resumed      bool
	quit         bool
	cancelled    bool
	caps         []string
	params       *qemu.MigrationParams
	migratedURI  string
	objectAdded  bool
	statusResult qemu.MigrationStatusType

	failAt  string // method name that should return an error
	failErr error
}

func (f *fakeMigrateSession) errFor(method string) error {
	if f.failAt == method {
		if f.failErr != nil {
			return f.failErr
		}
		return errors.New("fake failure at " + method)
	}
	return nil
}

func (f *fakeMigrateSession) Pause(ctx context.Context) error {
	if err := f.errFor("Pause"); err != nil {
		return err
	}
	f.paused = true
	return nil
}

func (f *fakeMigrateSession) Resume(ctx context.Context) error {
	f.resumed = true
	return f.errFor("Resume")
}

func (f *fakeMigrateSession) ObjectAdd(ctx context.Context, qomType, id string, props map[string]interface{}) error {
	if err := f.errFor("ObjectAdd"); err != nil {
		return err
	}
	f.objectAdded = true
	return nil
}

func (f *fakeMigrateSession) SetParameters(ctx context.Context, params *qemu.MigrationParams) error {
	if err := f.errFor("SetParameters"); err != nil {
		return err
	}
	f.params = params
	return nil
}

func (f *fakeMigrateSession) SetCapabilities(ctx context.Context, caps []string) error {
	if err := f.errFor("SetCapabilities"); err != nil {
		return err
	}
	f.caps = caps
	return nil
}

func (f *fakeMigrateSession) Migrate(ctx context.Context, uri string) error {
	if err := f.errFor("Migrate"); err != nil {
		return err
	}
	f.migratedURI = uri
	return nil
}

func (f *fakeMigrateSession) Status(ctx context.Context) (*qemu.MigrationStatus, error) {
	if err := f.errFor("Status"); err != nil {
		return nil, err
	}
	st := f.statusResult
	if st == "" {
		st = qemu.MigrationStatusCompleted
	}
	return &qemu.MigrationStatus{Status: st}, nil
}

func (f *fakeMigrateSession) Cancel(ctx context.Context) error {
	f.cancelled = true
	return nil
}

func (f *fakeMigrateSession) Quit(ctx context.Context) error {
	f.quit = true
	return nil
}

// fakeCoordinator records prepare/finalize calls and returns a scripted
// endpoint.
type fakeCoordinator struct {
	prepared    bool
	spec        MigrationSpec // spec passed to the last PrepareIncoming call
	finalized   bool
	finalizeErr error // streamErr passed to the last Finalize call
	prepareErr  error
	endpoint    *IncomingEndpoint
}

func (c *fakeCoordinator) PrepareIncoming(ctx context.Context, destination string, spec MigrationSpec) (*IncomingEndpoint, error) {
	if c.prepareErr != nil {
		return nil, c.prepareErr
	}
	c.prepared = true
	c.spec = spec
	if c.endpoint != nil {
		return c.endpoint, nil
	}
	return &IncomingEndpoint{URI: "tcp:dest.example:49152", TLSHostname: "dest.example"}, nil
}

func (c *fakeCoordinator) Finalize(ctx context.Context, destination string, spec MigrationSpec, streamErr error) error {
	c.finalized = true
	c.finalizeErr = streamErr
	return nil
}

// fakeTLSProvider provisions a scripted creds ID via the session and can fail.
type fakeTLSProvider struct {
	failErr error
	credsID string
}

func (p *fakeTLSProvider) EnsureTLSCreds(ctx context.Context, session MigrationSession, endpoint *IncomingEndpoint) (string, error) {
	if p.failErr != nil {
		return "", p.failErr
	}
	// Exercise the QMP object-add seam so the happy path proves creds are
	// installed on the source monitor.
	if err := session.ObjectAdd(ctx, "tls-creds-x509", "migtls0", map[string]interface{}{"dir": "/run/migtls", "endpoint": "client"}); err != nil {
		return "", err
	}
	id := p.credsID
	if id == "" {
		id = "migtls0"
	}
	return id, nil
}

// migrateTestOrchestrator wires a running VM plus fake coordinator + TLS
// provider and installs a fake migration session, returning the fake session so
// tests can assert the QMP call sequence.
func migrateTestOrchestrator(t *testing.T, live bool) (*QEMUOrchestrator, *fakeCoordinator, *fakeTLSProvider, *fakeMigrateSession) {
	t.Helper()

	orch := newOpsOrchestrator(t)
	coord := &fakeCoordinator{}
	tls := &fakeTLSProvider{}
	orch.config.MigrationCoordinator = coord
	orch.config.MigrationTLS = tls
	if live {
		orch.config.SharedStorage = &SharedStorageConfig{Enabled: true, Backend: "nfs"}
	}

	insertVMInstance(t, orch, "vm1", true, &InstanceConfig{WorkDir: t.TempDir(), DiskPath: "/vms/vm1/disk.qcow2", Memory: 2048})

	fake := &fakeMigrateSession{}
	orig := vmMigrationSessionFor
	vmMigrationSessionFor = func(ctx context.Context, o *QEMUOrchestrator, inst *qemuInstance) (MigrationSession, error) {
		return fake, nil
	}
	t.Cleanup(func() { vmMigrationSessionFor = orig })

	return orch, coord, tls, fake
}

// migrateOnFakeClock runs MigrateVM in a synctest bubble, so the status
// poll's ticker fires on fake time instead of a real 250ms wait.
func migrateOnFakeClock(t *testing.T, orch *QEMUOrchestrator, opts MigrateOptions) (result *MigrationResult, err error) {
	t.Helper()
	synctest.Test(t, func(*testing.T) {
		result, err = orch.MigrateVM(context.Background(), "vm1", "dest.example:10443", opts)
	})
	return result, err
}

func TestMigrateVM_ColdHappyPath(t *testing.T) {
	orch, coord, _, fake := migrateTestOrchestrator(t, false)

	result, err := migrateOnFakeClock(t, orch, MigrateOptions{Live: false, BandwidthLimitMbps: 100})
	require.NoError(t, err)
	require.NotNil(t, result)

	assert.Equal(t, MigrateModeCold, result.Mode)
	assert.True(t, result.Success)

	// Cold path pauses the guest, enables block migration, and installs TLS.
	assert.True(t, fake.paused, "cold migration must pause the guest")
	assert.Contains(t, fake.caps, "block", "cold migration must enable block migration")
	assert.True(t, fake.objectAdded, "TLS creds must be provisioned via QMP object-add")
	assert.Equal(t, "migtls0", fake.params.TLSCreds)
	assert.Equal(t, "dest.example", fake.params.TLSHostname)
	assert.Equal(t, int64(100)*mbpsToBytesPerSecond, fake.params.MaxBandwidth)
	assert.Equal(t, "tcp:dest.example:49152", fake.migratedURI)
	assert.True(t, fake.quit, "source QEMU must be quit after transfer")

	// Coordinator handshake completed with a nil stream error (success).
	assert.True(t, coord.prepared)
	assert.True(t, coord.finalized)
	assert.NoError(t, coord.finalizeErr)

	// Source bookkeeping is retired.
	_, err = orch.Get(context.Background(), "vm1")
	assert.ErrorIs(t, err, ErrInstanceNotFound)
}

// The destination refuses a guest of another architecture, so the source names
// its guest's architecture in the handshake.
func TestMigrateVM_SpecCarriesTheGuestArch(t *testing.T) {
	orch, coord, _, _ := migrateTestOrchestrator(t, false)
	orch.config.Arch = qemu.ArchAArch64

	_, err := migrateOnFakeClock(t, orch, MigrateOptions{})
	require.NoError(t, err)
	assert.Equal(t, qemu.ArchAArch64, coord.spec.Arch)
}

func TestMigrateVM_LiveHappyPath(t *testing.T) {
	orch, coord, _, fake := migrateTestOrchestrator(t, true)

	result, err := migrateOnFakeClock(t, orch, MigrateOptions{Live: true})
	require.NoError(t, err)
	assert.Equal(t, MigrateModeLive, result.Mode)

	// Live migration keeps the guest running (no pause) and streams RAM only
	// (no block capability).
	assert.False(t, fake.paused, "live migration must not pause the guest")
	assert.NotContains(t, fake.caps, "block", "live migration must not enable block migration")
	assert.True(t, coord.finalized)
	assert.NoError(t, coord.finalizeErr)
}

func TestMigrateVM_LiveWithoutSharedStorage(t *testing.T) {
	orch, coord, _, _ := migrateTestOrchestrator(t, false)

	_, err := orch.MigrateVM(context.Background(), "vm1", "dest.example:10443", MigrateOptions{Live: true})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrLiveMigrationRequiresSharedStorage)
	// The destination must never be contacted for a rejected request.
	assert.False(t, coord.prepared)
}

func TestMigrateVM_NoCoordinator(t *testing.T) {
	orch := newOpsOrchestrator(t)
	orch.config.MigrationTLS = &fakeTLSProvider{}
	insertVMInstance(t, orch, "vm1", true, &InstanceConfig{WorkDir: t.TempDir()})

	_, err := orch.MigrateVM(context.Background(), "vm1", "dest.example:10443", MigrateOptions{})
	assert.ErrorIs(t, err, ErrMigrationNotConfigured)
}

func TestMigrateVM_NoTLSProvider(t *testing.T) {
	orch := newOpsOrchestrator(t)
	orch.config.MigrationCoordinator = &fakeCoordinator{}
	insertVMInstance(t, orch, "vm1", true, &InstanceConfig{WorkDir: t.TempDir()})

	_, err := orch.MigrateVM(context.Background(), "vm1", "dest.example:10443", MigrateOptions{})
	assert.ErrorIs(t, err, ErrMigrationTLSNotConfigured)
}

func TestMigrateVM_TLSFailureRollsBack(t *testing.T) {
	orch, coord, tls, fake := migrateTestOrchestrator(t, false)
	tls.failErr = errors.New("CA unavailable")

	_, err := orch.MigrateVM(context.Background(), "vm1", "dest.example:10443", MigrateOptions{})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMigrationFailed)
	// Destination was prepared then aborted; the guest was never paused.
	assert.True(t, coord.prepared)
	assert.True(t, coord.finalized)
	assert.False(t, fake.paused)
	// The source VM survives a failed migration.
	_, getErr := orch.Get(context.Background(), "vm1")
	assert.NoError(t, getErr)
}

func TestMigrateVM_DestinationUnreachable(t *testing.T) {
	orch, coord, _, _ := migrateTestOrchestrator(t, false)
	coord.prepareErr = errors.New("dial dest.example:10443: connection refused")

	_, err := orch.MigrateVM(context.Background(), "vm1", "dest.example:10443", MigrateOptions{})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMigrationFailed)
	assert.False(t, coord.finalized, "no receiver to finalize when prepare failed")
	// The source VM survives.
	_, getErr := orch.Get(context.Background(), "vm1")
	assert.NoError(t, getErr)
}

func TestMigrateVM_StreamFailsRollsBack(t *testing.T) {
	orch, coord, _, fake := migrateTestOrchestrator(t, false)
	fake.failAt = "Migrate"

	_, err := orch.MigrateVM(context.Background(), "vm1", "dest.example:10443", MigrateOptions{})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMigrationFailed)
	// Cold migration paused the guest; rollback must resume it and cancel.
	assert.True(t, fake.paused)
	assert.True(t, fake.resumed, "rollback must resume the cold-paused guest")
	assert.True(t, fake.cancelled)
	assert.True(t, coord.finalized)
	assert.Error(t, coord.finalizeErr)
}

func TestMigrateVM_TerminalFailedStatus(t *testing.T) {
	orch, _, _, fake := migrateTestOrchestrator(t, false)
	fake.statusResult = qemu.MigrationStatusFailed

	_, err := migrateOnFakeClock(t, orch, MigrateOptions{})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMigrationFailed)
	assert.True(t, fake.resumed, "a failed transfer must resume the paused source")
}

func TestMigrateVM_NotRunning(t *testing.T) {
	orch, _, _, _ := migrateTestOrchestrator(t, false)
	// Insert a stopped instance under a second ID.
	insertVMInstance(t, orch, "vm2", false, &InstanceConfig{WorkDir: t.TempDir()})

	_, err := orch.MigrateVM(context.Background(), "vm2", "dest.example:10443", MigrateOptions{})
	assert.ErrorIs(t, err, ErrInstanceNotRunning)
}

func TestMigrateVM_Validation(t *testing.T) {
	orch, _, _, _ := migrateTestOrchestrator(t, false)

	_, err := orch.MigrateVM(context.Background(), "", "dest.example:10443", MigrateOptions{})
	assert.ErrorIs(t, err, ErrInvalidInstanceID)

	_, err = orch.MigrateVM(context.Background(), "vm1", "", MigrateOptions{})
	assert.ErrorIs(t, err, ErrMigrationDestinationRequired)
}
