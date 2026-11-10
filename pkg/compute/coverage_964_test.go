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
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"testing"
	"testing/synctest"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/vm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/policy"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/zone"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// These tests cover the QEMU orchestrator's error and fallback paths that run
// without a hypervisor: every VM here is created but never started, so each
// QMP seam meets a VM that is not running and a monitor that is not connected.

var (
	errCov964Lookup   = &MessageError{Msg: "fake bundle lookup failure"}
	errCov964Generate = &MessageError{Msg: "fake bundle generation failure"}
	errCov964Start    = &MessageError{Msg: "fake swtpm start failure"}
	errCov964Stop     = &MessageError{Msg: "fake swtpm stop failure"}
	errCov964Session  = &MessageError{Msg: "fake migration session failure"}
	errCov964Rollback = &MessageError{Msg: "fake rollback step failure"}
	errCov964Finalize = &MessageError{Msg: "fake destination finalize failure"}
	errCov964Proc     = &MessageError{Msg: "fake proc read failure"}
	errCov964Block    = &MessageError{Msg: "fake block stats failure"}
	errCov964Sink     = &MessageError{Msg: "fake log sink failure"}
	errCov964Events   = &MessageError{Msg: "fake QMP event subscription failure"}
	errCov964Disk     = &MessageError{Msg: "fake QMP disk failure"}
	errCov964Img      = &MessageError{Msg: "fake qemu-img failure"}
)

// cov964Emulator is an in-memory swtpm whose Start and Stop results are set
// by the test. It counts Stop calls so a test can assert cleanup ran.
type cov964Emulator struct {
	startErr  error
	stopErr   error
	running   bool
	stopCalls int
	socket    string
}

func (e *cov964Emulator) Initialize(ctx context.Context) error { return nil }
func (e *cov964Emulator) IsInitialized() bool                  { return true }

func (e *cov964Emulator) Start(ctx context.Context) error {
	if e.startErr != nil {
		return e.startErr
	}
	e.running = true
	return nil
}

func (e *cov964Emulator) WaitForSocket(timeout time.Duration) error { return nil }

func (e *cov964Emulator) Stop() error {
	e.stopCalls++
	if e.stopErr != nil {
		return e.stopErr
	}
	e.running = false
	return nil
}

func (e *cov964Emulator) IsRunning() bool    { return e.running }
func (e *cov964Emulator) PID() int           { return fakeEmulatorPID }
func (e *cov964Emulator) SocketPath() string { return e.socket }
func (e *cov964Emulator) StateDir() string   { return filepath.Dir(e.socket) }

// cov964Lookup is one GetByProfile answer.
type cov964Lookup struct {
	bundle *vtpm.VTPMInstance
	err    error
}

// cov964Generator is a vtpm.Generator that answers GetByProfile from a queue
// and GenerateForProfile with a fixed result. It records what it was asked
// for so tests can assert the profile and options the orchestrator sends.
type cov964Generator struct {
	vtpm.Generator
	lookups     []cov964Lookup
	generateErr error

	lookupIDs   []uint64
	generated   []*entities.DeviceProfile
	generateOpt []*vtpm.GenerateOptions
}

func (g *cov964Generator) GetByProfile(ctx context.Context, profileID uint64) (*vtpm.VTPMInstance, error) {
	g.lookupIDs = append(g.lookupIDs, profileID)
	next := g.lookups[0]
	g.lookups = g.lookups[1:]
	return next.bundle, next.err
}

func (g *cov964Generator) GenerateForProfile(ctx context.Context, profile *entities.DeviceProfile, opts *vtpm.GenerateOptions) (*vtpm.VTPMInstance, error) {
	g.generated = append(g.generated, profile)
	g.generateOpt = append(g.generateOpt, opts)
	return nil, g.generateErr
}

// cov964Bundle returns a vTPM bundle rooted in a temp directory.
func cov964Bundle(t *testing.T, id string) *vtpm.VTPMInstance {
	t.Helper()
	dir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(dir, "tpm"), 0700))
	return &vtpm.VTPMInstance{ID: id, StoragePath: dir, SocketPath: filepath.Join(dir, "swtpm.sock")}
}

// cov964Created returns a fake-host orchestrator and the internal record of
// one VM it created. The VM is never started.
func cov964Created(t *testing.T) (*QEMUOrchestrator, *qemuInstance) {
	t.Helper()
	orch := newSWTPMTestOrchestrator(t, &fakeHost{})
	inst, err := orch.Create(context.Background(), &entities.DeviceProfile{ID: 1, Name: "cov964"})
	require.NoError(t, err)
	return orch, orch.instances[inst.ID]
}

// cov964VMConfig returns a VM orchestrator config whose firmware is
// placeholder files and whose OVSDB socket is a path nothing listens on.
func cov964VMConfig(t *testing.T) *OrchestratorConfig {
	t.Helper()
	config := DefaultOrchestratorConfig(ComputeTypeVM)
	hostDir := t.TempDir()
	config.WorkDir = filepath.Join(hostDir, "work")
	config.OVSSocketPath = filepath.Join(hostDir, "ovsdb.sock")
	config.OVMFCode = writePlaceholder(t, hostDir, "OVMF_CODE.fd")
	config.OVMFCodeSecure = writePlaceholder(t, hostDir, "OVMF_CODE.secboot.fd")
	config.OVMFVars = writePlaceholder(t, hostDir, "OVMF_VARS.fd")
	return config
}

// cov964WrappedMsg asserts err is a *WrappedError with the given message.
func cov964WrappedMsg(t *testing.T, err error, msg string) {
	t.Helper()
	var wrapped *WrappedError
	require.ErrorAs(t, err, &wrapped)
	assert.Equal(t, msg, wrapped.Msg)
}

func TestCov964_ProvisionVTPM(t *testing.T) {
	ctx := context.Background()
	profile := &entities.DeviceProfile{ID: 9, Name: "cov964-profile"}

	t.Run("prestaged EK identity without a generator fails closed", func(t *testing.T) {
		orch := newSWTPMTestOrchestrator(t, &fakeHost{})

		_, err := orch.Create(ctx, &entities.DeviceProfile{ID: 3, Name: "staged", EKSerial: "01:02"})

		assert.ErrorIs(t, err, ErrVTPMIdentityRequired)
		assert.Empty(t, orch.instances)
	})

	t.Run("bundle lookup failure is not masked by generation", func(t *testing.T) {
		orch := newSWTPMTestOrchestrator(t, &fakeHost{})
		gen := &cov964Generator{lookups: []cov964Lookup{{err: errCov964Lookup}}}
		orch.SetVTPMGenerator(gen)

		_, err := orch.Create(ctx, profile)

		assert.ErrorIs(t, err, errCov964Lookup)
		cov964WrappedMsg(t, err, "failed to look up vTPM bundle for profile")
		assert.Equal(t, []uint64{profile.ID}, gen.lookupIDs)
		assert.Empty(t, gen.generated)
		assert.Empty(t, orch.instances)
	})

	t.Run("unassociated profile generates a bundle with the profile hostname", func(t *testing.T) {
		orch := newSWTPMTestOrchestrator(t, &fakeHost{})
		gen := &cov964Generator{
			lookups:     []cov964Lookup{{err: vtpm.ErrProfileNotAssociated{ProfileID: profile.ID}}},
			generateErr: errCov964Generate,
		}
		orch.SetVTPMGenerator(gen)

		_, err := orch.Create(ctx, profile)

		assert.ErrorIs(t, err, errCov964Generate)
		cov964WrappedMsg(t, err, "failed to generate vTPM bundle for profile")
		require.Len(t, gen.generated, 1)
		assert.Same(t, profile, gen.generated[0])
		assert.Equal(t, &vtpm.GenerateOptions{Hostname: profile.Name, SecureBootEnabled: false}, gen.generateOpt[0])
	})

	t.Run("bundle created concurrently is looked up again", func(t *testing.T) {
		bundle := cov964Bundle(t, "bundle-race")
		orch := newSWTPMTestOrchestrator(t, &fakeHost{})
		gen := &cov964Generator{
			lookups: []cov964Lookup{
				{err: vtpm.ErrProfileNotAssociated{ProfileID: profile.ID}},
				{bundle: bundle},
			},
			generateErr: vtpm.ErrVTPMAlreadyExists{ID: bundle.ID},
		}
		orch.SetVTPMGenerator(gen)

		inst, err := orch.Create(ctx, profile)

		require.NoError(t, err)
		assert.Equal(t, []uint64{profile.ID, profile.ID}, gen.lookupIDs)
		assert.Equal(t, bundle.ID, inst.Metadata["vtpm_bundle_id"])
		assert.Equal(t, bundle.SocketPath, inst.Metadata["tpm_socket"])
	})

	t.Run("second lookup after a concurrent create fails", func(t *testing.T) {
		orch := newSWTPMTestOrchestrator(t, &fakeHost{})
		gen := &cov964Generator{
			lookups: []cov964Lookup{
				{err: vtpm.ErrProfileNotAssociated{ProfileID: profile.ID}},
				{err: errCov964Lookup},
			},
			generateErr: vtpm.ErrVTPMAlreadyExists{ID: "other"},
		}
		orch.SetVTPMGenerator(gen)

		_, err := orch.Create(ctx, profile)

		assert.ErrorIs(t, err, errCov964Lookup)
		cov964WrappedMsg(t, err, "failed to generate vTPM bundle for profile")
		assert.Empty(t, orch.instances)
	})
}

func TestCov964_VTPMIdentityRequired(t *testing.T) {
	tests := []struct {
		name    string
		profile *entities.DeviceProfile
		cfg     *InstanceConfig
		want    bool
	}{
		{"secure boot without a profile", nil, &InstanceConfig{SecureBoot: true}, true},
		{"EK certificate", &entities.DeviceProfile{EKCert: "pem"}, &InstanceConfig{}, true},
		{"no profile and no config", nil, nil, false},
		{"anonymous profile", &entities.DeviceProfile{Name: "anon"}, &InstanceConfig{}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, vtpmIdentityRequired(tt.profile, tt.cfg))
		})
	}
}

func TestCov964_CreateWithSpecHostFailures(t *testing.T) {
	ctx := context.Background()
	profile := &entities.DeviceProfile{ID: 2, Name: "cov964"}

	t.Run("work directory cannot be created", func(t *testing.T) {
		orch := newSWTPMTestOrchestrator(t, &fakeHost{})
		blocker := filepath.Join(t.TempDir(), "file")
		require.NoError(t, os.WriteFile(blocker, nil, 0600))
		orch.config.WorkDir = blocker

		_, err := orch.Create(ctx, profile)

		cov964WrappedMsg(t, err, "failed to create instance work directory")
		assert.Empty(t, orch.instances)
	})

	t.Run("firmware removed after start-up", func(t *testing.T) {
		orch := newSWTPMTestOrchestrator(t, &fakeHost{})
		require.NoError(t, os.Remove(orch.config.OVMFCode))

		_, err := orch.Create(ctx, profile)

		cov964WrappedMsg(t, err, "failed to create VM")
		assert.ErrorIs(t, err, qemu.ErrOVMFNotFound)
		assert.Empty(t, orch.instances)
	})
}

func TestCov964_StartSWTPMFailures(t *testing.T) {
	ctx := context.Background()

	t.Run("swtpm does not start", func(t *testing.T) {
		orch, qi := cov964Created(t)
		emulator := &cov964Emulator{startErr: errCov964Start}
		qi.swtpm = emulator

		err := orch.Start(ctx, qi.instance.ID)

		assert.ErrorIs(t, err, errCov964Start)
		cov964WrappedMsg(t, err, "failed to start swtpm")
		assert.Equal(t, StateError, qi.instance.State)
		state, stateErr := orch.lifecycle.GetState(qi.instance.ID)
		require.NoError(t, stateErr)
		assert.Equal(t, StateError, state)
		assert.Zero(t, emulator.stopCalls)
	})

	t.Run("start refused outside the stopped state", func(t *testing.T) {
		orch, qi := cov964Created(t)
		require.NoError(t, orch.lifecycle.SetState(qi.instance.ID, StateError))

		err := orch.Start(ctx, qi.instance.ID)

		assert.ErrorIs(t, err, ErrInvalidState)
	})
}

func TestCov964_SWTPMStopFailureDoesNotBlockTeardown(t *testing.T) {
	t.Run("Delete", func(t *testing.T) {
		orch, qi := cov964Created(t)
		emulator := &cov964Emulator{running: true, stopErr: errCov964Stop}
		qi.swtpm = emulator
		workDir := qi.instance.Config.WorkDir

		require.NoError(t, orch.Delete(context.Background(), qi.instance.ID))

		assert.Equal(t, 1, emulator.stopCalls)
		assert.NotContains(t, orch.instances, qi.instance.ID)
		assert.NoDirExists(t, workDir)
	})

	t.Run("Close", func(t *testing.T) {
		orch, qi := cov964Created(t)
		emulator := &cov964Emulator{running: true, stopErr: errCov964Stop}
		qi.swtpm = emulator

		require.NoError(t, orch.Close())

		assert.Equal(t, 1, emulator.stopCalls)
	})

	t.Run("Close leaves a stopped swtpm alone", func(t *testing.T) {
		orch, qi := cov964Created(t)
		emulator := &cov964Emulator{}
		qi.swtpm = emulator

		require.NoError(t, orch.Close())

		assert.Zero(t, emulator.stopCalls)
	})
}

func TestCov964_MonitorSeamsNeedARunningVM(t *testing.T) {
	ctx := context.Background()
	orch, qi := cov964Created(t)

	tests := []struct {
		name string
		call func() error
	}{
		{"instanceMonitor", func() error {
			mon, err := instanceMonitor(ctx, qi)
			assert.Nil(t, mon)
			return err
		}},
		{"defaultVMRunControlFor", func() error {
			ctl, err := defaultVMRunControlFor(ctx, qi)
			assert.Nil(t, ctl)
			return err
		}},
		{"defaultVMDiskMonitorFor", func() error {
			ops, err := defaultVMDiskMonitorFor(ctx, orch, qi)
			assert.Nil(t, ops)
			return err
		}},
		{"defaultSnapshotOps", func() error {
			ops, err := orch.defaultSnapshotOps(ctx, qi)
			assert.Nil(t, ops)
			return err
		}},
		{"defaultVMBlockStatsFor", func() error {
			stats, err := defaultVMBlockStatsFor(ctx, orch, qi)
			assert.Nil(t, stats)
			return err
		}},
		{"defaultVMMigrationSessionFor", func() error {
			session, err := defaultVMMigrationSessionFor(ctx, orch, qi)
			assert.Nil(t, session)
			return err
		}},
		{"defaultSubscribeVMLifecycleEvents", func() error {
			emitted := 0
			err := defaultSubscribeVMLifecycleEvents(ctx, orch, qi, func(LogEntry) { emitted++ })
			assert.Zero(t, emitted)
			return err
		}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.call()

			assert.ErrorIs(t, err, qemu.ErrVMNotRunning)
			cov964WrappedMsg(t, err, "failed to connect QMP monitor")
		})
	}
}

func TestCov964_DefaultStopVMProcess(t *testing.T) {
	_, qi := cov964Created(t)

	for name, opts := range map[string]StopOptions{
		"force":   {Force: true},
		"timeout": {Timeout: time.Second},
		"default": {},
	} {
		t.Run(name, func(t *testing.T) {
			assert.ErrorIs(t, defaultStopVMProcess(qi, opts), qemu.ErrVMNotRunning)
		})
	}
}

func TestCov964_DefaultVTPMDeviceWithoutSWTPM(t *testing.T) {
	orch := newSWTPMTestOrchestrator(t, &fakeHost{})
	socket := filepath.Join(t.TempDir(), "missing.sock")

	device, err := orch.defaultVTPMDevice(socket)

	assert.Nil(t, device)
	assert.ErrorIs(t, err, ErrVTPMNotAvailable)
	var connErr vtpm.ErrTPMConnectionFailed
	require.ErrorAs(t, err, &connErr)
	assert.Equal(t, socket, connErr.SocketPath)
}

func TestCov964_RealMigrateSessionNeedsAConnectedMonitor(t *testing.T) {
	ctx := context.Background()
	logger := logging.DefaultLogger()
	mon := qemu.NewMonitor(filepath.Join(t.TempDir(), "qmp.sock"), time.Second, logger)
	session := &realMigrateSession{mon: mon, mgr: qemu.NewMigrationManager(mon, logger)}

	tests := []struct {
		name string
		call func() error
	}{
		{"Pause", func() error { return session.Pause(ctx) }},
		{"Resume", func() error { return session.Resume(ctx) }},
		{"ObjectAdd", func() error {
			return session.ObjectAdd(ctx, "tls-creds-x509", "migtls", map[string]interface{}{"endpoint": "client"})
		}},
		{"SetParameters", func() error { return session.SetParameters(ctx, &qemu.MigrationParams{TLSCreds: "migtls"}) }},
		{"SetCapabilities", func() error { return session.SetCapabilities(ctx, []string{"x-ignore-shared"}) }},
		{"Migrate", func() error { return session.Migrate(ctx, "tcp:127.0.0.1:4444") }},
		{"Status", func() error {
			status, err := session.Status(ctx)
			assert.Nil(t, status)
			return err
		}},
		{"Cancel", func() error { return session.Cancel(ctx) }},
		{"Quit", func() error { return session.Quit(ctx) }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.ErrorIs(t, tt.call(), qemu.ErrMonitorNotConnected{})
		})
	}
}

func TestCov964_QEMUIncomingReceiver(t *testing.T) {
	ctx := context.Background()
	_, qi := cov964Created(t)
	mon := qemu.NewMonitor(filepath.Join(t.TempDir(), "qmp.sock"), time.Second, logging.DefaultLogger())
	receiver := &qemuIncomingReceiver{vm: qi.vm, monitor: mon, port: 49152}

	assert.Equal(t, 49152, receiver.Port())

	err := receiver.Commit(ctx)
	assert.ErrorIs(t, err, qemu.ErrMonitorNotConnected{})
	cov964WrappedMsg(t, err, "resume received guest")

	assert.ErrorIs(t, receiver.Abort(ctx), qemu.ErrVMNotRunning)
}

func TestCov964_DefaultNewIncomingReceiverHostFailures(t *testing.T) {
	ctx := context.Background()

	t.Run("work directory cannot be created", func(t *testing.T) {
		orch := newSWTPMTestOrchestrator(t, &fakeHost{})
		blocker := filepath.Join(t.TempDir(), "file")
		require.NoError(t, os.WriteFile(blocker, nil, 0600))
		orch.config.WorkDir = blocker

		receiver, err := defaultNewIncomingReceiver(ctx, &incomingReceiverParams{
			orchestrator: orch,
			spec:         MigrationSpec{Config: &InstanceConfig{}},
		})

		assert.Nil(t, receiver)
		cov964WrappedMsg(t, err, "create receiver work directory")
	})

	t.Run("receiver VM refused before any disk is made", func(t *testing.T) {
		orch := newSWTPMTestOrchestrator(t, &fakeHost{})
		require.NoError(t, os.Remove(orch.config.OVMFCode))

		receiver, err := defaultNewIncomingReceiver(ctx, &incomingReceiverParams{
			orchestrator: orch,
			spec:         MigrationSpec{Config: &InstanceConfig{}},
		})

		assert.Nil(t, receiver)
		cov964WrappedMsg(t, err, "create receiver VM")
		assert.ErrorIs(t, err, qemu.ErrOVMFNotFound)
		dirs, globErr := filepath.Glob(filepath.Join(orch.config.WorkDir, "incoming-*"))
		require.NoError(t, globErr)
		require.Len(t, dirs, 1)
		assert.NoFileExists(t, filepath.Join(dirs[0], "disk.qcow2"))
	})
}

func TestCov964_QEMUFactory(t *testing.T) {
	ctx := context.Background()

	t.Run("nil config", func(t *testing.T) {
		orch, err := newQEMUOrchestratorForConfig(ctx, nil, nil)

		assert.Nil(t, orch)
		assert.ErrorIs(t, err, ErrInvalidConfiguration)
	})

	t.Run("alias resolves to a VM orchestrator carrying the generator", func(t *testing.T) {
		config := cov964VMConfig(t)
		config.Provider = "qemu"
		gen := &cov964Generator{}

		orch, err := NewOrchestratorForConfig(ctx, config, &Deps{VTPMGenerator: gen})
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, orch.Close()) })

		qemuOrch, ok := orch.(*QEMUOrchestrator)
		require.True(t, ok)
		assert.Same(t, gen, qemuOrch.vtpmGenerator)
		assert.Equal(t, ComputeTypeVM, qemuOrch.config.Type)
		assert.Equal(t, ProviderLocalQEMU, qemuOrch.config.Provider)
		assert.Equal(t, ProviderKind("qemu"), config.Provider, "the caller's config is not modified")
	})

	t.Run("nil deps leaves the generator unset", func(t *testing.T) {
		orch, err := newQEMUOrchestratorForConfig(ctx, cov964VMConfig(t), nil)
		require.NoError(t, err)
		t.Cleanup(func() { assert.NoError(t, orch.Close()) })

		assert.Nil(t, orch.(*QEMUOrchestrator).vtpmGenerator)
	})

	t.Run("invalid config is refused", func(t *testing.T) {
		config := cov964VMConfig(t)
		config.WorkDir = ""

		orch, err := newQEMUOrchestratorForConfig(ctx, config, &Deps{})

		assert.Nil(t, orch)
		assert.Error(t, err)
	})
}

func TestCov964_DepsLogger(t *testing.T) {
	custom := logging.DefaultLogger()

	assert.Same(t, custom, (&Deps{Logger: custom}).logger())
	assert.NotNil(t, (*Deps)(nil).logger())
	assert.NotNil(t, (&Deps{}).logger())
	assert.NotSame(t, custom, (&Deps{}).logger())
}

func TestCov964_ProviderKindNames(t *testing.T) {
	tests := []struct {
		kind     ProviderKind
		want     ProviderKind
		wantVM   bool
		buildTag string
	}{
		{"", ProviderLocalContainer, false, "local-container"},
		{"container", ProviderLocalContainer, false, "local-container"},
		{"vm", ProviderLocalQEMU, true, "local-qemu"},
		{"qemu", ProviderLocalQEMU, true, "local-qemu"},
		{ProviderLocalQEMU, ProviderLocalQEMU, true, "local-qemu"},
		{ProviderAWS, ProviderAWS, false, "awscompute"},
		{ProviderGCP, ProviderGCP, false, "gcpcompute"},
		{ProviderAzure, ProviderAzure, false, "azurecompute"},
	}
	for _, tt := range tests {
		t.Run(string(tt.kind), func(t *testing.T) {
			assert.Equal(t, string(tt.want), tt.kind.String())
			assert.Equal(t, tt.wantVM, tt.kind.IsVM())
			assert.Equal(t, tt.buildTag, buildTagFor(tt.kind))
		})
	}
}

func TestCov964_RegisteredProvidersSorted(t *testing.T) {
	kinds := RegisteredProviders()

	assert.Contains(t, kinds, ProviderLocalQEMU)
	assert.True(t, slices.IsSorted(kinds))
}

func TestCov964_ApplyLocalQEMUDefaultsFollowsHost(t *testing.T) {
	got := &OrchestratorConfig{}
	want := &OrchestratorConfig{}

	gotErr := got.ApplyLocalQEMUDefaults()
	wantErr := want.applyLocalQEMUDefaults(runtime.GOARCH)

	assert.Equal(t, wantErr, gotErr)
	assert.Equal(t, want, got)
	assert.Equal(t, ComputeTypeVM, got.Type)
}

// cov964Session is a migration session whose rollback and teardown calls can
// fail, so a test can prove those failures never decide the migration outcome.
type cov964Session struct {
	*fakeMigrateSession
	cancelErr error
	resumeErr error
	quitErr   error
}

func (s *cov964Session) Cancel(ctx context.Context) error {
	s.cancelled = true
	return s.cancelErr
}

func (s *cov964Session) Resume(ctx context.Context) error {
	s.resumed = true
	return s.resumeErr
}

func (s *cov964Session) Quit(ctx context.Context) error {
	s.quit = true
	return s.quitErr
}

// cov964Coordinator is a destination whose Finalize can fail. It records every
// Finalize call through the embedded fake.
type cov964Coordinator struct {
	*fakeCoordinator
	failFinalize  error
	finalizeCalls int
}

func (c *cov964Coordinator) Finalize(ctx context.Context, destination string, spec MigrationSpec, streamErr error) error {
	c.finalizeCalls++
	if err := c.fakeCoordinator.Finalize(ctx, destination, spec, streamErr); err != nil {
		return err
	}
	return c.failFinalize
}

// cov964Migration wires a running "vm1" for a cold migration with a session
// and destination that can fail where the shared fakes cannot.
func cov964Migration(t *testing.T) (*QEMUOrchestrator, *cov964Session, *cov964Coordinator) {
	t.Helper()
	orch, coord, _, fake := migrateTestOrchestrator(t, false)
	sess := &cov964Session{fakeMigrateSession: fake}
	dest := &cov964Coordinator{fakeCoordinator: coord}
	orch.config.MigrationCoordinator = dest

	prev := vmMigrationSessionFor
	vmMigrationSessionFor = func(ctx context.Context, o *QEMUOrchestrator, inst *qemuInstance) (MigrationSession, error) {
		return sess, nil
	}
	t.Cleanup(func() { vmMigrationSessionFor = prev })
	return orch, sess, dest
}

func TestCov964_MigrateVMFailureKeepsTheSource(t *testing.T) {
	cases := []struct {
		name        string
		setup       func(*cov964Session, *cov964Coordinator)
		wantMsg     string
		wantPaused  bool
		wantResumed bool
	}{
		{
			name:    "set parameters fails",
			setup:   func(s *cov964Session, _ *cov964Coordinator) { s.failAt = "SetParameters" },
			wantMsg: "migrate-set-parameters failed",
		},
		{
			name:    "pause fails",
			setup:   func(s *cov964Session, _ *cov964Coordinator) { s.failAt = "Pause" },
			wantMsg: "pause for cold migration failed",
		},
		{
			name: "set capabilities fails and every rollback step fails",
			setup: func(s *cov964Session, c *cov964Coordinator) {
				s.failAt = "SetCapabilities"
				s.cancelErr = errCov964Rollback
				s.resumeErr = errCov964Rollback
				c.failFinalize = errCov964Rollback
			},
			wantMsg:     "migrate-set-capabilities failed",
			wantPaused:  true,
			wantResumed: true,
		},
		{
			name:        "status query fails",
			setup:       func(s *cov964Session, _ *cov964Coordinator) { s.failAt = "Status" },
			wantMsg:     "query-migrate failed",
			wantPaused:  true,
			wantResumed: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			orch, sess, dest := cov964Migration(t)
			tc.setup(sess, dest)

			_, err := migrateOnFakeClock(t, orch, MigrateOptions{})
			require.Error(t, err)
			assert.ErrorIs(t, err, ErrMigrationFailed)
			cov964WrappedMsg(t, err, tc.wantMsg)

			assert.Equal(t, tc.wantPaused, sess.paused)
			assert.Equal(t, tc.wantResumed, sess.resumed)
			assert.False(t, sess.quit, "a failed migration must not quit the source")
			assert.Equal(t, 1, dest.finalizeCalls, "the destination receiver is aborted once")
			assert.Error(t, dest.finalizeErr, "the abort carries the failure")

			_, getErr := orch.Get(context.Background(), "vm1")
			assert.NoError(t, getErr, "the source VM survives")
		})
	}
}

func TestCov964_MigrateVMSessionUnavailable(t *testing.T) {
	orch, _, dest := cov964Migration(t)
	vmMigrationSessionFor = func(ctx context.Context, o *QEMUOrchestrator, inst *qemuInstance) (MigrationSession, error) {
		return nil, errCov964Session
	}

	_, err := orch.MigrateVM(context.Background(), "vm1", "dest.example:10443", MigrateOptions{})
	assert.Same(t, errCov964Session, err, "the session error is returned unwrapped")
	assert.Same(t, errCov964Session, dest.finalizeErr, "the destination learns why it was aborted")
}

func TestCov964_MigrateVMDestinationFinalizeFails(t *testing.T) {
	orch, sess, dest := cov964Migration(t)
	dest.failFinalize = errCov964Finalize

	_, err := migrateOnFakeClock(t, orch, MigrateOptions{})
	require.Error(t, err)
	assert.ErrorIs(t, err, ErrMigrationFailed)
	assert.ErrorIs(t, err, errCov964Finalize)
	cov964WrappedMsg(t, err, "destination finalize failed")
	assert.NoError(t, dest.finalizeErr, "finalize reported a successful stream")
	assert.False(t, sess.quit, "the source is kept when the destination did not take the guest")

	_, getErr := orch.Get(context.Background(), "vm1")
	assert.NoError(t, getErr)
}

func TestCov964_MigrateVMSourceQuitFailureStillRetires(t *testing.T) {
	orch, sess, _ := cov964Migration(t)
	sess.quitErr = errCov964Rollback
	orch.mu.RLock()
	workDir := orch.instances["vm1"].instance.Config.WorkDir
	orch.mu.RUnlock()

	result, err := migrateOnFakeClock(t, orch, MigrateOptions{})
	require.NoError(t, err)
	assert.True(t, result.Success)
	assert.True(t, sess.quit)

	_, getErr := orch.Get(context.Background(), "vm1")
	assert.ErrorIs(t, getErr, ErrInstanceNotFound)
	assert.NoDirExists(t, workDir, "the retired VM's work directory is removed")
}

func TestCov964_MigrateVMDeadlineCancelsTheStream(t *testing.T) {
	orch, sess, dest := cov964Migration(t)
	sess.statusResult = qemu.MigrationStatusActive

	var err error
	synctest.Test(t, func(*testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_, err = orch.MigrateVM(ctx, "vm1", "dest.example:10443", MigrateOptions{})
	})
	assert.ErrorIs(t, err, context.DeadlineExceeded)
	assert.True(t, sess.cancelled, "the stuck stream is cancelled")
	assert.True(t, sess.resumed, "the cold-paused guest is resumed")
	assert.ErrorIs(t, dest.finalizeErr, ErrMigrationFailed)
}

func TestCov964_MigrateVMUnknownInstance(t *testing.T) {
	orch, _, dest := cov964Migration(t)

	_, err := orch.MigrateVM(context.Background(), "ghost", "dest.example:10443", MigrateOptions{})
	assert.ErrorIs(t, err, ErrInstanceNotFound)
	assert.False(t, dest.prepared, "the destination is never contacted")

	orch.retireMigratedInstance("ghost")
	_, getErr := orch.Get(context.Background(), "vm1")
	assert.NoError(t, getErr, "retiring an unknown VM leaves the others alone")
}

func TestCov964_GetVMMetricsReadFailures(t *testing.T) {
	cases := []struct {
		name string
		cpu  func(int) (uint64, error)
		rss  func(int) (uint64, error)
	}{
		{
			name: "second CPU sample fails",
			cpu: func() func(int) (uint64, error) {
				calls := 0
				return func(int) (uint64, error) {
					calls++
					if calls == 1 {
						return 100, nil
					}
					return 0, errCov964Proc
				}
			}(),
			rss: func(int) (uint64, error) { return 0, nil },
		},
		{
			name: "RSS read fails",
			cpu:  func(int) (uint64, error) { return 100, nil },
			rss:  func(int) (uint64, error) { return 0, errCov964Proc },
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			orch := newOpsOrchestrator(t)
			insertVMInstance(t, orch, "vm1", true, &InstanceConfig{WorkDir: t.TempDir(), Memory: 1024})
			restore := swapMetricsSeams(t, tc.cpu, tc.rss,
				func(string) (uint64, uint64, error) { return 0, 0, nil },
				func(context.Context, *QEMUOrchestrator, *qemuInstance) ([]qemu.BlockStat, error) { return nil, nil },
			)
			defer restore()
			cpuSampleInterval = time.Millisecond

			_, err := orch.GetVMMetrics(context.Background(), "vm1")
			assert.ErrorIs(t, err, ErrVMMetricsUnavailable)
			assert.ErrorIs(t, err, errCov964Proc)
		})
	}
}

func TestCov964_GetVMMetricsDegradedSample(t *testing.T) {
	orch := newOpsOrchestrator(t)
	qi := insertVMInstance(t, orch, "vm1", true, &InstanceConfig{WorkDir: t.TempDir(), Memory: 1024})
	qi.instance.StartedAt = time.Time{}
	qi.instance.CreatedAt = time.Now().Add(-2 * time.Minute)

	samples := []uint64{500, 400} // the counter goes backwards
	restore := swapMetricsSeams(t,
		func(int) (uint64, error) {
			v := samples[0]
			samples = samples[1:]
			return v, nil
		},
		func(int) (uint64, error) { return 256 * 1024 * 1024, nil },
		func(string) (uint64, uint64, error) { return 0, 0, nil },
		func(context.Context, *QEMUOrchestrator, *qemuInstance) ([]qemu.BlockStat, error) {
			return nil, errCov964Block
		},
	)
	defer restore()
	cpuSampleInterval = time.Millisecond

	metrics, err := orch.GetVMMetrics(context.Background(), "vm1")
	require.NoError(t, err, "a block stats failure does not fail the sample")
	assert.Zero(t, metrics.CPUUsagePercent, "a counter that went backwards reads as idle")
	assert.Equal(t, uint64(256), metrics.MemoryUsedMB)
	assert.Equal(t, uint64(1024-256), metrics.MemoryAvailableMB)
	assert.Zero(t, metrics.DiskReadBytes)
	assert.Zero(t, metrics.DiskWriteBytes)
	assert.GreaterOrEqual(t, metrics.UptimeSeconds, uint32(120), "uptime falls back to the creation time")
}

// cov964LogVM inserts a VM whose work directory holds the given serial
// transcript; a nil transcript leaves serial.log absent.
func cov964LogVM(t *testing.T, transcript []byte) (*QEMUOrchestrator, string) {
	t.Helper()
	orch := newOpsOrchestrator(t)
	wd := t.TempDir()
	if transcript != nil {
		require.NoError(t, os.WriteFile(filepath.Join(wd, "serial.log"), transcript, 0o600))
	}
	insertVMInstance(t, orch, "vm1", true, &InstanceConfig{WorkDir: wd})
	return orch, wd
}

// cov964SwapEvents replaces the QMP lifecycle subscription for one test.
func cov964SwapEvents(t *testing.T, fn func(context.Context, *QEMUOrchestrator, *qemuInstance, func(LogEntry)) error) {
	t.Helper()
	prev := subscribeVMLifecycleEvents
	subscribeVMLifecycleEvents = fn
	t.Cleanup(func() { subscribeVMLifecycleEvents = prev })
}

func TestCov964_StreamVMLogsBacklog(t *testing.T) {
	t.Run("no work directory", func(t *testing.T) {
		orch := newOpsOrchestrator(t)
		insertVMInstance(t, orch, "vm1", true, nil)
		err := orch.StreamVMLogs(context.Background(), "vm1", VMLogOptions{}, func(LogEntry) error { return nil })
		assert.ErrorIs(t, err, ErrVMLogsUnavailable)
	})

	t.Run("transcript is unreadable", func(t *testing.T) {
		orch, wd := cov964LogVM(t, nil)
		require.NoError(t, os.Mkdir(filepath.Join(wd, "serial.log"), 0o700))
		err := orch.StreamVMLogs(context.Background(), "vm1", VMLogOptions{}, func(LogEntry) error { return nil })
		cov964WrappedMsg(t, err, "failed to read serial transcript")
		assert.NotErrorIs(t, err, ErrVMLogsUnavailable)
	})

	t.Run("sink error stops the backlog", func(t *testing.T) {
		orch, _ := cov964LogVM(t, []byte("first\nsecond\n"))
		var got []string
		err := orch.StreamVMLogs(context.Background(), "vm1", VMLogOptions{}, func(e LogEntry) error {
			got = append(got, e.Message)
			return errCov964Sink
		})
		assert.ErrorIs(t, err, errCov964Sink)
		assert.Equal(t, []string{"first"}, got)
	})

	t.Run("since filter drops older entries", func(t *testing.T) {
		orch, _ := cov964LogVM(t, []byte("first\nsecond\n"))
		calls := 0
		err := orch.StreamVMLogs(context.Background(), "vm1", VMLogOptions{Since: time.Now().Add(time.Hour)}, func(LogEntry) error {
			calls++
			return nil
		})
		require.NoError(t, err)
		assert.Zero(t, calls)
	})
}

func TestCov964_FollowVMLogs(t *testing.T) {
	t.Run("transcript created after follow starts", func(t *testing.T) {
		orch, wd := cov964LogVM(t, nil)
		// The subscription fails, which must not stop the serial tail. It runs
		// once follow has begun, so it is where the transcript first appears.
		cov964SwapEvents(t, func(context.Context, *QEMUOrchestrator, *qemuInstance, func(LogEntry)) error {
			if err := os.WriteFile(filepath.Join(wd, "serial.log"), []byte("boot ok\n"), 0o600); err != nil {
				return err
			}
			return errCov964Events
		})

		var got []LogEntry
		var err error
		synctest.Test(t, func(*testing.T) {
			err = orch.StreamVMLogs(context.Background(), "vm1", VMLogOptions{Follow: true}, func(e LogEntry) error {
				got = append(got, e)
				return errCov964Sink
			})
		})
		assert.ErrorIs(t, err, errCov964Sink)
		require.Len(t, got, 1)
		assert.Equal(t, "boot ok", got[0].Message)
		assert.Equal(t, "serial", got[0].Source)
	})

	t.Run("lifecycle event sink error", func(t *testing.T) {
		orch, _ := cov964LogVM(t, []byte{})
		cov964SwapEvents(t, func(_ context.Context, _ *QEMUOrchestrator, _ *qemuInstance, emit func(LogEntry)) error {
			emit(LogEntry{Source: "qmp", Message: "STOP"})
			return nil
		})

		var got []string
		var err error
		synctest.Test(t, func(*testing.T) {
			err = orch.StreamVMLogs(context.Background(), "vm1", VMLogOptions{Follow: true}, func(e LogEntry) error {
				got = append(got, e.Message)
				return errCov964Sink
			})
		})
		assert.ErrorIs(t, err, errCov964Sink)
		assert.Equal(t, []string{"STOP"}, got)
	})
}

func TestCov964_SerialTailerPollFailures(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "plain")
	require.NoError(t, os.WriteFile(file, []byte("x"), 0o600))

	cases := []struct {
		name string
		path string
	}{
		{"path is a directory", dir},
		{"parent is a file", filepath.Join(file, "serial.log")},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tail := &serialTailer{path: tc.path}
			lines, err := tail.poll()
			assert.Error(t, err)
			assert.Nil(t, lines)
			assert.Zero(t, tail.offset)
		})
	}
}

// cov964DiskMon is a QMP disk seam whose blockdev-del can fail.
type cov964DiskMon struct {
	*fakeDiskMon
	blockdevDelErr error
}

func (m *cov964DiskMon) BlockdevDel(ctx context.Context, nodeName string) error {
	m.blockdevDel = append(m.blockdevDel, nodeName)
	return m.blockdevDelErr
}

// cov964DiskSeams installs a disk monitor and qemu-img result for one test.
func cov964DiskSeams(t *testing.T, mon diskMonitorOps, monErr, imgErr error) *[]string {
	t.Helper()
	imgCalls := installDiskSeams(t, &fakeDiskMon{}, imgErr)
	vmDiskMonitorFor = func(context.Context, *QEMUOrchestrator, *qemuInstance) (diskMonitorOps, error) {
		if monErr != nil {
			return nil, monErr
		}
		return mon, nil
	}
	return imgCalls
}

func TestCov964_DiskMonitorUnavailable(t *testing.T) {
	orch := newOpsOrchestrator(t)
	wd := t.TempDir()
	diskPath := filepath.Join(wd, "d.qcow2")
	require.NoError(t, os.WriteFile(diskPath, []byte("x"), 0o600))
	qi := insertVMInstance(t, orch, "vm1", true, &InstanceConfig{WorkDir: wd, DiskPath: "/boot.qcow2"})
	qi.instance.Disks = []DiskInfo{{ID: "d1", NodeName: "node-d1", DeviceID: "disk-d1"}}
	cov964DiskSeams(t, nil, errCov964Disk, nil)

	ops := map[string]func() error{
		"attach": func() error {
			_, err := orch.AttachDisk(context.Background(), "vm1", DiskAttachRequest{ID: "d2", Path: diskPath})
			return err
		},
		"detach": func() error { return orch.DetachDisk(context.Background(), "vm1", "d1") },
		"resize": func() error { return orch.ResizeDisk(context.Background(), "vm1", "d1", 8) },
	}
	for name, op := range ops {
		t.Run(name, func(t *testing.T) {
			assert.Same(t, errCov964Disk, op())
			assert.Len(t, qi.instance.Disks, 1, "the tracked disks are unchanged")
		})
	}
}

func TestCov964_AttachDiskFailures(t *testing.T) {
	cases := []struct {
		name      string
		mon       *cov964DiskMon
		imgErr    error
		req       func(wd string) DiskAttachRequest
		wantMsg   string
		wantImg   []string
		wantDelBD []string
	}{
		{
			name: "backing image cannot be inspected",
			mon:  &cov964DiskMon{fakeDiskMon: &fakeDiskMon{}},
			req: func(wd string) DiskAttachRequest {
				return DiskAttachRequest{ID: "d1", Path: filepath.Join(wd, "existing", "d.qcow2"), SizeGB: 1}
			},
			wantMsg: "failed to stat disk image",
		},
		{
			name:   "backing image creation fails",
			mon:    &cov964DiskMon{fakeDiskMon: &fakeDiskMon{}},
			imgErr: errCov964Img,
			req: func(wd string) DiskAttachRequest {
				return DiskAttachRequest{ID: "d1", Path: filepath.Join(wd, "new.qcow2"), SizeGB: 1}
			},
			wantMsg: "failed to create disk image",
			wantImg: []string{"create"},
		},
		{
			name: "blockdev-add fails",
			mon:  &cov964DiskMon{fakeDiskMon: &fakeDiskMon{addErr: errCov964Disk}},
			req: func(wd string) DiskAttachRequest {
				return DiskAttachRequest{ID: "d1", Path: filepath.Join(wd, "existing")}
			},
			wantMsg: "blockdev-add failed",
		},
		{
			name: "device_add fails and the rollback fails",
			mon: &cov964DiskMon{
				fakeDiskMon:    &fakeDiskMon{devAddErr: errCov964Disk},
				blockdevDelErr: errCov964Disk,
			},
			req: func(wd string) DiskAttachRequest {
				return DiskAttachRequest{ID: "d1", Path: filepath.Join(wd, "existing")}
			},
			wantMsg:   "device_add failed",
			wantDelBD: []string{"node-d1"},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			orch := newOpsOrchestrator(t)
			wd := t.TempDir()
			// "existing" is a regular file, so a path beneath it cannot be stat'd.
			require.NoError(t, os.WriteFile(filepath.Join(wd, "existing"), []byte("x"), 0o600))
			qi := insertVMInstance(t, orch, "vm1", true, &InstanceConfig{WorkDir: wd})
			imgCalls := cov964DiskSeams(t, tc.mon, nil, tc.imgErr)

			info, err := orch.AttachDisk(context.Background(), "vm1", tc.req(wd))
			assert.Nil(t, info)
			cov964WrappedMsg(t, err, tc.wantMsg)
			assert.True(t, slices.Equal(tc.wantImg, *imgCalls), "qemu-img calls: %v", *imgCalls)
			assert.Equal(t, tc.wantDelBD, tc.mon.blockdevDel)
			assert.Empty(t, qi.instance.Disks, "a failed attach records nothing")
		})
	}
}

func TestCov964_DetachDiskQMPResults(t *testing.T) {
	cases := []struct {
		name      string
		mon       *cov964DiskMon
		wantMsg   string
		wantDisks int
	}{
		{
			name:      "device_del fails and the disk stays tracked",
			mon:       &cov964DiskMon{fakeDiskMon: &fakeDiskMon{devDelErr: errCov964Disk}},
			wantMsg:   "device_del failed",
			wantDisks: 1,
		},
		{
			name: "pending blockdev-del still untracks the disk",
			mon:  &cov964DiskMon{fakeDiskMon: &fakeDiskMon{}, blockdevDelErr: errCov964Disk},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			orch := newOpsOrchestrator(t)
			qi := insertVMInstance(t, orch, "vm1", true, &InstanceConfig{WorkDir: t.TempDir()})
			qi.instance.Disks = []DiskInfo{{ID: "d1", NodeName: "node-d1", DeviceID: "disk-d1"}}
			cov964DiskSeams(t, tc.mon, nil, nil)

			err := orch.DetachDisk(context.Background(), "vm1", "d1")
			if tc.wantMsg == "" {
				require.NoError(t, err)
				assert.Equal(t, []string{"node-d1"}, tc.mon.blockdevDel)
			} else {
				cov964WrappedMsg(t, err, tc.wantMsg)
				assert.Empty(t, tc.mon.blockdevDel)
			}
			assert.Equal(t, []string{"disk-d1"}, tc.mon.deviceDel)
			assert.Len(t, qi.instance.Disks, tc.wantDisks)
		})
	}
}

func TestCov964_ResizeDiskFailures(t *testing.T) {
	cases := []struct {
		name    string
		running bool
		wantMsg string
		wantImg []string
	}{
		{"online block_resize fails", true, "online block_resize failed", nil},
		{"offline qemu-img resize fails", false, "offline qemu-img resize failed", []string{"resize"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			orch := newOpsOrchestrator(t)
			qi := insertVMInstance(t, orch, "vm1", tc.running, &InstanceConfig{WorkDir: t.TempDir(), DiskPath: "/boot.qcow2"})
			qi.instance.Disks = []DiskInfo{{ID: "d1", NodeName: "node-d1", Path: "/d1.qcow2", SizeGB: 5}}
			mon := &cov964DiskMon{fakeDiskMon: &fakeDiskMon{resizeErr: errCov964Disk}}
			imgCalls := cov964DiskSeams(t, mon, nil, errCov964Img)

			err := orch.ResizeDisk(context.Background(), "vm1", "d1", 10)
			cov964WrappedMsg(t, err, tc.wantMsg)
			assert.True(t, slices.Equal(tc.wantImg, *imgCalls), "qemu-img calls: %v", *imgCalls)
			assert.Equal(t, uint64(5), qi.instance.Disks[0].SizeGB, "a failed resize keeps the recorded size")
		})
	}
}

// cov964VTPM is a fake vTPM session whose Close fails, so a test can prove a
// release failure never changes an attestation result.
type cov964VTPM struct {
	*fakeVTPMDevice
	closeErr error
}

func (d *cov964VTPM) Close() error {
	d.closed = true
	return d.closeErr
}

func TestCov964_VTPMSessionFailures(t *testing.T) {
	orch, device := newAttestTestOrchestrator(t)
	addFakeVMInstance(t, orch, "vm1", true, "/vms/vm1/disk.qcow2", "/tmp/swtpm.sock")
	session := &cov964VTPM{fakeVTPMDevice: device, closeErr: errCov964Rollback}
	orch.vtpmDeviceFor = func(string) (vm.VTPMDevice, error) { return session, nil }
	ctx := context.Background()
	nonce := []byte("cov964-nonce")

	report, err := orch.AttestVM(ctx, "vm1", nonce, []int{0})
	require.NoError(t, err, "a failed release does not fail the quote")
	assert.True(t, session.closed)

	t.Run("live PCR read fails", func(t *testing.T) {
		session.closed = false
		result, err := orch.VerifyVMAttestation(ctx, "vm1", &VMAttestationEvidence{
			Quote:              report.Quote,
			Signature:          report.Signature,
			SignatureAlgorithm: report.SignatureAlgorithm,
			Nonce:              nonce,
			ExpectedPCRs:       map[int][]byte{0: device.pcrValues[0], 24: make([]byte, 32)},
		})
		require.NoError(t, err)
		assert.True(t, result.SignatureValid)
		assert.False(t, result.PCRsValid, "PCR 24 is not in the quote")
		assert.Contains(t, result.ActualPCRs, 0)
		assert.NotContains(t, result.ActualPCRs, 24, "an unreadable PCR is left out of the diagnostics")
		assert.True(t, session.closed)
	})

	t.Run("AK read fails", func(t *testing.T) {
		device.aikErr = errCov964Rollback
		defer func() { device.aikErr = nil }()
		session.closed = false

		_, err := orch.VerifyVMAttestation(ctx, "vm1", &VMAttestationEvidence{
			Quote: report.Quote, Signature: report.Signature, Nonce: nonce,
		})
		assert.ErrorIs(t, err, ErrVTPMNotAvailable)
		assert.ErrorIs(t, err, errCov964Rollback)
		assert.True(t, session.closed, "the session is released on failure")
	})
}

func TestCov964_PlaceVNICPolicyDefaultTenant(t *testing.T) {
	engine, err := policy.NewEngine(policy.Config{BridgeName: "br-int", FlowController: &fakeOVSPort{}})
	require.NoError(t, err)

	placement, err := PlaceVNIC(context.Background(), &PlaceVNICConfig{
		Profile:      &entities.DeviceProfile{Zone: string(zone.ZoneStorage)},
		Plan:         placementPlan(t),
		PolicyEngine: engine,
		PortID:       "tap5",
	})
	require.NoError(t, err)
	assert.Equal(t, 407, int(placement.VLAN))

	got, err := engine.GetPolicy("tap5")
	require.NoError(t, err)
	assert.Equal(t, "default", got.TenantID, "an unnamed tenant is placed under the default tenant")
	assert.Equal(t, zone.ZoneStorage, got.Zone)
}

// cov964VLANRefusingPort is an OVS port controller that refuses VLAN tags.
type cov964VLANRefusingPort struct {
	*fakeOVSPort
}

func (p *cov964VLANRefusingPort) SetPortVLAN(context.Context, string, int64) error {
	return errCov964Rollback
}

func TestCov964_PlaceVNICZoneFlowFailure(t *testing.T) {
	plan := placementPlan(t)
	flows := &fakeOVSPort{}
	zfm, err := policy.NewZoneFlowManager(policy.ZoneFlowManagerConfig{
		BridgeName:     "br-int",
		FlowController: flows,
		PortController: &cov964VLANRefusingPort{fakeOVSPort: &fakeOVSPort{}},
		Plan:           plan,
	})
	require.NoError(t, err)

	placement, err := PlaceVNIC(context.Background(), &PlaceVNICConfig{
		Profile:         &entities.DeviceProfile{Zone: string(zone.ZoneBackup)},
		Plan:            plan,
		ZoneFlowManager: zfm,
		PortID:          "tap6",
	})
	assert.Nil(t, placement)
	assert.ErrorIs(t, err, errCov964Rollback)
	cov964WrappedMsg(t, err, "compute: place vnic: apply zone flows")
	assert.Zero(t, flows.flows, "no zone flows are installed on an untagged port")
}
