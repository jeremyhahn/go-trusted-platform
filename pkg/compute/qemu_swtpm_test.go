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
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
	"github.com/jeremyhahn/go-trusted-platform/pkg/swtpm"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The unit tests never run swtpm, swtpm_setup or qemu-img. fakeHost stands
// in for all three; the real binaries are exercised by
// test/integration/vtpm/qemu_test.go.

var (
	errFakeEmulator = &MessageError{Msg: "fake swtpm failure"}
	errFakeDisk     = &MessageError{Msg: "fake qemu-img failure"}
)

// fakeEmulatorPID is the PID a running fakeEmulator reports.
const fakeEmulatorPID = 4242

// fakeEmulator is an in-memory swtpm. Initialize writes the state file the
// real swtpm_setup writes, so IsInitialized answers from the state directory
// exactly as swtpm does.
type fakeEmulator struct {
	config   *swtpm.Config
	initErr  error
	initRuns atomic.Int32
	running  atomic.Bool

	// movedSockets, when set, are the sockets successive starts listen on
	// in place of the configured one, as swtpm does with a socket path too
	// long for a Unix socket.
	movedSockets []string
	starts       atomic.Int32
}

func (f *fakeEmulator) stateFile() string {
	return filepath.Join(f.config.StateDir, "tpm2-00.permall")
}

func (f *fakeEmulator) Initialize(ctx context.Context) error {
	f.initRuns.Add(1)
	if f.initErr != nil {
		return f.initErr
	}
	return os.WriteFile(f.stateFile(), []byte("fake tpm state"), 0600)
}

func (f *fakeEmulator) IsInitialized() bool {
	_, err := os.Stat(f.stateFile())
	return err == nil
}

func (f *fakeEmulator) Start(ctx context.Context) error {
	if !f.running.CompareAndSwap(false, true) {
		return swtpm.ErrAlreadyRunning
	}
	f.starts.Add(1)
	return nil
}

func (f *fakeEmulator) WaitForSocket(timeout time.Duration) error {
	if !f.running.Load() {
		return swtpm.ErrSocketNotReady
	}
	return nil
}

func (f *fakeEmulator) Stop() error {
	f.running.Store(false)
	return nil
}

func (f *fakeEmulator) IsRunning() bool { return f.running.Load() }

func (f *fakeEmulator) PID() int {
	if f.running.Load() {
		return fakeEmulatorPID
	}
	return 0
}

func (f *fakeEmulator) SocketPath() string {
	if f.running.Load() && len(f.movedSockets) > 0 {
		return f.movedSockets[f.starts.Load()-1]
	}
	return f.config.SocketPath
}

func (f *fakeEmulator) StateDir() string { return f.config.StateDir }

// fakeHost replaces the orchestrator's swtpm and qemu-img seams and records
// every emulator it opens.
type fakeHost struct {
	emulatorErr error
	initErr     error
	diskErr     error

	mu        sync.Mutex
	emulators []*fakeEmulator
}

func (h *fakeHost) emulatorFor(config *swtpm.Config) (tpmEmulator, error) {
	if h.emulatorErr != nil {
		return nil, h.emulatorErr
	}
	emulator := &fakeEmulator{config: config, initErr: h.initErr}
	h.mu.Lock()
	h.emulators = append(h.emulators, emulator)
	h.mu.Unlock()
	return emulator, nil
}

func (h *fakeHost) createDisk(vm *qemu.VM) error {
	if h.diskErr != nil {
		return h.diskErr
	}
	return os.WriteFile(vm.GetConfig().DiskPath, []byte("fake disk"), 0600)
}

func (h *fakeHost) opened() []*fakeEmulator {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]*fakeEmulator(nil), h.emulators...)
}

// newFakeHostOrchestrator is NewQEMUOrchestrator with every host dependency
// faked: swtpm and qemu-img are in memory, the UEFI firmware is placeholder
// files, and the OVSDB socket is a path nothing listens on.
func newFakeHostOrchestrator(t *testing.T, config *OrchestratorConfig, logger *logging.Logger) (*QEMUOrchestrator, error) {
	t.Helper()
	orch, _, err := newFakeHostOrchestratorWith(t, config, logger, &fakeHost{})
	return orch, err
}

// newFakeHostOrchestratorWith is newFakeHostOrchestrator with a caller-owned
// fakeHost.
func newFakeHostOrchestratorWith(t *testing.T, config *OrchestratorConfig, logger *logging.Logger, host *fakeHost) (*QEMUOrchestrator, *fakeHost, error) {
	t.Helper()
	if config != nil {
		hostDir := t.TempDir()
		config.OVSSocketPath = filepath.Join(hostDir, "ovsdb.sock")
		config.OVMFCode = writePlaceholder(t, hostDir, "OVMF_CODE.fd")
		config.OVMFCodeSecure = writePlaceholder(t, hostDir, "OVMF_CODE.secboot.fd")
		config.OVMFVars = writePlaceholder(t, hostDir, "OVMF_VARS.fd")
	}
	orch, err := NewQEMUOrchestrator(config, logger)
	if err != nil {
		return nil, nil, err
	}
	orch.emulatorFor = host.emulatorFor
	orch.createDisk = host.createDisk
	return orch, host, nil
}

// writePlaceholder writes a stand-in file Create only checks for and returns
// its path.
func writePlaceholder(t *testing.T, dir, name string) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte("placeholder"), 0600))
	return path
}

// newSWTPMTestOrchestrator returns a fake-host orchestrator rooted in a temp
// work directory, closed when the test ends.
func newSWTPMTestOrchestrator(t *testing.T, host *fakeHost) *QEMUOrchestrator {
	t.Helper()
	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = t.TempDir()
	config.Debug = true
	orch, _, err := newFakeHostOrchestratorWith(t, config, logging.DefaultLogger(), host)
	require.NoError(t, err)
	t.Cleanup(func() { assert.NoError(t, orch.Close()) })
	return orch
}

func TestQEMUOrchestrator_HostSeamDefaults(t *testing.T) {
	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = t.TempDir()
	config.OVSSocketPath = filepath.Join(t.TempDir(), "ovsdb.sock")
	orch, err := NewQEMUOrchestrator(config, logging.DefaultLogger())
	require.NoError(t, err)
	defer orch.Close()

	assert.Equal(t, reflect.ValueOf((*qemu.VM).CreateDisk).Pointer(), reflect.ValueOf(orch.createDisk).Pointer())
	require.NotNil(t, orch.emulatorFor)
}

func TestQEMUOrchestrator_DefaultEmulatorMissingSWTPM(t *testing.T) {
	// An empty PATH holds no swtpm, so the default emulator cannot open one.
	t.Setenv("PATH", t.TempDir())
	orch := newSWTPMTestOrchestrator(t, &fakeHost{})

	tpm, err := orch.defaultEmulator(&swtpm.Config{StateDir: t.TempDir()})

	assert.ErrorIs(t, err, swtpm.ErrSWTPMNotInstalled)
	assert.Nil(t, tpm, "a failed open must return a nil interface, not a typed nil")
}

func TestQEMUOrchestrator_SWTPM_Create(t *testing.T) {
	host := &fakeHost{}
	orch := newSWTPMTestOrchestrator(t, host)
	ctx := context.Background()

	instance, err := orch.Create(ctx, &entities.DeviceProfile{ID: 1, Name: "test-vm"})
	require.NoError(t, err)

	tpmStateDir := filepath.Join(instance.Config.WorkDir, "tpm")
	socketPath := filepath.Join(tpmStateDir, "swtpm.sock")
	assert.True(t, instance.Config.TPMEnabled)
	assert.Equal(t, socketPath, instance.Metadata["tpm_socket"])
	assert.NotContains(t, instance.Metadata, "vtpm_bundle_id")
	assert.FileExists(t, filepath.Join(tpmStateDir, "tpm2-00.permall"))
	assert.FileExists(t, instance.Config.DiskPath)

	emulators := host.opened()
	require.Len(t, emulators, 1)
	cfg := emulators[0].config
	assert.Equal(t, tpmStateDir, cfg.StateDir)
	assert.Equal(t, []string{"sha256"}, cfg.PCRBanks)
	assert.True(t, cfg.QEMUMode)
	assert.True(t, cfg.Debug)
	assert.Equal(t, int32(1), emulators[0].initRuns.Load())

	qemuInst := orch.instances[instance.ID]
	require.NotNil(t, qemuInst)
	assert.Same(t, emulators[0], qemuInst.swtpm)
	assert.False(t, qemuInst.swtpm.IsRunning())
	assert.Equal(t, socketPath, qemuInst.vm.GetConfig().TPMSocket)

	require.NoError(t, orch.Delete(ctx, instance.ID))
	assert.NoDirExists(t, instance.Config.WorkDir)
	assert.Empty(t, orch.instances)
}

// A reboot is Stop then Start on the same swtpm, which can listen on a new
// socket each time; the VM must attach to the socket of the current start.
func TestQEMUOrchestrator_SWTPM_StartAttachesVMToLiveSocket(t *testing.T) {
	host := &fakeHost{}
	orch := newSWTPMTestOrchestrator(t, host)
	// No QEMU binary: the VM fails to start once its TPM socket is chosen.
	orch.config.QEMUBinary = filepath.Join(t.TempDir(), "missing-qemu")
	ctx := context.Background()
	instance, err := orch.Create(ctx, &entities.DeviceProfile{ID: 1, Name: "test-vm-reboot"})
	require.NoError(t, err)
	emulator := host.opened()[0]
	emulator.movedSockets = []string{"/tmp/swtpm-first/swtpm.sock", "/tmp/swtpm-second/swtpm.sock"}
	vmConfig := orch.instances[instance.ID].vm.GetConfig()

	for _, want := range emulator.movedSockets {
		require.Error(t, orch.Start(ctx, instance.ID))
		assert.Equal(t, want, vmConfig.TPMSocket)
		assert.False(t, emulator.IsRunning(), "a failed VM start stops its swtpm")
		// The failed start left the instance in error; stopped lets it start again.
		orch.lifecycle.states[instance.ID] = StateStopped
	}
}

func TestQEMUOrchestrator_SWTPM_DeleteStopsRunningSWTPM(t *testing.T) {
	orch := newSWTPMTestOrchestrator(t, &fakeHost{})
	ctx := context.Background()
	instance, err := orch.Create(ctx, &entities.DeviceProfile{ID: 1, Name: "test-vm-lifecycle"})
	require.NoError(t, err)
	tpm := orch.instances[instance.ID].swtpm
	require.NoError(t, tpm.Start(ctx))
	require.True(t, tpm.IsRunning())

	require.NoError(t, orch.Delete(ctx, instance.ID))

	assert.False(t, tpm.IsRunning())
	assert.Equal(t, 0, tpm.PID())
}

func TestQEMUOrchestrator_SWTPM_CreateHelper(t *testing.T) {
	host := &fakeHost{}
	orch := newSWTPMTestOrchestrator(t, host)
	ctx := context.Background()
	workDir := filepath.Join(orch.config.WorkDir, "test-instance-123")
	require.NoError(t, os.MkdirAll(workDir, 0755))

	first, err := orch.createSWTPM(ctx, "test-instance-123", workDir)
	require.NoError(t, err)
	second, err := orch.createSWTPM(ctx, "test-instance-123", workDir)
	require.NoError(t, err)

	tpmStateDir := filepath.Join(workDir, "tpm")
	assert.Equal(t, tpmStateDir, first.StateDir())
	assert.Equal(t, filepath.Join(tpmStateDir, "swtpm.sock"), first.SocketPath())
	assert.True(t, second.IsInitialized())
	emulators := host.opened()
	require.Len(t, emulators, 2)
	assert.Equal(t, int32(1), emulators[0].initRuns.Load())
	assert.Equal(t, int32(0), emulators[1].initRuns.Load(), "existing TPM state must be reused, not re-initialized")
}

func TestQEMUOrchestrator_SWTPM_CreateHelperErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("swtpm cannot be opened", func(t *testing.T) {
		orch := newSWTPMTestOrchestrator(t, &fakeHost{emulatorErr: errFakeEmulator})

		tpm, err := orch.createSWTPM(ctx, "vm", t.TempDir())

		assert.ErrorIs(t, err, errFakeEmulator)
		assert.ErrorContains(t, err, "failed to create swtpm")
		assert.Nil(t, tpm)
	})

	t.Run("swtpm_setup fails", func(t *testing.T) {
		orch := newSWTPMTestOrchestrator(t, &fakeHost{initErr: errFakeEmulator})

		tpm, err := orch.createSWTPM(ctx, "vm", t.TempDir())

		assert.ErrorIs(t, err, errFakeEmulator)
		assert.ErrorContains(t, err, "failed to initialize swtpm")
		assert.Nil(t, tpm)
	})

	t.Run("state directory cannot be created", func(t *testing.T) {
		host := &fakeHost{}
		orch := newSWTPMTestOrchestrator(t, host)
		workDir := filepath.Join(t.TempDir(), "not-a-dir")
		require.NoError(t, os.WriteFile(workDir, nil, 0600))

		tpm, err := orch.createSWTPM(ctx, "vm", workDir)

		var wrapped *WrappedError
		require.ErrorAs(t, err, &wrapped)
		assert.Equal(t, "failed to create TPM state directory", wrapped.Msg)
		assert.Nil(t, tpm)
		assert.Empty(t, host.opened())
	})
}

func TestQEMUOrchestrator_SWTPM_MultipleInstances(t *testing.T) {
	host := &fakeHost{}
	orch := newSWTPMTestOrchestrator(t, host)
	orch.config.MaxInstances = 5
	ctx := context.Background()

	socketPaths := make(map[string]bool)
	instances := make([]*Instance, 3)
	for i := range instances {
		instance, err := orch.Create(ctx, &entities.DeviceProfile{ID: uint64(i + 1), Name: "test-vm-" + string(rune('a'+i))})
		require.NoError(t, err)
		instances[i] = instance

		socketPath := instance.Metadata["tpm_socket"]
		assert.False(t, socketPaths[socketPath], "socket path must be unique per instance")
		socketPaths[socketPath] = true
		assert.Contains(t, orch.instances[instance.ID].swtpm.StateDir(), instance.ID)
	}
	assert.Len(t, host.opened(), 3)

	for _, instance := range instances {
		require.NoError(t, orch.Delete(ctx, instance.ID))
	}
	assert.Empty(t, orch.instances)
}

func TestQEMUOrchestrator_SWTPM_StatePermissions(t *testing.T) {
	orch := newSWTPMTestOrchestrator(t, &fakeHost{})

	instance, err := orch.Create(context.Background(), &entities.DeviceProfile{ID: 1, Name: "test-vm-perms"})
	require.NoError(t, err)

	info, err := os.Stat(filepath.Join(instance.Config.WorkDir, "tpm"))
	require.NoError(t, err)
	assert.True(t, info.IsDir())
	assert.Equal(t, os.FileMode(0700), info.Mode().Perm()&0700, "TPM state directory must give the owner rwx")
}

func TestQEMUOrchestrator_SWTPM_CleanupOnError(t *testing.T) {
	ctx := context.Background()
	profile := &entities.DeviceProfile{ID: 1, Name: "test-vm-error"}

	t.Run("work directory cannot be created", func(t *testing.T) {
		parent := filepath.Join(t.TempDir(), "not-a-dir")
		require.NoError(t, os.WriteFile(parent, nil, 0600))
		config := DefaultOrchestratorConfig(ComputeTypeVM)
		config.WorkDir = filepath.Join(parent, "compute")

		_, err := newFakeHostOrchestrator(t, config, logging.DefaultLogger())

		assert.ErrorContains(t, err, "failed to create work directory")
	})

	t.Run("swtpm fails", func(t *testing.T) {
		orch := newSWTPMTestOrchestrator(t, &fakeHost{initErr: errFakeEmulator})

		_, err := orch.Create(ctx, profile)

		assert.ErrorIs(t, err, errFakeEmulator)
		assert.Empty(t, orch.instances)
	})

	t.Run("disk creation fails", func(t *testing.T) {
		orch := newSWTPMTestOrchestrator(t, &fakeHost{diskErr: errFakeDisk})

		_, err := orch.Create(ctx, profile)

		assert.ErrorIs(t, err, errFakeDisk)
		assert.ErrorContains(t, err, "failed to create VM disk")
		assert.Empty(t, orch.instances)
	})
}

// bundleGenerator is a vtpm.Generator holding one profile's bundle. Only
// GetByProfile is implemented; Create calls nothing else when the bundle
// exists.
type bundleGenerator struct {
	vtpm.Generator
	bundle *vtpm.VTPMInstance
}

func (g *bundleGenerator) GetByProfile(ctx context.Context, profileID uint64) (*vtpm.VTPMInstance, error) {
	return g.bundle, nil
}

func TestQEMUOrchestrator_SWTPM_Bundle(t *testing.T) {
	ctx := context.Background()
	bundleDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(bundleDir, "tpm"), 0700))
	bundle := &vtpm.VTPMInstance{
		ID:          "bundle-1",
		StoragePath: bundleDir,
		SocketPath:  filepath.Join(bundleDir, "swtpm.sock"),
	}

	t.Run("VM boots against the profile bundle", func(t *testing.T) {
		host := &fakeHost{}
		orch := newSWTPMTestOrchestrator(t, host)
		orch.SetVTPMGenerator(&bundleGenerator{bundle: bundle})

		instance, err := orch.Create(ctx, &entities.DeviceProfile{ID: 7, Name: "bundled"})
		require.NoError(t, err)

		assert.Equal(t, bundle.SocketPath, instance.Metadata["tpm_socket"])
		assert.Equal(t, bundle.ID, instance.Metadata["vtpm_bundle_id"])
		emulators := host.opened()
		require.Len(t, emulators, 1)
		assert.Equal(t, filepath.Join(bundleDir, "tpm"), emulators[0].config.StateDir)
		assert.Equal(t, bundle.SocketPath, emulators[0].config.SocketPath)
		assert.True(t, emulators[0].IsInitialized())
	})

	t.Run("bundle swtpm cannot be opened", func(t *testing.T) {
		orch := newSWTPMTestOrchestrator(t, &fakeHost{emulatorErr: errFakeEmulator})
		orch.SetVTPMGenerator(&bundleGenerator{bundle: bundle})

		_, err := orch.Create(ctx, &entities.DeviceProfile{ID: 7, Name: "bundled"})

		assert.ErrorIs(t, err, errFakeEmulator)
		assert.ErrorContains(t, err, "failed to open swtpm for bundle")
		assert.Empty(t, orch.instances)
	})

	t.Run("bundle swtpm_setup fails", func(t *testing.T) {
		emptyDir := t.TempDir()
		require.NoError(t, os.MkdirAll(filepath.Join(emptyDir, "tpm"), 0700))
		orch := newSWTPMTestOrchestrator(t, &fakeHost{initErr: errFakeEmulator})
		orch.SetVTPMGenerator(&bundleGenerator{bundle: &vtpm.VTPMInstance{
			ID:          "bundle-2",
			StoragePath: emptyDir,
			SocketPath:  filepath.Join(emptyDir, "swtpm.sock"),
		}})

		_, err := orch.Create(ctx, &entities.DeviceProfile{ID: 8, Name: "bundled"})

		assert.ErrorIs(t, err, errFakeEmulator)
		assert.ErrorContains(t, err, "failed to initialize swtpm for bundle")
	})
}
