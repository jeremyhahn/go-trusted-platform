package compute

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// newReceivedVMIn builds a never-started received VM whose work directory is
// workDir, and creates that directory with a small disk.qcow2 in it.
func newReceivedVMIn(t *testing.T, orch *QEMUOrchestrator, workDir string) *qemu.VM {
	t.Helper()
	fw := t.TempDir()
	cfg := orch.config.qemuBase()
	cfg.Arch = qemu.ArchX86_64
	cfg.OVMFCode = filepath.Join(fw, "OVMF_CODE.fd")
	cfg.OVMFVars = filepath.Join(fw, "OVMF_VARS.fd")
	require.NoError(t, os.WriteFile(cfg.OVMFCode, nil, 0o600))
	require.NoError(t, os.WriteFile(cfg.OVMFVars, nil, 0o600))
	cfg.WorkDir = workDir
	cfg.DiskPath = filepath.Join(workDir, "disk.qcow2")
	cfg.DiskSize = "1G"
	cfg.Memory = 512
	cfg.CPUs = 1
	vm, err := qemu.NewVM(cfg, logging.DefaultLogger())
	require.NoError(t, err)
	writeReceiverDisk(t, vm)
	return vm
}

// writeReceiverDisk creates the received VM's work dir and its disk.qcow2.
func writeReceiverDisk(t *testing.T, vm *qemu.VM) {
	t.Helper()
	cfg := vm.GetConfig()
	require.NoError(t, os.MkdirAll(cfg.WorkDir, 0o755))
	require.NoError(t, os.WriteFile(cfg.DiskPath, []byte("disk"), 0o600))
}

func receiverWorkDirExists(dir string) bool {
	_, err := os.Stat(dir)
	return err == nil
}

func receiveInto(t *testing.T, orch *QEMUOrchestrator, recv incomingReceiver) string {
	t.Helper()
	swapReceiverLauncher(t, func(ctx context.Context, p *incomingReceiverParams) (incomingReceiver, error) {
		return recv, nil
	})
	handle, err := orch.ReceiveIncoming(context.Background(), MigrationSpec{
		InstanceID: "vm-migrated",
		Arch:       orch.config.Arch,
		VMName:     "guest",
		Config:     &InstanceConfig{Memory: 1024},
	})
	require.NoError(t, err)
	return handle.ReceiverID
}

// A released receiver's incoming-<id> work dir and its disk are removed; an
// adopted receiver's dir belongs to the instance and stays (#2021 Codex C6).
func TestReceiverWorkDir_RemovedWhenTheReceiverIsReleased(t *testing.T) {
	t.Run("expiry", func(t *testing.T) {
		swapReceiverLifetime(t, 20*time.Millisecond)
		orch := newOpsOrchestrator(t)
		orch.config.MigrationTLS = &fakeServerTLS{dir: t.TempDir()}
		vm := newReceivedVM(t, orch)
		writeReceiverDisk(t, vm)
		dir := vm.GetConfig().WorkDir

		receiveInto(t, orch, &fakeIncomingReceiver{port: 5000, vm: vm})
		require.Eventually(t, func() bool { return !receiverWorkDirExists(dir) },
			2*time.Second, 10*time.Millisecond, "an expired receiver's work dir must be removed")
	})

	t.Run("failed commit", func(t *testing.T) {
		orch := newOpsOrchestrator(t)
		orch.config.MigrationTLS = &fakeServerTLS{dir: t.TempDir()}
		vm := newReceivedVM(t, orch)
		writeReceiverDisk(t, vm)
		dir := vm.GetConfig().WorkDir

		id := receiveInto(t, orch, &fakeIncomingReceiver{port: 5000, vm: vm, commitErr: errors.New("resume failed")})
		require.ErrorIs(t, orch.FinalizeIncoming(context.Background(), id, true), ErrMigrationReceiveFailed)
		assert.False(t, receiverWorkDirExists(dir), "a failed commit must remove the receiver's work dir")
	})

	t.Run("abort", func(t *testing.T) {
		orch := newOpsOrchestrator(t)
		orch.config.MigrationTLS = &fakeServerTLS{dir: t.TempDir()}
		vm := newReceivedVM(t, orch)
		writeReceiverDisk(t, vm)
		dir := vm.GetConfig().WorkDir

		id := receiveInto(t, orch, &fakeIncomingReceiver{port: 5000, vm: vm})
		require.NoError(t, orch.FinalizeIncoming(context.Background(), id, false))
		assert.False(t, receiverWorkDirExists(dir), "an aborted receiver's work dir must be removed")
	})

	t.Run("abort error", func(t *testing.T) {
		orch := newOpsOrchestrator(t)
		orch.config.MigrationTLS = &fakeServerTLS{dir: t.TempDir()}
		vm := newReceivedVM(t, orch)
		writeReceiverDisk(t, vm)
		dir := vm.GetConfig().WorkDir

		id := receiveInto(t, orch, &fakeIncomingReceiver{port: 5000, vm: vm, abortErr: errors.New("kill failed")})
		require.ErrorIs(t, orch.FinalizeIncoming(context.Background(), id, false), ErrMigrationReceiveFailed)
		assert.True(t, receiverWorkDirExists(dir), "a receiver whose abort failed may still hold its disk")
	})

	t.Run("adopted", func(t *testing.T) {
		orch := newOpsOrchestrator(t)
		orch.config.MigrationTLS = &fakeServerTLS{dir: t.TempDir()}
		vm := startReceivedVM(t, orch)
		cfg := vm.GetConfig()

		id := receiveInto(t, orch, &fakeIncomingReceiver{port: 5000, vm: vm})
		require.NoError(t, orch.FinalizeIncoming(context.Background(), id, true))
		assert.True(t, receiverWorkDirExists(cfg.WorkDir), "the adopted instance owns its work dir")
		assert.True(t, receiverWorkDirExists(cfg.DiskPath), "the adopted instance owns its disk")
		require.NoError(t, orch.Close())
	})

	t.Run("outside the work dir", func(t *testing.T) {
		orch := newOpsOrchestrator(t)
		orch.config.MigrationTLS = &fakeServerTLS{dir: t.TempDir()}
		dir := t.TempDir()
		vm := newReceivedVMIn(t, orch, dir)

		id := receiveInto(t, orch, &fakeIncomingReceiver{port: 5000, vm: vm})
		require.NoError(t, orch.FinalizeIncoming(context.Background(), id, false))
		assert.True(t, receiverWorkDirExists(dir), "only an incoming-* child of the orchestrator work dir is removed")
		assert.True(t, receiverWorkDirExists(filepath.Join(dir, "disk.qcow2")))
	})
}
