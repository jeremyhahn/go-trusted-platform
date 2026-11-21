package compute

import (
	"context"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
)

// transferReceiver is a signalReceiver that also reports whether QEMU says the
// incoming migration stream is still arriving, and the VM it received into.
type transferReceiver struct {
	aborts       atomic.Int32
	commits      atomic.Int32
	abortedC     chan struct{}
	once         sync.Once
	transferring atomic.Bool
	vm           *qemu.VM
}

func newTransferReceiver() *transferReceiver {
	return &transferReceiver{abortedC: make(chan struct{})}
}

func (r *transferReceiver) Port() int { return 49302 }

func (r *transferReceiver) Commit(context.Context) error {
	r.commits.Add(1)
	return nil
}

func (r *transferReceiver) Abort(context.Context) error {
	r.aborts.Add(1)
	r.once.Do(func() { close(r.abortedC) })
	return nil
}

func (r *transferReceiver) TransferState(context.Context) receiverTransferState {
	if r.transferring.Load() {
		return transferActive
	}
	return transferIdle
}

func (r *transferReceiver) VM() *qemu.VM { return r.vm }

// receiveWith prepares a receiver on orch that the launcher answers with recv.
func receiveWith(t *testing.T, orch *QEMUOrchestrator, recv incomingReceiver, spec MigrationSpec) *ReceiverHandle {
	t.Helper()
	swapReceiverLauncher(t, func(context.Context, *incomingReceiverParams) (incomingReceiver, error) {
		return recv, nil
	})
	handle, err := orch.ReceiveIncoming(context.Background(), spec)
	require.NoError(t, err)
	return handle
}

func adoptSpec(orch *QEMUOrchestrator) MigrationSpec {
	return MigrationSpec{
		Arch:       orch.config.Arch,
		InstanceID: "src-vm-1",
		VMName:     "guest",
		Config:     &InstanceConfig{Memory: 1024, CPUs: 1},
	}
}

func TestReceiveIncoming_ActiveTransferOutlivesTheLifetime(t *testing.T) {
	swapReceiverLifetime(t, 20*time.Millisecond)
	orch := newOpsOrchestrator(t)
	orch.config.MigrationTLS = newSignalServerTLS(t.TempDir())

	recv := newTransferReceiver()
	recv.transferring.Store(true)
	handle := receiveWith(t, orch, recv, MigrationSpec{
		Arch:   orch.config.Arch,
		VMName: "guest",
		Config: &InstanceConfig{Memory: 1024},
	})

	// Several lifetimes pass while QEMU reports the stream still arriving.
	time.Sleep(150 * time.Millisecond)
	assert.Equal(t, int32(0), recv.aborts.Load(), "a receiver whose transfer runs is not reaped")

	// The receiver is still owned and finalizable after the lifetimes passed.
	require.NoError(t, orch.FinalizeIncoming(context.Background(), handle.ReceiverID, false))
	assert.Equal(t, int32(1), recv.aborts.Load())
}

func TestReceiveIncoming_IdleReceiverStillExpires(t *testing.T) {
	swapReceiverLifetime(t, 20*time.Millisecond)
	orch := newOpsOrchestrator(t)
	tlsProv := newSignalServerTLS(t.TempDir())
	orch.config.MigrationTLS = tlsProv

	recv := newTransferReceiver()
	recv.transferring.Store(true)
	handle := receiveWith(t, orch, recv, MigrationSpec{
		Arch:   orch.config.Arch,
		VMName: "guest",
		Config: &InstanceConfig{Memory: 1024},
	})

	time.Sleep(100 * time.Millisecond)
	recv.transferring.Store(false)

	awaitSignal(t, recv.abortedC, "the idle receiver to be aborted")
	awaitSignal(t, tlsProv.cleanedUp, "the idle receiver's creds to be released")
	assert.Equal(t, int32(0), recv.commits.Load())

	err := orch.FinalizeIncoming(context.Background(), handle.ReceiverID, true)
	assert.ErrorIs(t, err, ErrReceiverNotFound)
}

// A committed receiver with no QEMU process cannot be adopted: the finalize
// fails, the receiver is aborted, and no instance is tracked. Adoption of a
// running guest is covered by TestFinalizeIncoming_CommitAdoptsTheGuest.
func TestFinalizeIncoming_CommitWithoutProcessTracksNothing(t *testing.T) {
	ctx := context.Background()
	orch := newOpsOrchestrator(t)
	orch.config.MigrationTLS = newSignalServerTLS(t.TempDir())

	recv := newTransferReceiver()
	handle := receiveWith(t, orch, recv, adoptSpec(orch))
	err := orch.FinalizeIncoming(ctx, handle.ReceiverID, true)
	assert.ErrorIs(t, err, ErrMigrationReceiveFailed)
	assert.Equal(t, int32(1), recv.commits.Load())
	assert.Equal(t, int32(1), recv.aborts.Load(), "a receiver that cannot be adopted is aborted")

	list, err := orch.List(ctx, nil)
	require.NoError(t, err)
	assert.Empty(t, list)

	_, err = orch.lifecycle.GetState("src-vm-1")
	assert.Error(t, err, "no lifecycle state is recorded for a refused guest")

	err = orch.FinalizeIncoming(ctx, handle.ReceiverID, true)
	assert.ErrorIs(t, err, ErrReceiverNotFound)
}

func TestFinalizeIncoming_AbortAdoptsNothing(t *testing.T) {
	ctx := context.Background()
	orch := newOpsOrchestrator(t)
	orch.config.MigrationTLS = newSignalServerTLS(t.TempDir())

	recv := newTransferReceiver()
	handle := receiveWith(t, orch, recv, adoptSpec(orch))
	require.NoError(t, orch.FinalizeIncoming(ctx, handle.ReceiverID, false))
	assert.Equal(t, int32(1), recv.aborts.Load())

	list, err := orch.List(ctx, nil)
	require.NoError(t, err)
	assert.Empty(t, list)
}

// A committed receiver whose QEMU is not running (here a real, never-started
// VM) is not adopted: the finalize fails, nothing is tracked, and Close
// succeeds.
func TestFinalizeIncoming_ExitedGuestIsNotAdopted(t *testing.T) {
	ctx := context.Background()
	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = t.TempDir()
	orch, err := newFakeHostOrchestrator(t, config, logging.DefaultLogger())
	require.NoError(t, err)
	orch.config.MigrationTLS = newSignalServerTLS(t.TempDir())

	workDir := t.TempDir()
	qcfg := orch.config.qemuBase()
	qcfg.WorkDir = workDir
	qcfg.DiskPath = filepath.Join(workDir, "disk.qcow2")
	qcfg.DiskSize = "1G"
	qcfg.Memory = 1024
	qcfg.CPUs = 1
	vm, err := qemu.NewVM(qcfg, orch.logger)
	require.NoError(t, err)

	recv := newTransferReceiver()
	recv.vm = vm
	handle := receiveWith(t, orch, recv, adoptSpec(orch))
	err = orch.FinalizeIncoming(ctx, handle.ReceiverID, true)
	assert.ErrorIs(t, err, ErrMigrationReceiveFailed)
	assert.Equal(t, int32(1), recv.aborts.Load())

	list, err := orch.List(ctx, nil)
	require.NoError(t, err)
	assert.Empty(t, list)
	assert.NotPanics(t, func() { assert.Error(t, orch.Stop(ctx, "src-vm-1")) })
	assert.NotPanics(t, func() { assert.NoError(t, orch.Close()) })
}

// After a refused adoption of a receiver without a VM, Stop answers with an
// error rather than panicking and Close succeeds.
func TestClose_AfterRefusedAdoptionWithoutVM(t *testing.T) {
	ctx := context.Background()
	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = t.TempDir()
	orch, err := newFakeHostOrchestrator(t, config, logging.DefaultLogger())
	require.NoError(t, err)
	orch.config.MigrationTLS = newSignalServerTLS(t.TempDir())

	handle := receiveWith(t, orch, newTransferReceiver(), adoptSpec(orch))
	assert.Error(t, orch.FinalizeIncoming(ctx, handle.ReceiverID, true))

	assert.NotPanics(t, func() { assert.Error(t, orch.Stop(ctx, "src-vm-1")) })
	assert.NotPanics(t, func() { assert.NoError(t, orch.Close()) })
}
