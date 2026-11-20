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

func (r *transferReceiver) Transferring(context.Context) (bool, error) {
	return r.transferring.Load(), nil
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

	require.NoError(t, orch.FinalizeIncoming(context.Background(), handle.ReceiverID, true))
	assert.Equal(t, int32(1), recv.commits.Load())
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

func TestFinalizeIncoming_CommitAdoptsTheGuest(t *testing.T) {
	ctx := context.Background()
	orch := newOpsOrchestrator(t)
	orch.config.MigrationTLS = newSignalServerTLS(t.TempDir())

	recv := newTransferReceiver()
	handle := receiveWith(t, orch, recv, adoptSpec(orch))
	require.NoError(t, orch.FinalizeIncoming(ctx, handle.ReceiverID, true))

	list, err := orch.List(ctx, nil)
	require.NoError(t, err)
	require.Len(t, list, 1, "the committed guest is a tracked instance")
	inst := list[0]
	assert.Equal(t, "src-vm-1", inst.ID)
	assert.Equal(t, "guest", inst.Name)
	assert.Equal(t, ComputeTypeVM, inst.Type)
	assert.Equal(t, StateRunning, inst.State)
	assert.Equal(t, handle.ReceiverID, inst.Metadata["migration_receiver"])

	got, err := orch.Get(ctx, "src-vm-1")
	require.NoError(t, err)
	assert.Equal(t, StateRunning, got.State)

	state, err := orch.lifecycle.GetState("src-vm-1")
	require.NoError(t, err)
	assert.Equal(t, StateRunning, state)

	// A second guest received under the same source ID does not overwrite it.
	second := receiveWith(t, orch, newTransferReceiver(), adoptSpec(orch))
	require.NoError(t, orch.FinalizeIncoming(ctx, second.ReceiverID, true))

	list, err = orch.List(ctx, nil)
	require.NoError(t, err)
	require.Len(t, list, 2)
	ids := map[string]string{}
	for _, i := range list {
		ids[i.ID] = i.Metadata["migration_receiver"]
	}
	assert.Equal(t, handle.ReceiverID, ids["src-vm-1"], "the first adopted guest is kept")
	for id, receiver := range ids {
		if id != "src-vm-1" {
			assert.NotEmpty(t, id)
			assert.Equal(t, second.ReceiverID, receiver)
		}
	}
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

func TestFinalizeIncoming_AdoptedGuestStopsAndCloses(t *testing.T) {
	ctx := context.Background()
	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = t.TempDir()
	orch, err := newFakeHostOrchestrator(t, config, logging.DefaultLogger())
	require.NoError(t, err)
	orch.config.MigrationTLS = newSignalServerTLS(t.TempDir())

	// A real, never-started VM: no QEMU process runs.
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
	require.NoError(t, orch.FinalizeIncoming(ctx, handle.ReceiverID, true))

	// The guest's QEMU is not running, so the stop cannot power it off: it
	// answers with an error, and the delete that stops first refuses.
	assert.NotPanics(t, func() { _ = orch.Stop(ctx, "src-vm-1") })
	assert.NotPanics(t, func() { _ = orch.Delete(ctx, "src-vm-1") })
	assert.NotPanics(t, func() { assert.NoError(t, orch.Close()) })
}

func TestClose_AdoptedGuestWithoutVM(t *testing.T) {
	ctx := context.Background()
	config := DefaultOrchestratorConfig(ComputeTypeVM)
	config.WorkDir = t.TempDir()
	orch, err := newFakeHostOrchestrator(t, config, logging.DefaultLogger())
	require.NoError(t, err)
	orch.config.MigrationTLS = newSignalServerTLS(t.TempDir())

	handle := receiveWith(t, orch, newTransferReceiver(), adoptSpec(orch))
	require.NoError(t, orch.FinalizeIncoming(ctx, handle.ReceiverID, true))

	assert.NotPanics(t, func() { _ = orch.Stop(ctx, "src-vm-1") })
	assert.NotPanics(t, func() { assert.NoError(t, orch.Close()) })
}
