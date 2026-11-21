package compute

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// exitAfterCommitReceiver acknowledges the resume, then its QEMU exits
// before the orchestrator adopts it.
type exitAfterCommitReceiver struct {
	*fakeIncomingReceiver
}

func (r *exitAfterCommitReceiver) Commit(ctx context.Context) error {
	if err := r.fakeIncomingReceiver.Commit(ctx); err != nil {
		return err
	}
	_ = r.vm.Stop()
	deadline := time.Now().Add(10 * time.Second)
	for r.vm.IsRunning() && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	return nil
}

// A receiver whose QEMU exits between Commit and adoption must not be
// published as a running instance, and FinalizeIncoming must not report
// success: the source would retire its copy of the guest (Codex P1, PR #2021).
func TestFinalizeIncoming_ExitedReceiverIsNotAdopted(t *testing.T) {
	orch := newOpsOrchestrator(t)
	orch.config.MigrationTLS = &fakeServerTLS{dir: t.TempDir()}

	recv := &exitAfterCommitReceiver{&fakeIncomingReceiver{port: 5000, vm: startReceivedVM(t, orch)}}
	swapReceiverLauncher(t, func(ctx context.Context, p *incomingReceiverParams) (incomingReceiver, error) {
		return recv, nil
	})
	adopted := false
	receiverAdoptedHook = func(string) { adopted = true }
	t.Cleanup(func() { receiverAdoptedHook = nil })

	spec := MigrationSpec{
		InstanceID: "vm-migrated",
		Arch:       orch.config.Arch,
		VMName:     "guest",
		Config:     &InstanceConfig{Memory: 1024},
	}
	handle, err := orch.ReceiveIncoming(context.Background(), spec)
	require.NoError(t, err)

	err = orch.FinalizeIncoming(context.Background(), handle.ReceiverID, true)
	require.Error(t, err, "an exited receiver must not be acknowledged as adopted")
	assert.True(t, errors.Is(err, ErrMigrationReceiveFailed))
	assert.False(t, adopted, "an exited receiver must not be published")

	state, stateErr := orch.GetState(context.Background(), spec.InstanceID)
	if stateErr == nil {
		assert.NotEqual(t, StateRunning, state, "an exited receiver must not be recorded as running")
	}
	list, err := orch.List(context.Background(), nil)
	require.NoError(t, err)
	assert.Empty(t, list, "an exited receiver must not be listed")
	require.NoError(t, orch.Close())
}
