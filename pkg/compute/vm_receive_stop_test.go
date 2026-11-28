package compute

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// TestStopAfterAdoption_KillsAGuestThatIgnoresTerm: an adopted receiver's
// QEMU runs under a context that is never cancelled, so the run's cancel
// is the only thing that can end a guest that ignores the stop signal. The
// stop seam returns as a SIGTERM to such a guest does, leaving the process
// alive; the stop must still end the run rather than wait on it forever.
func TestStopAfterAdoption_KillsAGuestThatIgnoresTerm(t *testing.T) {
	orch := newOpsOrchestrator(t)
	orch.config.MigrationTLS = &fakeServerTLS{dir: t.TempDir()}

	recv := &fakeIncomingReceiver{port: 5000, vm: startReceivedVM(t, orch)}
	swapReceiverLauncher(t, func(ctx context.Context, p *incomingReceiverParams) (incomingReceiver, error) {
		return recv, nil
	})

	spec := MigrationSpec{
		InstanceID: "vm-migrated",
		Arch:       orch.config.Arch,
		VMName:     "guest",
		Config:     &InstanceConfig{Memory: 1024},
	}
	handle, err := orch.ReceiveIncoming(context.Background(), spec)
	require.NoError(t, err)
	require.NoError(t, orch.FinalizeIncoming(context.Background(), handle.ReceiverID, true))

	orig := stopVMProcess
	stopVMProcess = func(*qemuInstance, StopOptions) error { return nil }
	t.Cleanup(func() { stopVMProcess = orig })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stopped := make(chan error, 1)
	go func() { stopped <- orch.StopWithOptions(ctx, spec.InstanceID, StopOptions{}) }()
	select {
	case err := <-stopped:
		require.NoError(t, err)
	case <-ctx.Done():
		t.Fatal("the stop of an adopted receiver waited forever on a guest that ignores SIGTERM")
	}

	state, err := orch.GetState(context.Background(), spec.InstanceID)
	require.NoError(t, err)
	require.Equal(t, StateStopped, state)
}
