package compute

import (
	"context"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
)

// A stop of an adopted guest releases the instance lock while it stops the
// process; once recordExit marks the instance stopped, a Start may reuse the
// same VM object. The old stop's cancel must not kill that new guest.
func TestStopAfterAdoption_DoesNotKillAGuestStartedDuringTheStop(t *testing.T) {
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

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	restartedPID := 0
	orig := stopVMProcess
	stopVMProcess = func(*qemuInstance, StopOptions) error {
		require.NoError(t, recv.vm.Kill())
		tick := time.NewTicker(10 * time.Millisecond)
		defer tick.Stop()
		for {
			state, err := orch.GetState(ctx, spec.InstanceID)
			require.NoError(t, err)
			if state == StateStopped {
				break
			}
			select {
			case <-ctx.Done():
				t.Fatal("the adopted guest's exit was never recorded")
			case <-tick.C:
			}
		}
		require.NoError(t, recv.vm.Start(context.Background(), string(qemu.BootModeBoot)))
		restartedPID = recv.vm.GetPID()
		return nil
	}
	t.Cleanup(func() { stopVMProcess = orig })

	stopped := make(chan error, 1)
	go func() { stopped <- orch.StopWithOptions(ctx, spec.InstanceID, StopOptions{}) }()
	select {
	case err := <-stopped:
		require.NoError(t, err)
	case <-ctx.Done():
		t.Fatal("the stop of an adopted receiver did not return")
	}

	require.NotZero(t, restartedPID)
	require.NoError(t, syscall.Kill(restartedPID, 0), "the old stop killed the guest started on the same VM")
	require.True(t, recv.vm.IsRunning())
}
