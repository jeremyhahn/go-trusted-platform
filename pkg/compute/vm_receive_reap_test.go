package compute

import (
	"context"
	"os/exec"
	"syscall"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

// startSleepProcess launches a child that runs until it is signalled and
// returns it with a channel closed once Wait has reaped it.
func startSleepProcess(t *testing.T, ignoreTerm bool) (*exec.Cmd, chan struct{}) {
	t.Helper()
	script := "sleep 60"
	if ignoreTerm {
		script = "trap '' TERM; sleep 60 & wait"
	}
	cmd := exec.Command("sh", "-c", script)
	require.NoError(t, cmd.Start())
	t.Cleanup(func() { _ = cmd.Process.Kill() })
	return cmd, make(chan struct{})
}

func newSleepReceiverProcess(cmd *exec.Cmd, reaped chan struct{}) *receiverProcess {
	return startReceiverProcess(
		func() error { err := cmd.Wait(); close(reaped); return err },
		func() error { return cmd.Process.Signal(syscall.SIGTERM) },
		cmd.Process.Kill,
	)
}

// An aborted receiver (deadline expired or commit failed: both release the
// receiver through Abort) has its process reaped before Abort returns.
func TestQEMUIncomingReceiver_AbortReapsTheProcess(t *testing.T) {
	cmd, reaped := startSleepProcess(t, false)
	r := &qemuIncomingReceiver{proc: newSleepReceiverProcess(cmd, reaped)}

	require.NoError(t, r.Abort(context.Background()))
	select {
	case <-reaped:
	default:
		t.Fatal("Abort returned before the receiver process was reaped")
	}
	require.NotNil(t, r.Done())
	select {
	case <-r.Done():
	default:
		t.Fatal("Done is not closed after Abort")
	}
}

// A receiver process that ignores the stop is killed once the bounded wait
// runs out, and is still reaped before Abort returns.
func TestQEMUIncomingReceiver_AbortKillsAProcessThatIgnoresStop(t *testing.T) {
	orig := receiverStopGrace
	receiverStopGrace = 200 * time.Millisecond
	t.Cleanup(func() { receiverStopGrace = orig })

	cmd, reaped := startSleepProcess(t, true)
	// Let the shell install its trap before the stop is sent.
	time.Sleep(100 * time.Millisecond)
	r := &qemuIncomingReceiver{proc: newSleepReceiverProcess(cmd, reaped)}

	start := time.Now()
	require.NoError(t, r.Abort(context.Background()))
	select {
	case <-reaped:
	default:
		t.Fatal("Abort returned before the receiver process was reaped")
	}
	require.Less(t, time.Since(start), 5*time.Second)
}

// A receiver whose deadline expires is reaped through releaseReceiver.
func TestReleaseReceiver_ReapsTheProcess(t *testing.T) {
	cmd, reaped := startSleepProcess(t, false)
	r := &qemuIncomingReceiver{proc: newSleepReceiverProcess(cmd, reaped)}
	orch := newOpsOrchestrator(t)
	cleaned := false
	orch.releaseReceiver("rx-1", &trackedReceiver{recv: r, cleanup: func() {
		select {
		case <-reaped:
			cleaned = true
		default:
		}
	}}, "receiver lifetime expired")
	require.True(t, cleaned, "cleanup ran before the receiver process was reaped")
}
