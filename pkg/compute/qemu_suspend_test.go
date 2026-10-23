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
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errFakeQMP = errors.New("fake QMP failure")

// fakeRunControl records the QMP run-state commands sent to it.
type fakeRunControl struct {
	commands  []string
	pauseErr  error
	resumeErr error
}

func (f *fakeRunControl) Pause(ctx context.Context) error {
	f.commands = append(f.commands, "stop")
	return f.pauseErr
}

func (f *fakeRunControl) Resume(ctx context.Context) error {
	f.commands = append(f.commands, "cont")
	return f.resumeErr
}

// installRunControlSeam wires the fake run control; connectErr makes the
// monitor lookup itself fail.
func installRunControlSeam(t *testing.T, rc *fakeRunControl, connectErr error) {
	t.Helper()
	orig := vmRunControlFor
	vmRunControlFor = func(ctx context.Context, inst *qemuInstance) (vmRunControl, error) {
		if connectErr != nil {
			return nil, connectErr
		}
		return rc, nil
	}
	t.Cleanup(func() { vmRunControlFor = orig })
}

// installStopSeam replaces the QEMU process stop. On success it releases a
// stand-in for Start's wait goroutine, which takes the instance lock to
// record the exit exactly as the real one does.
func installStopSeam(t *testing.T, orch *QEMUOrchestrator, qi *qemuInstance, stopErr error) *int {
	t.Helper()
	calls, _ := installStopSeamWithOptions(t, orch, qi, stopErr)
	return calls
}

// installStopSeamWithOptions is installStopSeam that also records the
// StopOptions each process stop received.
// installTestRun makes a stand-in run the instance's current run, as Start
// does once QEMU runs. The caller closes its done channel when the stand-in
// exits.
func installTestRun(qi *qemuInstance, cancel context.CancelFunc) *qemuRun {
	run := &qemuRun{cancel: cancel, done: make(chan struct{})}
	qi.mu.Lock()
	qi.run = run
	qi.mu.Unlock()
	return run
}

func installStopSeamWithOptions(t *testing.T, orch *QEMUOrchestrator, qi *qemuInstance, stopErr error) (*int, *[]StopOptions) {
	t.Helper()
	calls := new(int)
	seen := new([]StopOptions)
	exited := make(chan struct{})
	run := installTestRun(qi, func() {})
	go func() {
		defer close(run.done)
		if _, ok := <-exited; ok {
			return
		}
		orch.recordExit(qi.instance.ID, qi)
	}()

	orig := stopVMProcess
	stopVMProcess = func(inst *qemuInstance, opts StopOptions) error {
		*calls++
		*seen = append(*seen, opts)
		if stopErr != nil {
			return stopErr
		}
		close(exited)
		return nil
	}
	t.Cleanup(func() {
		stopVMProcess = orig
		select {
		case <-exited:
		default:
			// Stop failed, so nothing exited; release the stand-in anyway.
			exited <- struct{}{}
		}
	})
	return calls, seen
}

// insertSuspendedVM inserts a running instance and moves it to suspended.
func insertSuspendedVM(t *testing.T, orch *QEMUOrchestrator, id string) *qemuInstance {
	t.Helper()
	qi := insertVMInstance(t, orch, id, true, &InstanceConfig{WorkDir: t.TempDir()})
	require.NoError(t, orch.lifecycle.SetState(id, StateSuspended))
	qi.instance.State = StateSuspended
	return qi
}

func assertVMState(t *testing.T, orch *QEMUOrchestrator, qi *qemuInstance, want InstanceState) {
	t.Helper()
	got, err := orch.GetState(context.Background(), qi.instance.ID)
	require.NoError(t, err)
	assert.Equal(t, want, got)
	assert.Equal(t, want, qi.instance.State)
}

func TestSuspend_RunningVMIsPaused(t *testing.T) {
	orch := newOpsOrchestrator(t)
	qi := insertVMInstance(t, orch, "vm1", true, &InstanceConfig{})
	rc := &fakeRunControl{}
	installRunControlSeam(t, rc, nil)

	require.NoError(t, orch.Suspend(context.Background(), "vm1"))
	assert.Equal(t, []string{"stop"}, rc.commands)
	assertVMState(t, orch, qi, StateSuspended)
}

func TestResume_SuspendedVMContinues(t *testing.T) {
	orch := newOpsOrchestrator(t)
	qi := insertSuspendedVM(t, orch, "vm1")
	rc := &fakeRunControl{}
	installRunControlSeam(t, rc, nil)

	require.NoError(t, orch.Resume(context.Background(), "vm1"))
	assert.Equal(t, []string{"cont"}, rc.commands)
	assertVMState(t, orch, qi, StateRunning)
}

func TestSuspendResume_WrongStateIsRefused(t *testing.T) {
	tests := []struct {
		name    string
		insert  func(t *testing.T, orch *QEMUOrchestrator) *qemuInstance
		call    func(orch *QEMUOrchestrator) error
		wantErr error
		state   InstanceState
	}{
		{
			name: "suspend stopped VM",
			insert: func(t *testing.T, orch *QEMUOrchestrator) *qemuInstance {
				return insertVMInstance(t, orch, "vm1", false, &InstanceConfig{})
			},
			call:    func(orch *QEMUOrchestrator) error { return orch.Suspend(context.Background(), "vm1") },
			wantErr: ErrInstanceNotRunning,
			state:   StateStopped,
		},
		{
			name:    "suspend suspended VM",
			insert:  func(t *testing.T, orch *QEMUOrchestrator) *qemuInstance { return insertSuspendedVM(t, orch, "vm1") },
			call:    func(orch *QEMUOrchestrator) error { return orch.Suspend(context.Background(), "vm1") },
			wantErr: ErrInstanceNotRunning,
			state:   StateSuspended,
		},
		{
			name: "resume running VM",
			insert: func(t *testing.T, orch *QEMUOrchestrator) *qemuInstance {
				return insertVMInstance(t, orch, "vm1", true, &InstanceConfig{})
			},
			call:    func(orch *QEMUOrchestrator) error { return orch.Resume(context.Background(), "vm1") },
			wantErr: ErrInstanceNotSuspended,
			state:   StateRunning,
		},
		{
			name: "resume stopped VM",
			insert: func(t *testing.T, orch *QEMUOrchestrator) *qemuInstance {
				return insertVMInstance(t, orch, "vm1", false, &InstanceConfig{})
			},
			call:    func(orch *QEMUOrchestrator) error { return orch.Resume(context.Background(), "vm1") },
			wantErr: ErrInstanceNotSuspended,
			state:   StateStopped,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			orch := newOpsOrchestrator(t)
			qi := tt.insert(t, orch)
			rc := &fakeRunControl{}
			installRunControlSeam(t, rc, nil)

			err := tt.call(orch)
			require.ErrorIs(t, err, tt.wantErr)
			assert.Empty(t, rc.commands, "nothing is sent to QEMU in the wrong state")
			got, stateErr := orch.GetState(context.Background(), "vm1")
			require.NoError(t, stateErr)
			assert.Equal(t, tt.state, got)
			assert.Equal(t, tt.state, qi.instance.State)
		})
	}
}

func TestSuspendResume_BadInstance(t *testing.T) {
	orch := newOpsOrchestrator(t)
	ctx := context.Background()

	assert.ErrorIs(t, orch.Suspend(ctx, ""), ErrInvalidInstanceID)
	assert.ErrorIs(t, orch.Resume(ctx, ""), ErrInvalidInstanceID)
	assert.ErrorIs(t, orch.Suspend(ctx, "missing"), ErrInstanceNotFound)
	assert.ErrorIs(t, orch.Resume(ctx, "missing"), ErrInstanceNotFound)
}

func TestSuspend_QMPFailureKeepsState(t *testing.T) {
	orch := newOpsOrchestrator(t)
	qi := insertVMInstance(t, orch, "vm1", true, &InstanceConfig{})
	installRunControlSeam(t, &fakeRunControl{pauseErr: errFakeQMP}, nil)

	err := orch.Suspend(context.Background(), "vm1")
	require.ErrorIs(t, err, errFakeQMP)
	assertVMState(t, orch, qi, StateRunning)
}

func TestResume_MonitorConnectFailureKeepsState(t *testing.T) {
	orch := newOpsOrchestrator(t)
	qi := insertSuspendedVM(t, orch, "vm1")
	installRunControlSeam(t, nil, errFakeQMP)

	err := orch.Resume(context.Background(), "vm1")
	require.ErrorIs(t, err, errFakeQMP)
	assertVMState(t, orch, qi, StateSuspended)
}

func TestStop_SuspendedVMIsContinuedThenStopped(t *testing.T) {
	orch := newOpsOrchestrator(t)
	qi := insertSuspendedVM(t, orch, "vm1")
	rc := &fakeRunControl{}
	installRunControlSeam(t, rc, nil)
	stops := installStopSeam(t, orch, qi, nil)

	require.NoError(t, orch.Stop(context.Background(), "vm1"))
	assert.Equal(t, []string{"cont"}, rc.commands)
	assert.Equal(t, 1, *stops)
	assertVMState(t, orch, qi, StateStopped)
}

func TestStop_SuspendedVMStopsWhenContinueFails(t *testing.T) {
	orch := newOpsOrchestrator(t)
	qi := insertSuspendedVM(t, orch, "vm1")
	installRunControlSeam(t, &fakeRunControl{resumeErr: errFakeQMP}, nil)
	stops := installStopSeam(t, orch, qi, nil)

	require.NoError(t, orch.Stop(context.Background(), "vm1"))
	assert.Equal(t, 1, *stops)
	assertVMState(t, orch, qi, StateStopped)
}

func TestStop_ProcessStopFailureMarksError(t *testing.T) {
	orch := newOpsOrchestrator(t)
	qi := insertVMInstance(t, orch, "vm1", true, &InstanceConfig{})
	installRunControlSeam(t, &fakeRunControl{}, nil)
	installStopSeam(t, orch, qi, errFakeQMP)

	err := orch.Stop(context.Background(), "vm1")
	require.ErrorIs(t, err, errFakeQMP)
	assertVMState(t, orch, qi, StateError)
}

func TestStop_StoppedVMIsRefused(t *testing.T) {
	orch := newOpsOrchestrator(t)
	insertVMInstance(t, orch, "vm1", false, &InstanceConfig{})

	err := orch.Stop(context.Background(), "vm1")
	assert.ErrorIs(t, err, ErrInstanceNotRunning)
}

// stopUnblockedWithin bounds how long a call made while another VM's stop
// waits for its guest may take before the test calls it blocked.
const stopUnblockedWithin = 5 * time.Second

// TestStop_GuestWaitDoesNotBlockOtherCalls: a graceful stop waits for the
// guest without the instance lock, so get, list and create answer while it
// waits, and the VM reads stopping until its exit is recorded.
func TestStop_GuestWaitDoesNotBlockOtherCalls(t *testing.T) {
	orch := newOpsOrchestrator(t)
	qi := insertVMInstance(t, orch, "vm1", true, &InstanceConfig{})

	exited := make(chan struct{})
	run := installTestRun(qi, func() {})
	go func() {
		defer close(run.done)
		<-exited
		orch.recordExit("vm1", qi)
	}()

	waiting := make(chan struct{})
	release := make(chan struct{})
	orig := stopVMProcess
	stopVMProcess = func(*qemuInstance, StopOptions) error {
		close(waiting)
		<-release
		close(exited)
		return nil
	}
	t.Cleanup(func() { stopVMProcess = orig })

	stopped := make(chan error, 1)
	go func() { stopped <- orch.Stop(context.Background(), "vm1") }()
	<-waiting

	type answer struct {
		listErr error
		got     *Instance
		getErr  error
	}
	others := make(chan answer, 1)
	go func() {
		var a answer
		_, a.listErr = orch.List(context.Background(), nil)
		a.got, a.getErr = orch.Get(context.Background(), "vm1")
		// Create takes the orchestrator's write lock.
		insertVMInstance(t, orch, "vm2", false, &InstanceConfig{})
		others <- a
	}()
	select {
	case a := <-others:
		require.NoError(t, a.listErr)
		require.NoError(t, a.getErr)
		assert.Equal(t, StateStopping, a.got.State)
	case <-time.After(stopUnblockedWithin):
		close(release)
		t.Fatal("get, list or create blocked behind a stop waiting for its guest")
	}

	close(release)
	require.NoError(t, <-stopped)
	assertVMState(t, orch, qi, StateStopped)
}

// TestStop_RestartDuringGuestWaitKeepsNewRun: a stop waits for its guest
// without the instance lock, so the stopped run can exit and a start can
// replace the instance's run before the stop finishes. The stop cancels and
// waits on the run it stopped, so it neither kills the new run nor waits
// for it to exit.
func TestStop_RestartDuringGuestWaitKeepsNewRun(t *testing.T) {
	orch := newOpsOrchestrator(t)
	qi := insertVMInstance(t, orch, "vm1", true, &InstanceConfig{})

	exitA := make(chan struct{})
	runA := installTestRun(qi, func() {})
	go func() {
		defer close(runA.done)
		<-exitA
		orch.recordExit("vm1", qi)
	}()

	var cancelledB atomic.Bool
	runB := &qemuRun{cancel: func() { cancelledB.Store(true) }, done: make(chan struct{})}
	t.Cleanup(func() { close(runB.done) })

	orig := stopVMProcess
	stopVMProcess = func(*qemuInstance, StopOptions) error {
		// Run A exits and its exit is recorded, then a start brings up run B.
		close(exitA)
		<-runA.done
		qi.mu.Lock()
		defer qi.mu.Unlock()
		assert.NoError(t, orch.lifecycle.SetState("vm1", StateStarting))
		assert.NoError(t, orch.lifecycle.SetState("vm1", StateRunning))
		qi.instance.State = StateRunning
		qi.run = runB
		return nil
	}
	t.Cleanup(func() { stopVMProcess = orig })

	stopped := make(chan error, 1)
	go func() { stopped <- orch.Stop(context.Background(), "vm1") }()
	select {
	case err := <-stopped:
		require.NoError(t, err)
	case <-time.After(stopUnblockedWithin):
		t.Fatal("the stop of run A waited for run B to exit")
	}
	assert.False(t, cancelledB.Load(), "the stop of run A cancelled run B")
	assertVMState(t, orch, qi, StateRunning)
}

// TestStop_ExitDuringFailedStopIsStopped: a stop whose process call fails
// after the guest has exited leaves the VM stopped, not in error.
func TestStop_ExitDuringFailedStopIsStopped(t *testing.T) {
	orch := newOpsOrchestrator(t)
	qi := insertVMInstance(t, orch, "vm1", true, &InstanceConfig{})

	orig := stopVMProcess
	stopVMProcess = func(inst *qemuInstance, _ StopOptions) error {
		orch.recordExit("vm1", inst)
		return errFakeQMP
	}
	t.Cleanup(func() { stopVMProcess = orig })

	require.NoError(t, orch.Stop(context.Background(), "vm1"))
	assertVMState(t, orch, qi, StateStopped)
}

func TestDelete_SuspendedVMIsStoppedFirst(t *testing.T) {
	orch := newOpsOrchestrator(t)
	qi := insertSuspendedVM(t, orch, "vm1")
	installRunControlSeam(t, &fakeRunControl{}, nil)
	stops := installStopSeam(t, orch, qi, nil)

	require.NoError(t, orch.Delete(context.Background(), "vm1"))
	assert.Equal(t, 1, *stops)
	_, err := orch.Get(context.Background(), "vm1")
	assert.ErrorIs(t, err, ErrInstanceNotFound)
}
