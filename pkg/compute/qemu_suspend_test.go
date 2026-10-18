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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
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
func installStopSeamWithOptions(t *testing.T, orch *QEMUOrchestrator, qi *qemuInstance, stopErr error) (*int, *[]StopOptions) {
	t.Helper()
	calls := new(int)
	seen := new([]StopOptions)
	exited := make(chan struct{})
	qi.waitGroup.Add(1)
	go func() {
		defer qi.waitGroup.Done()
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

// installExitedProcessSeam stands in for a QEMU process that exited on its
// own: Start's wait goroutine has already returned and recorded the exit, so
// the process stop finds nothing to stop.
func installExitedProcessSeam(t *testing.T) {
	t.Helper()
	orig := stopVMProcess
	stopVMProcess = func(inst *qemuInstance, opts StopOptions) error {
		return qemu.ErrVMNotRunning
	}
	t.Cleanup(func() { stopVMProcess = orig })
}

func TestStop_ExitedProcessIsRecordedStopped(t *testing.T) {
	for _, opts := range []StopOptions{{}, {Force: true}} {
		orch := newOpsOrchestrator(t)
		qi := insertVMInstance(t, orch, "vm1", true, &InstanceConfig{})
		installRunControlSeam(t, &fakeRunControl{}, nil)
		installExitedProcessSeam(t)

		require.NoError(t, orch.StopWithOptions(context.Background(), "vm1", opts))
		assertVMState(t, orch, qi, StateStopped)
		assert.Zero(t, qi.instance.PID)
	}
}

func TestSuspendResume_ExitedProcessIsNotRunning(t *testing.T) {
	exited := &WrappedError{Msg: "failed to connect QMP monitor", Err: qemu.ErrVMNotRunning}

	orch := newOpsOrchestrator(t)
	running := insertVMInstance(t, orch, "vm1", true, &InstanceConfig{})
	suspended := insertSuspendedVM(t, orch, "vm2")
	installRunControlSeam(t, nil, exited)

	err := orch.Suspend(context.Background(), "vm1")
	require.ErrorIs(t, err, ErrInstanceNotRunning)
	assert.ErrorIs(t, err, qemu.ErrVMNotRunning)
	assertVMState(t, orch, running, StateRunning)

	err = orch.Resume(context.Background(), "vm2")
	require.ErrorIs(t, err, ErrInstanceNotRunning)
	assertVMState(t, orch, suspended, StateSuspended)
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
