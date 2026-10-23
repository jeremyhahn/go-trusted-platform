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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/qemu"
)

var errQMPRefused = errors.New("connect: connection refused")

// fakeMonitorConnector answers each ConnectMonitor call with connect(call),
// call counting from 0.
type fakeMonitorConnector struct {
	calls   int
	connect func(call int) error
}

func (f *fakeMonitorConnector) ConnectMonitor(ctx context.Context) error {
	call := f.calls
	f.calls++
	return f.connect(call)
}

// A monitor that refuses dials while QEMU starts is retried until it accepts.
func TestAwaitMonitor_RetriesRefusedDialUntilConnected(t *testing.T) {
	vm := &fakeMonitorConnector{connect: func(call int) error {
		if call < 2 {
			return errQMPRefused
		}
		return nil
	}}

	err := awaitMonitor(context.Background(), vm, make(chan error), time.Minute)

	require.NoError(t, err)
	assert.Equal(t, 3, vm.calls)
}

func TestAwaitMonitor_AlreadyConnectedIsReady(t *testing.T) {
	vm := &fakeMonitorConnector{connect: func(int) error { return qemu.ErrMonitorAlreadyConnected{} }}

	require.NoError(t, awaitMonitor(context.Background(), vm, make(chan error), time.Minute))
}

// QEMU exiting after it bound the socket is a start failure carrying its reason.
func TestAwaitMonitor_QEMUExitIsStartFailureWithReason(t *testing.T) {
	vm := &fakeMonitorConnector{connect: func(int) error { return errQMPRefused }}
	exited := make(chan error, 1)
	exited <- &qemu.SentinelCauseError{
		Sentinel: qemu.ErrQEMUFailed,
		Cause:    &qemu.MessageError{Msg: "exit status 1: failed to initialize kvm: No such file or directory"},
	}

	err := awaitMonitor(context.Background(), vm, exited, time.Minute)

	require.ErrorIs(t, err, ErrVMExitedDuringStart)
	assert.ErrorIs(t, err, qemu.ErrQEMUFailed)
	assert.Contains(t, err.Error(), "failed to initialize kvm")
}

func TestAwaitMonitor_CleanExitIsStartFailure(t *testing.T) {
	vm := &fakeMonitorConnector{connect: func(int) error { return qemu.ErrVMNotRunning }}
	exited := make(chan error, 1)
	exited <- nil

	err := awaitMonitor(context.Background(), vm, exited, time.Minute)

	assert.ErrorIs(t, err, ErrVMExitedDuringStart)
}

func TestAwaitMonitor_TimesOutWhenMonitorNeverAccepts(t *testing.T) {
	vm := &fakeMonitorConnector{connect: func(int) error { return errQMPRefused }}

	err := awaitMonitor(context.Background(), vm, make(chan error), 3*monitorRetryInterval)

	require.ErrorIs(t, err, ErrMonitorNotReady)
	assert.ErrorIs(t, err, errQMPRefused)
}

func TestAwaitMonitor_StopsWhenContextCanceled(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	vm := &fakeMonitorConnector{connect: func(int) error {
		cancel()
		return errQMPRefused
	}}

	err := awaitMonitor(ctx, vm, make(chan error), time.Minute)

	assert.ErrorIs(t, err, context.Canceled)
}

// A QEMU that exits during start (here it refuses to run, as without KVM)
// fails Start with QEMU's own reason and leaves the instance in error, not
// running with a monitor nobody can reach. The name stays short: the
// instance sockets live under t.TempDir, and unix socket paths cap at 107.
func TestStart_QEMUExitIsStartFailure(t *testing.T) {
	orch := newSWTPMTestOrchestrator(t, &fakeHost{})
	firmwareDir := t.TempDir()
	orch.config.OVMFCode = writeTestFile(t, firmwareDir, "OVMF_CODE.fd", "code", 0o644)
	orch.config.OVMFVars = writeTestFile(t, firmwareDir, "OVMF_VARS.fd", "vars", 0o644)
	orch.config.QEMUBinary = writeTestFile(t, firmwareDir, "qemu-system-x86_64",
		"#!/bin/sh\necho 'qemu-system-x86_64: failed to initialize kvm: No such file or directory' >&2\nexit 1\n", 0o755)
	ctx := context.Background()
	instance, err := orch.Create(ctx, &entities.DeviceProfile{ID: 1, Name: "test-vm-exits"})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(instance.Config.DiskPath, []byte("disk"), 0o600))

	err = orch.Start(ctx, instance.ID)

	require.ErrorIs(t, err, ErrVMExitedDuringStart)
	assert.Contains(t, err.Error(), "failed to initialize kvm")
	state, stateErr := orch.GetState(ctx, instance.ID)
	require.NoError(t, stateErr)
	assert.Equal(t, StateError, state)
}

func writeTestFile(t *testing.T, dir, name, content string, mode os.FileMode) string {
	t.Helper()
	path := filepath.Join(dir, name)
	require.NoError(t, os.WriteFile(path, []byte(content), mode))
	return path
}
