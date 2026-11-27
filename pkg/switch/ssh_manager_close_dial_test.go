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

package switchmgmt

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// TestSSHManager_CloseDuringDialClosesLateConnection starts Close while an
// operation's dialer is blocked. Close must not return while a connection
// that the in-flight dial publishes stays open: after Close returns, every
// connection the dialer handed back is closed and the manager holds none.
func TestSSHManager_CloseDuringDialClosesLateConnection(t *testing.T) {
	entered := make(chan struct{})
	var dials atomic.Int32
	var mu sync.Mutex
	var dialed []*mockSSHExecutor
	dial := func(ctx context.Context, _ *Config) (SSHExecutor, error) {
		if dials.Add(1) == 1 {
			close(entered)
			// Close cancels the dial context, so Close has started once
			// this returns; the dial still hands back a connection, as a
			// dial that finished despite the cancel would.
			<-ctx.Done()
		}
		mock := newSwitchportMock()
		mu.Lock()
		dialed = append(dialed, mock)
		mu.Unlock()
		return mock, nil
	}
	mgr := newSSHManagerWithDialer(testSSHConfig(), testSSHLogger(), dial)

	opDone := make(chan error, 1)
	go func() {
		_, err := mgr.GetPortVLAN(context.Background(), "Eth1/3")
		opDone <- err
	}()
	<-entered

	closeDone := make(chan error, 1)
	go func() { closeDone <- mgr.Close() }()

	select {
	case err := <-closeDone:
		if err != nil {
			t.Errorf("Close: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return after the blocked dial finished")
	}
	var opErr error
	select {
	case opErr = <-opDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the in-flight operation did not return after Close")
	}

	mu.Lock()
	if len(dialed) != 1 {
		mu.Unlock()
		t.Fatalf("no connection was dialed after Close started (dialed %d, want 1)", len(dialed))
	}
	if !dialed[0].closed {
		t.Error("the connection dialed during Close is still open after Close returned")
	}
	mu.Unlock()
	mgr.connMu.Lock()
	live := mgr.executor
	mgr.connMu.Unlock()
	if live != nil {
		t.Error("manager still holds a connection after Close returned")
	}
	if !errors.Is(opErr, errSSHConnectionClosed) {
		t.Errorf("in-flight operation error = %v, want errSSHConnectionClosed", opErr)
	}

	if _, err := mgr.GetPortVLAN(context.Background(), "Eth1/3"); !errors.Is(err, errSSHConnectionClosed) {
		t.Errorf("GetPortVLAN after Close = %v, want errSSHConnectionClosed", err)
	}
	if n := dials.Load(); n != 1 {
		t.Errorf("dials = %d, want 1 (a call after Close must not dial)", n)
	}
}

// TestSSHManager_CloseRejectsQueuedOperation queues an operation on the slot
// behind one stalled in Execute, then closes the manager: the queued
// operation must fail with errSSHConnectionClosed and never dial.
func TestSSHManager_CloseRejectsQueuedOperation(t *testing.T) {
	stall := newStallingExecutor()
	t.Cleanup(func() { _ = stall.Close() })
	mgr := newSSHManagerWithExecutor(testSSHConfig(), testSSHLogger(), stall)
	var dials atomic.Int32
	mgr.dial = func(context.Context, *Config) (SSHExecutor, error) {
		dials.Add(1)
		return newSwitchportMock(), nil
	}

	op1 := make(chan error, 1)
	go func() {
		_, err := mgr.GetPortVLAN(context.Background(), "Eth1/3")
		op1 <- err
	}()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-stall.entered:
	case <-timer.C:
		t.Fatal("first GetPortVLAN never reached the executor")
	}

	op2 := make(chan error, 1)
	go func() {
		_, err := mgr.GetPortVLAN(context.Background(), "Eth1/3")
		op2 <- err
	}()
	closeDone := make(chan error, 1)
	go func() { closeDone <- mgr.Close() }()

	for pending := 3; pending > 0; pending-- {
		select {
		case err := <-op1:
			if err == nil {
				t.Error("stalled GetPortVLAN returned no error after Close")
			}
			op1 = nil
		case err := <-op2:
			if !errors.Is(err, errSSHConnectionClosed) {
				t.Errorf("queued GetPortVLAN error = %v, want errSSHConnectionClosed", err)
			}
			op2 = nil
		case err := <-closeDone:
			if err != nil {
				t.Errorf("Close: %v", err)
			}
			closeDone = nil
		case <-timer.C:
			t.Fatalf("timed out (op1 returned: %t, op2 returned: %t, Close returned: %t)",
				op1 == nil, op2 == nil, closeDone == nil)
		}
	}
	if n := dials.Load(); n != 0 {
		t.Errorf("dials = %d, want 0 (a queued operation must not dial after Close)", n)
	}
}

// TestSSHManager_CloseInterruptsBlockedDial checks that Close does not wait
// on a dial that never finishes by itself: it cancels the dial's context, and
// the operation that was dialing returns an error.
func TestSSHManager_CloseInterruptsBlockedDial(t *testing.T) {
	entered := make(chan struct{})
	dial := func(ctx context.Context, _ *Config) (SSHExecutor, error) {
		close(entered)
		<-ctx.Done()
		return nil, ctx.Err()
	}
	mgr := newSSHManagerWithDialer(testSSHConfig(), testSSHLogger(), dial)

	opErr := make(chan error, 1)
	go func() {
		_, err := mgr.GetPortVLAN(context.Background(), "Eth1/3")
		opErr <- err
	}()
	<-entered

	closeDone := make(chan error, 1)
	go func() { closeDone <- mgr.Close() }()

	select {
	case <-closeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return while the dial was blocked")
	}
	select {
	case err := <-opErr:
		if err == nil {
			t.Error("the operation dialing during Close returned no error")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the in-flight operation did not return after Close")
	}
}
