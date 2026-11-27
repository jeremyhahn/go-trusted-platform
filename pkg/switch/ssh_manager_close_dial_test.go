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
	"sync"
	"testing"
	"time"
)

// TestSSHManager_CloseDuringDialClosesLateConnection starts Close while an
// operation's dialer is blocked. Close must not return while a connection
// that the in-flight dial publishes stays open: after Close returns, every
// connection the dialer handed back is closed and the manager holds none.
func TestSSHManager_CloseDuringDialClosesLateConnection(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	var mu sync.Mutex
	var dialed []*mockSSHExecutor
	dial := func(ctx context.Context, _ *Config) (SSHExecutor, error) {
		close(entered)
		select {
		case <-release:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		mock := newSwitchportMock()
		mu.Lock()
		dialed = append(dialed, mock)
		mu.Unlock()
		return mock, nil
	}
	mgr := newSSHManagerWithDialer(testSSHConfig(), testSSHLogger(), dial)

	opDone := make(chan struct{})
	go func() {
		defer close(opDone)
		_, _ = mgr.GetPortVLAN(context.Background(), "Eth1/3")
	}()
	<-entered

	closeDone := make(chan error, 1)
	go func() { closeDone <- mgr.Close() }()

	// Give Close time to start before the dial finishes.
	time.Sleep(50 * time.Millisecond)
	close(release)

	select {
	case <-closeDone:
	case <-time.After(5 * time.Second):
		t.Fatal("Close did not return after the blocked dial finished")
	}
	select {
	case <-opDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the in-flight operation did not return after Close")
	}

	mu.Lock()
	defer mu.Unlock()
	for i, mock := range dialed {
		if !mock.closed {
			t.Errorf("connection %d dialed during Close is still open after Close returned", i)
		}
	}
	mgr.connMu.Lock()
	live := mgr.executor
	mgr.connMu.Unlock()
	if live != nil {
		t.Error("manager still holds a connection after Close returned")
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
