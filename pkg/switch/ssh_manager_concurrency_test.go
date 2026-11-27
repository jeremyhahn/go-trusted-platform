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

const concurrencySwitchportOutput = `Name: Eth1/3
Switchport: Enabled
Administrative Mode: static access
Operational Mode: static access
Access Mode VLAN: 100 (provisioning)
Trunking Native Mode VLAN: 1 (default)
`

func newSwitchportMock() *mockSSHExecutor {
	mock := newMockSSHExecutor()
	mock.outputs["show interfaces Eth1/3 switchport"] = concurrencySwitchportOutput
	return mock
}

// TestSSHManager_ConcurrentFirstUseDialsOnce starts n first calls at once on
// a manager with no connection: the dialer is held open while the calls pile
// up, and only one SSH connection may be dialed for all of them.
func TestSSHManager_ConcurrentFirstUseDialsOnce(t *testing.T) {
	const n = 8
	var dials atomic.Int32
	entered := make(chan struct{}, n)
	release := make(chan struct{})
	dial := func(context.Context, *Config) (SSHExecutor, error) {
		dials.Add(1)
		entered <- struct{}{}
		<-release
		return newSwitchportMock(), nil
	}
	mgr := newSSHManagerWithDialer(testSSHConfig(), testSSHLogger(), dial)

	ctx := context.Background()
	start := make(chan struct{})
	vlans := make([]uint16, n)
	errs := make([]error, n)
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			vlans[i], errs[i] = mgr.GetPortVLAN(ctx, "Eth1/3")
		}(i)
	}
	close(start)

	<-entered
	timeout := time.After(200 * time.Millisecond)
collect:
	for {
		select {
		case <-entered:
		case <-timeout:
			break collect
		}
	}
	close(release)
	wg.Wait()

	if got := dials.Load(); got != 1 {
		t.Fatalf("concurrent first use dialed %d SSH connections, want 1", got)
	}
	for i := 0; i < n; i++ {
		if errs[i] != nil || vlans[i] != 100 {
			t.Errorf("call %d: GetPortVLAN = %d, %v; want 100, nil", i, vlans[i], errs[i])
		}
	}
}

// TestSSHManager_CloseThenUseIsRejected pins that Close drops the connection
// and is final: a later call returns errSSHConnectionClosed without dialing.
func TestSSHManager_CloseThenUseIsRejected(t *testing.T) {
	var dials atomic.Int32
	var first *mockSSHExecutor
	dial := func(context.Context, *Config) (SSHExecutor, error) {
		dials.Add(1)
		mock := newSwitchportMock()
		if first == nil {
			first = mock
		}
		return mock, nil
	}
	mgr := newSSHManagerWithDialer(testSSHConfig(), testSSHLogger(), dial)
	ctx := context.Background()

	if _, err := mgr.GetPortVLAN(ctx, "Eth1/3"); err != nil {
		t.Fatalf("first GetPortVLAN: %v", err)
	}
	if err := mgr.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if first == nil || !first.closed {
		t.Fatal("Close did not close the first connection")
	}
	if _, err := mgr.GetPortVLAN(ctx, "Eth1/3"); !errors.Is(err, errSSHConnectionClosed) {
		t.Fatalf("GetPortVLAN after Close = %v, want errSSHConnectionClosed", err)
	}
	if got := dials.Load(); got != 1 {
		t.Fatalf("dials = %d, want 1 (a closed manager never redials)", got)
	}
}
