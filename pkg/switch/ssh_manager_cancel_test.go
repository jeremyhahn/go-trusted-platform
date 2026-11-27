package switchmgmt

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// blockingExecutor is an SSHExecutor whose first Execute holds the
// connection until release is closed, so a second call has to queue.
type blockingExecutor struct {
	mu       sync.Mutex
	commands []string
	closed   bool
	calls    int
	entered  chan struct{}
	release  chan struct{}
}

func newBlockingExecutor() *blockingExecutor {
	return &blockingExecutor{
		entered: make(chan struct{}),
		release: make(chan struct{}),
	}
}

func (b *blockingExecutor) Execute(_ context.Context, command string) (string, error) {
	b.mu.Lock()
	b.commands = append(b.commands, command)
	b.calls++
	first := b.calls == 1
	b.mu.Unlock()
	if first {
		close(b.entered)
		<-b.release
	}
	if command == "show interfaces Eth1/3 switchport" {
		return concurrencySwitchportOutput, nil
	}
	return "", nil
}

func (b *blockingExecutor) Close() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.closed = true
	return nil
}

func (b *blockingExecutor) snapshot() ([]string, bool) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]string(nil), b.commands...), b.closed
}

func TestSSHManager_QueuedCanceledMutationSendsNoCommand(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(context.Context, *sshManager) error
	}{
		{"SetPortVLAN", func(ctx context.Context, m *sshManager) error { return m.SetPortVLAN(ctx, "Eth1/3", 200) }},
		{"EnablePort", func(ctx context.Context, m *sshManager) error { return m.EnablePort(ctx, "Eth1/3") }},
		{"DisablePort", func(ctx context.Context, m *sshManager) error { return m.DisablePort(ctx, "Eth1/3") }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			exec := newBlockingExecutor()
			m := newSSHManagerWithExecutor(testSSHConfig(), testSSHLogger(), exec)
			var dials atomic.Int32
			m.dial = func(context.Context, *Config) (SSHExecutor, error) {
				dials.Add(1)
				return exec, nil
			}

			aDone := make(chan error, 1)
			go func() {
				_, err := m.GetPortVLAN(context.Background(), "Eth1/3")
				aDone <- err
			}()
			select {
			case <-exec.entered:
			case <-time.After(2 * time.Second):
				close(exec.release)
				t.Fatal("first call never reached the executor")
			}

			ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
			defer cancel()
			bDone := make(chan error, 1)
			go func() { bDone <- tc.mutate(ctx, m) }()

			var bErr error
			bReturned := false
			select {
			case bErr = <-bDone:
				bReturned = true
				if !errors.Is(bErr, context.DeadlineExceeded) {
					t.Errorf("queued mutation error = %v, want context.DeadlineExceeded", bErr)
				}
			case <-time.After(2 * time.Second):
				t.Errorf("queued mutation did not return while the connection was busy")
			}

			close(exec.release)
			if err := <-aDone; err != nil {
				t.Errorf("first call: %v", err)
			}
			if !bReturned {
				bErr = <-bDone
				if !errors.Is(bErr, context.DeadlineExceeded) {
					t.Errorf("queued mutation error = %v, want context.DeadlineExceeded", bErr)
				}
			}

			commands, closed := exec.snapshot()
			if len(commands) != 1 || commands[0] != "show interfaces Eth1/3 switchport" {
				t.Errorf("commands = %q, want only the first call's show command", commands)
			}
			if closed {
				t.Errorf("a canceled call closed the connection")
			}

			vlan, err := m.GetPortVLAN(context.Background(), "Eth1/3")
			if err != nil {
				t.Fatalf("GetPortVLAN after the canceled call: %v", err)
			}
			if vlan != 100 {
				t.Errorf("vlan = %d, want 100", vlan)
			}
			if n := dials.Load(); n != 0 {
				t.Errorf("dials = %d, want 0 (the connection stays open)", n)
			}
		})
	}
}

func TestSSHManager_CanceledContextSendsNoCommand(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	ops := []struct {
		name string
		call func(*sshManager) error
	}{
		{"SetPortVLAN", func(m *sshManager) error { return m.SetPortVLAN(ctx, "Eth1/3", 200) }},
		{"GetPortVLAN", func(m *sshManager) error { _, err := m.GetPortVLAN(ctx, "Eth1/3"); return err }},
		{"GetPortStatus", func(m *sshManager) error { _, err := m.GetPortStatus(ctx, "Eth1/3"); return err }},
		{"ListPorts", func(m *sshManager) error { _, err := m.ListPorts(ctx); return err }},
		{"EnablePort", func(m *sshManager) error { return m.EnablePort(ctx, "Eth1/3") }},
		{"DisablePort", func(m *sshManager) error { return m.DisablePort(ctx, "Eth1/3") }},
	}
	for _, op := range ops {
		t.Run(op.name, func(t *testing.T) {
			mock := newMockSSHExecutor()
			m := newSSHManagerWithExecutor(testSSHConfig(), testSSHLogger(), mock)
			err := op.call(m)
			if !errors.Is(err, context.Canceled) {
				t.Errorf("error = %v, want context.Canceled", err)
			}
			if len(mock.commands) != 0 {
				t.Errorf("commands = %q, want none", mock.commands)
			}
			if mock.closed {
				t.Errorf("a canceled call closed the connection")
			}
		})
	}
}

// stallingExecutor is an SSHExecutor whose Execute never returns until its
// Close is called, like a session whose channel open the switch never answers.
type stallingExecutor struct {
	enterOnce sync.Once
	closeOnce sync.Once
	entered   chan struct{}
	closed    chan struct{}
	closes    atomic.Int32
}

func newStallingExecutor() *stallingExecutor {
	return &stallingExecutor{
		entered: make(chan struct{}),
		closed:  make(chan struct{}),
	}
}

func (s *stallingExecutor) Execute(context.Context, string) (string, error) {
	s.enterOnce.Do(func() { close(s.entered) })
	<-s.closed
	return "", errors.New("connection closed")
}

func (s *stallingExecutor) Close() error {
	s.closes.Add(1)
	s.closeOnce.Do(func() { close(s.closed) })
	return nil
}

func TestSSHManager_CloseInterruptsAnExecuteThatNeverReturns(t *testing.T) {
	stall := newStallingExecutor()
	t.Cleanup(func() { _ = stall.Close() })
	mgr := newSSHManagerWithExecutor(testSSHConfig(), testSSHLogger(), stall)
	var dials atomic.Int32
	mgr.dial = func(context.Context, *Config) (SSHExecutor, error) {
		dials.Add(1)
		return newSwitchportMock(), nil
	}

	getDone := make(chan error, 1)
	go func() {
		_, err := mgr.GetPortVLAN(context.Background(), "Eth1/3")
		getDone <- err
	}()
	timer := time.NewTimer(5 * time.Second)
	defer timer.Stop()
	select {
	case <-stall.entered:
	case <-timer.C:
		t.Fatal("GetPortVLAN never reached the executor")
	}

	closeDone := make(chan error, 1)
	go func() { closeDone <- mgr.Close() }()

	var getErr error
	for pending := 2; pending > 0; pending-- {
		select {
		case getErr = <-getDone:
			if getErr == nil {
				t.Error("GetPortVLAN on a closed connection returned no error")
			}
			getDone = nil
		case err := <-closeDone:
			if err != nil {
				t.Errorf("Close: %v", err)
			}
			closeDone = nil
		case <-timer.C:
			t.Fatalf("Close did not interrupt the stalled Execute (GetPortVLAN returned: %t, Close returned: %t)",
				getDone == nil, closeDone == nil)
		}
	}
	if n := stall.closes.Load(); n != 1 {
		t.Errorf("executor closed %d times, want 1", n)
	}

	if _, err := mgr.GetPortVLAN(context.Background(), "Eth1/3"); err != nil {
		t.Fatalf("GetPortVLAN after Close: %v", err)
	}
	if n := dials.Load(); n != 1 {
		t.Errorf("dials = %d, want 1 (the call after Close redials)", n)
	}
}
