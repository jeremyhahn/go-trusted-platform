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
