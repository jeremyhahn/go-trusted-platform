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

package daemon

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// mockManagedService is a test implementation of ManagedService
type mockManagedService struct {
	name       string
	running    atomic.Bool
	startErr   error
	stopErr    error
	startDelay time.Duration
	stopDelay  time.Duration
	startCount atomic.Int32
	stopCount  atomic.Int32

	// starts carries one pending notification. startCount above is
	// authoritative; this only nudges a waiter, so a notification dropped while
	// nobody is waiting cannot lose an occurrence — awaitStarts re-reads the
	// counter on every wakeup.
	//
	// Sends are non-blocking, so a mock whose caller is not waiting never
	// stalls the daemon's auto-start goroutine.
	//
	// There is deliberately no `stops` counterpart: Stop() is synchronous, so
	// every stopCount assertion in this package already runs after Stop has
	// returned and needs no wait. A symmetrical-but-unused channel would be the
	// residue the No-Cruft policy targets.
	starts chan struct{}
}

func newMockService(name string) *mockManagedService {
	return &mockManagedService{
		name:   name,
		starts: make(chan struct{}, 1),
	}
}

// daemonTestDeadline bounds how long a test waits for something that must
// eventually happen. It is a liveness backstop, not a timing assumption: these
// tests advance on the event itself, so a loaded machine only takes longer and
// the deadline is reached only by a daemon that has stopped making progress.
const daemonTestDeadline = 10 * time.Second

// awaitStarts blocks until Start has been called at least want times.
func (m *mockManagedService) awaitStarts(t *testing.T, want int32) {
	t.Helper()
	m.await(t, want, &m.startCount, m.starts, "Start")
}

func (m *mockManagedService) await(t *testing.T, want int32, count *atomic.Int32, wake <-chan struct{}, what string) {
	t.Helper()

	deadline := time.After(daemonTestDeadline)
	for {
		if got := count.Load(); got >= want {
			return
		}
		select {
		case <-wake:
		case <-deadline:
			t.Fatalf("%s: %s called %d of %d times within %s",
				m.name, what, count.Load(), want, daemonTestDeadline)
		}
	}
}

// notify performs the non-blocking send described on the struct.
func notify(ch chan struct{}) {
	select {
	case ch <- struct{}{}:
	default:
	}
}

func (m *mockManagedService) Name() string {
	return m.name
}

func (m *mockManagedService) Start(ctx context.Context) error {
	m.startCount.Add(1)
	notify(m.starts)
	if m.startDelay > 0 {
		select {
		case <-time.After(m.startDelay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if m.startErr != nil {
		return m.startErr
	}
	m.running.Store(true)
	return nil
}

func (m *mockManagedService) Stop(ctx context.Context) error {
	m.stopCount.Add(1)
	if m.stopDelay > 0 {
		select {
		case <-time.After(m.stopDelay):
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if m.stopErr != nil {
		return m.stopErr
	}
	m.running.Store(false)
	return nil
}

func (m *mockManagedService) IsRunning() bool {
	return m.running.Load()
}

// testConfig returns a test-friendly configuration with gRPC TCP disabled
// to avoid port conflicts when running tests in parallel
func testConfig(socketPath string) *Config {
	config := DefaultConfig()
	config.SocketPath = socketPath
	config.GRPCSocketPath = socketPath // Use same path for gRPC UDS
	config.SocketGroup = ""            // Don't require specific group for tests
	config.EnableGRPCTCP = false       // Disable gRPC TCP to avoid port conflicts
	config.SkipIAMValidation = true    // Skip IAM for unit tests (no QuicBaaS)
	// Fail-closed transports (#32): network transports refuse to start
	// without TLS material, so lifecycle tests get the shared in-memory
	// certificate. REST binds an ephemeral loopback port — bind failures
	// are now synchronous typed errors, so daemons sharing the default
	// :8443 would correctly fail each other.
	cert := sharedTestTLSCertificate()
	config.TLSCertificate = &cert
	config.RESTListenAddr = "127.0.0.1:0"
	// An enabled QUIC transport that cannot be constructed fails New
	// (#444), so a test that enables QUIC gets TLS material for it too.
	config.QUICConfig = testQUICServerConfig(cert)
	return config
}

func TestNew(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name:    "nil config uses defaults",
			config:  nil,
			wantErr: true,
		},
		{
			name:    "valid config",
			config:  testConfig("/tmp/test-daemon-new.sock"),
			wantErr: false,
		},
		{
			name: "custom config",
			config: &Config{
				SocketPath:        "/tmp/test-daemon.sock",
				GRPCSocketPath:    "/tmp/test-daemon.sock", // Set gRPC UDS socket path
				SocketGroup:       "",
				SocketMode:        0600,
				ShutdownTimeout:   10 * time.Second,
				EnableMetrics:     true,
				EnableEvents:      true,
				EnableGRPCTCP:     false,
				Services:          DefaultConfig().Services,
				SkipIAMValidation: true, // Skip IAM for unit tests (no QuicBaaS)
			},
			wantErr: false,
		},
		{
			name: "invalid config - empty socket path",
			config: &Config{
				SocketPath:        "",
				ShutdownTimeout:   10 * time.Second,
				Services:          map[string]ServiceConfig{},
				SkipIAMValidation: true,
			},
			wantErr: true,
		},
		{
			name: "invalid config - zero timeout",
			config: &Config{
				SocketPath:        "/tmp/test.sock",
				ShutdownTimeout:   0,
				Services:          map[string]ServiceConfig{},
				SkipIAMValidation: true,
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			d, err := New(tt.config)

			if tt.wantErr {
				if err == nil {
					t.Error("New() expected error but got nil")
				}
				if d != nil {
					_ = d.ForceStop()
				}
				return
			}

			if err != nil {
				t.Errorf("New() unexpected error: %v", err)
				return
			}

			if d == nil {
				t.Fatal("New() returned nil daemon")
			}

			if d.IsRunning() {
				t.Error("newly created daemon should not be running")
			}

			expectedPath := "/tmp/test-daemon.sock"
			if tt.config != nil && tt.config.GRPCSocketPath != "" {
				expectedPath = tt.config.GRPCSocketPath
			} else if tt.config == nil {
				expectedPath = DefaultConfig().GRPCSocketPath
			}

			if d.SocketPath() != expectedPath {
				t.Errorf("SocketPath() = %q, want %q", d.SocketPath(), expectedPath)
			}
		})
	}
}

func TestDaemon_StartStop(t *testing.T) {
	config := testConfig("/tmp/test-daemon-startstop.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	if d.IsRunning() {
		t.Error("daemon should not be running initially")
	}

	ctx := context.Background()
	if err := d.Start(ctx); err != nil {
		t.Errorf("Start() error: %v", err)
	}

	if !d.IsRunning() {
		t.Error("daemon should be running after Start()")
	}

	if err := d.Stop(ctx); err != nil {
		t.Errorf("Stop() error: %v", err)
	}

	if d.IsRunning() {
		t.Error("daemon should not be running after Stop()")
	}

	_ = d.ForceStop()
}

func TestDaemon_DoubleStart(t *testing.T) {
	config := testConfig("/tmp/test-daemon-doublestart.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer func() {
		_ = d.ForceStop()
	}()

	ctx := context.Background()

	if err := d.Start(ctx); err != nil {
		t.Errorf("first Start() error: %v", err)
	}

	if err := d.Start(ctx); err == nil {
		t.Error("second Start() should return error")
	}
}

func TestDaemon_DoubleStop(t *testing.T) {
	config := testConfig("/tmp/test-daemon-doublestop.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx := context.Background()

	if err := d.Start(ctx); err != nil {
		t.Errorf("Start() error: %v", err)
	}

	if err := d.Stop(ctx); err != nil {
		t.Errorf("first Stop() error: %v", err)
	}

	if err := d.Stop(ctx); err == nil {
		t.Error("second Stop() should return error")
	}
}

func TestDaemon_ForceStop(t *testing.T) {
	config := testConfig("/tmp/test-daemon-forcestop.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	ctx := context.Background()

	if err := d.Start(ctx); err != nil {
		t.Errorf("Start() error: %v", err)
	}

	if err := d.ForceStop(); err != nil {
		t.Fatalf("ForceStop() failed: %v", err)
	}

	// After ForceStop, daemon should not be running
	if d.IsRunning() {
		t.Error("daemon should not be running after ForceStop()")
	}
}

func TestDaemon_ManagedServices(t *testing.T) {
	config := testConfig("/tmp/test-daemon-managed.sock")
	config.Services = map[string]ServiceConfig{
		"test1": {Enabled: true, AutoStart: true, Timeout: 5 * time.Second},
		"test2": {Enabled: true, AutoStart: true, Timeout: 5 * time.Second},
	}

	// Daemon.Start launches the auto-start pass on its own goroutine. Observe
	// its completion so the manual Start/Stop below cannot interleave with it
	// and have a service restarted behind the test's back.
	autoStarted := make(chan struct{})
	var autoStartOnce sync.Once
	d, err := New(config, withAutoStartObserver(func() {
		autoStartOnce.Do(func() { close(autoStarted) })
	}))
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer func() {
		_ = d.ForceStop()
	}()

	svc1 := newMockService("test1")
	svc2 := newMockService("test2")

	if err := d.RegisterService(svc1); err != nil {
		t.Errorf("RegisterService(svc1) error: %v", err)
	}
	if err := d.RegisterService(svc2); err != nil {
		t.Errorf("RegisterService(svc2) error: %v", err)
	}

	ctx := context.Background()

	if err := d.Start(ctx); err != nil {
		t.Fatalf("Start() error: %v", err)
	}

	// Wait for the whole auto-start pass, not for one service.
	select {
	case <-autoStarted:
	case <-time.After(daemonTestDeadline):
		t.Fatalf("auto-start pass did not complete within %s", daemonTestDeadline)
	}

	if !svc1.IsRunning() {
		t.Error("svc1 should be running after auto-start")
	}
	if !svc2.IsRunning() {
		t.Error("svc2 should be running after auto-start")
	}

	// Stop the auto-started services by hand, then start them by hand again.
	if err := svc1.Stop(ctx); err != nil {
		t.Errorf("svc1.Stop() after auto-start error: %v", err)
	}
	if err := svc2.Stop(ctx); err != nil {
		t.Errorf("svc2.Stop() after auto-start error: %v", err)
	}
	if svc1.IsRunning() || svc2.IsRunning() {
		t.Error("services should not be running after the first manual Stop()")
	}

	if err := svc1.Start(ctx); err != nil {
		t.Errorf("svc1.Start() error: %v", err)
	}
	if err := svc2.Start(ctx); err != nil {
		t.Errorf("svc2.Start() error: %v", err)
	}

	if !svc1.IsRunning() {
		t.Error("svc1 should be running after Start()")
	}
	if !svc2.IsRunning() {
		t.Error("svc2 should be running after Start()")
	}

	// Stop services manually
	if err := svc1.Stop(ctx); err != nil {
		t.Errorf("svc1.Stop() error: %v", err)
	}
	if err := svc2.Stop(ctx); err != nil {
		t.Errorf("svc2.Stop() error: %v", err)
	}

	if svc1.IsRunning() {
		t.Error("svc1 should not be running after Stop()")
	}
	if svc2.IsRunning() {
		t.Error("svc2 should not be running after Stop()")
	}
}

func TestDaemon_ServiceStartFailure(t *testing.T) {
	config := testConfig("/tmp/test-daemon-svcfail.sock")
	config.Services = map[string]ServiceConfig{
		"failing": {Enabled: true, AutoStart: true, Timeout: 5 * time.Second},
	}

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer func() {
		_ = d.ForceStop()
	}()

	svc := newMockService("failing")
	svc.startErr = errors.New("simulated start failure")

	if err := d.RegisterService(svc); err != nil {
		t.Errorf("RegisterService() error: %v", err)
	}

	ctx := context.Background()

	// Start should still succeed (service failures are logged but don't stop daemon)
	_ = d.Start(ctx)
}

func TestDaemon_RegisterDuplicateService(t *testing.T) {
	config := testConfig("/tmp/test-daemon-dupservice.sock")

	d, err := New(config)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	defer func() {
		_ = d.ForceStop()
	}()

	svc := newMockService("test")

	if err := d.RegisterService(svc); err != nil {
		t.Errorf("first RegisterService() error: %v", err)
	}

	if err := d.RegisterService(svc); err == nil {
		t.Error("second RegisterService() should return error")
	}
}
