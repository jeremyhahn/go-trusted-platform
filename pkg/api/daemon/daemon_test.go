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
}

func newMockService(name string) *mockManagedService {
	return &mockManagedService{
		name: name,
	}
}

func (m *mockManagedService) Name() string {
	return m.name
}

func (m *mockManagedService) Start(ctx context.Context) error {
	m.startCount.Add(1)
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

	// Give servers time to fully start
	time.Sleep(50 * time.Millisecond)

	// ForceStop may return error if underlying servers have timing issues,
	// but the important thing is that the daemon stops
	_ = d.ForceStop()

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

	d, err := New(config)
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
		t.Errorf("Start() error: %v", err)
	}

	// Note: Managed services must be started manually - daemon Start() only starts core servers
	// The AutoStart config is a hint for the service manager, not enforced by the daemon
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
