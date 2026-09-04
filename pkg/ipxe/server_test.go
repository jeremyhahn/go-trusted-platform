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

package ipxe

import (
	"context"
	"errors"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNewServer(t *testing.T) {
	tests := []struct {
		name      string
		config    *ServerConfig
		logger    *logging.Logger
		wantErr   bool
		errType   error
		setupFunc func() // Optional setup before test
	}{
		{
			name:    "nil config",
			config:  nil,
			logger:  logging.DefaultLogger(),
			wantErr: true,
			errType: ErrInvalidConfig,
		},
		{
			name:    "nil logger uses default",
			config:  createMinimalConfig(t),
			logger:  nil,
			wantErr: false,
		},
		{
			name:    "valid minimal config",
			config:  createMinimalConfig(t),
			logger:  logging.DefaultLogger(),
			wantErr: false,
		},
		{
			name: "invalid config - no boot entries",
			config: &ServerConfig{
				HTTPPort:      8080,
				TFTPPort:      69,
				LocalFilesDir: "/tmp",
				EnableDHCP:    false,
				BootEntries:   []BootEntry{}, // Empty
			},
			logger:  logging.DefaultLogger(),
			wantErr: true,
			errType: ErrNoBootEntries,
		},
		{
			name: "invalid config - invalid HTTP port",
			config: &ServerConfig{
				HTTPPort:      -1,
				TFTPPort:      69,
				LocalFilesDir: "/tmp",
				EnableDHCP:    false,
				BootEntries: []BootEntry{
					{Name: "test", Description: "Test", Kernel: "http://example.com/kernel"},
				},
			},
			logger:  logging.DefaultLogger(),
			wantErr: true,
			errType: ErrInvalidPort,
		},
		{
			name: "invalid config - invalid TFTP port",
			config: &ServerConfig{
				HTTPPort:      8080,
				TFTPPort:      70000,
				LocalFilesDir: "/tmp",
				EnableDHCP:    false,
				BootEntries: []BootEntry{
					{Name: "test", Description: "Test", Kernel: "http://example.com/kernel"},
				},
			},
			logger:  logging.DefaultLogger(),
			wantErr: true,
			errType: ErrInvalidPort,
		},
		{
			name: "auto-detect external URL",
			config: &ServerConfig{
				HTTPPort:      8080,
				TFTPPort:      69,
				ExternalURL:   "", // Should be auto-detected
				LocalFilesDir: "/tmp",
				EnableDHCP:    false,
				BootEntries: []BootEntry{
					{Name: "test", Description: "Test", Kernel: "http://example.com/kernel"},
				},
			},
			logger:  logging.DefaultLogger(),
			wantErr: false,
		},
		{
			name: "auto-detect iPXE script URL",
			config: &ServerConfig{
				HTTPPort:      8080,
				TFTPPort:      69,
				ExternalURL:   "http://192.168.1.1:8080",
				IPXEScript:    "", // Should be auto-detected
				LocalFilesDir: "/tmp",
				EnableDHCP:    false,
				BootEntries: []BootEntry{
					{Name: "test", Description: "Test", Kernel: "http://example.com/kernel"},
				},
			},
			logger:  logging.DefaultLogger(),
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.setupFunc != nil {
				tt.setupFunc()
			}

			server, err := NewServer(tt.config, tt.logger)

			if tt.wantErr {
				if err == nil {
					t.Errorf("NewServer() expected error, got nil")
					return
				}
				if tt.errType != nil {
					if !isErrorType(err, tt.errType) {
						t.Errorf("NewServer() error type = %v, want %v", err, tt.errType)
					}
				}
				return
			}

			if err != nil {
				t.Errorf("NewServer() unexpected error: %v", err)
				return
			}

			if server == nil {
				t.Error("NewServer() returned nil server")
				return
			}

			// Verify server components were created
			if server.httpServer == nil {
				t.Error("HTTP server not created")
			}
			if server.tftpServer == nil {
				t.Error("TFTP server not created")
			}

			// Verify DHCP server creation based on config
			if tt.config.EnableDHCP {
				if server.dhcpServer == nil {
					t.Error("DHCP server should be created when enabled")
				}
			} else {
				if server.dhcpServer != nil {
					t.Error("DHCP server should not be created when disabled")
				}
			}

			// Verify auto-detection worked
			if tt.config.ExternalURL == "" && server.config.ExternalURL == "" {
				t.Error("External URL should be auto-detected")
			}

			if tt.config.IPXEScript == "" && server.config.IPXEScript == "" {
				t.Error("iPXE script URL should be auto-detected")
			}
		})
	}
}

func TestServer_ServerIP(t *testing.T) {
	config := createMinimalConfig(t)
	logger := logging.DefaultLogger()

	server, err := NewServer(config, logger)
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}

	serverIP := server.ServerIP()
	if serverIP == nil {
		t.Error("ServerIP() returned nil")
	}

	if serverIP.To4() == nil {
		t.Error("ServerIP() should return valid IPv4 address")
	}
}

func TestServer_IsRunning(t *testing.T) {
	config := createMinimalConfig(t)
	logger := logging.DefaultLogger()

	server, err := NewServer(config, logger)
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}

	if server.IsRunning() {
		t.Error("Server should not be running initially")
	}
}

// freeTCPPort asks the OS for an unused TCP port so tests never collide
// with daemons already listening on fixed ports.
func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freeTCPPort: %v", err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

// freeUDPPort asks the OS for an unused UDP port so tests never collide
// with daemons already listening on fixed ports.
func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("freeUDPPort: %v", err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

func TestServer_StartStop(t *testing.T) {
	// OS-allocated ports avoid conflicts with anything already
	// listening on the host (e.g. a fixed-port daemon).
	config := &ServerConfig{
		HTTPPort:      freeTCPPort(t),
		TFTPPort:      freeUDPPort(t),
		LocalFilesDir: t.TempDir(),
		EnableDHCP:    false,
		BootEntries: []BootEntry{
			{Name: "test", Description: "Test Entry", Kernel: "http://example.com/kernel"},
		},
	}

	logger := logging.DefaultLogger()

	server, err := NewServer(config, logger)
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Start server in goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.Start(ctx)
	}()

	// Poll for readiness with a bounded ticker instead of a fixed sleep.
	ready := false
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	deadline := time.After(2 * time.Second)
pollLoop:
	for {
		select {
		case <-ticker.C:
			if server.IsRunning() {
				ready = true
				break pollLoop
			}
			// A failed Start surfaces on errChan — fail fast instead of
			// polling out the deadline.
			select {
			case err := <-errChan:
				t.Fatalf("Start() failed before becoming ready: %v", err)
			default:
			}
		case <-deadline:
			break pollLoop
		}
	}

	if !ready {
		t.Error("Server should be running after Start()")
	}

	// Stop the server
	if err := server.Stop(); err != nil {
		t.Errorf("Stop() error: %v", err)
	}

	// Wait for Start to complete
	select {
	case err := <-errChan:
		if err != nil {
			t.Errorf("Start() error: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Error("Start() did not complete after Stop()")
	}

	if server.IsRunning() {
		t.Error("Server should not be running after Stop()")
	}
}

func TestServer_StopWhenNotRunning(t *testing.T) {
	config := createMinimalConfig(t)
	logger := logging.DefaultLogger()

	server, err := NewServer(config, logger)
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}

	// Stop without starting should not error
	if err := server.Stop(); err != nil {
		t.Errorf("Stop() on non-running server should not error: %v", err)
	}
}

func TestServer_StartAlreadyRunning(t *testing.T) {
	config := &ServerConfig{
		HTTPPort:      28080,
		TFTPPort:      20069,
		LocalFilesDir: t.TempDir(),
		EnableDHCP:    false,
		BootEntries: []BootEntry{
			{Name: "test", Description: "Test Entry", Kernel: "http://example.com/kernel"},
		},
	}

	logger := logging.DefaultLogger()

	server, err := NewServer(config, logger)
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}

	ctx1, cancel1 := context.WithCancel(context.Background())
	defer cancel1()

	// Start server
	go func() {
		server.Start(ctx1)
	}()

	// Server.Ready() closes once every listener has bound; the 500ms sleep
	// this replaces was guessing at it (#260).
	awaitReady(t, server)

	// Try to start again
	ctx2 := context.Background()
	err = server.Start(ctx2)
	if err == nil {
		t.Error("Start() on already running server should error")
	}

	// Cleanup
	cancel1()
	server.Stop()
}

func TestServer_WaitForReady(t *testing.T) {
	config := &ServerConfig{
		HTTPPort:      38080,
		TFTPPort:      30069,
		LocalFilesDir: t.TempDir(),
		EnableDHCP:    false,
		BootEntries: []BootEntry{
			{Name: "test", Description: "Test Entry", Kernel: "http://example.com/kernel"},
		},
	}

	logger := logging.DefaultLogger()

	server, err := NewServer(config, logger)
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server
	go func() {
		server.Start(ctx)
	}()

	// Wait for ready with timeout
	err = server.WaitForReady(15 * time.Second)
	if err != nil {
		t.Errorf("WaitForReady() error: %v", err)
	}

	// Cleanup
	cancel()
	server.Stop()
}

func TestServer_WaitForReadyTimeout(t *testing.T) {
	config := createMinimalConfig(t)
	logger := logging.DefaultLogger()

	server, err := NewServer(config, logger)
	if err != nil {
		t.Fatalf("NewServer() error: %v", err)
	}

	// Don't start the server, should timeout
	err = server.WaitForReady(500 * time.Millisecond)
	if err == nil {
		t.Error("WaitForReady() should timeout when server not started")
	}
}

func TestServer_WaitForReadyDefaultTimeout(t *testing.T) {
	config := &ServerConfig{
		HTTPPort:      48080,
		TFTPPort:      40069,
		LocalFilesDir: t.TempDir(),
		EnableDHCP:    false,
		BootEntries: []BootEntry{
			{Name: "test", Description: "Test Entry", Kernel: "http://example.com/kernel"},
		},
	}

	logger := logging.DefaultLogger()

	server, err := NewServer(config, logger)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server
	go func() {
		server.Start(ctx)
	}()

	// Wait for ready with zero timeout (uses default)
	err = server.WaitForReady(0)
	require.NoError(t, err)

	// Cleanup
	cancel()
	server.Stop()
}

func TestServer_BuildDHCPConfig(t *testing.T) {
	tests := []struct {
		name    string
		config  *ServerConfig
		wantErr bool
		errType error
	}{
		{
			name: "valid DHCP config",
			config: &ServerConfig{
				HTTPPort:       8080,
				TFTPPort:       69,
				EnableDHCP:     true,
				DHCPInterface:  "lo",
				DHCPRangeStart: "127.0.0.1",
				DHCPRangeEnd:   "127.0.0.10",
				DHCPSubnetMask: "255.255.255.0",
				DHCPGateway:    "127.0.0.1",
				DHCPDNS:        "8.8.8.8",
				DHCPLeaseTime:  1 * time.Hour,
				BootFilename:   "ipxe.efi",
				LocalFilesDir:  "/tmp",
				BootEntries: []BootEntry{
					{Name: "test", Description: "Test", Kernel: "http://example.com/kernel"},
				},
			},
			wantErr: false,
		},
		{
			name: "invalid range start",
			config: &ServerConfig{
				HTTPPort:       8080,
				TFTPPort:       69,
				EnableDHCP:     true,
				DHCPInterface:  "lo",
				DHCPRangeStart: "invalid",
				DHCPRangeEnd:   "127.0.0.10",
				DHCPSubnetMask: "255.255.255.0",
				DHCPLeaseTime:  1 * time.Hour,
				LocalFilesDir:  "/tmp",
				BootEntries: []BootEntry{
					{Name: "test", Description: "Test", Kernel: "http://example.com/kernel"},
				},
			},
			wantErr: true,
			errType: ErrInvalidIPRange,
		},
		{
			name: "invalid range end",
			config: &ServerConfig{
				HTTPPort:       8080,
				TFTPPort:       69,
				EnableDHCP:     true,
				DHCPInterface:  "lo",
				DHCPRangeStart: "127.0.0.1",
				DHCPRangeEnd:   "invalid",
				DHCPSubnetMask: "255.255.255.0",
				DHCPLeaseTime:  1 * time.Hour,
				LocalFilesDir:  "/tmp",
				BootEntries: []BootEntry{
					{Name: "test", Description: "Test", Kernel: "http://example.com/kernel"},
				},
			},
			wantErr: true,
			errType: ErrInvalidIPRange,
		},
		{
			name: "invalid subnet mask",
			config: &ServerConfig{
				HTTPPort:       8080,
				TFTPPort:       69,
				EnableDHCP:     true,
				DHCPInterface:  "lo",
				DHCPRangeStart: "127.0.0.1",
				DHCPRangeEnd:   "127.0.0.10",
				DHCPSubnetMask: "invalid",
				DHCPLeaseTime:  1 * time.Hour,
				LocalFilesDir:  "/tmp",
				BootEntries: []BootEntry{
					{Name: "test", Description: "Test", Kernel: "http://example.com/kernel"},
				},
			},
			wantErr: true,
			errType: ErrInvalidConfig,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := logging.DefaultLogger()

			server, err := NewServer(tt.config, logger)

			if tt.wantErr {
				if err == nil {
					t.Error("NewServer() expected error, got nil")
				}
				if tt.errType != nil {
					if !isErrorType(err, tt.errType) {
						t.Errorf("NewServer() error type = %v, want %v", err, tt.errType)
					}
				}
				return
			}

			if err != nil {
				t.Errorf("NewServer() unexpected error: %v", err)
				return
			}

			if server.dhcpServer == nil {
				t.Error("DHCP server should be created")
			}
		})
	}
}

func TestServer_RunWithSignals(t *testing.T) {
	config := &ServerConfig{
		HTTPPort:      58080,
		TFTPPort:      50069,
		LocalFilesDir: t.TempDir(),
		EnableDHCP:    false,
		BootEntries: []BootEntry{
			{Name: "test", Description: "Test Entry", Kernel: "http://example.com/kernel"},
		},
	}

	logger := logging.DefaultLogger()

	server, err := NewServer(config, logger)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server with signal handling in goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.RunWithSignals(ctx)
	}()

	awaitReady(t, server)

	// Verify server is running
	assert.True(t, server.IsRunning())

	// Send SIGTERM to trigger shutdown
	// Note: This sends to the current process, which should be caught by the signal handler
	process, err := os.FindProcess(os.Getpid())
	require.NoError(t, err)
	err = process.Signal(syscall.SIGTERM)
	require.NoError(t, err)

	// Wait for shutdown
	select {
	case err := <-errChan:
		// Should return without error after handling signal
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		cancel()
		t.Error("RunWithSignals did not complete after signal")
	}
}

func TestServer_RunWithSignals_ContextCancel(t *testing.T) {
	config := &ServerConfig{
		HTTPPort:      59080,
		TFTPPort:      50169,
		LocalFilesDir: t.TempDir(),
		EnableDHCP:    false,
		BootEntries: []BootEntry{
			{Name: "test", Description: "Test Entry", Kernel: "http://example.com/kernel"},
		},
	}

	logger := logging.DefaultLogger()

	server, err := NewServer(config, logger)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())

	// Start server with signal handling in goroutine
	errChan := make(chan error, 1)
	go func() {
		errChan <- server.RunWithSignals(ctx)
	}()

	awaitReady(t, server)

	// Cancel context to trigger shutdown
	cancel()

	// Wait for shutdown
	select {
	case err := <-errChan:
		// Should return without error after context cancel
		assert.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Error("RunWithSignals did not complete after context cancel")
	}
}

func TestServer_DHCPConfigWithFallbackInterface(t *testing.T) {
	// Test when DHCPInterface is empty, it should use Interface
	config := &ServerConfig{
		HTTPPort:       8080,
		TFTPPort:       69,
		Interface:      "lo",
		EnableDHCP:     true,
		DHCPInterface:  "", // Should fall back to Interface
		DHCPRangeStart: "127.0.0.1",
		DHCPRangeEnd:   "127.0.0.10",
		DHCPSubnetMask: "255.255.255.0",
		DHCPLeaseTime:  1 * time.Hour,
		DHCPServerIP:   "127.0.0.1",
		LocalFilesDir:  "/tmp",
		BootEntries: []BootEntry{
			{Name: "test", Description: "Test", Kernel: "http://example.com/kernel"},
		},
	}

	logger := logging.DefaultLogger()

	server, err := NewServer(config, logger)
	require.NoError(t, err)
	assert.NotNil(t, server.dhcpServer)
}

func TestServer_DHCPConfigWithoutOptionalFields(t *testing.T) {
	// Test DHCP config without gateway and DNS
	config := &ServerConfig{
		HTTPPort:       8080,
		TFTPPort:       69,
		Interface:      "lo",
		EnableDHCP:     true,
		DHCPInterface:  "lo",
		DHCPRangeStart: "127.0.0.1",
		DHCPRangeEnd:   "127.0.0.10",
		DHCPSubnetMask: "255.255.255.0",
		DHCPServerIP:   "127.0.0.1",
		DHCPLeaseTime:  1 * time.Hour,
		DHCPGateway:    "", // Empty - optional
		DHCPDNS:        "", // Empty - optional
		LocalFilesDir:  "/tmp",
		BootEntries: []BootEntry{
			{Name: "test", Description: "Test", Kernel: "http://example.com/kernel"},
		},
	}

	logger := logging.DefaultLogger()

	server, err := NewServer(config, logger)
	require.NoError(t, err)
	assert.NotNil(t, server.dhcpServer)
}

func TestServer_MultipleStopCalls(t *testing.T) {
	config := &ServerConfig{
		HTTPPort:      58080,
		TFTPPort:      60069,
		LocalFilesDir: t.TempDir(),
		EnableDHCP:    false,
		BootEntries: []BootEntry{
			{Name: "test", Description: "Test Entry", Kernel: "http://example.com/kernel"},
		},
	}

	logger := logging.DefaultLogger()

	server, err := NewServer(config, logger)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server
	go func() {
		server.Start(ctx)
	}()

	awaitReady(t, server)

	// Multiple Stop calls should be safe
	err1 := server.Stop()
	err2 := server.Stop()
	err3 := server.Stop()

	assert.NoError(t, err1)
	assert.NoError(t, err2)
	assert.NoError(t, err3)
}

// createMinimalConfig creates a minimal valid configuration for testing.
// Uses high ports to avoid conflicts with other services.
func createMinimalConfig(t *testing.T) *ServerConfig {
	return &ServerConfig{
		HTTPPort:      58080,
		TFTPPort:      50069,
		LocalFilesDir: t.TempDir(),
		EnableDHCP:    false,
		BootEntries: []BootEntry{
			{
				Name:        "test",
				Description: "Test Entry",
				Kernel:      "http://example.com/kernel",
			},
		},
	}
}

// isErrorType checks if the error chain contains the target error type.
func isErrorType(err, target error) bool {
	if err == nil || target == nil {
		return err == target
	}
	return errors.Is(err, target)
}

func TestServer_BuildDHCPConfig_InvalidRangeEnd(t *testing.T) {
	// Create a server with invalid range end
	config := &ServerConfig{
		HTTPPort:       18080,
		TFTPPort:       10069,
		LocalFilesDir:  t.TempDir(),
		EnableDHCP:     true,
		DHCPServerIP:   "127.0.0.1",
		DHCPInterface:  "lo",
		DHCPRangeStart: "192.168.1.100",
		DHCPRangeEnd:   "invalid",
		DHCPSubnetMask: "255.255.255.0",
		DHCPLeaseTime:  1 * time.Hour,
		BootEntries: []BootEntry{
			{Name: "test", Description: "Test", Kernel: "http://example.com/kernel"},
		},
	}

	logger := logging.DefaultLogger()
	_, err := NewServer(config, logger)

	// Should fail due to invalid range end IP
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid range end IP")
}

func TestServer_BuildDHCPConfig_InvalidSubnetMask(t *testing.T) {
	// Create a server with invalid subnet mask
	config := &ServerConfig{
		HTTPPort:       18080,
		TFTPPort:       10069,
		LocalFilesDir:  t.TempDir(),
		EnableDHCP:     true,
		DHCPServerIP:   "127.0.0.1",
		DHCPInterface:  "lo",
		DHCPRangeStart: "192.168.1.100",
		DHCPRangeEnd:   "192.168.1.200",
		DHCPSubnetMask: "invalid",
		DHCPLeaseTime:  1 * time.Hour,
		BootEntries: []BootEntry{
			{Name: "test", Description: "Test", Kernel: "http://example.com/kernel"},
		},
	}

	logger := logging.DefaultLogger()
	_, err := NewServer(config, logger)

	// Should fail due to invalid subnet mask
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "invalid subnet mask")
}

func TestServer_BuildDHCPConfig_WithOptionalFields(t *testing.T) {
	// Create a server with optional gateway and DNS
	config := &ServerConfig{
		HTTPPort:       18080,
		TFTPPort:       10069,
		LocalFilesDir:  t.TempDir(),
		EnableDHCP:     true,
		DHCPServerIP:   "127.0.0.1",
		DHCPInterface:  "lo",
		DHCPRangeStart: "192.168.1.100",
		DHCPRangeEnd:   "192.168.1.200",
		DHCPSubnetMask: "255.255.255.0",
		DHCPLeaseTime:  1 * time.Hour,
		DHCPGateway:    "192.168.1.1",
		DHCPDNS:        "8.8.8.8",
		BootEntries: []BootEntry{
			{Name: "test", Description: "Test", Kernel: "http://example.com/kernel"},
		},
	}

	logger := logging.DefaultLogger()
	server, err := NewServer(config, logger)

	require.NoError(t, err)
	assert.NotNil(t, server)
	assert.NotNil(t, server.dhcpServer)
}

func TestServer_StartErrorAlreadyRunning(t *testing.T) {
	config := &ServerConfig{
		HTTPPort:      48080,
		TFTPPort:      40069,
		LocalFilesDir: t.TempDir(),
		EnableDHCP:    false,
		BootEntries: []BootEntry{
			{Name: "test", Description: "Test Entry", Kernel: "http://example.com/kernel"},
		},
	}

	logger := logging.DefaultLogger()
	server, err := NewServer(config, logger)
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start server in background, tracking the goroutine so cleanup can join
	// it rather than sleep for it.
	stopped := make(chan struct{})
	go func() {
		defer close(stopped)
		server.Start(ctx)
	}()

	awaitReady(t, server)

	// Try to start again - should fail
	ctx2 := context.Background()
	err = server.Start(ctx2)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already running")

	// Clean up: wait for Start to actually return instead of sleeping 100ms
	// and hoping. Nothing tracked that goroutine before, so the test could
	// finish while the server was still shutting down.
	cancel()
	select {
	case <-stopped:
	case <-time.After(ipxeDeadline):
		t.Fatalf("server did not stop within %s after context cancellation", ipxeDeadline)
	}
}

func TestServer_Config(t *testing.T) {
	config := createMinimalConfig(t)
	logger := logging.DefaultLogger()

	server, err := NewServer(config, logger)
	require.NoError(t, err)

	// Verify config is accessible
	assert.Equal(t, config.HTTPPort, server.config.HTTPPort)
	assert.Equal(t, config.TFTPPort, server.config.TFTPPort)
}
