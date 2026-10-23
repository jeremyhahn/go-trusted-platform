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

package unix

import (
	"context"
	"crypto/tls"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
)

func TestConnect_NilOptions(t *testing.T) {
	ctx := context.Background()

	_, err := Connect(ctx, nil)
	if !errors.Is(err, platform.ErrNilOptions) {
		t.Errorf("Connect(nil) error = %v, want %v", err, platform.ErrNilOptions)
	}
}

func TestConnect_RefusesCredentialOptions(t *testing.T) {
	// A listening socket, so the refusal is not masked by a missing one.
	socketPath := filepath.Join(t.TempDir(), "test.sock")
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to create Unix socket: %v", err)
	}
	defer listener.Close()

	tests := []struct {
		name   string
		option platform.Option
	}{
		{"BearerToken", platform.WithBearerToken("secret")},
		{"TLSConfig", platform.WithTLSConfig(&tls.Config{})},
		{"TLSServerName", platform.WithTLSServerName("example.com")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			adapter, err := Connect(context.Background(), platform.NewOptions(
				platform.WithUnixSocket(socketPath),
				tt.option,
			))
			if adapter != nil {
				t.Error("Connect() returned an adapter, want nil")
			}
			var unsupported platform.ErrUnsupportedOption
			if !errors.As(err, &unsupported) {
				t.Fatalf("Connect() error = %v, want ErrUnsupportedOption", err)
			}
			if unsupported.Protocol != platform.ProtocolUnix || unsupported.Option != tt.name {
				t.Errorf("ErrUnsupportedOption = %+v, want protocol Unix and option %s", unsupported, tt.name)
			}
		})
	}
}

func TestConnect_SocketNotExists(t *testing.T) {
	ctx := context.Background()
	opts := platform.NewOptions(
		platform.WithUnixSocket("/nonexistent/path/socket.sock"),
	)

	_, err := Connect(ctx, opts)
	if err == nil {
		t.Error("Connect() should return error when socket does not exist")
	}

	var connErr platform.ErrConnectionFailed
	if !errors.As(err, &connErr) {
		t.Errorf("expected ErrConnectionFailed, got %T: %v", err, err)
	}
	if connErr.Protocol != platform.ProtocolUnix {
		t.Errorf("Protocol = %v, want %v", connErr.Protocol, platform.ProtocolUnix)
	}
}

func TestConnect_UsesDefaultSocketPath(t *testing.T) {
	ctx := context.Background()
	opts := platform.NewOptions()
	opts.UnixSocket = "" // Empty should use default

	_, err := Connect(ctx, opts)
	if err == nil {
		t.Error("expected error (socket likely doesn't exist)")
	}

	var connErr platform.ErrConnectionFailed
	if !errors.As(err, &connErr) {
		t.Errorf("expected ErrConnectionFailed, got %T: %v", err, err)
	}
	// Should have used default path
	if connErr.Target != platform.DefaultUnixSocket {
		t.Errorf("Target = %q, want %q", connErr.Target, platform.DefaultUnixSocket)
	}
}

func TestConnect_WithRealSocket(t *testing.T) {
	// Create a temporary Unix socket that actually listens
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	// Create a real Unix socket listener
	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to create Unix socket: %v", err)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	ctx := context.Background()
	opts := platform.NewOptions(
		platform.WithUnixSocket(socketPath),
	)

	adapter, err := Connect(ctx, opts)
	if err != nil {
		t.Fatalf("Connect() returned error: %v", err)
	}
	defer adapter.Close()

	if !adapter.IsConnected() {
		t.Error("adapter should report connected")
	}

	if adapter.Target() != socketPath {
		t.Errorf("Target() = %q, want %q", adapter.Target(), socketPath)
	}

	if adapter.Connection() == nil {
		t.Error("Connection() should not return nil")
	}
}

func TestAdapter_Target(t *testing.T) {
	a := &Adapter{
		socketPath: "/run/test.sock",
	}

	if got := a.Target(); got != "/run/test.sock" {
		t.Errorf("Target() = %q, want %q", got, "/run/test.sock")
	}
}

func TestAdapter_IsConnected(t *testing.T) {
	a := &Adapter{}

	// Initially not connected
	if a.IsConnected() {
		t.Error("IsConnected() should return false initially")
	}

	// After storing true
	a.connected.Store(true)
	if !a.IsConnected() {
		t.Error("IsConnected() should return true after storing true")
	}

	// After storing false
	a.connected.Store(false)
	if a.IsConnected() {
		t.Error("IsConnected() should return false after storing false")
	}
}

func TestAdapter_Close_NotConnected(t *testing.T) {
	a := &Adapter{}
	a.connected.Store(false)

	err := a.Close()
	if err != nil {
		t.Errorf("Close() on disconnected adapter should not return error, got %v", err)
	}
}

func TestAdapter_Close_NilConn(t *testing.T) {
	a := &Adapter{
		conn: nil,
	}
	a.connected.Store(true)

	err := a.Close()
	if err != nil {
		t.Errorf("Close() with nil conn should not return error, got %v", err)
	}
	if a.IsConnected() {
		t.Error("IsConnected() should return false after Close()")
	}
}

func TestAdapter_Close_WithConnection(t *testing.T) {
	// Create a temporary Unix socket
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to create Unix socket: %v", err)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	ctx := context.Background()
	opts := platform.NewOptions(
		platform.WithUnixSocket(socketPath),
	)

	adapter, err := Connect(ctx, opts)
	if err != nil {
		t.Fatalf("Connect() returned error: %v", err)
	}

	// Close should succeed
	err = adapter.Close()
	if err != nil {
		t.Errorf("Close() returned error: %v", err)
	}

	// Should be disconnected after close
	if adapter.IsConnected() {
		t.Error("IsConnected() should return false after Close()")
	}

	// Connection should be nil after close
	unixAdapter := adapter.(*Adapter)
	if unixAdapter.conn != nil {
		t.Error("conn should be nil after Close()")
	}

	// Close again should be safe
	err = adapter.Close()
	if err != nil {
		t.Errorf("second Close() returned error: %v", err)
	}
}

func TestConnect_FileExistsButNotSocket(t *testing.T) {
	// Create a regular file (not a socket)
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "notasocket")

	f, err := os.Create(filePath)
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	f.Close()

	ctx := context.Background()
	opts := platform.NewOptions(
		platform.WithUnixSocket(filePath),
	)

	// gRPC dial is non-blocking, but it will fail when we try to connect to a regular file
	// The dial itself may succeed, but subsequent operations would fail
	// For this test, we just verify no panic and the adapter is created
	adapter, err := Connect(ctx, opts)
	if err != nil {
		// This is acceptable - the dial may fail for a non-socket file
		var connErr platform.ErrConnectionFailed
		if !errors.As(err, &connErr) {
			t.Errorf("expected ErrConnectionFailed, got %T: %v", err, err)
		}
		return
	}

	// If we get here, dial succeeded (non-blocking), but the connection
	// won't actually work - this is okay for this test
	if err := adapter.Close(); err != nil {
		t.Errorf("Close() returned error: %v", err)
	}
}

func TestConnect_UsesDefaults(t *testing.T) {
	// Create a temporary Unix socket
	tmpDir := t.TempDir()
	socketPath := filepath.Join(tmpDir, "test.sock")

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to create Unix socket: %v", err)
	}
	defer func() {
		if err := listener.Close(); err != nil {
			t.Logf("cleanup: %v", err)
		}
	}()

	ctx := context.Background()
	opts := platform.NewOptions(
		platform.WithUnixSocket(socketPath),
	)
	opts.Timeout = 0        // Zero should use default
	opts.MaxMessageSize = 0 // Zero should use default

	adapter, err := Connect(ctx, opts)
	if err != nil {
		t.Fatalf("Connect() returned error: %v", err)
	}
	defer adapter.Close()

	if !adapter.IsConnected() {
		t.Error("adapter should report connected")
	}
}
