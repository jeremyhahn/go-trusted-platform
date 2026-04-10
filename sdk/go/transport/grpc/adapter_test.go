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

package grpc

import (
	"context"
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/platform"
)

func TestConnect_NilOptions(t *testing.T) {
	ctx := context.Background()

	_, err := Connect(ctx, nil)
	if !errors.Is(err, platform.ErrNilOptions) {
		t.Errorf("Connect(nil) error = %v, want %v", err, platform.ErrNilOptions)
	}
}

func TestConnect_EmptyAddress(t *testing.T) {
	ctx := context.Background()
	opts := platform.NewOptions()
	opts.GRPCAddr = ""

	_, err := Connect(ctx, opts)
	if !errors.Is(err, platform.ErrEmptyAddress) {
		t.Errorf("Connect() error = %v, want %v", err, platform.ErrEmptyAddress)
	}
}

func TestConnect_SuccessfulDial(t *testing.T) {
	// gRPC dial is non-blocking by default - it doesn't actually connect until first RPC.
	// This test verifies the adapter is created correctly for a valid address format.
	ctx := context.Background()

	opts := platform.NewOptions(
		platform.WithGRPCAddr("localhost:10443"),
	)

	adapter, err := Connect(ctx, opts)
	if err != nil {
		t.Fatalf("Connect() returned error: %v", err)
	}
	defer adapter.Close()

	if !adapter.IsConnected() {
		t.Error("adapter should report connected after successful dial")
	}

	if adapter.Target() != "localhost:10443" {
		t.Errorf("Target() = %q, want %q", adapter.Target(), "localhost:10443")
	}

	if adapter.Connection() == nil {
		t.Error("Connection() should not return nil after successful dial")
	}
}

func TestAdapter_Target(t *testing.T) {
	a := &Adapter{
		address: "localhost:10443",
	}

	if got := a.Target(); got != "localhost:10443" {
		t.Errorf("Target() = %q, want %q", got, "localhost:10443")
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
	// Create a real adapter via Connect
	ctx := context.Background()
	opts := platform.NewOptions(
		platform.WithGRPCAddr("localhost:10443"),
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
	grpcAdapter := adapter.(*Adapter)
	if grpcAdapter.conn != nil {
		t.Error("conn should be nil after Close()")
	}

	// Close again should be safe
	err = adapter.Close()
	if err != nil {
		t.Errorf("second Close() returned error: %v", err)
	}
}

func TestConnect_UsesDefaults(t *testing.T) {
	ctx := context.Background()
	opts := platform.NewOptions(
		platform.WithGRPCAddr("localhost:10443"),
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

func TestConnect_WithCustomTLS(t *testing.T) {
	// This test exercises the TLS config code path
	// gRPC dial is non-blocking, so this will succeed even without a real server
	ctx := context.Background()

	opts := platform.NewOptions(
		platform.WithGRPCAddr("localhost:10443"),
		// Not setting TLSConfig or Insecure exercises the default TLS path
	)

	adapter, err := Connect(ctx, opts)
	if err != nil {
		t.Fatalf("Connect() returned error: %v", err)
	}
	defer adapter.Close()

	if !adapter.IsConnected() {
		t.Error("adapter should report connected")
	}
}

func TestAdapter_Connection_ReturnsInterface(t *testing.T) {
	// Create a real adapter to test Connection() returns valid interface
	ctx := context.Background()
	opts := platform.NewOptions(
		platform.WithGRPCAddr("localhost:10443"),
	)

	adapter, err := Connect(ctx, opts)
	if err != nil {
		t.Fatalf("Connect() returned error: %v", err)
	}
	defer adapter.Close()

	conn := adapter.Connection()
	if conn == nil {
		t.Error("Connection() should not return nil")
	}
}
