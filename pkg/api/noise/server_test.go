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

//go:build !fips

// The tests in this file construct a server, which needs the Curve25519
// static key a fips build cannot generate; server_fips_test.go asserts that
// refusal instead.

package noise

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

func TestNewServer_ValidConfig(t *testing.T) {
	srv, err := NewServer(testConfig(), testBundlerWithData(), testLogger())
	if err != nil {
		t.Fatalf("NewServer returned unexpected error: %v", err)
	}
	if srv == nil {
		t.Fatal("NewServer returned nil server")
	}
	if srv.IsRunning() {
		t.Error("newly created server should not be running")
	}
}

func TestNewServer_NilConfig(t *testing.T) {
	_, err := NewServer(nil, testBundlerWithData(), testLogger())
	if err == nil {
		t.Fatal("NewServer with nil config should return error")
	}
	var nilCfgErr *ErrNilConfig
	if !errors.As(err, &nilCfgErr) {
		t.Errorf("expected ErrNilConfig, got %T: %v", err, err)
	}
}

func TestNewServer_NilBundleProvider(t *testing.T) {
	_, err := NewServer(testConfig(), nil, testLogger())
	if err == nil {
		t.Fatal("NewServer with nil bundler should return error")
	}
	var nilBundlerErr *ErrNilBundleProvider
	if !errors.As(err, &nilBundlerErr) {
		t.Errorf("expected ErrNilBundleProvider, got %T: %v", err, err)
	}
}

func TestNewServer_NilLogger(t *testing.T) {
	_, err := NewServer(testConfig(), testBundlerWithData(), nil)
	if err == nil {
		t.Fatal("NewServer with nil logger should return error")
	}
	var nilLoggerErr *ErrNilLogger
	if !errors.As(err, &nilLoggerErr) {
		t.Errorf("expected ErrNilLogger, got %T: %v", err, err)
	}
}

func TestServer_StartStop(t *testing.T) {
	srv, err := NewServer(testConfig(), testBundlerWithData(), testLogger())
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	ctx := context.Background()

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Stop(stopCtx)
	})

	if !srv.IsRunning() {
		t.Error("server should be running after Start")
	}

	addr := srv.Addr()
	if addr == nil {
		t.Fatal("Addr returned nil on started server")
	}
	t.Logf("server listening on %s", addr.String())

	stopCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := srv.Stop(stopCtx); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	if srv.IsRunning() {
		t.Error("server should not be running after Stop")
	}
}

func TestServer_DoubleStart(t *testing.T) {
	srv, err := NewServer(testConfig(), testBundlerWithData(), testLogger())
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	ctx := context.Background()

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("first Start failed: %v", err)
	}
	t.Cleanup(func() {
		stopCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		srv.Stop(stopCtx)
	})

	err = srv.Start(ctx)
	if err == nil {
		t.Fatal("second Start should return error")
	}
	var alreadyStarted *ErrServerAlreadyStarted
	if !errors.As(err, &alreadyStarted) {
		t.Errorf("expected ErrServerAlreadyStarted, got %T: %v", err, err)
	}
}

func TestServer_StopWithoutStart(t *testing.T) {
	srv, err := NewServer(testConfig(), testBundlerWithData(), testLogger())
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	ctx := context.Background()
	err = srv.Stop(ctx)
	if err == nil {
		t.Fatal("Stop without Start should return error")
	}
	var notStarted *ErrServerNotStarted
	if !errors.As(err, &notStarted) {
		t.Errorf("expected ErrServerNotStarted, got %T: %v", err, err)
	}
}

func TestServer_PublicKey(t *testing.T) {
	srv, err := NewServer(testConfig(), testBundlerWithData(), testLogger())
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	pubKey := srv.PublicKey()
	if len(pubKey) == 0 {
		t.Fatal("PublicKey returned empty key")
	}
	if len(pubKey) != 32 {
		t.Errorf("PublicKey expected 32 bytes, got %d", len(pubKey))
	}
}

func TestServer_PublicKeyUniqueness(t *testing.T) {
	srv1, err := NewServer(testConfig(), testBundlerWithData(), testLogger())
	if err != nil {
		t.Fatalf("NewServer (1) failed: %v", err)
	}
	srv2, err := NewServer(testConfig(), testBundlerWithData(), testLogger())
	if err != nil {
		t.Fatalf("NewServer (2) failed: %v", err)
	}

	key1 := srv1.PublicKey()
	key2 := srv2.PublicKey()

	if string(key1) == string(key2) {
		t.Error("two servers should have different ephemeral keys")
	}
}

func TestServer_IsRunning_DefaultFalse(t *testing.T) {
	srv, err := NewServer(testConfig(), testBundlerWithData(), testLogger())
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	if srv.IsRunning() {
		t.Error("IsRunning should return false before Start")
	}
}

func TestServer_Addr_BeforeStart(t *testing.T) {
	srv, err := NewServer(testConfig(), testBundlerWithData(), testLogger())
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}
	// Before Start, the inner server has no listener, so Addr returns nil.
	addr := srv.Addr()
	if addr != nil {
		t.Errorf("Addr before Start should return nil, got %v", addr)
	}
}

func TestServer_StartFailed_PortInUse(t *testing.T) {
	// Bind a port first, then try to start the server on the same port.
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create listener: %v", err)
	}
	t.Cleanup(func() { listener.Close() })

	boundAddr := listener.Addr().String()

	cfg := testConfig()
	cfg.ListenAddr = boundAddr

	srv, err := NewServer(cfg, testBundlerWithData(), testLogger())
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	ctx := context.Background()
	err = srv.Start(ctx)
	if err == nil {
		t.Fatal("Start on occupied port should return error")
	}

	var startFailed *ErrServerStartFailed
	if !errors.As(err, &startFailed) {
		t.Errorf("expected ErrServerStartFailed, got %T: %v", err, err)
	}

	if srv.IsRunning() {
		t.Error("server should not be running after failed Start")
	}
}

func TestServer_NewServer_ExceedsMaxConnections(t *testing.T) {
	cfg := testConfig()
	cfg.MaxConnections = 100000

	_, err := NewServer(cfg, testBundlerWithData(), testLogger())
	if err == nil {
		t.Fatal("NewServer with excessive MaxConnections should return error")
	}

	var startFailed *ErrServerStartFailed
	if !errors.As(err, &startFailed) {
		t.Errorf("expected ErrServerStartFailed, got %T: %v", err, err)
	}
}

func TestServer_Addr_AfterStop(t *testing.T) {
	srv, err := NewServer(testConfig(), testBundlerWithData(), testLogger())
	if err != nil {
		t.Fatalf("NewServer failed: %v", err)
	}

	ctx := context.Background()

	if err := srv.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}

	// Capture addr while running.
	addr := srv.Addr()
	if addr == nil {
		t.Fatal("Addr returned nil while running")
	}

	stopCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	if err := srv.Stop(stopCtx); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}

	// After stop, the listener is closed. Addr may return the old address
	// or nil depending on the inner server implementation. Either is acceptable.
	t.Logf("Addr after stop: %v", srv.Addr())
}
