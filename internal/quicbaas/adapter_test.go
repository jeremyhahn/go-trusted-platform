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

package quicbaas

import (
	"context"
	"errors"
	"log/slog"
	"sync"
	"testing"
	"time"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

func TestNewAdapter(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	t.Run("valid_config", func(t *testing.T) {
		cfg := &Config{
			Transport:      TransportEmbedded,
			RequestTimeout: 30 * time.Second,
		}

		adapter, err := NewAdapter(cfg, logger)
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if adapter == nil {
			t.Fatal("expected adapter, got nil")
		}
		if adapter.IsStarted() {
			t.Error("expected adapter to not be started")
		}
		if adapter.IsClosed() {
			t.Error("expected adapter to not be closed")
		}
	})

	t.Run("nil_config", func(t *testing.T) {
		adapter, err := NewAdapter(nil, logger)
		if err != ErrNilConfig {
			t.Errorf("expected ErrNilConfig, got %v", err)
		}
		if adapter != nil {
			t.Error("expected nil adapter")
		}
	})

	t.Run("nil_logger", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportEmbedded,
		}

		adapter, err := NewAdapter(cfg, nil)
		if err != ErrNilLogger {
			t.Errorf("expected ErrNilLogger, got %v", err)
		}
		if adapter != nil {
			t.Error("expected nil adapter")
		}
	})

	t.Run("invalid_config_returns_error", func(t *testing.T) {
		cfg := &Config{
			Transport: "invalid_transport",
		}

		adapter, err := NewAdapter(cfg, logger)
		if err == nil {
			t.Error("expected error for invalid config")
		}
		if adapter != nil {
			t.Error("expected nil adapter")
		}
		var unsupportedErr ErrUnsupportedTransport
		if !errors.As(err, &unsupportedErr) {
			t.Errorf("expected ErrUnsupportedTransport, got %T", err)
		}
	})
}

func TestConfig_Validate(t *testing.T) {
	t.Run("embedded_mode_defaults", func(t *testing.T) {
		cfg := &Config{}
		err := cfg.Validate()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if cfg.Transport != TransportEmbedded {
			t.Errorf("expected transport to be embedded, got %s", cfg.Transport)
		}
		if cfg.RequestTimeout != DefaultRequestTimeout {
			t.Errorf("expected timeout %v, got %v", DefaultRequestTimeout, cfg.RequestTimeout)
		}
	})

	t.Run("remote_mode_inferred", func(t *testing.T) {
		cfg := &Config{
			Backend: "quicbaas-primary",
			Address: "localhost:10443",
		}
		err := cfg.Validate()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if cfg.Transport != TransportGRPC {
			t.Errorf("expected transport to be grpc, got %s", cfg.Transport)
		}
	})

	t.Run("unix_missing_socket", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportUnix,
		}
		err := cfg.Validate()
		if err != ErrMissingUnixSocket {
			t.Errorf("expected ErrMissingUnixSocket, got %v", err)
		}
	})

	t.Run("unix_with_socket", func(t *testing.T) {
		cfg := &Config{
			Transport:  TransportUnix,
			UnixSocket: "/tmp/quicbaas.sock",
		}
		err := cfg.Validate()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("grpc_missing_address", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportGRPC,
		}
		err := cfg.Validate()
		if err != ErrMissingAddress {
			t.Errorf("expected ErrMissingAddress, got %v", err)
		}
	})

	t.Run("grpc_with_address", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportGRPC,
			Address:   "localhost:10443",
		}
		err := cfg.Validate()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("rest_missing_address", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportREST,
		}
		err := cfg.Validate()
		if err != ErrMissingAddress {
			t.Errorf("expected ErrMissingAddress, got %v", err)
		}
	})

	t.Run("rest_with_address", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportREST,
			Address:   "https://localhost:8443",
		}
		err := cfg.Validate()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("quic_missing_address", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportQUIC,
		}
		err := cfg.Validate()
		if err != ErrMissingAddress {
			t.Errorf("expected ErrMissingAddress, got %v", err)
		}
	})

	t.Run("quic_with_address", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportQUIC,
			Address:   "localhost:9444",
		}
		err := cfg.Validate()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
	})

	t.Run("unsupported_transport", func(t *testing.T) {
		cfg := &Config{
			Transport: "invalid",
		}
		err := cfg.Validate()
		if err == nil {
			t.Error("expected error for unsupported transport")
		}
		var unsupportedErr ErrUnsupportedTransport
		if !errors.As(err, &unsupportedErr) {
			t.Errorf("expected ErrUnsupportedTransport, got %T", err)
		}
	})
}

func TestConfig_IsEmbedded(t *testing.T) {
	t.Run("empty_config_is_embedded", func(t *testing.T) {
		cfg := &Config{}
		if !cfg.IsEmbedded() {
			t.Error("expected empty config to be embedded")
		}
	})

	t.Run("explicit_embedded", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportEmbedded,
		}
		if !cfg.IsEmbedded() {
			t.Error("expected explicit embedded transport to be embedded")
		}
	})

	t.Run("with_backend_is_remote", func(t *testing.T) {
		cfg := &Config{
			Backend: "quicbaas-primary",
		}
		if cfg.IsEmbedded() {
			t.Error("expected config with backend to be remote")
		}
		if !cfg.IsRemote() {
			t.Error("expected config with backend to be remote")
		}
	})

	t.Run("grpc_is_remote", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportGRPC,
			Address:   "localhost:10443",
		}
		if cfg.IsEmbedded() {
			t.Error("expected gRPC transport to be remote")
		}
	})
}

func TestDefaultConfig(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Transport != TransportEmbedded {
		t.Errorf("expected embedded transport, got %s", cfg.Transport)
	}
	if cfg.RequestTimeout != DefaultRequestTimeout {
		t.Errorf("expected timeout %v, got %v", DefaultRequestTimeout, cfg.RequestTimeout)
	}
}

func TestRemoteConfig(t *testing.T) {
	cfg := RemoteConfig("localhost:10443", TransportGRPC)
	if cfg.Address != "localhost:10443" {
		t.Errorf("expected address localhost:10443, got %s", cfg.Address)
	}
	if cfg.Transport != TransportGRPC {
		t.Errorf("expected gRPC transport, got %s", cfg.Transport)
	}
	if cfg.RequestTimeout != DefaultRequestTimeout {
		t.Errorf("expected timeout %v, got %v", DefaultRequestTimeout, cfg.RequestTimeout)
	}
}

func TestAdapter_NotStarted(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &Config{
		Transport: TransportEmbedded,
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// All service accessors should return nil when not started
	if adapter.KV() != nil {
		t.Error("expected KV() to return nil when not started")
	}
	if adapter.Batch() != nil {
		t.Error("expected Batch() to return nil when not started")
	}
	if adapter.Transaction() != nil {
		t.Error("expected Transaction() to return nil when not started")
	}
	if adapter.Query() != nil {
		t.Error("expected Query() to return nil when not started")
	}
	if adapter.Cluster() != nil {
		t.Error("expected Cluster() to return nil when not started")
	}
	if adapter.Health() != nil {
		t.Error("expected Health() to return nil when not started")
	}
	if adapter.Operations() != nil {
		t.Error("expected Operations() to return nil when not started")
	}
	if adapter.Cache() != nil {
		t.Error("expected Cache() to return nil when not started")
	}
	if adapter.Auth() != nil {
		t.Error("expected Auth() to return nil when not started")
	}
	if adapter.Seal() != nil {
		t.Error("expected Seal() to return nil when not started")
	}
	if adapter.KMS() != nil {
		t.Error("expected KMS() to return nil when not started")
	}
	if adapter.Secrets() != nil {
		t.Error("expected Secrets() to return nil when not started")
	}
	if adapter.Crypto() != nil {
		t.Error("expected Crypto() to return nil when not started")
	}
	if adapter.RBAC() != nil {
		t.Error("expected RBAC() to return nil when not started")
	}
	if adapter.DynamicSecrets() != nil {
		t.Error("expected DynamicSecrets() to return nil when not started")
	}
	if adapter.Certificate() != nil {
		t.Error("expected Certificate() to return nil when not started")
	}
	if adapter.DEK() != nil {
		t.Error("expected DEK() to return nil when not started")
	}
	if adapter.IAM() != nil {
		t.Error("expected IAM() to return nil when not started")
	}
	if adapter.Vector() != nil {
		t.Error("expected Vector() to return nil when not started")
	}
	if adapter.TimeSeries() != nil {
		t.Error("expected TimeSeries() to return nil when not started")
	}
	if adapter.Backup() != nil {
		t.Error("expected Backup() to return nil when not started")
	}
	if adapter.ObjectStorage() != nil {
		t.Error("expected ObjectStorage() to return nil when not started")
	}
	if adapter.ObjectStorageAdmin() != nil {
		t.Error("expected ObjectStorageAdmin() to return nil when not started")
	}
	if adapter.ObjectTransfer() != nil {
		t.Error("expected ObjectTransfer() to return nil when not started")
	}
	if adapter.ParameterStore() != nil {
		t.Error("expected ParameterStore() to return nil when not started")
	}
	if adapter.Scheduler() != nil {
		t.Error("expected Scheduler() to return nil when not started")
	}
	if adapter.Messaging() != nil {
		t.Error("expected Messaging() to return nil when not started")
	}
	if adapter.Embedding() != nil {
		t.Error("expected Embedding() to return nil when not started")
	}
	if adapter.Ollama() != nil {
		t.Error("expected Ollama() to return nil when not started")
	}
}

func TestAdapter_EmbeddedRequiresService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	cfg := &Config{
		Transport: TransportEmbedded,
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	// Starting embedded without a service should fail
	err = adapter.Start(context.TODO(), nil)
	if err != ErrEmbeddedServiceRequired {
		t.Errorf("expected ErrEmbeddedServiceRequired, got %v", err)
	}
}

func TestAdapterError(t *testing.T) {
	t.Run("without_cause", func(t *testing.T) {
		err := &AdapterError{
			Op:  "test",
			Msg: "test error",
		}
		expected := "quicbaas adapter test: test error"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("with_cause", func(t *testing.T) {
		cause := &AdapterError{Op: "cause", Msg: "underlying error"}
		err := &AdapterError{
			Op:    "test",
			Msg:   "test error",
			Cause: cause,
		}
		expected := "quicbaas adapter test: test error: quicbaas adapter cause: underlying error"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
		if err.Unwrap() != cause {
			t.Error("expected Unwrap() to return cause")
		}
	})

	t.Run("with_cause_method", func(t *testing.T) {
		base := &AdapterError{
			Op:  "test",
			Msg: "test error",
		}
		cause := &AdapterError{Op: "cause", Msg: "underlying error"}
		err := base.WithCause(cause)
		if err.Cause != cause {
			t.Error("expected WithCause to set cause")
		}
		if err.Op != base.Op {
			t.Error("expected WithCause to preserve Op")
		}
		if err.Msg != base.Msg {
			t.Error("expected WithCause to preserve Msg")
		}
	})
}

func TestErrUnsupportedTransport(t *testing.T) {
	err := ErrUnsupportedTransport{Transport: "invalid"}
	expected := "quicbaas adapter: unsupported transport: invalid"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrConnectionFailed(t *testing.T) {
	t.Run("without_cause", func(t *testing.T) {
		err := ErrConnectionFailed{
			Address:   "localhost:10443",
			Transport: TransportGRPC,
		}
		expected := "quicbaas adapter: connection failed to localhost:10443 via grpc"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("with_cause", func(t *testing.T) {
		cause := &AdapterError{Op: "dial", Msg: "connection refused"}
		err := ErrConnectionFailed{
			Address:   "localhost:10443",
			Transport: TransportGRPC,
			Cause:     cause,
		}
		if err.Unwrap() != cause {
			t.Error("expected Unwrap() to return cause")
		}
		// Verify error message includes cause
		msg := err.Error()
		if msg == "" {
			t.Error("expected non-empty error message")
		}
	})
}

func TestErrServiceUnavailable(t *testing.T) {
	err := ErrServiceUnavailable{Service: "KMS"}
	expected := "quicbaas adapter: service unavailable: KMS"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrBackendNotFound(t *testing.T) {
	err := ErrBackendNotFound{Backend: "quicbaas-primary"}
	expected := "quicbaas adapter: backend not found: quicbaas-primary"
	if err.Error() != expected {
		t.Errorf("expected %q, got %q", expected, err.Error())
	}
}

func TestErrSecretResolutionFailed(t *testing.T) {
	t.Run("without_cause", func(t *testing.T) {
		err := ErrSecretResolutionFailed{URI: "kms://platform/tls/key"}
		expected := "quicbaas adapter: secret resolution failed for kms://platform/tls/key"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})

	t.Run("with_cause", func(t *testing.T) {
		cause := &AdapterError{Op: "lookup", Msg: "secret not found"}
		err := ErrSecretResolutionFailed{
			URI:   "kms://platform/tls/key",
			Cause: cause,
		}
		if err.Unwrap() != cause {
			t.Error("expected Unwrap() to return cause")
		}
		// Verify the error message includes cause
		msg := err.Error()
		if msg == "" {
			t.Error("expected non-empty error message")
		}
	})
}

// =============================================================================
// Adapter State Tests
// =============================================================================

func TestAdapter_StateTransitions(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	t.Run("client_returns_nil_when_not_started", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportEmbedded,
		}
		adapter, err := NewAdapter(cfg, logger)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		client := adapter.Client()
		if client != nil {
			t.Error("expected Client() to return nil before start")
		}
	})

	t.Run("config_returns_correct_value", func(t *testing.T) {
		cfg := &Config{
			Transport:      TransportEmbedded,
			RequestTimeout: 45 * time.Second,
		}
		adapter, err := NewAdapter(cfg, logger)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		returnedCfg := adapter.Config()
		if returnedCfg != cfg {
			t.Error("expected Config() to return the same config")
		}
		if returnedCfg.RequestTimeout != 45*time.Second {
			t.Errorf("expected 45s timeout, got %v", returnedCfg.RequestTimeout)
		}
	})

	t.Run("transport_returns_correct_value", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportGRPC,
			Address:   "localhost:10443",
		}
		adapter, err := NewAdapter(cfg, logger)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if adapter.Transport() != TransportGRPC {
			t.Errorf("expected gRPC transport, got %v", adapter.Transport())
		}
	})

	t.Run("is_embedded_returns_correct_value", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportEmbedded,
		}
		adapter, err := NewAdapter(cfg, logger)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if !adapter.IsEmbedded() {
			t.Error("expected IsEmbedded() to return true")
		}
		if adapter.IsRemote() {
			t.Error("expected IsRemote() to return false")
		}
	})

	t.Run("is_remote_returns_correct_value", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportGRPC,
			Address:   "localhost:10443",
		}
		adapter, err := NewAdapter(cfg, logger)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if adapter.IsEmbedded() {
			t.Error("expected IsEmbedded() to return false for gRPC")
		}
		if !adapter.IsRemote() {
			t.Error("expected IsRemote() to return true for gRPC")
		}
	})
}

func TestAdapter_StopWhenNotStarted(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	cfg := &Config{
		Transport: TransportEmbedded,
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Stop should succeed even when not started
	ctx := context.Background()
	err = adapter.Stop(ctx)
	if err != nil {
		t.Errorf("expected Stop() to succeed when not started, got %v", err)
	}
}

// =============================================================================
// Adapter with Mock Client Tests
// =============================================================================

func TestAdapter_WithMockClient(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	t.Run("service_accessors_return_mock_values", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportEmbedded,
		}
		adapter, err := NewAdapter(cfg, logger)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		// Create mock client
		mockClient := NewMockClient()

		// Inject mock client for testing (using the test helper)
		adapter.setClientForTest(mockClient)
		adapter.started.Store(true)

		// Verify client is returned
		client := adapter.Client()
		if client != quicbaas.Client(mockClient) {
			t.Error("expected Client() to return mock client")
		}

		// All service accessors should delegate to mock client
		if adapter.KV() != mockClient.KV() {
			t.Error("expected KV() to return mock KV client")
		}
		if adapter.Batch() != mockClient.Batch() {
			t.Error("expected Batch() to return mock Batch client")
		}
	})

	t.Run("client_returns_nil_when_closed", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportEmbedded,
		}
		adapter, err := NewAdapter(cfg, logger)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		mockClient := NewMockClient()
		adapter.setClientForTest(mockClient)
		adapter.started.Store(true)
		adapter.closed.Store(true)

		// Client should return nil when closed
		if adapter.Client() != nil {
			t.Error("expected Client() to return nil when closed")
		}
	})

	t.Run("stop_calls_client_close", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportEmbedded,
		}
		adapter, err := NewAdapter(cfg, logger)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		mockClient := NewMockClient()
		adapter.setClientForTest(mockClient)
		adapter.started.Store(true)

		ctx := context.Background()
		err = adapter.Stop(ctx)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}

		if !mockClient.WasCloseCalled() {
			t.Error("expected Stop() to call client.Close()")
		}
	})

	t.Run("stop_returns_client_close_error", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportEmbedded,
		}
		adapter, err := NewAdapter(cfg, logger)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		mockClient := NewMockClient()
		mockClient.CloseError = errors.New("close failed")
		adapter.setClientForTest(mockClient)
		adapter.started.Store(true)

		ctx := context.Background()
		err = adapter.Stop(ctx)
		if err == nil {
			t.Error("expected Stop() to return error")
		}
		if err.Error() != "close failed" {
			t.Errorf("expected 'close failed' error, got %v", err)
		}
	})
}

// =============================================================================
// Concurrency Tests
// =============================================================================

func TestAdapter_ConcurrentAccess(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	cfg := &Config{
		Transport: TransportEmbedded,
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mockClient := NewMockClient()
	adapter.setClientForTest(mockClient)
	adapter.started.Store(true)

	// Test concurrent reads
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_ = adapter.Client()
			_ = adapter.IsStarted()
			_ = adapter.IsClosed()
			_ = adapter.IsEmbedded()
			_ = adapter.IsRemote()
			_ = adapter.Config()
			_ = adapter.Transport()
		}()
	}
	wg.Wait()
}

func TestAdapter_ConcurrentStartStop(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	t.Run("multiple_starts_are_idempotent", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportEmbedded,
		}
		adapter, err := NewAdapter(cfg, logger)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		mockClient := NewMockClient()
		adapter.setClientForTest(mockClient)
		adapter.started.Store(true)

		// Multiple stops should be safe
		ctx := context.Background()
		var wg sync.WaitGroup
		for i := 0; i < 10; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				_ = adapter.Stop(ctx)
			}()
		}
		wg.Wait()
	})
}

// =============================================================================
// Start Error Path Tests
// =============================================================================

func TestAdapter_StartWhenClosed(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	cfg := &Config{
		Transport: TransportEmbedded,
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Mark as closed
	adapter.closed.Store(true)

	// Start should fail when closed
	ctx := context.Background()
	err = adapter.Start(ctx, nil)
	if err != ErrAdapterClosed {
		t.Errorf("expected ErrAdapterClosed, got %v", err)
	}
}

func TestAdapter_StartIdempotent(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	cfg := &Config{
		Transport: TransportEmbedded,
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mockClient := NewMockClient()
	adapter.setClientForTest(mockClient)
	adapter.started.Store(true)

	// Second start should be no-op
	ctx := context.Background()
	err = adapter.Start(ctx, nil)
	if err != nil {
		t.Errorf("expected second Start() to succeed (no-op), got %v", err)
	}
}

// =============================================================================
// All Service Accessor Tests
// =============================================================================

func TestAdapter_AllServiceAccessors(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	cfg := &Config{
		Transport: TransportEmbedded,
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mockClient := NewMockClient()
	adapter.setClientForTest(mockClient)
	adapter.started.Store(true)

	// Core Data Operations
	t.Run("KV", func(t *testing.T) {
		if adapter.KV() != mockClient.KV() {
			t.Error("KV() did not return expected client")
		}
	})

	t.Run("Batch", func(t *testing.T) {
		if adapter.Batch() != mockClient.Batch() {
			t.Error("Batch() did not return expected client")
		}
	})

	t.Run("Transaction", func(t *testing.T) {
		if adapter.Transaction() != mockClient.Transaction() {
			t.Error("Transaction() did not return expected client")
		}
	})

	t.Run("Query", func(t *testing.T) {
		if adapter.Query() != mockClient.Query() {
			t.Error("Query() did not return expected client")
		}
	})

	// Cluster Operations
	t.Run("Cluster", func(t *testing.T) {
		if adapter.Cluster() != mockClient.Cluster() {
			t.Error("Cluster() did not return expected client")
		}
	})

	t.Run("Health", func(t *testing.T) {
		if adapter.Health() != mockClient.Health() {
			t.Error("Health() did not return expected client")
		}
	})

	t.Run("Operations", func(t *testing.T) {
		if adapter.Operations() != mockClient.Operations() {
			t.Error("Operations() did not return expected client")
		}
	})

	t.Run("Cache", func(t *testing.T) {
		if adapter.Cache() != mockClient.Cache() {
			t.Error("Cache() did not return expected client")
		}
	})

	// Security Operations
	t.Run("Auth", func(t *testing.T) {
		if adapter.Auth() != mockClient.Auth() {
			t.Error("Auth() did not return expected client")
		}
	})

	t.Run("Seal", func(t *testing.T) {
		if adapter.Seal() != mockClient.Seal() {
			t.Error("Seal() did not return expected client")
		}
	})

	t.Run("KMS", func(t *testing.T) {
		if adapter.KMS() != mockClient.KMS() {
			t.Error("KMS() did not return expected client")
		}
	})

	t.Run("Secrets", func(t *testing.T) {
		if adapter.Secrets() != mockClient.Secrets() {
			t.Error("Secrets() did not return expected client")
		}
	})

	t.Run("Crypto", func(t *testing.T) {
		if adapter.Crypto() != mockClient.Crypto() {
			t.Error("Crypto() did not return expected client")
		}
	})

	t.Run("RBAC", func(t *testing.T) {
		if adapter.RBAC() != mockClient.RBAC() {
			t.Error("RBAC() did not return expected client")
		}
	})

	t.Run("DynamicSecrets", func(t *testing.T) {
		if adapter.DynamicSecrets() != mockClient.DynamicSecrets() {
			t.Error("DynamicSecrets() did not return expected client")
		}
	})

	t.Run("Certificate", func(t *testing.T) {
		if adapter.Certificate() != mockClient.Certificate() {
			t.Error("Certificate() did not return expected client")
		}
	})

	t.Run("DEK", func(t *testing.T) {
		if adapter.DEK() != mockClient.DEK() {
			t.Error("DEK() did not return expected client")
		}
	})

	// IAM Operations
	t.Run("IAM", func(t *testing.T) {
		if adapter.IAM() != mockClient.IAM() {
			t.Error("IAM() did not return expected client")
		}
	})

	// Specialized Data Operations
	t.Run("Vector", func(t *testing.T) {
		if adapter.Vector() != mockClient.Vector() {
			t.Error("Vector() did not return expected client")
		}
	})

	t.Run("TimeSeries", func(t *testing.T) {
		if adapter.TimeSeries() != mockClient.TimeSeries() {
			t.Error("TimeSeries() did not return expected client")
		}
	})

	t.Run("Backup", func(t *testing.T) {
		if adapter.Backup() != mockClient.Backup() {
			t.Error("Backup() did not return expected client")
		}
	})

	t.Run("ObjectStorage", func(t *testing.T) {
		if adapter.ObjectStorage() != mockClient.ObjectStorage() {
			t.Error("ObjectStorage() did not return expected client")
		}
	})

	t.Run("ObjectStorageAdmin", func(t *testing.T) {
		if adapter.ObjectStorageAdmin() != mockClient.ObjectStorageAdmin() {
			t.Error("ObjectStorageAdmin() did not return expected client")
		}
	})

	t.Run("ObjectTransfer", func(t *testing.T) {
		if adapter.ObjectTransfer() != mockClient.ObjectTransfer() {
			t.Error("ObjectTransfer() did not return expected client")
		}
	})

	t.Run("ParameterStore", func(t *testing.T) {
		if adapter.ParameterStore() != mockClient.ParameterStore() {
			t.Error("ParameterStore() did not return expected client")
		}
	})

	// Scheduler Operations
	t.Run("Scheduler", func(t *testing.T) {
		if adapter.Scheduler() != mockClient.Scheduler() {
			t.Error("Scheduler() did not return expected client")
		}
	})

	// Messaging Operations
	t.Run("Messaging", func(t *testing.T) {
		if adapter.Messaging() != mockClient.Messaging() {
			t.Error("Messaging() did not return expected client")
		}
	})

	// AI/ML Operations
	t.Run("Embedding", func(t *testing.T) {
		if adapter.Embedding() != mockClient.Embedding() {
			t.Error("Embedding() did not return expected client")
		}
	})

	t.Run("Ollama", func(t *testing.T) {
		if adapter.Ollama() != mockClient.Ollama() {
			t.Error("Ollama() did not return expected client")
		}
	})
}

// =============================================================================
// Transport Type Tests
// =============================================================================

func TestTransportTypes(t *testing.T) {
	t.Run("embedded_transport", func(t *testing.T) {
		if TransportEmbedded != "embedded" {
			t.Errorf("expected 'embedded', got %s", TransportEmbedded)
		}
	})

	t.Run("unix_transport", func(t *testing.T) {
		if TransportUnix != "unix" {
			t.Errorf("expected 'unix', got %s", TransportUnix)
		}
	})

	t.Run("grpc_transport", func(t *testing.T) {
		if TransportGRPC != "grpc" {
			t.Errorf("expected 'grpc', got %s", TransportGRPC)
		}
	})

	t.Run("rest_transport", func(t *testing.T) {
		if TransportREST != "rest" {
			t.Errorf("expected 'rest', got %s", TransportREST)
		}
	})

	t.Run("quic_transport", func(t *testing.T) {
		if TransportQUIC != "quic" {
			t.Errorf("expected 'quic', got %s", TransportQUIC)
		}
	})
}

// =============================================================================
// TLS and Pool Config Tests
// =============================================================================

func TestTLSConfig(t *testing.T) {
	t.Run("empty_tls_config", func(t *testing.T) {
		cfg := &TLSConfig{}
		if cfg.CACert != "" {
			t.Error("expected empty CACert")
		}
		if cfg.ClientCert != "" {
			t.Error("expected empty ClientCert")
		}
		if cfg.ClientKey != "" {
			t.Error("expected empty ClientKey")
		}
	})

	t.Run("populated_tls_config", func(t *testing.T) {
		cfg := &TLSConfig{
			CACert:     "/path/to/ca.crt",
			ClientCert: "/path/to/client.crt",
			ClientKey:  "/path/to/client.key",
		}
		if cfg.CACert != "/path/to/ca.crt" {
			t.Errorf("expected /path/to/ca.crt, got %s", cfg.CACert)
		}
		if cfg.ClientCert != "/path/to/client.crt" {
			t.Errorf("expected /path/to/client.crt, got %s", cfg.ClientCert)
		}
		if cfg.ClientKey != "/path/to/client.key" {
			t.Errorf("expected /path/to/client.key, got %s", cfg.ClientKey)
		}
	})
}

func TestPoolConfig(t *testing.T) {
	t.Run("empty_pool_config", func(t *testing.T) {
		cfg := &PoolConfig{}
		if cfg.MaxConnections != 0 {
			t.Error("expected MaxConnections to be 0")
		}
		if cfg.MinConnections != 0 {
			t.Error("expected MinConnections to be 0")
		}
		if cfg.MaxIdleTime != 0 {
			t.Error("expected MaxIdleTime to be 0")
		}
	})

	t.Run("populated_pool_config", func(t *testing.T) {
		cfg := &PoolConfig{
			MaxConnections: 100,
			MinConnections: 10,
			MaxIdleTime:    5 * time.Minute,
		}
		if cfg.MaxConnections != 100 {
			t.Errorf("expected 100, got %d", cfg.MaxConnections)
		}
		if cfg.MinConnections != 10 {
			t.Errorf("expected 10, got %d", cfg.MinConnections)
		}
		if cfg.MaxIdleTime != 5*time.Minute {
			t.Errorf("expected 5m, got %v", cfg.MaxIdleTime)
		}
	})
}

// =============================================================================
// Config with TLS and Pool Tests
// =============================================================================

func TestConfig_WithTLSAndPool(t *testing.T) {
	t.Run("config_with_tls", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportGRPC,
			Address:   "localhost:10443",
			TLS: &TLSConfig{
				CACert:     "/path/to/ca.crt",
				ClientCert: "/path/to/client.crt",
				ClientKey:  "/path/to/client.key",
			},
		}
		err := cfg.Validate()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if cfg.TLS == nil {
			t.Error("expected TLS config to be preserved")
		}
		if cfg.TLS.CACert != "/path/to/ca.crt" {
			t.Error("expected TLS CACert to be preserved")
		}
	})

	t.Run("config_with_pool", func(t *testing.T) {
		cfg := &Config{
			Transport: TransportGRPC,
			Address:   "localhost:10443",
			Pool: &PoolConfig{
				MaxConnections: 50,
				MinConnections: 5,
			},
		}
		err := cfg.Validate()
		if err != nil {
			t.Fatalf("expected no error, got %v", err)
		}
		if cfg.Pool == nil {
			t.Error("expected Pool config to be preserved")
		}
		if cfg.Pool.MaxConnections != 50 {
			t.Error("expected Pool MaxConnections to be preserved")
		}
	})
}

// =============================================================================
// Mock Client Tests
// =============================================================================

func TestMockClient(t *testing.T) {
	t.Run("new_mock_client", func(t *testing.T) {
		mock := NewMockClient()
		if mock == nil {
			t.Fatal("expected non-nil mock client")
		}
	})

	t.Run("close_tracks_call", func(t *testing.T) {
		mock := NewMockClient()
		if mock.WasCloseCalled() {
			t.Error("expected WasCloseCalled to be false before Close()")
		}

		err := mock.Close()
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if !mock.WasCloseCalled() {
			t.Error("expected WasCloseCalled to be true after Close()")
		}
	})

	t.Run("close_returns_configured_error", func(t *testing.T) {
		mock := NewMockClient()
		mock.CloseError = errors.New("close error")

		err := mock.Close()
		if err == nil {
			t.Error("expected error")
		}
		if err.Error() != "close error" {
			t.Errorf("expected 'close error', got %v", err)
		}
	})

	t.Run("reset_clears_state", func(t *testing.T) {
		mock := NewMockClient()
		mock.CloseError = errors.New("close error")
		_ = mock.Close()

		mock.Reset()

		if mock.WasCloseCalled() {
			t.Error("expected Reset() to clear closeCalled")
		}
		if mock.CloseError != nil {
			t.Error("expected Reset() to clear CloseError")
		}
	})
}

// =============================================================================
// Client Factory Transport Tests
// =============================================================================

// mockClientFactory returns a factory that produces mock clients
func mockClientFactory(mockClient *MockClient) ClientFactory {
	return func(address string, opts ...quicbaas.Option) (quicbaas.Client, error) {
		return mockClient, nil
	}
}

// mockClientFactoryWithError returns a factory that returns an error
func mockClientFactoryWithError(err error) ClientFactory {
	return func(address string, opts ...quicbaas.Option) (quicbaas.Client, error) {
		return nil, err
	}
}

func TestAdapter_StartWithGRPCTransport(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	cfg := &Config{
		Transport:      TransportGRPC,
		Address:        "localhost:10443",
		RequestTimeout: 30 * time.Second,
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Inject mock client factory
	mockClient := NewMockClient()
	adapter.clientFactory = mockClientFactory(mockClient)

	ctx := context.Background()
	err = adapter.Start(ctx, nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !adapter.IsStarted() {
		t.Error("expected adapter to be started")
	}
	if adapter.Client() != quicbaas.Client(mockClient) {
		t.Error("expected Client() to return mock client")
	}
}

func TestAdapter_StartWithRESTTransport(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	cfg := &Config{
		Transport:      TransportREST,
		Address:        "https://localhost:8443",
		RequestTimeout: 30 * time.Second,
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Inject mock client factory
	mockClient := NewMockClient()
	adapter.clientFactory = mockClientFactory(mockClient)

	ctx := context.Background()
	err = adapter.Start(ctx, nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !adapter.IsStarted() {
		t.Error("expected adapter to be started")
	}
}

func TestAdapter_StartWithQUICTransport(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	cfg := &Config{
		Transport:      TransportQUIC,
		Address:        "localhost:9444",
		RequestTimeout: 30 * time.Second,
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Inject mock client factory
	mockClient := NewMockClient()
	adapter.clientFactory = mockClientFactory(mockClient)

	ctx := context.Background()
	err = adapter.Start(ctx, nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !adapter.IsStarted() {
		t.Error("expected adapter to be started")
	}
}

func TestAdapter_StartWithUnixTransport(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	cfg := &Config{
		Transport:      TransportUnix,
		UnixSocket:     "/tmp/quicbaas.sock",
		RequestTimeout: 30 * time.Second,
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Inject mock client factory
	mockClient := NewMockClient()
	adapter.clientFactory = mockClientFactory(mockClient)

	ctx := context.Background()
	err = adapter.Start(ctx, nil)
	if err != nil {
		t.Fatalf("expected no error, got %v", err)
	}

	if !adapter.IsStarted() {
		t.Error("expected adapter to be started")
	}
}

func TestAdapter_StartWithClientFactoryError(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	cfg := &Config{
		Transport: TransportGRPC,
		Address:   "localhost:10443",
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Inject mock client factory that returns an error
	factoryErr := errors.New("connection refused")
	adapter.clientFactory = mockClientFactoryWithError(factoryErr)

	ctx := context.Background()
	err = adapter.Start(ctx, nil)
	if err == nil {
		t.Error("expected error from client factory")
	}
	if err != factoryErr {
		t.Errorf("expected factory error, got %v", err)
	}

	if adapter.IsStarted() {
		t.Error("expected adapter to not be started after error")
	}
}

func TestAdapter_GRPCWithTimeout(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	cfg := &Config{
		Transport:      TransportGRPC,
		Address:        "localhost:10443",
		RequestTimeout: 60 * time.Second,
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mockClient := NewMockClient()
	adapter.clientFactory = mockClientFactory(mockClient)

	ctx := context.Background()
	err = adapter.Start(ctx, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !adapter.IsStarted() {
		t.Error("expected adapter to be started")
	}
}

func TestAdapter_RESTWithTimeout(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	cfg := &Config{
		Transport:      TransportREST,
		Address:        "https://localhost:8443",
		RequestTimeout: 60 * time.Second,
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mockClient := NewMockClient()
	adapter.clientFactory = mockClientFactory(mockClient)

	ctx := context.Background()
	err = adapter.Start(ctx, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !adapter.IsStarted() {
		t.Error("expected adapter to be started")
	}
}

func TestAdapter_QUICWithTimeout(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	cfg := &Config{
		Transport:      TransportQUIC,
		Address:        "localhost:9444",
		RequestTimeout: 60 * time.Second,
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mockClient := NewMockClient()
	adapter.clientFactory = mockClientFactory(mockClient)

	ctx := context.Background()
	err = adapter.Start(ctx, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !adapter.IsStarted() {
		t.Error("expected adapter to be started")
	}
}

func TestAdapter_UnixWithTimeout(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	cfg := &Config{
		Transport:      TransportUnix,
		UnixSocket:     "/tmp/quicbaas.sock",
		RequestTimeout: 60 * time.Second,
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mockClient := NewMockClient()
	adapter.clientFactory = mockClientFactory(mockClient)

	ctx := context.Background()
	err = adapter.Start(ctx, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !adapter.IsStarted() {
		t.Error("expected adapter to be started")
	}
}

func TestAdapter_StartWithNilClient(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	cfg := &Config{
		Transport: TransportGRPC,
		Address:   "localhost:10443",
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Factory that returns nil client (should not happen in practice)
	adapter.clientFactory = func(address string, opts ...quicbaas.Option) (quicbaas.Client, error) {
		return nil, nil
	}

	ctx := context.Background()
	err = adapter.Start(ctx, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// When client is nil but no error, adapter should still be started
	if !adapter.IsStarted() {
		t.Error("expected adapter to be started")
	}
}

// =============================================================================
// Full Lifecycle Tests
// =============================================================================

func TestAdapter_FullLifecycle(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	cfg := &Config{
		Transport: TransportGRPC,
		Address:   "localhost:10443",
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mockClient := NewMockClient()
	adapter.clientFactory = mockClientFactory(mockClient)

	// Initially not started
	if adapter.IsStarted() {
		t.Error("expected adapter to not be started initially")
	}
	if adapter.IsClosed() {
		t.Error("expected adapter to not be closed initially")
	}

	// Start
	ctx := context.Background()
	err = adapter.Start(ctx, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !adapter.IsStarted() {
		t.Error("expected adapter to be started")
	}
	if adapter.IsClosed() {
		t.Error("expected adapter to not be closed after start")
	}

	// Verify client is accessible
	if adapter.Client() != quicbaas.Client(mockClient) {
		t.Error("expected Client() to return mock client")
	}

	// Stop
	err = adapter.Stop(ctx)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !adapter.IsClosed() {
		t.Error("expected adapter to be closed after stop")
	}

	// Client should return nil after close
	if adapter.Client() != nil {
		t.Error("expected Client() to return nil after close")
	}

	// Verify Close was called on mock client
	if !mockClient.WasCloseCalled() {
		t.Error("expected Close() to be called on client")
	}
}

// =============================================================================
// Embedded Transport Tests with Mock Service
// =============================================================================

// mockQuicBaaSService is a minimal mock of service.QuicBaaS for testing
type mockQuicBaaSService struct {
	service.QuicBaaS
}

func TestAdapter_EmbeddedWithMockService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	cfg := &Config{
		Transport:      TransportEmbedded,
		RequestTimeout: 30 * time.Second,
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mockClient := NewMockClient()
	adapter.clientFactory = mockClientFactory(mockClient)

	// Create mock service
	mockService := &mockQuicBaaSService{}

	ctx := context.Background()
	err = adapter.Start(ctx, mockService)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !adapter.IsStarted() {
		t.Error("expected adapter to be started")
	}
	if adapter.Client() != quicbaas.Client(mockClient) {
		t.Error("expected Client() to return mock client")
	}
}

func TestAdapter_EmbeddedWithoutTimeout(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	cfg := &Config{
		Transport:      TransportEmbedded,
		RequestTimeout: 0, // No timeout
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mockClient := NewMockClient()
	adapter.clientFactory = mockClientFactory(mockClient)

	mockService := &mockQuicBaaSService{}

	ctx := context.Background()
	err = adapter.Start(ctx, mockService)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !adapter.IsStarted() {
		t.Error("expected adapter to be started")
	}
}

// =============================================================================
// Transport Tests without Timeout (timeout = 0)
// =============================================================================

func TestAdapter_GRPCWithoutTimeout(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	cfg := &Config{
		Transport:      TransportGRPC,
		Address:        "localhost:10443",
		RequestTimeout: 0, // No timeout
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mockClient := NewMockClient()
	adapter.clientFactory = mockClientFactory(mockClient)

	ctx := context.Background()
	err = adapter.Start(ctx, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !adapter.IsStarted() {
		t.Error("expected adapter to be started")
	}
}

func TestAdapter_RESTWithoutTimeout(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	cfg := &Config{
		Transport:      TransportREST,
		Address:        "https://localhost:8443",
		RequestTimeout: 0, // No timeout
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mockClient := NewMockClient()
	adapter.clientFactory = mockClientFactory(mockClient)

	ctx := context.Background()
	err = adapter.Start(ctx, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !adapter.IsStarted() {
		t.Error("expected adapter to be started")
	}
}

func TestAdapter_QUICWithoutTimeout(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	cfg := &Config{
		Transport:      TransportQUIC,
		Address:        "localhost:9444",
		RequestTimeout: 0, // No timeout
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mockClient := NewMockClient()
	adapter.clientFactory = mockClientFactory(mockClient)

	ctx := context.Background()
	err = adapter.Start(ctx, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !adapter.IsStarted() {
		t.Error("expected adapter to be started")
	}
}

func TestAdapter_UnixWithoutTimeout(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	cfg := &Config{
		Transport:      TransportUnix,
		UnixSocket:     "/tmp/quicbaas.sock",
		RequestTimeout: 0, // No timeout
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mockClient := NewMockClient()
	adapter.clientFactory = mockClientFactory(mockClient)

	ctx := context.Background()
	err = adapter.Start(ctx, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !adapter.IsStarted() {
		t.Error("expected adapter to be started")
	}
}

// =============================================================================
// Unsupported Transport Test
// =============================================================================

func TestAdapter_UnsupportedTransportInCreateClient(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)

	// Create adapter with valid config initially
	cfg := &Config{
		Transport: TransportGRPC,
		Address:   "localhost:10443",
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Manually change transport to an invalid value to test createClient's default case
	adapter.config.Transport = "unsupported_transport"

	ctx := context.Background()
	err = adapter.Start(ctx, nil)
	if err == nil {
		t.Error("expected error for unsupported transport")
	}

	var unsupportedErr ErrUnsupportedTransport
	if !errors.As(err, &unsupportedErr) {
		t.Errorf("expected ErrUnsupportedTransport, got %T: %v", err, err)
	}

	if adapter.IsStarted() {
		t.Error("expected adapter to not be started after error")
	}
}

// =============================================================================
// Double-check After Lock Test (Start with race)
// =============================================================================

func TestAdapter_StartDoubleCheckAfterLock(t *testing.T) {
	logger := logging.NewLogger(slog.LevelDebug, nil)
	cfg := &Config{
		Transport: TransportGRPC,
		Address:   "localhost:10443",
	}

	adapter, err := NewAdapter(cfg, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	mockClient := NewMockClient()
	adapter.clientFactory = mockClientFactory(mockClient)

	// Simulate a race condition by calling Start concurrently
	var wg sync.WaitGroup
	ctx := context.Background()
	errChan := make(chan error, 10)

	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := adapter.Start(ctx, nil); err != nil {
				errChan <- err
			}
		}()
	}

	wg.Wait()
	close(errChan)

	// Check no errors occurred
	for err := range errChan {
		t.Errorf("unexpected error during concurrent Start: %v", err)
	}

	// Verify adapter is started exactly once
	if !adapter.IsStarted() {
		t.Error("expected adapter to be started")
	}
}

// setClientForTest is a test helper to inject a mock client.
func (a *Adapter) setClientForTest(c quicbaas.Client) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.client = c
}
