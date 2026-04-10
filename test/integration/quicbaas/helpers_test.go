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

//go:build integration

// Package quicbaas_test provides integration tests for multi-transport QuicBaaS support.
// These tests verify that all QuicBaaS services work correctly via the SDK across
// different transport modes (embedded, Unix socket, gRPC, REST, QUIC).
//
// Run these tests via:
//
//	make integration-test-quicbaas
//
// Tests require INTEGRATION_TEST=1 environment variable.
package quicbaas_test

import (
	"context"
	"os"
	"testing"
	"time"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
)

// testTimeout is the default timeout for test operations.
const testTimeout = 30 * time.Second

// startupTimeout is the timeout for factory startup operations.
const startupTimeout = 60 * time.Second

// shutdownTimeout is the timeout for factory shutdown operations.
const shutdownTimeout = 10 * time.Second

// skipIfNotIntegration skips the test if the INTEGRATION_TEST env var is not set.
func skipIfNotIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("INTEGRATION_TEST") == "" {
		t.Skip("Skipping integration test. Set INTEGRATION_TEST=1 to run.")
	}
}

// testContext returns a context with the test timeout.
func testContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), testTimeout)
}

// startupContext returns a context with the startup timeout.
func startupContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), startupTimeout)
}

// shutdownContext returns a context with the shutdown timeout.
func shutdownContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), shutdownTimeout)
}

// testFactory holds a Factory instance and its cleanup function.
type testFactory struct {
	Factory *quicbaas.Factory
	Logger  *logging.Logger
	Cleanup func()
}

// newTestFactory creates a new test factory with embedded transport.
// The factory is automatically started and ready for use.
// Call Cleanup() when done to stop the factory and clean up resources.
func newTestFactory(t *testing.T) *testFactory {
	t.Helper()

	cfg := quicbaas.TestConfig(t)
	cfg.Transport = quicbaas.TransportEmbedded

	logger := logging.DefaultLogger()

	factory, err := quicbaas.NewFactory(cfg, logger, nil)
	if err != nil {
		t.Fatalf("Failed to create factory: %v", err)
	}

	ctx, cancel := startupContext()
	defer cancel()

	if err := factory.Start(ctx); err != nil {
		t.Fatalf("Failed to start factory: %v", err)
	}

	cleanup := func() {
		ctx, cancel := shutdownContext()
		defer cancel()
		if err := factory.Stop(ctx); err != nil {
			t.Logf("Warning: factory stop error: %v", err)
		}
	}

	return &testFactory{
		Factory: factory,
		Logger:  logger,
		Cleanup: cleanup,
	}
}

// newMemoryTestFactory creates a test factory using in-memory storage.
// This is faster for tests that don't need persistence.
func newMemoryTestFactory(t *testing.T) *testFactory {
	t.Helper()

	cfg := quicbaas.MemoryTestConfig(t)
	cfg.Transport = quicbaas.TransportEmbedded

	logger := logging.DefaultLogger()

	factory, err := quicbaas.NewFactory(cfg, logger, nil)
	if err != nil {
		t.Fatalf("Failed to create factory: %v", err)
	}

	ctx, cancel := startupContext()
	defer cancel()

	if err := factory.Start(ctx); err != nil {
		t.Fatalf("Failed to start factory: %v", err)
	}

	cleanup := func() {
		ctx, cancel := shutdownContext()
		defer cancel()
		if err := factory.Stop(ctx); err != nil {
			t.Logf("Warning: factory stop error: %v", err)
		}
	}

	return &testFactory{
		Factory: factory,
		Logger:  logger,
		Cleanup: cleanup,
	}
}

// requireSDK returns the SDK client from the factory, failing the test if nil.
func requireSDK(t *testing.T, factory *quicbaas.Factory) quicbaassdk.Client {
	t.Helper()
	sdk := factory.SDK()
	if sdk == nil {
		t.Fatal("SDK client is nil")
	}
	return sdk
}

// assertKVClient verifies the KV client is available and functional.
func assertKVClient(t *testing.T, sdk quicbaassdk.Client) {
	t.Helper()
	kv := sdk.KV()
	if kv == nil {
		t.Fatal("KV client is nil")
	}
}

// assertHealthClient verifies the Health client is available.
func assertHealthClient(t *testing.T, sdk quicbaassdk.Client) {
	t.Helper()
	health := sdk.Health()
	if health == nil {
		t.Fatal("Health client is nil")
	}
}

// generateTestKey generates a unique key for testing.
func generateTestKey(prefix string) string {
	return prefix + "_" + time.Now().Format("20060102150405.000000000")
}

// generateTestValue generates test data.
func generateTestValue(data string) []byte {
	return []byte(data)
}
