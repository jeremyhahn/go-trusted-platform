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

package quicbaas_test

import (
	"testing"
	"time"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestSDKMultiTransport tests the QuicBaaS SDK across different transport modes.
// This is the primary integration test for verifying multi-transport support.
func TestSDKMultiTransport(t *testing.T) {
	// Test embedded transport (in-process) - this is the default and most common mode
	t.Run("Embedded", func(t *testing.T) {
		testEmbeddedTransport(t)
	})

	// Test embedded with memory backend for faster operations
	t.Run("EmbeddedMemory", func(t *testing.T) {
		testEmbeddedMemoryTransport(t)
	})

	// Test embedded with file backend for debugging
	t.Run("EmbeddedFile", func(t *testing.T) {
		testEmbeddedFileTransport(t)
	})

	// Note: Unix, gRPC, REST, and QUIC transports require a running QuicBaaS server.
	// These tests are run separately with a real server in the devcontainer environment.
	// See remote_transport_test.go for those tests.
}

// testEmbeddedTransport tests the embedded (in-process) transport mode.
// This is the default transport that provides highest performance by
// avoiding network overhead.
func testEmbeddedTransport(t *testing.T) {
	t.Helper()

	// Create factory with embedded transport
	cfg := quicbaas.TestConfig(t)
	cfg.Transport = quicbaas.TransportEmbedded
	logger := logging.DefaultLogger()

	factory, err := quicbaas.NewFactory(cfg, logger, nil)
	require.NoError(t, err, "Factory creation should succeed")

	ctx, cancel := startupContext()
	defer cancel()

	require.NoError(t, factory.Start(ctx), "Factory start should succeed")
	defer func() {
		stopCtx, stopCancel := shutdownContext()
		defer stopCancel()
		factory.Stop(stopCtx)
	}()

	// Verify factory is properly started
	assert.True(t, factory.IsStarted(), "Factory should be started")
	assert.False(t, factory.IsClosed(), "Factory should not be closed")
	assert.True(t, factory.IsEmbedded(), "Factory should be in embedded mode")
	assert.Equal(t, quicbaas.TransportEmbedded, factory.Transport(), "Transport should be embedded")

	// Get SDK client and verify it's available
	sdk := factory.SDK()
	require.NotNil(t, sdk, "SDK client should not be nil")

	// Verify all 28 service clients are accessible
	verifyAllServiceClients(t, sdk)

	// Test basic KV operations via SDK
	testSDKKVOperations(t, sdk)

	// Test health check via SDK
	testSDKHealthCheck(t, sdk)
}

// testEmbeddedMemoryTransport tests embedded mode with in-memory storage.
// This is the fastest option for tests that don't need persistence.
func testEmbeddedMemoryTransport(t *testing.T) {
	t.Helper()

	cfg := quicbaas.MemoryTestConfig(t)
	cfg.Transport = quicbaas.TransportEmbedded
	logger := logging.DefaultLogger()

	factory, err := quicbaas.NewFactory(cfg, logger, nil)
	require.NoError(t, err)

	ctx, cancel := startupContext()
	defer cancel()

	require.NoError(t, factory.Start(ctx))
	defer func() {
		stopCtx, stopCancel := shutdownContext()
		defer stopCancel()
		factory.Stop(stopCtx)
	}()

	sdk := factory.SDK()
	require.NotNil(t, sdk)

	// Test basic operations
	testSDKKVOperations(t, sdk)
}

// testEmbeddedFileTransport tests embedded mode with file-based storage.
// Each key-value pair is stored as a separate file, making it easy to inspect.
func testEmbeddedFileTransport(t *testing.T) {
	t.Helper()

	cfg := quicbaas.FileTestConfig(t)
	cfg.Transport = quicbaas.TransportEmbedded
	logger := logging.DefaultLogger()

	factory, err := quicbaas.NewFactory(cfg, logger, nil)
	require.NoError(t, err)

	ctx, cancel := startupContext()
	defer cancel()

	require.NoError(t, factory.Start(ctx))
	defer func() {
		stopCtx, stopCancel := shutdownContext()
		defer stopCancel()
		factory.Stop(stopCtx)
	}()

	sdk := factory.SDK()
	require.NotNil(t, sdk)

	// Test basic operations
	testSDKKVOperations(t, sdk)
}

// verifyAllServiceClients verifies that all 28 QuicBaaS service clients are accessible.
func verifyAllServiceClients(t *testing.T, sdk quicbaassdk.Client) {
	t.Helper()

	// Core Data Services
	assert.NotNil(t, sdk.KV(), "KV client should not be nil")
	assert.NotNil(t, sdk.Batch(), "Batch client should not be nil")
	assert.NotNil(t, sdk.Transaction(), "Transaction client should not be nil")
	assert.NotNil(t, sdk.Query(), "Query client should not be nil")

	// Cluster Operations
	assert.NotNil(t, sdk.Cluster(), "Cluster client should not be nil")
	assert.NotNil(t, sdk.Health(), "Health client should not be nil")
	assert.NotNil(t, sdk.Operations(), "Operations client should not be nil")
	assert.NotNil(t, sdk.Cache(), "Cache client should not be nil")

	// Security Operations
	assert.NotNil(t, sdk.Security().Auth(), "Auth client should not be nil")
	assert.NotNil(t, sdk.Security().Seal(), "Seal client should not be nil")
	assert.NotNil(t, sdk.Security().KMS(), "KMS client should not be nil")
	assert.NotNil(t, sdk.Security().Secrets(), "Secrets client should not be nil")
	assert.NotNil(t, sdk.Security().Crypto(), "Crypto client should not be nil")
	assert.NotNil(t, sdk.Security().RBAC(), "RBAC client should not be nil")
	assert.NotNil(t, sdk.Security().DynamicSecrets(), "DynamicSecrets client should not be nil")
	assert.NotNil(t, sdk.Security().Certificate(), "Certificate client should not be nil")
	assert.NotNil(t, sdk.Security().DEK(), "DEK client should not be nil")

	// IAM Operations
	assert.NotNil(t, sdk.Identity().IAM(), "IAM client should not be nil")

	// Specialized Data Operations
	assert.NotNil(t, sdk.Vector(), "Vector client should not be nil")
	assert.NotNil(t, sdk.TimeSeries(), "TimeSeries client should not be nil")
	assert.NotNil(t, sdk.Backup(), "Backup client should not be nil")
	assert.NotNil(t, sdk.ObjectStorage(), "ObjectStorage client should not be nil")
	assert.NotNil(t, sdk.ObjectStorageAdmin(), "ObjectStorageAdmin client should not be nil")
	assert.NotNil(t, sdk.ObjectTransfer(), "ObjectTransfer client should not be nil")
	assert.NotNil(t, sdk.ParameterStore(), "ParameterStore client should not be nil")

	// Scheduler Operations
	assert.NotNil(t, sdk.Scheduler(), "Scheduler client should not be nil")

	// AI/ML Operations
	assert.NotNil(t, sdk.Embedding(), "Embedding client should not be nil")
	assert.NotNil(t, sdk.Ollama(), "Ollama client should not be nil")

	// Transport
	assert.NotNil(t, sdk.Transport(), "Transport should not be nil")
}

// testSDKKVOperations tests basic KV operations via the SDK.
func testSDKKVOperations(t *testing.T, sdk quicbaassdk.Client) {
	t.Helper()

	ctx, cancel := testContext()
	defer cancel()

	kv := sdk.KV()
	require.NotNil(t, kv, "KV client should not be nil")

	entityType := generateTestKey("test/integration")
	testData := []byte(`{"message": "hello from integration test"}`)

	// Put
	putResp, err := kv.Put(ctx, &quicbaassdk.PutRequest{
		EntityType: entityType,
		Data:       testData,
	})
	require.NoError(t, err, "Put should succeed")
	assert.NotNil(t, putResp, "Put response should not be nil")
	entityID := putResp.ID

	// Get
	getResp, err := kv.Get(ctx, &quicbaassdk.GetRequest{
		EntityType: entityType,
		ID:         entityID,
	})
	require.NoError(t, err, "Get should succeed")
	assert.NotNil(t, getResp, "Get response should not be nil")
	assert.True(t, getResp.Found, "Entity should be found")
	assert.Equal(t, testData, getResp.Data, "Data should match")

	// Delete
	deleteResp, err := kv.Delete(ctx, &quicbaassdk.DeleteRequest{
		EntityType: entityType,
		ID:         entityID,
	})
	require.NoError(t, err, "Delete should succeed")
	assert.NotNil(t, deleteResp, "Delete response should not be nil")

	// Verify deletion (may need retry due to eventual consistency)
	require.Eventually(t, func() bool {
		getResp, err := kv.Get(ctx, &quicbaassdk.GetRequest{
			EntityType: entityType,
			ID:         entityID,
		})
		return err == nil && !getResp.Found
	}, 5*time.Second, 100*time.Millisecond, "Entity should be deleted")
}

// testSDKHealthCheck tests the health check service via the SDK.
func testSDKHealthCheck(t *testing.T, sdk quicbaassdk.Client) {
	t.Helper()

	ctx, cancel := testContext()
	defer cancel()

	health := sdk.Health()
	require.NotNil(t, health, "Health client should not be nil")

	// Ping should succeed for embedded mode
	err := health.Ping(ctx)
	require.NoError(t, err, "Ping should succeed")
}

// TestFactorySDKClientLifecycle tests the SDK client lifecycle through the factory.
func TestFactorySDKClientLifecycle(t *testing.T) {
	cfg := quicbaas.TestConfig(t)
	cfg.Transport = quicbaas.TransportEmbedded
	logger := logging.DefaultLogger()

	// Create factory
	factory, err := quicbaas.NewFactory(cfg, logger, nil)
	require.NoError(t, err)

	// SDK should be nil before start
	assert.Nil(t, factory.SDK(), "SDK should be nil before start")
	assert.False(t, factory.IsStarted(), "Factory should not be started")

	// Start factory
	ctx, cancel := startupContext()
	require.NoError(t, factory.Start(ctx))
	cancel()

	// SDK should be available after start
	sdk := factory.SDK()
	assert.NotNil(t, sdk, "SDK should not be nil after start")
	assert.True(t, factory.IsStarted(), "Factory should be started")

	// Verify SDK client is functional
	healthClient := sdk.Health()
	require.NotNil(t, healthClient)

	pingCtx, pingCancel := testContext()
	defer pingCancel()
	err = healthClient.Ping(pingCtx)
	require.NoError(t, err, "Health ping should succeed")

	// Stop factory
	stopCtx, stopCancel := shutdownContext()
	require.NoError(t, factory.Stop(stopCtx))
	stopCancel()

	// Verify factory is stopped
	assert.False(t, factory.IsStarted(), "Factory should not be started after stop")
	assert.True(t, factory.IsClosed(), "Factory should be closed")

	// SDK should be nil after stop
	assert.Nil(t, factory.SDK(), "SDK should be nil after stop")
}

// TestFactoryMultipleStartStop tests that factory can be started and stopped multiple times.
func TestFactoryMultipleStartStop(t *testing.T) {
	cfg := quicbaas.TestConfig(t)
	cfg.Transport = quicbaas.TransportEmbedded
	logger := logging.DefaultLogger()

	factory, err := quicbaas.NewFactory(cfg, logger, nil)
	require.NoError(t, err)

	ctx, cancel := startupContext()
	require.NoError(t, factory.Start(ctx))
	cancel()

	// SDK should work
	sdk := factory.SDK()
	require.NotNil(t, sdk)

	// Stop and verify closed state
	stopCtx, stopCancel := shutdownContext()
	require.NoError(t, factory.Stop(stopCtx))
	stopCancel()

	assert.True(t, factory.IsClosed())

	// Starting a closed factory should fail (need new factory)
	ctx2, cancel2 := startupContext()
	err = factory.Start(ctx2)
	cancel2()
	assert.Error(t, err, "Starting a closed factory should fail")
}

// TestSDKClientServiceAccessors tests that SDK service accessors return consistent clients.
func TestSDKClientServiceAccessors(t *testing.T) {
	tf := newTestFactory(t)
	defer tf.Cleanup()

	sdk := requireSDK(t, tf.Factory)

	// Verify service accessors return the same instance (cached)
	kv1 := sdk.KV()
	kv2 := sdk.KV()
	assert.Same(t, kv1, kv2, "KV client should be cached")

	health1 := sdk.Health()
	health2 := sdk.Health()
	assert.Same(t, health1, health2, "Health client should be cached")

	kms1 := sdk.Security().KMS()
	kms2 := sdk.Security().KMS()
	assert.Same(t, kms1, kms2, "KMS client should be cached")

	iam1 := sdk.Identity().IAM()
	iam2 := sdk.Identity().IAM()
	assert.Same(t, iam1, iam2, "IAM client should be cached")
}

// TestEmbeddedTransportConfig tests embedded transport configuration.
func TestEmbeddedTransportConfig(t *testing.T) {
	tests := []struct {
		name       string
		configFunc func(t *testing.T) *quicbaas.Config
	}{
		{
			name: "DefaultConfig",
			configFunc: func(t *testing.T) *quicbaas.Config {
				cfg := quicbaas.TestConfig(t)
				cfg.Transport = quicbaas.TransportEmbedded
				return cfg
			},
		},
		{
			name: "MemoryConfig",
			configFunc: func(t *testing.T) *quicbaas.Config {
				cfg := quicbaas.MemoryTestConfig(t)
				cfg.Transport = quicbaas.TransportEmbedded
				return cfg
			},
		},
		{
			name: "FileConfig",
			configFunc: func(t *testing.T) *quicbaas.Config {
				cfg := quicbaas.FileTestConfig(t)
				cfg.Transport = quicbaas.TransportEmbedded
				return cfg
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := tc.configFunc(t)
			logger := logging.DefaultLogger()

			factory, err := quicbaas.NewFactory(cfg, logger, nil)
			require.NoError(t, err)

			ctx, cancel := startupContext()
			require.NoError(t, factory.Start(ctx))
			cancel()

			defer func() {
				stopCtx, stopCancel := shutdownContext()
				defer stopCancel()
				factory.Stop(stopCtx)
			}()

			// Verify SDK is available
			sdk := factory.SDK()
			require.NotNil(t, sdk)

			// Verify basic operation works
			testCtx, testCancel := testContext()
			defer testCancel()

			err = sdk.Health().Ping(testCtx)
			require.NoError(t, err, "Health ping should succeed")
		})
	}
}

// TestSDKClientConcurrentAccess tests concurrent access to SDK service clients.
func TestSDKClientConcurrentAccess(t *testing.T) {
	tf := newTestFactory(t)
	defer tf.Cleanup()

	sdk := requireSDK(t, tf.Factory)

	// Launch multiple goroutines accessing different services concurrently
	done := make(chan bool, 100)

	for i := 0; i < 100; i++ {
		go func(idx int) {
			defer func() { done <- true }()

			// Access various services
			_ = sdk.KV()
			_ = sdk.Health()
			_ = sdk.Security().KMS()
			_ = sdk.Identity().IAM()
			_ = sdk.Vector()
			_ = sdk.Batch()
		}(i)
	}

	// Wait for all goroutines to complete
	for i := 0; i < 100; i++ {
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			t.Fatal("Timeout waiting for concurrent access test")
		}
	}
}

// TestSDKClientKVConcurrentOperations tests concurrent KV operations.
func TestSDKClientKVConcurrentOperations(t *testing.T) {
	tf := newTestFactory(t)
	defer tf.Cleanup()

	sdk := requireSDK(t, tf.Factory)
	kv := sdk.KV()

	numOperations := 50
	done := make(chan error, numOperations)
	entityType := generateTestKey("concurrent")

	for i := 0; i < numOperations; i++ {
		go func(idx int) {
			ctx, cancel := testContext()
			defer cancel()

			data := []byte(`{"index": ` + string(rune('0'+idx%10)) + `}`)

			// Put
			putResp, err := kv.Put(ctx, &quicbaassdk.PutRequest{
				EntityType: entityType,
				Data:       data,
			})
			if err != nil {
				done <- err
				return
			}

			// Get
			_, err = kv.Get(ctx, &quicbaassdk.GetRequest{
				EntityType: entityType,
				ID:         putResp.ID,
			})
			done <- err
		}(i)
	}

	// Wait for all operations to complete
	for i := 0; i < numOperations; i++ {
		select {
		case err := <-done:
			if err != nil {
				t.Errorf("Concurrent operation %d failed: %v", i, err)
			}
		case <-time.After(30 * time.Second):
			t.Fatal("Timeout waiting for concurrent operations")
		}
	}
}
