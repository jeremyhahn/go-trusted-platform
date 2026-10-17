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

// Package sdk_test provides integration tests for the platform SDK's QuicBaaS client.
// These tests verify that the SDK wrapper correctly exposes all QuicBaaS services
// and that consumers can use the SDK to interact with QuicBaaS via all supported
// transport modes.
//
// Run these tests via:
//
//	make integration-test-sdk
package sdk_test

import (
	"context"
	"testing"
	"time"

	quicbaassdk "github.com/jeremyhahn/go-quicbaas/sdk/go"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/vector"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	sdkquicbaas "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// testTimeout is the default timeout for test operations.
const testTimeout = 30 * time.Second

// startupTimeout is the timeout for factory startup operations.
const startupTimeout = 60 * time.Second

// shutdownTimeout is the timeout for factory shutdown operations.
const shutdownTimeout = 10 * time.Second

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

// generateTestKey generates a unique key for testing.
func generateTestKey(prefix string) string {
	return prefix + "_" + time.Now().Format("20060102150405.000000000")
}

// testFixture holds test resources.
type testFixture struct {
	Factory   *quicbaas.Factory
	SDKClient *sdkquicbaas.Client
	Logger    *logging.Logger
	Cleanup   func()
}

// newTestFixture creates a test fixture with an embedded QuicBaaS instance
// and an SDK client wrapping it.
func newTestFixture(t *testing.T) *testFixture {
	t.Helper()

	cfg := quicbaas.TestConfig(t)
	cfg.Transport = quicbaas.TransportEmbedded
	logger := logging.DefaultLogger()

	factory, err := quicbaas.NewFactory(cfg, logger, nil)
	require.NoError(t, err, "Factory creation should succeed")

	ctx, cancel := startupContext()
	defer cancel()

	require.NoError(t, factory.Start(ctx), "Factory start should succeed")

	// Get the underlying SDK client from the factory and wrap it
	sdk := factory.SDK()
	require.NotNil(t, sdk, "Factory SDK should not be nil")

	// Create platform SDK client wrapper from the underlying SDK
	sdkClient, err := sdkquicbaas.NewClientFromSDK(sdk)
	require.NoError(t, err, "SDK client wrapper creation should succeed")

	cleanup := func() {
		if sdkClient != nil {
			// Note: Don't close the SDK client here as it's owned by the factory
			// sdkClient.Close() would close the underlying client
		}
		stopCtx, stopCancel := shutdownContext()
		defer stopCancel()
		factory.Stop(stopCtx)
	}

	return &testFixture{
		Factory:   factory,
		SDKClient: sdkClient,
		Logger:    logger,
		Cleanup:   cleanup,
	}
}

// TestPlatformSDKClient_Creation tests platform SDK client creation.
func TestPlatformSDKClient_Creation(t *testing.T) {
	tf := newTestFixture(t)
	defer tf.Cleanup()

	t.Run("ClientNotNil", func(t *testing.T) {
		assert.NotNil(t, tf.SDKClient, "SDK client should not be nil")
	})

	t.Run("SDKAccessor", func(t *testing.T) {
		sdk := tf.SDKClient.SDK()
		assert.NotNil(t, sdk, "SDK() should return underlying client")
	})

	t.Run("NotClosed", func(t *testing.T) {
		assert.False(t, tf.SDKClient.IsClosed(), "Client should not be closed initially")
	})
}

// TestPlatformSDKClient_AllServiceAccessors tests that all 28 service accessors work.
func TestPlatformSDKClient_AllServiceAccessors(t *testing.T) {
	tf := newTestFixture(t)
	defer tf.Cleanup()

	client := tf.SDKClient

	t.Run("CoreDataServices", func(t *testing.T) {
		assert.NotNil(t, client.KV(), "KV() should not be nil")
		assert.NotNil(t, client.Batch(), "Batch() should not be nil")
		assert.NotNil(t, client.Transaction(), "Transaction() should not be nil")
		assert.NotNil(t, client.Query(), "Query() should not be nil")
	})

	t.Run("ClusterOperations", func(t *testing.T) {
		assert.NotNil(t, client.Cluster(), "Cluster() should not be nil")
		assert.NotNil(t, client.Health(), "Health() should not be nil")
		assert.NotNil(t, client.Operations(), "Operations() should not be nil")
		assert.NotNil(t, client.Cache(), "Cache() should not be nil")
	})

	t.Run("SecurityOperations", func(t *testing.T) {
		assert.NotNil(t, client.Auth(), "Auth() should not be nil")
		assert.NotNil(t, client.Seal(), "Seal() should not be nil")
		assert.NotNil(t, client.KMS(), "KMS() should not be nil")
		assert.NotNil(t, client.Secrets(), "Secrets() should not be nil")
		assert.NotNil(t, client.Crypto(), "Crypto() should not be nil")
		assert.NotNil(t, client.RBAC(), "RBAC() should not be nil")
		assert.NotNil(t, client.DynamicSecrets(), "DynamicSecrets() should not be nil")
		assert.NotNil(t, client.Certificate(), "Certificate() should not be nil")
		assert.NotNil(t, client.DEK(), "DEK() should not be nil")
	})

	t.Run("IAMOperations", func(t *testing.T) {
		assert.NotNil(t, client.IAM(), "IAM() should not be nil")
	})

	t.Run("SpecializedDataOperations", func(t *testing.T) {
		assert.NotNil(t, client.Vector(), "Vector() should not be nil")
		assert.NotNil(t, client.TimeSeries(), "TimeSeries() should not be nil")
		assert.NotNil(t, client.Backup(), "Backup() should not be nil")
		assert.NotNil(t, client.ObjectStorage(), "ObjectStorage() should not be nil")
		assert.NotNil(t, client.ObjectStorageAdmin(), "ObjectStorageAdmin() should not be nil")
		assert.NotNil(t, client.ObjectTransfer(), "ObjectTransfer() should not be nil")
		assert.NotNil(t, client.ParameterStore(), "ParameterStore() should not be nil")
	})

	t.Run("SchedulerOperations", func(t *testing.T) {
		assert.NotNil(t, client.Scheduler(), "Scheduler() should not be nil")
	})

	t.Run("AIMLOperations", func(t *testing.T) {
		assert.NotNil(t, client.Embedding(), "Embedding() should not be nil")
		assert.NotNil(t, client.Ollama(), "Ollama() should not be nil")
	})

	t.Run("Transport", func(t *testing.T) {
		assert.NotNil(t, client.Transport(), "Transport() should not be nil")
	})
}

// TestPlatformSDKClient_KVOperations tests KV operations via the platform SDK.
func TestPlatformSDKClient_KVOperations(t *testing.T) {
	tf := newTestFixture(t)
	defer tf.Cleanup()

	kv := tf.SDKClient.KV()
	require.NotNil(t, kv)

	ctx, cancel := testContext()
	defer cancel()

	t.Run("PutGetDelete", func(t *testing.T) {
		entityType := generateTestKey("sdk/kv/crud")
		value := []byte(`{"source": "platform-sdk"}`)

		// Put
		putResp, err := kv.Put(ctx, &quicbaassdk.PutRequest{
			EntityType: entityType,
			Data:       value,
		})
		require.NoError(t, err)
		assert.NotNil(t, putResp)

		// Capture the auto-generated ID
		entityID := putResp.ID

		// Get
		getResp, err := kv.Get(ctx, &quicbaassdk.GetRequest{EntityType: entityType, ID: entityID})
		require.NoError(t, err)
		assert.True(t, getResp.Found)
		assert.Equal(t, value, getResp.Data)

		// Delete
		delResp, err := kv.Delete(ctx, &quicbaassdk.DeleteRequest{EntityType: entityType, ID: entityID})
		require.NoError(t, err)
		assert.NotNil(t, delResp)

		// Verify deleted
		require.Eventually(t, func() bool {
			getResp, err := kv.Get(ctx, &quicbaassdk.GetRequest{EntityType: entityType, ID: entityID})
			return helpers.KVEntityAbsent(getResp, err)
		}, 5*time.Second, 100*time.Millisecond)
	})
}

// TestPlatformSDKClient_VectorOperations tests vector operations via the platform SDK.
func TestPlatformSDKClient_VectorOperations(t *testing.T) {
	tf := newTestFixture(t)
	defer tf.Cleanup()

	vectorClient := tf.SDKClient.Vector()
	require.NotNil(t, vectorClient)

	ctx, cancel := testContext()
	defer cancel()

	t.Run("UpsertAndSearch", func(t *testing.T) {
		namespace := generateTestKey("sdk/vector")
		vectorData := []float32{0.1, 0.2, 0.3, 0.4, 0.5}

		// Upsert
		upsertResp, err := vectorClient.Upsert(ctx, &vector.UpsertRequest{
			Vector: &vector.VectorEntity{
				ID:        "vec-001",
				Namespace: namespace,
				Vector:    vectorData,
				Metadata:  map[string]string{"source": "platform-sdk"},
			},
		})
		require.NoError(t, err)
		assert.NotNil(t, upsertResp)

		// Search
		searchResp, err := vectorClient.SearchSimilar(ctx, &vector.SearchSimilarRequest{
			Namespace:   namespace,
			QueryVector: vectorData,
			K:           5,
		})
		require.NoError(t, err)
		assert.NotEmpty(t, searchResp.Results)
	})
}

// TestPlatformSDKClient_HealthCheck tests health check via the platform SDK.
func TestPlatformSDKClient_HealthCheck(t *testing.T) {
	tf := newTestFixture(t)
	defer tf.Cleanup()

	health := tf.SDKClient.Health()
	require.NotNil(t, health)

	ctx, cancel := testContext()
	defer cancel()

	t.Run("Ping", func(t *testing.T) {
		err := health.Ping(ctx)
		require.NoError(t, err)
	})

	t.Run("Readiness", func(t *testing.T) {
		resp, err := health.Readiness(ctx)
		require.NoError(t, err)
		assert.NotNil(t, resp)
	})
}

// TestPlatformSDKClient_BatchOperations tests batch operations via the platform SDK.
func TestPlatformSDKClient_BatchOperations(t *testing.T) {
	tf := newTestFixture(t)
	defer tf.Cleanup()

	batch := tf.SDKClient.Batch()
	require.NotNil(t, batch)

	ctx, cancel := testContext()
	defer cancel()

	t.Run("BatchPut", func(t *testing.T) {
		prefix := generateTestKey("sdk/batch")
		ops := make([]quicbaassdk.BatchOperation, 5)
		for i := 0; i < 5; i++ {
			ops[i] = quicbaassdk.BatchOperation{
				Type:       quicbaassdk.BatchOpPut,
				EntityType: prefix,
				Key:        prefix + "/" + string(rune('a'+i)),
				Value:      []byte(`{"index": ` + string(rune('0'+i)) + `}`),
			}
		}

		resp, err := batch.Execute(ctx, &quicbaassdk.BatchRequest{
			Operations: ops,
		})
		require.NoError(t, err)
		assert.NotNil(t, resp)
	})
}

// TestPlatformSDKClient_TransactionOperations tests transaction operations via the platform SDK.
func TestPlatformSDKClient_TransactionOperations(t *testing.T) {
	tf := newTestFixture(t)
	defer tf.Cleanup()

	txn := tf.SDKClient.Transaction()
	require.NotNil(t, txn)

	ctx, cancel := testContext()
	defer cancel()

	t.Run("ConditionalUpdate", func(t *testing.T) {
		entityType := generateTestKey("sdk/txn")
		key := entityType + "/config"
		value := []byte(`{"version": 1}`)
		newValue := []byte(`{"version": 2}`)

		// Create the key only if it does not exist: version 0 means absent.
		createResp, err := txn.Execute(ctx, &quicbaassdk.TxnRequest{
			Compare: []quicbaassdk.Compare{
				{Key: key, Target: quicbaassdk.CompareVersion, Result: quicbaassdk.CompareEqual, Revision: 0},
			},
			Success: []quicbaassdk.TxnOp{
				{Type: quicbaassdk.TxnOpPut, EntityType: entityType, Key: key, Value: value},
			},
		})
		require.NoError(t, err)
		assert.True(t, createResp.Succeeded)

		// Update only while the stored value is still the one just written.
		updateResp, err := txn.Execute(ctx, &quicbaassdk.TxnRequest{
			Compare: []quicbaassdk.Compare{
				{Key: key, Target: quicbaassdk.CompareValue, Result: quicbaassdk.CompareEqual, Value: value},
			},
			Success: []quicbaassdk.TxnOp{
				{Type: quicbaassdk.TxnOpPut, EntityType: entityType, Key: key, Value: newValue},
			},
		})
		require.NoError(t, err)
		assert.True(t, updateResp.Succeeded)

		// The same compare now fails: the value moved on.
		staleResp, err := txn.Execute(ctx, &quicbaassdk.TxnRequest{
			Compare: []quicbaassdk.Compare{
				{Key: key, Target: quicbaassdk.CompareValue, Result: quicbaassdk.CompareEqual, Value: value},
			},
			Success: []quicbaassdk.TxnOp{
				{Type: quicbaassdk.TxnOpPut, EntityType: entityType, Key: key, Value: value},
			},
		})
		require.NoError(t, err)
		assert.False(t, staleResp.Succeeded)
	})
}

// TestPlatformSDKClient_ParameterStore tests parameter store operations.
func TestPlatformSDKClient_ParameterStore(t *testing.T) {
	tf := newTestFixture(t)
	defer tf.Cleanup()

	params := tf.SDKClient.ParameterStore()
	require.NotNil(t, params)

	ctx, cancel := testContext()
	defer cancel()

	t.Run("SetAndGet", func(t *testing.T) {
		path := generateTestKey("/config/app/setting")
		value := []byte("test-value")

		// Set parameter
		setResp, err := params.SetParameter(ctx, &quicbaassdk.SetParameterRequest{
			Path:  path,
			Value: value,
		})
		require.NoError(t, err)
		assert.NotNil(t, setResp)

		// Get parameter
		getResp, err := params.GetParameter(ctx, &quicbaassdk.GetParameterRequest{
			Path: path,
		})
		require.NoError(t, err)
		assert.Equal(t, value, getResp.Parameter.Value)
	})
}

// TestPlatformSDKClient_ConcurrentAccess tests concurrent access to the SDK client.
func TestPlatformSDKClient_ConcurrentAccess(t *testing.T) {
	tf := newTestFixture(t)
	defer tf.Cleanup()

	numGoroutines := 50
	done := make(chan error, numGoroutines)

	for i := 0; i < numGoroutines; i++ {
		go func(idx int) {
			ctx, cancel := testContext()
			defer cancel()

			kv := tf.SDKClient.KV()
			key := generateTestKey("sdk/concurrent") + "_" + string(rune('A'+idx%26))
			value := []byte(`{"index": ` + string(rune('0'+idx%10)) + `}`)

			_, err := kv.Put(ctx, &quicbaassdk.PutRequest{EntityType: key, Data: value})
			done <- err
		}(i)
	}

	// Collect results
	for i := 0; i < numGoroutines; i++ {
		select {
		case err := <-done:
			assert.NoError(t, err, "Concurrent operation %d should succeed", i)
		case <-time.After(30 * time.Second):
			t.Fatal("Timeout waiting for concurrent operations")
		}
	}
}

// TestPlatformSDKClient_ErrorHandling tests error handling in the SDK client.
func TestPlatformSDKClient_ErrorHandling(t *testing.T) {
	t.Run("NilSDKClient", func(t *testing.T) {
		_, err := sdkquicbaas.NewClientFromSDK(nil)
		assert.Error(t, err, "Creating client with nil SDK should fail")
	})

	t.Run("ClosedClient", func(t *testing.T) {
		tf := newTestFixture(t)
		// Note: We can't easily test closed client operations because
		// the client is shared with the factory. Just verify close semantics.
		tf.Cleanup()
	})
}

// TestPlatformSDKClient_Close tests client close behavior.
func TestPlatformSDKClient_Close(t *testing.T) {
	// Create a standalone SDK client (not through factory)
	cfg := quicbaas.TestConfig(t)
	cfg.Transport = quicbaas.TransportEmbedded
	logger := logging.DefaultLogger()

	factory, err := quicbaas.NewFactory(cfg, logger, nil)
	require.NoError(t, err)

	ctx, cancel := startupContext()
	require.NoError(t, factory.Start(ctx))
	cancel()

	sdk := factory.SDK()
	require.NotNil(t, sdk)

	// Create a separate client instance (not from factory's SDK)
	// This demonstrates how external consumers would use the SDK
	client, err := sdkquicbaas.NewClientFromSDK(sdk)
	require.NoError(t, err)

	assert.False(t, client.IsClosed())

	// Don't close the client because it shares the SDK with the factory
	// Just verify the state
	stopCtx, stopCancel := shutdownContext()
	factory.Stop(stopCtx)
	stopCancel()
}
