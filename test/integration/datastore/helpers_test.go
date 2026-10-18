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

// Package datastore provides integration tests for the QuicBaaS datastore DAOs.
package datastore

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/stretchr/testify/require"
)

// testTimeout is the default timeout for test operations.
const testTimeout = 30 * time.Second

// startupTimeout is the timeout for factory startup operations.
const startupTimeout = 60 * time.Second

// shutdownTimeout is the timeout for factory shutdown operations.
const shutdownTimeout = 10 * time.Second

// newIntegrationClient creates a new QuicBaaS Factory for integration testing.
// It returns the Factory's Storage interface and a cleanup function that must be called with defer.
// The Storage interface is compatible with DAO creation.
// Uses in-memory storage which is fast and doesn't require Raft.
func newIntegrationClient(t *testing.T) (quicbaas.Storage, func()) {
	t.Helper()

	cfg := quicbaas.MemoryTestConfig(t)
	cfg.Transport = quicbaas.TransportEmbedded
	logger := logging.DefaultLogger()

	factory, err := quicbaas.NewFactory(cfg, logger, nil)
	require.NoError(t, err, "Failed to create QuicBaaS factory")

	ctx, cancel := context.WithTimeout(context.Background(), startupTimeout)
	defer cancel()

	err = factory.Start(ctx)
	require.NoError(t, err, "Failed to start QuicBaaS factory")

	cleanup := func() {
		ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()
		if err := factory.Stop(ctx); err != nil {
			t.Logf("Warning: factory stop error: %v", err)
		}
	}

	// Get the storage from the factory
	storage := factory.Storage()
	require.NotNil(t, storage, "Factory storage is nil")

	return storage, cleanup
}

// testContext returns a context with the test timeout.
func testContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), testTimeout)
}

// idCounter makes entity names unique across tests and goroutines in this package.
var idCounter atomic.Uint64

// uniqueID returns prefix with a process-unique suffix, safe to call concurrently.
func uniqueID(prefix string) string {
	return fmt.Sprintf("%s-%d", prefix, idCounter.Add(1))
}
