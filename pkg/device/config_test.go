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

package device

import (
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestDatastorePartition(t *testing.T) {
	assert.Equal(t, "devices", DatastorePartition)
}

func TestDefaultConfig(t *testing.T) {
	config := DefaultConfig

	require.NotNil(t, config.QuicBaaS)
	assert.Equal(t, "pebble", config.QuicBaaS.StorageBackend)
	assert.Equal(t, "trusted-data/quicbaas", config.QuicBaaS.DataDir)
	assert.Equal(t, "trusted-data/quicbaas/wal", config.QuicBaaS.WALDir)
	assert.Equal(t, uint64(1), config.QuicBaaS.NodeID)
	assert.Equal(t, int64(64*1024*1024), config.QuicBaaS.CacheSize)
	assert.Equal(t, "warn", config.QuicBaaS.LogLevel)
	assert.Equal(t, quicbaas.ConsistencyLinearizable, config.QuicBaaS.ConsistencyLevel)

	// Verify new ShardID and Partition fields
	assert.Equal(t, uint64(0), config.ShardID)
	assert.Equal(t, "devices", config.Partition)
}
