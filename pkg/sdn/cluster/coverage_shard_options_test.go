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

package cluster

import (
	"context"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestWithBridgeShard(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewBridgeDAO(mock, logger,
		WithBridgeRequestTimeout(5*time.Second),
		WithBridgeShard(42),
	)
	assert.NotNil(t, dao)
	assert.Equal(t, uint64(42), dao.shardID)
}

func TestWithFlowShard(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewFlowDAO(mock, logger,
		WithFlowRequestTimeout(5*time.Second),
		WithFlowShard(99),
	)
	assert.NotNil(t, dao)
	assert.Equal(t, uint64(99), dao.shardID)
}

func TestWithPortShard(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewPortDAO(mock, logger,
		WithPortRequestTimeout(5*time.Second),
		WithPortShard(7),
	)
	assert.NotNil(t, dao)
	assert.Equal(t, uint64(7), dao.shardID)
}

func TestWithRemoteMACShard(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewRemoteMACDAO(mock, logger,
		WithRemoteMACRequestTimeout(5*time.Second),
		WithRemoteMACShard(15),
	)
	assert.NotNil(t, dao)
	assert.Equal(t, uint64(15), dao.shardID)
}

func TestWithTunnelShard(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewTunnelDAO(mock, logger,
		WithTunnelRequestTimeout(5*time.Second),
		WithTunnelShard(33),
	)
	assert.NotNil(t, dao)
	assert.Equal(t, uint64(33), dao.shardID)
}

func TestWithVLANShard(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewVLANDAO(mock, logger,
		WithVLANRequestTimeout(5*time.Second),
		WithVLANShard(55),
	)
	assert.NotNil(t, dao)
	assert.Equal(t, uint64(55), dao.shardID)
}

func TestWithVNIMappingShard(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewVNIMappingDAO(mock, logger,
		WithVNIMappingRequestTimeout(5*time.Second),
		WithVNIMappingShard(128),
	)
	assert.NotNil(t, dao)
	assert.Equal(t, uint64(128), dao.shardID)
}

func TestWithVTEPShard(t *testing.T) {
	mock := quicbaas.NewMockStorage()
	require.NoError(t, mock.Start(context.Background()))
	defer mock.Stop(context.Background())

	logger := logging.DefaultLogger()
	dao := NewVTEPDAO(mock, logger,
		WithVTEPRequestTimeout(5*time.Second),
		WithVTEPShard(256),
	)
	assert.NotNil(t, dao)
	assert.Equal(t, uint64(256), dao.shardID)
}
