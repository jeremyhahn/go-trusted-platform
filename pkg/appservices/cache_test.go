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

package appservices

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/cache"
)

var errSDK = errors.New("sdk failure")

type fakeCacheClient struct {
	err       error
	statsReq  *cache.GetCacheStatsRequest
	clearReq  *cache.ClearCacheRequest
	updateReq *cache.UpdateCacheConfigRequest
}

func (f *fakeCacheClient) GetCacheStats(_ context.Context, req *cache.GetCacheStatsRequest) (*cache.GetCacheStatsResponse, error) {
	f.statsReq = req
	if f.err != nil {
		return nil, f.err
	}
	return &cache.GetCacheStatsResponse{Size: 7, Hits: 3}, nil
}

func (f *fakeCacheClient) ClearCache(_ context.Context, req *cache.ClearCacheRequest) (*cache.ClearCacheResponse, error) {
	f.clearReq = req
	if f.err != nil {
		return nil, f.err
	}
	return &cache.ClearCacheResponse{EntriesCleared: 4}, nil
}

func (f *fakeCacheClient) GetCacheConfig(context.Context, *cache.GetCacheConfigRequest) (*cache.GetCacheConfigResponse, error) {
	if f.err != nil {
		return nil, f.err
	}
	return &cache.GetCacheConfigResponse{L1Size: 100, Enabled: true}, nil
}

func (f *fakeCacheClient) UpdateCacheConfig(_ context.Context, req *cache.UpdateCacheConfigRequest) (*cache.UpdateCacheConfigResponse, error) {
	f.updateReq = req
	if f.err != nil {
		return nil, f.err
	}
	return &cache.UpdateCacheConfigResponse{Updated: true}, nil
}

func cacheServiceWith(client *fakeCacheClient) *CacheService {
	return NewCacheService(func() cache.Client { return client })
}

// assertCallFailed checks that err wraps the SDK failure of op.
func assertCallFailed(t *testing.T, err error, service, op string) {
	t.Helper()
	var failed ErrCallFailed
	require.ErrorAs(t, err, &failed)
	assert.Equal(t, service, failed.Service)
	assert.Equal(t, op, failed.Op)
	assert.ErrorIs(t, err, errSDK)
}

// assertInvalid checks that err refuses field before the SDK is reached.
func assertInvalid(t *testing.T, err error, field string) {
	t.Helper()
	var invalid ErrInvalidArgument
	require.ErrorAs(t, err, &invalid)
	assert.Equal(t, field, invalid.Field)
}

func TestCacheService_NotConfigured(t *testing.T) {
	services := map[string]*CacheService{
		"no resolver":         NewCacheService(nil),
		"resolver yields nil": NewCacheService(func() cache.Client { return nil }),
	}
	size := 1
	for name, svc := range services {
		t.Run(name, func(t *testing.T) {
			ctx := context.Background()
			_, statsErr := svc.Stats(ctx, "")
			_, clearErr := svc.Clear(ctx, "", true)
			_, configErr := svc.Config(ctx)
			_, updateErr := svc.UpdateConfig(ctx, &cache.UpdateCacheConfigRequest{L1Size: &size})
			for _, err := range []error{statsErr, clearErr, configErr, updateErr} {
				assert.Equal(t, ErrNotConfigured{Service: ServiceCache}, err)
			}
		})
	}
}

func TestCacheService_Stats(t *testing.T) {
	client := &fakeCacheClient{}
	resp, err := cacheServiceWith(client).Stats(context.Background(), "users")
	require.NoError(t, err)
	assert.Equal(t, uint64(7), resp.Size)
	assert.Equal(t, "users", client.statsReq.EntityType)
}

func TestCacheService_StatsSDKError(t *testing.T) {
	_, err := cacheServiceWith(&fakeCacheClient{err: errSDK}).Stats(context.Background(), "")
	assertCallFailed(t, err, ServiceCache, "stats")
}

func TestCacheService_Clear(t *testing.T) {
	client := &fakeCacheClient{}
	svc := cacheServiceWith(client)

	resp, err := svc.Clear(context.Background(), "users", false)
	require.NoError(t, err)
	assert.Equal(t, uint64(4), resp.EntriesCleared)
	assert.Equal(t, &cache.ClearCacheRequest{EntityType: "users"}, client.clearReq)

	_, err = svc.Clear(context.Background(), "", true)
	require.NoError(t, err)
	assert.Equal(t, &cache.ClearCacheRequest{All: true}, client.clearReq)
}

func TestCacheService_ClearRefusesAmbiguousRequest(t *testing.T) {
	client := &fakeCacheClient{}
	svc := cacheServiceWith(client)

	_, err := svc.Clear(context.Background(), "", false)
	assertInvalid(t, err, "entity_type")
	_, err = svc.Clear(context.Background(), "users", true)
	assertInvalid(t, err, "entity_type")
	assert.Nil(t, client.clearReq, "an invalid clear must not reach the SDK")

	_, err = cacheServiceWith(&fakeCacheClient{err: errSDK}).Clear(context.Background(), "", true)
	assertCallFailed(t, err, ServiceCache, "clear")
}

func TestCacheService_Config(t *testing.T) {
	resp, err := cacheServiceWith(&fakeCacheClient{}).Config(context.Background())
	require.NoError(t, err)
	assert.Equal(t, 100, resp.L1Size)

	_, err = cacheServiceWith(&fakeCacheClient{err: errSDK}).Config(context.Background())
	assertCallFailed(t, err, ServiceCache, "get config")
}

func TestCacheService_UpdateConfig(t *testing.T) {
	client := &fakeCacheClient{}
	ttl := time.Minute
	req := &cache.UpdateCacheConfigRequest{L1TTL: &ttl}

	resp, err := cacheServiceWith(client).UpdateConfig(context.Background(), req)
	require.NoError(t, err)
	assert.True(t, resp.Updated)
	assert.Same(t, req, client.updateReq)

	_, err = cacheServiceWith(&fakeCacheClient{err: errSDK}).UpdateConfig(context.Background(), req)
	assertCallFailed(t, err, ServiceCache, "update config")
}

func TestCacheService_UpdateConfigRefusesInvalidRequest(t *testing.T) {
	negativeSize := -1
	negativeDuration := -time.Second
	cases := map[string]struct {
		req   *cache.UpdateCacheConfigRequest
		field string
	}{
		"nil request":       {nil, "config"},
		"no field set":      {&cache.UpdateCacheConfigRequest{}, "config"},
		"negative size":     {&cache.UpdateCacheConfigRequest{L1Size: &negativeSize}, "l1_size"},
		"negative ttl":      {&cache.UpdateCacheConfigRequest{L1TTL: &negativeDuration}, "l1_ttl"},
		"negative interval": {&cache.UpdateCacheConfigRequest{CleanupInterval: &negativeDuration}, "cleanup_interval"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			client := &fakeCacheClient{}
			_, err := cacheServiceWith(client).UpdateConfig(context.Background(), tc.req)
			assertInvalid(t, err, tc.field)
			assert.Nil(t, client.updateReq)
		})
	}
}

func TestErrors_Messages(t *testing.T) {
	assert.Contains(t, ErrNotConfigured{Service: ServiceCache}.Error(), "cache is not served")
	assert.Equal(t, "scheduler: invalid name: is required",
		ErrInvalidArgument{Service: ServiceScheduler, Field: "name", Reason: "is required"}.Error())
	failed := ErrCallFailed{Service: ServiceMessaging, Op: "publish", Cause: errSDK}
	assert.Equal(t, "messaging publish failed: sdk failure", failed.Error())
	assert.Equal(t, errSDK, failed.Unwrap())
}
