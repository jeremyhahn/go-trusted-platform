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

package daemon

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/appservices"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/cache"
)

// CacheGRPCService implements platformv1.CacheServiceServer over the
// appservices cache service.
type CacheGRPCService struct {
	platformv1.UnimplementedCacheServiceServer

	service *appservices.CacheService
	logger  *logging.Logger
}

// NewCacheGRPCService returns the cache gRPC service. A nil service answers
// every call with the not-configured status.
func NewCacheGRPCService(logger *logging.Logger, service *appservices.CacheService) *CacheGRPCService {
	if logger == nil {
		logger = logging.DefaultLogger()
	}
	if service == nil {
		service = appservices.NewCacheService(nil)
	}
	return &CacheGRPCService{service: service, logger: logger}
}

// GetStats returns the cache statistics.
func (s *CacheGRPCService) GetStats(ctx context.Context, req *platformv1.GetCacheStatsRequest) (*platformv1.GetCacheStatsResponse, error) {
	stats, err := s.service.Stats(ctx, req.GetEntityType())
	if err != nil {
		return nil, appServiceError(s.logger, "cache stats", err)
	}
	return &platformv1.GetCacheStatsResponse{
		HitRate:   stats.HitRate,
		Size:      stats.Size,
		MaxSize:   stats.MaxSize,
		Evictions: stats.Evictions,
		Hits:      stats.Hits,
		Misses:    stats.Misses,
	}, nil
}

// Clear removes cache entries.
func (s *CacheGRPCService) Clear(ctx context.Context, req *platformv1.ClearCacheRequest) (*platformv1.ClearCacheResponse, error) {
	resp, err := s.service.Clear(ctx, req.GetEntityType(), req.GetAll())
	if err != nil {
		return nil, appServiceError(s.logger, "cache clear", err)
	}
	return &platformv1.ClearCacheResponse{EntriesCleared: resp.EntriesCleared}, nil
}

// GetConfig returns the cache configuration.
func (s *CacheGRPCService) GetConfig(ctx context.Context, _ *platformv1.GetCacheConfigRequest) (*platformv1.GetCacheConfigResponse, error) {
	config, err := s.service.Config(ctx)
	if err != nil {
		return nil, appServiceError(s.logger, "cache get config", err)
	}
	return &platformv1.GetCacheConfigResponse{Config: cacheConfigToPb(config)}, nil
}

// UpdateConfig changes the configuration fields that are set.
func (s *CacheGRPCService) UpdateConfig(ctx context.Context, req *platformv1.UpdateCacheConfigRequest) (*platformv1.UpdateCacheConfigResponse, error) {
	update := &cache.UpdateCacheConfigRequest{}
	if req.L1Size != nil {
		size := int(req.GetL1Size())
		update.L1Size = &size
	}
	if req.L1TtlMs != nil {
		ttl := appDuration(req.GetL1TtlMs())
		update.L1TTL = &ttl
	}
	if req.CleanupIntervalMs != nil {
		interval := appDuration(req.GetCleanupIntervalMs())
		update.CleanupInterval = &interval
	}
	resp, err := s.service.UpdateConfig(ctx, update)
	if err != nil {
		return nil, appServiceError(s.logger, "cache update config", err)
	}
	return &platformv1.UpdateCacheConfigResponse{
		Updated: resp.Updated,
		Config:  cacheConfigToPb(resp.NewConfig),
	}, nil
}

func cacheConfigToPb(config *cache.GetCacheConfigResponse) *platformv1.CacheConfig {
	if config == nil {
		return nil
	}
	return &platformv1.CacheConfig{
		L1Size:            int64(config.L1Size),
		L1TtlMs:           config.L1TTL.Milliseconds(),
		CleanupIntervalMs: config.CleanupInterval.Milliseconds(),
		Enabled:           config.Enabled,
	}
}
