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

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/cache"
)

// CacheService manages the cache of the composed SDK.
type CacheService struct {
	resolver Resolver[cache.Client]
}

// NewCacheService returns a CacheService that reaches the SDK's Cache group
// through resolver.
func NewCacheService(resolver Resolver[cache.Client]) *CacheService {
	return &CacheService{resolver: resolver}
}

// Stats returns the cache statistics, of the whole cache when entityType is
// empty.
func (s *CacheService) Stats(ctx context.Context, entityType string) (*cache.GetCacheStatsResponse, error) {
	client, err := resolve(ServiceCache, s.resolver)
	if err != nil {
		return nil, err
	}
	resp, err := client.GetCacheStats(ctx, &cache.GetCacheStatsRequest{EntityType: entityType})
	return resp, callFailed(ServiceCache, "stats", err)
}

// Clear removes every entry when all is set, or the entries of entityType.
// Exactly one of the two must be given, so an empty request never clears
// the whole cache by accident.
func (s *CacheService) Clear(ctx context.Context, entityType string, all bool) (*cache.ClearCacheResponse, error) {
	if all == (entityType != "") {
		return nil, ErrInvalidArgument{
			Service: ServiceCache,
			Field:   "entity_type",
			Reason:  "give exactly one of an entity type and all",
		}
	}
	client, err := resolve(ServiceCache, s.resolver)
	if err != nil {
		return nil, err
	}
	resp, err := client.ClearCache(ctx, &cache.ClearCacheRequest{EntityType: entityType, All: all})
	return resp, callFailed(ServiceCache, "clear", err)
}

// Config returns the cache configuration.
func (s *CacheService) Config(ctx context.Context) (*cache.GetCacheConfigResponse, error) {
	client, err := resolve(ServiceCache, s.resolver)
	if err != nil {
		return nil, err
	}
	resp, err := client.GetCacheConfig(ctx, &cache.GetCacheConfigRequest{})
	return resp, callFailed(ServiceCache, "get config", err)
}

// UpdateConfig changes the configuration fields that are set. At least one
// must be set, and none may be negative.
func (s *CacheService) UpdateConfig(ctx context.Context, req *cache.UpdateCacheConfigRequest) (*cache.UpdateCacheConfigResponse, error) {
	if err := validateCacheUpdate(req); err != nil {
		return nil, err
	}
	client, err := resolve(ServiceCache, s.resolver)
	if err != nil {
		return nil, err
	}
	resp, err := client.UpdateCacheConfig(ctx, req)
	return resp, callFailed(ServiceCache, "update config", err)
}

func validateCacheUpdate(req *cache.UpdateCacheConfigRequest) error {
	if req == nil || (req.L1Size == nil && req.L1TTL == nil && req.CleanupInterval == nil) {
		return ErrInvalidArgument{Service: ServiceCache, Field: "config", Reason: "set at least one field"}
	}
	if req.L1Size != nil {
		if err := requireNotNegative(ServiceCache, "l1_size", *req.L1Size); err != nil {
			return err
		}
	}
	if req.L1TTL != nil {
		if err := requireNotNegative(ServiceCache, "l1_ttl", *req.L1TTL); err != nil {
			return err
		}
	}
	if req.CleanupInterval != nil {
		return requireNotNegative(ServiceCache, "cleanup_interval", *req.CleanupInterval)
	}
	return nil
}
