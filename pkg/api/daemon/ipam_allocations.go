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

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
)

// activeAllocations returns the allocations that still hold an address, in
// pool poolID or, when poolID is empty, in every pool. The gRPC, QUIC, REST
// and MCP gateway services all list allocations through it.
//
// Only active and reserved allocations are listed. Released allocations are
// excluded: the memory backend keeps them for audit, but their address is free
// again. gRPC and QUIC filtered them and REST did not, so an address released
// over REST was still listed as allocated (#730). Expired allocations are
// excluded for the same reason: IPAM expiry for inactivity frees the address
// but keeps a zero ExpiresAt, so only the status tells the gateway's VTEP
// admission it no longer belongs to the device (#765). MCP read one pool
// unfiltered, so it listed a released address and answered an empty pool id
// "pool not found" (#949).
// A pool that cannot be read while listing every pool is skipped, as all three
// services did before.
func activeAllocations(ctx context.Context, alloc ipam.Allocator, poolID string) ([]*ipam.Allocation, error) {
	var all []*ipam.Allocation
	if poolID != "" {
		pool, err := alloc.GetAllocationsByPool(ctx, poolID)
		if err != nil {
			return nil, err
		}
		all = pool
	} else {
		pools, err := alloc.ListPools(ctx)
		if err != nil {
			return nil, err
		}
		for _, p := range pools {
			pool, err := alloc.GetAllocationsByPool(ctx, p.ID)
			if err != nil {
				continue
			}
			all = append(all, pool...)
		}
	}
	active := make([]*ipam.Allocation, 0, len(all))
	for _, a := range all {
		if a.Status == ipam.AllocationStatusActive || a.Status == ipam.AllocationStatusReserved {
			active = append(active, a)
		}
	}
	return active, nil
}
