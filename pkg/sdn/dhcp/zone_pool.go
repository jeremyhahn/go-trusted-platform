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

package dhcp

import (
	"context"
	"fmt"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
)

// ErrNoPoolForZone indicates that no IPAM pool is registered for the requested
// zone. The caller should fall back to an explicit pool binding or fail if no
// explicit binding is available.
type ErrNoPoolForZone struct {
	// Zone is the zone name that had no matching pool.
	Zone string
}

// Error implements the error interface.
func (e ErrNoPoolForZone) Error() string {
	return fmt.Sprintf("dhcp: no ipam pool found for zone %q", e.Zone)
}

// ErrAmbiguousZonePool indicates that more than one IPAM pool matches the
// requested zone. The caller must supply an explicit pool binding to resolve
// the ambiguity.
type ErrAmbiguousZonePool struct {
	// Zone is the zone name that matched multiple pools.
	Zone string
	// Count is the number of pools that matched.
	Count int
}

// Error implements the error interface.
func (e ErrAmbiguousZonePool) Error() string {
	return fmt.Sprintf("dhcp: zone %q matches %d ipam pools; set an explicit pool binding to resolve ambiguity", e.Zone, e.Count)
}

// PoolResolution describes how a DHCP pool was selected.
type PoolResolution int

const (
	// PoolResolutionExplicit indicates the pool was selected via an explicit
	// PoolID or PoolStart/PoolEnd binding (highest precedence).
	PoolResolutionExplicit PoolResolution = iota

	// PoolResolutionZone indicates the pool was selected by matching the
	// serving network's zone via ListPoolsByZone (derived).
	PoolResolutionZone

	// PoolResolutionSegment indicates the pool was selected via a legacy
	// Segment name binding (lowest precedence, kept for backward compatibility).
	PoolResolutionSegment
)

// ResolvePoolForZone selects an IPAM pool ID for a DHCP service using the
// following precedence rules (highest first):
//
//  1. Explicit: when explicitPoolID is non-empty, it is returned as-is
//     (the caller has already specified the pool directly — no lookup needed).
//  2. Zone-derived: when zone is non-empty, Allocator.ListPoolsByZone is called
//     and the single matching pool is returned. Multiple matches return
//     ErrAmbiguousZonePool; zero matches return ErrNoPoolForZone.
//  3. Segment fallback: when segmentName is non-empty, the allocator's
//     GetPoolByName is called with segmentName as the pool name. This preserves
//     backward compatibility with templates that set gateway.dhcp.segment.
//
// If none of the inputs resolve to a pool, ErrPoolIDRequired is returned.
//
// The resolution method is returned so the caller can log or audit which path
// was taken.
func ResolvePoolForZone(
	ctx context.Context,
	alloc ipam.Allocator,
	explicitPoolID string,
	zone string,
	segmentName string,
) (poolID string, resolution PoolResolution, err error) {
	// 1. Explicit binding wins unconditionally.
	if explicitPoolID != "" {
		return explicitPoolID, PoolResolutionExplicit, nil
	}

	// 2. Zone-derived: call ListPoolsByZone.
	if zone != "" {
		pools, listErr := alloc.ListPoolsByZone(ctx, zone)
		if listErr != nil {
			return "", 0, listErr
		}
		switch len(pools) {
		case 0:
			return "", 0, ErrNoPoolForZone{Zone: zone}
		case 1:
			return pools[0].ID, PoolResolutionZone, nil
		default:
			return "", 0, ErrAmbiguousZonePool{Zone: zone, Count: len(pools)}
		}
	}

	// 3. Segment legacy fallback.
	if segmentName != "" {
		pool, getErr := alloc.GetPoolByName(ctx, segmentName)
		if getErr != nil {
			return "", 0, getErr
		}
		return pool.ID, PoolResolutionSegment, nil
	}

	return "", 0, ErrPoolIDRequired
}
