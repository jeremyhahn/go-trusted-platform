//go:build integration

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

package sdn

import (
	"context"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// createIPAMPoolRPC creates a pool over the GatewayService the gRPC and Unix
// overlay adapters share. Both transports serve the same RPCs, so the request
// mapping lives once here and each adapter only wraps the error in its own
// type. The adapters used to return "not implemented" on the stated grounds
// that the gateway proto has no pool RPCs; it does (CreateIPAMPool,
// DeleteIPAMPool), and TestIPAMPoolCRUDMultiProtocol drives them (#730).
func createIPAMPoolRPC(ctx context.Context, client platformv1.GatewayServiceClient, opts IPAMPoolCreateOptions) (*IPAMPoolCreateResult, error) {
	resp, err := client.CreateIPAMPool(ctx, &platformv1.CreateIPAMPoolRequest{
		Name:                      opts.Name,
		Cidr:                      opts.CIDR,
		Gateway:                   opts.Gateway,
		DefaultLeaseDurationNanos: opts.LeaseDuration.Nanoseconds(),
	})
	if err != nil {
		return nil, err
	}
	pool := resp.GetPool()
	return &IPAMPoolCreateResult{
		ID:        pool.GetId(),
		Name:      pool.GetName(),
		CIDR:      pool.GetCidr(),
		CreatedAt: protoTimestampToTime(pool.GetCreatedAt()),
	}, nil
}

// deleteIPAMPoolRPC deletes a pool over the shared GatewayService.
func deleteIPAMPoolRPC(ctx context.Context, client platformv1.GatewayServiceClient, poolID string) (*IPAMPoolDeleteResult, error) {
	if _, err := client.DeleteIPAMPool(ctx, &platformv1.DeleteIPAMPoolRequest{Id: poolID}); err != nil {
		return nil, err
	}
	return &IPAMPoolDeleteResult{ID: poolID, Deleted: true}, nil
}

// ipamPoolListFromProto converts the pools the gateway returns -- over gRPC,
// Unix, or printed by `platformctl sdn ipam pool list` -- into the suite's
// list result. One conversion keeps the three adapters from drifting apart.
func ipamPoolListFromProto(pools []*platformv1.IPAMPool) *IPAMPoolListResult {
	out := make([]IPAMPoolInfo, 0, len(pools))
	for _, p := range pools {
		var utilizationPct float64
		if p.GetTotal() > 0 {
			utilizationPct = float64(p.GetAllocated()) / float64(p.GetTotal()) * 100
		}
		out = append(out, IPAMPoolInfo{
			ID:             p.GetId(),
			Name:           p.GetName(),
			CIDR:           p.GetCidr(),
			Gateway:        p.GetGateway(),
			TotalIPs:       int64(p.GetTotal()),
			AllocatedIPs:   int64(p.GetAllocated()),
			AvailableIPs:   int64(p.GetAvailable()),
			UtilizationPct: utilizationPct,
			LeaseDuration:  time.Duration(p.GetDefaultLeaseDurationNanos()),
		})
	}
	return &IPAMPoolListResult{Pools: out, TotalCount: len(out)}
}
