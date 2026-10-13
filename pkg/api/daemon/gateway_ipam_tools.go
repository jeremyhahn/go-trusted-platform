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
	"fmt"
	"net/netip"
	"time"

	"github.com/google/uuid"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
)

// gatewayIPAMTools serves the MCP gateway_ipam_* tools from the IPAM
// allocator platformd owns. It is embedded by both MCP service providers
// so neither carries its own copy (#65).
type gatewayIPAMTools struct {
	ipam ipam.Allocator
}

// SetIPAMAllocator wires the IPAM allocator the tools answer from.
func (t *gatewayIPAMTools) SetIPAMAllocator(allocator ipam.Allocator) {
	t.ipam = allocator
}

// requireIPAM returns an error when the IPAM allocator is not configured.
func (t gatewayIPAMTools) requireIPAM() error {
	if t.ipam == nil {
		return ErrServiceNotAvailable{Service: "ipam"}
	}
	return nil
}

// GatewayIPAMPools lists IPAM pools, optionally filtered by zone.
func (t gatewayIPAMTools) GatewayIPAMPools(ctx context.Context, filterZone string) ([]interface{}, error) {
	if err := t.requireIPAM(); err != nil {
		return nil, err
	}
	var pools []*ipam.Pool
	var err error
	if filterZone != "" {
		pools, err = t.ipam.ListPoolsByZone(ctx, filterZone)
	} else {
		pools, err = t.ipam.ListPools(ctx)
	}
	if err != nil {
		return nil, err
	}
	out := make([]interface{}, 0, len(pools))
	for _, p := range pools {
		out = append(out, p)
	}
	return out, nil
}

// GatewayIPAMPoolGet retrieves a single IPAM pool by ID.
func (t gatewayIPAMTools) GatewayIPAMPoolGet(ctx context.Context, poolID string) (interface{}, error) {
	if err := t.requireIPAM(); err != nil {
		return nil, err
	}
	return t.ipam.GetPool(ctx, poolID)
}

// GatewayIPAMAllocate allocates an IP address from a pool.
func (t gatewayIPAMTools) GatewayIPAMAllocate(ctx context.Context, poolID string, deviceID string, hostname string) (interface{}, error) {
	if err := t.requireIPAM(); err != nil {
		return nil, err
	}
	alloc, err := t.ipam.Allocate(ctx, &ipam.AllocationRequest{
		PoolID:   poolID,
		DeviceID: deviceID,
		Hostname: hostname,
	})
	if err != nil {
		return nil, err
	}
	return alloc, nil
}

// GatewayIPAMRelease releases an IP address back to the pool.
func (t gatewayIPAMTools) GatewayIPAMRelease(ctx context.Context, ipStr string) error {
	if err := t.requireIPAM(); err != nil {
		return err
	}
	addr, parseErr := netip.ParseAddr(ipStr)
	if parseErr != nil {
		return &WrappedError{Msg: fmt.Sprintf("invalid ip address %q", ipStr), Err: parseErr}
	}
	return t.ipam.Release(ctx, addr)
}

// GatewayIPAMAllocations lists all IP address allocations for a pool.
func (t gatewayIPAMTools) GatewayIPAMAllocations(ctx context.Context, poolID string) ([]interface{}, error) {
	if err := t.requireIPAM(); err != nil {
		return nil, err
	}
	allocs, err := t.ipam.GetAllocationsByPool(ctx, poolID)
	if err != nil {
		return nil, err
	}
	out := make([]interface{}, 0, len(allocs))
	for _, a := range allocs {
		out = append(out, a)
	}
	return out, nil
}

// GatewayIPAMPoolCreate creates a new IPAM pool.
func (t gatewayIPAMTools) GatewayIPAMPoolCreate(ctx context.Context, req *mcp.IPAMPoolCreateRequest) (interface{}, error) {
	if err := t.requireIPAM(); err != nil {
		return nil, err
	}
	cidr, err := netip.ParsePrefix(req.CIDR)
	if err != nil {
		return nil, &WrappedError{Msg: fmt.Sprintf("invalid cidr %q", req.CIDR), Err: err}
	}
	pool := &ipam.Pool{
		ID:                   uuid.New().String(),
		Name:                 req.Name,
		CIDR:                 cidr.Masked(),
		Zone:                 req.Zone,
		Description:          req.Description,
		DefaultLeaseDuration: time.Duration(req.LeaseDurationSeconds) * time.Second,
	}
	if req.Gateway != "" {
		gw, parseErr := netip.ParseAddr(req.Gateway)
		if parseErr != nil {
			return nil, &WrappedError{Msg: fmt.Sprintf("invalid gateway %q", req.Gateway), Err: parseErr}
		}
		pool.Gateway = gw
	}
	reserved, rangeStart, rangeEnd, err := ipam.ParseWindow(req.Reserved, req.RangeStart, req.RangeEnd)
	if err != nil {
		return nil, err
	}
	pool.Reserved = reserved
	pool.RangeStart = rangeStart
	pool.RangeEnd = rangeEnd
	if err := t.ipam.CreatePool(ctx, pool); err != nil {
		return nil, err
	}
	return t.ipam.GetPool(ctx, pool.ID)
}

// GatewayIPAMPoolUpdate updates mutable fields of an IPAM pool; empty
// fields keep their current values. CIDR is immutable.
func (t gatewayIPAMTools) GatewayIPAMPoolUpdate(ctx context.Context, poolID string, req *mcp.IPAMPoolUpdateRequest) (interface{}, error) {
	if err := t.requireIPAM(); err != nil {
		return nil, err
	}
	pool, err := t.ipam.GetPool(ctx, poolID)
	if err != nil {
		return nil, err
	}
	if req.Name != "" {
		pool.Name = req.Name
	}
	if req.Zone != "" {
		pool.Zone = req.Zone
	}
	if req.Description != "" {
		pool.Description = req.Description
	}
	if req.Gateway != "" {
		gw, parseErr := netip.ParseAddr(req.Gateway)
		if parseErr != nil {
			return nil, &WrappedError{Msg: fmt.Sprintf("invalid gateway %q", req.Gateway), Err: parseErr}
		}
		pool.Gateway = gw
	}
	if req.LeaseDurationSeconds > 0 {
		pool.DefaultLeaseDuration = time.Duration(req.LeaseDurationSeconds) * time.Second
	}
	if err := pool.ApplyWindowUpdate(req.Reserved, req.RangeStart, req.RangeEnd); err != nil {
		return nil, err
	}
	if err := t.ipam.UpdatePool(ctx, pool); err != nil {
		return nil, err
	}
	return t.ipam.GetPool(ctx, poolID)
}

// GatewayIPAMPoolDelete deletes an IPAM pool.
func (t gatewayIPAMTools) GatewayIPAMPoolDelete(ctx context.Context, poolID string) error {
	if err := t.requireIPAM(); err != nil {
		return err
	}
	return t.ipam.DeletePool(ctx, poolID)
}
