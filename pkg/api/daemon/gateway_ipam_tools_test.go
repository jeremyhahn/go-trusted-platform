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
	"errors"
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam/backends"
)

// newIPAMToolsWithPool returns IPAM tools over an in-memory allocator that
// holds one pool in the "lab" zone.
func newIPAMToolsWithPool(t *testing.T) (gatewayIPAMTools, *ipam.Pool) {
	t.Helper()
	var tools gatewayIPAMTools
	tools.SetIPAMAllocator(backends.NewMemoryBackend())
	out, err := tools.GatewayIPAMPoolCreate(context.Background(), &mcp.IPAMPoolCreateRequest{
		Name:                 "lab",
		CIDR:                 "10.9.0.7/24",
		Gateway:              "10.9.0.1",
		Zone:                 "lab",
		Description:          "lab pool",
		LeaseDurationSeconds: 3600,
	})
	require.NoError(t, err)
	pool, ok := out.(*ipam.Pool)
	require.True(t, ok, "create returns the stored pool, got %T", out)
	return tools, pool
}

func TestGatewayIPAMTools_PoolCreate(t *testing.T) {
	t.Run("creates the pool with a masked CIDR", func(t *testing.T) {
		_, pool := newIPAMToolsWithPool(t)
		assert.NotEmpty(t, pool.ID)
		assert.Equal(t, netip.MustParsePrefix("10.9.0.0/24"), pool.CIDR)
		assert.Equal(t, netip.MustParseAddr("10.9.0.1"), pool.Gateway)
		assert.Equal(t, time.Hour, pool.DefaultLeaseDuration)
	})

	t.Run("refuses a malformed cidr or gateway", func(t *testing.T) {
		tools, _ := newIPAMToolsWithPool(t)
		ctx := context.Background()
		var wrapped *WrappedError

		_, err := tools.GatewayIPAMPoolCreate(ctx, &mcp.IPAMPoolCreateRequest{Name: "x", CIDR: "not-a-cidr"})
		assert.True(t, errors.As(err, &wrapped), "got %T: %v", err, err)

		_, err = tools.GatewayIPAMPoolCreate(ctx, &mcp.IPAMPoolCreateRequest{Name: "x", CIDR: "10.8.0.0/24", Gateway: "nope"})
		assert.True(t, errors.As(err, &wrapped), "got %T: %v", err, err)
	})
}

func TestGatewayIPAMTools_Pools(t *testing.T) {
	tools, pool := newIPAMToolsWithPool(t)
	ctx := context.Background()

	t.Run("lists every pool and filters by zone", func(t *testing.T) {
		all, err := tools.GatewayIPAMPools(ctx, "")
		require.NoError(t, err)
		require.Len(t, all, 1)
		assert.Equal(t, pool.ID, all[0].(*ipam.Pool).ID)

		inZone, err := tools.GatewayIPAMPools(ctx, "lab")
		require.NoError(t, err)
		assert.Len(t, inZone, 1)
	})

	t.Run("a zone with no pools lists none", func(t *testing.T) {
		none, err := tools.GatewayIPAMPools(ctx, "dmz")
		require.NoError(t, err)
		assert.Empty(t, none)
	})
}

func TestGatewayIPAMTools_PoolGet(t *testing.T) {
	tools, pool := newIPAMToolsWithPool(t)
	ctx := context.Background()

	t.Run("returns the pool", func(t *testing.T) {
		out, err := tools.GatewayIPAMPoolGet(ctx, pool.ID)
		require.NoError(t, err)
		assert.Equal(t, "lab", out.(*ipam.Pool).Name)
	})

	t.Run("an unknown pool is an error", func(t *testing.T) {
		_, err := tools.GatewayIPAMPoolGet(ctx, "missing")
		assert.Error(t, err)
	})
}

func TestGatewayIPAMTools_PoolUpdate(t *testing.T) {
	ctx := context.Background()

	t.Run("changes only the fields given", func(t *testing.T) {
		tools, pool := newIPAMToolsWithPool(t)

		out, err := tools.GatewayIPAMPoolUpdate(ctx, pool.ID, &mcp.IPAMPoolUpdateRequest{Description: "renamed"})
		require.NoError(t, err)
		updated := out.(*ipam.Pool)
		assert.Equal(t, "renamed", updated.Description)
		assert.Equal(t, "lab", updated.Zone, "an omitted zone is kept")
		assert.Equal(t, time.Hour, updated.DefaultLeaseDuration, "an omitted lease is kept")
	})

	t.Run("refuses an unknown pool or a malformed gateway", func(t *testing.T) {
		tools, pool := newIPAMToolsWithPool(t)

		_, err := tools.GatewayIPAMPoolUpdate(ctx, "missing", &mcp.IPAMPoolUpdateRequest{Name: "x"})
		assert.Error(t, err)

		var wrapped *WrappedError
		_, err = tools.GatewayIPAMPoolUpdate(ctx, pool.ID, &mcp.IPAMPoolUpdateRequest{Gateway: "nope"})
		assert.True(t, errors.As(err, &wrapped), "got %T: %v", err, err)
	})
}

func TestGatewayIPAMTools_AllocateReleaseAllocations(t *testing.T) {
	ctx := context.Background()

	t.Run("allocates, lists and releases an address", func(t *testing.T) {
		tools, pool := newIPAMToolsWithPool(t)

		out, err := tools.GatewayIPAMAllocate(ctx, pool.ID, "dev-1", "host-1")
		require.NoError(t, err)
		alloc := out.(*ipam.Allocation)
		assert.Equal(t, "dev-1", alloc.DeviceID)
		assert.True(t, pool.CIDR.Contains(alloc.IP))

		allocs, err := tools.GatewayIPAMAllocations(ctx, pool.ID)
		require.NoError(t, err)
		require.Len(t, allocs, 1)
		assert.Equal(t, alloc.IP, allocs[0].(*ipam.Allocation).IP)

		require.NoError(t, tools.GatewayIPAMRelease(ctx, alloc.IP.String()))
	})

	t.Run("refuses an unknown pool and a malformed address", func(t *testing.T) {
		tools, _ := newIPAMToolsWithPool(t)

		_, err := tools.GatewayIPAMAllocate(ctx, "missing", "dev-1", "")
		assert.Error(t, err)

		var wrapped *WrappedError
		err = tools.GatewayIPAMRelease(ctx, "not-an-ip")
		assert.True(t, errors.As(err, &wrapped), "got %T: %v", err, err)
	})
}

func TestGatewayIPAMTools_PoolDelete(t *testing.T) {
	ctx := context.Background()

	t.Run("deletes the pool", func(t *testing.T) {
		tools, pool := newIPAMToolsWithPool(t)
		require.NoError(t, tools.GatewayIPAMPoolDelete(ctx, pool.ID))
		_, err := tools.GatewayIPAMPoolGet(ctx, pool.ID)
		assert.Error(t, err)
	})

	t.Run("an unknown pool is an error", func(t *testing.T) {
		tools, _ := newIPAMToolsWithPool(t)
		assert.Error(t, tools.GatewayIPAMPoolDelete(ctx, "missing"))
	})
}
