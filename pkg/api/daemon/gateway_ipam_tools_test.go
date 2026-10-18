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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam/backends"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
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

		_, err := tools.GatewayIPAMPoolCreate(ctx, &mcp.IPAMPoolCreateRequest{Name: "x", CIDR: "not-a-cidr"})
		assert.Equal(t, codes.InvalidArgument, status.Code(err), "got %T: %v", err, err)

		_, err = tools.GatewayIPAMPoolCreate(ctx, &mcp.IPAMPoolCreateRequest{Name: "x", CIDR: "10.8.0.0/24", Gateway: "nope"})
		assert.Equal(t, codes.InvalidArgument, status.Code(err), "got %T: %v", err, err)
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

		_, err = tools.GatewayIPAMPoolUpdate(ctx, pool.ID, &mcp.IPAMPoolUpdateRequest{Gateway: "nope"})
		assert.Equal(t, codes.InvalidArgument, status.Code(err), "got %T: %v", err, err)
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

		// The memory backend keeps the released allocation for audit; the
		// list must not, as GatewayService.ListAllocations does not (#949).
		allocs, err = tools.GatewayIPAMAllocations(ctx, pool.ID)
		require.NoError(t, err)
		assert.Empty(t, allocs, "a released address is not listed")
	})

	t.Run("lists every pool when no pool is given", func(t *testing.T) {
		tools, pool := newIPAMToolsWithPool(t)
		other, err := tools.GatewayIPAMPoolCreate(ctx, &mcp.IPAMPoolCreateRequest{
			Name: "other",
			CIDR: "10.8.0.0/24",
		})
		require.NoError(t, err)

		_, err = tools.GatewayIPAMAllocate(ctx, pool.ID, "dev-1", "")
		require.NoError(t, err)
		_, err = tools.GatewayIPAMAllocate(ctx, other.(*ipam.Pool).ID, "dev-2", "")
		require.NoError(t, err)

		allocs, err := tools.GatewayIPAMAllocations(ctx, "")
		require.NoError(t, err)
		devices := make([]string, 0, len(allocs))
		for _, a := range allocs {
			devices = append(devices, a.(*ipam.Allocation).DeviceID)
		}
		assert.ElementsMatch(t, []string{"dev-1", "dev-2"}, devices)
	})

	t.Run("refuses an unknown pool and a malformed address", func(t *testing.T) {
		tools, _ := newIPAMToolsWithPool(t)

		_, err := tools.GatewayIPAMAllocate(ctx, "missing", "dev-1", "")
		assert.Equal(t, codes.NotFound, status.Code(err), "got %T: %v", err, err)

		err = tools.GatewayIPAMRelease(ctx, "not-an-ip")
		assert.Equal(t, codes.InvalidArgument, status.Code(err), "got %T: %v", err, err)
	})

	t.Run("answers NotFound as gRPC does, not Internal", func(t *testing.T) {
		tools, _ := newIPAMToolsWithPool(t)

		_, err := tools.GatewayIPAMAllocations(ctx, "missing")
		assert.Equal(t, codes.NotFound, status.Code(err), "unknown pool: %v", err)

		err = tools.GatewayIPAMRelease(ctx, "10.9.0.200")
		assert.Equal(t, codes.NotFound, status.Code(err), "unallocated address: %v", err)
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

// TestGatewayIPAMTools_ErrorsMatchGRPC drives each MCP IPAM tool and the
// gRPC method it mirrors against the same allocator, and asserts both answer
// the same class. MCP's toolErrorCode reads that class from the gRPC status,
// so a plain IPAM error here would be -32603 on MCP (#949).
func TestGatewayIPAMTools_ErrorsMatchGRPC(t *testing.T) {
	ctx := context.Background()

	// exhaust narrows the pool's dynamic range to two addresses and
	// allocates until IPAM refuses, so the next allocation meets an
	// exhausted pool.
	exhaust := func(t *testing.T, tools gatewayIPAMTools, poolID string) {
		t.Helper()
		start, end := "10.9.0.10", "10.9.0.11"
		_, err := tools.GatewayIPAMPoolUpdate(ctx, poolID, &mcp.IPAMPoolUpdateRequest{RangeStart: &start, RangeEnd: &end})
		require.NoError(t, err)
		for i := 0; i < 4; i++ {
			if _, err := tools.GatewayIPAMAllocate(ctx, poolID, fmt.Sprintf("fill-%d", i), ""); err != nil {
				return
			}
		}
		t.Fatalf("pool %s never exhausted", poolID)
	}

	cases := []struct {
		name  string
		want  codes.Code
		setup func(t *testing.T, tools gatewayIPAMTools, pool *ipam.Pool)
		mcp   func(tools gatewayIPAMTools, pool *ipam.Pool) error
		grpc  func(svc *GatewayService, pool *ipam.Pool) error
	}{
		{
			name: "pool get of an unknown pool",
			want: codes.NotFound,
			mcp: func(tools gatewayIPAMTools, _ *ipam.Pool) error {
				_, err := tools.GatewayIPAMPoolGet(ctx, "missing")
				return err
			},
			grpc: func(svc *GatewayService, _ *ipam.Pool) error {
				_, err := svc.GetIPAMPool(ctx, &platformv1.GetIPAMPoolRequest{Id: "missing"})
				return err
			},
		},
		{
			name: "allocate from an unknown pool",
			want: codes.NotFound,
			mcp: func(tools gatewayIPAMTools, _ *ipam.Pool) error {
				_, err := tools.GatewayIPAMAllocate(ctx, "missing", "dev-1", "")
				return err
			},
			grpc: func(svc *GatewayService, _ *ipam.Pool) error {
				_, err := svc.AllocateIP(ctx, &platformv1.AllocateIPRequest{PoolId: "missing", DeviceId: "dev-1"})
				return err
			},
		},
		{
			name: "allocate from an exhausted pool",
			want: codes.ResourceExhausted,
			setup: func(t *testing.T, tools gatewayIPAMTools, pool *ipam.Pool) {
				exhaust(t, tools, pool.ID)
			},
			mcp: func(tools gatewayIPAMTools, pool *ipam.Pool) error {
				_, err := tools.GatewayIPAMAllocate(ctx, pool.ID, "dev-mcp", "")
				return err
			},
			grpc: func(svc *GatewayService, pool *ipam.Pool) error {
				_, err := svc.AllocateIP(ctx, &platformv1.AllocateIPRequest{PoolId: pool.ID, DeviceId: "dev-grpc"})
				return err
			},
		},
		{
			name: "release of a malformed address",
			want: codes.InvalidArgument,
			mcp: func(tools gatewayIPAMTools, _ *ipam.Pool) error {
				return tools.GatewayIPAMRelease(ctx, "not-an-ip")
			},
			grpc: func(svc *GatewayService, _ *ipam.Pool) error {
				_, err := svc.ReleaseIP(ctx, &platformv1.ReleaseIPRequest{Ip: "not-an-ip"})
				return err
			},
		},
		{
			name: "pool create with a malformed cidr",
			want: codes.InvalidArgument,
			mcp: func(tools gatewayIPAMTools, _ *ipam.Pool) error {
				_, err := tools.GatewayIPAMPoolCreate(ctx, &mcp.IPAMPoolCreateRequest{Name: "x", CIDR: "not-a-cidr"})
				return err
			},
			grpc: func(svc *GatewayService, _ *ipam.Pool) error {
				_, err := svc.CreateIPAMPool(ctx, &platformv1.CreateIPAMPoolRequest{Name: "x", Cidr: "not-a-cidr"})
				return err
			},
		},
		{
			name: "pool create with a malformed gateway",
			want: codes.InvalidArgument,
			mcp: func(tools gatewayIPAMTools, _ *ipam.Pool) error {
				_, err := tools.GatewayIPAMPoolCreate(ctx, &mcp.IPAMPoolCreateRequest{Name: "x", CIDR: "10.8.0.0/24", Gateway: "nope"})
				return err
			},
			grpc: func(svc *GatewayService, _ *ipam.Pool) error {
				_, err := svc.CreateIPAMPool(ctx, &platformv1.CreateIPAMPoolRequest{Name: "x", Cidr: "10.8.0.0/24", Gateway: "nope"})
				return err
			},
		},
		{
			name: "pool create with a reserved entry that is not a prefix",
			want: codes.InvalidArgument,
			mcp: func(tools gatewayIPAMTools, _ *ipam.Pool) error {
				_, err := tools.GatewayIPAMPoolCreate(ctx, &mcp.IPAMPoolCreateRequest{Name: "x", CIDR: "10.8.0.0/24", Reserved: []string{"nope"}})
				return err
			},
			grpc: func(svc *GatewayService, _ *ipam.Pool) error {
				_, err := svc.CreateIPAMPool(ctx, &platformv1.CreateIPAMPoolRequest{Name: "x", Cidr: "10.8.0.0/24", Reserved: []string{"nope"}})
				return err
			},
		},
		{
			name: "pool create of a pool that clashes with an existing one",
			want: codes.AlreadyExists,
			mcp: func(tools gatewayIPAMTools, _ *ipam.Pool) error {
				_, err := tools.GatewayIPAMPoolCreate(ctx, &mcp.IPAMPoolCreateRequest{Name: "lab", CIDR: "10.9.0.0/24"})
				return err
			},
			grpc: func(svc *GatewayService, _ *ipam.Pool) error {
				_, err := svc.CreateIPAMPool(ctx, &platformv1.CreateIPAMPoolRequest{Name: "lab", Cidr: "10.9.0.0/24"})
				return err
			},
		},
		{
			name: "pool update of an unknown pool",
			want: codes.NotFound,
			mcp: func(tools gatewayIPAMTools, _ *ipam.Pool) error {
				_, err := tools.GatewayIPAMPoolUpdate(ctx, "missing", &mcp.IPAMPoolUpdateRequest{Name: "x"})
				return err
			},
			grpc: func(svc *GatewayService, _ *ipam.Pool) error {
				_, err := svc.UpdateIPAMPool(ctx, &platformv1.UpdateIPAMPoolRequest{Id: "missing", Name: "x"})
				return err
			},
		},
		{
			name: "pool update with a malformed gateway",
			want: codes.InvalidArgument,
			mcp: func(tools gatewayIPAMTools, pool *ipam.Pool) error {
				_, err := tools.GatewayIPAMPoolUpdate(ctx, pool.ID, &mcp.IPAMPoolUpdateRequest{Gateway: "nope"})
				return err
			},
			grpc: func(svc *GatewayService, pool *ipam.Pool) error {
				_, err := svc.UpdateIPAMPool(ctx, &platformv1.UpdateIPAMPoolRequest{Id: pool.ID, Gateway: "nope"})
				return err
			},
		},
		{
			name: "pool update with a reserved entry that is not a prefix",
			want: codes.InvalidArgument,
			mcp: func(tools gatewayIPAMTools, pool *ipam.Pool) error {
				_, err := tools.GatewayIPAMPoolUpdate(ctx, pool.ID, &mcp.IPAMPoolUpdateRequest{Reserved: []string{"nope"}})
				return err
			},
			grpc: func(svc *GatewayService, pool *ipam.Pool) error {
				_, err := svc.UpdateIPAMPool(ctx, &platformv1.UpdateIPAMPoolRequest{Id: pool.ID, UpdateWindow: true, Reserved: []string{"nope"}})
				return err
			},
		},
		{
			name: "pool delete of an unknown pool",
			want: codes.NotFound,
			mcp: func(tools gatewayIPAMTools, _ *ipam.Pool) error {
				return tools.GatewayIPAMPoolDelete(ctx, "missing")
			},
			grpc: func(svc *GatewayService, _ *ipam.Pool) error {
				_, err := svc.DeleteIPAMPool(ctx, &platformv1.DeleteIPAMPoolRequest{Id: "missing"})
				return err
			},
		},
		{
			name: "pool delete of a pool that holds allocations",
			want: codes.FailedPrecondition,
			setup: func(t *testing.T, tools gatewayIPAMTools, pool *ipam.Pool) {
				_, err := tools.GatewayIPAMAllocate(ctx, pool.ID, "dev-1", "")
				require.NoError(t, err)
			},
			mcp: func(tools gatewayIPAMTools, pool *ipam.Pool) error {
				return tools.GatewayIPAMPoolDelete(ctx, pool.ID)
			},
			grpc: func(svc *GatewayService, pool *ipam.Pool) error {
				_, err := svc.DeleteIPAMPool(ctx, &platformv1.DeleteIPAMPoolRequest{Id: pool.ID})
				return err
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			tools, pool := newIPAMToolsWithPool(t)
			if tc.setup != nil {
				tc.setup(t, tools, pool)
			}
			svc := NewGatewayService()
			svc.SetIPAMAllocator(tools.ipam)

			grpcErr := tc.grpc(svc, pool)
			require.Equal(t, tc.want, status.Code(grpcErr), "gRPC reference: %v", grpcErr)

			mcpErr := tc.mcp(tools, pool)
			assert.Equal(t, tc.want, status.Code(mcpErr), "MCP: %v", mcpErr)
		})
	}
}
