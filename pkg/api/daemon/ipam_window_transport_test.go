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
	"io"
	"log/slog"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/rest"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam/backends"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The IPAM allocation window (reserved prefixes, dynamic range) travels on
// every transport. These tests drive each server-side implementation
// against a real in-memory allocator.

const (
	windowCIDR  = "192.0.2.0/24"
	windowStart = "192.0.2.50"
	windowEnd   = "192.0.2.254"
)

var windowReserved = []string{"192.0.2.1/32"}

func ipamWindowStr(s string) *string { return &s }

// TestIPAMWindow_GRPC creates a pool with a window, refuses a malformed one,
// replaces the window with update_window and leaves it with update_window
// unset.
func TestIPAMWindow_GRPC(t *testing.T) {
	ctx := context.Background()
	svc := NewGatewayService(WithIPAMAllocator(backends.NewMemoryBackend()))

	resp, err := svc.CreateIPAMPool(ctx, &platformv1.CreateIPAMPoolRequest{
		Id: "prov", Name: "prov", Cidr: windowCIDR, Gateway: "192.0.2.1",
		Reserved: windowReserved, RangeStart: windowStart, RangeEnd: windowEnd,
	})
	require.NoError(t, err)
	assert.Equal(t, windowReserved, resp.GetPool().GetReserved())
	assert.Equal(t, windowStart, resp.GetPool().GetRangeStart())
	assert.Equal(t, uint64(253), resp.GetPool().GetTotal(), "usable less the gateway")

	alloc, err := svc.AllocateIP(ctx, &platformv1.AllocateIPRequest{PoolId: "prov", DeviceId: "dev"})
	require.NoError(t, err)
	assert.Equal(t, windowStart, alloc.GetAllocation().GetIp(), "dynamic allocation starts at the window")

	_, err = svc.CreateIPAMPool(ctx, &platformv1.CreateIPAMPoolRequest{
		Name: "bad", Cidr: "10.4.6.0/24", RangeStart: "10.4.6.50",
	})
	assert.Equal(t, codes.InvalidArgument, status.Code(err), "a half-set range is refused")

	_, err = svc.CreateIPAMPool(ctx, &platformv1.CreateIPAMPoolRequest{
		Name: "bad2", Cidr: "10.4.7.0/24", Reserved: []string{"not-a-prefix"},
	})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))

	upd, err := svc.UpdateIPAMPool(ctx, &platformv1.UpdateIPAMPoolRequest{
		Id: "prov", Name: "prov", DefaultLeaseDurationNanos: -1, InactivityTimeoutNanos: -1,
	})
	require.NoError(t, err)
	assert.Equal(t, windowStart, upd.GetPool().GetRangeStart(), "update_window unset keeps the window")

	upd, err = svc.UpdateIPAMPool(ctx, &platformv1.UpdateIPAMPoolRequest{
		Id: "prov", Name: "prov", DefaultLeaseDurationNanos: -1, InactivityTimeoutNanos: -1,
		UpdateWindow: true, Reserved: []string{"192.0.2.1/32", "192.0.2.8/30"},
	})
	require.NoError(t, err)
	assert.Empty(t, upd.GetPool().GetRangeStart(), "update_window replaces the whole window")
	assert.Len(t, upd.GetPool().GetReserved(), 2)

	_, err = svc.UpdateIPAMPool(ctx, &platformv1.UpdateIPAMPoolRequest{
		Id: "prov", UpdateWindow: true, RangeStart: "nope", RangeEnd: "nope",
	})
	assert.Equal(t, codes.InvalidArgument, status.Code(err))
}

// TestIPAMErrToGRPC_Window maps the window errors to InvalidArgument.
func TestIPAMErrToGRPC_Window(t *testing.T) {
	assert.Equal(t, codes.InvalidArgument, status.Code(ipamErrToGRPC(&ipam.ErrIPReserved{})))
	assert.Equal(t, codes.InvalidArgument, status.Code(ipamErrToGRPC(&ipam.ErrInvalidWindow{})))
	assert.False(t, isIPAMWindowError(errors.New("other")))
}

// TestIPAMWindow_REST covers the daemon REST service: create with a window,
// a partial window update, and the typed refusal.
func TestIPAMWindow_REST(t *testing.T) {
	ctx := context.Background()
	svc := newGatewayRESTService(backends.NewMemoryBackend(), slog.New(slog.NewTextHandler(io.Discard, nil)))

	pool, err := svc.CreateIPAMPool(ctx, &rest.CreateIPAMPoolRequest{
		ID: "prov", Name: "prov", CIDR: windowCIDR, Gateway: "192.0.2.1",
		Reserved: windowReserved, RangeStart: windowStart, RangeEnd: windowEnd,
	})
	require.NoError(t, err)
	assert.Equal(t, windowReserved, pool.Reserved)
	assert.Equal(t, windowEnd, pool.RangeEnd)

	pool, err = svc.UpdateIPAMPool(ctx, "prov", &rest.UpdateIPAMPoolRequest{RangeStart: ipamWindowStr("192.0.2.100")})
	require.NoError(t, err)
	assert.Equal(t, "192.0.2.100", pool.RangeStart)
	assert.Equal(t, windowEnd, pool.RangeEnd, "an omitted bound is kept")
	assert.Equal(t, windowReserved, pool.Reserved, "omitted reservations are kept")

	_, err = svc.UpdateIPAMPool(ctx, "prov", &rest.UpdateIPAMPoolRequest{RangeEnd: ipamWindowStr("")})
	var window rest.ErrIPAMWindow
	require.True(t, errors.As(err, &window), "a half-cleared range is refused: %v", err)

	_, err = svc.CreateIPAMPool(ctx, &rest.CreateIPAMPoolRequest{Name: "bad", CIDR: "10.4.6.0/24", Reserved: []string{"x"}})
	require.True(t, errors.As(err, &window))
}

// TestIPAMWindow_QUIC covers the QUIC adapter: create, update_window, and
// the typed refusal.
func TestIPAMWindow_QUIC(t *testing.T) {
	ctx := context.Background()
	a := newFullGatewayQUICAdapter(backends.NewMemoryBackend(), nil, nil, nil, nil)

	info, err := a.CreateIPAMPool(ctx, &quic.CreateIPAMPoolOptions{
		ID: "prov", Name: "prov", CIDR: windowCIDR, Gateway: "192.0.2.1",
		Reserved: windowReserved, RangeStart: windowStart, RangeEnd: windowEnd,
	})
	require.NoError(t, err)
	assert.Equal(t, windowReserved, info.Reserved)
	assert.Equal(t, windowStart, info.RangeStart)

	info, err = a.UpdateIPAMPool(ctx, "prov", &quic.UpdateIPAMPoolOptions{Name: "renamed"})
	require.NoError(t, err)
	assert.Equal(t, windowStart, info.RangeStart, "update_window unset keeps the window")

	info, err = a.UpdateIPAMPool(ctx, "prov", &quic.UpdateIPAMPoolOptions{UpdateWindow: true})
	require.NoError(t, err)
	assert.Empty(t, info.Reserved, "an empty window clears it")
	assert.Empty(t, info.RangeStart)

	_, err = a.UpdateIPAMPool(ctx, "prov", &quic.UpdateIPAMPoolOptions{UpdateWindow: true, RangeStart: windowStart})
	assert.ErrorIs(t, err, quic.ErrGatewayIPAMWindow)

	_, err = a.CreateIPAMPool(ctx, &quic.CreateIPAMPoolOptions{Name: "bad", CIDR: "10.4.6.0/24", Reserved: []string{"x"}})
	assert.ErrorIs(t, err, quic.ErrGatewayIPAMWindow)
}

// TestIPAMWindow_MCP covers the MCP provider: create, a partial update and
// the refusal.
func TestIPAMWindow_MCP(t *testing.T) {
	ctx := context.Background()
	p := NewMCPServiceProvider(&MCPServiceProviderConfig{IPAMService: backends.NewMemoryBackend()})

	out, err := p.GatewayIPAMPoolCreate(ctx, &mcp.IPAMPoolCreateRequest{
		Name: "prov", CIDR: windowCIDR, Gateway: "192.0.2.1",
		Reserved: windowReserved, RangeStart: windowStart, RangeEnd: windowEnd,
	})
	require.NoError(t, err)
	pool := out.(*ipam.Pool)
	assert.Equal(t, windowStart, pool.RangeStart.String())

	out, err = p.GatewayIPAMPoolUpdate(ctx, pool.ID, &mcp.IPAMPoolUpdateRequest{Reserved: []string{}})
	require.NoError(t, err)
	assert.Empty(t, out.(*ipam.Pool).Reserved, "an empty list clears the reservations")
	assert.Equal(t, windowStart, out.(*ipam.Pool).RangeStart.String(), "the range is kept")

	_, err = p.GatewayIPAMPoolUpdate(ctx, pool.ID, &mcp.IPAMPoolUpdateRequest{RangeStart: ipamWindowStr("nope")})
	var window *ipam.ErrInvalidWindow
	require.True(t, errors.As(err, &window))

	_, err = p.GatewayIPAMPoolCreate(ctx, &mcp.IPAMPoolCreateRequest{Name: "bad", CIDR: "10.4.6.0/24", RangeEnd: "10.4.6.9"})
	require.True(t, errors.As(err, &window), "a half-set range is refused")
}
