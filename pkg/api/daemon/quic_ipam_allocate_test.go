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
	"net/netip"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
	ipamBackends "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam/backends"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// newQUICIPAMAdapter returns the daemon's QUIC gateway adapter over a real
// memory allocator holding pool "p1" (10.9.0.0/29) and pool "p2".
func newQUICIPAMAdapter(t *testing.T) (*fullGatewayQUICAdapter, ipam.Allocator) {
	t.Helper()
	alloc := ipamBackends.NewMemoryBackend()
	t.Cleanup(func() { _ = alloc.Close() })
	ctx := context.Background()
	require.NoError(t, alloc.CreatePool(ctx, &ipam.Pool{ID: "p1", Name: "p1", CIDR: netip.MustParsePrefix("10.9.0.0/29")}))
	require.NoError(t, alloc.CreatePool(ctx, &ipam.Pool{ID: "p2", Name: "p2", CIDR: netip.MustParsePrefix("10.9.1.0/29")}))
	return newFullGatewayQUICAdapter(alloc, nil, nil, nil, nil, nil), alloc
}

// TestQUICAllocateRelease_RoundTrip is the #730 regression: QUIC allocate and
// release reach the allocator gRPC and REST use, instead of answering
// "gateway feature not configured".
func TestQUICAllocateRelease_RoundTrip(t *testing.T) {
	ctx := context.Background()
	a, _ := newQUICIPAMAdapter(t)

	info, err := a.AllocateIP(ctx, "p1", &quic.AllocateIPOptions{Owner: "dev-1", Hostname: "web-1"})
	require.NoError(t, err)
	assert.Equal(t, "p1", info.PoolID)
	assert.Equal(t, "dev-1", info.Owner)
	assert.Equal(t, "web-1", info.Hostname)
	require.True(t, netip.MustParseAddr(info.IPAddress).IsValid())

	listed, err := a.ListAllocations(ctx, "p1")
	require.NoError(t, err)
	require.Len(t, listed, 1)

	require.NoError(t, a.ReleaseIP(ctx, "", info.IPAddress))
	listed, err = a.ListAllocations(ctx, "p1")
	require.NoError(t, err)
	assert.Empty(t, listed, "a released address is not listed as allocated")
}

func TestQUICAllocate_SpecificAddressAndConflict(t *testing.T) {
	ctx := context.Background()
	a, _ := newQUICIPAMAdapter(t)

	info, err := a.AllocateIP(ctx, "p1", &quic.AllocateIPOptions{Owner: "dev-1", IPAddress: "10.9.0.5", Type: "static"})
	require.NoError(t, err)
	assert.Equal(t, "10.9.0.5", info.IPAddress)

	_, err = a.AllocateIP(ctx, "p1", &quic.AllocateIPOptions{Owner: "dev-2", IPAddress: "10.9.0.5"})
	assert.ErrorIs(t, err, quic.ErrGatewayIPAlreadyAllocated)
}

func TestQUICAllocate_RefusesWhatIPAMCannotRecord(t *testing.T) {
	ctx := context.Background()
	a, _ := newQUICIPAMAdapter(t)

	tests := []struct {
		name string
		opts *quic.AllocateIPOptions
		want error
	}{
		{"no owner", &quic.AllocateIPOptions{}, quic.ErrGatewayMissingOwner},
		{"nil options", nil, quic.ErrGatewayMissingOwner},
		{"mac address", &quic.AllocateIPOptions{Owner: "d", MACAddress: "02:00:00:00:00:01"}, quic.ErrGatewayMACNotRecorded},
		{"unknown type", &quic.AllocateIPOptions{Owner: "d", Type: "dhcp"}, quic.ErrGatewayInvalidAllocationType},
		{"static without address", &quic.AllocateIPOptions{Owner: "d", Type: "static"}, quic.ErrGatewayMissingIPAddress},
		{"unparsable address", &quic.AllocateIPOptions{Owner: "d", IPAddress: "not-an-ip"}, quic.ErrGatewayInvalidIPAddress},
		{"address outside the pool", &quic.AllocateIPOptions{Owner: "d", IPAddress: "192.0.2.1"}, quic.ErrGatewayInvalidIPAddress},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := a.AllocateIP(ctx, "p1", tt.opts)
			assert.ErrorIs(t, err, tt.want)
		})
	}

	t.Run("unknown pool", func(t *testing.T) {
		_, err := a.AllocateIP(ctx, "nope", &quic.AllocateIPOptions{Owner: "d"})
		assert.ErrorIs(t, err, quic.ErrGatewayPoolNotFound)
	})
}

func TestQUICRelease_Errors(t *testing.T) {
	ctx := context.Background()
	a, _ := newQUICIPAMAdapter(t)
	info, err := a.AllocateIP(ctx, "p1", &quic.AllocateIPOptions{Owner: "dev-1"})
	require.NoError(t, err)

	assert.ErrorIs(t, a.ReleaseIP(ctx, "", "garbage"), quic.ErrGatewayInvalidIPAddress)
	assert.ErrorIs(t, a.ReleaseIP(ctx, "", "10.9.0.6"), quic.ErrGatewayAllocationNotFound)
	assert.ErrorIs(t, a.ReleaseIP(ctx, "p2", info.IPAddress), quic.ErrGatewayAllocationNotFound,
		"an address held in another pool is not released")

	require.NoError(t, a.ReleaseIP(ctx, "p1", info.IPAddress))
	assert.ErrorIs(t, a.ReleaseIP(ctx, "p1", info.IPAddress), quic.ErrGatewayAllocationNotFound,
		"releasing twice reports the allocation gone")
}

// TestActiveAllocations_ExcludesReleased pins the listing every gateway
// transport shares: REST used to list released addresses as allocated.
func TestActiveAllocations_ExcludesReleased(t *testing.T) {
	ctx := context.Background()
	_, alloc := newQUICIPAMAdapter(t)

	kept, err := alloc.Allocate(ctx, &ipam.AllocationRequest{PoolID: "p1", DeviceID: "a"})
	require.NoError(t, err)
	gone, err := alloc.Allocate(ctx, &ipam.AllocationRequest{PoolID: "p1", DeviceID: "b"})
	require.NoError(t, err)
	other, err := alloc.Allocate(ctx, &ipam.AllocationRequest{PoolID: "p2", DeviceID: "c"})
	require.NoError(t, err)
	require.NoError(t, alloc.Release(ctx, gone.IP))

	inPool, err := activeAllocations(ctx, alloc, "p1")
	require.NoError(t, err)
	require.Len(t, inPool, 1)
	assert.Equal(t, kept.IP, inPool[0].IP)

	everywhere, err := activeAllocations(ctx, alloc, "")
	require.NoError(t, err)
	ips := []netip.Addr{}
	for _, a := range everywhere {
		ips = append(ips, a.IP)
	}
	assert.ElementsMatch(t, []netip.Addr{kept.IP, other.IP}, ips)

	_, err = activeAllocations(ctx, alloc, "nope")
	assert.ErrorIs(t, err, ipam.ErrPoolNotFound)
}

// An allocation IPAM expired for inactivity keeps a zero ExpiresAt, so only
// its status says the address is free. It must not be listed, and every
// listed allocation must carry its real status on the gRPC wire (#765).
func TestActiveAllocations_ExcludesExpired(t *testing.T) {
	ctx := context.Background()
	_, alloc := newQUICIPAMAdapter(t)
	require.NoError(t, alloc.CreatePool(ctx, &ipam.Pool{
		ID: "idle", Name: "idle", CIDR: netip.MustParsePrefix("10.9.2.0/29"), InactivityTimeout: time.Nanosecond,
	}))

	kept, err := alloc.Allocate(ctx, &ipam.AllocationRequest{PoolID: "p1", DeviceID: "a"})
	require.NoError(t, err)
	idle, err := alloc.Allocate(ctx, &ipam.AllocationRequest{PoolID: "idle", DeviceID: "b"})
	require.NoError(t, err)
	expired, err := alloc.ExpireInactive(ctx, "idle")
	require.NoError(t, err)
	require.Len(t, expired, 1)
	require.Equal(t, idle.IP, expired[0].IP)
	require.True(t, expired[0].ExpiresAt.IsZero(), "expiry for inactivity leaves ExpiresAt zero")

	inPool, err := activeAllocations(ctx, alloc, "idle")
	require.NoError(t, err)
	assert.Empty(t, inPool)

	svc := NewGatewayService()
	svc.SetIPAMAllocator(alloc)
	resp, err := svc.ListAllocations(ctx, &platformv1.ListAllocationsRequest{})
	require.NoError(t, err)
	require.Len(t, resp.GetAllocations(), 1)
	assert.Equal(t, kept.IP.String(), resp.GetAllocations()[0].GetIp())
	assert.Equal(t, string(ipam.AllocationStatusActive), resp.GetAllocations()[0].GetStatus())

	_, err = alloc.ExpireInactive(ctx, "nope")
	assert.ErrorIs(t, err, ipam.ErrPoolNotFound)
}
