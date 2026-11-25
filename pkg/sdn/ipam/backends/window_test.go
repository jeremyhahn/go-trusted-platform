//go:build !platform_p2p

// Copyright (c) 2025 Jeremy Hahn. All rights reserved.
// Use of this source code is governed by the MIT license
// that can be found in the LICENSE file.

package backends

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
)

// windowBackends returns a fresh memory and QuicBaaS backend, so every
// window rule is checked against both with one table.
func windowBackends(t *testing.T) map[string]ipam.Allocator {
	t.Helper()
	qb, err := NewQuicBaaSBackend(NewMockQuicBaaSClient(), nil)
	require.NoError(t, err)
	return map[string]ipam.Allocator{
		"memory":   NewMemoryBackend(),
		"quicbaas": qb,
	}
}

// referenceZonePool is a reference zone pool: gateway .1 reserved, DHCP .50
// to .254. The window here is narrowed to .50-.52 so exhaustion is cheap.
func referenceZonePool() *ipam.Pool {
	return &ipam.Pool{
		ID:         "provisioning",
		Name:       "provisioning",
		Zone:       "provisioning",
		CIDR:       netip.MustParsePrefix("192.0.2.0/24"),
		Gateway:    netip.MustParseAddr("192.0.2.1"),
		Reserved:   []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")},
		RangeStart: netip.MustParseAddr("192.0.2.50"),
		RangeEnd:   netip.MustParseAddr("192.0.2.52"),
	}
}

func req(pool, device string) *ipam.AllocationRequest {
	return &ipam.AllocationRequest{PoolID: pool, DeviceID: device}
}

// TestWindow_AllocateStaysInRange verifies dynamic allocation starts at the
// range start (never the gateway), stays in the range, and exhausts at its
// end while static addresses outside it remain allocatable.
func TestWindow_AllocateStaysInRange(t *testing.T) {
	ctx := context.Background()
	for name, b := range windowBackends(t) {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, b.CreatePool(ctx, referenceZonePool()))

			for i, want := range []string{"192.0.2.50", "192.0.2.51", "192.0.2.52"} {
				a, err := b.Allocate(ctx, req("provisioning", fmt.Sprintf("dev-%d", i)))
				require.NoError(t, err)
				assert.Equal(t, want, a.IP.String())
			}
			_, err := b.Allocate(ctx, req("provisioning", "dev-x"))
			assert.ErrorIs(t, err, ipam.ErrPoolExhausted)

			static := req("provisioning", "cp-01")
			static.RequestedIP = netip.MustParseAddr("192.0.2.10")
			a, err := b.AllocateSpecific(ctx, static)
			require.NoError(t, err, "a static address outside the dynamic window is allowed")
			assert.Equal(t, "192.0.2.10", a.IP.String())
		})
	}
}

// TestWindow_AllocateSpecificRefusesReserved refuses the gateway and an
// address inside a reserved prefix with ErrIPReserved.
func TestWindow_AllocateSpecificRefusesReserved(t *testing.T) {
	ctx := context.Background()
	for name, b := range windowBackends(t) {
		t.Run(name, func(t *testing.T) {
			pool := referenceZonePool()
			pool.Reserved = append(pool.Reserved, netip.MustParsePrefix("192.0.2.8/30"))
			require.NoError(t, b.CreatePool(ctx, pool))

			for _, ip := range []string{"192.0.2.1", "192.0.2.10"} {
				r := req("provisioning", "dev")
				r.RequestedIP = netip.MustParseAddr(ip)
				_, err := b.AllocateSpecific(ctx, r)
				var reserved *ipam.ErrIPReserved
				require.True(t, errors.As(err, &reserved), "%s: got %v", ip, err)
				assert.Equal(t, r.RequestedIP, reserved.IP)
			}
		})
	}
}

// TestWindow_GatewayNeverAllocated verifies a pool without a range and
// without explicit reservations still never hands out its gateway.
func TestWindow_GatewayNeverAllocated(t *testing.T) {
	ctx := context.Background()
	for name, b := range windowBackends(t) {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, b.CreatePool(ctx, &ipam.Pool{
				ID:      "gw",
				Name:    "gw",
				CIDR:    netip.MustParsePrefix("10.4.1.0/29"),
				Gateway: netip.MustParseAddr("10.4.1.1"),
			}))
			a, err := b.Allocate(ctx, req("gw", "dev"))
			require.NoError(t, err)
			assert.Equal(t, "10.4.1.2", a.IP.String())
		})
	}
}

// TestWindow_HASyncReservedSlash31 verifies the tunnel range never hands out
// the gateway HA sync /31.
func TestWindow_HASyncReservedSlash31(t *testing.T) {
	ctx := context.Background()
	for name, b := range windowBackends(t) {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, b.CreatePool(ctx, &ipam.Pool{
				ID:       "tunnel-p2p",
				Name:     "tunnel-p2p",
				CIDR:     netip.MustParsePrefix("10.4.128.0/22"),
				Reserved: []netip.Prefix{netip.MustParsePrefix("10.4.128.0/31")},
			}))
			a, err := b.Allocate(ctx, req("tunnel-p2p", "gw"))
			require.NoError(t, err)
			assert.Equal(t, "10.4.128.2", a.IP.String())
		})
	}
}

// TestWindow_IPv6 verifies allocation in an IPv6 pool skips the gateway.
func TestWindow_IPv6(t *testing.T) {
	ctx := context.Background()
	for name, b := range windowBackends(t) {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, b.CreatePool(ctx, &ipam.Pool{
				ID:         "v6",
				Name:       "v6",
				CIDR:       netip.MustParsePrefix("fd12:3456:789a:405::/120"),
				Gateway:    netip.MustParseAddr("fd12:3456:789a:405::1"),
				RangeStart: netip.MustParseAddr("fd12:3456:789a:405::1"),
				RangeEnd:   netip.MustParseAddr("fd12:3456:789a:405::ff"),
			}))
			a, err := b.Allocate(ctx, req("v6", "dev"))
			require.NoError(t, err)
			assert.Equal(t, "fd12:3456:789a:405::2", a.IP.String())
		})
	}
}

// TestWindow_StatsCountAllocatable verifies pool size counts only what can
// be allocated, and that updating the reserved prefixes resizes the pool.
func TestWindow_StatsCountAllocatable(t *testing.T) {
	ctx := context.Background()
	for name, b := range windowBackends(t) {
		t.Run(name, func(t *testing.T) {
			require.NoError(t, b.CreatePool(ctx, referenceZonePool()))
			p, err := b.GetPool(ctx, "provisioning")
			require.NoError(t, err)
			assert.Equal(t, uint64(253), p.TotalIPs)
			assert.Equal(t, uint64(253), p.AvailableIPs)
			assert.Equal(t, []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}, p.Reserved, "the window persists")
			assert.Equal(t, "192.0.2.50", p.RangeStart.String())

			p.Reserved = append(p.Reserved, netip.MustParsePrefix("192.0.2.8/30"))
			require.NoError(t, b.UpdatePool(ctx, p))
			p, err = b.GetPool(ctx, "provisioning")
			require.NoError(t, err)
			assert.Equal(t, uint64(249), p.TotalIPs)
		})
	}
}

// TestWindow_CreateAndUpdateRefuseBadWindow refuses a reserved prefix or a
// range outside the CIDR, on create and on update.
func TestWindow_CreateAndUpdateRefuseBadWindow(t *testing.T) {
	ctx := context.Background()
	for name, b := range windowBackends(t) {
		t.Run(name, func(t *testing.T) {
			bad := referenceZonePool()
			bad.Reserved = []netip.Prefix{netip.MustParsePrefix("10.4.6.0/30")}
			var window *ipam.ErrInvalidWindow
			require.True(t, errors.As(b.CreatePool(ctx, bad), &window))

			require.NoError(t, b.CreatePool(ctx, referenceZonePool()))
			p, err := b.GetPool(ctx, "provisioning")
			require.NoError(t, err)
			p.RangeEnd = netip.Addr{}
			require.True(t, errors.As(b.UpdatePool(ctx, p), &window))
		})
	}
}

// TestMemory_ReserveRefusesPoolReserved verifies the memory backend's
// Reserve refuses an address the pool already reserves.
func TestMemory_ReserveRefusesPoolReserved(t *testing.T) {
	ctx := context.Background()
	m := NewMemoryBackend()
	require.NoError(t, m.CreatePool(ctx, referenceZonePool()))
	var reserved *ipam.ErrIPReserved
	require.True(t, errors.As(m.Reserve(ctx, "provisioning", netip.MustParseAddr("192.0.2.1"), "gw"), &reserved))
	require.NoError(t, m.Reserve(ctx, "provisioning", netip.MustParseAddr("192.0.2.20"), "static"))
}
