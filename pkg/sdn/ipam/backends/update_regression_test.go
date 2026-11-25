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

package backends

import (
	"context"
	"net/netip"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
)

// TestMemoryBackend_UpdatePool_RefusedRenameKeepsIndex verifies a rename
// refused for an invalid window leaves the name index untouched: the old
// name still resolves and the new one is free.
func TestMemoryBackend_UpdatePool_RefusedRenameKeepsIndex(t *testing.T) {
	ctx := context.Background()
	backend := NewMemoryBackend()
	defer backend.Close()

	pool := &ipam.Pool{ID: "p1", Name: "fabric", CIDR: netip.MustParsePrefix("10.4.1.0/24")}
	require.NoError(t, backend.CreatePool(ctx, pool))

	bad := &ipam.Pool{
		ID: "p1", Name: "renamed", CIDR: netip.MustParsePrefix("10.4.1.0/24"),
		RangeStart: netip.MustParseAddr("10.4.1.200"), RangeEnd: netip.MustParseAddr("10.4.1.50"),
	}
	require.Error(t, backend.UpdatePool(ctx, bad))

	got, err := backend.GetPoolByName(ctx, "fabric")
	require.NoError(t, err, "the old name must still resolve")
	assert.Equal(t, "p1", got.ID)
	_, err = backend.GetPoolByName(ctx, "renamed")
	assert.ErrorIs(t, err, ipam.ErrPoolNotFound, "the refused name must stay free")
}

// TestQuicBaaSBackend_UpdatePool_KeepsCountersAndCreation verifies an update
// keeps the backend's allocation count and creation time, whatever the
// caller sends.
func TestQuicBaaSBackend_UpdatePool_KeepsCountersAndCreation(t *testing.T) {
	ctx := context.Background()
	backend, err := NewQuicBaaSBackend(NewMockQuicBaaSClient(), nil)
	require.NoError(t, err)

	pool := &ipam.Pool{ID: "p1", Name: "fabric", CIDR: netip.MustParsePrefix("10.4.1.0/24")}
	require.NoError(t, backend.CreatePool(ctx, pool))
	_, err = backend.Allocate(ctx, &ipam.AllocationRequest{PoolID: "p1", DeviceID: "dev-1"})
	require.NoError(t, err)
	before, err := backend.GetPool(ctx, "p1")
	require.NoError(t, err)

	update := &ipam.Pool{ID: "p1", Name: "fabric", CIDR: netip.MustParsePrefix("10.4.1.0/24"), Description: "x"}
	require.NoError(t, backend.UpdatePool(ctx, update))

	after, err := backend.GetPool(ctx, "p1")
	require.NoError(t, err)
	assert.Equal(t, before.AllocatedIPs, after.AllocatedIPs, "allocations survive an update")
	assert.Equal(t, before.CreatedAt.Unix(), after.CreatedAt.Unix(), "the creation time survives an update")
	assert.Equal(t, after.TotalIPs-after.AllocatedIPs, after.AvailableIPs)
}
