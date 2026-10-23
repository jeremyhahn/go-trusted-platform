package backends

import (
	"context"
	"errors"
	"net/netip"
	"sync/atomic"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

var errPoolWrite = errors.New("pool write refused")

// poolWriteFailClient fails every pool write once failPool is set, while
// allocation and index writes still succeed. It isolates the pool update
// that Allocate, AllocateSpecific and Release make after the address is
// chosen.
type poolWriteFailClient struct {
	*MockQuicBaaSClient
	failPool atomic.Bool
}

func (c *poolWriteFailClient) Put(ctx context.Context, entityType string, id uint64, data []byte) error {
	if entityType == entityTypePool && c.failPool.Load() {
		return errPoolWrite
	}
	return c.MockQuicBaaSClient.Put(ctx, entityType, id, data)
}

func newPoolWriteFailBackend(t *testing.T) (*QuicBaaSBackend, *poolWriteFailClient) {
	t.Helper()
	client := &poolWriteFailClient{MockQuicBaaSClient: NewMockQuicBaaSClient()}
	backend, err := NewQuicBaaSBackend(client, nil)
	require.NoError(t, err)
	require.NoError(t, backend.CreatePool(context.Background(), &ipam.Pool{
		ID:   "pool-write",
		Name: "pool-write",
		CIDR: netip.MustParsePrefix("10.20.0.0/24"),
	}))
	return backend, client
}

// assertPoolWriteError checks that a failed pool write reaches the caller
// as a typed pool-operation error carrying the storage cause.
func assertPoolWriteError(t *testing.T, err error, operation string) {
	t.Helper()
	var opErr *ipam.ErrPoolOperationFailed
	require.ErrorAs(t, err, &opErr)
	assert.Equal(t, "pool-write", opErr.PoolID)
	assert.Equal(t, operation, opErr.Operation)
	assert.ErrorIs(t, err, errPoolWrite)
}

func TestQuicBaaSBackend_Allocate_PoolWriteFailure(t *testing.T) {
	ctx := context.Background()
	backend, client := newPoolWriteFailBackend(t)
	client.failPool.Store(true)

	alloc, err := backend.Allocate(ctx, &ipam.AllocationRequest{PoolID: "pool-write", DeviceID: "dev-1"})

	assert.Nil(t, alloc)
	assertPoolWriteError(t, err, "allocate")
	allocs, err := backend.GetAllocationsByPool(ctx, "pool-write")
	require.NoError(t, err)
	assert.Empty(t, allocs, "a failed allocation must not hold an address")
}

func TestQuicBaaSBackend_Allocate_PoolWriteSucceeds(t *testing.T) {
	ctx := context.Background()
	backend, _ := newPoolWriteFailBackend(t)

	alloc, err := backend.Allocate(ctx, &ipam.AllocationRequest{PoolID: "pool-write", DeviceID: "dev-1"})

	require.NoError(t, err)
	got, err := backend.GetAllocation(ctx, alloc.IP)
	require.NoError(t, err)
	assert.Equal(t, "dev-1", got.DeviceID)
}

func TestQuicBaaSBackend_AllocateSpecific_PoolWriteFailure(t *testing.T) {
	ctx := context.Background()
	backend, client := newPoolWriteFailBackend(t)
	client.failPool.Store(true)
	ip := netip.MustParseAddr("10.20.0.50")

	alloc, err := backend.AllocateSpecific(ctx, &ipam.AllocationRequest{
		PoolID: "pool-write", DeviceID: "dev-1", RequestedIP: ip,
	})

	assert.Nil(t, alloc)
	assertPoolWriteError(t, err, "allocate")
	_, err = backend.GetAllocation(ctx, ip)
	assert.ErrorIs(t, err, ipam.ErrAllocationNotFound, "a failed allocation must not hold the address")
}

func TestQuicBaaSBackend_Release_PoolWriteFailure(t *testing.T) {
	ctx := context.Background()
	backend, client := newPoolWriteFailBackend(t)
	alloc, err := backend.Allocate(ctx, &ipam.AllocationRequest{PoolID: "pool-write", DeviceID: "dev-1"})
	require.NoError(t, err)
	client.failPool.Store(true)

	err = backend.Release(ctx, alloc.IP)

	assertPoolWriteError(t, err, "release")
	got, err := backend.GetAllocation(ctx, alloc.IP)
	require.NoError(t, err)
	assert.Equal(t, ipam.AllocationStatusActive, got.Status, "a failed release must leave the allocation active")
}
