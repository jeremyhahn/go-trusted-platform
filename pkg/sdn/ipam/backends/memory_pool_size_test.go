package backends

import (
	"context"
	"net/netip"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// An IPv6 /64 pool used to get a bitmap whose word count wrapped to zero,
// so the first Allocate panicked; a /72 asked for a multi-terabyte slice.
func TestMemoryBackend_CreatePool_RefusesPoolLargerThanBitmapBound(t *testing.T) {
	for _, cidr := range []string{"2001:db8:1234::/64", "2001:db8:1234::/72", "2001:db8:1234::/103"} {
		t.Run(cidr, func(t *testing.T) {
			ctx := context.Background()
			backend := NewMemoryBackend()
			prefix := netip.MustParsePrefix(cidr)

			err := backend.CreatePool(ctx, &ipam.Pool{ID: "v6", Name: "v6", CIDR: prefix})

			var tooLarge *ipam.ErrPoolTooLarge
			require.ErrorAs(t, err, &tooLarge)
			assert.Equal(t, prefix, tooLarge.CIDR)
			assert.Equal(t, uint64(maxMemoryPoolSize), tooLarge.Max)
			assert.True(t, ipam.IsValidationError(err))
			_, err = backend.GetPool(ctx, "v6")
			assert.ErrorIs(t, err, ipam.ErrPoolNotFound, "a refused pool must not be stored")
		})
	}
}

func TestMemoryBackend_CreatePool_AcceptsPoolAtBitmapBound(t *testing.T) {
	ctx := context.Background()
	backend := NewMemoryBackend()
	// A /104 holds exactly maxMemoryPoolSize addresses.
	require.NoError(t, backend.CreatePool(ctx, &ipam.Pool{
		ID: "v6", Name: "v6", CIDR: netip.MustParsePrefix("2001:db8:1234::/104"),
	}))

	alloc, err := backend.Allocate(ctx, &ipam.AllocationRequest{PoolID: "v6", DeviceID: "dev-1"})

	require.NoError(t, err)
	assert.True(t, netip.MustParsePrefix("2001:db8:1234::/104").Contains(alloc.IP))
}
