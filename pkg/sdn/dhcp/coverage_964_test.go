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

package dhcp

import (
	"context"
	"errors"
	"net/netip"
	"testing"

	"github.com/insomniacslk/dhcp/dhcpv4"
	"github.com/insomniacslk/dhcp/dhcpv4/server4"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ipam"
)

// errZoneListing964 is the failure the stub allocator returns from
// ListPoolsByZone.
type errZoneListing964 struct{}

func (errZoneListing964) Error() string { return "zone listing unavailable" }

// zoneListFailAllocator fails ListPoolsByZone; ResolvePoolForZone calls no
// other Allocator method on the zone path, so the embedded nil interface is
// never reached.
type zoneListFailAllocator struct {
	ipam.Allocator
}

func (zoneListFailAllocator) ListPoolsByZone(context.Context, string) ([]*ipam.Pool, error) {
	return nil, errZoneListing964{}
}

func TestResolvePoolForZone_ListError_Propagates(t *testing.T) {
	poolID, res, err := ResolvePoolForZone(context.Background(), zoneListFailAllocator{}, "", "provisioning")

	var target errZoneListing964
	require.ErrorAs(t, err, &target)
	assert.Empty(t, poolID)
	assert.Equal(t, PoolResolution(0), res)
}

func TestZonePoolErrors_Messages(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "no pool for zone",
			err:  ErrNoPoolForZone{Zone: "storage"},
			want: `dhcp: no ipam pool found for zone "storage"`,
		},
		{
			name: "ambiguous zone pool",
			err:  ErrAmbiguousZonePool{Zone: "provisioning", Count: 3},
			want: `dhcp: zone "provisioning" matches 3 ipam pools; set an explicit pool binding to resolve ambiguity`,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.want, tt.err.Error())
		})
	}
}

func TestWrappedError_MessageAndUnwrap(t *testing.T) {
	wrapped := &WrappedError{Msg: "start interface eth0", Err: ErrBindFailed}

	assert.Equal(t, "start interface eth0: "+ErrBindFailed.Error(), wrapped.Error())
	assert.ErrorIs(t, wrapped, ErrBindFailed)
	assert.True(t, IsServerError(wrapped), "a wrapped server error stays classifiable")
}

func TestWrappedError_UnwrapPreservesTypedCause(t *testing.T) {
	cause := &ErrPoolExhausted{PoolID: "pool-1"}
	wrapped := &WrappedError{Msg: "allocate", Err: cause}

	var target *ErrPoolExhausted
	require.ErrorAs(t, wrapped, &target)
	assert.Equal(t, "pool-1", target.PoolID)
	assert.Same(t, cause, errors.Unwrap(wrapped))
}

func TestRecordMessageTypeStats_CountsEachClientType(t *testing.T) {
	s := &CoreDHCPServer{stats: NewStatsCollector()}

	s.recordMessageTypeStats(dhcpv4.MessageTypeRelease)
	s.recordMessageTypeStats(dhcpv4.MessageTypeDecline)
	s.recordMessageTypeStats(dhcpv4.MessageTypeDecline)
	s.recordMessageTypeStats(dhcpv4.MessageTypeInform)
	s.recordMessageTypeStats(dhcpv4.MessageTypeInform)
	s.recordMessageTypeStats(dhcpv4.MessageTypeInform)
	// A server-side type is not a client message and counts nowhere.
	s.recordMessageTypeStats(dhcpv4.MessageTypeAck)

	stats := s.stats.Snapshot()
	assert.Equal(t, uint64(1), stats.ReleaseCount)
	assert.Equal(t, uint64(2), stats.DeclineCount)
	assert.Equal(t, uint64(3), stats.InformCount)
	assert.Zero(t, stats.DiscoverCount)
	assert.Zero(t, stats.RequestCount)
}

func TestStopAllServersLocked_ClosesPluginsAndClearsMaps(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	plugin := &IPAMPlugin{leaseStore: NewLeaseStore()}
	require.NoError(t, plugin.leaseStore.Add(&Lease{
		IP:  netip.MustParseAddr("10.0.0.10"),
		MAC: []byte{0x02, 0x00, 0x00, 0x00, 0x00, 0x01},
	}))

	s := &CoreDHCPServer{
		servers:     map[string]*server4.Server{"eth0": nil},
		plugins:     map[string]*IPAMPlugin{"eth0": plugin, "eth1": nil},
		cancelFuncs: map[string]context.CancelFunc{"eth0": cancel},
	}

	s.stopAllServersLocked()

	assert.ErrorIs(t, ctx.Err(), context.Canceled, "the server context is cancelled")
	assert.Empty(t, s.cancelFuncs)
	assert.Empty(t, s.servers)
	assert.Empty(t, s.plugins)
	assert.ErrorIs(t, plugin.Close(), ErrPluginClosed, "the plugin was already closed")
	assert.Zero(t, plugin.leaseStore.Count(), "closing the plugin closed its lease store")
}
