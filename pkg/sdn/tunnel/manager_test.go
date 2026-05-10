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

package tunnel

import (
	"context"
	"errors"
	"log/slog"
	"net"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	vnl "github.com/vishvananda/netlink"
)

func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelDebug}))
}

func TestManager_EnsureTunnel_CreatesGRETunnel(t *testing.T) {
	mock := newMockNetlinkOps()
	mgr := newManagerWithOps(testLogger(), mock)
	ctx := context.Background()

	config := validGREConfig()
	err := mgr.EnsureTunnel(ctx, config)
	require.NoError(t, err)

	// Verify the link was created
	link, err := mock.LinkByName("gre1")
	require.NoError(t, err)
	assert.Equal(t, "gre1", link.Attrs().Name)

	// Verify address was added
	addrs := mock.addrs["gre1"]
	require.Len(t, addrs, 1)
	assert.Equal(t, "10.255.0.1/30", addrs[0].IPNet.String())
}

func TestManager_EnsureTunnel_InvalidConfig(t *testing.T) {
	mock := newMockNetlinkOps()
	mgr := newManagerWithOps(testLogger(), mock)
	ctx := context.Background()

	config := TunnelConfig{} // empty, invalid
	err := mgr.EnsureTunnel(ctx, config)
	require.Error(t, err)

	var invalidErr *ErrInvalidTunnelConfig
	require.True(t, errors.As(err, &invalidErr))
}

func TestManager_EnsureTunnel_Idempotent(t *testing.T) {
	mock := newMockNetlinkOps()
	mgr := newManagerWithOps(testLogger(), mock)
	ctx := context.Background()

	config := validGREConfig()

	// First call creates
	err := mgr.EnsureTunnel(ctx, config)
	require.NoError(t, err)

	// Second call is a no-op
	err = mgr.EnsureTunnel(ctx, config)
	require.NoError(t, err)

	// Still only one link
	links, err := mock.LinkList()
	require.NoError(t, err)
	assert.Len(t, links, 1)
}

func TestManager_EnsureTunnel_UpdatesOnConfigChange(t *testing.T) {
	mock := newMockNetlinkOps()
	mgr := newManagerWithOps(testLogger(), mock)
	ctx := context.Background()

	config := validGREConfig()
	err := mgr.EnsureTunnel(ctx, config)
	require.NoError(t, err)

	// Change MTU
	config.MTU = 1280
	err = mgr.EnsureTunnel(ctx, config)
	require.NoError(t, err)

	// Link was recreated (old deleted, new added)
	link, err := mock.LinkByName("gre1")
	require.NoError(t, err)
	assert.Equal(t, 1280, link.Attrs().MTU)
}

func TestManager_EnsureTunnel_WithIPv6(t *testing.T) {
	mock := newMockNetlinkOps()
	mgr := newManagerWithOps(testLogger(), mock)
	ctx := context.Background()

	config := validGREConfig()
	config.TunnelIPv6 = "fd00::1/126"
	err := mgr.EnsureTunnel(ctx, config)
	require.NoError(t, err)

	// Should have 2 addresses (IPv4 + IPv6)
	addrs := mock.addrs["gre1"]
	require.Len(t, addrs, 2)
}

func TestManager_EnsureTunnel_WithGREKey(t *testing.T) {
	mock := newMockNetlinkOps()
	mgr := newManagerWithOps(testLogger(), mock)
	ctx := context.Background()

	config := validGREConfig()
	config.Key = 42
	err := mgr.EnsureTunnel(ctx, config)
	require.NoError(t, err)

	link, err := mock.LinkByName("gre1")
	require.NoError(t, err)
	gre, ok := link.(*vnl.Gretun)
	require.True(t, ok)
	assert.Equal(t, uint32(42), gre.IKey)
	assert.Equal(t, uint32(42), gre.OKey)
}

func TestManager_EnsureTunnel_IPIPType(t *testing.T) {
	mock := newMockNetlinkOps()
	mgr := newManagerWithOps(testLogger(), mock)
	ctx := context.Background()

	config := TunnelConfig{
		Name:     "ipip1",
		Type:     TunnelTypeIPIP,
		Local:    "192.168.1.1",
		Remote:   "192.168.2.1",
		TunnelIP: "10.0.0.1/30",
	}
	err := mgr.EnsureTunnel(ctx, config)
	require.NoError(t, err)

	link, err := mock.LinkByName("ipip1")
	require.NoError(t, err)
	_, ok := link.(*vnl.Iptun)
	assert.True(t, ok, "expected Iptun link type")
}

func TestManager_EnsureTunnel_GRE6Type(t *testing.T) {
	mock := newMockNetlinkOps()
	mgr := newManagerWithOps(testLogger(), mock)
	ctx := context.Background()

	config := TunnelConfig{
		Name:     "gre6-01",
		Type:     TunnelTypeGRE6,
		Local:    "2001:db8::1",
		Remote:   "2001:db8::2",
		TunnelIP: "10.255.0.1/30",
	}
	err := mgr.EnsureTunnel(ctx, config)
	require.NoError(t, err)

	link, err := mock.LinkByName("gre6-01")
	require.NoError(t, err)
	_, ok := link.(*vnl.Ip6tnl)
	assert.True(t, ok, "expected Ip6tnl link type")
}

func TestManager_EnsureTunnel_LinkAddFails(t *testing.T) {
	mock := newMockNetlinkOps()
	mock.linkAddFn = func(link vnl.Link) error {
		return errors.New("kernel error")
	}
	mgr := newManagerWithOps(testLogger(), mock)
	ctx := context.Background()

	err := mgr.EnsureTunnel(ctx, validGREConfig())
	require.Error(t, err)

	var createErr *ErrTunnelCreateFailed
	require.True(t, errors.As(err, &createErr))
	assert.Equal(t, "gre1", createErr.Name)
}

func TestManager_EnsureTunnel_SetMTUFails(t *testing.T) {
	mock := newMockNetlinkOps()
	mock.linkSetMTUFn = func(link vnl.Link, mtu int) error {
		return errors.New("mtu error")
	}
	mgr := newManagerWithOps(testLogger(), mock)
	ctx := context.Background()

	err := mgr.EnsureTunnel(ctx, validGREConfig())
	require.Error(t, err)

	var createErr *ErrTunnelCreateFailed
	require.True(t, errors.As(err, &createErr))
}

func TestManager_EnsureTunnel_AddrAddFails(t *testing.T) {
	mock := newMockNetlinkOps()
	mock.addrAddFn = func(link vnl.Link, addr *vnl.Addr) error {
		return errors.New("addr error")
	}
	mgr := newManagerWithOps(testLogger(), mock)
	ctx := context.Background()

	err := mgr.EnsureTunnel(ctx, validGREConfig())
	require.Error(t, err)

	var createErr *ErrTunnelCreateFailed
	require.True(t, errors.As(err, &createErr))
}

func TestManager_EnsureTunnel_SetUpFails(t *testing.T) {
	mock := newMockNetlinkOps()
	mock.linkSetUpFn = func(link vnl.Link) error {
		return errors.New("set up error")
	}
	mgr := newManagerWithOps(testLogger(), mock)
	ctx := context.Background()

	err := mgr.EnsureTunnel(ctx, validGREConfig())
	require.Error(t, err)

	var createErr *ErrTunnelCreateFailed
	require.True(t, errors.As(err, &createErr))
}

func TestManager_RemoveTunnel(t *testing.T) {
	mock := newMockNetlinkOps()
	mgr := newManagerWithOps(testLogger(), mock)
	ctx := context.Background()

	config := validGREConfig()
	err := mgr.EnsureTunnel(ctx, config)
	require.NoError(t, err)

	err = mgr.RemoveTunnel(ctx, "gre1")
	require.NoError(t, err)

	// Link should be gone
	_, err = mock.LinkByName("gre1")
	require.Error(t, err)
}

func TestManager_RemoveTunnel_NotFound(t *testing.T) {
	mock := newMockNetlinkOps()
	mgr := newManagerWithOps(testLogger(), mock)
	ctx := context.Background()

	err := mgr.RemoveTunnel(ctx, "nonexistent")
	require.Error(t, err)

	var notFound *ErrTunnelNotFound
	require.True(t, errors.As(err, &notFound))
	assert.Equal(t, "nonexistent", notFound.Name)
}

func TestManager_RemoveTunnel_KernelDeleteFails(t *testing.T) {
	mock := newMockNetlinkOps()
	mgr := newManagerWithOps(testLogger(), mock)
	ctx := context.Background()

	// Create tunnel
	err := mgr.EnsureTunnel(ctx, validGREConfig())
	require.NoError(t, err)

	// Make delete fail
	mock.linkDelFn = func(link vnl.Link) error {
		return errors.New("permission denied")
	}

	err = mgr.RemoveTunnel(ctx, "gre1")
	require.Error(t, err)

	var removeErr *ErrTunnelRemoveFailed
	require.True(t, errors.As(err, &removeErr))
}

func TestManager_RemoveTunnel_AlreadyGoneFromKernel(t *testing.T) {
	mock := newMockNetlinkOps()
	mgr := newManagerWithOps(testLogger(), mock)
	ctx := context.Background()

	// Create tunnel
	err := mgr.EnsureTunnel(ctx, validGREConfig())
	require.NoError(t, err)

	// Simulate kernel removing it behind our back
	mock.mu.Lock()
	delete(mock.links, "gre1")
	mock.mu.Unlock()

	// RemoveTunnel should succeed (just removes tracking)
	err = mgr.RemoveTunnel(ctx, "gre1")
	require.NoError(t, err)
}

func TestManager_Status(t *testing.T) {
	mock := newMockNetlinkOps()
	mgr := newManagerWithOps(testLogger(), mock)
	ctx := context.Background()

	config := validGREConfig()
	err := mgr.EnsureTunnel(ctx, config)
	require.NoError(t, err)

	status, err := mgr.Status(ctx, "gre1")
	require.NoError(t, err)
	assert.Equal(t, "gre1", status.Name)
	assert.Equal(t, config.Local, status.LocalIP)
	assert.Equal(t, config.Remote, status.RemoteIP)
	assert.Equal(t, config.TunnelIP, status.TunnelIP)
}

func TestManager_Status_NotFound(t *testing.T) {
	mock := newMockNetlinkOps()
	mgr := newManagerWithOps(testLogger(), mock)
	ctx := context.Background()

	_, err := mgr.Status(ctx, "nonexistent")
	require.Error(t, err)

	var notFound *ErrTunnelNotFound
	require.True(t, errors.As(err, &notFound))
}

func TestManager_Status_WithStats(t *testing.T) {
	mock := newMockNetlinkOps()
	mgr := newManagerWithOps(testLogger(), mock)
	ctx := context.Background()

	config := validGREConfig()
	err := mgr.EnsureTunnel(ctx, config)
	require.NoError(t, err)

	// Inject stats into the mock link
	mock.mu.Lock()
	if link, ok := mock.links["gre1"]; ok {
		link.Attrs().Statistics = &vnl.LinkStatistics{
			RxBytes:   1024,
			TxBytes:   2048,
			RxPackets: 10,
			TxPackets: 20,
		}
	}
	mock.mu.Unlock()

	status, err := mgr.Status(ctx, "gre1")
	require.NoError(t, err)
	assert.Equal(t, uint64(1024), status.RxBytes)
	assert.Equal(t, uint64(2048), status.TxBytes)
	assert.Equal(t, uint64(10), status.RxPackets)
	assert.Equal(t, uint64(20), status.TxPackets)
}

func TestManager_Status_UpState(t *testing.T) {
	mock := newMockNetlinkOps()
	mgr := newManagerWithOps(testLogger(), mock)
	ctx := context.Background()

	config := validGREConfig()
	err := mgr.EnsureTunnel(ctx, config)
	require.NoError(t, err)

	// Simulate the link being up
	mock.mu.Lock()
	if link, ok := mock.links["gre1"]; ok {
		link.Attrs().Flags |= net.FlagUp
		link.Attrs().OperState = vnl.OperUp
	}
	mock.mu.Unlock()

	status, err := mgr.Status(ctx, "gre1")
	require.NoError(t, err)
	assert.Equal(t, TunnelStateUp, status.State)
}

func TestManager_Status_DownState(t *testing.T) {
	mock := newMockNetlinkOps()
	mgr := newManagerWithOps(testLogger(), mock)
	ctx := context.Background()

	config := validGREConfig()
	err := mgr.EnsureTunnel(ctx, config)
	require.NoError(t, err)

	// Set OperState to down
	mock.mu.Lock()
	if link, ok := mock.links["gre1"]; ok {
		link.Attrs().OperState = vnl.OperDown
	}
	mock.mu.Unlock()

	status, err := mgr.Status(ctx, "gre1")
	require.NoError(t, err)
	assert.Equal(t, TunnelStateDown, status.State)
}

func TestManager_Status_LinkByNameFails(t *testing.T) {
	mock := newMockNetlinkOps()
	mgr := newManagerWithOps(testLogger(), mock)
	ctx := context.Background()

	config := validGREConfig()
	err := mgr.EnsureTunnel(ctx, config)
	require.NoError(t, err)

	// Make LinkByName fail
	mock.linkByNameFn = func(name string) (vnl.Link, error) {
		return nil, errors.New("device gone")
	}

	_, err = mgr.Status(ctx, "gre1")
	require.Error(t, err)

	var statusErr *ErrTunnelStatusFailed
	require.True(t, errors.As(err, &statusErr))
}

func TestManager_ListTunnels(t *testing.T) {
	mock := newMockNetlinkOps()
	mgr := newManagerWithOps(testLogger(), mock)
	ctx := context.Background()

	// Empty list
	tunnels, err := mgr.ListTunnels(ctx)
	require.NoError(t, err)
	assert.Empty(t, tunnels)

	// Add two tunnels
	config1 := validGREConfig()
	config2 := TunnelConfig{
		Name:     "gre2",
		Type:     TunnelTypeGRE,
		Local:    "99.12.246.37",
		Remote:   "66.42.90.190",
		TunnelIP: "10.255.0.5/30",
	}
	err = mgr.EnsureTunnel(ctx, config1)
	require.NoError(t, err)
	err = mgr.EnsureTunnel(ctx, config2)
	require.NoError(t, err)

	tunnels, err = mgr.ListTunnels(ctx)
	require.NoError(t, err)
	assert.Len(t, tunnels, 2)

	// Verify names are present
	names := make(map[string]bool)
	for _, s := range tunnels {
		names[s.Name] = true
	}
	assert.True(t, names["gre1"])
	assert.True(t, names["gre2"])
}

func TestManager_Close(t *testing.T) {
	mock := newMockNetlinkOps()
	mgr := newManagerWithOps(testLogger(), mock)
	ctx := context.Background()

	// Create multiple tunnels
	config1 := validGREConfig()
	config2 := TunnelConfig{
		Name:     "gre2",
		Type:     TunnelTypeGRE,
		Local:    "99.12.246.37",
		Remote:   "66.42.90.190",
		TunnelIP: "10.255.0.5/30",
	}
	err := mgr.EnsureTunnel(ctx, config1)
	require.NoError(t, err)
	err = mgr.EnsureTunnel(ctx, config2)
	require.NoError(t, err)

	// Close should remove all tunnels
	err = mgr.Close()
	require.NoError(t, err)

	// All links should be gone
	links, err := mock.LinkList()
	require.NoError(t, err)
	assert.Empty(t, links)

	// Listing should be empty
	tunnels, err := mgr.ListTunnels(ctx)
	require.NoError(t, err)
	assert.Empty(t, tunnels)
}

func TestManager_Close_PartialFailure(t *testing.T) {
	mock := newMockNetlinkOps()
	mgr := newManagerWithOps(testLogger(), mock)
	ctx := context.Background()

	config := validGREConfig()
	err := mgr.EnsureTunnel(ctx, config)
	require.NoError(t, err)

	// Make delete fail
	mock.linkDelFn = func(link vnl.Link) error {
		return errors.New("permission denied")
	}

	err = mgr.Close()
	require.Error(t, err)
}

func TestManager_EnsureTunnel_ReclainsUnmanagedLink(t *testing.T) {
	mock := newMockNetlinkOps()
	mgr := newManagerWithOps(testLogger(), mock)
	ctx := context.Background()

	// Pre-populate a link that is not managed by us
	mock.mu.Lock()
	mock.links["gre1"] = &vnl.Dummy{
		LinkAttrs: vnl.LinkAttrs{Name: "gre1", MTU: 1500},
	}
	mock.mu.Unlock()

	config := validGREConfig()
	err := mgr.EnsureTunnel(ctx, config)
	require.NoError(t, err)

	// Verify it was replaced with our GRE tunnel
	link, err := mock.LinkByName("gre1")
	require.NoError(t, err)
	_, ok := link.(*vnl.Gretun)
	assert.True(t, ok, "expected GRE tunnel link")
}

func TestTunnelConfigEqual(t *testing.T) {
	a := validGREConfig()
	b := validGREConfig()

	t.Run("identical configs", func(t *testing.T) {
		assert.True(t, tunnelConfigEqual(a, b))
	})

	t.Run("different remote", func(t *testing.T) {
		b2 := b
		b2.Remote = "1.2.3.4"
		assert.False(t, tunnelConfigEqual(a, b2))
	})

	t.Run("different MTU explicit vs default", func(t *testing.T) {
		a2 := a
		a2.MTU = 0 // will use DefaultMTU
		b2 := b
		b2.MTU = DefaultMTU // explicitly set to same
		assert.True(t, tunnelConfigEqual(a2, b2))
	})

	t.Run("different key", func(t *testing.T) {
		b2 := b
		b2.Key = 99
		assert.False(t, tunnelConfigEqual(a, b2))
	})
}

func TestManager_NewManager(t *testing.T) {
	logger := testLogger()
	mgr := NewManager(logger)
	require.NotNil(t, mgr)
	assert.NotNil(t, mgr.tunnels)
	assert.NotNil(t, mgr.nl)
}
