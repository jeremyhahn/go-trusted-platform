package main

import (
	"context"
	"net/netip"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/ipc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/loadbalancer"
)

// TestServe_AnswersEveryRowVerbOverIPC drives the in-memory datapath the
// real-server harness hands platformd through the same IPC client platformd
// uses: a VIP is added, listed, read, re-pointed, refused a second add and
// removed, and the status reads answer.
func TestServe_AnswersEveryRowVerbOverIPC(t *testing.T) {
	path := filepath.Join(t.TempDir(), "d.sock")
	stop, err := serve(path)
	require.NoError(t, err)
	t.Cleanup(stop)

	client, err := ipc.Dial(path)
	require.NoError(t, err)
	t.Cleanup(func() { _ = client.Close() })

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	addr := netip.MustParseAddrPort("192.0.2.200:8443")
	vip := loadbalancer.VIP{
		Address:  addr.Addr(),
		Port:     addr.Port(),
		Protocol: "tcp",
		Backends: []loadbalancer.Backend{{Address: netip.MustParseAddr("192.0.2.10"), Port: 443}},
	}
	require.NoError(t, client.AddVIP(ctx, vip))

	list, err := client.ListVIPs(ctx)
	require.NoError(t, err)
	require.Len(t, list, 1)
	assert.Equal(t, addr.Addr(), list[0].VIP.Address)
	assert.Equal(t, addr.Port(), list[0].VIP.Port)

	got, err := client.GetVIP(ctx, "tcp", addr)
	require.NoError(t, err)
	require.Len(t, got.VIP.Backends, 1)
	assert.Equal(t, netip.MustParseAddr("192.0.2.10"), got.VIP.Backends[0].Address)
	assert.Equal(t, uint16(443), got.VIP.Backends[0].Port)
	require.Len(t, got.Backends, 1)

	next := []loadbalancer.Backend{{Address: netip.MustParseAddr("192.0.2.11"), Port: 443}}
	require.NoError(t, client.SetVIPBackends(ctx, "tcp", addr, next))
	got, err = client.GetVIP(ctx, "tcp", addr)
	require.NoError(t, err)
	require.Len(t, got.VIP.Backends, 1)
	assert.Equal(t, netip.MustParseAddr("192.0.2.11"), got.VIP.Backends[0].Address)

	assert.Error(t, client.AddVIP(ctx, vip), "a second add of the same protocol and address is refused")

	health, err := client.LBStatus(ctx)
	require.NoError(t, err)
	assert.True(t, health.Active)
	assert.Equal(t, 1, health.VIPCount)

	require.NoError(t, client.RemoveVIP(ctx, "tcp", addr))
	_, err = client.GetVIP(ctx, "tcp", addr)
	assert.Error(t, err, "a removed VIP is not found")
	assert.Error(t, client.RemoveVIP(ctx, "tcp", addr), "a second remove is refused")

	_, err = client.NAT64Status(ctx)
	assert.NoError(t, err)
	_, err = client.Datapath(ctx, "br-int")
	assert.NoError(t, err)
	_, err = client.Conntrack(ctx, 0)
	assert.NoError(t, err)
}
