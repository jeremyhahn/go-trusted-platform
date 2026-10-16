//go:build integration

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

package sdn

import (
	"context"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"strconv"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/server"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
)

// The gateway speaker listens on 127.0.0.1 and the upstream router dials it
// from 127.0.0.2, so each side sees a distinct neighbour address on loopback.
const (
	grGatewayAddress  = "127.0.0.1"
	grUpstreamAddress = "127.0.0.2"
	grGatewayASN      = 64512
	grUpstreamASN     = 64513
	grRestartTime     = 30
	grSessionBound    = 30 * time.Second
	grPoll            = 50 * time.Millisecond
)

var grPrefix = netip.MustParsePrefix("198.51.100.0/24")

// grUpstream is a plain GoBGP router standing in for the transit peer: it
// helps a restarting neighbour the way RFC 4724 says, and nothing more.
type grUpstream struct {
	server bgp.BGPServerInterface
}

// TestBGPGracefulRestart_UpstreamKeepsTheGatewaysRoutes kills the gateway
// speaker the way a SIGKILL of the routing child does — the TCP session
// closes with no NOTIFICATION — and reads the upstream router's RIB while
// the gateway is down. With graceful restart the gateway's prefix stays,
// marked stale, until the successor's session refreshes it; without it the
// prefix is withdrawn the moment the session drops.
func TestBGPGracefulRestart_UpstreamKeepsTheGatewaysRoutes(t *testing.T) {
	t.Run("graceful restart on", func(t *testing.T) {
		port := grFreePort(t)
		upstream := startGRUpstream(t, port)
		killed := startGRGateway(t, port, true)
		upstream.awaitRoute(t, false)

		killGRGateway(t, killed)
		upstream.awaitSessionDown(t)
		path, found := upstream.route(t)
		require.True(t, found, "the upstream withdrew %s while the gateway restarted", grPrefix)
		require.True(t, path.GetStale(), "the retained %s is not marked stale", grPrefix)

		startGRGateway(t, port, true)
		upstream.awaitRoute(t, false)
	})

	t.Run("graceful restart off", func(t *testing.T) {
		port := grFreePort(t)
		upstream := startGRUpstream(t, port)
		killed := startGRGateway(t, port, false)
		upstream.awaitRoute(t, false)

		killGRGateway(t, killed)
		upstream.awaitSessionDown(t)
		_, found := upstream.route(t)
		require.False(t, found, "the upstream kept %s from a gateway that never offered graceful restart", grPrefix)
	})
}

// startGRGateway starts the platform speaker under test announcing grPrefix
// to the upstream, and returns the GoBGP server it drives so the test can
// stop that server without a NOTIFICATION.
func startGRGateway(t *testing.T, port uint16, gracefulRestart bool) bgp.BGPServerInterface {
	t.Helper()
	ctx := context.Background()
	gobgpServer := bgp.NewGoBGPServerAdapter(server.NewBgpServer())
	config := &bgp.BGPConfig{
		RouterID:            netip.MustParseAddr("192.0.2.1"),
		ASN:                 grGatewayASN,
		ListenPort:          port,
		ListenAddresses:     []netip.Addr{netip.MustParseAddr(grGatewayAddress)},
		EnabledFamilies:     []bgp.AddressFamily{bgp.AFamilyIPv4Unicast},
		GracefulRestart:     &gracefulRestart,
		GracefulRestartTime: grRestartTime,
	}
	logger := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelWarn}))
	speaker, err := bgp.NewSpeaker(config, logger, bgp.WithBGPServer(gobgpServer))
	require.NoError(t, err)
	require.NoError(t, speaker.Start(ctx))

	t.Cleanup(func() { gobgpServer.Stop() })

	require.NoError(t, speaker.AddPeer(ctx, &bgp.NeighborConfig{
		Address:         netip.MustParseAddr(grUpstreamAddress),
		ASN:             grUpstreamASN,
		PassiveMode:     true,
		EnabledFamilies: []bgp.AddressFamily{bgp.AFamilyIPv4Unicast},
		Policy:          bgp.PeerPolicyConfig{ExportDefaultAccept: true},
	}))
	require.NoError(t, speaker.AddPath(ctx, &bgp.Path{
		Family:  bgp.AFamilyIPv4Unicast,
		Prefix:  grPrefix,
		NextHop: netip.MustParseAddr(grGatewayAddress),
		Origin:  bgp.OriginIGP,
	}))
	return gobgpServer
}

// killGRGateway closes the gateway's sessions and listener without sending
// a NOTIFICATION, which is what the peer sees when the routing child dies.
func killGRGateway(t *testing.T, gateway bgp.BGPServerInterface) {
	t.Helper()
	require.NoError(t, gateway.StopBgp(context.Background(), &api.StopBgpRequest{AllowGracefulRestart: true}))
}

func startGRUpstream(t *testing.T, gatewayPort uint16) *grUpstream {
	t.Helper()
	ctx := context.Background()
	gobgpServer := bgp.NewGoBGPServerAdapter(server.NewBgpServer())
	require.NoError(t, gobgpServer.Start())
	t.Cleanup(func() { gobgpServer.Stop() })

	require.NoError(t, gobgpServer.StartBgp(ctx, &api.StartBgpRequest{Global: &api.Global{
		Asn:        grUpstreamASN,
		RouterId:   "192.0.2.2",
		ListenPort: -1, // dial only: the gateway owns the session's listener
	}}))
	ipv4 := &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST}
	require.NoError(t, gobgpServer.AddPeer(ctx, &api.AddPeerRequest{Peer: &api.Peer{
		Conf: &api.PeerConf{NeighborAddress: grGatewayAddress, PeerAsn: grGatewayASN},
		Transport: &api.Transport{
			LocalAddress: grUpstreamAddress,
			RemotePort:   uint32(gatewayPort),
		},
		Timers: &api.Timers{Config: &api.TimersConfig{ConnectRetry: 1}},
		GracefulRestart: &api.GracefulRestart{
			Enabled:             true,
			RestartTime:         grRestartTime,
			NotificationEnabled: true,
		},
		AfiSafis: []*api.AfiSafi{{
			Config:            &api.AfiSafiConfig{Family: ipv4, Enabled: true},
			MpGracefulRestart: &api.MpGracefulRestart{Config: &api.MpGracefulRestartConfig{Enabled: true}},
		}},
	}}))
	return &grUpstream{server: gobgpServer}
}

// route returns the upstream's path for grPrefix, if it holds one.
func (u *grUpstream) route(t *testing.T) (*api.Path, bool) {
	t.Helper()
	var found *api.Path
	err := u.server.ListPath(context.Background(), &api.ListPathRequest{
		TableType: api.TableType_TABLE_TYPE_GLOBAL,
		Family:    &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST},
	}, func(dest *api.Destination) {
		if dest.GetPrefix() == grPrefix.String() && len(dest.GetPaths()) > 0 {
			found = dest.GetPaths()[0]
		}
	})
	require.NoError(t, err)
	return found, found != nil
}

// awaitRoute waits until the upstream holds grPrefix with the given stale
// flag, which for a fresh session means the gateway's update arrived.
func (u *grUpstream) awaitRoute(t *testing.T, stale bool) {
	t.Helper()
	require.Eventually(t, func() bool {
		path, found := u.route(t)
		return found && path.GetStale() == stale
	}, grSessionBound, grPoll, "the upstream never held %s (stale=%v)", grPrefix, stale)
}

// awaitSessionDown waits until the upstream has noticed the gateway's
// session is gone.
func (u *grUpstream) awaitSessionDown(t *testing.T) {
	t.Helper()
	require.Eventually(t, func() bool {
		established := false
		err := u.server.ListPeer(context.Background(), &api.ListPeerRequest{Address: grGatewayAddress}, func(peer *api.Peer) {
			established = peer.GetState().GetSessionState() == api.PeerState_SESSION_STATE_ESTABLISHED
		})
		require.NoError(t, err)
		return !established
	}, grSessionBound, grPoll, "the upstream never saw the gateway's session drop")
}

// grFreePort reserves a loopback port for the gateway's listener.
func grFreePort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp", net.JoinHostPort(grGatewayAddress, "0"))
	require.NoError(t, err)
	_, portText, err := net.SplitHostPort(listener.Addr().String())
	require.NoError(t, err)
	require.NoError(t, listener.Close())
	port, err := strconv.ParseUint(portText, 10, 16)
	require.NoError(t, err)
	return uint16(port)
}
