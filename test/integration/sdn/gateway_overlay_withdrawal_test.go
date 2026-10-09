//go:build integration

// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	api "github.com/osrg/gobgp/v4/api"
	"github.com/osrg/gobgp/v4/pkg/server"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/modes"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/vxlan"
)

// The overlay withdrawal fabric: the gateway and one remote VTEP, each a real
// GoBGP speaker, peered over loopback. Their tunnel addresses are not
// configured anywhere; the decap flows only match on them.
var (
	overlayGatewaySession = netip.MustParseAddr("127.0.0.1")
	overlayRemoteSession  = netip.MustParseAddr("127.0.0.2")

	overlayGatewayVTEP = netip.MustParseAddr("192.0.2.10")
	overlayRemoteVTEP  = netip.MustParseAddr("198.51.100.21")
)

const (
	overlayWithdrawalASN        uint32 = 64512
	overlayWithdrawalOverlayASN uint16 = 65000

	// overlayWithdrawnVNI is the segment whose route the remote VTEP
	// withdraws; overlayKeptVNI is the control it keeps advertising.
	overlayWithdrawnVNI  uint32 = 10711
	overlayWithdrawnVLAN uint16 = 711
	overlayKeptVNI       uint32 = 10712
	overlayKeptVLAN      uint16 = 712

	overlayWithdrawalBridge     = "br-ovl-wd"
	overlayWithdrawalAccessPort = "ovl-wd-acc"

	// overlayWithdrawalWait bounds every wait on the BGP session and the
	// routes crossing it. The session comes up in about two seconds (GoBGP's
	// minimum connect retry).
	overlayWithdrawalWait = 30 * time.Second
)

// TestGatewayOverlayWithdrawalRemovesDecapFlows proves on a real OVS bridge
// that a remote VTEP loses its VXLAN decap authorisation when it stops being
// a member of a segment. The remote VTEP's Type-3 routes reach the gateway
// over a real BGP session and install a decap flow per VNI in the decap
// table. Withdrawing one VNI's route removes that VNI's flow and leaves the
// other's, and revoking the VTEP removes every flow it still has.
func TestGatewayOverlayWithdrawalRemovesDecapFlows(t *testing.T) {
	ctx, cancel := LongRunningTestContext()
	t.Cleanup(cancel)
	logger := slog.Default()

	bridge := setupTestBridge(t, overlayWithdrawalBridge)
	runCmd(t, "ovs-vsctl", "add-port", bridge.name, overlayWithdrawalAccessPort,
		"--", "set", "interface", overlayWithdrawalAccessPort, "type=internal")
	ofClient := bridge.createClient(t)
	ovsClient := newOVSDBClient(t)

	gatewaySpeaker, remoteSpeaker := startOverlayEVPNPeers(t, ctx, logger)
	remote := startOverlayEVPNManager(t, ctx, &bgp.EVPNManagerConfig{
		Speaker:    remoteSpeaker,
		Logger:     logger,
		LocalVTEP:  overlayRemoteVTEP,
		OverlayASN: overlayWithdrawalOverlayASN,
	})

	handler, err := modes.NewOverlayModeHandler(&modes.OverlayModeConfig{
		VTEPConfig: &vxlan.VTEPConfig{
			LocalIP:       overlayGatewayVTEP,
			UnderlayIface: "lo",
			UnderlayMTU:   vxlan.MinimumUnderlayMTU,
			VXLANPort:     vxlan.DefaultVXLANPort,
		},
		EVPNConfig: &bgp.EVPNManagerConfig{
			Speaker:    gatewaySpeaker,
			Logger:     logger,
			LocalVTEP:  overlayGatewayVTEP,
			OverlayASN: overlayWithdrawalOverlayASN,
		},
		BridgeName: bridge.name,
		AccessPort: overlayWithdrawalAccessPort,
		Admitter:   admitOnlyVTEP{vtep: overlayRemoteVTEP},
		Logger:     logger,
	}, ovsClient, ofClient)
	require.NoError(t, err, "create overlay handler")
	require.NoError(t, handler.Start(ctx), "start overlay handler")
	t.Cleanup(func() {
		if err := handler.Stop(context.Background()); err != nil {
			t.Errorf("stop overlay handler: %v", err)
		}
	})
	dumpBridgeOnFailure(t, bridge.name)

	require.NoError(t, handler.AddVNI(ctx, overlayWithdrawnVNI, overlayWithdrawnVLAN))
	require.NoError(t, handler.AddVNI(ctx, overlayKeptVNI, overlayKeptVLAN))
	require.NoError(t, remote.JoinVNI(ctx, overlayWithdrawnVNI, 0))
	require.NoError(t, remote.JoinVNI(ctx, overlayKeptVNI, 0))

	waitFor(ctx, t, "the remote VTEP's decap flows", 100*time.Millisecond, overlayWithdrawalWait, func() bool {
		return decapFlowCount(t, bridge.name, overlayWithdrawnVNI, overlayRemoteVTEP) == 1 &&
			decapFlowCount(t, bridge.name, overlayKeptVNI, overlayRemoteVTEP) == 1
	})

	t.Run("RouteWithdrawalRemovesThatVNIsDecapFlow", func(t *testing.T) {
		require.NoError(t, remote.LeaveVNI(ctx, overlayWithdrawnVNI))

		waitFor(ctx, t, "the withdrawn VNI's decap flow to go", 100*time.Millisecond, overlayWithdrawalWait, func() bool {
			return decapFlowCount(t, bridge.name, overlayWithdrawnVNI, overlayRemoteVTEP) == 0
		})
		require.Equal(t, 1, decapFlowCount(t, bridge.name, overlayKeptVNI, overlayRemoteVTEP),
			"a withdrawal must leave the VTEP's other segments decapsulating")
		require.Equal(t, []modes.InstalledVTEP{{VTEP: overlayRemoteVTEP, VNIs: []uint32{overlayKeptVNI}}}, handler.InstalledVTEPs())
	})

	t.Run("RevocationRemovesEveryDecapFlow", func(t *testing.T) {
		require.NoError(t, handler.RevokeVTEP(ctx, overlayRemoteVTEP))

		require.Zero(t, decapFlowCount(t, bridge.name, overlayKeptVNI, overlayRemoteVTEP),
			"a revoked VTEP must not keep a decap flow")
		require.Empty(t, handler.InstalledVTEPs())
	})
}

// admitOnlyVTEP stands in for gatewayd's attested admission, which needs a
// passing TPM verdict no suite fixture produces yet (see
// TestGatewayOverlayAdmissionFollowsPlatformdVerdicts). It admits one VTEP.
type admitOnlyVTEP struct {
	vtep netip.Addr
}

func (a admitOnlyVTEP) AdmitVTEP(_ context.Context, vni uint32, vtep netip.Addr) error {
	if vtep != a.vtep {
		return errVTEPNotAdmitted{vtep: vtep, vni: vni}
	}
	return nil
}

// errVTEPNotAdmitted is admitOnlyVTEP's refusal of any other VTEP.
type errVTEPNotAdmitted struct {
	vtep netip.Addr
	vni  uint32
}

func (e errVTEPNotAdmitted) Error() string {
	return fmt.Sprintf("VTEP %s is not admitted to VNI %d", e.vtep, e.vni)
}

// decapFlowCount counts the decap table's flows admitting frames tunnelled
// from vtep on vni.
func decapFlowCount(t *testing.T, bridge string, vni uint32, vtep netip.Addr) int {
	t.Helper()
	out := runCmd(t, "ovs-ofctl", "-O", "OpenFlow13", "dump-flows", bridge,
		fmt.Sprintf("table=%d", modes.TableVXLANDecap))
	tunID := fmt.Sprintf("tun_id=%#x", vni)
	tunSrc := "tun_src=" + vtep.String()
	count := 0
	for _, line := range strings.Split(out, "\n") {
		fields := strings.FieldsFunc(line, func(r rune) bool { return r == ',' || r == ' ' })
		if slices.Contains(fields, tunID) && slices.Contains(fields, tunSrc) {
			count++
		}
	}
	return count
}

// startOverlayEVPNPeers starts the gateway's overlay speaker the way gatewayd
// runs it, outbound-only and dialling from its session address, and a remote
// VTEP speaker it peers with, and waits for the session.
func startOverlayEVPNPeers(t *testing.T, ctx context.Context, logger *slog.Logger) (gateway, remote *bgp.Speaker) {
	t.Helper()
	families := []bgp.AddressFamily{bgp.AFamilyEVPN}
	var rts []string
	for _, vni := range []uint32{overlayWithdrawnVNI, overlayKeptVNI} {
		rt, err := bgp.AutoRouteTarget(overlayWithdrawalOverlayASN, 0, vni)
		require.NoError(t, err)
		rts = append(rts, rt.String())
	}
	policy := bgp.PeerPolicyConfig{ImportRouteTargets: rts, ExportRouteTargets: rts}
	remotePort := freeLoopbackPort(t)

	remote = startOverlaySpeaker(t, ctx, logger, &bgp.BGPConfig{
		RouterID:        overlayRemoteVTEP,
		ASN:             overlayWithdrawalASN,
		ListenAddresses: []netip.Addr{overlayRemoteSession},
		ListenPort:      remotePort,
		EnabledFamilies: families,
	})
	require.NoError(t, remote.AddPeer(ctx, &bgp.NeighborConfig{
		Name:            "gateway",
		Address:         overlayGatewaySession,
		ASN:             overlayWithdrawalASN,
		PassiveMode:     true,
		EnabledFamilies: families,
		Policy:          policy,
	}))

	gateway = startOverlaySpeaker(t, ctx, logger, &bgp.BGPConfig{
		RouterID:        overlayGatewayVTEP,
		ASN:             overlayWithdrawalASN,
		OutboundOnly:    true,
		SessionSource:   overlayGatewaySession,
		Capabilities:    bgp.BGPCapabilities{EVPN: true},
		EnabledFamilies: families,
	}, bgp.WithBGPServer(dialPortServer{
		BGPServerInterface: bgp.NewGoBGPServerAdapter(server.NewBgpServer()),
		port:               uint32(remotePort),
	}))
	require.NoError(t, gateway.AddPeer(ctx, &bgp.NeighborConfig{
		Name:            "remote-vtep",
		Address:         overlayRemoteSession,
		ASN:             overlayWithdrawalASN,
		EnabledFamilies: families,
		Policy:          policy,
	}))

	waitFor(ctx, t, "the overlay BGP session", 100*time.Millisecond, overlayWithdrawalWait, func() bool {
		state, err := gateway.GetPeerState(ctx, overlayRemoteSession)
		return err == nil && state == bgp.PeerStateEstablished
	})
	return gateway, remote
}

// startOverlaySpeaker starts a speaker and stops it when the test ends.
func startOverlaySpeaker(t *testing.T, ctx context.Context, logger *slog.Logger, config *bgp.BGPConfig, opts ...bgp.SpeakerOption) *bgp.Speaker {
	t.Helper()
	speaker, err := bgp.NewSpeaker(config, logger, opts...)
	require.NoError(t, err, "create speaker %s", config.RouterID)
	require.NoError(t, speaker.Start(ctx), "start speaker %s", config.RouterID)
	t.Cleanup(func() {
		if err := speaker.Stop(context.Background()); err != nil {
			t.Errorf("stop speaker %s: %v", config.RouterID, err)
		}
	})
	return speaker
}

// startOverlayEVPNManager starts the remote VTEP's EVPN manager and stops it
// when the test ends.
func startOverlayEVPNManager(t *testing.T, ctx context.Context, config *bgp.EVPNManagerConfig) *bgp.EVPNManager {
	t.Helper()
	manager, err := bgp.NewEVPNManager(config)
	require.NoError(t, err, "create EVPN manager")
	require.NoError(t, manager.Start(ctx), "start EVPN manager")
	t.Cleanup(func() {
		if err := manager.Stop(context.Background()); err != nil {
			t.Errorf("stop EVPN manager: %v", err)
		}
	})
	return manager
}

// dialPortServer is the real GoBGP adapter with one change: the sessions it
// opens dial port instead of 179, so the remote VTEP can listen on a free
// loopback port. The speaker configuration has no remote-port field because
// nothing in production needs one.
type dialPortServer struct {
	bgp.BGPServerInterface
	port uint32
}

// AddPeer points the peer's outgoing connection at the test port.
func (d dialPortServer) AddPeer(ctx context.Context, req *api.AddPeerRequest) error {
	if req.GetPeer().GetTransport() == nil {
		req.Peer.Transport = &api.Transport{}
	}
	req.Peer.Transport.RemotePort = d.port
	return d.BGPServerInterface.AddPeer(ctx, req)
}

// freeLoopbackPort returns a loopback TCP port nothing is listening on.
func freeLoopbackPort(t *testing.T) uint16 {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	port := listener.Addr().(*net.TCPAddr).Port
	require.NoError(t, listener.Close())
	return uint16(port)
}
