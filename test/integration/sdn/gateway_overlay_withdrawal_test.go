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

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/deviceverdict"
	deviceentities "github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway"
	gwcommands "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/commands"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/modes"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/vxlan"
	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// The overlay withdrawal fabric: the gateway and one remote VTEP, each a real
// GoBGP speaker, peered over loopback. The remote VTEP's address is its
// device's platformd fabric allocation; neither tunnel address is configured
// anywhere, the decap flows only match on them.
var (
	overlayGatewaySession = netip.MustParseAddr("127.0.0.1")
	overlayRemoteSession  = netip.MustParseAddr("127.0.0.2")

	overlayGatewayVTEP = netip.MustParseAddr("192.0.2.10")
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
// a member of a segment or its device fails attestation. gatewayd's own VTEP
// admitter judges the remote VTEP's routes against platformd, wired as the
// serve command wires it: the VTEP is a platformd fabric allocation of an
// enrolled device whose latest verdict passed against a signed baseline. The
// remote VTEP's Type-3 routes reach the gateway over a real BGP session and
// install a decap flow per VNI in the decap table. Withdrawing one VNI's
// route removes that VNI's flow and leaves the other's, and a failed verdict
// for the device removes every flow it still has.
func TestGatewayOverlayWithdrawalRemovesDecapFlows(t *testing.T) {
	ctx, cancel := LongRunningTestContext()
	t.Cleanup(cancel)
	logger := slog.Default()

	client, err := platform.Connect(ctx, platform.NewOptions(
		platform.WithOnlyProtocol(platform.ProtocolGRPC),
		platform.WithGRPCAddr(helpers.GetGRPCEndpoint()),
		platform.WithTLSConfig(helpers.TLSConfigOrInsecure()),
	))
	require.NoError(t, err, "connect to platformd over gRPC as gatewayd does")
	t.Cleanup(func() {
		if err := client.Close(); err != nil {
			t.Errorf("close platformd client: %v", err)
		}
	})
	deviceID, remoteVTEP := enrollFabricDevice(t, ctx, client)

	runtime := &gateway.GatewayRuntime{}
	gwcommands.WireOverlayPlatform(runtime, client)
	device, err := runtime.OverlayDevices.Get(ctx, deviceID)
	require.NoError(t, err, "read the enrolled device through gatewayd's reader")
	require.NotNil(t, device, "platformd does not hold the enrolled device")
	control := &overlayControl{}
	admitter, err := gateway.NewVTEPAdmitter(gateway.VTEPAdmissionConfig{
		IPAM:     runtime.OverlayIPAM,
		Devices:  runtime.OverlayDevices,
		Verdicts: newSignedVerdict(deviceID, device.Serial),
		Revoker:  control,
		Replayer: control,
		Logger:   logger,
	})
	require.NoError(t, err, "create the VTEP admitter")

	bridge := setupTestBridge(t, overlayWithdrawalBridge)
	runCmd(t, "ovs-vsctl", "add-port", bridge.name, overlayWithdrawalAccessPort,
		"--", "set", "interface", overlayWithdrawalAccessPort, "type=internal")
	ofClient := bridge.createClient(t)
	ovsClient := newOVSDBClient(t)

	gatewaySpeaker, remoteSpeaker := startOverlayEVPNPeers(t, ctx, logger, remoteVTEP)
	remote := startOverlayEVPNManager(t, ctx, &bgp.EVPNManagerConfig{
		Speaker:    remoteSpeaker,
		Logger:     logger,
		LocalVTEP:  remoteVTEP,
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
		Admitter:   admitter,
		Logger:     logger,
	}, ovsClient, ofClient)
	require.NoError(t, err, "create overlay handler")
	control.handler = handler
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
		return decapFlowCount(t, bridge.name, overlayWithdrawnVNI, remoteVTEP) == 1 &&
			decapFlowCount(t, bridge.name, overlayKeptVNI, remoteVTEP) == 1
	})
	admitted := admitter.Admitted(handler.InstalledVTEPs())
	require.Len(t, admitted, 1, "the installed VTEP must carry the admission that let it in")
	require.Equal(t, deviceID, admitted[0].DeviceID)
	require.Equal(t, string(deviceentities.BaselineSourceSigned), admitted[0].BaselineSource)

	t.Run("RouteWithdrawalRemovesThatVNIsDecapFlow", func(t *testing.T) {
		require.NoError(t, remote.LeaveVNI(ctx, overlayWithdrawnVNI))

		waitFor(ctx, t, "the withdrawn VNI's decap flow to go", 100*time.Millisecond, overlayWithdrawalWait, func() bool {
			return decapFlowCount(t, bridge.name, overlayWithdrawnVNI, remoteVTEP) == 0
		})
		require.Equal(t, 1, decapFlowCount(t, bridge.name, overlayKeptVNI, remoteVTEP),
			"a withdrawal must leave the VTEP's other segments decapsulating")
		require.Equal(t, []modes.InstalledVTEP{{VTEP: remoteVTEP, VNIs: []uint32{overlayKeptVNI}}}, handler.InstalledVTEPs())
	})

	t.Run("FailedVerdictRemovesEveryDecapFlow", func(t *testing.T) {
		admitter.OnDeviceVerdict(ctx, deviceverdict.RecordedDeviceVerdict{
			Verdict: deviceverdict.DeviceVerdict{
				DeviceID:      deviceID,
				Serial:        device.Serial,
				Cryptographic: true,
				Reason:        "quote signature does not verify",
			},
			EventID:    "overlay-withdrawal-failed",
			RecordedAt: time.Now().UTC(),
		})

		require.Zero(t, decapFlowCount(t, bridge.name, overlayKeptVNI, remoteVTEP),
			"a VTEP whose device failed attestation must not keep a decap flow")
		require.Empty(t, handler.InstalledVTEPs())

		var refused gateway.ErrOverlayVTEPVerdict
		require.ErrorAs(t, admitter.AdmitVTEP(ctx, overlayKeptVNI, remoteVTEP), &refused,
			"a signed verdict attested before the failure must not readmit the VTEP")
	})
}

// signedVerdict serves the one admission input platformd cannot produce: a
// passing verdict against a signed PCR baseline. platformd's quote verifier
// records only a trust-on-first-use baseline (DeviceQuoteVerifier.
// evaluateBaseline), the profile baseline is read-only on every transport
// (DeviceProfile.pcr_baseline in device.proto), and gatewayd admits only a
// signed one. Every other input is platformd's.
type signedVerdict struct {
	recorded deviceverdict.RecordedDeviceVerdict
}

// newSignedVerdict returns the passing verdict of deviceID, attested now.
func newSignedVerdict(deviceID uint64, serial string) *signedVerdict {
	return &signedVerdict{recorded: deviceverdict.RecordedDeviceVerdict{
		Verdict: deviceverdict.DeviceVerdict{
			DeviceID:       deviceID,
			Serial:         serial,
			Passed:         true,
			BaselineSource: string(deviceentities.BaselineSourceSigned),
		},
		EventID:    "overlay-withdrawal-signed",
		RecordedAt: time.Now().UTC(),
	}}
}

// LatestDeviceVerdict implements gateway.OverlayVerdictReader.
func (s *signedVerdict) LatestDeviceVerdict(_ context.Context, deviceID uint64) (*deviceverdict.RecordedDeviceVerdict, error) {
	if deviceID != s.recorded.Verdict.DeviceID {
		return nil, gateway.ErrOverlayRecordNotFound
	}
	recorded := s.recorded
	return &recorded, nil
}

// overlayControl hands the admitter's revocations and replays to the overlay
// handler, as gatewayd's own proxy does: the admitter is built first, because
// the handler is configured with it. The handler is set before it starts, so
// before any route reaches the admitter.
type overlayControl struct {
	handler *modes.OverlayModeHandler
}

func (c *overlayControl) RevokeVTEP(ctx context.Context, vtep netip.Addr) error {
	return c.handler.RevokeVTEP(ctx, vtep)
}

func (c *overlayControl) ReplayVTEP(ctx context.Context, vtep netip.Addr) error {
	return c.handler.ReplayVTEP(ctx, vtep)
}

func (c *overlayControl) RefusedVTEPs() []netip.Addr {
	return c.handler.RefusedVTEPs()
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
func startOverlayEVPNPeers(t *testing.T, ctx context.Context, logger *slog.Logger, remoteVTEP netip.Addr) (gatewaySpeaker, remote *bgp.Speaker) {
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
		RouterID:        remoteVTEP,
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

	gatewaySpeaker = startOverlaySpeaker(t, ctx, logger, &bgp.BGPConfig{
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
	require.NoError(t, gatewaySpeaker.AddPeer(ctx, &bgp.NeighborConfig{
		Name:            "remote-vtep",
		Address:         overlayRemoteSession,
		ASN:             overlayWithdrawalASN,
		EnabledFamilies: families,
		Policy:          policy,
	}))

	waitFor(ctx, t, "the overlay BGP session", 100*time.Millisecond, overlayWithdrawalWait, func() bool {
		state, err := gatewaySpeaker.GetPeerState(ctx, overlayRemoteSession)
		return err == nil && state == bgp.PeerStateEstablished
	})
	return gatewaySpeaker, remote
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
