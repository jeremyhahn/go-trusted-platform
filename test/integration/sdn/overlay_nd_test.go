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
	"encoding/binary"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/mdlayher/packet"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"golang.org/x/sys/unix"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/modes"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/vxlan"
)

// These tests drive overlay ND suppression (#709) on a live OVS bridge: a
// real meter, a real packet-in, and a real packet-out, seen from a
// namespace on the segment's VLAN.

const (
	ovlNDBridge = "tp-ovl-nd"
	ovlNDNS     = "tpovlnd"
	ovlNDVNI    = 10709
	ovlNDVLAN   = 709

	// ovlNDSolicitorCIDR only brings the namespace's VLAN interface up; the
	// solicitations are written raw.
	ovlNDSolicitorCIDR = "10.70.9.2/24"

	// ovlNDNoAnswerWait bounds the wait for an advertisement that must not
	// come, once the controller has already accounted for the solicitation.
	ovlNDNoAnswerWait = 2 * time.Second

	// ovlNDHoldDown is the controller's first fallback hold-down here. The
	// 30-second default would spend 90 seconds of the package's budget
	// waiting out it and the doubled one; the back-off itself is unit
	// tested on a fake clock. It stays well above the no-answer check a
	// fallen-back subtest makes before the hold-down ends.
	ovlNDHoldDown = 10 * time.Second

	// ovlNDHoldDownWait outlasts the first fallback hold-down by a poll and
	// a punt refresh, and ovlNDDoubledHoldDownWait the doubled one that
	// follows a second fallback inside the quiet period
	// (docs/sdn/overlay/architecture.md, ND suppression).
	ovlNDHoldDownWait        = ovlNDHoldDown + 15*time.Second
	ovlNDDoubledHoldDownWait = 2*ovlNDHoldDown + 20*time.Second

	// ovlNDBurst solicitations far exceed the punt meter's 64 kb burst.
	ovlNDBurst = 2000

	// ovlNDMeterID is the meter on the ND punt.
	ovlNDMeterID = 709

	ethTypeIPv6Frame   = 0x86dd
	icmpv6ProtoNumber  = 58
	icmpv6TypeNS       = 135
	icmpv6TypeNA       = 136
	ndOptionSourceLLA  = 1
	ndOptionTargetLLA  = 2
	ndFlagSolicited    = 0x40
	ndFlagOverride     = 0x20
	ndFrameICMPOffset  = 14 + 40
	ndMessageHeaderLen = 24
)

var (
	ovlNDSolicitorIP = netip.MustParseAddr("fd00:709::2")
	ovlNDTargetIP    = netip.MustParseAddr("fd00:709::10")
	ovlNDUnknownIP   = netip.MustParseAddr("fd00:709::99")
	ovlNDTargetMAC   = net.HardwareAddr{0x02, 0x70, 0x09, 0x00, 0x00, 0x10}
)

// proxyAdvert is the part of a neighbor advertisement the tests check.
type proxyAdvert struct {
	dstMAC     net.HardwareAddr
	srcMAC     net.HardwareAddr
	src        netip.Addr
	dst        netip.Addr
	flags      byte
	target     netip.Addr
	targetLLA  net.HardwareAddr
	checksumOK bool
}

// TestOverlayND_SuppressesKnownTargets proves, on OVS, RFC 9161 ND
// suppression and its fail mode: a solicitation for a known binding is
// answered on the segment's VLAN and not flooded; one for an unknown target
// and a DAD probe flood unanswered; punts a crashed controller leaves behind
// expire, and the controller restores them when it returns; over the meter
// the controller falls back to the flood; and a stopped controller leaves
// no punt and no meter behind.
func TestOverlayND_SuppressesKnownTargets(t *testing.T) {
	requireOVSForTest(t)

	bridge := setupTestBridge(t, ovlNDBridge)
	// The overlay owns this bridge: drop the default NORMAL flow.
	runCmd(t, "ovs-ofctl", "-O", "OpenFlow13", "del-flows", bridge.name)

	ep := createNSEndpoint(t, bridge.name, ovlNDNS, ovlNDSolicitorCIDR, ovlNDVLAN)
	// The namespace's own IPv6 traffic would land on the flood flow the
	// tests count.
	runCmd(t, "ip", "netns", "exec", ep.NS, "sysctl", "-qw", "net.ipv6.conf.all.disable_ipv6=1")
	solicitorMAC, err := net.ParseMAC(ep.MAC)
	require.NoError(t, err)
	conn := openNDSocket(t, ep)

	ctx, cancel := context.WithTimeout(context.Background(), 180*time.Second)
	defer cancel()

	ofClient := bridge.createClient(t)
	ovsClient := newOVSDBClient(t)
	handler := startOverlay(ctx, t, ovlNDBridge, netip.MustParseAddr("10.70.9.1"), ovsClient, ofClient, ep.HostIf)
	dumpBridgeOnFailure(t, bridge.name)

	require.NoError(t, handler.AddVNI(ctx, ovlNDVNI, ovlNDVLAN))
	require.NoError(t, handler.LearnMAC(ctx, ovlNDVNI, ovlNDTargetMAC, ovlNDTargetIP))
	waitFor(ctx, t, "the known target's punt", 50*time.Millisecond, 10*time.Second, func() bool {
		punts, _ := ovlNDPunts(ctx, t, ovsClient)
		return punts == 1
	})
	ovlNDSettle(t)

	t.Run("KnownTargetAnsweredOnTheSegmentVLANNotFlooded", func(t *testing.T) {
		floods := ovlNDFloodPackets(ctx, t, ovsClient)
		_, punted := ovlNDPunts(ctx, t, ovsClient)
		before := handler.GetStatus().NDSuppression

		sendNDFrame(t, conn, neighborSolicitation(solicitorMAC, ovlNDSolicitorIP, ovlNDTargetIP))

		// The socket is on the VLAN sub-interface: an untagged or
		// wrongly tagged advertisement never reaches it.
		na, ok := readProxyAdvert(t, conn, ovlNDTargetIP, 10*time.Second)
		require.True(t, ok, "no advertisement on VLAN %d", ovlNDVLAN)
		assert.True(t, na.checksumOK, "ICMPv6 checksum")
		assert.Equal(t, solicitorMAC.String(), na.dstMAC.String())
		assert.Equal(t, ovlNDTargetMAC.String(), na.srcMAC.String())
		assert.Equal(t, ovlNDTargetIP, na.src)
		assert.Equal(t, ovlNDSolicitorIP, na.dst)
		assert.Equal(t, byte(ndFlagSolicited|ndFlagOverride), na.flags)
		assert.Equal(t, ovlNDTargetMAC.String(), na.targetLLA.String())

		// The counter moves after the packet-out returns.
		waitFor(ctx, t, "the answer to be counted", 10*time.Millisecond, 5*time.Second, func() bool {
			return handler.GetStatus().NDSuppression.Answered == before.Answered+1
		})
		// Once the punt has counted the solicitation, the flood flow's
		// counter is as current as the datapath's.
		waitFor(ctx, t, "the punt to count the solicitation", 50*time.Millisecond, 10*time.Second, func() bool {
			_, packets := ovlNDPunts(ctx, t, ovsClient)
			return packets > punted
		})
		assert.Equal(t, floods, ovlNDFloodPackets(ctx, t, ovsClient), "an answered solicitation must not flood")
		assert.Equal(t, before.Flooded, handler.GetStatus().NDSuppression.Flooded)
	})

	t.Run("UnknownTargetFloods", func(t *testing.T) {
		floods := ovlNDFloodPackets(ctx, t, ovsClient)
		before := handler.GetStatus().NDSuppression

		sendNDFrame(t, conn, neighborSolicitation(solicitorMAC, ovlNDSolicitorIP, ovlNDUnknownIP))

		waitFor(ctx, t, "the solicitation to flood", 50*time.Millisecond, 10*time.Second, func() bool {
			return ovlNDFloodPackets(ctx, t, ovsClient) > floods
		})
		_, answered := readProxyAdvert(t, conn, ovlNDUnknownIP, ovlNDNoAnswerWait)
		assert.False(t, answered, "nothing knows the target")
		assert.Equal(t, before.Received, handler.GetStatus().NDSuppression.Received, "an unknown target is not punted")
	})

	t.Run("DADProbeFloodsUnanswered", func(t *testing.T) {
		floods := ovlNDFloodPackets(ctx, t, ovsClient)
		before := handler.GetStatus().NDSuppression

		sendNDFrame(t, conn, neighborSolicitation(solicitorMAC, netip.IPv6Unspecified(), ovlNDTargetIP))

		waitFor(ctx, t, "the probe to flood", 50*time.Millisecond, 10*time.Second, func() bool {
			return ovlNDFloodPackets(ctx, t, ovsClient) > floods
		})
		_, answered := readProxyAdvert(t, conn, ovlNDTargetIP, ovlNDNoAnswerWait)
		assert.False(t, answered, "a DAD probe must not be answered: the prober would see its address in use")
		after := handler.GetStatus().NDSuppression
		assert.Equal(t, before.Received, after.Received, "the DAD flow outranks the punt")
		assert.Equal(t, before.Answered, after.Answered)
	})

	t.Run("DroppedConnectionFallsBack", func(t *testing.T) {
		// A dropped connection is what a crash looks like to OVS. The
		// controller redials, cannot know what the switch kept, and falls
		// back: the punts go and every solicitation floods for the hold-down.
		fallbacks := handler.GetStatus().NDSuppression.Fallbacks
		require.NoError(t, ofClient.Disconnect())

		waitFor(ctx, t, "the redial to fall back", 100*time.Millisecond, 20*time.Second, func() bool {
			punts, _ := ovlNDPunts(ctx, t, ovsClient)
			return punts == 0 && handler.GetStatus().NDSuppression.Fallbacks > fallbacks
		})
		ovlNDSettle(t)
		floods := ovlNDFloodPackets(ctx, t, ovsClient)
		sendNDFrame(t, conn, neighborSolicitation(solicitorMAC, ovlNDSolicitorIP, ovlNDTargetIP))
		waitFor(ctx, t, "the solicitation to flood", 50*time.Millisecond, 10*time.Second, func() bool {
			return ovlNDFloodPackets(ctx, t, ovsClient) > floods
		})
		_, answered := readProxyAdvert(t, conn, ovlNDTargetIP, ovlNDNoAnswerWait)
		assert.False(t, answered, "nothing answers during the hold-down")

		// The reconnected controller restores suppression on its own once
		// the hold-down ends.
		require.NoError(t, ofClient.Connect(ctx))
		waitFor(ctx, t, "the punt to return after the hold-down", 100*time.Millisecond, ovlNDHoldDownWait, func() bool {
			punts, _ := ovlNDPunts(ctx, t, ovsClient)
			return punts == 1
		})
		ovlNDSettle(t)
		sendNDFrame(t, conn, neighborSolicitation(solicitorMAC, ovlNDSolicitorIP, ovlNDTargetIP))
		_, answered = readProxyAdvert(t, conn, ovlNDTargetIP, 10*time.Second)
		assert.True(t, answered, "the returned controller answers again")
	})

	// This burst leaves advertisements in the socket: later subtests must
	// not read it for one.
	t.Run("OverMeterFallsBackToTheFlood", func(t *testing.T) {
		before := handler.GetStatus().NDSuppression
		solicitation := neighborSolicitation(solicitorMAC, ovlNDSolicitorIP, ovlNDTargetIP)
		for range ovlNDBurst {
			sendNDFrame(t, conn, solicitation)
		}

		waitFor(ctx, t, "the controller to fall back", 50*time.Millisecond, 10*time.Second, func() bool {
			status := handler.GetStatus().NDSuppression
			return status.Fallbacks > before.Fallbacks && !status.Suppressing
		})
		punts, _ := ovlNDPunts(ctx, t, ovsClient)
		require.Zero(t, punts, "the fallback removes every punt")
		after := handler.GetStatus().NDSuppression
		assert.Greater(t, after.MeterDropped+after.QueueDropped, before.MeterDropped+before.QueueDropped,
			"the fallback follows a drop")

		ovlNDSettle(t)
		floods := ovlNDFloodPackets(ctx, t, ovsClient)
		// A failed flood wait shows whether a punt or a meter was back by then.
		flooded := false
		t.Cleanup(func() {
			if flooded || !t.Failed() {
				return
			}
			t.Logf("table 50 at the failed flood wait:\n%s",
				runCmd(t, "ovs-ofctl", "-O", "OpenFlow13", "dump-flows", bridge.name, "table=50"))
			t.Logf("meters at the failed flood wait:\n%s",
				runCmd(t, "ovs-ofctl", "-O", "OpenFlow13", "dump-meters", bridge.name))
		})
		sendNDFrame(t, conn, solicitation)
		waitFor(ctx, t, "the known target's solicitation to flood", 50*time.Millisecond, 10*time.Second, func() bool {
			return ovlNDFloodPackets(ctx, t, ovsClient) > floods
		})
		flooded = true

		// The second fallback inside the quiet period holds down twice as long.
		waitFor(ctx, t, "suppression to resume after the hold-down", 500*time.Millisecond, ovlNDDoubledHoldDownWait, func() bool {
			punts, _ := ovlNDPunts(ctx, t, ovsClient)
			return punts == 1 && handler.GetStatus().NDSuppression.Suppressing
		})
	})

	t.Run("StoppedControllerLeavesNoPuntOrMeter", func(t *testing.T) {
		require.NoError(t, handler.Stop(ctx))

		punts, _ := ovlNDPunts(ctx, t, ovsClient)
		assert.Zero(t, punts)
		meters := runCmd(t, "ovs-ofctl", "-O", "OpenFlow13", "dump-meters", bridge.name)
		assert.NotContains(t, meters, fmt.Sprintf("meter=%d ", ovlNDMeterID))
	})
}

// startOverlay starts an overlay without a control plane on bridge, with
// localIP its VTEP and accessPort carrying its VLANs, and stops it at
// cleanup.
func startOverlay(ctx context.Context, t *testing.T, bridge string, localIP netip.Addr,
	ovsClient *ovs.Client, ofClient *openflow.Client, accessPort string) *modes.OverlayModeHandler {
	t.Helper()
	cfg := &modes.OverlayModeConfig{
		VTEPConfig: &vxlan.VTEPConfig{
			LocalIP:       localIP,
			UnderlayIface: "eth0",
			UnderlayMTU:   vxlan.MinimumUnderlayMTU,
			VXLANPort:     vxlan.DefaultVXLANPort,
		},
		BridgeName:         bridge,
		AccessPort:         accessPort,
		NDFallbackHoldDown: ovlNDHoldDown,
		Logger:             slog.Default(),
	}
	handler, err := modes.NewOverlayModeHandler(cfg, ovsClient, ofClient)
	require.NoError(t, err)
	require.NoError(t, handler.Start(ctx), "start overlay")
	t.Cleanup(func() {
		stopCtx, stopCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer stopCancel()
		// A subtest disconnects the controller; Stop needs it back.
		if err := ofClient.Connect(stopCtx); err != nil {
			t.Logf("reconnect before overlay stop: %v", err)
		}
		// The last subtest stops the overlay itself.
		if err := handler.Stop(stopCtx); err != nil && !errors.Is(err, modes.ErrNotRunning) {
			t.Logf("overlay stop: %v", err)
		}
	})
	return handler
}

// ovlNDFloodPackets is the packet count of the VNI's flood flow in the
// egress table, the one overlay flow there that is not its miss.
func ovlNDFloodPackets(ctx context.Context, t *testing.T, client *ovs.Client) int64 {
	t.Helper()
	flows, err := client.GetFlowStats(ctx, ovlNDBridge,
		fmt.Sprintf("table=%d,cookie=0x%x/0x%x", modes.TableEgress, modes.OverlayCookie, ovs.OwnerCookieMask))
	require.NoError(t, err, "dump table %d", modes.TableEgress)
	for _, flow := range flows {
		if flow.Priority != 0 {
			return flow.PacketCount
		}
	}
	t.Fatalf("no flood flow in table %d: %+v", modes.TableEgress, flows)
	return 0
}

// ovlNDPunts is the number of ND punt flows on the bridge and the packets
// they have sent to the controller.
func ovlNDPunts(ctx context.Context, t *testing.T, client *ovs.Client) (int, int64) {
	t.Helper()
	flows, err := client.GetFlowStats(ctx, ovlNDBridge,
		fmt.Sprintf("table=%d,cookie=0x%x/0xffffffffffffffff", modes.TableARP, modes.OverlayNDCookie))
	require.NoError(t, err, "dump the ND punts")
	var packets int64
	for _, flow := range flows {
		packets += flow.PacketCount
	}
	return len(flows), packets
}

// ovlNDSettle waits for the datapath to follow a punt change the OpenFlow
// tables already show. OVS revalidates its kernel megaflows asynchronously,
// so a solicitation sent right after a punt is removed can still ride the
// old megaflow to the controller, which answers a known target instead of
// letting it flood; one sent right after a punt is installed can still
// flood. Every send that follows a punt change waits here first.
func ovlNDSettle(t *testing.T) {
	t.Helper()
	runCmd(t, "ovs-appctl", "revalidator/wait")
}

// openNDSocket opens a raw IPv6 packet socket on the endpoint's VLAN
// interface, inside its namespace.
func openNDSocket(t *testing.T, ep *nsEndpoint) *packet.Conn {
	t.Helper()
	var conn *packet.Conn
	err := inNetns(ep.NS, func() error {
		ifi, err := net.InterfaceByName(ep.DataIf)
		if err != nil {
			return err
		}
		conn, err = packet.Listen(ifi, packet.Raw, unix.ETH_P_IPV6, nil)
		return err
	})
	require.NoError(t, err, "open packet socket on %s", ep.DataIf)
	t.Cleanup(func() { conn.Close() })
	return conn
}

// sendNDFrame writes a whole Ethernet frame to the socket.
func sendNDFrame(t *testing.T, conn *packet.Conn, frame []byte) {
	t.Helper()
	_, err := conn.WriteTo(frame, &packet.Addr{HardwareAddr: net.HardwareAddr(frame[0:6])})
	require.NoError(t, err, "send solicitation")
}

// readProxyAdvert reads frames until an advertisement for target arrives
// or timeout passes; the socket also sees the solicitations it sent.
func readProxyAdvert(t *testing.T, conn *packet.Conn, target netip.Addr, timeout time.Duration) (proxyAdvert, bool) {
	t.Helper()
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(timeout)))
	buf := make([]byte, 2048)
	for {
		n, _, err := conn.ReadFrom(buf)
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return proxyAdvert{}, false
		}
		require.NoError(t, err, "read from packet socket")
		if na, ok := parseProxyAdvert(buf[:n]); ok && na.target == target {
			return na, true
		}
	}
}

// neighborSolicitation builds an NS for target to its solicited-node
// address. An unspecified src makes it a DAD probe, which carries no
// source link-layer option.
func neighborSolicitation(srcMAC net.HardwareAddr, src, target netip.Addr) []byte {
	t16 := target.As16()
	dst := netip.AddrFrom16([16]byte{0: 0xff, 1: 0x02, 11: 0x01, 12: 0xff, 13: t16[13], 14: t16[14], 15: t16[15]})
	dstMAC := net.HardwareAddr{0x33, 0x33, 0xff, t16[13], t16[14], t16[15]}

	icmp := make([]byte, ndMessageHeaderLen)
	icmp[0] = icmpv6TypeNS
	copy(icmp[8:], t16[:])
	if !src.IsUnspecified() {
		icmp = append(icmp, ndOptionSourceLLA, 1)
		icmp = append(icmp, srcMAC...)
	}
	binary.BigEndian.PutUint16(icmp[2:], icmpv6Checksum(src, dst, icmp))

	frame := make([]byte, 0, ndFrameICMPOffset+len(icmp))
	frame = append(frame, dstMAC...)
	frame = append(frame, srcMAC...)
	frame = binary.BigEndian.AppendUint16(frame, ethTypeIPv6Frame)
	frame = append(frame, 0x60, 0, 0, 0)
	frame = binary.BigEndian.AppendUint16(frame, uint16(len(icmp)))
	frame = append(frame, icmpv6ProtoNumber, 255)
	s16, d16 := src.As16(), dst.As16()
	frame = append(frame, s16[:]...)
	frame = append(frame, d16[:]...)
	return append(frame, icmp...)
}

// parseProxyAdvert reads an untagged Ethernet frame as a neighbor
// advertisement.
func parseProxyAdvert(frame []byte) (proxyAdvert, bool) {
	if len(frame) < ndFrameICMPOffset+ndMessageHeaderLen ||
		binary.BigEndian.Uint16(frame[12:14]) != ethTypeIPv6Frame ||
		frame[20] != icmpv6ProtoNumber || frame[ndFrameICMPOffset] != icmpv6TypeNA {
		return proxyAdvert{}, false
	}
	payloadLen := int(binary.BigEndian.Uint16(frame[18:20]))
	if ndFrameICMPOffset+payloadLen > len(frame) || payloadLen < ndMessageHeaderLen {
		return proxyAdvert{}, false
	}
	icmp := frame[ndFrameICMPOffset : ndFrameICMPOffset+payloadLen]
	na := proxyAdvert{
		dstMAC: net.HardwareAddr(frame[0:6]),
		srcMAC: net.HardwareAddr(frame[6:12]),
		src:    netip.AddrFrom16([16]byte(frame[22:38])),
		dst:    netip.AddrFrom16([16]byte(frame[38:54])),
		flags:  icmp[4],
		target: netip.AddrFrom16([16]byte(icmp[8:24])),
	}
	na.checksumOK = icmpv6Checksum(na.src, na.dst, icmp) == 0
	for options := icmp[ndMessageHeaderLen:]; len(options) >= 8; {
		size := int(options[1]) * 8
		if size == 0 || size > len(options) {
			break
		}
		if options[0] == ndOptionTargetLLA {
			na.targetLLA = net.HardwareAddr(options[2:8])
		}
		options = options[size:]
	}
	return na, true
}

// icmpv6Checksum is the ICMPv6 checksum of body over the IPv6 pseudo
// header; over a body that already carries its checksum it is zero.
func icmpv6Checksum(src, dst netip.Addr, body []byte) uint16 {
	s16, d16 := src.As16(), dst.As16()
	data := make([]byte, 0, 40+len(body))
	data = append(data, s16[:]...)
	data = append(data, d16[:]...)
	data = binary.BigEndian.AppendUint32(data, uint32(len(body)))
	data = append(data, 0, 0, 0, icmpv6ProtoNumber)
	data = append(data, body...)

	var sum uint32
	for i := 0; i+1 < len(data); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(data[i:]))
	}
	if len(data)%2 == 1 {
		sum += uint32(data[len(data)-1]) << 8
	}
	for sum>>16 != 0 {
		sum = sum&0xffff + sum>>16
	}
	return ^uint16(sum)
}
