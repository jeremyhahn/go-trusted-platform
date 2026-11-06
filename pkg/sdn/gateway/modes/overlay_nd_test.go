package modes

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The access port's OpenFlow number in the fake OVSDB, and the host that
// sends the solicitations.
const ndAccessOFPort uint32 = 3

var (
	ndSolicitorMAC = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x01}
	ndSolicitorIP  = netip.MustParseAddr("2001:db8::2")
	ndTargetIP     = netip.MustParseAddr("2001:db8::10")
)

// ndSolicitation is the fields of a solicitation from the access port on
// the test VNI, for fakeSwitch.lookup.
func ndSolicitation(src, target netip.Addr) []string {
	return []string{
		"in_port=3",
		"tun_id=10100",
		"eth_type=0x86dd",
		"ip_proto=58",
		"icmpv6_type=135",
		"ipv6_src=" + src.String(),
		"nd_target=" + target.String(),
	}
}

// ndPuntOf is what a solicitation for target hits in table 40.
func ndPuntOf(t *testing.T, f *overlayFixture, target netip.Addr) string {
	t.Helper()
	return f.sw.lookup(t, TableARP, ndSolicitation(ndSolicitorIP, target)...)
}

const (
	ndPunted = "controller:meter=709"
	ndFloods = "goto:60"
)

func TestOverlayNDPuntsOnlyKnownTargets(t *testing.T) {
	f := newOverlayFixture(t, nil).withVNI(t)
	require.NoError(t, f.handler.LearnMAC(context.Background(), ovlL2VNI, ovlHostMAC, ndTargetIP))

	assert.Equal(t, ndPunted, ndPuntOf(t, f, ndTargetIP),
		"a known target is punted, metered, and not flooded")
	assert.Equal(t, ndFloods, ndPuntOf(t, f, netip.MustParseAddr("2001:db8::99")), "an unknown target floods")
	assert.Equal(t, ndFloods, f.sw.lookup(t, TableARP, ndSolicitation(netip.IPv6Unspecified(), ndTargetIP)...),
		"a DAD probe floods, even for a known target")

	for _, batch := range f.sw.batchesSince(0) {
		for _, mod := range batch {
			for _, instruction := range mod.Instructions {
				_, metered := instruction.(*openflow.InstructionMeter)
				assert.False(t, metered, "an OFPIT_METER drops the whole flow entry over the rate")
			}
		}
	}
}

func TestOverlayNDPuntsExpireUnlessRefreshed(t *testing.T) {
	f := newOverlayFixture(t, nil).withVNI(t)
	require.NoError(t, f.handler.LearnMAC(context.Background(), ovlL2VNI, ovlHostMAC, ndTargetIP))

	timeouts := f.sw.hardTimeouts()
	require.Len(t, timeouts, 1, "only the punt expires")
	for flow, timeout := range timeouts {
		assert.Contains(t, flow, "nd_target=2001:db8::10")
		assert.Equal(t, overlayNDPuntHardTimeout, timeout)
	}
	assert.Less(t, 2*overlayNDPuntRefresh, time.Duration(overlayNDPuntHardTimeout)*time.Second,
		"a refresh may be missed without the punts expiring")

	// A crashed controller refreshes nothing: the punts expire and the
	// solicitations flood.
	f.sw.expire()
	assert.Equal(t, ndFloods, ndPuntOf(t, f, ndTargetIP))

	f.handler.ndTick(context.Background(), time.Now().Add(overlayNDPuntRefresh))
	assert.Equal(t, ndPunted, ndPuntOf(t, f, ndTargetIP), "a live controller puts them back")
}

// The refresh is a mod per binding and a barrier, sent without mu so
// binding changes are not held behind it. A withdrawal it races still
// wins: here the withdrawal's delete reaches the switch while the refresh
// is in flight, and the refresh lands after it.
func TestOverlayNDRefreshDoesNotUndoAWithdrawal(t *testing.T) {
	f := newOverlayFixture(t, nil).withVNI(t)
	ctx := context.Background()
	require.NoError(t, f.handler.LearnMAC(ctx, ovlL2VNI, ovlHostMAC, ndTargetIP))
	stopNDWatch(t, f)
	var raced atomic.Bool
	f.sw.mu.Lock()
	f.sw.beforeSend = func([]*openflow.FlowMod) {
		if !raced.CompareAndSwap(false, true) {
			return
		}
		if !f.handler.mu.TryLock() {
			t.Error("the refresh holds mu while it sends")
			return
		}
		f.handler.mu.Unlock()
		assert.NoError(t, f.handler.ForgetMAC(ctx, ovlL2VNI, ovlHostMAC))
	}
	f.sw.mu.Unlock()

	f.handler.ndTick(ctx, time.Now().Add(overlayNDPuntRefresh))

	require.True(t, raced.Load(), "the refresh sent its batch")
	assert.Equal(t, ndFloods, ndPuntOf(t, f, ndTargetIP), "the withdrawn target stays off the punts")
}

// stopNDWatch stops the watch's own ticks, so a test runs every round
// itself and nothing else takes mu.
func stopNDWatch(t *testing.T, f *overlayFixture) {
	t.Helper()
	f.handler.mu.Lock()
	stop, done := f.handler.ndStopPoll, f.handler.ndPollDone
	f.handler.mu.Unlock()
	require.NotNil(t, stop, "the ND watch is running")
	stop()
	<-done
}

func TestOverlayNDPuntsCarryTheirOwnCookie(t *testing.T) {
	f := newOverlayFixture(t, nil).withVNI(t)
	ctx := context.Background()
	require.NoError(t, f.handler.LearnMAC(ctx, ovlL2VNI, ovlHostMAC, ndTargetIP))
	overlay := len(f.sw.table()) - 1

	require.NoError(t, f.sw.SendFlowMods(ctx, []*openflow.FlowMod{ndFlush()}))

	assert.Equal(t, ndFloods, ndPuntOf(t, f, ndTargetIP))
	assert.Len(t, f.sw.table(), overlay, "the ND flush removes the punts alone")
}

func TestOverlayNDAnswersOnTheSegmentVLAN(t *testing.T) {
	f := newOverlayFixture(t, nil).withVNI(t)
	require.NoError(t, f.handler.LearnMAC(context.Background(), ovlL2VNI, ovlHostMAC, ndTargetIP))

	require.NoError(t, f.handler.handleNDPacketIn(context.Background(), ndPacketIn(nxmTunnelMatch(ovlL2VNI), validNS(ndTargetIP).frame())))

	status := f.handler.GetStatus().NDSuppression
	assert.Equal(t, uint64(1), status.Received)
	assert.Equal(t, uint64(1), status.Answered)
	require.Len(t, f.sw.packetOuts, 1)
	out := f.sw.packetOuts[0]
	assert.Equal(t, ndAccessOFPort, out.InPort)
	require.Len(t, out.Actions, 3)
	assert.IsType(t, &openflow.ActionPushVLAN{}, out.Actions[0])
	assert.Equal(t, "set:vlan=100", describeAction(out.Actions[1]))
	assert.Equal(t, "output:IN_PORT", describeAction(out.Actions[2]))

	na := parseTestNA(t, out.Data)
	assert.Equal(t, ndSolicitorMAC.String(), na.DstMAC.String())
	assert.Equal(t, ovlHostMAC.String(), na.SrcMAC.String())
	assert.Equal(t, ndSolicitorIP, na.DstIP)
	assert.Equal(t, ndTargetIP, na.SrcIP)
	assert.Equal(t, ndTargetIP, na.Target)
	assert.Equal(t, ovlHostMAC.String(), na.TargetLLA.String())
	assert.False(t, na.Router)
	assert.True(t, na.Solicited)
	assert.True(t, na.Override)
}

func TestOverlayNDReadsOXMTunnelID(t *testing.T) {
	f := newOverlayFixture(t, nil).withVNI(t)
	require.NoError(t, f.handler.LearnMAC(context.Background(), ovlL2VNI, ovlHostMAC, ndTargetIP))

	// OVS reports tun_id in an OpenFlow 1.3 packet-in as the OXM basic
	// TUNNEL_ID, not the NXM field the flows are written with.
	match := openflow.NewMatch()
	match.AddInPort(ndAccessOFPort)
	match.AddField(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBTunnelId, uint64Bytes(uint64(ovlL2VNI)), nil)

	require.NoError(t, f.handler.handleNDPacketIn(context.Background(), ndPacketIn(*match, validNS(ndTargetIP).frame())))

	assert.Equal(t, uint64(1), f.handler.GetStatus().NDSuppression.Answered)
	require.Len(t, f.sw.packetOuts, 1)
}

func TestOverlayNDAnswersPacketInFromSwitch(t *testing.T) {
	f := newOverlayFixture(t, nil).withVNI(t)
	require.NoError(t, f.handler.LearnMAC(context.Background(), ovlL2VNI, ovlHostMAC, ndTargetIP))

	f.sw.emitPacketIn(ndPacketIn(nxmTunnelMatch(ovlL2VNI), validNS(ndTargetIP).frame()))

	require.Eventually(t, func() bool {
		return f.handler.GetStatus().NDSuppression.Answered == 1
	}, 5*time.Second, time.Millisecond)
	f.sw.mu.Lock()
	reply := f.sw.packetOuts[0].Data
	f.sw.mu.Unlock()
	assert.Equal(t, ndTargetIP, parseTestNA(t, reply).Target)
}

func TestOverlayNDAddressesTheSolicitorLinkLayer(t *testing.T) {
	other := net.HardwareAddr{0x02, 0, 0, 0, 0, 0x99}
	tests := []struct {
		name string
		spec func() nsSpec
		want net.HardwareAddr
	}{
		{
			name: "source link-layer option",
			spec: func() nsSpec {
				s := validNS(ndTargetIP)
				s.options = sllaoOption(other)
				return s
			},
			want: other,
		},
		{
			name: "no option: the Ethernet source",
			spec: func() nsSpec {
				s := validNS(ndTargetIP)
				s.options = nil
				return s
			},
			want: ndSolicitorMAC,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newOverlayFixture(t, nil).withVNI(t)
			require.NoError(t, f.handler.LearnMAC(context.Background(), ovlL2VNI, ovlHostMAC, ndTargetIP))

			require.NoError(t, f.handler.handleNDPacketIn(context.Background(), ndPacketIn(nxmTunnelMatch(ovlL2VNI), tt.spec().frame())))

			require.Len(t, f.sw.packetOuts, 1)
			assert.Equal(t, tt.want.String(), parseTestNA(t, f.sw.packetOuts[0].Data).DstMAC.String())
		})
	}
}

func TestOverlayNDFloodsWhatItDoesNotAnswer(t *testing.T) {
	tests := []struct {
		name  string
		frame func() []byte
	}{
		{
			// The target lost its binding, or never had one, since the
			// punt went in.
			name:  "unknown target",
			frame: func() []byte { return validNS(netip.MustParseAddr("2001:db8::99")).frame() },
		},
		{
			// A DAD probe must reach the address's owner, which defends
			// it; a proxy answer would make the prober give the address
			// up.
			name:  "duplicate address detection probe",
			frame: func() []byte { return dadProbe(ndTargetIP).frame() },
		},
		{
			name: "the binding's own MAC solicits",
			frame: func() []byte {
				s := validNS(ndTargetIP)
				s.ethSrc = ovlHostMAC
				s.options = sllaoOption(ovlHostMAC)
				return s.frame()
			},
		},
		{
			// The controller cannot read past the header, so it cannot
			// answer; the switch matched the target past it all the same.
			name:  "a solicitation behind an extension header",
			frame: func() []byte { return withHopByHop(validNS(ndTargetIP).frame()) },
		},
		{
			name: "the binding's own MAC in the link-layer option",
			frame: func() []byte {
				s := validNS(ndTargetIP)
				s.options = sllaoOption(ovlHostMAC)
				return s.frame()
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newOverlayFixture(t, nil).withVNI(t)
			require.NoError(t, f.route(t, imet(ovlL2VNI, ovlVTEPB)))
			require.NoError(t, f.handler.LearnMAC(context.Background(), ovlL2VNI, ovlHostMAC, ndTargetIP))
			frame := tt.frame()

			require.NoError(t, f.handler.handleNDPacketIn(context.Background(), ndPacketIn(nxmTunnelMatch(ovlL2VNI), frame)))

			status := f.handler.GetStatus().NDSuppression
			assert.Equal(t, uint64(1), status.Received)
			assert.Equal(t, uint64(1), status.Flooded)
			assert.Zero(t, status.Answered)
			require.Len(t, f.sw.packetOuts, 1, "the punt took it off the flood; the controller puts it back")
			out := f.sw.packetOuts[0]
			assert.Equal(t, ndAccessOFPort, out.InPort)
			assert.Equal(t, frame, out.Data)
			assert.Equal(t, []string{
				"set:tun_id=10100",
				"set:tun_dst=" + ovlVTEPB.String(),
				"output:" + strconv.FormatUint(uint64(f.handler.builder.ports.vxlan), 10),
			}, describeActions(out.Actions), "the segment's flood to its VTEPs")
		})
	}
}

func TestOverlayNDDiscardsWhatItCannotFlood(t *testing.T) {
	noInPort := openflow.NewMatch()
	noInPort.AddTunnelID(uint64(ovlL2VNI))
	noTunnel := openflow.NewMatch()
	noTunnel.AddInPort(ndAccessOFPort)

	tests := []struct {
		name  string
		match openflow.Match
		frame []byte
	}{
		{name: "a VNI with no segment here", match: nxmTunnelMatch(ovlL2VNI + 1), frame: validNS(ndTargetIP).frame()},
		{name: "no tunnel ID", match: *noTunnel, frame: validNS(ndTargetIP).frame()},
		{name: "no ingress port", match: *noInPort, frame: validNS(ndTargetIP).frame()},
		{name: "invalid solicitation", match: nxmTunnelMatch(ovlL2VNI), frame: invalidNSFrames()[0].frame},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newOverlayFixture(t, nil).withVNI(t)
			require.NoError(t, f.handler.LearnMAC(context.Background(), ovlL2VNI, ovlHostMAC, ndTargetIP))

			require.NoError(t, f.handler.handleNDPacketIn(context.Background(), ndPacketIn(tt.match, tt.frame)))

			status := f.handler.GetStatus().NDSuppression
			assert.Equal(t, uint64(1), status.Received)
			assert.Equal(t, uint64(1), status.Discarded)
			assert.Zero(t, status.Answered)
			assert.Zero(t, status.Flooded)
			assert.Empty(t, f.sw.packetOuts)
		})
	}
}

func TestOverlayNDCountsSendFailures(t *testing.T) {
	f := newOverlayFixture(t, nil).withVNI(t)
	require.NoError(t, f.handler.LearnMAC(context.Background(), ovlL2VNI, ovlHostMAC, ndTargetIP))
	f.sw.mu.Lock()
	f.sw.packetOutErr = errSwitchDown
	f.sw.mu.Unlock()

	err := f.handler.handleNDPacketIn(context.Background(), ndPacketIn(nxmTunnelMatch(ovlL2VNI), validNS(ndTargetIP).frame()))

	assert.ErrorIs(t, err, errSwitchDown)
	status := f.handler.GetStatus().NDSuppression
	assert.Equal(t, uint64(1), status.SendFailed)
	assert.Zero(t, status.Answered)
}

func TestOverlayNDIndexFollowsBindings(t *testing.T) {
	f := newOverlayFixture(t, nil).withVNI(t)
	ctx := context.Background()
	second := net.HardwareAddr{0x02, 0, 0, 0, 0x01, 0x11}
	require.NoError(t, f.handler.LearnMAC(ctx, ovlL2VNI, ovlHostMAC, ndTargetIP))
	require.NoError(t, f.handler.LearnMAC(ctx, ovlL2VNI, second, ndTargetIP))

	answer := func() net.HardwareAddr {
		f.handler.mu.Lock()
		defer f.handler.mu.Unlock()
		mac, _ := f.handler.ndTarget(ovlL2VNI, ndTargetIP)
		return mac
	}
	assert.Nil(t, answer(), "two hosts claim the address: leave it to them")
	assert.Equal(t, ndFloods, ndPuntOf(t, f, ndTargetIP), "and to the flood")

	require.NoError(t, f.handler.ForgetMAC(ctx, ovlL2VNI, ovlHostMAC))
	assert.Equal(t, second.String(), answer().String())
	assert.Equal(t, ndPunted, ndPuntOf(t, f, ndTargetIP))

	require.NoError(t, f.handler.RemoveVNI(ctx, ovlL2VNI))
	assert.Nil(t, answer())
	assert.Empty(t, f.handler.ndOwners)
	assert.Empty(t, f.sw.hardTimeouts(), "no punt outlives its target")
}

func TestOverlayNDPuntsRemoteBindings(t *testing.T) {
	f := newOverlayFixture(t, nil).withVNI(t)
	remote := net.HardwareAddr{0x02, 0, 0, 0, 0x02, 0x22}
	require.NoError(t, f.route(t, imet(ovlL2VNI, ovlVTEPB)))
	route := macip(ovlVTEPB, remote, ndTargetIP)
	require.NoError(t, f.route(t, route))

	assert.Equal(t, ndPunted, ndPuntOf(t, f, ndTargetIP), "a Type-2 IPv6 binding is a known target")
	require.NoError(t, f.handler.handleNDPacketIn(context.Background(), ndPacketIn(nxmTunnelMatch(ovlL2VNI), validNS(ndTargetIP).frame())))
	require.Len(t, f.sw.packetOuts, 1)
	assert.Equal(t, remote.String(), parseTestNA(t, f.sw.packetOuts[0].Data).TargetLLA.String())

	route.IsWithdraw = true
	require.NoError(t, f.route(t, route))
	assert.Equal(t, ndFloods, ndPuntOf(t, f, ndTargetIP), "a withdrawn binding floods again")
}

func TestOverlayNDIndexClearedOnStop(t *testing.T) {
	f := newOverlayFixture(t, nil).withVNI(t)
	require.NoError(t, f.handler.LearnMAC(context.Background(), ovlL2VNI, ovlHostMAC, ndTargetIP))
	require.NotEmpty(t, f.handler.ndOwners)

	require.NoError(t, f.handler.Stop(context.Background()))

	assert.Empty(t, f.handler.ndOwners)
}

func TestOverlayNDStopRemovesThePunts(t *testing.T) {
	f := newOverlayFixture(t, nil).withVNI(t)
	ctx := context.Background()
	require.NoError(t, f.handler.LearnMAC(ctx, ovlL2VNI, ovlHostMAC, ndTargetIP))
	require.Equal(t, ndPunted, ndPuntOf(t, f, ndTargetIP))

	require.NoError(t, f.handler.stopNDController(ctx))

	assert.Equal(t, ndFloods, ndPuntOf(t, f, ndTargetIP), "with no controller the solicitation floods")
	assert.Empty(t, f.sw.meters)
	assert.False(t, f.handler.GetStatus().NDSuppression.Suppressing)
}

func TestOverlayNDStopReportsPuntsLeftBehind(t *testing.T) {
	f := newOverlayFixture(t, nil).withVNI(t)
	f.sw.fail(errSwitchDown)

	err := f.handler.Stop(context.Background())

	var failed *ErrFlowOperationFailed
	require.True(t, errors.As(err, &failed), "got %v", err)
	assert.Equal(t, "delete ND punts", failed.Operation)
	assert.ErrorIs(t, err, errSwitchDown)
}

// A relaunch does not flush the punts a killed run left: their packet-ins
// carry the ND cookie the new controller routes, so it answers them, and they
// lapse at their hard timeout unless the new run refreshes them.
func TestOverlayStartKeepsPuntsAKilledRunLeft(t *testing.T) {
	f := newStoppedOverlay(t, nil)
	ctx := context.Background()
	left := openflow.NewFlowMod(0)
	left.Command = openflow.OFPFCAdd
	left.Cookie = OverlayNDCookie
	left.TableID = TableARP
	left.Priority = priorityNDPunt
	left.HardTimeout = overlayNDPuntHardTimeout
	left.Match.AddInPort(ndAccessOFPort)
	require.NoError(t, f.sw.SendFlowMods(ctx, []*openflow.FlowMod{left}))

	require.NoError(t, f.handler.Start(ctx))
	t.Cleanup(func() { assert.NoError(t, f.handler.Stop(ctx)) })

	assert.True(t, f.sw.has("t=40 p=200 in_port=3 -> drop"), "the old run's punt keeps suppressing")
	f.sw.expire()
	assert.False(t, f.sw.has("t=40 p=200 in_port=3 -> drop"), "the old run's punt lapses at its hard timeout")
}

func TestOverlayNDFallsBackOnDrops(t *testing.T) {
	tests := []struct {
		name string
		drop func(t *testing.T, f *overlayFixture)
	}{
		{
			name: "over the meter",
			drop: func(_ *testing.T, f *overlayFixture) {
				f.sw.mu.Lock()
				f.sw.meterDrops++
				f.sw.mu.Unlock()
			},
		},
		{
			name: "over the controller's queue",
			drop: func(t *testing.T, f *overlayFixture) {
				// The worker blocks on mu, so the queue fills and the rest
				// are dropped.
				f.handler.mu.Lock()
				for range overlayNDQueueSize + 8 {
					f.sw.emitPacketIn(ndPacketIn(nxmTunnelMatch(ovlL2VNI), validNS(ndTargetIP).frame()))
				}
				f.handler.mu.Unlock()
				require.NotZero(t, f.handler.GetStatus().NDSuppression.QueueDropped)
			},
		},
		{
			// The punt took the solicitation off the flood, and the answer
			// never left: it is as lost as one the meter dropped.
			name: "a failed answer",
			drop: func(t *testing.T, f *overlayFixture) {
				f.sw.mu.Lock()
				f.sw.packetOutErr = errSwitchDown
				f.sw.mu.Unlock()
				err := f.handler.handleNDPacketIn(context.Background(), ndPacketIn(nxmTunnelMatch(ovlL2VNI), validNS(ndTargetIP).frame()))
				require.ErrorIs(t, err, errSwitchDown)
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newOverlayFixture(t, nil).withVNI(t)
			ctx := context.Background()
			require.NoError(t, f.handler.LearnMAC(ctx, ovlL2VNI, ovlHostMAC, ndTargetIP))
			now := time.Now()
			f.handler.ndTick(ctx, now)
			require.Equal(t, ndPunted, ndPuntOf(t, f, ndTargetIP), "no drop, no fallback")

			tt.drop(t, f)
			f.handler.ndTick(ctx, now)

			status := f.handler.GetStatus().NDSuppression
			assert.False(t, status.Suppressing)
			assert.Equal(t, uint64(1), status.Fallbacks)
			assert.Equal(t, ndFloods, ndPuntOf(t, f, ndTargetIP), "every solicitation floods")
		})
	}
}

func TestOverlayNDResumesAfterTheHoldDown(t *testing.T) {
	f := newOverlayFixture(t, nil).withVNI(t)
	ctx := context.Background()
	require.NoError(t, f.handler.LearnMAC(ctx, ovlL2VNI, ovlHostMAC, ndTargetIP))
	f.sw.mu.Lock()
	f.sw.meterDrops = 1
	f.sw.mu.Unlock()
	now := time.Now()
	f.handler.ndTick(ctx, now)

	other := netip.MustParseAddr("2001:db8::11")
	require.NoError(t, f.handler.LearnMAC(ctx, ovlL2VNI, net.HardwareAddr{0x02, 0, 0, 0, 0x01, 0x12}, other))
	f.handler.ndTick(ctx, now.Add(overlayNDFallbackHoldDown-time.Second))
	assert.Equal(t, ndFloods, ndPuntOf(t, f, other), "no punt goes in while fallen back")
	assert.Equal(t, ndFloods, ndPuntOf(t, f, ndTargetIP))

	f.handler.ndTick(ctx, now.Add(overlayNDFallbackHoldDown))

	assert.True(t, f.handler.GetStatus().NDSuppression.Suppressing)
	assert.Equal(t, ndPunted, ndPuntOf(t, f, ndTargetIP))
	assert.Equal(t, ndPunted, ndPuntOf(t, f, other))
}

func TestOverlayNDFallsBackWhenTheSwitchConnectionIsLost(t *testing.T) {
	f := newOverlayFixture(t, nil).withVNI(t)
	ctx := context.Background()
	require.NoError(t, f.handler.LearnMAC(ctx, ovlL2VNI, ovlHostMAC, ndTargetIP))
	now := time.Now()
	f.handler.ndTick(ctx, now)
	require.True(t, f.handler.GetStatus().NDSuppression.Suppressing)

	// Stop needs the switch again; this runs before the fixture's cleanup.
	t.Cleanup(func() {
		f.sw.restore()
		require.NoError(t, f.sw.Connect(ctx))
	})
	f.sw.lose()
	f.handler.ndTick(ctx, now)

	status := f.handler.GetStatus().NDSuppression
	assert.False(t, status.Suppressing, "punts that can no longer be refreshed must not keep suppressing")
	assert.Equal(t, uint64(1), status.Fallbacks)
	assert.Equal(t, 1, f.sw.connects, "the handler redials the switch")

	f.handler.ndTick(ctx, now.Add(time.Second))
	assert.Equal(t, 2, f.sw.connects, "it keeps redialling while the switch is down")
	assert.Equal(t, uint64(1), f.handler.GetStatus().NDSuppression.Fallbacks, "one outage is one fallback")
}

func TestOverlayNDRecoversAfterTheSwitchRestarts(t *testing.T) {
	f := newOverlayFixture(t, nil).withVNI(t)
	ctx := context.Background()
	require.NoError(t, f.handler.LearnMAC(ctx, ovlL2VNI, ovlHostMAC, ndTargetIP))
	now := time.Now()
	f.handler.ndTick(ctx, now)
	f.sw.lose()
	f.sw.mu.Lock()
	delete(f.sw.meters, overlayNDMeterID) // a restarted switch keeps no meter
	f.sw.mu.Unlock()
	f.sw.restore()

	f.handler.ndTick(ctx, now)

	assert.True(t, f.sw.IsConnected())
	f.sw.mu.Lock()
	_, metered := f.sw.meters[overlayNDMeterID]
	f.sw.mu.Unlock()
	assert.True(t, metered, "the drop meter the punts point at is installed again")
	status := f.handler.GetStatus().NDSuppression
	assert.False(t, status.Suppressing, "the hold-down applies after an outage")
	assert.Equal(t, uint64(1), status.Fallbacks)
	assert.Equal(t, ndFloods, ndPuntOf(t, f, ndTargetIP))

	f.handler.ndTick(ctx, now.Add(overlayNDFallbackHoldDown))

	assert.True(t, f.handler.GetStatus().NDSuppression.Suppressing)
	assert.Equal(t, ndPunted, ndPuntOf(t, f, ndTargetIP), "suppression resumes on the new connection")
}

// overlayPipeline is the switch's flows without the ND punts.
func overlayPipeline(f *overlayFixture) []string {
	return slices.DeleteFunc(f.sw.table(), func(flow string) bool { return strings.Contains(flow, ndPunted) })
}

func TestOverlayNDRebuildsThePipelineAfterTheSwitchRestarts(t *testing.T) {
	f := newOverlayFixture(t, nil).withVNI(t)
	ctx := context.Background()
	require.NoError(t, f.handler.LearnMAC(ctx, ovlL2VNI, ovlHostMAC, ndTargetIP))
	now := time.Now()
	f.handler.ndTick(ctx, now)
	pipeline := overlayPipeline(f)
	f.sw.restart()
	mark := f.sw.batchCount()

	f.handler.ndTick(ctx, now)

	assert.Equal(t, pipeline, f.sw.table(), "the restarted switch holds the committed pipeline again, and no punt yet")
	batches := f.sw.batchesSince(mark)
	require.NotEmpty(t, batches)
	assertFailClosed(t, batches[0])
	f.sw.mu.Lock()
	_, metered := f.sw.meters[overlayNDMeterID]
	f.sw.mu.Unlock()
	assert.True(t, metered, "the meter the punts point at is installed again")

	f.handler.ndTick(ctx, now.Add(overlayNDFallbackHoldDown))

	assert.Equal(t, ndPunted, ndPuntOf(t, f, ndTargetIP), "the punts return once the hold-down passes")
	assert.Equal(t, pipeline, overlayPipeline(f))
}

func TestOverlayNDRebuildsThePipelineOnTheNextChangeWhenTheRestartedSwitchRefusesIt(t *testing.T) {
	f := newOverlayFixture(t, nil).withVNI(t)
	ctx := context.Background()
	require.NoError(t, f.handler.LearnMAC(ctx, ovlL2VNI, ovlHostMAC, ndTargetIP))
	now := time.Now()
	f.handler.ndTick(ctx, now)
	pipeline := overlayPipeline(f)
	f.sw.restart()
	f.sw.fail(errSwitchDown)

	f.handler.ndTick(ctx, now)

	assert.Empty(t, f.sw.table(), "the switch refused the rebuild")
	f.sw.fail(nil)
	require.NoError(t, f.handler.LearnMAC(ctx, ovlL2VNI, ovlRemoteMAC, ovlRemoteIP))
	for _, flow := range pipeline {
		assert.True(t, f.sw.has(flow), "the next change rebuilds %s first", flow)
	}
}

func TestOverlayNDRetriesTheRebuildOnTheNextTickWhenTheRestartedSwitchRefusesIt(t *testing.T) {
	f := newOverlayFixture(t, nil).withVNI(t)
	ctx := context.Background()
	require.NoError(t, f.handler.LearnMAC(ctx, ovlL2VNI, ovlHostMAC, ndTargetIP))
	now := time.Now()
	f.handler.ndTick(ctx, now)
	pipeline := overlayPipeline(f)
	f.sw.restart()
	f.sw.fail(errSwitchDown)
	f.handler.ndTick(ctx, now)
	require.Empty(t, f.sw.table(), "the switch refused the rebuild")
	f.sw.fail(nil)

	f.handler.ndTick(ctx, now.Add(overlayNDPollInterval))

	assert.Equal(t, pipeline, f.sw.table(), "a quiet overlay gets its pipeline back without a change")
}

func TestOverlayNDBacksOffWhileTheSwitchKeepsRefusingTheRebuild(t *testing.T) {
	f := newOverlayFixture(t, nil).withVNI(t)
	ctx := context.Background()
	require.NoError(t, f.handler.LearnMAC(ctx, ovlL2VNI, ovlHostMAC, ndTargetIP))
	now := time.Now()
	f.handler.ndTick(ctx, now)
	pipeline := overlayPipeline(f)
	f.sw.restart()
	f.sw.fail(errSwitchDown)
	f.handler.ndTick(ctx, now)
	f.handler.ndTick(ctx, now.Add(overlayNDPollInterval)) // the retry fails: wait 1s
	f.handler.ndTick(ctx, now.Add(3*overlayNDPollInterval))
	mark := f.sw.batchCount()
	f.sw.fail(nil)

	f.handler.ndTick(ctx, now.Add(3*overlayNDPollInterval+overlayNDPollInterval/2))
	assert.Equal(t, mark, f.sw.batchCount(), "no retry inside the backoff")

	f.handler.ndTick(ctx, now.Add(5*overlayNDPollInterval))
	assert.Equal(t, pipeline, f.sw.table(), "the retry after the doubled wait restores the pipeline")
}

func TestOverlayNDDoesNotRebuildAnUndriftedSwitch(t *testing.T) {
	f := newOverlayFixture(t, nil).withVNI(t)
	ctx := context.Background()
	require.NoError(t, f.handler.LearnMAC(ctx, ovlL2VNI, ovlHostMAC, ndTargetIP))
	now := time.Now()
	f.handler.ndTick(ctx, now)
	mark := f.sw.batchCount()

	f.handler.ndTick(ctx, now.Add(overlayNDPollInterval))

	assert.Empty(t, f.sw.batchesSince(mark), "a switch that has not drifted is left alone")
}

// populatedOverlay is an overlay on a VXLAN port and an access port of
// these OpenFlow numbers, holding a flow of every kind: the base pipeline,
// a VNI with a remote VTEP, a local and a remote host, and a prefix.
func populatedOverlay(t *testing.T, vxlanPort, accessPort int32) *overlayFixture {
	t.Helper()
	f := newStoppedOverlay(t, nil)
	f.ovs.renumber(vxlanPort, accessPort)
	f.start(t).withVNI(t)
	require.NoError(t, f.handler.LearnMAC(context.Background(), ovlL2VNI, ovlHostMAC, ndTargetIP))
	require.NoError(t, f.route(t, imet(ovlL2VNI, ovlVTEPB)))
	require.NoError(t, f.route(t, macip(ovlVTEPB, ovlRemoteMAC, ovlRemoteIP)))
	require.NoError(t, f.route(t, prefixRoute(ovlVTEPB, "10.9.0.0/16")))
	return f
}

func TestOverlayNDRemapsThePortsTheRestartedSwitchRenumbered(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	want := populatedOverlay(t, 17, 13)
	f := populatedOverlay(t, 7, 3)
	want.handler.ndTick(ctx, now)
	f.handler.ndTick(ctx, now)
	f.sw.restart()
	f.ovs.renumber(17, 13)

	f.handler.ndTick(ctx, now)

	assert.Equal(t, overlayPipeline(want), f.sw.table(), "the pipeline is rebuilt on the new port numbers")

	resumed := now.Add(overlayNDFallbackHoldDown)
	f.handler.ndTick(ctx, resumed)
	want.handler.ndTick(ctx, resumed)
	assert.True(t, f.handler.GetStatus().NDSuppression.Suppressing)
	assert.Equal(t, want.sw.table(), f.sw.table(), "the punts resume on the new access port")

	for _, o := range []*overlayFixture{want, f} {
		require.NoError(t, o.handler.ForgetMAC(ctx, ovlL2VNI, ovlHostMAC), "a remapped flow is released")
		require.NoError(t, o.handler.LearnMAC(ctx, ovlL2VNI, ovlHostMAC, ovlHostIP))
	}
	assert.Equal(t, want.sw.table(), f.sw.table(), "later changes are built on the new port numbers")
}

func TestOverlayNDHoldsTheOverlayOffTheSwitchUntilItsPortsResolve(t *testing.T) {
	ctx := context.Background()
	now := time.Now()
	want := populatedOverlay(t, 17, 13)
	f := populatedOverlay(t, 7, 3)
	f.handler.ndTick(ctx, now)
	f.sw.restart()
	f.ovs.unnumber()

	f.handler.ndTick(ctx, now)
	f.handler.ndTick(ctx, now.Add(overlayNDFallbackHoldDown))

	assert.Empty(t, f.sw.table(), "no flow goes on a switch whose port numbers are unknown")
	assert.False(t, f.handler.GetStatus().NDSuppression.Suppressing, "nor does any punt")
	err := f.handler.LearnMAC(ctx, ovlL2VNI, ovlHostMAC, ovlHostIP)
	require.ErrorIs(t, err, ErrSwitchNotRestored)
	assert.Empty(t, f.sw.table())

	f.ovs.renumber(17, 13)
	resumed := now.Add(overlayNDFallbackHoldDown + overlayNDPollInterval)
	f.handler.ndTick(ctx, resumed)
	want.handler.ndTick(ctx, resumed)

	assert.True(t, f.handler.GetStatus().NDSuppression.Suppressing)
	assert.Equal(t, want.sw.table(), f.sw.table(), "the overlay goes back on once its ports resolve")
}

func TestOverlayNDRetriesTheMeterTheRestartedSwitchRefused(t *testing.T) {
	f := newOverlayFixture(t, nil).withVNI(t)
	ctx := context.Background()
	require.NoError(t, f.handler.LearnMAC(ctx, ovlL2VNI, ovlHostMAC, ndTargetIP))
	now := time.Now()
	f.handler.ndTick(ctx, now)
	f.sw.restart()
	f.sw.mu.Lock()
	f.sw.meterErr = errSwitchDown
	f.sw.mu.Unlock()

	f.handler.ndTick(ctx, now)
	f.handler.ndTick(ctx, now.Add(overlayNDFallbackHoldDown))

	assert.False(t, f.handler.GetStatus().NDSuppression.Suppressing,
		"suppression stays off while the meter its punts point at is missing")
	assert.Equal(t, ndFloods, ndPuntOf(t, f, ndTargetIP), "a known target floods")
	assert.Empty(t, f.sw.matching(ndPunted))

	f.sw.mu.Lock()
	f.sw.meterErr = nil
	f.sw.mu.Unlock()
	f.handler.ndTick(ctx, now.Add(overlayNDFallbackHoldDown+overlayNDPollInterval))

	f.sw.mu.Lock()
	_, metered := f.sw.meters[overlayNDMeterID]
	f.sw.mu.Unlock()
	assert.True(t, metered, "the meter is retried on the connection that refused it")
	assert.True(t, f.handler.GetStatus().NDSuppression.Suppressing)
	assert.Equal(t, ndPunted, ndPuntOf(t, f, ndTargetIP))
}

func TestNextRebuildBackoffDoublesUpToTheMaximum(t *testing.T) {
	wait := time.Duration(0)
	var waits []time.Duration
	for range 8 {
		wait = nextRebuildBackoff(wait)
		waits = append(waits, wait)
	}

	assert.Equal(t, []time.Duration{
		time.Second, 2 * time.Second, 4 * time.Second, 8 * time.Second,
		16 * time.Second, overlayRebuildBackoffMax, overlayRebuildBackoffMax, overlayRebuildBackoffMax,
	}, waits)
}

func TestOverlayNDStaysFallenBackWhenTheMeterCannotBeRestored(t *testing.T) {
	f := newOverlayFixture(t, nil).withVNI(t)
	ctx := context.Background()
	require.NoError(t, f.handler.LearnMAC(ctx, ovlL2VNI, ovlHostMAC, ndTargetIP))
	now := time.Now()
	f.handler.ndTick(ctx, now)
	f.sw.lose()
	f.sw.restore()
	f.sw.mu.Lock()
	f.sw.meterErr = errSwitchDown
	f.sw.mu.Unlock()

	f.handler.ndTick(ctx, now)

	status := f.handler.GetStatus().NDSuppression
	assert.False(t, status.Suppressing)
	assert.Equal(t, uint64(1), status.Fallbacks)
}

func TestOverlayNDDropsDuringTheHoldDownExtendIt(t *testing.T) {
	f := newOverlayFixture(t, nil).withVNI(t)
	ctx := context.Background()
	require.NoError(t, f.handler.LearnMAC(ctx, ovlL2VNI, ovlHostMAC, ndTargetIP))
	now := time.Now()
	for i := range 2 {
		f.sw.mu.Lock()
		f.sw.meterDrops++
		f.sw.mu.Unlock()
		f.handler.ndTick(ctx, now.Add(time.Duration(i)*overlayNDFallbackHoldDown/2))
	}

	f.handler.ndTick(ctx, now.Add(overlayNDFallbackHoldDown))

	status := f.handler.GetStatus().NDSuppression
	assert.False(t, status.Suppressing, "the hold-down runs from the last drop")
	assert.Equal(t, uint64(1), status.Fallbacks)
	assert.Equal(t, ndFloods, ndPuntOf(t, f, ndTargetIP))
}

// ndFallBackAt has the meter drop a punt and runs the watch at now, and
// returns the hold-down the fallback set.
func ndFallBackAt(t *testing.T, f *overlayFixture, now time.Time) time.Duration {
	t.Helper()
	return ndFallBackHandledAt(t, f, now, now).Sub(now)
}

// ndFallBackHandledAt has the meter drop a punt and runs the watch on a
// tick that fired at fired and is handled at handled, and returns the time
// the fallback resumes suppression at.
func ndFallBackHandledAt(t *testing.T, f *overlayFixture, fired, handled time.Time) time.Time {
	t.Helper()
	f.sw.mu.Lock()
	f.sw.meterDrops++
	f.sw.mu.Unlock()
	f.handler.mu.Lock()
	f.handler.ndClock = func() time.Time { return handled }
	f.handler.mu.Unlock()
	f.handler.ndTick(context.Background(), fired)
	f.handler.mu.Lock()
	defer f.handler.mu.Unlock()
	require.False(t, f.handler.ndSuppressing, "a drop falls back")
	return f.handler.ndResumeAt
}

func TestOverlayNDHoldDownCountsFromTheLaterOfTickAndClock(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name           string
		fired, handled time.Time
	}{
		{
			name:  "a tick handled late holds down from when it is handled, not from when it fired",
			fired: now.Add(-5 * time.Second), handled: now,
		},
		{
			name:  "a clock behind the tick never moves the hold-down earlier",
			fired: now, handled: now.Add(-5 * time.Second),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newOverlayFixture(t, nil).withVNI(t)
			require.NoError(t, f.handler.LearnMAC(context.Background(), ovlL2VNI, ovlHostMAC, ndTargetIP))

			assert.Equal(t, now.Add(overlayNDFallbackHoldDown), ndFallBackHandledAt(t, f, tt.fired, tt.handled))
		})
	}
}

func TestOverlayNDHoldDownBacksOffOnRepeatedFallbacks(t *testing.T) {
	f := newOverlayFixture(t, nil).withVNI(t)
	ctx := context.Background()
	require.NoError(t, f.handler.LearnMAC(ctx, ovlL2VNI, ovlHostMAC, ndTargetIP))
	now := time.Now()

	want := overlayNDFallbackHoldDown
	for range 8 {
		holdDown := ndFallBackAt(t, f, now)
		assert.Equal(t, want, holdDown)

		f.handler.ndTick(ctx, now.Add(holdDown-time.Second))
		assert.False(t, f.handler.GetStatus().NDSuppression.Suppressing, "still held down")
		now = now.Add(holdDown)
		f.handler.ndTick(ctx, now)
		require.True(t, f.handler.GetStatus().NDSuppression.Suppressing, "resumed after %s", holdDown)
		now = now.Add(time.Second)
		want = min(2*want, overlayNDFallbackHoldDownMax)
	}
	assert.Equal(t, overlayNDFallbackHoldDownMax, want, "the back-off reached its cap")
	assert.Equal(t, uint64(8), f.handler.GetStatus().NDSuppression.Fallbacks)
}

func TestOverlayNDHoldDownResetsAfterAQuietPeriod(t *testing.T) {
	f := newOverlayFixture(t, nil).withVNI(t)
	ctx := context.Background()
	require.NoError(t, f.handler.LearnMAC(ctx, ovlL2VNI, ovlHostMAC, ndTargetIP))
	now := time.Now()
	holdDown := ndFallBackAt(t, f, now)
	now = now.Add(holdDown)
	f.handler.ndTick(ctx, now)
	require.Equal(t, 2*overlayNDFallbackHoldDown, ndFallBackAt(t, f, now.Add(time.Second)), "backed off")
	now = now.Add(time.Second + 2*overlayNDFallbackHoldDown)
	f.handler.ndTick(ctx, now)
	require.True(t, f.handler.GetStatus().NDSuppression.Suppressing)

	assert.Equal(t, 4*overlayNDFallbackHoldDown, ndFallBackAt(t, f, now.Add(overlayNDFallbackQuiet-time.Second)),
		"a drop inside the quiet period backs off further")
	now = now.Add(overlayNDFallbackQuiet - time.Second + 4*overlayNDFallbackHoldDown)
	f.handler.ndTick(ctx, now)
	require.True(t, f.handler.GetStatus().NDSuppression.Suppressing)

	assert.Equal(t, overlayNDFallbackHoldDown, ndFallBackAt(t, f, now.Add(overlayNDFallbackQuiet)),
		"suppression that held for the quiet period starts the back-off over")
}

func TestOverlayNDHoldDownStartsAtTheConfiguredBase(t *testing.T) {
	tests := []struct {
		name       string
		base       time.Duration
		wantSecond time.Duration
	}{
		{name: "a recent fallback doubles the configured base", base: 2 * time.Second, wantSecond: 4 * time.Second},
		{name: "the back-off never passes its cap", base: overlayNDFallbackHoldDownMax, wantSecond: overlayNDFallbackHoldDownMax},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := newOverlayFixture(t, func(c *OverlayModeConfig) { c.NDFallbackHoldDown = tt.base }).withVNI(t)
			ctx := context.Background()
			require.NoError(t, f.handler.LearnMAC(ctx, ovlL2VNI, ovlHostMAC, ndTargetIP))
			now := time.Now()

			require.Equal(t, tt.base, ndFallBackAt(t, f, now), "the first fallback holds down for the configured base")
			now = now.Add(tt.base)
			f.handler.ndTick(ctx, now)
			require.True(t, f.handler.GetStatus().NDSuppression.Suppressing)
			assert.Equal(t, tt.wantSecond, ndFallBackAt(t, f, now.Add(time.Second)))
		})
	}
}

func TestOverlayNDFallbackPuntsExpireWhenTheDeleteFails(t *testing.T) {
	f := newOverlayFixture(t, nil).withVNI(t)
	ctx := context.Background()
	require.NoError(t, f.handler.LearnMAC(ctx, ovlL2VNI, ovlHostMAC, ndTargetIP))
	f.sw.mu.Lock()
	f.sw.meterDrops = 1
	f.sw.mu.Unlock()
	f.sw.fail(errSwitchDown)
	now := time.Now()
	f.handler.ndTick(ctx, now)
	f.sw.fail(nil)
	require.Equal(t, ndPunted, ndPuntOf(t, f, ndTargetIP), "the switch refused the delete")

	f.handler.ndTick(ctx, now.Add(overlayNDPuntRefresh))
	f.sw.expire()

	assert.Equal(t, uint64(1), f.handler.GetStatus().NDSuppression.Fallbacks)
	assert.Equal(t, ndFloods, ndPuntOf(t, f, ndTargetIP), "nothing refreshed the punt")
}

func TestOverlayNDStartIgnoresEarlierMeterDrops(t *testing.T) {
	f := newStoppedOverlay(t, nil)
	ctx := context.Background()
	f.sw.mu.Lock()
	f.sw.meterDrops = 9
	f.sw.mu.Unlock()
	require.NoError(t, f.handler.Start(ctx))
	t.Cleanup(func() { assert.NoError(t, f.handler.Stop(ctx)) })

	f.handler.ndTick(ctx, time.Now())

	status := f.handler.GetStatus().NDSuppression
	assert.True(t, status.Suppressing)
	assert.Zero(t, status.Fallbacks)
}

func TestOverlayStartWithoutMetersInstallsNoFlows(t *testing.T) {
	f := newStoppedOverlay(t, nil)
	f.sw.meterErr = &openflow.ErrMeterUnsupported{MeterID: overlayNDMeterID}

	err := f.handler.Start(context.Background())

	var unsupported *openflow.ErrMeterUnsupported
	require.True(t, errors.As(err, &unsupported), "got %v", err)
	assert.Zero(t, f.sw.batchCount(), "no flow may punt to a meter the datapath lacks")
	assert.Empty(t, f.sw.packetIns)
	assert.False(t, f.handler.GetStatus().Running)
	assert.False(t, f.ovs.hasPort(f.handler.vtepManager.PortName()))
}

func TestOverlayStartRollsBackNDWhenTheBaseFails(t *testing.T) {
	f := newStoppedOverlay(t, nil)
	f.sw.fail(errSwitchDown)

	require.Error(t, f.handler.Start(context.Background()))

	assert.Empty(t, f.sw.packetIns, "the packet-in subscription is cancelled")
	assert.Empty(t, f.sw.meters, "the meter is deleted")
	assert.Nil(t, f.handler.ndController)
}

func TestOverlayNDMeterDropsComeFromTheSwitch(t *testing.T) {
	f := newOverlayFixture(t, nil)
	ctx := context.Background()
	f.sw.mu.Lock()
	f.sw.meterDrops = 7
	f.sw.mu.Unlock()

	f.handler.refreshNDMeterDrops(ctx)
	assert.Equal(t, uint64(7), f.handler.GetStatus().NDSuppression.MeterDropped)

	// Stopping deletes the meter and its counter; the status keeps the
	// count across the restart.
	require.NoError(t, f.handler.Stop(ctx))
	assert.Equal(t, uint64(7), f.handler.GetStatus().NDSuppression.MeterDropped)
	f.sw.mu.Lock()
	f.sw.meterDrops = 3
	f.sw.mu.Unlock()
	require.NoError(t, f.handler.Start(ctx))
	f.handler.refreshNDMeterDrops(ctx)
	assert.Equal(t, uint64(10), f.handler.GetStatus().NDSuppression.MeterDropped)
}

func TestOverlayNDMeterRefreshKeepsTheCountWhenStatsFail(t *testing.T) {
	f := newOverlayFixture(t, nil)
	ctx := context.Background()
	f.sw.mu.Lock()
	f.sw.meterDrops = 4
	f.sw.mu.Unlock()
	f.handler.refreshNDMeterDrops(ctx)

	f.sw.mu.Lock()
	delete(f.sw.meters, overlayNDMeterID)
	f.sw.mu.Unlock()
	f.handler.refreshNDMeterDrops(ctx)

	assert.Equal(t, uint64(4), f.handler.GetStatus().NDSuppression.MeterDropped)
}

func TestParseNeighborSolicitation(t *testing.T) {
	ns, err := parseNeighborSolicitation(validNS(ndTargetIP).frame())
	require.NoError(t, err)
	assert.Equal(t, ndSolicitorMAC.String(), ns.SrcMAC.String())
	assert.Equal(t, ndSolicitorMAC.String(), ns.SourceLLA.String())
	assert.Equal(t, ndSolicitorIP, ns.SrcIP)
	assert.Equal(t, ndTargetIP, ns.Target)

	probe, err := parseNeighborSolicitation(dadProbe(ndTargetIP).frame())
	require.NoError(t, err, "a DAD probe is valid; it is only not answered")
	assert.True(t, probe.SrcIP.IsUnspecified())
	assert.Nil(t, probe.SourceLLA)
}

func TestParseNeighborSolicitationSkipsUnknownOptions(t *testing.T) {
	s := validNS(ndTargetIP)
	s.options = append([]byte{14, 1, 0, 0, 0, 0, 0, 0}, sllaoOption(ndSolicitorMAC)...) // a nonce option first

	ns, err := parseNeighborSolicitation(s.frame())

	require.NoError(t, err)
	assert.Equal(t, ndSolicitorMAC.String(), ns.SourceLLA.String())
}

// OVS matches nd_target past an extension header, so a valid solicitation
// behind one is punted: the parser reports it unread, not invalid, and the
// controller floods it.
func TestParseNeighborSolicitationLeavesExtensionHeadersUnread(t *testing.T) {
	_, err := parseNeighborSolicitation(withHopByHop(validNS(ndTargetIP).frame()))

	var unsupported *ErrUnsupportedNDMessage
	require.True(t, errors.As(err, &unsupported), "got %v", err)
	assert.Equal(t, "extension header", unsupported.Reason)
}

func TestParseNeighborSolicitationRejectsInvalid(t *testing.T) {
	for _, tt := range invalidNSFrames() {
		t.Run(tt.name, func(t *testing.T) {
			_, err := parseNeighborSolicitation(tt.frame)
			var invalid *ErrInvalidNDMessage
			require.True(t, errors.As(err, &invalid), "got %v", err)
			assert.Equal(t, tt.reason, invalid.Reason)
		})
	}
}

func TestBuildNeighborAdvertisementRejectsUnusableInput(t *testing.T) {
	valid, err := parseNeighborSolicitation(validNS(ndTargetIP).frame())
	require.NoError(t, err)
	tests := []struct {
		name string
		req  func() neighborSolicitation
		mac  net.HardwareAddr
	}{
		{
			name: "unspecified destination",
			req: func() neighborSolicitation {
				r := valid
				r.SrcIP = netip.IPv6Unspecified()
				return r
			},
			mac: ovlHostMAC,
		},
		{
			name: "multicast destination",
			req: func() neighborSolicitation {
				r := valid
				r.SrcIP = netip.MustParseAddr("ff02::1")
				return r
			},
			mac: ovlHostMAC,
		},
		{name: "short MAC", req: func() neighborSolicitation { return valid }, mac: net.HardwareAddr{1, 2}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := buildNeighborAdvertisement(tt.req(), tt.mac)
			var invalid *ErrInvalidNDMessage
			assert.True(t, errors.As(err, &invalid), "got %v", err)
		})
	}
}

func FuzzNeighborSolicitationParseBuild(f *testing.F) {
	f.Add(validNS(ndTargetIP).frame())
	f.Add(dadProbe(ndTargetIP).frame())
	f.Add(withHopByHop(validNS(ndTargetIP).frame()))
	for _, invalid := range invalidNSFrames() {
		f.Add(invalid.frame)
	}
	f.Fuzz(func(t *testing.T, frame []byte) {
		ns, err := parseNeighborSolicitation(frame)
		if err != nil {
			var invalid *ErrInvalidNDMessage
			var unsupported *ErrUnsupportedNDMessage
			if !errors.As(err, &invalid) && !errors.As(err, &unsupported) {
				t.Fatalf("untyped parse error: %v", err)
			}
			return
		}
		if ns.SrcIP.IsUnspecified() {
			return
		}
		na, err := buildNeighborAdvertisement(ns, ovlHostMAC)
		if err != nil {
			t.Fatalf("build NA for a valid solicitation: %v", err)
		}
		if na[0]&0x01 != 0 {
			t.Fatalf("NA addressed to the multicast MAC %s", net.HardwareAddr(na[0:6]))
		}
		parsed := parseTestNA(t, na)
		if parsed.Target != ns.Target || parsed.DstIP != ns.SrcIP {
			t.Fatalf("NA answers %s to %s, solicitation asked %s from %s", parsed.Target, parsed.DstIP, ns.Target, ns.SrcIP)
		}
	})
}

// invalidNS is a frame RFC 4861 §7.1.1 has the receiver discard, and the
// reason the parser gives.
type invalidNS struct {
	name   string
	frame  []byte
	reason string
}

func invalidNSFrames() []invalidNS {
	spec := func(edit func(*nsSpec)) []byte {
		s := validNS(ndTargetIP)
		edit(&s)
		return s.frame()
	}
	frame := func(edit func([]byte)) []byte {
		f := validNS(ndTargetIP).frame()
		edit(f)
		return f
	}
	return []invalidNS{
		{name: "bad ICMPv6 checksum", frame: frame(func(f []byte) { f[56] ^= 0xff }), reason: "bad ICMPv6 checksum"},
		{name: "truncated", frame: validNS(ndTargetIP).frame()[:60], reason: "truncated"},
		{name: "not IPv6", frame: frame(func(f []byte) { binary.BigEndian.PutUint16(f[12:14], ethTypeIPv4) }), reason: "not IPv6"},
		{name: "IP version", frame: frame(func(f []byte) { f[14] = 0x40 }), reason: "not IPv6"},
		{name: "payload length past the frame", frame: frame(func(f []byte) {
			binary.BigEndian.PutUint16(f[18:20], binary.BigEndian.Uint16(f[18:20])+8)
		}), reason: "payload length past the frame"},
		{name: "payload shorter than a solicitation", frame: frame(func(f []byte) {
			binary.BigEndian.PutUint16(f[18:20], 16)
		}), reason: "payload shorter than a solicitation"},
		{name: "extension header with hop limit below 255", frame: withHopByHop(spec(func(s *nsSpec) { s.hopLimit = 64 })), reason: "hop limit not 255"},
		{name: "hop limit below 255", frame: spec(func(s *nsSpec) { s.hopLimit = 64 }), reason: "hop limit not 255"},
		{name: "not a solicitation", frame: spec(func(s *nsSpec) { s.icmpType = 136 }), reason: "not a solicitation"},
		{name: "nonzero code", frame: spec(func(s *nsSpec) { s.icmpCode = 1 }), reason: "nonzero ICMPv6 code"},
		{name: "zero-length option", frame: spec(func(s *nsSpec) {
			s.options = []byte{1, 0, 0, 0, 0, 0, 0, 0}
		}), reason: "zero-length option"},
		{name: "option past the payload", frame: spec(func(s *nsSpec) {
			s.options = []byte{1, 2, 0, 0, 0, 0, 0, 0}
		}), reason: "option past the payload"},
		{name: "link-layer option not 8 bytes", frame: spec(func(s *nsSpec) {
			s.options = make([]byte, 16)
			s.options[0], s.options[1] = 1, 2
		}), reason: "source link-layer option not 8 bytes"},
		{name: "multicast source link-layer option", frame: spec(func(s *nsSpec) {
			s.options = sllaoOption(net.HardwareAddr{0x33, 0x33, 0, 0, 0, 1})
		}), reason: "multicast source link-layer option"},
		{name: "link-layer option with an unspecified source", frame: spec(func(s *nsSpec) {
			s.src = netip.IPv6Unspecified()
		}), reason: "source link-layer option with an unspecified source"},
		{name: "unspecified source to a non-solicited-node address", frame: spec(func(s *nsSpec) {
			s.src = netip.IPv6Unspecified()
			s.dst = ndSolicitorIP
			s.options = nil
		}), reason: "unspecified source not to a solicited-node address"},
		{name: "multicast source IP", frame: spec(func(s *nsSpec) {
			s.src = netip.MustParseAddr("ff02::1")
		}), reason: "multicast source"},
		{name: "multicast Ethernet source", frame: spec(func(s *nsSpec) {
			s.ethSrc = net.HardwareAddr{0x33, 0x33, 0, 0, 0, 1}
		}), reason: "multicast Ethernet source"},
		{name: "multicast target", frame: spec(func(s *nsSpec) {
			s.target = netip.MustParseAddr("ff02::1")
		}), reason: "multicast target"},
	}
}

// withHopByHop puts an empty hop-by-hop options header (one PadN) between
// the IPv6 header and the ICMPv6 message of an untagged frame. The ICMPv6
// checksum covers only the message, so it still holds.
func withHopByHop(frame []byte) []byte {
	hopByHop := []byte{ipProtoICMPv6, 0, 1, 4, 0, 0, 0, 0}
	out := slices.Concat(frame[:ndICMPOffset], hopByHop, frame[ndICMPOffset:])
	out[20] = 0
	binary.BigEndian.PutUint16(out[18:20], binary.BigEndian.Uint16(out[18:20])+uint16(len(hopByHop)))
	return out
}

// nsSpec describes one neighbor solicitation; frame encodes it with a
// correct ICMPv6 checksum.
type nsSpec struct {
	ethSrc   net.HardwareAddr
	src      netip.Addr
	dst      netip.Addr
	target   netip.Addr
	hopLimit uint8
	icmpType uint8
	icmpCode uint8
	options  []byte
}

// validNS is the solicitation a host sends to resolve target: to its
// solicited-node address, carrying its own link-layer address.
func validNS(target netip.Addr) nsSpec {
	return nsSpec{
		ethSrc:   ndSolicitorMAC,
		src:      ndSolicitorIP,
		dst:      solicitedNode(target),
		target:   target,
		hopLimit: 255,
		icmpType: icmpv6NS,
		options:  sllaoOption(ndSolicitorMAC),
	}
}

// dadProbe is the solicitation duplicate address detection sends.
func dadProbe(target netip.Addr) nsSpec {
	s := validNS(target)
	s.src = netip.IPv6Unspecified()
	s.options = nil
	return s
}

func (s nsSpec) frame() []byte {
	payload := 24 + len(s.options)
	frame := make([]byte, 14+40+payload)
	dst := s.dst.As16()
	copy(frame[0:6], []byte{0x33, 0x33, dst[12], dst[13], dst[14], dst[15]})
	copy(frame[6:12], s.ethSrc)
	binary.BigEndian.PutUint16(frame[12:14], ethTypeIPv6)
	frame[14] = 0x60
	binary.BigEndian.PutUint16(frame[18:20], uint16(payload))
	frame[20] = ipProtoICMPv6
	frame[21] = s.hopLimit
	src := s.src.As16()
	target := s.target.As16()
	copy(frame[22:38], src[:])
	copy(frame[38:54], dst[:])
	icmp := frame[54:]
	icmp[0] = s.icmpType
	icmp[1] = s.icmpCode
	copy(icmp[8:24], target[:])
	copy(icmp[24:], s.options)
	binary.BigEndian.PutUint16(icmp[2:4], icmpv6Checksum(frame[22:38], frame[38:54], icmp))
	return frame
}

func solicitedNode(ip netip.Addr) netip.Addr {
	b := ip.As16()
	return netip.AddrFrom16([16]byte{0xff, 0x02, 10: 0, 11: 0x01, 12: 0xff, 13: b[13], 14: b[14], 15: b[15]})
}

func sllaoOption(mac net.HardwareAddr) []byte {
	return append([]byte{1, 1}, mac...)
}

func uint64Bytes(v uint64) []byte {
	b := make([]byte, 8)
	binary.BigEndian.PutUint64(b, v)
	return b
}

func nxmTunnelMatch(vni uint32) openflow.Match {
	match := openflow.NewMatch()
	match.AddInPort(ndAccessOFPort)
	match.AddTunnelID(uint64(vni))
	return *match
}

func ndPacketIn(match openflow.Match, frame []byte) openflow.PacketIn {
	return openflow.PacketIn{
		Reason: openflow.PacketInReasonAction,
		Cookie: OverlayNDCookie,
		Match:  match,
		Data:   frame,
	}
}

func describeActions(actions []openflow.Action) []string {
	out := make([]string, 0, len(actions))
	for _, action := range actions {
		out = append(out, describeAction(action))
	}
	return out
}

type testNA struct {
	DstMAC    net.HardwareAddr
	SrcMAC    net.HardwareAddr
	SrcIP     netip.Addr
	DstIP     netip.Addr
	Target    netip.Addr
	TargetLLA net.HardwareAddr
	Router    bool
	Solicited bool
	Override  bool
}

// parseTestNA decodes a neighbor advertisement the handler built, failing
// the test unless it is one a host would accept.
func parseTestNA(t *testing.T, frame []byte) testNA {
	t.Helper()
	require.Len(t, frame, 14+40+32)
	require.Equal(t, ethTypeIPv6, binary.BigEndian.Uint16(frame[12:14]))
	require.Equal(t, uint16(32), binary.BigEndian.Uint16(frame[18:20]))
	require.Equal(t, ipProtoICMPv6, frame[20])
	require.Equal(t, uint8(255), frame[21], "hop limit")
	icmp := frame[54:]
	require.Equal(t, uint8(136), icmp[0])
	require.Zero(t, icmpv6Checksum(frame[22:38], frame[38:54], icmp), "checksum")
	require.Equal(t, []byte{2, 1}, icmp[24:26], "target link-layer option")
	var src, dst, target [16]byte
	copy(src[:], frame[22:38])
	copy(dst[:], frame[38:54])
	copy(target[:], icmp[8:24])
	flags := icmp[4]
	return testNA{
		DstMAC:    net.HardwareAddr(frame[0:6]),
		SrcMAC:    net.HardwareAddr(frame[6:12]),
		SrcIP:     netip.AddrFrom16(src),
		DstIP:     netip.AddrFrom16(dst),
		Target:    netip.AddrFrom16(target),
		TargetLLA: net.HardwareAddr(icmp[26:32]),
		Router:    flags&0x80 != 0,
		Solicited: flags&0x40 != 0,
		Override:  flags&0x20 != 0,
	}
}
