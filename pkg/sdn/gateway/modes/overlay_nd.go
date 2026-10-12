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

package modes

import (
	"context"
	"encoding/binary"
	"errors"
	"log/slog"
	"maps"
	"net"
	"net/netip"
	"slices"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
)

// ND suppression (RFC 9161): a neighbor solicitation from the access port
// for an IPv6 binding the overlay knows is sent to the controller through a
// meter instead of the flood, and answered with a proxy neighbor
// advertisement sent back out the port it came in on. Unknown targets and
// DAD probes flood. A punted solicitation the controller does not answer is
// sent to the flood by the controller, so a punt is answered or flooded.
//
// Fail mode: the punt flows exist only while the controller can take what
// they punt. Stopping removes them; a controller that dies without
// stopping leaves them to their hard timeout, which only it refreshes; and
// a punt dropped over the meter or the controller's queue, or lost with a
// refused packet-out, removes them until a hold-down passes. Open vSwitch meters only drop, so a punt over
// the meter cannot fall through to the flood: the controller reads the
// drops every poll and sends every solicitation back to the flood from the
// next, which the solicitor's retransmission reaches.

const (
	// overlayNDMeterID is the meter limiting the ND punts. It is the one
	// meter the overlay installs, named here and nowhere else; 709 is the
	// issue that introduced it, clear of the low IDs set by hand.
	overlayNDMeterID uint32 = 709

	// overlayNDMeterRateKbps and overlayNDMeterBurstKbps bound the punts: a
	// solicitation is under a hundred bytes, so this is several hundred a
	// second.
	overlayNDMeterRateKbps  uint32 = 512
	overlayNDMeterBurstKbps uint32 = 64

	overlayNDQueueSize int = 256
	overlayNDWorkers   int = 1

	// overlayNDPollInterval is how often the controller reads the punt
	// drops of the meter and its queue. A drop falls back to the flood
	// within one interval, inside the second a host waits before it
	// retransmits a solicitation (RFC 4861 RetransTimer).
	overlayNDPollInterval = time.Second

	// overlayRebuildBackoffMax is the longest wait between the tries to
	// rebuild the overlay flows on a switch that keeps refusing them.
	overlayRebuildBackoffMax = 30 * time.Second

	// overlayNDPuntHardTimeout is how long, in seconds, a punt flow
	// outlives its last refresh: the most a dead controller holds known
	// targets off the flood. overlayNDPuntRefresh is how often the
	// controller refreshes the flows; three refreshes fit in one timeout,
	// so a lost refresh does not let a flow lapse.
	overlayNDPuntHardTimeout uint16 = 12
	overlayNDPuntRefresh            = 4 * time.Second

	// overlayNDFallbackHoldDown is how long every solicitation floods after
	// a punt was lost, before known targets are punted again. A fallback
	// within overlayNDFallbackQuiet of the last resumption doubles the
	// hold-down, up to overlayNDFallbackHoldDownMax: a load the punts
	// cannot take does not have them flap. Suppression that holds for the
	// quiet period starts the back-off over.
	overlayNDFallbackHoldDown    = 30 * time.Second
	overlayNDFallbackHoldDownMax = 8 * time.Minute
	overlayNDFallbackQuiet       = 10 * time.Minute
)

// Layout of an untagged Ethernet IPv6 neighbor discovery message. The punt
// flow matches after the access VLAN is popped, so the controller always
// sees the frame untagged.
const (
	ndEthHeaderLen  = 14
	ndIPv6HeaderLen = 40
	ndICMPOffset    = ndEthHeaderLen + ndIPv6HeaderLen
	// ndMessageLen is the ICMPv6 header, the flags or reserved word and
	// the target: the fixed part of a solicitation and an advertisement.
	ndMessageLen = 24
	ndOptionUnit = 8

	ndOptSourceLLA uint8 = 1
	ndOptTargetLLA uint8 = 2
	ndHopLimit     uint8 = 255
	icmpv6NA       uint8 = 136

	naFlagSolicited uint8 = 0x40
	naFlagOverride  uint8 = 0x20
)

// solicitedNodePrefix is ff02::1:ff00:0/104, where a DAD probe must go.
var solicitedNodePrefix = netip.MustParsePrefix("ff02::1:ff00:0/104")

// ndKey names one IPv6 binding on one VNI: what a punted solicitation asks
// about.
type ndKey struct {
	vni uint32
	ip  netip.Addr
}

// ndCounters are the ND suppression counters. The queue and meter drops of
// stopped controllers and deleted meters are folded into queueDropped and
// meterDropped; meterCurrent is the running meter's count, last read.
type ndCounters struct {
	received     atomic.Uint64
	answered     atomic.Uint64
	flooded      atomic.Uint64
	discarded    atomic.Uint64
	sendFailed   atomic.Uint64
	queueDropped atomic.Uint64
	meterDropped atomic.Uint64
	meterCurrent atomic.Uint64
	fallbacks    atomic.Uint64
}

// startNDController installs the punt meter and starts answering punted
// solicitations. It runs before any flow is installed: a datapath without
// meters fails Start with nothing on the switch to roll back. The workers
// and the meter poll outlive ctx, which only bounds the start.
func (h *OverlayModeHandler) startNDController(ctx context.Context) error {
	if err := h.ofClient.SetMeter(ctx, overlayNDMeterID, overlayNDMeterRateKbps, overlayNDMeterBurstKbps); err != nil {
		return err
	}
	controller, err := openflow.NewPacketInController(openflow.PacketInControllerConfig{
		Source:  h.ofClient,
		Queue:   overlayNDQueueSize,
		Workers: overlayNDWorkers,
		Routes: []openflow.PacketInRoute{{
			Key:     openflow.PacketInKey{Reason: openflow.PacketInReasonAction, Cookie: OverlayNDCookie},
			Handler: h.handleNDPacketIn,
		}},
	})
	if err != nil {
		return err
	}
	background := context.WithoutCancel(ctx)
	if err := controller.Start(background); err != nil {
		controller.Stop()
		return err
	}
	// A meter a previous run left keeps its count: drops from before this
	// start are no reason to fall back.
	h.refreshNDMeterDrops(ctx)
	pollCtx, stopPoll := context.WithCancel(background)
	pollDone := make(chan struct{})
	h.mu.Lock()
	h.ndController = controller
	h.ndStopPoll = stopPoll
	h.ndPollDone = pollDone
	h.ndSuppressing, h.ndMeterReady = true, true
	h.ndHoldDown = 0
	h.ndResumedAt = time.Now()
	h.ndRefreshAt = h.ndResumedAt.Add(overlayNDPuntRefresh)
	h.ndDropsSeen = h.ndLosses()
	h.mu.Unlock()
	go h.runND(pollCtx, pollDone)
	return nil
}

// stopNDController stops answering, folds the controller's queue drops and
// the meter's last drop count into the totals, and deletes the meter.
func (h *OverlayModeHandler) stopNDController(ctx context.Context) error {
	h.mu.Lock()
	controller := h.ndController
	stopPoll, pollDone := h.ndStopPoll, h.ndPollDone
	h.ndController, h.ndStopPoll, h.ndPollDone = nil, nil, nil
	h.ndSuppressing, h.ndMeterReady = false, false
	h.mu.Unlock()
	if stopPoll != nil {
		stopPoll()
		<-pollDone
	}
	var err error
	if controller != nil {
		// Open vSwitch keeps flows when their controller goes: with nothing
		// to answer them, the punts must go first.
		if sendErr := h.ofClient.SendFlowMods(ctx, []*openflow.FlowMod{ndFlush()}); sendErr != nil {
			err = &ErrFlowOperationFailed{Table: TableARP, Operation: "delete ND punts", Cause: sendErr}
		}
		controller.Stop()
		h.nd.queueDropped.Add(controller.QueueDropped())
		h.refreshNDMeterDrops(ctx)
	}
	h.nd.meterDropped.Add(h.nd.meterCurrent.Swap(0))
	if meterErr := h.ofClient.DeleteMeter(ctx, overlayNDMeterID); meterErr != nil {
		h.logger.Debug("deleting the overlay ND meter", slog.Any("error", meterErr))
	}
	return err
}

// runND runs the ND watch once a poll interval until ctx ends.
func (h *OverlayModeHandler) runND(ctx context.Context, done chan<- struct{}) {
	defer close(done)
	ticker := time.NewTicker(overlayNDPollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case now := <-ticker.C:
			h.ndTick(ctx, now)
		}
	}
}

// ndLosses is how many punted solicitations were neither answered nor
// flooded: dropped over the meter or the controller's queue, or lost with a
// packet-out the switch refused. Caller holds mu, with the controller
// running.
func (h *OverlayModeHandler) ndLosses() uint64 {
	return h.nd.meterCurrent.Load() + h.ndController.QueueDropped() + h.nd.sendFailed.Load()
}

// ndTick is one round of the ND watch. A punt lost since the last round is
// a solicitation neither answered nor flooded, so the punts go and every
// solicitation floods until the hold-down passes. While suppressing, the
// punts are re-added before their hard timeout expires them.
func (h *OverlayModeHandler) ndTick(ctx context.Context, now time.Time) {
	h.retryRebuild(ctx, now)
	h.retryNDMeter(ctx)
	h.ndReconnect(ctx, now)
	h.refreshNDMeterDrops(ctx)
	targets, punts := h.ndWatch(ctx, now)
	h.refreshNDPunts(ctx, targets, punts)
}

// retryRebuild rebuilds the switch's overlay flows while it is connected and
// they may have drifted from the table: a switch that refused the rebuild
// after a reconnect, or the put-back of a refused change, would otherwise
// leave a quiet overlay on an empty or stale pipeline until its next change.
// A rebuild that keeps failing is tried at doubling intervals, up to
// overlayRebuildBackoffMax, and the backoff ends when one succeeds.
func (h *OverlayModeHandler) retryRebuild(ctx context.Context, now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if !h.running || !h.drifted {
		h.rebuildBackoff, h.rebuildRetryAt = 0, time.Time{}
		return
	}
	// A lost connection is ndReconnect's: it rebuilds on the new one.
	if !h.ofClient.IsConnected() || now.Before(h.rebuildRetryAt) {
		return
	}
	if err := h.rebuild(ctx); err != nil {
		h.rebuildBackoff = nextRebuildBackoff(h.rebuildBackoff)
		h.rebuildRetryAt = now.Add(h.rebuildBackoff)
		h.logger.Warn("rebuilding the overlay flows; trying again",
			slog.Duration("after", h.rebuildBackoff), slog.Any("error", err))
		return
	}
	h.rebuildBackoff, h.rebuildRetryAt = 0, time.Time{}
}

// nextRebuildBackoff is the wait after a failed rebuild that followed one of
// the given wait.
func nextRebuildBackoff(last time.Duration) time.Duration {
	if last == 0 {
		return overlayNDPollInterval
	}
	return min(2*last, overlayRebuildBackoffMax)
}

// ndReconnect redials a management socket the switch closed. Nothing can
// refresh the punts through a dead socket, and a restarted switch has lost
// every flow along with the drop meter: once redialled, the overlay's flows
// are rebuilt from the committed state and the meter is put back, and the
// controller falls back to the flood and resumes the punts after the
// hold-down, once the meter is back. It keeps redialling every tick until
// the switch is back.
func (h *OverlayModeHandler) ndReconnect(ctx context.Context, now time.Time) {
	if h.ofClient.IsConnected() {
		return
	}
	// The switch at the other end may be a restarted one without the meter.
	h.mu.Lock()
	h.ndMeterReady = false
	h.mu.Unlock()
	err := h.ofClient.Connect(ctx)
	if err == nil {
		err = h.restoreSwitch(ctx)
	}
	if err != nil {
		h.logger.Warn("recovering the overlay ND switch connection", slog.Any("error", err))
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.ndController != nil {
		h.ndFallBack(ctx, now)
	}
}

// restoreSwitch puts back what a restarted switch lost: the overlay's flows,
// regenerated on the ports' OpenFlow numbers read again and rebuilt in
// fail-closed order, then the ND meter. A refused rebuild or meter stays due
// and the poll retries it; until the ports resolve, no change goes on.
func (h *OverlayModeHandler) restoreSwitch(ctx context.Context) error {
	h.mu.Lock()
	defer h.mu.Unlock()
	var rebuildErr error
	if h.running {
		h.drifted, h.remap = true, true
		rebuildErr = h.rebuild(ctx)
	}
	return errors.Join(rebuildErr, h.restoreNDMeter(ctx))
}

// retryNDMeter puts back a meter the connected switch refused after a
// reconnect; suppression stays off until it takes it.
func (h *OverlayModeHandler) retryNDMeter(ctx context.Context) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.ndController == nil || h.ndMeterReady || !h.ofClient.IsConnected() {
		return
	}
	if err := h.restoreNDMeter(ctx); err != nil {
		h.logger.Debug("restoring the overlay ND meter; trying again", slog.Any("error", err))
		return
	}
	h.logger.Info("overlay ND meter restored")
}

// restoreNDMeter installs meter 709 and records whether the switch took
// it. Caller holds mu.
func (h *OverlayModeHandler) restoreNDMeter(ctx context.Context) error {
	err := h.ofClient.SetMeter(ctx, overlayNDMeterID, overlayNDMeterRateKbps, overlayNDMeterBurstKbps)
	h.ndMeterReady = err == nil
	return err
}

// ndWatch falls back or resumes as the losses since the last round
// require, and returns the punts due a refresh with their targets, if any.
func (h *OverlayModeHandler) ndWatch(ctx context.Context, now time.Time) ([]ndKey, []*openflow.FlowMod) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if h.ndController == nil {
		return nil, nil
	}
	drops := h.ndLosses()
	if drops > h.ndDropsSeen {
		h.ndFallBack(ctx, now)
	}
	h.ndDropsSeen = drops
	// Punts go on only once the flows they sit among are on the switch's
	// port numbers again and the meter they go through is there.
	if !h.ndSuppressing && h.ndMeterReady && !h.remap && !now.Before(h.ndResumeAt) {
		h.ndSuppressing = true
		h.ndResumedAt = now
		h.ndRefreshAt = now
		h.logger.Info("overlay ND suppression resumed")
	}
	if !h.ndSuppressing || now.Before(h.ndRefreshAt) {
		return nil, nil
	}
	h.ndRefreshAt = now.Add(overlayNDPuntRefresh)
	targets := slices.Collect(maps.Keys(h.ndOwners))
	return targets, h.ndPunts(targets)
}

// ndFallBack deletes the punts, so every solicitation floods, and holds
// suppression off for the hold-down from now, backing it off when the last
// fallback was recent. Should the delete fail, the
// punts still expire: nothing refreshes them while fallen back. Caller
// holds mu.
func (h *OverlayModeHandler) ndFallBack(ctx context.Context, now time.Time) {
	if h.ndSuppressing {
		h.ndHoldDown = nextNDHoldDown(h.ndHoldDown, now.Sub(h.ndResumedAt))
	}
	h.ndResumeAt = now.Add(h.ndHoldDown)
	if !h.ndSuppressing {
		return
	}
	h.ndSuppressing = false
	h.nd.fallbacks.Add(1)
	h.logger.Warn("overlay ND punts dropped; flooding every solicitation",
		slog.Duration("hold_down", h.ndHoldDown))
	if err := h.ofClient.SendFlowMods(ctx, []*openflow.FlowMod{ndFlush()}); err != nil {
		h.logger.Warn("deleting the overlay ND punts", slog.Any("error", err))
	}
}

// nextNDHoldDown is the hold-down of a fallback after suppression held for
// suppressed: the base on the first fallback or after a quiet period, or
// else twice the last, capped.
func nextNDHoldDown(last, suppressed time.Duration) time.Duration {
	if last == 0 || suppressed >= overlayNDFallbackQuiet {
		return overlayNDFallbackHoldDown
	}
	return min(2*last, overlayNDFallbackHoldDownMax)
}

// refreshNDPunts sends the punts ndWatch built for these targets, which
// restarts their hard timeouts. A punt per binding and a barrier is too
// long to hold mu over, so binding changes are synced while the refresh is
// in flight, and the refresh may land after one and undo it. Once the
// barrier is back, every target whose owners no longer match what the
// refresh sent is synced again, under mu: a withdrawal still wins.
func (h *OverlayModeHandler) refreshNDPunts(ctx context.Context, targets []ndKey, punts []*openflow.FlowMod) {
	if len(punts) == 0 {
		return
	}
	if err := h.ofClient.SendFlowMods(ctx, punts); err != nil {
		h.logger.Warn("refreshing the overlay ND punts", slog.Any("error", err))
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	var stale []ndKey
	for i, target := range targets {
		punted := punts[i].Command != openflow.OFPFCDeleteStrict
		if punted != (len(h.ndOwners[target]) == 1) {
			stale = append(stale, target)
		}
	}
	h.syncNDPunts(ctx, stale)
}

// syncNDPunts brings the punts for these targets in line with the answer
// index: a target with one owner is punted, any other is not — an address
// two hosts claim is left to them to answer. A switch that refuses is
// left to the next refresh. Caller holds mu.
func (h *OverlayModeHandler) syncNDPunts(ctx context.Context, targets []ndKey) {
	punts := h.ndPunts(targets)
	if len(punts) == 0 {
		return
	}
	if err := h.ofClient.SendFlowMods(ctx, punts); err != nil {
		h.logger.Warn("updating the overlay ND punts", slog.Any("error", err))
	}
}

// ndPunts is the punt flow mods for these targets, in their order: an add
// for a target with one owner, a strict delete for any other. It is nil
// while not suppressing or without the meter. Caller holds mu.
func (h *OverlayModeHandler) ndPunts(targets []ndKey) []*openflow.FlowMod {
	if !h.ndSuppressing || !h.ndMeterReady || h.builder == nil || len(targets) == 0 {
		return nil
	}
	mods := make([]*openflow.FlowMod, 0, len(targets))
	for _, target := range targets {
		punt := h.builder.ndPunt(target.vni, target.ip)
		if len(h.ndOwners[target]) != 1 {
			punt = strictDelete(punt)
		}
		mods = append(mods, punt)
	}
	return mods
}

// ndFlush deletes every ND punt and no other flow.
func ndFlush() *openflow.FlowMod {
	f := openflow.NewFlowMod(0)
	f.Command = openflow.OFPFCDelete
	f.TableID = TableARP
	f.Cookie = OverlayNDCookie
	f.CookieMask = ^uint64(0)
	return f
}

// refreshNDMeterDrops reads how many punts the meter has dropped. A failed
// read keeps the last count.
func (h *OverlayModeHandler) refreshNDMeterDrops(ctx context.Context) {
	stats, err := h.ofClient.GetMeterStats(ctx, overlayNDMeterID)
	if err != nil {
		h.logger.Debug("reading the overlay ND meter", slog.Any("error", err))
		return
	}
	h.nd.meterCurrent.Store(stats.BandPackets())
}

// ndStatus reports the ND counters. Caller holds mu.
func (h *OverlayModeHandler) ndStatus() NDSuppressionStatus {
	queueDropped := h.nd.queueDropped.Load()
	if h.ndController != nil {
		queueDropped += h.ndController.QueueDropped()
	}
	return NDSuppressionStatus{
		// Between a lost connection and the fallback after the redial the
		// punts are still marked on; without the meter they suppress nothing.
		Suppressing:  h.ndSuppressing && h.ndMeterReady,
		Received:     h.nd.received.Load(),
		Answered:     h.nd.answered.Load(),
		Flooded:      h.nd.flooded.Load(),
		Discarded:    h.nd.discarded.Load(),
		SendFailed:   h.nd.sendFailed.Load(),
		QueueDropped: queueDropped,
		MeterDropped: h.nd.meterDropped.Load() + h.nd.meterCurrent.Load(),
		Fallbacks:    h.nd.fallbacks.Load(),
	}
}

// handleNDPacketIn answers a punted solicitation for a target the overlay
// knows. The punt took the solicitation off the flood, so any other goes
// back to it from here: the controller never swallows a valid one, nor one
// it cannot read. Only a frame invalid under RFC 4861, or with no segment to
// flood it on, is discarded.
func (h *OverlayModeHandler) handleNDPacketIn(ctx context.Context, packet openflow.PacketIn) error {
	h.nd.received.Add(1)
	var req *neighborSolicitation
	parsed, err := parseNeighborSolicitation(packet.Data)
	var unsupported *ErrUnsupportedNDMessage
	switch {
	case err == nil:
		req = &parsed
	case errors.As(err, &unsupported):
		h.logger.Debug("punted neighbor solicitation flooded unread", slog.Any("error", err))
	default:
		h.nd.discarded.Add(1)
		h.logger.Debug("punted neighbor solicitation discarded", slog.Any("error", err))
		return nil
	}
	vni, hasVNI := packetInTunnelID(packet)
	inPort, hasPort := packetInPort(packet)
	if !hasVNI || !hasPort {
		h.nd.discarded.Add(1)
		return nil
	}
	reply, answered := h.ndReply(vni, inPort, req, packet.Data)
	if reply == nil {
		h.nd.discarded.Add(1)
		return nil
	}
	if err := h.ofClient.SendPacketOut(ctx, reply); err != nil {
		h.nd.sendFailed.Add(1)
		return err
	}
	if answered {
		h.nd.answered.Add(1)
		return nil
	}
	h.nd.flooded.Add(1)
	return nil
}

// ndReply is the packet-out for a punted solicitation: the answer, true,
// for a target with one owner on the VNI, or else the solicitation on to
// the segment's VTEPs, the flood it was taken off. A nil req, a
// solicitation the controller could not read, floods. It is nil when the
// VNI has no segment here.
//
// It does not answer a DAD probe, whose unspecified source asks whether
// anyone else holds the address: the owner must defend it, and a proxy
// answer would make the prober give up an address it may own. Nor does it
// answer the binding's own MAC, a host asking about its own address.
func (h *OverlayModeHandler) ndReply(vni, inPort uint32, req *neighborSolicitation, frame []byte) (*openflow.PacketOut, bool) {
	h.mu.Lock()
	defer h.mu.Unlock()
	segment, ok := h.segments[vni]
	if !ok || h.builder == nil {
		return nil, false
	}
	if req != nil {
		mac, known := h.ndTarget(vni, req.Target)
		if known && !req.SrcIP.IsUnspecified() && !slices.Equal(mac, req.SrcMAC) && !slices.Equal(mac, req.SourceLLA) {
			if advertisement, err := buildNeighborAdvertisement(*req, mac); err == nil {
				return openflow.NewPacketOut(inPort, []openflow.Action{
					openflow.NewActionPushVLAN(ethTypeVLAN),
					openflow.NewActionSetField(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBVlanVid, encodeVLAN(segment.vlan)),
					openflow.NewActionOutput(openflow.OFPPInPort, 0),
				}, advertisement), true
			}
		}
	}
	flood := append([]openflow.Action{openflow.NewActionSetTunnelID(uint64(vni))}, h.builder.vtepFlood(segment)...)
	return openflow.NewPacketOut(inPort, flood, frame), false
}

// ndTarget returns the MAC bound to ip on vni. An address two hosts claim
// is left to them to answer. Caller holds mu.
func (h *OverlayModeHandler) ndTarget(vni uint32, ip netip.Addr) (net.HardwareAddr, bool) {
	owners := h.ndOwners[ndKey{vni: vni, ip: ip}]
	if len(owners) != 1 {
		return nil, false
	}
	host, ok := h.hosts[owners[0]]
	if !ok {
		return nil, false
	}
	return slices.Clone(host.mac), true
}

// indexND moves a host's IPv6 bindings in the answer index from its old
// state to its next, either of which may be nil, and returns the targets
// it touched. Caller holds mu.
func (h *OverlayModeHandler) indexND(key hostKey, old, next *overlayHost) []ndKey {
	var touched []ndKey
	if old != nil {
		for ip := range old.ips {
			if !ip.Is6() {
				continue
			}
			k := ndKey{vni: key.vni, ip: ip}
			touched = append(touched, k)
			owners := slices.DeleteFunc(h.ndOwners[k], func(owner hostKey) bool { return owner == key })
			if len(owners) == 0 {
				delete(h.ndOwners, k)
				continue
			}
			h.ndOwners[k] = owners
		}
	}
	if next != nil {
		for ip := range next.ips {
			if !ip.Is6() {
				continue
			}
			k := ndKey{vni: key.vni, ip: ip}
			if !slices.Contains(touched, k) {
				touched = append(touched, k)
			}
			h.ndOwners[k] = append(h.ndOwners[k], key)
		}
	}
	return touched
}

// packetInPort is the port a punted packet came in on.
func packetInPort(packet openflow.PacketIn) (uint32, bool) {
	for _, field := range packet.Match.Fields {
		if field.Class == openflow.OFPXMCOpenflowBasic && field.Field == openflow.OFPXMTOFBInPort && len(field.Value) == 4 {
			return binary.BigEndian.Uint32(field.Value), true
		}
	}
	return 0, false
}

// packetInTunnelID is the VNI a punted packet was on. Open vSwitch reports
// tun_id in an OpenFlow 1.3 packet-in as the OXM basic TUNNEL_ID; the NXM
// field the flows match on is accepted too.
func packetInTunnelID(packet openflow.PacketIn) (uint32, bool) {
	for _, field := range packet.Match.Fields {
		nxm := field.Class == openflow.OFPXMCNxm1 && field.Field == openflow.NXMFieldTunID
		oxm := field.Class == openflow.OFPXMCOpenflowBasic && field.Field == openflow.OFPXMTOFBTunnelId
		if (!nxm && !oxm) || field.HasMask || len(field.Value) != 8 {
			continue
		}
		vni := binary.BigEndian.Uint64(field.Value)
		if vni > uint64(^uint32(0)) {
			return 0, false
		}
		return uint32(vni), true
	}
	return 0, false
}

// neighborSolicitation is what the answer needs from a solicitation.
// SourceLLA is the source link-layer address option, nil when absent.
type neighborSolicitation struct {
	SrcMAC    net.HardwareAddr
	SrcIP     netip.Addr
	DstIP     netip.Addr
	Target    netip.Addr
	SourceLLA net.HardwareAddr
}

func invalidND(reason string) error {
	return &ErrInvalidNDMessage{Reason: reason}
}

// parseNeighborSolicitation decodes an untagged Ethernet frame holding a
// neighbor solicitation, applying the validity checks of RFC 4861 §7.1.1.
// Bytes past the IPv6 payload, Ethernet padding, are ignored. Extension
// headers are not followed: a solicitation carrying one is not answered.
func parseNeighborSolicitation(frame []byte) (neighborSolicitation, error) {
	if len(frame) < ndICMPOffset+ndMessageLen {
		return neighborSolicitation{}, invalidND("truncated")
	}
	if binary.BigEndian.Uint16(frame[12:14]) != ethTypeIPv6 || frame[14]>>4 != 6 {
		return neighborSolicitation{}, invalidND("not IPv6")
	}
	if frame[6]&0x01 != 0 {
		return neighborSolicitation{}, invalidND("multicast Ethernet source")
	}
	payloadLen := int(binary.BigEndian.Uint16(frame[18:20]))
	if ndICMPOffset+payloadLen > len(frame) {
		return neighborSolicitation{}, invalidND("payload length past the frame")
	}
	if payloadLen < ndMessageLen {
		return neighborSolicitation{}, invalidND("payload shorter than a solicitation")
	}
	if frame[21] != ndHopLimit {
		return neighborSolicitation{}, invalidND("hop limit not 255")
	}
	// The punt matched an ICMPv6 solicitation, so any other next header is
	// an extension header in front of one; Open vSwitch reads past them,
	// this parser does not.
	if frame[20] != ipProtoICMPv6 {
		return neighborSolicitation{}, &ErrUnsupportedNDMessage{Reason: "extension header"}
	}
	icmp := frame[ndICMPOffset : ndICMPOffset+payloadLen]
	if icmp[0] != icmpv6NS {
		return neighborSolicitation{}, invalidND("not a solicitation")
	}
	if icmp[1] != 0 {
		return neighborSolicitation{}, invalidND("nonzero ICMPv6 code")
	}
	if icmpv6Checksum(frame[22:38], frame[38:54], icmp) != 0 {
		return neighborSolicitation{}, invalidND("bad ICMPv6 checksum")
	}

	req := neighborSolicitation{
		SrcMAC: slices.Clone(net.HardwareAddr(frame[6:12])),
		SrcIP:  netip.AddrFrom16([16]byte(frame[22:38])),
		DstIP:  netip.AddrFrom16([16]byte(frame[38:54])),
		Target: netip.AddrFrom16([16]byte(icmp[8:24])),
	}
	if req.SrcIP.IsMulticast() {
		return neighborSolicitation{}, invalidND("multicast source")
	}
	if req.Target.IsMulticast() {
		return neighborSolicitation{}, invalidND("multicast target")
	}
	for options := icmp[ndMessageLen:]; len(options) > 0; {
		if len(options) < 2 {
			return neighborSolicitation{}, invalidND("option past the payload")
		}
		size := int(options[1]) * ndOptionUnit
		if size == 0 {
			return neighborSolicitation{}, invalidND("zero-length option")
		}
		if size > len(options) {
			return neighborSolicitation{}, invalidND("option past the payload")
		}
		if options[0] == ndOptSourceLLA {
			if size != ndOptionUnit {
				return neighborSolicitation{}, invalidND("source link-layer option not 8 bytes")
			}
			if options[2]&0x01 != 0 {
				return neighborSolicitation{}, invalidND("multicast source link-layer option")
			}
			req.SourceLLA = slices.Clone(net.HardwareAddr(options[2:8]))
		}
		options = options[size:]
	}
	if req.SrcIP.IsUnspecified() {
		if req.SourceLLA != nil {
			return neighborSolicitation{}, invalidND("source link-layer option with an unspecified source")
		}
		if !solicitedNodePrefix.Contains(req.DstIP) {
			return neighborSolicitation{}, invalidND("unspecified source not to a solicited-node address")
		}
	}
	return req, nil
}

// buildNeighborAdvertisement answers req for its target with mac: a
// solicited, overriding advertisement unicast to the solicitor, at its
// link-layer option's address or else the frame's source. Only a unicast
// solicitor is answered, so no advertisement goes to a multicast address.
func buildNeighborAdvertisement(req neighborSolicitation, mac net.HardwareAddr) ([]byte, error) {
	if len(mac) != 6 || len(req.SrcMAC) != 6 || !req.Target.Is6() {
		return nil, invalidND("advertisement needs a 6-byte MAC and an IPv6 target")
	}
	if !req.SrcIP.Is6() || req.SrcIP.IsUnspecified() || req.SrcIP.IsMulticast() {
		return nil, invalidND("advertisement needs a unicast destination")
	}
	dstMAC := req.SrcMAC
	if req.SourceLLA != nil {
		dstMAC = req.SourceLLA
	}
	payloadLen := ndMessageLen + ndOptionUnit
	frame := make([]byte, ndICMPOffset+payloadLen)
	copy(frame[0:6], dstMAC)
	copy(frame[6:12], mac)
	binary.BigEndian.PutUint16(frame[12:14], ethTypeIPv6)

	frame[14] = 0x60
	binary.BigEndian.PutUint16(frame[18:20], uint16(payloadLen))
	frame[20] = ipProtoICMPv6
	frame[21] = ndHopLimit
	target := req.Target.As16()
	dst := req.SrcIP.As16()
	copy(frame[22:38], target[:])
	copy(frame[38:54], dst[:])

	icmp := frame[ndICMPOffset:]
	icmp[0] = icmpv6NA
	icmp[4] = naFlagSolicited | naFlagOverride
	copy(icmp[8:24], target[:])
	icmp[24] = ndOptTargetLLA
	icmp[25] = 1
	copy(icmp[26:32], mac)
	binary.BigEndian.PutUint16(icmp[2:4], icmpv6Checksum(frame[22:38], frame[38:54], icmp))
	return frame, nil
}

// icmpv6Checksum is the ICMPv6 checksum over the IPv6 pseudo-header and
// payload. Over a payload carrying a correct checksum it is zero.
func icmpv6Checksum(src []byte, dst []byte, payload []byte) uint16 {
	sum := checksumAdd(0, src)
	sum = checksumAdd(sum, dst)
	var pseudo [8]byte
	binary.BigEndian.PutUint32(pseudo[0:4], uint32(len(payload)))
	pseudo[7] = ipProtoICMPv6
	sum = checksumAdd(sum, pseudo[:])
	sum = checksumAdd(sum, payload)
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

func checksumAdd(sum uint32, data []byte) uint32 {
	for len(data) > 1 {
		sum += uint32(binary.BigEndian.Uint16(data[0:2]))
		data = data[2:]
	}
	if len(data) == 1 {
		sum += uint32(data[0]) << 8
	}
	return sum
}
