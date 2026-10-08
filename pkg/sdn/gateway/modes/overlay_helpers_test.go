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
	"io"
	"log/slog"
	"net"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/bgp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/ovs"
	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/vxlan"
)

// The test overlay: this VTEP is A, B and C are remote. The VXLAN port is
// OpenFlow port 7 and the access trunk port 3.
var (
	ovlVTEPA      = netip.MustParseAddr("10.0.0.1")
	ovlVTEPB      = netip.MustParseAddr("10.0.0.2")
	ovlVTEPC      = netip.MustParseAddr("10.0.0.3")
	ovlRouterMAC  = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x0a}
	ovlRouterMACB = net.HardwareAddr{0x02, 0, 0, 0, 0, 0x0b}
	ovlAnycastIP  = netip.MustParseAddr("10.1.0.1")
	ovlAnycastMAC = net.HardwareAddr{0x02, 0xaa, 0xaa, 0xaa, 0xaa, 0xaa}
	ovlHostMAC    = net.HardwareAddr{0x02, 0, 0, 0, 0x01, 0x10}
	ovlHostIP     = netip.MustParseAddr("10.1.0.10")
	ovlRemoteMAC  = net.HardwareAddr{0x02, 0, 0, 0, 0x02, 0x20}
	ovlRemoteIP   = netip.MustParseAddr("10.1.0.20")
)

const (
	ovlL2VNI      uint32 = 10100
	ovlL3VNI      uint32 = 50000
	ovlVLAN       uint16 = 100
	ovlASN        uint16 = 65000
	ovlAccessPort        = "access0"
)

func ovlLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// fakeOverlayOVS is an OVSDB holding the VXLAN port and the access port.
type fakeOverlayOVS struct {
	mu        sync.Mutex
	ports     map[string]*ovs.VXLANPort
	ofPorts   map[string]int32
	addErr    error
	deleteErr error
}

func newFakeOverlayOVS() *fakeOverlayOVS {
	return &fakeOverlayOVS{
		ports:   make(map[string]*ovs.VXLANPort),
		ofPorts: map[string]int32{ovlAccessPort: 3},
	}
}

func (f *fakeOverlayOVS) AddVXLANPortWithName(_ context.Context, _, port string, cfg *ovs.VXLANPortConfig) (*ovs.VXLANPort, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.addErr != nil {
		return nil, f.addErr
	}
	p := &ovs.VXLANPort{Name: port, IsFlowRemote: cfg.RemoteFlow, IsFlowKey: cfg.Key == 0, DstPort: cfg.DstPort}
	f.ports[port] = p
	f.ofPorts[port] = 7
	return p, nil
}

func (f *fakeOverlayOVS) GetVXLANPortWithOptions(_ context.Context, _, port string) (*ovs.VXLANPort, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	p, ok := f.ports[port]
	if !ok {
		return nil, ovs.ErrPortNotFound
	}
	return p, nil
}

func (f *fakeOverlayOVS) DeleteVXLANPort(_ context.Context, _, port string) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.deleteErr != nil {
		return f.deleteErr
	}
	delete(f.ports, port)
	delete(f.ofPorts, port)
	return nil
}

func (f *fakeOverlayOVS) GetOFPort(_ context.Context, port string) (int32, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	ofPort, ok := f.ofPorts[port]
	if !ok {
		return 0, ovs.ErrPortNotFound
	}
	return ofPort, nil
}

func (f *fakeOverlayOVS) hasPort(port string) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	_, ok := f.ports[port]
	return ok
}

// switchFlow is one flow on the fake switch, rendered: its match as
// name=value fields and its instructions as one line.
type switchFlow struct {
	table    uint8
	priority uint16
	match    []string
	actions  string
}

func (f *switchFlow) String() string {
	return flowIdentity(f.table, f.priority, f.match) + " -> " + f.actions
}

// matches reports whether a packet with the fields pkt hits the flow: it
// carries every field the flow matches, a masked address inside the prefix.
func (f *switchFlow) matches(pkt map[string]string) bool {
	for _, field := range f.match {
		name, want, _ := strings.Cut(field, "=")
		got, ok := pkt[name]
		if !ok {
			return false
		}
		if prefix, err := netip.ParsePrefix(want); err == nil {
			addr, err := netip.ParseAddr(got)
			if err != nil || !prefix.Contains(addr) {
				return false
			}
			continue
		}
		if got != want {
			return false
		}
	}
	return true
}

// fakeSwitch applies flow mods to a flow table the way OVS does — an add
// replaces the flow of the same table, priority and match; a strict delete
// removes exactly one; a delete removes by cookie — so tests assert on what
// the switch holds and on which flow a packet hits.
type fakeSwitch struct {
	mu      sync.Mutex
	flows   map[string]*switchFlow
	failErr error
	// refuseAt, while refusing, is the mod the next batch refuses;
	// refuseThen is what every send after that batch fails with.
	refuseAt   int
	refuseThen error
	refusing   bool
	// passes, while passThen is set, is how many batches still apply
	// before every send fails with passThen.
	passes   int
	passThen error
	sent     chan struct{}
	// batches is the mods of every batch the switch has applied, in the
	// order it applied them: OVS applies a batch one mod at a time.
	batches [][]*openflow.FlowMod
}

func newFakeSwitch() *fakeSwitch {
	return &fakeSwitch{flows: make(map[string]*switchFlow), sent: make(chan struct{}, 64)}
}

// SendFlowMods applies a batch the way the OpenFlow client does: a mod the
// switch refuses fails the batch with ErrBatchPartialFailure, and the
// mods around it are applied all the same.
func (s *fakeSwitch) SendFlowMods(_ context.Context, mods []*openflow.FlowMod) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.passThen != nil {
		if s.passes == 0 {
			s.failErr, s.passThen = s.passThen, nil
		}
		s.passes--
	}
	if s.failErr != nil {
		return s.failErr
	}
	refused := -1
	if s.refusing && s.refuseAt < len(mods) {
		refused, s.refusing, s.failErr = s.refuseAt, false, s.refuseThen
	}
	applied := make([]*openflow.FlowMod, 0, len(mods))
	for i, mod := range mods {
		if i != refused {
			s.applyMod(mod)
			applied = append(applied, mod)
		}
	}
	s.batches = append(s.batches, applied)
	select {
	case s.sent <- struct{}{}:
	default:
	}
	if refused >= 0 {
		return &openflow.ErrBatchPartialFailure{Failed: []openflow.BatchFlowError{{
			Index: refused,
			Err:   &openflow.OFError{Type: openflow.OFPETFlowModFailed},
		}}}
	}
	return nil
}

// refuse makes the next batch of more than index mods refuse the mod at
// index and apply the rest; every send after it fails with then, and a
// nil then leaves the switch healthy.
func (s *fakeSwitch) refuse(index int, then error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.refuseAt, s.refuseThen, s.refusing = index, then, true
}

// newSwitchFlow renders the flow a mod adds or removes.
func newSwitchFlow(mod *openflow.FlowMod) *switchFlow {
	flow := &switchFlow{table: mod.TableID, priority: mod.Priority, actions: describeInstructions(mod.Instructions)}
	for _, field := range mod.Match.Fields {
		flow.match = append(flow.match, describeField(field.Class, field.Field, field.Value, field.Mask))
	}
	return flow
}

// describeMods renders mods in order, as the flows they add or remove.
func describeMods(mods []*openflow.FlowMod) []string {
	out := make([]string, 0, len(mods))
	for _, mod := range mods {
		out = append(out, newSwitchFlow(mod).String())
	}
	return out
}

// assertFailClosed checks that a batch a switch applies one mod at a time
// never lets through a frame the whole batch would drop: the flows that
// pass a frame on from tables 0 and 10 follow the drop of unauthorised
// tunnelled frames, and every goto follows the flows of the table it
// reaches.
func assertFailClosed(t *testing.T, mods []*openflow.FlowMod) {
	t.Helper()
	decapDrop := slices.IndexFunc(mods, func(m *openflow.FlowMod) bool {
		return m.Command == openflow.OFPFCAdd && m.TableID == TableVXLANDecap && m.Priority == priorityDecapDrop
	})
	require.GreaterOrEqual(t, decapDrop, 0, "the batch installs the decap drop")
	for i, mod := range mods {
		if mod.Command != openflow.OFPFCAdd {
			continue
		}
		passes := mod.TableID == TableIngress || (mod.TableID == TableVXLANDecap && mod.Priority < priorityDecapDrop)
		if passes {
			assert.Greater(t, i, decapDrop, "%s precedes the decap drop", newSwitchFlow(mod))
		}
		for _, instruction := range mod.Instructions {
			gotoTable, ok := instruction.(*openflow.InstructionGotoTable)
			if !ok {
				continue
			}
			reached := slices.IndexFunc(mods[i+1:], func(m *openflow.FlowMod) bool { return m.TableID == gotoTable.TableID })
			assert.Negative(t, reached, "%s precedes a flow of the table it reaches", newSwitchFlow(mod))
		}
	}
}

// applyMod applies one flow mod. Caller holds mu.
func (s *fakeSwitch) applyMod(mod *openflow.FlowMod) {
	flow := newSwitchFlow(mod)
	key := flowIdentity(flow.table, flow.priority, flow.match)
	switch mod.Command {
	case openflow.OFPFCAdd:
		s.flows[key] = flow
	case openflow.OFPFCDeleteStrict:
		delete(s.flows, key)
	case openflow.OFPFCDelete:
		// Every flow on the test switch carries the overlay cookie.
		clear(s.flows)
	}
}

// batchesSince returns the batches the switch has applied since it had
// applied mark of them, each in the order it applied its mods.
func (s *fakeSwitch) batchesSince(mark int) [][]*openflow.FlowMod {
	s.mu.Lock()
	defer s.mu.Unlock()
	return slices.Clone(s.batches[mark:])
}

// batchCount is how many batches the switch has applied, a mark for
// batchesSince.
func (s *fakeSwitch) batchCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.batches)
}

// failAfter lets the next n batches apply and makes every send after them
// fail with err.
func (s *fakeSwitch) failAfter(n int, err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.passes, s.passThen = n, err
}

// fail makes every following send fail with err; nil heals the switch.
func (s *fakeSwitch) fail(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.failErr = err
}

// table returns the switch's flows rendered, sorted.
func (s *fakeSwitch) table() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	flows := make([]string, 0, len(s.flows))
	for _, f := range s.flows {
		flows = append(flows, f.String())
	}
	slices.Sort(flows)
	return flows
}

// has reports whether the switch holds exactly the flow want.
func (s *fakeSwitch) has(want string) bool {
	return slices.Contains(s.table(), want)
}

// matching returns the flows containing every one of parts.
func (s *fakeSwitch) matching(parts ...string) []string {
	var out []string
	for _, f := range s.table() {
		all := true
		for _, part := range parts {
			all = all && strings.Contains(f, part)
		}
		if all {
			out = append(out, f)
		}
	}
	return out
}

// lookup returns the instructions of the flow a packet with the given
// name=value fields hits in table, the way the switch picks it: the
// highest-priority match. Two matching flows of one priority fail the
// test — OVS would pick either.
func (s *fakeSwitch) lookup(t *testing.T, table uint8, fields ...string) string {
	t.Helper()
	pkt := make(map[string]string, len(fields))
	for _, field := range fields {
		name, value, _ := strings.Cut(field, "=")
		pkt[name] = value
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	var hit *switchFlow
	for _, f := range s.flows {
		if f.table != table || !f.matches(pkt) {
			continue
		}
		if hit != nil && hit.priority == f.priority {
			t.Fatalf("ambiguous flows in table %d: %s and %s", table, hit, f)
		}
		if hit == nil || f.priority > hit.priority {
			hit = f
		}
	}
	if hit == nil {
		t.Fatalf("no flow in table %d for %v", table, fields)
	}
	return hit.actions
}

// awaitSend waits for the next batch the switch receives.
func (s *fakeSwitch) awaitSend(t *testing.T) {
	t.Helper()
	select {
	case <-s.sent:
	case <-time.After(5 * time.Second):
		t.Fatal("no flow mods reached the switch")
	}
}

// drainSends forgets the batches already signalled.
func (s *fakeSwitch) drainSends() {
	for {
		select {
		case <-s.sent:
		default:
			return
		}
	}
}

// flowIdentity renders a flow's table, priority and match; "any" is the
// empty match.
func flowIdentity(table uint8, priority uint16, match []string) string {
	fields := "any"
	if len(match) > 0 {
		fields = strings.Join(match, ",")
	}
	return "t=" + strconv.Itoa(int(table)) + " p=" + strconv.Itoa(int(priority)) + " " + fields
}

type oxmName struct {
	class uint16
	field uint8
}

var oxmNames = map[oxmName]string{
	{openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBInPort}:  "in_port",
	{openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBEthDst}:  "eth_dst",
	{openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBEthSrc}:  "eth_src",
	{openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBEthType}: "eth_type",
	{openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBVlanVid}: "vlan",
	{openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBIPv4Dst}: "ipv4_dst",
	{openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBArpOp}:   "arp_op",
	{openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBArpSpa}:  "arp_spa",
	{openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBArpTpa}:  "arp_tpa",
	{openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBArpSha}:  "arp_sha",
	{openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBArpTha}:  "arp_tha",
	{openflow.OFPXMCNxm1, openflow.NXMFieldTunID}:             "tun_id",
	{openflow.OFPXMCNxm1, openflow.NXMFieldTunIPv4Src}:        "tun_src",
}

// describeField renders one match field or set-field as name=value.
func describeField(class uint16, field uint8, value, mask []byte) string {
	name, ok := oxmNames[oxmName{class, field}]
	if !ok {
		name = "field" + strconv.Itoa(int(field))
	}
	var v string
	switch {
	case len(value) == 6:
		v = net.HardwareAddr(value).String()
	case len(value) == 4 && name != "in_port":
		v = netip.AddrFrom4([4]byte(value)).String()
		if len(mask) == 4 {
			ones, _ := net.IPMask(mask).Size()
			v += "/" + strconv.Itoa(ones)
		}
	case name == "vlan":
		v = strconv.Itoa(int(binary.BigEndian.Uint16(value) & 0x0fff))
	case name == "eth_type":
		v = "0x" + strconv.FormatUint(uint64(binary.BigEndian.Uint16(value)), 16)
	case len(value) == 2:
		v = strconv.Itoa(int(binary.BigEndian.Uint16(value)))
	case len(value) == 4:
		v = strconv.FormatUint(uint64(binary.BigEndian.Uint32(value)), 10)
	case len(value) == 8:
		v = strconv.FormatUint(binary.BigEndian.Uint64(value), 10)
	}
	return name + "=" + v
}

// describeInstructions renders a flow's instructions; none is a drop.
func describeInstructions(instructions []openflow.Instruction) string {
	if len(instructions) == 0 {
		return "drop"
	}
	parts := make([]string, 0, len(instructions))
	for _, instruction := range instructions {
		switch i := instruction.(type) {
		case *openflow.InstructionGotoTable:
			parts = append(parts, "goto:"+strconv.Itoa(int(i.TableID)))
		case *openflow.InstructionApplyActions:
			actions := make([]string, 0, len(i.Actions))
			for _, action := range i.Actions {
				actions = append(actions, describeAction(action))
			}
			parts = append(parts, strings.Join(actions, ","))
		}
	}
	return strings.Join(parts, " ")
}

// regNames names the OXM headers of the ARP rewrite's moves.
var regNames = map[uint32]string{
	openflow.OXMHeader(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBEthSrc, 6): "eth_src",
	openflow.OXMHeader(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBEthDst, 6): "eth_dst",
	openflow.OXMHeader(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBArpSha, 6): "arp_sha",
	openflow.OXMHeader(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBArpTha, 6): "arp_tha",
	openflow.OXMHeader(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBArpSpa, 4): "arp_spa",
	openflow.OXMHeader(openflow.OFPXMCOpenflowBasic, openflow.OFPXMTOFBArpTpa, 4): "arp_tpa",
}

func describeAction(action openflow.Action) string {
	switch a := action.(type) {
	case *openflow.ActionOutput:
		if a.Port == openflow.OFPPInPort {
			return "output:IN_PORT"
		}
		return "output:" + strconv.FormatUint(uint64(a.Port), 10)
	case *openflow.ActionSetField:
		return "set:" + describeField(a.Field.Class, a.Field.Field, a.Field.Value, nil)
	case *openflow.ActionPushVLAN:
		return "push_vlan"
	case *openflow.ActionPopVLAN:
		return "pop_vlan"
	case *openflow.ActionDecNwTTL:
		return "dec_ttl"
	case *openflow.ActionSetTunnelID:
		return "set:tun_id=" + strconv.FormatUint(a.TunnelID, 10)
	case *openflow.ActionSetTunDst:
		return "set:tun_dst=" + a.IPv4.String()
	case *openflow.ActionRegMove:
		return "move:" + regNames[a.Src] + "->" + regNames[a.Dst]
	}
	return "unknown"
}

// fakeSpeaker is the BGP speaker of the EVPN manager: it records what is
// originated and delivers the routes a test receives.
type fakeSpeaker struct {
	mu        sync.Mutex
	added     []*bgp.Path
	deleted   []*bgp.Path
	events    chan *bgp.Event
	addErr    error
	deleteErr error
	watchErr  error
}

func newFakeSpeaker() *fakeSpeaker {
	return &fakeSpeaker{events: make(chan *bgp.Event, 16)}
}

func (s *fakeSpeaker) AddPath(_ context.Context, path *bgp.Path) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.addErr != nil {
		return s.addErr
	}
	s.added = append(s.added, path)
	return nil
}

func (s *fakeSpeaker) DeletePath(_ context.Context, path *bgp.Path) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.deleteErr != nil {
		return s.deleteErr
	}
	s.deleted = append(s.deleted, path)
	return nil
}

func (s *fakeSpeaker) WatchEvent(_ context.Context, _ ...bgp.WatchOption) (<-chan *bgp.Event, error) {
	if s.watchErr != nil {
		return nil, s.watchErr
	}
	return s.events, nil
}

func (s *fakeSpeaker) failAdds(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.addErr = err
}

// failDeletes makes every withdrawal fail with err; nil heals the speaker.
func (s *fakeSpeaker) failDeletes(err error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deleteErr = err
}

// addedMACIPs returns the Type-2 routes originated.
func (s *fakeSpeaker) addedMACIPs() []*bgp.MACIPEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []*bgp.MACIPEntry
	for _, p := range s.added {
		if p.EVPN != nil && p.EVPN.MACIP != nil {
			out = append(out, p.EVPN.MACIP)
		}
	}
	return out
}

// addedTypes returns the types of the routes originated.
func (s *fakeSpeaker) addedTypes() []bgp.EVPNRouteType {
	s.mu.Lock()
	defer s.mu.Unlock()
	return routeTypes(s.added)
}

// deletedTypes returns the types of the routes withdrawn.
func (s *fakeSpeaker) deletedTypes() []bgp.EVPNRouteType {
	s.mu.Lock()
	defer s.mu.Unlock()
	return routeTypes(s.deleted)
}

func routeTypes(paths []*bgp.Path) []bgp.EVPNRouteType {
	var out []bgp.EVPNRouteType
	for _, p := range paths {
		if p.EVPN != nil {
			out = append(out, p.EVPN.Type)
		}
	}
	return out
}

// recordingAdmitter admits every VTEP but those refused, and records what
// it was asked.
type recordingAdmitter struct {
	mu      sync.Mutex
	refused map[netip.Addr]bool
	asked   []string
}

func (a *recordingAdmitter) AdmitVTEP(_ context.Context, vni uint32, vtep netip.Addr) error {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.asked = append(a.asked, strconv.FormatUint(uint64(vni), 10)+"@"+vtep.String())
	if a.refused[vtep] {
		return errAdmissionRefused
	}
	return nil
}

// admitAll admits every VTEP, for the tests that do not vet admission.
type admitAll struct{}

func (admitAll) AdmitVTEP(context.Context, uint32, netip.Addr) error { return nil }

type overlayTestError struct{ msg string }

func (e *overlayTestError) Error() string { return e.msg }

var (
	errAdmissionRefused = &overlayTestError{msg: "VTEP not admitted"}
	errSwitchDown       = &overlayTestError{msg: "switch down"}
)

// overlayFixture is a handler with fakes for everything below it.
type overlayFixture struct {
	handler *OverlayModeHandler
	ovs     *fakeOverlayOVS
	sw      *fakeSwitch
	speaker *fakeSpeaker
}

// overlayConfig is a symmetric-IRB VTEP with ARP suppression.
func overlayConfig(speaker bgp.EVPNSpeaker) *OverlayModeConfig {
	return &OverlayModeConfig{
		VTEPConfig: &vxlan.VTEPConfig{
			LocalIP:       ovlVTEPA,
			UnderlayIface: "eth0",
			UnderlayMTU:   9216,
			VXLANPort:     vxlan.DefaultVXLANPort,
		},
		EVPNConfig: &bgp.EVPNManagerConfig{
			Speaker:    speaker,
			Logger:     ovlLogger(),
			LocalVTEP:  ovlVTEPA,
			OverlayASN: ovlASN,
			RouterMAC:  ovlRouterMAC,
		},
		ARPSuppression:    true,
		AnycastGatewayIP:  ovlAnycastIP,
		AnycastGatewayMAC: ovlAnycastMAC,
		L3VNI:             ovlL3VNI,
		BridgeName:        "br-int",
		AccessPort:        ovlAccessPort,
		Admitter:          admitAll{},
		Logger:            ovlLogger(),
	}
}

// newStoppedOverlay builds a handler from the default config, adjusted by
// edit, without starting it.
func newStoppedOverlay(t *testing.T, edit func(*OverlayModeConfig)) *overlayFixture {
	t.Helper()
	f := &overlayFixture{ovs: newFakeOverlayOVS(), sw: newFakeSwitch(), speaker: newFakeSpeaker()}
	cfg := overlayConfig(f.speaker)
	if edit != nil {
		edit(cfg)
	}
	h, err := NewOverlayModeHandler(cfg, f.ovs, f.sw)
	require.NoError(t, err)
	f.handler = h
	return f
}

// newOverlayFixture starts a handler built from the default config,
// adjusted by edit, and stops it when the test ends.
func newOverlayFixture(t *testing.T, edit func(*OverlayModeConfig)) *overlayFixture {
	t.Helper()
	f := newStoppedOverlay(t, edit)
	require.NoError(t, f.handler.Start(context.Background()))
	t.Cleanup(func() {
		if f.handler.GetStatus().Running {
			require.NoError(t, f.handler.Stop(context.Background()))
		}
	})
	return f
}

// withVNI adds the test L2VNI on its VLAN.
func (f *overlayFixture) withVNI(t *testing.T) *overlayFixture {
	t.Helper()
	require.NoError(t, f.handler.AddVNI(context.Background(), ovlL2VNI, ovlVLAN))
	return f
}

// route delivers an EVPN route change straight to the handler.
func (f *overlayFixture) route(t *testing.T, route *bgp.EVPNRouteData) error {
	t.Helper()
	return f.handler.handleEVPNRoute(context.Background(), route)
}

// imet is vtep's Type-3 route for vni.
func imet(vni uint32, vtep netip.Addr) *bgp.EVPNRouteData {
	return &bgp.EVPNRouteData{
		Type:    bgp.EVPNTypeInclusiveMulticast,
		RD:      bgp.RouteDistinguisher{Admin: vtep, Index: 1},
		IMET:    &bgp.IMETEntry{VNI: vni, VTEPIP: vtep},
		NextHop: vtep,
	}
}

// macip is vtep's Type-2 route for mac (and ip, when valid) on the test
// L2VNI, carrying the L3VNI and router MAC of symmetric IRB.
func macip(vtep netip.Addr, mac net.HardwareAddr, ip netip.Addr) *bgp.EVPNRouteData {
	return &bgp.EVPNRouteData{
		Type:      bgp.EVPNTypeMACIPAdvertisement,
		RD:        bgp.RouteDistinguisher{Admin: vtep, Index: 1},
		MACIP:     &bgp.MACIPEntry{MAC: mac, IP: ip, VNI: ovlL2VNI, L3VNI: ovlL3VNI, VTEPIP: vtep},
		NextHop:   vtep,
		RouterMAC: ovlRouterMACB,
	}
}

// prefixRoute is vtep's Type-5 route for prefix in the test IP-VRF.
func prefixRoute(vtep netip.Addr, prefix string) *bgp.EVPNRouteData {
	return &bgp.EVPNRouteData{
		Type:       bgp.EVPNTypeIPPrefix,
		RD:         bgp.RouteDistinguisher{Admin: vtep, Index: 2},
		PrefixData: &bgp.PrefixRoute{Prefix: netip.MustParsePrefix(prefix), VNI: ovlL3VNI, VTEPIP: vtep},
		NextHop:    vtep,
		RouterMAC:  ovlRouterMACB,
	}
}

// withdraw marks a route withdrawn.
func withdraw(route *bgp.EVPNRouteData) *bgp.EVPNRouteData {
	route.IsWithdraw = true
	return route
}

// importable gives a route the route targets the EVPN manager imports for
// vnis, as a remote VTEP would.
func importable(t *testing.T, route *bgp.EVPNRouteData, vnis ...uint32) *bgp.EVPNRouteData {
	t.Helper()
	for _, vni := range vnis {
		rt, err := bgp.AutoRouteTarget(ovlASN, 0, vni)
		require.NoError(t, err)
		route.RouteTargets = append(route.RouteTargets, rt)
	}
	return route
}
