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

package openflow

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// mockOFServer represents a mock OpenFlow server for testing
type mockOFServer struct {
	t        *testing.T
	listener net.Listener
	conn     net.Conn
	done     chan struct{}
	wg       sync.WaitGroup
	mu       sync.Mutex
	closed   atomic.Bool

	// Server state
	datapathID   uint64
	nBuffers     uint32
	nTables      uint8
	capabilities uint32

	// Received messages for verification
	receivedFlowMods  []FlowMod
	receivedBarriers  int
	receivedGroupMods []GroupMod
	receivedEchoReply int

	// injected counts faults actually written to the wire. A test that
	// asserts "the client survived X" is vacuous unless X was delivered, so
	// the fault tests assert this too.
	injected int

	// arrivals carries a wakeup per recorded message so a test can wait for
	// what it is about to assert on instead of sleeping and hoping. Sends are
	// non-blocking, so the mock's read loop is never stalled by a test that
	// is not currently waiting, and the counters above stay authoritative —
	// a dropped wakeup cannot lose a message.
	arrivals chan struct{}

	// accepted carries a wakeup per connection the server accepts.
	accepted chan struct{}

	// Response behavior
	sendHelloReply          bool
	sendFeaturesReply       bool
	sendBarrierReply        bool
	sendEchoReply           bool
	sendMultipartReply      bool
	respondWithError        bool
	sendErrorOnFlowMod      bool
	errorType               uint16
	errorCode               uint16
	stallResponses          bool
	flowStats               []FlowStats
	groupDescs              []GroupDesc
	failFlowModIndexes      map[int]struct{}
	sendErrorOnGroupMod     bool
	closeAfterHandshake     bool
	invalidVersionInHello   bool
	sendEchoRequest         bool
	sendIncompleteHeader    bool
	sendMalformedHeader     bool
	sendWrongHelloType      bool
	sendWrongFeaturesType   bool
	sendShortMultipartReply bool
	sendUnknownXid          bool

	// Switch config: missSendLen is what SET_CONFIG stored and GET_CONFIG
	// reports; ignoreSetConfig models a switch that keeps it at zero.
	missSendLen     uint16
	ignoreSetConfig bool

	// Meter table: meters holds the installed meters by ID; meterMods
	// records every meter mod in arrival order; metersUnsupported models a
	// datapath without meter support.
	meters            map[uint32]MeterMod
	meterMods         []MeterMod
	meterStats        map[uint32]MeterStats
	metersUnsupported bool

	// receivedPacketOuts records the packet-out message bodies.
	receivedPacketOuts [][]byte

	// packetOutErrType and packetOutErrCode, when nonzero, make the switch
	// reject every packet-out asynchronously with an OFPT_ERROR.
	packetOutErrType uint16
	packetOutErrCode uint16

	// configFlags is the fragment policy SET_CONFIG stored and GET_CONFIG
	// reports; setConfigs records every SET_CONFIG flags value received.
	configFlags uint16
	setConfigs  []uint16
}

// newMockOFServer creates a new mock OpenFlow server
// Returns the server and socket path for client connection
func newMockOFServer(t *testing.T) (*mockOFServer, string) {
	t.Helper()

	// A short directory keeps the socket path under the sun_path limit.
	socketDir := shortSocketDir(t)
	socketPath := filepath.Join(socketDir, "test-bridge.mgmt")

	listener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to create mock server listener: %v", err)
	}

	s := &mockOFServer{
		t:                  t,
		listener:           listener,
		done:               make(chan struct{}),
		datapathID:         0x0000000000000001,
		nBuffers:           256,
		nTables:            254,
		capabilities:       0x000000ff,
		sendHelloReply:     true,
		sendFeaturesReply:  true,
		sendBarrierReply:   true,
		sendEchoReply:      true,
		sendMultipartReply: true,
		receivedFlowMods:   make([]FlowMod, 0),
		arrivals:           make(chan struct{}, 1),
		accepted:           make(chan struct{}, 4),
		flowStats:          make([]FlowStats, 0),
		failFlowModIndexes: make(map[int]struct{}),
		meters:             make(map[uint32]MeterMod),
		meterStats:         make(map[uint32]MeterStats),
	}

	// Start accepting connections
	s.wg.Add(1)
	go s.acceptConnections()

	return s, socketPath
}

// acceptConnections accepts incoming connections
func (s *mockOFServer) acceptConnections() {
	defer s.wg.Done()

	for {
		select {
		case <-s.done:
			return
		default:
		}

		// Set accept deadline to allow checking done channel
		_ = s.listener.(*net.UnixListener).SetDeadline(time.Now().Add(100 * time.Millisecond))

		conn, err := s.listener.Accept()
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			select {
			case <-s.done:
				return
			default:
				s.t.Logf("accept error: %v", err)
				continue
			}
		}

		s.mu.Lock()
		s.conn = conn
		s.mu.Unlock()
		select {
		case s.accepted <- struct{}{}:
		default:
		}

		// Handle connection in a separate goroutine
		s.wg.Add(1)
		go s.handleConnection()
		return // Only handle one connection for tests
	}
}

// handleConnection handles OpenFlow messages from a client
func (s *mockOFServer) handleConnection() {
	defer s.wg.Done()

	// This handler owns the connection it was started for: after a
	// reconnect s.conn is the next handler's.
	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()

	headerBuf := make([]byte, HeaderSize)

	for {
		select {
		case <-s.done:
			return
		default:
		}

		if conn == nil {
			return
		}

		// Perform any injection a test has armed. The read deadline below
		// makes this loop wake regularly, so an injection armed after the
		// handshake is applied promptly.
		s.injectPending(conn)

		// Set read deadline
		_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

		// Read header
		n, err := io.ReadFull(conn, headerBuf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}
			if err == io.EOF {
				return
			}
			select {
			case <-s.done:
				return
			default:
				s.t.Logf("read error: %v", err)
				return
			}
		}

		if n < HeaderSize {
			continue
		}

		// Parse header
		var header Header
		if err := header.UnmarshalBinary(headerBuf); err != nil {
			s.t.Logf("failed to parse header: %v", err)
			continue
		}

		// Read body
		bodyLen := int(header.Length) - HeaderSize
		var body []byte
		if bodyLen > 0 {
			body = make([]byte, bodyLen)
			_ = conn.SetReadDeadline(time.Now().Add(time.Second))
			if _, err := io.ReadFull(conn, body); err != nil {
				s.t.Logf("failed to read body: %v", err)
				continue
			}
		}

		// Clear deadline
		_ = conn.SetReadDeadline(time.Time{})

		// Handle message
		s.handleMessage(&header, body)
	}
}

// handleMessage processes a received OpenFlow message
func (s *mockOFServer) handleMessage(header *Header, body []byte) {
	s.mu.Lock()
	conn := s.conn
	stallResponses := s.stallResponses
	s.mu.Unlock()

	if conn == nil {
		return
	}

	// A stalled peer never answers: the handler holds the message until the
	// server closes. That is the fixture a test arms to exercise a
	// client-side deadline, and unlike a fixed delay it cannot answer
	// before the deadline however slow the client is.
	if stallResponses {
		<-s.done
		return
	}

	switch header.Type {
	case OFPTHello:
		s.handleHello(header, body)

	case OFPTFeaturesRequest:
		s.handleFeaturesRequest(header)

	case OFPTEchoRequest:
		s.handleEchoRequest(header, body)

	case OFPTBarrierRequest:
		s.handleBarrierRequest(header)

	case OFPTFlowMod:
		s.handleFlowMod(header, body)

	case OFPTGroupMod:
		s.handleGroupMod(header, body)

	case OFPTMultipartRequest:
		s.handleMultipartRequest(header, body)

	case OFPTSetConfig:
		s.handleSetConfig(body)

	case OFPTGetConfigRequest:
		s.handleGetConfigRequest(header)

	case OFPTMeterMod:
		s.handleMeterMod(header, body)

	case OFPTPacketOut:
		s.mu.Lock()
		s.receivedPacketOuts = append(s.receivedPacketOuts, append([]byte(nil), body...))
		if s.packetOutErrType != 0 {
			s.sendErrorMessage(header.Xid, s.packetOutErrType, s.packetOutErrCode)
		}
		s.mu.Unlock()
		s.noteArrival()

	case OFPTEchoReply:
		// The client auto-replies to an echo request. Recording it is what
		// lets TestClient_HandleMessage_EchoRequestResponse assert the
		// auto-reply happened; before this it fell into the default branch
		// and the test asserted nothing at all.
		s.mu.Lock()
		s.receivedEchoReply++
		s.mu.Unlock()
		s.noteArrival()

	default:
		s.t.Logf("unhandled message type: %d", header.Type)
	}
}

// handleHello handles HELLO message
func (s *mockOFServer) handleHello(header *Header, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.respondWithError {
		s.sendErrorMessage(header.Xid, s.errorType, s.errorCode)
		return
	}

	if !s.sendHelloReply {
		return
	}

	if s.sendWrongHelloType {
		// Send wrong message type
		reply := &Header{
			Version: DefaultVersion,
			Type:    OFPTEchoRequest, // Wrong type
			Length:  HeaderSize,
			Xid:     header.Xid,
		}
		data, _ := reply.MarshalBinary()
		_, _ = s.conn.Write(data)
		return
	}

	if s.closeAfterHandshake {
		// Close after sending hello
		defer func() {
			if s.conn != nil {
				_ = s.conn.Close()
			}
		}()
	}

	version := uint8(DefaultVersion)
	if s.invalidVersionInHello {
		version = uint8(OFP10) // Wrong version
	}

	reply := &Header{
		Version: version,
		Type:    OFPTHello,
		Length:  HeaderSize,
		Xid:     header.Xid,
	}

	data, err := reply.MarshalBinary()
	if err != nil {
		s.t.Errorf("failed to marshal hello reply: %v", err)
		return
	}

	if _, err := s.conn.Write(data); err != nil {
		s.t.Logf("failed to send hello reply: %v", err)
	}
}

// handleFeaturesRequest handles FEATURES_REQUEST
func (s *mockOFServer) handleFeaturesRequest(header *Header) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.respondWithError {
		s.sendErrorMessage(header.Xid, s.errorType, s.errorCode)
		return
	}

	if !s.sendFeaturesReply {
		return
	}

	if s.sendWrongFeaturesType {
		// Answer with another reply type on the request's xid. Not an echo
		// request: the client answers those itself and never hands them to
		// the waiting request, so the handshake would only time out.
		reply := &Header{
			Version: DefaultVersion,
			Type:    OFPTBarrierReply, // Wrong type
			Length:  HeaderSize,
			Xid:     header.Xid,
		}
		data, _ := reply.MarshalBinary()
		_, _ = s.conn.Write(data)
		return
	}

	// Build features reply
	data := make([]byte, 32)

	// Header
	data[0] = DefaultVersion
	data[1] = OFPTFeaturesReply
	binary.BigEndian.PutUint16(data[2:4], 32) // Length
	binary.BigEndian.PutUint32(data[4:8], header.Xid)

	// Body
	binary.BigEndian.PutUint64(data[8:16], s.datapathID)
	binary.BigEndian.PutUint32(data[16:20], s.nBuffers)
	data[20] = s.nTables
	data[21] = 0 // AuxiliaryID
	// 2 bytes padding
	binary.BigEndian.PutUint32(data[24:28], s.capabilities)
	binary.BigEndian.PutUint32(data[28:32], 0) // Reserved

	if _, err := s.conn.Write(data); err != nil {
		s.t.Logf("failed to send features reply: %v", err)
	}
}

// handleEchoRequest handles ECHO_REQUEST
func (s *mockOFServer) handleEchoRequest(header *Header, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.sendEchoReply {
		return
	}

	reply := NewEchoReply(header.Xid, body)
	data, err := reply.MarshalBinary()
	if err != nil {
		s.t.Errorf("failed to marshal echo reply: %v", err)
		return
	}

	if _, err := s.conn.Write(data); err != nil {
		s.t.Logf("failed to send echo reply: %v", err)
	}
}

// handleBarrierRequest handles BARRIER_REQUEST
func (s *mockOFServer) handleBarrierRequest(header *Header) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.receivedBarriers++

	if s.respondWithError {
		s.sendErrorMessage(header.Xid, s.errorType, s.errorCode)
		return
	}

	if !s.sendBarrierReply {
		return
	}

	reply := &Header{
		Version: DefaultVersion,
		Type:    OFPTBarrierReply,
		Length:  HeaderSize,
		Xid:     header.Xid,
	}

	data, err := reply.MarshalBinary()
	if err != nil {
		s.t.Errorf("failed to marshal barrier reply: %v", err)
		return
	}

	if _, err := s.conn.Write(data); err != nil {
		s.t.Logf("failed to send barrier reply: %v", err)
	}
}

// handleFlowMod handles FLOW_MOD messages
func (s *mockOFServer) handleFlowMod(header *Header, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Parse flow mod for verification (simplified parsing)
	if len(body) < 40 {
		s.t.Logf("flow mod body too short")
		return
	}

	flowMod := FlowMod{
		Header: *header,
	}

	// Parse the fixed body fields: Cookie[0:8], CookieMask[8:16],
	// TableID=16, Command=17, IdleTimeout[18:20], HardTimeout[20:22],
	// Priority[22:24]
	flowMod.Cookie = binary.BigEndian.Uint64(body[0:8])
	flowMod.CookieMask = binary.BigEndian.Uint64(body[8:16])
	flowMod.TableID = body[16]
	flowMod.Command = body[17]
	flowMod.Priority = binary.BigEndian.Uint16(body[22:24])

	s.receivedFlowMods = append(s.receivedFlowMods, flowMod)
	defer s.noteArrival()

	// Inject an error for specific flow mod indexes (batch failure testing)
	if _, ok := s.failFlowModIndexes[len(s.receivedFlowMods)-1]; ok {
		s.sendErrorMessage(header.Xid, s.errorType, s.errorCode)
		return
	}

	if s.sendErrorOnFlowMod {
		s.sendErrorMessage(header.Xid, s.errorType, s.errorCode)
		return
	}

	if s.respondWithError {
		s.sendErrorMessage(header.Xid, s.errorType, s.errorCode)
	}
}

// handleGroupMod handles GROUP_MOD messages
func (s *mockOFServer) handleGroupMod(header *Header, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if len(body) < 8 {
		s.t.Logf("group mod body too short")
		return
	}

	groupMod := GroupMod{
		Header:  *header,
		Command: binary.BigEndian.Uint16(body[0:2]),
		Type:    body[2],
		GroupID: binary.BigEndian.Uint32(body[4:8]),
	}
	s.receivedGroupMods = append(s.receivedGroupMods, groupMod)

	if s.sendErrorOnGroupMod {
		s.sendErrorMessage(header.Xid, s.errorType, s.errorCode)
	}
}

// handleMultipartRequest handles MULTIPART_REQUEST messages
func (s *mockOFServer) handleMultipartRequest(header *Header, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.respondWithError {
		s.sendErrorMessage(header.Xid, s.errorType, s.errorCode)
		return
	}

	if !s.sendMultipartReply {
		return
	}

	if s.sendShortMultipartReply {
		// Send a response that's too short
		data := make([]byte, 10)
		data[0] = DefaultVersion
		data[1] = OFPTMultipartReply
		binary.BigEndian.PutUint16(data[2:4], 10)
		binary.BigEndian.PutUint32(data[4:8], header.Xid)
		_, _ = s.conn.Write(data)
		return
	}

	// Parse request type
	if len(body) < 8 {
		s.t.Logf("multipart request body too short")
		return
	}

	reqType := binary.BigEndian.Uint16(body[0:2])

	if reqType == OFPMPFlow {
		s.sendFlowStatsReply(header)
	}

	if reqType == OFPMPGroupDesc {
		s.sendGroupDescReply(header)
	}

	if reqType == OFPMPMeter && len(body) >= 12 {
		s.sendMeterStatsReply(header, binary.BigEndian.Uint32(body[8:12]))
	}
}

// handleSetConfig stores miss_send_len unless the switch is set to ignore it.
func (s *mockOFServer) handleSetConfig(body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(body) < 4 || s.ignoreSetConfig {
		return
	}
	s.configFlags = binary.BigEndian.Uint16(body[0:2])
	s.setConfigs = append(s.setConfigs, s.configFlags)
	s.missSendLen = binary.BigEndian.Uint16(body[2:4])
}

// handleGetConfigRequest reports the stored switch config.
func (s *mockOFServer) handleGetConfigRequest(header *Header) {
	s.mu.Lock()
	defer s.mu.Unlock()
	reply := &SwitchConfig{
		Header:      Header{Version: DefaultVersion, Type: OFPTGetConfigReply, Xid: header.Xid},
		Flags:       s.configFlags,
		MissSendLen: s.missSendLen,
	}
	data, err := reply.MarshalBinary()
	if err != nil {
		s.t.Errorf("failed to marshal get config reply: %v", err)
		return
	}
	_, _ = s.conn.Write(data)
}

// handleMeterMod applies a meter mod with Open vSwitch's error semantics:
// ADD of an existing meter is METER_EXISTS, MODIFY or DELETE of a missing
// one is UNKNOWN_METER, and a datapath without meters refuses ADD and
// MODIFY with INVALID_METER.
func (s *mockOFServer) handleMeterMod(header *Header, body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	defer s.noteArrival()
	if len(body) < 8 {
		s.t.Logf("meter mod body too short")
		return
	}
	mod := MeterMod{
		Header:  *header,
		Command: binary.BigEndian.Uint16(body[0:2]),
		Flags:   binary.BigEndian.Uint16(body[2:4]),
		MeterID: binary.BigEndian.Uint32(body[4:8]),
	}
	for band := body[8:]; len(band) >= 16; band = band[16:] {
		mod.Bands = append(mod.Bands, NewMeterBandDrop(binary.BigEndian.Uint32(band[4:8]), binary.BigEndian.Uint32(band[8:12])))
	}
	s.meterMods = append(s.meterMods, mod)

	_, exists := s.meters[mod.MeterID]
	switch {
	case s.metersUnsupported && mod.Command != OFPMCDelete:
		s.sendErrorMessage(header.Xid, OFPETMeterModFailed, OFPMMFCInvalidMeter)
	case mod.Command == OFPMCAdd && exists:
		s.sendErrorMessage(header.Xid, OFPETMeterModFailed, OFPMMFCMeterExists)
	case mod.Command != OFPMCAdd && !exists:
		s.sendErrorMessage(header.Xid, OFPETMeterModFailed, OFPMMFCUnknownMeter)
	case mod.Command == OFPMCDelete:
		delete(s.meters, mod.MeterID)
	default:
		s.meters[mod.MeterID] = mod
	}
}

// sendMeterStatsReply answers an OFPMP_METER request with the configured
// statistics of the requested meter, or an empty reply.
func (s *mockOFServer) sendMeterStatsReply(header *Header, meterID uint32) {
	var body []byte
	if stats, ok := s.meterStats[meterID]; ok {
		entry := make([]byte, 40+16*len(stats.Bands))
		binary.BigEndian.PutUint32(entry[0:4], stats.MeterID)
		binary.BigEndian.PutUint16(entry[4:6], uint16(len(entry)))
		binary.BigEndian.PutUint32(entry[12:16], stats.FlowCount)
		binary.BigEndian.PutUint64(entry[16:24], stats.PacketInCount)
		binary.BigEndian.PutUint64(entry[24:32], stats.ByteInCount)
		for i, band := range stats.Bands {
			binary.BigEndian.PutUint64(entry[40+16*i:48+16*i], band.PacketCount)
			binary.BigEndian.PutUint64(entry[48+16*i:56+16*i], band.ByteCount)
		}
		body = entry
	}
	data := make([]byte, 16+len(body))
	data[0] = DefaultVersion
	data[1] = OFPTMultipartReply
	binary.BigEndian.PutUint16(data[2:4], uint16(len(data)))
	binary.BigEndian.PutUint32(data[4:8], header.Xid)
	binary.BigEndian.PutUint16(data[8:10], OFPMPMeter)
	copy(data[16:], body)
	_, _ = s.conn.Write(data)
}

// sendPacketIn writes an OFPT_PACKET_IN carrying body to the client.
func (s *mockOFServer) sendPacketIn(body []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	data := make([]byte, HeaderSize+len(body))
	data[0] = DefaultVersion
	data[1] = OFPTPacketIn
	binary.BigEndian.PutUint16(data[2:4], uint16(len(data)))
	copy(data[HeaderSize:], body)
	if _, err := s.conn.Write(data); err != nil {
		s.t.Logf("failed to send packet-in: %v", err)
	}
}

func (s *mockOFServer) getMeterMods() []MeterMod {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]MeterMod(nil), s.meterMods...)
}

func (s *mockOFServer) getMissSendLen() uint16 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.missSendLen
}

// failPacketOuts makes the switch reject every packet-out with an error.
func (s *mockOFServer) failPacketOuts(errType, errCode uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.packetOutErrType = errType
	s.packetOutErrCode = errCode
}

// setFragFlags presets the fragment policy a bridge is configured with.
func (s *mockOFServer) setFragFlags(flags uint16) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.configFlags = flags
}

// getSetConfigs returns the flags of every SET_CONFIG received.
func (s *mockOFServer) getSetConfigs() []uint16 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]uint16(nil), s.setConfigs...)
}

// dropConnection closes the current connection the way a restarting switch
// does, and accepts the next one, so the client can reconnect.
func (s *mockOFServer) dropConnection() {
	s.mu.Lock()
	conn := s.conn
	s.mu.Unlock()
	if conn != nil {
		_ = conn.Close()
	}
	s.wg.Add(1)
	go s.acceptConnections()
}

// awaitAccept waits until the server has accepted another connection.
func (s *mockOFServer) awaitAccept(t *testing.T) {
	t.Helper()
	select {
	case <-s.accepted:
	case <-time.After(5 * time.Second):
		t.Fatal("the server accepted no connection")
	}
}

func (s *mockOFServer) getReceivedPacketOuts() [][]byte {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([][]byte(nil), s.receivedPacketOuts...)
}

// sendGroupDescReply sends a multipart group description reply
func (s *mockOFServer) sendGroupDescReply(header *Header) {
	descData := make([]byte, 0)
	for i := range s.groupDescs {
		desc := &s.groupDescs[i]

		bucketsData := make([]byte, 0)
		for j := range desc.Buckets {
			bucketData, err := desc.Buckets[j].MarshalBinary()
			if err != nil {
				s.t.Errorf("failed to marshal bucket: %v", err)
				return
			}
			bucketsData = append(bucketsData, bucketData...)
		}

		entry := make([]byte, 8)
		binary.BigEndian.PutUint16(entry[0:2], uint16(8+len(bucketsData)))
		entry[2] = desc.Type
		binary.BigEndian.PutUint32(entry[4:8], desc.GroupID)
		descData = append(descData, entry...)
		descData = append(descData, bucketsData...)
	}

	replyLen := uint16(16 + len(descData))
	data := make([]byte, replyLen)

	// Header
	data[0] = DefaultVersion
	data[1] = OFPTMultipartReply
	binary.BigEndian.PutUint16(data[2:4], replyLen)
	binary.BigEndian.PutUint32(data[4:8], header.Xid)

	// Multipart header
	binary.BigEndian.PutUint16(data[8:10], OFPMPGroupDesc)
	binary.BigEndian.PutUint16(data[10:12], 0)
	// 4 bytes padding

	copy(data[16:], descData)

	if _, err := s.conn.Write(data); err != nil {
		s.t.Logf("failed to send group desc reply: %v", err)
	}
}

// sendFlowStatsReply sends a multipart flow stats reply
func (s *mockOFServer) sendFlowStatsReply(header *Header) {
	// Build flow stats reply body
	statsData := make([]byte, 0)
	for _, stat := range s.flowStats {
		// Simplified: just create minimal flow stat entry
		entry := make([]byte, 48)
		binary.BigEndian.PutUint16(entry[0:2], 48) // Length
		entry[2] = stat.TableID
		binary.BigEndian.PutUint32(entry[4:8], stat.DurationSec)
		binary.BigEndian.PutUint32(entry[8:12], stat.DurationNsec)
		binary.BigEndian.PutUint16(entry[12:14], stat.Priority)
		binary.BigEndian.PutUint64(entry[24:32], stat.Cookie)
		binary.BigEndian.PutUint64(entry[32:40], stat.PacketCount)
		binary.BigEndian.PutUint64(entry[40:48], stat.ByteCount)
		statsData = append(statsData, entry...)
	}

	// Build multipart reply
	replyLen := uint16(16 + len(statsData))
	data := make([]byte, replyLen)

	// Header
	data[0] = DefaultVersion
	data[1] = OFPTMultipartReply
	binary.BigEndian.PutUint16(data[2:4], replyLen)
	binary.BigEndian.PutUint32(data[4:8], header.Xid)

	// Multipart header
	binary.BigEndian.PutUint16(data[8:10], OFPMPFlow) // Type
	binary.BigEndian.PutUint16(data[10:12], 0)        // Flags (no more)
	// 4 bytes padding

	// Stats data
	copy(data[16:], statsData)

	if _, err := s.conn.Write(data); err != nil {
		s.t.Logf("failed to send multipart reply: %v", err)
	}
}

// sendErrorMessage sends an OpenFlow error message
func (s *mockOFServer) sendErrorMessage(xid uint32, errType, errCode uint16) {
	data := make([]byte, 12)

	// Header
	data[0] = DefaultVersion
	data[1] = OFPTError
	binary.BigEndian.PutUint16(data[2:4], 12) // Length
	binary.BigEndian.PutUint32(data[4:8], xid)

	// Error
	binary.BigEndian.PutUint16(data[8:10], errType)
	binary.BigEndian.PutUint16(data[10:12], errCode)

	if _, err := s.conn.Write(data); err != nil {
		s.t.Logf("failed to send error message: %v", err)
	}
}

// close shuts down the mock server
func (s *mockOFServer) close() {
	if !s.closed.CompareAndSwap(false, true) {
		return // Already closed
	}

	close(s.done)

	s.mu.Lock()
	if s.conn != nil {
		_ = s.conn.Close()
	}
	s.mu.Unlock()

	if s.listener != nil {
		_ = s.listener.Close()
	}

	s.wg.Wait()
}

// getReceivedFlowMods returns the received flow mods
// injectPending applies whichever fault or stimulus a test has armed, once
// each, then clears the flag.
//
// These four flags were declared and set by tests and READ BY NOTHING. Each
// test set one, slept, and asserted nothing, so the client paths they name —
// the echo auto-reply, the reader's short- and malformed-header handling, and
// unknown-xid dispatch — were never exercised at all. Wiring them is what makes
// those tests real; removing their sleeps alone would only have made four inert
// tests faster (#262).
func (s *mockOFServer) injectPending(conn net.Conn) {
	s.mu.Lock()
	echo := s.sendEchoRequest
	short := s.sendIncompleteHeader
	malformed := s.sendMalformedHeader
	unknownXid := s.sendUnknownXid
	s.sendEchoRequest, s.sendIncompleteHeader = false, false
	s.sendMalformedHeader, s.sendUnknownXid = false, false
	s.mu.Unlock()

	if echo || short || malformed || unknownXid {
		defer func() {
			s.mu.Lock()
			s.injected++
			s.mu.Unlock()
			s.noteArrival()
		}()
	}

	switch {
	case echo:
		// A well-formed echo request; the client must auto-reply.
		req := NewEchoRequest(0xE0E0E0E0, []byte("ping"))
		if data, err := req.MarshalBinary(); err == nil {
			_, _ = conn.Write(data)
		}
	case short:
		// A partial header followed by a close. The close is the point: on a
		// byte stream a partial header on a LIVE connection just means more
		// is coming, and blocking for the rest is correct — so injecting
		// three bytes and holding the connection open tests nothing and
		// wedges the reader by design. A truncated header in the field is a
		// peer that died mid-write, which is this.
		_, _ = conn.Write([]byte{DefaultVersion, OFPTEchoRequest, 0x00})
		_ = conn.Close()
	case malformed:
		// A header whose declared length is shorter than a header can be.
		_, _ = conn.Write([]byte{DefaultVersion, OFPTEchoReply, 0x00, 0x02, 0x00, 0x00, 0x00, 0x01})
	case unknownXid:
		// A reply nobody is waiting on: dispatch must drop it rather than
		// block or misroute it to another caller's channel.
		reply := NewEchoReply(0xDEADBEEF, nil)
		if data, err := reply.MarshalBinary(); err == nil {
			_, _ = conn.Write(data)
		}
	}
}

// noteArrival records that a message was received. It runs on the mock's read
// loop, so it must never block.
func (s *mockOFServer) noteArrival() {
	select {
	case s.arrivals <- struct{}{}:
	default: // a wakeup is already pending and unconsumed; one is enough
	}
}

// ofDeadline bounds how long a test waits for a message that must eventually
// arrive. It is a liveness backstop, not a timing assumption: these tests
// advance on the arrival itself, so a loaded host only makes them slower.
const ofDeadline = 10 * time.Second

// awaitArrivals blocks until cond reports true, waking on each recorded
// message. what names the failure so a timeout says which message never came.
func (s *mockOFServer) awaitArrivals(t *testing.T, what string, cond func() bool) {
	t.Helper()

	deadline := time.After(ofDeadline)
	for {
		if cond() {
			return
		}
		select {
		case <-s.arrivals:
		case <-deadline:
			t.Fatalf("%s within %s", what, ofDeadline)
		}
	}
}

// awaitFlowMods blocks until at least n flow mods have been recorded.
func (s *mockOFServer) awaitFlowMods(t *testing.T, n int) {
	t.Helper()
	s.awaitArrivals(t, fmt.Sprintf("server received %d of %d flow mods", len(s.getReceivedFlowMods()), n),
		func() bool { return len(s.getReceivedFlowMods()) >= n })
}

// getInjected returns how many faults the mock has written to the wire.
func (s *mockOFServer) getInjected() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.injected
}

// awaitInjected blocks until the mock has delivered a fault, so a survival
// assertion cannot pass because nothing was ever sent.
func (s *mockOFServer) awaitInjected(t *testing.T) {
	t.Helper()
	s.awaitArrivals(t, "the mock never delivered the armed fault",
		func() bool { return s.getInjected() > 0 })
}

// getReceivedEchoReplies returns how many echo replies the client sent.
func (s *mockOFServer) getReceivedEchoReplies() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.receivedEchoReply
}

func (s *mockOFServer) getReceivedFlowMods() []FlowMod {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]FlowMod(nil), s.receivedFlowMods...)
}

// getReceivedBarriers returns the number of received barriers
func (s *mockOFServer) getReceivedBarriers() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.receivedBarriers
}

// setFlowStats sets the flow stats to return in multipart replies
func (s *mockOFServer) setFlowStats(stats []FlowStats) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.flowStats = stats
}

// setGroupDescs sets the group descriptions to return in multipart replies
func (s *mockOFServer) setGroupDescs(descs []GroupDesc) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.groupDescs = descs
}

// failFlowModAt injects an OpenFlow error for the given 0-based indexes of
// received flow mods
func (s *mockOFServer) failFlowModAt(errType, errCode uint16, indexes ...int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.errorType = errType
	s.errorCode = errCode
	for _, idx := range indexes {
		s.failFlowModIndexes[idx] = struct{}{}
	}
}

// getReceivedGroupMods returns the received group mods
func (s *mockOFServer) getReceivedGroupMods() []GroupMod {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]GroupMod(nil), s.receivedGroupMods...)
}
