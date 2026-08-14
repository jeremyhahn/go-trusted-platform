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
	delayResponse           time.Duration
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
}

// newMockOFServer creates a new mock OpenFlow server
// Returns the server and socket path for client connection
func newMockOFServer(t *testing.T) (*mockOFServer, string) {
	t.Helper()

	// Use t.TempDir() for Unix socket
	socketDir := t.TempDir()
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
		flowStats:          make([]FlowStats, 0),
		failFlowModIndexes: make(map[int]struct{}),
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

		// Handle connection in a separate goroutine
		s.wg.Add(1)
		go s.handleConnection()
		return // Only handle one connection for tests
	}
}

// handleConnection handles OpenFlow messages from a client
func (s *mockOFServer) handleConnection() {
	defer s.wg.Done()
	defer func() {
		s.mu.Lock()
		if s.conn != nil {
			_ = s.conn.Close()
		}
		s.mu.Unlock()
	}()

	headerBuf := make([]byte, HeaderSize)

	for {
		select {
		case <-s.done:
			return
		default:
		}

		s.mu.Lock()
		conn := s.conn
		s.mu.Unlock()

		if conn == nil {
			return
		}

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
	delayResponse := s.delayResponse
	s.mu.Unlock()

	if conn == nil {
		return
	}

	// Apply response delay if configured
	if delayResponse > 0 {
		time.Sleep(delayResponse)
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
