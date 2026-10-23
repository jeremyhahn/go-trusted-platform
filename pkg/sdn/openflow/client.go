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
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"time"
)

// DefaultTimeout is the default operation timeout
const DefaultTimeout = 30 * time.Second

// Client represents an OpenFlow client connection to an OVS bridge
type Client struct {
	bridgeName string
	socketDir  string
	connected  atomic.Bool

	// session is the current connection. Connect replaces it only once the
	// previous connection's reader has exited, under connMu, which
	// serialises Connect and Disconnect.
	session    atomic.Pointer[session]
	generation atomic.Uint64
	connMu     sync.Mutex

	// Datapath info from FeaturesReply
	datapathID uint64
	nBuffers   uint32
	nTables    uint8

	// Negotiated version
	negotiatedVersion uint8

	// Transaction ID counter
	xid atomic.Uint32

	// Request tracking
	pending   map[uint32]pendingRequest
	pendingMu sync.Mutex

	// Batch flow mod tracking (xid of each batch member)
	batches map[uint32]*batchMember
	batchMu sync.Mutex

	// Asynchronous packet-in subscribers. Each subscriber owns its bounded
	// queue; a full queue drops the packet rather than blocking the reader.
	packetInMu     sync.RWMutex
	packetInSinks  map[uint64]*PacketInSubscription
	packetInNextID atomic.Uint64

	// wg tracks the reader of the current connection.
	wg sync.WaitGroup

	// Configuration
	timeout time.Duration
}

// response represents a response message
type response struct {
	header Header
	data   []byte
	err    error
}

// session is one connection to the switch and the state that lives and dies
// with it. Its reader owns it: a reader only ever reads, answers and closes
// its own connection, so a connection that died cannot touch the next one.
type session struct {
	conn       net.Conn
	generation uint64
	done       chan struct{}
	stopOnce   sync.Once
	helloCh    chan *response
	helloOnce  sync.Once
}

// newSession wraps a freshly dialled connection.
func newSession(conn net.Conn, generation uint64) *session {
	return &session{
		conn:       conn,
		generation: generation,
		done:       make(chan struct{}),
		helloCh:    make(chan *response, 1),
	}
}

// stop ends the session: its reader exits and its connection closes.
func (s *session) stop() {
	s.stopOnce.Do(func() {
		close(s.done)
		_ = s.conn.Close()
	})
}

// pendingRequest is a caller waiting for a reply, tagged with the
// generation of the connection the request went out on.
type pendingRequest struct {
	ch         chan *response
	generation uint64
}

// flowBatch collects switch-reported errors for a batch of flow mods
// submitted via SendFlowMods.
type flowBatch struct {
	mu     sync.Mutex
	failed []BatchFlowError
}

// addFailure records a switch-reported error for a batch member
func (b *flowBatch) addFailure(fail BatchFlowError) {
	b.mu.Lock()
	b.failed = append(b.failed, fail)
	b.mu.Unlock()
}

// failures returns a copy of the recorded failures
func (b *flowBatch) failures() []BatchFlowError {
	b.mu.Lock()
	defer b.mu.Unlock()
	return append([]BatchFlowError(nil), b.failed...)
}

// batchMember associates a batch-tracked transaction ID with the flow index
// it belongs to within the batch.
type batchMember struct {
	batch *flowBatch
	index int
}

// ClientOption configures the Client
type ClientOption func(*Client)

// WithSocketDir sets the OVS socket directory
func WithSocketDir(dir string) ClientOption {
	return func(c *Client) {
		c.socketDir = dir
	}
}

// WithTimeout sets the operation timeout
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) {
		c.timeout = timeout
	}
}

// NewClient creates a new OpenFlow client for a bridge
func NewClient(bridgeName string, opts ...ClientOption) (*Client, error) {
	if bridgeName == "" {
		return nil, ErrInvalidBridgeName
	}

	c := &Client{
		bridgeName:    bridgeName,
		socketDir:     "/var/run/openvswitch",
		pending:       make(map[uint32]pendingRequest),
		batches:       make(map[uint32]*batchMember),
		packetInSinks: make(map[uint64]*PacketInSubscription),
		timeout:       DefaultTimeout,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c, nil
}

// Connect establishes a connection to the OVS bridge's OpenFlow socket
func (c *Client) Connect(ctx context.Context) error {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	if c.connected.Load() {
		return nil
	}

	socketPath := filepath.Join(c.socketDir, c.bridgeName+".mgmt")

	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrConnectionFailed, Cause: err}
	}

	// The reader of a connection the switch closed may still be failing
	// that connection's requests; the new connection starts once it is gone.
	c.wg.Wait()

	s := newSession(conn, c.generation.Add(1))
	c.session.Store(s)
	c.connected.Store(true)

	c.wg.Add(1)
	go c.reader(s)

	if err := c.handshake(ctx, s); err != nil {
		c.disconnect()
		return err
	}

	return nil
}

// Disconnect closes the connection
func (c *Client) Disconnect() error {
	c.connMu.Lock()
	defer c.connMu.Unlock()
	c.disconnect()
	return nil
}

// disconnect stops the current connection, waits for its reader to exit
// and fails its waiting requests. Caller holds connMu.
func (c *Client) disconnect() {
	c.connected.Store(false)
	s := c.session.Load()
	if s == nil {
		return
	}
	s.stop()
	c.wg.Wait()
	c.failPending(s.generation)
}

// connectionLost records that the switch closed the connection under its
// reader: the client stops reporting connected, so a later Connect redials
// rather than returning early, and every request waiting on that connection
// fails at once instead of running out its timeout. Only the reader of s
// calls it, and Connect starts no new connection until that reader is gone.
func (c *Client) connectionLost(s *session) {
	c.connected.Store(false)
	s.stop()
	c.failPending(s.generation)
}

// failPending wakes every request waiting on the connection of this
// generation with a closed channel, which sendAndWait reports as
// ErrConnectionClosed.
func (c *Client) failPending(generation uint64) {
	c.pendingMu.Lock()
	defer c.pendingMu.Unlock()
	for xid, request := range c.pending {
		if request.generation == generation {
			close(request.ch)
			delete(c.pending, xid)
		}
	}
}

// addPending registers a request waiting for the reply to xid on the
// connection of this generation.
func (c *Client) addPending(xid uint32, generation uint64) chan *response {
	respCh := make(chan *response, 1)
	c.pendingMu.Lock()
	c.pending[xid] = pendingRequest{ch: respCh, generation: generation}
	c.pendingMu.Unlock()
	return respCh
}

// write sends data on the current connection.
func (c *Client) write(data []byte) (int, error) {
	s := c.session.Load()
	if s == nil {
		return 0, ErrNotConnected
	}
	return s.conn.Write(data)
}

// Close is an alias for Disconnect
func (c *Client) Close() error {
	return c.Disconnect()
}

// IsConnected returns whether the client is connected
func (c *Client) IsConnected() bool {
	return c.connected.Load()
}

// DatapathID returns the datapath ID
func (c *Client) DatapathID() uint64 {
	return c.datapathID
}

// nextXid generates the next transaction ID
func (c *Client) nextXid() uint32 {
	return c.xid.Add(1)
}

// handshake performs the OpenFlow handshake
// OpenFlow HELLO exchange is different from other message types:
// - Both sides send HELLO independently as soon as connection is established
// - Both sides read their peer's HELLO
// - The negotiated version is the minimum of the two versions
func (c *Client) handshake(ctx context.Context, s *session) error {
	// Send our Hello first
	xid := c.nextXid()
	hello := NewHello(xid)
	helloData, err := hello.MarshalBinary()
	if err != nil {
		return err
	}
	if _, err := s.conn.Write(helloData); err != nil {
		return &WrappedError{Msg: "failed to send hello", Err: err}
	}

	// Wait for peer's Hello on the dedicated HELLO channel
	// Note: HELLO is NOT a request/response - peer sends its own HELLO with its own XID
	select {
	case <-ctx.Done():
		return ctx.Err()
	case resp := <-s.helloCh:
		if resp == nil {
			return ErrConnectionClosed
		}
		if resp.err != nil {
			return resp.err
		}
		if resp.header.Type != OFPTHello {
			return &SentinelCauseError{Sentinel: ErrVersionMismatch, Cause: &MessageError{Msg: fmt.Sprintf("expected HELLO, got type %d", resp.header.Type)}}
		}

		// Negotiate version: use the minimum of both sides
		peerVersion := resp.header.Version
		if peerVersion < DefaultVersion {
			// Peer only supports older version
			return &SentinelCauseError{Sentinel: ErrVersionMismatch, Cause: &MessageError{Msg: fmt.Sprintf("peer version %d is lower than our minimum %d", peerVersion, DefaultVersion)}}
		}
		// Use our version (DefaultVersion) since peer supports >= DefaultVersion
		c.negotiatedVersion = DefaultVersion
	case <-time.After(c.timeout):
		return ErrTimeout
	}

	// Send Features Request (this IS a request/response exchange by XID)
	xid = c.nextXid()
	featReq := NewFeaturesRequest(xid)
	featReqData, err := featReq.MarshalBinary()
	if err != nil {
		return err
	}

	respCh := c.addPending(xid, s.generation)

	if _, err := s.conn.Write(featReqData); err != nil {
		return &WrappedError{Msg: "failed to send features request", Err: err}
	}

	// Wait for Features Reply
	select {
	case <-ctx.Done():
		return ctx.Err()
	case resp := <-respCh:
		if resp == nil {
			return ErrConnectionClosed
		}
		if resp.err != nil {
			return resp.err
		}
		if resp.header.Type != OFPTFeaturesReply {
			return ErrNoFeatures
		}

		var featReply FeaturesReply
		if err := featReply.UnmarshalBinary(resp.data); err != nil {
			return err
		}

		c.datapathID = featReply.DatapathID
		c.nBuffers = featReply.NBuffers
		c.nTables = featReply.NTables
	case <-time.After(c.timeout):
		return ErrTimeout
	}

	return c.enablePacketIn(ctx)
}

// enablePacketIn asks the switch to send packet-ins on this connection.
// Open vSwitch serves bridge.mgmt as a service connection whose
// miss_send_len starts at 0, and it sends a service connection no
// asynchronous message, packet-ins included, until that is raised. The
// GET_CONFIG round trip confirms the switch applied it.
func (c *Client) enablePacketIn(ctx context.Context) error {
	// SET_CONFIG replaces the switch-wide fragment policy too, so read it
	// first and send it back unchanged: only miss_send_len is ours to set.
	current, err := c.getConfig(ctx)
	if err != nil {
		return err
	}
	set := NewSetConfig(c.nextXid(), current.Flags, OFPCMLNoBuffer)
	setData, err := set.MarshalBinary()
	if err != nil {
		return err
	}
	if _, err := c.write(setData); err != nil {
		return &WrappedError{Msg: "failed to send set config", Err: err}
	}

	config, err := c.getConfig(ctx)
	if err != nil {
		return err
	}
	if config.MissSendLen == 0 {
		return &ErrPacketInDisabled{MissSendLen: config.MissSendLen}
	}
	return nil
}

// getConfig reads the switch configuration. The reply to a request sent
// after a SET_CONFIG reflects it, because the switch handles messages in order.
func (c *Client) getConfig(ctx context.Context) (*SwitchConfig, error) {
	xid := c.nextXid()
	getData, err := NewGetConfigRequest(xid).MarshalBinary()
	if err != nil {
		return nil, err
	}
	resp, err := c.sendAndWait(ctx, xid, getData, OFPTGetConfigReply)
	if err != nil {
		return nil, err
	}
	if resp.header.Type != OFPTGetConfigReply {
		return nil, ErrInvalidMessage
	}
	var config SwitchConfig
	if err := config.UnmarshalBinary(resp.data); err != nil {
		return nil, err
	}
	return &config, nil
}

// reader reads the messages of one connection until the switch closes it or
// the session stops.
func (c *Client) reader(s *session) {
	defer c.wg.Done()

	headerBuf := make([]byte, HeaderSize)

	for {
		select {
		case <-s.done:
			return
		default:
		}

		_ = s.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))

		// Read header
		n, err := io.ReadFull(s.conn, headerBuf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}

			select {
			case <-s.done:
				return
			default:
			}

			// The switch closed the socket or it failed for good: nothing
			// more will be read, so the client is no longer connected.
			c.connectionLost(s)
			return
		}

		if n < HeaderSize {
			continue
		}

		// Parse header
		var header Header
		if err := header.UnmarshalBinary(headerBuf); err != nil {
			continue
		}

		// Read body
		bodyLen := int(header.Length) - HeaderSize
		var body []byte
		if bodyLen > 0 {
			body = make([]byte, bodyLen)
			_ = s.conn.SetReadDeadline(time.Now().Add(c.timeout))
			if _, err := io.ReadFull(s.conn, body); err != nil {
				continue
			}
		}

		// Clear deadline
		_ = s.conn.SetReadDeadline(time.Time{})

		// Handle message
		c.handleMessage(s, &header, body)
	}
}

// handleMessage processes a message received on the connection of s
func (c *Client) handleMessage(s *session, header *Header, body []byte) {
	// Combine header and body for full message
	fullData := make([]byte, int(header.Length))
	headerData, _ := header.MarshalBinary()
	copy(fullData, headerData)
	if len(body) > 0 {
		copy(fullData[HeaderSize:], body)
	}

	// Handle asynchronous messages
	switch header.Type {
	case OFPTHello:
		// HELLO messages are handled specially during handshake
		// They have their own XID and are not request/response pairs
		s.helloOnce.Do(func() {
			select {
			case s.helloCh <- &response{header: *header, data: fullData}:
			default:
			}
		})
		return

	case OFPTEchoRequest:
		// Auto-reply to echo requests
		reply := NewEchoReply(header.Xid, body)
		data, err := reply.MarshalBinary()
		if err == nil {
			_, _ = s.conn.Write(data)
		}
		return

	case OFPTPacketIn:
		packet, err := ParsePacketIn(body)
		if err == nil {
			c.dispatchPacketIn(packet)
		}
		return

	case OFPTError:
		// Parse error and dispatch
		if len(body) >= 4 {
			errType := ByteOrder.Uint16(body[0:2])
			errCode := ByteOrder.Uint16(body[2:4])
			ofErr := &OFError{Type: errType, Code: errCode}
			if len(body) > 4 {
				ofErr.Data = body[4:]
			}

			// Route errors for batch-tracked flow mods to their batch collector
			c.batchMu.Lock()
			if member, ok := c.batches[header.Xid]; ok {
				delete(c.batches, header.Xid)
				c.batchMu.Unlock()
				member.batch.addFailure(BatchFlowError{Index: member.index, Xid: header.Xid, Err: ofErr})
				return
			}
			c.batchMu.Unlock()

			c.pendingMu.Lock()
			if request, ok := c.pending[header.Xid]; ok {
				request.ch <- &response{header: *header, data: fullData, err: ofErr}
				delete(c.pending, header.Xid)
			}
			c.pendingMu.Unlock()
			return
		}
	}

	// Dispatch to waiting caller
	c.pendingMu.Lock()
	if request, ok := c.pending[header.Xid]; ok {
		select {
		case request.ch <- &response{header: *header, data: fullData}:
		default:
		}
		delete(c.pending, header.Xid)
	}
	c.pendingMu.Unlock()
}

func (c *Client) dispatchPacketIn(packet PacketIn) {
	c.packetInMu.RLock()
	defer c.packetInMu.RUnlock()
	for _, subscription := range c.packetInSinks {
		subscription.Deliver(packet)
	}
}

// SubscribePacketIn registers a bounded queue for asynchronous packet-in
// messages. A full queue drops the packet and counts it on the
// subscription; Cancel unregisters the queue and closes it.
func (c *Client) SubscribePacketIn(queueSize int) (*PacketInSubscription, error) {
	id := c.packetInNextID.Add(1)
	subscription, err := NewPacketInSubscription(queueSize, func() {
		c.packetInMu.Lock()
		delete(c.packetInSinks, id)
		c.packetInMu.Unlock()
	})
	if err != nil {
		return nil, err
	}
	c.packetInMu.Lock()
	c.packetInSinks[id] = subscription
	c.packetInMu.Unlock()
	return subscription, nil
}

// sendAndWait sends a message and waits for a response
func (c *Client) sendAndWait(ctx context.Context, xid uint32, data []byte, expectedType uint8) (*response, error) {
	s := c.session.Load()
	if !c.connected.Load() || s == nil {
		return nil, ErrNotConnected
	}
	return c.sendAndWaitOn(ctx, s, xid, data, expectedType)
}

// sendAndWaitOn is sendAndWait on a connection the caller already chose. A
// caller that wrote to s earlier must wait on s as well: loading the current
// connection again could pick a reconnect's, and a reply from that one says
// nothing about what the switch did with the write. It fails with
// ErrConnectionClosed when s is no longer the client's connection.
func (c *Client) sendAndWaitOn(ctx context.Context, s *session, xid uint32, data []byte, expectedType uint8) (*response, error) {
	respCh := c.addPending(xid, s.generation)

	defer func() {
		c.pendingMu.Lock()
		delete(c.pending, xid)
		c.pendingMu.Unlock()
	}()

	// Registered before the check: a connection lost after it fails the
	// request through failPending, one lost before it is caught here.
	if c.session.Load() != s {
		return nil, ErrConnectionClosed
	}

	if _, err := s.conn.Write(data); err != nil {
		return nil, &WrappedError{Msg: "failed to send message", Err: err}
	}

	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case resp := <-respCh:
		if resp == nil {
			return nil, ErrConnectionClosed
		}
		if resp.err != nil {
			return nil, resp.err
		}
		return resp, nil
	case <-time.After(c.timeout):
		return nil, ErrTimeout
	}
}

// AddFlow adds a flow entry to the bridge
func (c *Client) AddFlow(ctx context.Context, flow *FlowMod) error {
	if !c.connected.Load() {
		return ErrNotConnected
	}

	xid := c.nextXid()
	flow.Header.Xid = xid
	flow.Command = OFPFCAdd

	data, err := flow.MarshalBinary()
	if err != nil {
		return err
	}

	// No response is expected: the barrier confirms the switch processed it
	return c.writeConfirmed(ctx, data, "failed to send flow mod")
}

// DeleteFlow deletes flows matching the criteria
func (c *Client) DeleteFlow(ctx context.Context, flow *FlowMod) error {
	if !c.connected.Load() {
		return ErrNotConnected
	}

	xid := c.nextXid()
	flow.Header.Xid = xid
	flow.Command = OFPFCDelete

	data, err := flow.MarshalBinary()
	if err != nil {
		return err
	}

	return c.writeConfirmed(ctx, data, "failed to send flow mod")
}

// DeleteFlowStrict deletes the single flow whose match, priority, and table
// exactly equal the given FlowMod (OFPFC_DELETE_STRICT). When the FlowMod
// carries a non-zero CookieMask the delete is additionally restricted to
// flows whose cookie matches Cookie under that mask.
func (c *Client) DeleteFlowStrict(ctx context.Context, flow *FlowMod) error {
	if !c.connected.Load() {
		return ErrNotConnected
	}

	xid := c.nextXid()
	flow.Header.Xid = xid
	flow.Command = OFPFCDeleteStrict

	data, err := flow.MarshalBinary()
	if err != nil {
		return err
	}

	return c.writeConfirmed(ctx, data, "failed to send flow mod")
}

// DeleteAllFlows deletes all flows from the bridge
func (c *Client) DeleteAllFlows(ctx context.Context) error {
	flow := NewFlowMod(0)
	flow.TableID = OFPTTAll
	flow.OutPort = OFPPAny
	flow.OutGroup = 0xffffffff
	return c.DeleteFlow(ctx, flow)
}

// ModifyFlow modifies existing flows
func (c *Client) ModifyFlow(ctx context.Context, flow *FlowMod) error {
	if !c.connected.Load() {
		return ErrNotConnected
	}

	xid := c.nextXid()
	flow.Header.Xid = xid
	flow.Command = OFPFCModify

	data, err := flow.MarshalBinary()
	if err != nil {
		return err
	}

	return c.writeConfirmed(ctx, data, "failed to send flow mod")
}

// GetFlowStats retrieves flow statistics from every table.
func (c *Client) GetFlowStats(ctx context.Context, match *Match) ([]FlowStats, error) {
	return c.GetTableFlowStats(ctx, OFPTTAll, match)
}

// GetTableFlowStats retrieves flow statistics restricted to one table.
// tableID OFPTTAll queries every table.
func (c *Client) GetTableFlowStats(ctx context.Context, tableID uint8, match *Match) ([]FlowStats, error) {
	return c.QueryFlowStats(ctx, FlowStatsFilter{TableID: tableID, Match: match})
}

// FlowStatsFilter scopes a flow statistics request: to one table (OFPTTAll
// for every table), to flows whose cookie matches Cookie under CookieMask
// (a zero mask matches every cookie), and to flows matching Match.
type FlowStatsFilter struct {
	TableID    uint8
	Cookie     uint64
	CookieMask uint64
	Match      *Match
}

// QueryFlowStats retrieves the statistics of the flows filter selects.
func (c *Client) QueryFlowStats(ctx context.Context, filter FlowStatsFilter) ([]FlowStats, error) {
	if !c.connected.Load() {
		return nil, ErrNotConnected
	}

	xid := c.nextXid()

	// Build flow stats request body
	req := NewFlowStatsRequest()
	req.TableID = filter.TableID
	req.Cookie = filter.Cookie
	req.CookieMask = filter.CookieMask
	if filter.Match != nil {
		req.Match = filter.Match
	}

	body, err := req.MarshalBinary()
	if err != nil {
		return nil, err
	}

	// Create multipart request
	mpReq := NewMultipartRequest(xid, OFPMPFlow, body)
	data, err := mpReq.MarshalBinary()
	if err != nil {
		return nil, err
	}

	resp, err := c.sendAndWait(ctx, xid, data, OFPTMultipartReply)
	if err != nil {
		return nil, err
	}

	// Parse multipart reply
	if len(resp.data) < 16 {
		return nil, ErrMessageTooShort
	}

	// Skip header (8) + type (2) + flags (2) + pad (4) = 16 bytes
	statsData := resp.data[16:]
	return ParseFlowStats(statsData)
}

// barrier sends a barrier request and waits for reply
func (c *Client) barrier(ctx context.Context) error {
	s := c.session.Load()
	if !c.connected.Load() || s == nil {
		return ErrNotConnected
	}
	return c.barrierOn(ctx, s)
}

// barrierOn sends a barrier on s, the connection the caller's writes went to.
func (c *Client) barrierOn(ctx context.Context, s *session) error {
	xid := c.nextXid()
	req := NewBarrierRequest(xid)
	data, err := req.MarshalBinary()
	if err != nil {
		return err
	}

	_, err = c.sendAndWaitOn(ctx, s, xid, data, OFPTBarrierReply)
	return err
}

// writeConfirmed writes data to the current connection and returns once the
// switch has processed it. The write and its barrier share one connection:
// a reconnect in between fails the call instead of confirming a write the
// new connection never saw. failure labels a write error.
func (c *Client) writeConfirmed(ctx context.Context, data []byte, failure string) error {
	s := c.session.Load()
	if !c.connected.Load() || s == nil {
		return ErrNotConnected
	}
	if _, err := s.conn.Write(data); err != nil {
		return &WrappedError{Msg: failure, Err: err}
	}
	return c.barrierOn(ctx, s)
}

// Echo sends an echo request
func (c *Client) Echo(ctx context.Context, data []byte) ([]byte, error) {
	xid := c.nextXid()
	req := NewEchoRequest(xid, data)
	reqData, err := req.MarshalBinary()
	if err != nil {
		return nil, err
	}

	resp, err := c.sendAndWait(ctx, xid, reqData, OFPTEchoReply)
	if err != nil {
		return nil, err
	}

	if len(resp.data) > HeaderSize {
		return resp.data[HeaderSize:], nil
	}
	return nil, nil
}

// SendPacketOut emits a packet through the connected switch. A context
// already done sends nothing; once the write starts it completes, because
// abandoning a message half-written would corrupt the OpenFlow stream.
//
// The switch can reject a packet-out after accepting the write, for example
// when its output port is gone. A barrier follows the packet-out, so the
// rejection is returned rather than lost.
func (c *Client) SendPacketOut(ctx context.Context, packet *PacketOut) error {
	if packet == nil {
		return ErrInvalidMessage
	}
	if !c.connected.Load() {
		return ErrNotConnected
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	packet.Header.Xid = c.nextXid()
	data, err := packet.MarshalBinary()
	if err != nil {
		return err
	}
	return c.sendConfirmed(ctx, packet.Header.Xid, data)
}

// SetMeter installs a drop meter, or updates it when it already exists:
// an ADD the switch refuses with METER_EXISTS (a meter left by an earlier
// run) is retried as a MODIFY, so the requested rate always applies. A
// datapath without meter support is reported as *ErrMeterUnsupported.
func (c *Client) SetMeter(ctx context.Context, meterID uint32, rateKbps uint32, burstKbps uint32) error {
	bands := []MeterBand{NewMeterBandDrop(rateKbps, burstKbps)}
	err := c.sendMeterMod(ctx, NewMeterMod(OFPMCAdd, OFPMFKbps|OFPMFBurst, meterID, bands))
	if isMeterModError(err, OFPMMFCMeterExists) {
		err = c.sendMeterMod(ctx, NewMeterMod(OFPMCModify, OFPMFKbps|OFPMFBurst, meterID, bands))
	}
	if isMeterModError(err, OFPMMFCInvalidMeter) || isMeterModError(err, OFPMMFCOutOfMeters) {
		return &ErrMeterUnsupported{MeterID: meterID, Cause: err}
	}
	return err
}

// DeleteMeter removes a meter from the connected switch.
func (c *Client) DeleteMeter(ctx context.Context, meterID uint32) error {
	return c.sendMeterMod(ctx, NewMeterMod(OFPMCDelete, 0, meterID, nil))
}

// GetMeterStats returns the OFPMP_METER statistics of one meter.
func (c *Client) GetMeterStats(ctx context.Context, meterID uint32) (MeterStats, error) {
	if !c.connected.Load() {
		return MeterStats{}, ErrNotConnected
	}
	xid := c.nextXid()
	data, err := NewMultipartRequest(xid, OFPMPMeter, meterStatsRequestBody(meterID)).MarshalBinary()
	if err != nil {
		return MeterStats{}, err
	}
	resp, err := c.sendAndWait(ctx, xid, data, OFPTMultipartReply)
	if err != nil {
		return MeterStats{}, err
	}
	// Header (8) + type (2) + flags (2) + pad (4)
	if len(resp.data) < 16 {
		return MeterStats{}, ErrMessageTooShort
	}
	stats, err := ParseMeterStats(resp.data[16:])
	if err != nil {
		return MeterStats{}, err
	}
	for _, entry := range stats {
		if entry.MeterID == meterID {
			return entry, nil
		}
	}
	return MeterStats{}, &ErrMeterNotFound{MeterID: meterID}
}

func isMeterModError(err error, code uint16) bool {
	var ofErr *OFError
	return errors.As(err, &ofErr) && ofErr.Type == OFPETMeterModFailed && ofErr.Code == code
}

// sendMeterMod sends one meter mod and returns the error the switch
// reported for it, if any.
func (c *Client) sendMeterMod(ctx context.Context, mod *MeterMod) error {
	if mod == nil {
		return ErrInvalidMessage
	}
	if !c.connected.Load() {
		return ErrNotConnected
	}
	mod.Header.Xid = c.nextXid()
	data, err := mod.MarshalBinary()
	if err != nil {
		return err
	}
	return c.sendConfirmed(ctx, mod.Header.Xid, data)
}

// sendConfirmed writes one message that has no reply of its own, followed
// by a barrier. The barrier reply guarantees the switch processed the
// message, so an error it raised has arrived by then and is returned.
func (c *Client) sendConfirmed(ctx context.Context, xid uint32, data []byte) error {
	batch := &flowBatch{}
	c.batchMu.Lock()
	c.batches[xid] = &batchMember{batch: batch}
	c.batchMu.Unlock()
	defer func() {
		c.batchMu.Lock()
		delete(c.batches, xid)
		c.batchMu.Unlock()
	}()

	if err := c.writeConfirmed(ctx, data, "failed to send message"); err != nil {
		return err
	}
	if failed := batch.failures(); len(failed) > 0 {
		return failed[0].Err
	}
	return nil
}

// SendFlowMods sends a batch of FlowMod messages back-to-back followed by a
// single barrier. The commands already set on the flow mods are preserved
// (NewFlowMod defaults to OFPFC_ADD). Switch-reported errors for individual
// flow mods are collected until the barrier reply arrives; if any flow was
// rejected an ErrBatchPartialFailure identifying the failed flows is returned.
// An empty batch is a no-op.
func (c *Client) SendFlowMods(ctx context.Context, flows []*FlowMod) error {
	if len(flows) == 0 {
		return nil
	}
	if !c.connected.Load() {
		return ErrNotConnected
	}

	batch := &flowBatch{}
	xids := make([]uint32, len(flows))

	// Marshal all flow mods into a single buffer before registering the batch
	buf := make([]byte, 0, len(flows)*64)
	for i, flow := range flows {
		if flow == nil {
			return &SentinelCauseError{Sentinel: ErrInvalidMessage, Cause: &MessageError{Msg: fmt.Sprintf("flow mod at index %d is nil", i)}}
		}
		xid := c.nextXid()
		flow.Header.Xid = xid
		data, err := flow.MarshalBinary()
		if err != nil {
			return &WrappedError{Msg: fmt.Sprintf("failed to marshal flow mod at index %d", i), Err: err}
		}
		buf = append(buf, data...)
		xids[i] = xid
	}

	// Register every batch member so the reader can route errors to the batch
	c.batchMu.Lock()
	for i, xid := range xids {
		c.batches[xid] = &batchMember{batch: batch, index: i}
	}
	c.batchMu.Unlock()

	defer func() {
		c.batchMu.Lock()
		for _, xid := range xids {
			delete(c.batches, xid)
		}
		c.batchMu.Unlock()
	}()

	// The whole batch goes out in a single write to keep it contiguous on the
	// wire. The barrier reply guarantees every flow mod (and any error it
	// produced) has been processed by the switch.
	if err := c.writeConfirmed(ctx, buf, "failed to send flow mod batch"); err != nil {
		return err
	}

	failed := batch.failures()
	if len(failed) > 0 {
		sort.Slice(failed, func(i, j int) bool { return failed[i].Index < failed[j].Index })
		return &ErrBatchPartialFailure{Failed: failed}
	}

	return nil
}

// sendGroupMod sends a group mod and confirms processing with a barrier
func (c *Client) sendGroupMod(ctx context.Context, group *GroupMod) error {
	if !c.connected.Load() {
		return ErrNotConnected
	}

	xid := c.nextXid()
	group.Header.Xid = xid

	data, err := group.MarshalBinary()
	if err != nil {
		return err
	}

	return c.writeConfirmed(ctx, data, "failed to send group mod")
}

// AddGroup adds a group entry to the bridge
func (c *Client) AddGroup(ctx context.Context, group *GroupMod) error {
	if group == nil {
		return ErrInvalidMessage
	}
	group.Command = OFPGCAdd
	return c.sendGroupMod(ctx, group)
}

// ModifyGroup modifies an existing group entry
func (c *Client) ModifyGroup(ctx context.Context, group *GroupMod) error {
	if group == nil {
		return ErrInvalidMessage
	}
	group.Command = OFPGCModify
	return c.sendGroupMod(ctx, group)
}

// DeleteGroup deletes the group with the given ID. Passing OFPGAll deletes
// all groups.
func (c *Client) DeleteGroup(ctx context.Context, groupID uint32) error {
	group := NewGroupMod(OFPGCDelete, OFPGTAll, groupID)
	return c.sendGroupMod(ctx, group)
}

// DeleteAllGroups deletes all groups from the bridge
func (c *Client) DeleteAllGroups(ctx context.Context) error {
	return c.DeleteGroup(ctx, OFPGAll)
}

// GetGroupDesc retrieves the group descriptions from the bridge
func (c *Client) GetGroupDesc(ctx context.Context) ([]GroupDesc, error) {
	if !c.connected.Load() {
		return nil, ErrNotConnected
	}

	xid := c.nextXid()
	mpReq := NewMultipartRequest(xid, OFPMPGroupDesc, nil)
	data, err := mpReq.MarshalBinary()
	if err != nil {
		return nil, err
	}

	resp, err := c.sendAndWait(ctx, xid, data, OFPTMultipartReply)
	if err != nil {
		return nil, err
	}

	// Skip header (8) + type (2) + flags (2) + pad (4) = 16 bytes
	if len(resp.data) < 16 {
		return nil, ErrMessageTooShort
	}
	return ParseGroupDesc(resp.data[16:])
}
