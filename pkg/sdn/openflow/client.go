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
	"fmt"
	"io"
	"net"
	"path/filepath"
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
	conn       net.Conn
	connected  atomic.Bool
	closed     atomic.Bool

	// Datapath info from FeaturesReply
	datapathID uint64
	nBuffers   uint32
	nTables    uint8

	// Negotiated version
	negotiatedVersion uint8

	// Transaction ID counter
	xid atomic.Uint32

	// Request tracking
	pending   map[uint32]chan *response
	pendingMu sync.Mutex

	// HELLO reception channel for handshake
	helloCh   chan *response
	helloOnce sync.Once

	// Shutdown
	done   chan struct{}
	doneMu sync.Mutex
	wg     sync.WaitGroup

	// Configuration
	timeout time.Duration
}

// response represents a response message
type response struct {
	header Header
	data   []byte
	err    error
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
		bridgeName: bridgeName,
		socketDir:  "/var/run/openvswitch",
		pending:    make(map[uint32]chan *response),
		helloCh:    make(chan *response, 1),
		done:       make(chan struct{}),
		timeout:    DefaultTimeout,
	}

	for _, opt := range opts {
		opt(c)
	}

	return c, nil
}

// Connect establishes a connection to the OVS bridge's OpenFlow socket
func (c *Client) Connect(ctx context.Context) error {
	if c.connected.Load() {
		return nil
	}

	socketPath := filepath.Join(c.socketDir, c.bridgeName+".mgmt")

	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", socketPath)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrConnectionFailed, err)
	}

	c.conn = conn
	c.connected.Store(true)
	c.closed.Store(false)

	// Reset done channel and hello handling for new connection
	c.doneMu.Lock()
	c.done = make(chan struct{})
	c.doneMu.Unlock()

	// Reset hello channel and sync.Once for new connection
	c.helloCh = make(chan *response, 1)
	c.helloOnce = sync.Once{}

	// Start reader goroutine
	c.wg.Add(1)
	go c.reader()

	// Perform handshake
	if err := c.handshake(ctx); err != nil {
		_ = c.Disconnect()
		return err
	}

	return nil
}

// Disconnect closes the connection
func (c *Client) Disconnect() error {
	if !c.connected.Load() {
		return nil
	}

	c.connected.Store(false)
	c.closed.Store(true)

	// Signal shutdown
	c.doneMu.Lock()
	select {
	case <-c.done:
		// Already closed
	default:
		close(c.done)
	}
	c.doneMu.Unlock()

	// Close connection
	if c.conn != nil {
		_ = c.conn.Close()
	}

	// Wait for reader to exit
	c.wg.Wait()

	// Clean up pending requests
	c.pendingMu.Lock()
	for xid, ch := range c.pending {
		close(ch)
		delete(c.pending, xid)
	}
	c.pendingMu.Unlock()

	return nil
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
func (c *Client) handshake(ctx context.Context) error {
	// Send our Hello first
	xid := c.nextXid()
	hello := NewHello(xid)
	helloData, err := hello.MarshalBinary()
	if err != nil {
		return err
	}
	if _, err := c.conn.Write(helloData); err != nil {
		return fmt.Errorf("failed to send hello: %w", err)
	}

	// Wait for peer's Hello on the dedicated HELLO channel
	// Note: HELLO is NOT a request/response - peer sends its own HELLO with its own XID
	select {
	case <-ctx.Done():
		return ctx.Err()
	case resp := <-c.helloCh:
		if resp == nil {
			return ErrConnectionClosed
		}
		if resp.err != nil {
			return resp.err
		}
		if resp.header.Type != OFPTHello {
			return fmt.Errorf("%w: expected HELLO, got type %d", ErrVersionMismatch, resp.header.Type)
		}

		// Negotiate version: use the minimum of both sides
		peerVersion := resp.header.Version
		if peerVersion < DefaultVersion {
			// Peer only supports older version
			return fmt.Errorf("%w: peer version %d is lower than our minimum %d", ErrVersionMismatch, peerVersion, DefaultVersion)
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

	respCh := make(chan *response, 1)
	c.pendingMu.Lock()
	c.pending[xid] = respCh
	c.pendingMu.Unlock()

	if _, err := c.conn.Write(featReqData); err != nil {
		return fmt.Errorf("failed to send features request: %w", err)
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

	return nil
}

// reader reads messages from the connection
func (c *Client) reader() {
	defer c.wg.Done()

	headerBuf := make([]byte, HeaderSize)

	for {
		select {
		case <-c.done:
			return
		default:
		}

		// Set read deadline
		if c.conn != nil {
			_ = c.conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		}

		// Read header
		n, err := io.ReadFull(c.conn, headerBuf)
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				continue
			}

			select {
			case <-c.done:
				return
			default:
			}

			if err == io.EOF || !c.connected.Load() {
				return
			}
			continue
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
			_ = c.conn.SetReadDeadline(time.Now().Add(c.timeout))
			if _, err := io.ReadFull(c.conn, body); err != nil {
				continue
			}
		}

		// Clear deadline
		_ = c.conn.SetReadDeadline(time.Time{})

		// Handle message
		c.handleMessage(&header, body)
	}
}

// handleMessage processes a received message
func (c *Client) handleMessage(header *Header, body []byte) {
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
		c.helloOnce.Do(func() {
			select {
			case c.helloCh <- &response{header: *header, data: fullData}:
			default:
			}
		})
		return

	case OFPTEchoRequest:
		// Auto-reply to echo requests
		reply := NewEchoReply(header.Xid, body)
		data, err := reply.MarshalBinary()
		if err == nil && c.conn != nil {
			_, _ = c.conn.Write(data)
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

			c.pendingMu.Lock()
			if ch, ok := c.pending[header.Xid]; ok {
				ch <- &response{header: *header, data: fullData, err: ofErr}
				delete(c.pending, header.Xid)
			}
			c.pendingMu.Unlock()
			return
		}
	}

	// Dispatch to waiting caller
	c.pendingMu.Lock()
	if ch, ok := c.pending[header.Xid]; ok {
		select {
		case ch <- &response{header: *header, data: fullData}:
		default:
		}
		delete(c.pending, header.Xid)
	}
	c.pendingMu.Unlock()
}

// sendAndWait sends a message and waits for a response
func (c *Client) sendAndWait(ctx context.Context, xid uint32, data []byte, expectedType uint8) (*response, error) {
	if !c.connected.Load() {
		return nil, ErrNotConnected
	}

	respCh := make(chan *response, 1)
	c.pendingMu.Lock()
	c.pending[xid] = respCh
	c.pendingMu.Unlock()

	defer func() {
		c.pendingMu.Lock()
		delete(c.pending, xid)
		c.pendingMu.Unlock()
	}()

	if _, err := c.conn.Write(data); err != nil {
		return nil, fmt.Errorf("failed to send message: %w", err)
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

	// Send flow mod (no response expected, use barrier to confirm)
	if _, err := c.conn.Write(data); err != nil {
		return fmt.Errorf("failed to send flow mod: %w", err)
	}

	// Send barrier to ensure processing
	return c.barrier(ctx)
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

	if _, err := c.conn.Write(data); err != nil {
		return fmt.Errorf("failed to send flow mod: %w", err)
	}

	return c.barrier(ctx)
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

	if _, err := c.conn.Write(data); err != nil {
		return fmt.Errorf("failed to send flow mod: %w", err)
	}

	return c.barrier(ctx)
}

// GetFlowStats retrieves flow statistics
func (c *Client) GetFlowStats(ctx context.Context, match *Match) ([]FlowStats, error) {
	if !c.connected.Load() {
		return nil, ErrNotConnected
	}

	xid := c.nextXid()

	// Build flow stats request body
	req := NewFlowStatsRequest()
	if match != nil {
		req.Match = match
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
	xid := c.nextXid()
	req := NewBarrierRequest(xid)
	data, err := req.MarshalBinary()
	if err != nil {
		return err
	}

	_, err = c.sendAndWait(ctx, xid, data, OFPTBarrierReply)
	return err
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
