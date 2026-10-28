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

package ovs

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/openflow"
)

// defaultCallTimeout is the per-operation timeout applied when the caller's
// context has no deadline, preventing indefinite waits on OVS I/O.
const defaultCallTimeout = 30 * time.Second

// callRequest bundles a JSON-RPC request with a channel for the caller to
// receive the result. The dispatcher goroutine reads these from the requests
// channel, serializing all socket I/O through a single goroutine.
type callRequest struct {
	ctx    context.Context
	method string
	params []interface{}
	result chan callResult
}

// callResult carries the response (or error) back from the dispatcher to
// the caller that submitted the callRequest.
type callResult struct {
	response *JSONRPCResponse
	err      error
}

// Client represents an OVSDB client connection.
//
// All JSON-RPC I/O is serialized through a single dispatcher goroutine,
// eliminating encoder/decoder concurrency issues on the shared Unix socket.
type Client struct {
	socketPath string
	database   string
	conn       net.Conn
	encoder    *json.Encoder
	decoder    *json.Decoder
	mu         sync.RWMutex
	timeout    time.Duration

	// connected and closed are atomic so the dispatcher can mark a broken
	// connection without c.mu: Disconnect holds c.mu while it waits for
	// the dispatcher to exit (#1183).
	connected atomic.Bool
	closed    atomic.Bool

	// Serialized request dispatch channel. The dispatcher goroutine is
	// the sole reader; callers submit callRequest values to it.
	requests chan callRequest

	// Shutdown
	done chan struct{}
	wg   sync.WaitGroup

	// OpenFlow clients per bridge (pure Go implementation)
	ofClients   map[string]*openflow.Client
	ofClientsMu sync.RWMutex
	ofSocketDir string // Directory for OpenFlow sockets

	// appctlRunDir is the OVS runtime directory used to discover the
	// ovs-vswitchd unixctl control socket (see appctl.go).
	appctlRunDir string
}

// ClientOption is a functional option for configuring the Client
type ClientOption func(*Client)

// WithDatabase sets the OVSDB database name
func WithDatabase(database string) ClientOption {
	return func(c *Client) {
		c.database = database
	}
}

// WithTimeout sets the operation timeout
func WithTimeout(timeout time.Duration) ClientOption {
	return func(c *Client) {
		c.timeout = timeout
	}
}

// WithOpenFlowSocketDir sets the directory for OpenFlow management sockets
func WithOpenFlowSocketDir(dir string) ClientOption {
	return func(c *Client) {
		c.ofSocketDir = dir
	}
}

// NewClient creates a new OVSDB client
func NewClient(socketPath string, opts ...ClientOption) (*Client, error) {
	if socketPath == "" {
		return nil, ErrInvalidSocket
	}

	client := &Client{
		socketPath:   socketPath,
		database:     DefaultDatabase,
		timeout:      30 * time.Second,
		done:         make(chan struct{}),
		ofClients:    make(map[string]*openflow.Client),
		ofSocketDir:  "/var/run/openvswitch",
		appctlRunDir: DefaultAppCtlRunDir,
	}

	for _, opt := range opts {
		opt(client)
	}

	return client, nil
}

// Connect establishes a connection to the OVSDB server.
// Connect is idempotent: if already connected, it returns nil immediately.
func (c *Client) Connect(ctx context.Context) error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if c.connected.Load() {
		return nil
	}

	// Clean up stale connection state from a previous broken connection
	if c.conn != nil {
		c.conn.Close()
	}
	if c.done != nil {
		select {
		case <-c.done:
		default:
			close(c.done)
		}
	}

	// Wait for any old dispatcher to exit before proceeding.
	// Unlock briefly so the dispatcher goroutine can finish if needed.
	c.mu.Unlock()
	c.wg.Wait()
	c.mu.Lock()

	// Connect to the Unix socket
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.socketPath)
	if err != nil {
		return &SentinelCauseError{Sentinel: ErrConnectionFailed, Cause: err}
	}

	c.conn = conn
	c.encoder = json.NewEncoder(conn)
	c.decoder = json.NewDecoder(bufio.NewReader(conn))
	c.closed.Store(false)
	c.done = make(chan struct{})
	c.requests = make(chan callRequest)
	// Published last: IsConnected reads it without c.mu, and a caller that
	// sees true goes on to use done and requests.
	c.connected.Store(true)

	// Start the dispatcher goroutine that serializes all socket I/O
	c.wg.Add(1)
	go c.dispatcher()

	return nil
}

// Disconnect closes the connection to the OVSDB server
func (c *Client) Disconnect() error {
	c.mu.Lock()
	defer c.mu.Unlock()

	if !c.connected.Load() {
		return nil
	}

	c.closed.Store(true)
	c.connected.Store(false)

	// Signal shutdown — the dispatcher selects on this channel
	close(c.done)

	// Close connection — unblocks any pending decoder.Decode in the dispatcher
	if c.conn != nil {
		if err := c.conn.Close(); err != nil {
			// Log but continue cleanup - connection may already be closed
			_ = err // best-effort close during shutdown
		}
	}

	// Wait for the dispatcher goroutine to exit
	c.wg.Wait()

	// Close all OpenFlow clients
	c.ofClientsMu.Lock()
	for name, ofClient := range c.ofClients {
		if err := ofClient.Close(); err != nil {
			// Log but continue cleanup for remaining clients
			_ = err // best-effort close during shutdown
		}
		delete(c.ofClients, name)
	}
	c.ofClientsMu.Unlock()

	return nil
}

// IsConnected returns whether the client is connected
func (c *Client) IsConnected() bool {
	return c.connected.Load()
}

// Close is an alias for Disconnect
func (c *Client) Close() error {
	return c.Disconnect()
}

// ensureConnected establishes the OVSDB connection if not already connected.
// This provides lazy connect semantics: the connection is established on
// first use rather than at creation time. If the connection was dropped
// (idle timeout, OVS restart), a fresh connection is established transparently.
func (c *Client) ensureConnected(ctx context.Context) error {
	if c.IsConnected() {
		return nil
	}
	if err := c.Connect(ctx); err != nil {
		return &WrappedError{Msg: "ovs: connect failed", Err: err}
	}
	return nil
}

// dispatcher is the sole goroutine that performs socket I/O. It reads
// callRequest values from the requests channel, encodes each request on the
// wire, synchronously decodes the response, and sends the result back to
// the caller via the per-request result channel.
//
// Because OVSDB JSON-RPC is strictly synchronous (one response per request,
// in order), there is no need for a separate response listener or a pending
// request map. Serializing both encode and decode in a single goroutine
// eliminates the protocol desync bug that occurs under rapid concurrent use.
func (c *Client) dispatcher() {
	defer c.wg.Done()

	for {
		select {
		case <-c.done:
			return
		case req, ok := <-c.requests:
			if !ok {
				return
			}
			c.handleRequest(req)
		}
	}
}

// handleRequest encodes a single JSON-RPC request on the socket, reads the
// response, and delivers the result to the caller. Called exclusively from
// the dispatcher goroutine.
func (c *Client) handleRequest(req callRequest) {
	// Check if the caller's context is already cancelled before doing I/O
	if req.ctx.Err() != nil {
		req.result <- callResult{err: req.ctx.Err()}
		return
	}

	// Build the JSON-RPC request
	rpcReq := NewJSONRPCRequest(req.method, req.params)

	// Encode (write) the request to the socket
	if err := c.encoder.Encode(rpcReq); err != nil {
		c.markDisconnected()
		req.result <- callResult{err: &WrappedError{Msg: "failed to send request", Err: err}}
		return
	}

	// Decode (read) the response from the socket.
	// Use a deadline derived from the caller's context so we don't block
	// the dispatcher forever if the server stops responding.
	deadline, hasDeadline := req.ctx.Deadline()
	if hasDeadline {
		if err := c.conn.SetReadDeadline(deadline); err != nil {
			c.markDisconnected()
			req.result <- callResult{err: &WrappedError{Msg: "failed to set read deadline", Err: err}}
			return
		}
	}

	var response JSONRPCResponse
	if err := c.decoder.Decode(&response); err != nil {
		// Clear deadline before returning
		if c.conn != nil {
			if deadlineErr := c.conn.SetReadDeadline(time.Time{}); deadlineErr != nil {
				c.markDisconnected()
				req.result <- callResult{err: &WrappedError{Msg: "failed to clear read deadline", Err: deadlineErr}}
				return
			}
		}

		// Distinguish context cancellation from connection errors
		if req.ctx.Err() != nil {
			req.result <- callResult{err: req.ctx.Err()}
			return
		}
		c.markDisconnected()
		req.result <- callResult{err: &WrappedError{Msg: "failed to read response", Err: err}}
		return
	}

	// Clear deadline
	if hasDeadline && c.conn != nil {
		if err := c.conn.SetReadDeadline(time.Time{}); err != nil {
			c.markDisconnected()
			req.result <- callResult{err: &WrappedError{Msg: "failed to clear read deadline", Err: err}}
			return
		}
	}

	if response.Error != nil {
		req.result <- callResult{
			err: &MessageError{Msg: fmt.Sprintf("OVSDB error: %s", response.Error.Message)},
		}
		return
	}

	req.result <- callResult{response: &response}
}

// markDisconnected sets the client state to disconnected. Safe to call from
// the dispatcher goroutine only.
func (c *Client) markDisconnected() {
	// Never take c.mu here: Disconnect holds it while it waits for this
	// goroutine to exit (#1183).
	if !c.closed.Load() {
		c.connected.Store(false)
	}
}

// call sends a JSON-RPC request and waits for response.
// If the client is not connected, it establishes a fresh connection
// transparently (lazy connect). Connection is established once and
// reused for subsequent calls.
func (c *Client) call(ctx context.Context, method string, params []interface{}) (*JSONRPCResponse, error) {
	// Enforce per-operation timeout when the caller provides no deadline
	if _, hasDeadline := ctx.Deadline(); !hasDeadline {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, defaultCallTimeout)
		defer cancel()
	}

	// Lazy connect: establish connection on first use or after drop
	if err := c.ensureConnected(ctx); err != nil {
		return nil, err
	}

	// Check context before proceeding - fail fast on already-canceled contexts
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}

	// Submit the request to the dispatcher goroutine
	req := callRequest{
		ctx:    ctx,
		method: method,
		params: params,
		result: make(chan callResult, 1),
	}

	// Send to dispatcher, respecting context cancellation and shutdown
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case <-c.done:
		return nil, ErrConnectionClosed
	case c.requests <- req:
	}

	// Wait for the dispatcher to process the request and return a result
	select {
	case <-ctx.Done():
		return nil, ctx.Err()
	case res := <-req.result:
		if res.err != nil {
			return nil, res.err
		}
		return res.response, nil
	}
}

// ListDatabases returns a list of available databases
func (c *Client) ListDatabases(ctx context.Context) ([]string, error) {
	resp, err := c.call(ctx, "list_dbs", []interface{}{})
	if err != nil {
		return nil, err
	}

	var result []string
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, &WrappedError{Msg: "failed to parse list_dbs result", Err: err}
	}

	return result, nil
}

// GetSchema retrieves the schema for the specified database
func (c *Client) GetSchema(ctx context.Context) (*GetSchemaResult, error) {
	resp, err := c.call(ctx, "get_schema", []interface{}{c.database})
	if err != nil {
		return nil, err
	}

	var result GetSchemaResult
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, &WrappedError{Msg: "failed to parse get_schema result", Err: err}
	}

	return &result, nil
}

// Echo sends an echo request to test connectivity
func (c *Client) Echo(ctx context.Context, data []interface{}) ([]interface{}, error) {
	resp, err := c.call(ctx, "echo", data)
	if err != nil {
		return nil, err
	}

	var result []interface{}
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, &WrappedError{Msg: "failed to parse echo result", Err: err}
	}

	return result, nil
}

// Transact executes a transaction on the OVSDB server
func (c *Client) Transact(ctx context.Context, operations ...Operation) (TransactResponse, error) {
	// Build params: database name followed by operations
	params := make([]interface{}, 0, len(operations)+1)
	params = append(params, c.database)
	for _, op := range operations {
		params = append(params, op)
	}

	resp, err := c.call(ctx, "transact", params)
	if err != nil {
		return nil, err
	}

	var result TransactResponse
	if err := json.Unmarshal(resp.Result, &result); err != nil {
		return nil, &WrappedError{Msg: "failed to parse transact result", Err: err}
	}

	// Check for operation errors
	for i, opResult := range result {
		if opResult.Error != "" {
			return result, &MessageError{Msg: fmt.Sprintf("operation %d failed: %s - %s", i, opResult.Error, opResult.Details)}
		}
	}

	return result, nil
}

// Select executes a select operation and returns the matching rows
func (c *Client) Select(ctx context.Context, table string, where []Condition, columns []string) ([]map[string]interface{}, error) {
	op := NewSelectOperation(table, where, columns)
	results, err := c.Transact(ctx, op)
	if err != nil {
		return nil, err
	}

	if len(results) == 0 {
		return nil, ErrNoResult
	}

	return results[0].Rows, nil
}

// getOpenVSwitchUUID retrieves the UUID of the Open_vSwitch table row
func (c *Client) getOpenVSwitchUUID(ctx context.Context) (string, error) {
	rows, err := c.Select(ctx, "Open_vSwitch", nil, []string{"_uuid"})
	if err != nil {
		return "", err
	}

	if len(rows) == 0 {
		return "", &MessageError{Msg: "no Open_vSwitch row found"}
	}

	// Parse UUID from result
	uuidVal, ok := rows[0]["_uuid"]
	if !ok {
		return "", &MessageError{Msg: "_uuid field not found"}
	}

	// UUID is returned as ["uuid", "actual-uuid-string"]
	uuidArr, ok := uuidVal.([]interface{})
	if !ok || len(uuidArr) != 2 {
		return "", &MessageError{Msg: fmt.Sprintf("invalid UUID format: %v", uuidVal)}
	}

	uuidStr, ok := uuidArr[1].(string)
	if !ok {
		return "", &MessageError{Msg: fmt.Sprintf("invalid UUID string: %v", uuidArr[1])}
	}

	return uuidStr, nil
}

// getOpenFlowClient returns an OpenFlow client for the specified bridge.
// Creates and connects a new client if one doesn't exist.
// It waits for the socket to become available with exponential backoff.
func (c *Client) getOpenFlowClient(ctx context.Context, bridgeName string) (*openflow.Client, error) {
	c.ofClientsMu.RLock()
	if ofClient, ok := c.ofClients[bridgeName]; ok {
		if ofClient.IsConnected() {
			c.ofClientsMu.RUnlock()
			return ofClient, nil
		}
	}
	c.ofClientsMu.RUnlock()

	// Need to create/reconnect
	c.ofClientsMu.Lock()
	defer c.ofClientsMu.Unlock()

	// Double-check after acquiring write lock
	if ofClient, ok := c.ofClients[bridgeName]; ok {
		if ofClient.IsConnected() {
			return ofClient, nil
		}
		// Disconnect stale client
		if err := ofClient.Close(); err != nil {
			// Log but continue - we're replacing this client anyway
			_ = err // best-effort close of stale client
		}
	}

	// Create new OpenFlow client
	ofClient, err := openflow.NewClient(bridgeName,
		openflow.WithSocketDir(c.ofSocketDir),
		openflow.WithTimeout(c.timeout),
	)
	if err != nil {
		return nil, &WrappedError{Msg: "failed to create OpenFlow client", Err: err}
	}

	// Try to connect - if the socket doesn't exist, fail immediately
	// Otherwise retry with backoff for transient errors
	if err := ofClient.Connect(ctx); err != nil {
		return nil, &WrappedError{Msg: "failed to connect OpenFlow client", Err: err}
	}

	c.ofClients[bridgeName] = ofClient
	return ofClient, nil
}

// closeOpenFlowClient closes the OpenFlow client for a specific bridge
func (c *Client) closeOpenFlowClient(bridgeName string) {
	c.ofClientsMu.Lock()
	defer c.ofClientsMu.Unlock()

	if ofClient, ok := c.ofClients[bridgeName]; ok {
		if err := ofClient.Close(); err != nil {
			// Best-effort close during cleanup
			_ = err
		}
		delete(c.ofClients, bridgeName)
	}
}
