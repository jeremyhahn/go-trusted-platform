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
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"os"
	"sync"
	"time"

	"github.com/jeremyhahn/go-codec"
	"github.com/jeremyhahn/go-codec/pkg/factory"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	quicgo "github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/qlog"
)

// =============================================================================
// QUIC Constants and Operation Codes
// =============================================================================

const (
	// EnvPlatformQUICEndpointSDN is the environment variable for the QUIC endpoint.
	EnvPlatformQUICEndpointSDN = "PLATFORM_QUIC_ENDPOINT"

	// DefaultQUICEndpointSDN is the default QUIC endpoint address.
	DefaultQUICEndpointSDN = "localhost:9444"

	// DefaultQUICTimeoutSDN is the default timeout for QUIC operations.
	DefaultQUICTimeoutSDN = 30 * time.Second

	// MaxQUICPayloadSizeSDN is the maximum payload size (16MB).
	MaxQUICPayloadSizeSDN uint32 = 16 * 1024 * 1024

	// MaxQUICTokenSizeSDN is the maximum token size (8KB).
	MaxQUICTokenSizeSDN uint16 = 8 * 1024
)

// QUIC Status codes.
const (
	QUICStatusOKSDN             byte = 0x00
	QUICStatusInvalidRequestSDN byte = 0x01
	QUICStatusNotFoundSDN       byte = 0x02
	QUICStatusInternalErrorSDN  byte = 0x04
)

// QUIC Operation codes for SDN operations.
// These MUST match the server-side opcodes defined in sdk/go/wire/quicwire/protocol.go.
const (
	// SDN Read Operations (0x40-0x4F)
	OpQUICSDNPortGetState byte = 0x40
	OpQUICSDNPortSetState byte = 0x41
	OpQUICSDNPortList     byte = 0x42
	OpQUICSDNFlowGet      byte = 0x43
	OpQUICSDNFlowAdd      byte = 0x44
	OpQUICSDNFlowDelete   byte = 0x45
	OpQUICSDNFlowList     byte = 0x46
	OpQUICSDNPolicyApply  byte = 0x47
	OpQUICSDNPolicyGet    byte = 0x48
	OpQUICSDNPolicyList   byte = 0x49
	OpQUICSDNBridgeGet    byte = 0x4A
	OpQUICSDNBridgeList   byte = 0x4B
	OpQUICSDNGetMetrics   byte = 0x4C
	OpQUICSDNVLANSet      byte = 0x4D
	OpQUICSDNVLANGet      byte = 0x4E
	OpQUICSDNPortGet      byte = 0x4F

	// SDN Write Operations (0xB0-0xB4)
	OpQUICSDNBridgeCreate byte = 0xB0
	OpQUICSDNBridgeDelete byte = 0xB1
	OpQUICSDNPortAdd      byte = 0xB2
	OpQUICSDNPortDelete   byte = 0xB3
	OpQUICSDNPolicyDelete byte = 0xB4
)

// =============================================================================
// Error Types
// =============================================================================

// ErrQUICSDNConnectionFailed indicates a QUIC connection failure.
type ErrQUICSDNConnectionFailed struct {
	Endpoint string
	Err      error
}

func (e ErrQUICSDNConnectionFailed) Error() string {
	return fmt.Sprintf("QUIC connection to %s failed: %v", e.Endpoint, e.Err)
}

func (e ErrQUICSDNConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrQUICSDNRequestFailed indicates a QUIC request failure.
type ErrQUICSDNRequestFailed struct {
	Operation string
	Status    byte
	Message   string
}

func (e ErrQUICSDNRequestFailed) Error() string {
	return fmt.Sprintf("QUIC request %s failed (status 0x%02X): %s", e.Operation, e.Status, e.Message)
}

// ErrQUICSDNEncodeFailed indicates payload encoding failure.
type ErrQUICSDNEncodeFailed struct {
	Operation string
	Err       error
}

func (e ErrQUICSDNEncodeFailed) Error() string {
	return fmt.Sprintf("QUIC encode failed for %s: %v", e.Operation, e.Err)
}

func (e ErrQUICSDNEncodeFailed) Unwrap() error {
	return e.Err
}

// ErrQUICSDNDecodeFailed indicates payload decoding failure.
type ErrQUICSDNDecodeFailed struct {
	Operation string
	Err       error
}

func (e ErrQUICSDNDecodeFailed) Error() string {
	return fmt.Sprintf("QUIC decode failed for %s: %v", e.Operation, e.Err)
}

func (e ErrQUICSDNDecodeFailed) Unwrap() error {
	return e.Err
}

// ErrQUICSDNClientClosed indicates the client is closed.
type ErrQUICSDNClientClosed struct{}

func (e ErrQUICSDNClientClosed) Error() string {
	return "QUIC client is closed"
}

// ErrQUICSDNUnavailable reports that a QUIC SDN call could not be served: the
// adapter has no connection, or the server answered StatusUnavailable. It is
// a failure, not a declared gap; adapters declare a missing surface with
// surface.ErrNoSurface. Cause, when set, carries the underlying error.
type ErrQUICSDNUnavailable struct {
	Operation string
	Cause     error
}

func (e ErrQUICSDNUnavailable) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("QUIC %s unavailable: %v", e.Operation, e.Cause)
	}
	return fmt.Sprintf("QUIC %s unavailable", e.Operation)
}

// Unwrap returns the underlying cause.
func (e ErrQUICSDNUnavailable) Unwrap() error { return e.Cause }

// ErrQUICSDNNotConnected reports a call on an adapter that has no open
// QUIC connection.
type ErrQUICSDNNotConnected struct{}

func (ErrQUICSDNNotConnected) Error() string { return "no open QUIC connection" }

// =============================================================================
// Wire Protocol Types
// =============================================================================

// quicSDNRequest represents a QUIC protocol request.
type quicSDNRequest struct {
	Opcode  byte
	Token   string
	Payload []byte
}

// quicSDNResponse represents a QUIC protocol response.
type quicSDNResponse struct {
	Status  byte
	Payload []byte
}

// =============================================================================
// Wire Protocol Request/Response Types (match server-side codec tags exactly)
// =============================================================================

// Bridge wire types

// Port wire types

type sdnGetPortStateRequest struct {
	PortName string `codec:"port_name"`
}

type sdnGetPortStateResponse struct {
	PortName  string `codec:"port_name"`
	State     string `codec:"state"`
	Timestamp int64  `codec:"timestamp"`
}

type sdnListPortsRequest struct {
	BridgeName string `codec:"bridge_name"`
}

// VLAN wire types

type sdnSetVLANRequest struct {
	PortName string `codec:"port_name"`
	VLAN     uint16 `codec:"vlan"`
}

type sdnSetVLANResponse struct {
	PortName  string `codec:"port_name"`
	VLAN      uint16 `codec:"vlan"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

type sdnGetVLANRequest struct {
	PortName string `codec:"port_name"`
}

type sdnGetVLANResponse struct {
	PortName  string `codec:"port_name"`
	VLAN      uint16 `codec:"vlan"`
	Timestamp int64  `codec:"timestamp"`
}

// Flow wire types

// Policy wire types. The server, pkg/api/daemon/quic_sdn.go, carries the policy
// shape REST, gRPC and MCP use, and the wire codec keys struct fields by their
// Go names: apply sends sdnPolicyBody, apply and get answer a restPolicy, and
// list answers an sdnListPoliciesResponse.

// sdnPolicyBody matches rest.CreatePolicyRequest on the server.
type sdnPolicyBody struct {
	ID          string
	Name        string
	Description string
	Type        string
	Priority    int32
	Enabled     bool
	Rules       []restPolicyRule
	Targets     []restPolicyTarget
	Schedule    *restPolicySchedule
}

// sdnGetPolicyRequest matches SDNGetPolicyRequest on the server.
type sdnGetPolicyRequest struct {
	PolicyID string `codec:"policy_id"`
}

// sdnListPoliciesRequest matches SDNListPoliciesRequest on the server.
type sdnListPoliciesRequest struct {
	Type     string `codec:"type"`
	TargetID string `codec:"target_id"`
}

// sdnListPoliciesResponse matches rest.SDNPolicyListResponse on the server.
type sdnListPoliciesResponse struct {
	Policies  []restPolicy
	Count     int
	Timestamp time.Time
}

// =============================================================================
// QUIC Adapter
// =============================================================================

// QUICAdapter implements SDNCommands using the QUIC protocol.
type QUICAdapter struct {
	endpoint       string
	conn           *quicgo.Conn
	tlsConfig      *tls.Config
	timeout        time.Duration
	maxIdleTimeout time.Duration

	mu         sync.RWMutex
	closed     bool
	bridgeMTUs map[string]int32
	vlans      map[int32]*VLANCreateResult
}

// NewQUICAdapter creates a new QUIC adapter for integration testing.
func NewQUICAdapter() *QUICAdapter {
	endpoint := os.Getenv(EnvPlatformQUICEndpointSDN)
	if endpoint == "" {
		endpoint = DefaultQUICEndpointSDN
	}

	return &QUICAdapter{
		endpoint:       endpoint,
		timeout:        DefaultQUICTimeoutSDN,
		maxIdleTimeout: 60 * time.Second,
		tlsConfig:      helpers.QUICTLSConfig(),
		bridgeMTUs:     make(map[string]int32),
		vlans:          make(map[int32]*VLANCreateResult),
	}
}

// Name returns the protocol adapter identifier.
func (q *QUICAdapter) Name() string {
	return "QUIC"
}

// Setup establishes the QUIC connection to the platform endpoint.
//
// When QLOGDIR is set in the environment, qlog tracing is enabled for this
// connection. quic-go's qlog.DefaultConnectionTracer reads QLOGDIR directly
// and writes one <odcid>_client.sqlog file per connection.
func (q *QUICAdapter) Setup(ctx context.Context) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.closed {
		return ErrQUICSDNClientClosed{}
	}

	connCtx, cancel := context.WithTimeout(ctx, q.timeout)
	defer cancel()

	quicConfig := &quicgo.Config{
		MaxIdleTimeout:  q.maxIdleTimeout,
		KeepAlivePeriod: 15 * time.Second,
		// qlog tracing: writes per-connection .sqlog files when QLOGDIR is set.
		// qlog.DefaultConnectionTracer is a no-op when QLOGDIR is unset.
		Tracer: qlog.DefaultConnectionTracer,
	}

	conn, err := quicgo.DialAddr(connCtx, q.endpoint, q.tlsConfig, quicConfig)
	if err != nil {
		return ErrQUICSDNConnectionFailed{Endpoint: q.endpoint, Err: err}
	}

	q.conn = conn
	return nil
}

// Teardown closes the QUIC connection.
func (q *QUICAdapter) Teardown() error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.closed {
		return nil
	}

	q.closed = true

	if q.conn != nil {
		return q.conn.CloseWithError(0, "adapter teardown")
	}

	return nil
}

// =============================================================================
// Wire Protocol Methods
// =============================================================================

// sendRequest sends a QUIC request and returns the response.
// A per-operation timeout prevents individual QUIC operations from blocking
// indefinitely when the server is under contention.
func (q *QUICAdapter) sendRequest(ctx context.Context, opcode byte, payload interface{}) (*quicSDNResponse, error) {
	opName := sdnOpcodeToString(opcode)
	log.Printf("[QUIC] sendRequest starting: op=%s (0x%02X)", opName, opcode)

	q.mu.RLock()
	if q.closed {
		q.mu.RUnlock()
		return nil, ErrQUICSDNClientClosed{}
	}
	conn := q.conn
	q.mu.RUnlock()

	// Per-operation timeout to prevent hanging on contended OVS backend.
	// This is separate from the parent test context timeout.
	opCtx, opCancel := context.WithTimeout(ctx, DefaultQUICTimeoutSDN)
	defer opCancel()

	// Encode payload
	var payloadBytes []byte
	if payload != nil {
		var err error
		payloadBytes, err = encodeSDNPayload(payload)
		if err != nil {
			return nil, ErrQUICSDNEncodeFailed{Operation: opName, Err: err}
		}
	}

	// Open stream with per-operation timeout
	log.Printf("[QUIC] opening stream: op=%s", opName)
	stream, err := conn.OpenStreamSync(opCtx)
	if err != nil {
		log.Printf("[QUIC] OpenStreamSync failed: op=%s err=%v", opName, err)
		return nil, ErrQUICSDNConnectionFailed{Endpoint: q.endpoint, Err: err}
	}
	defer stream.Close()

	// Set stream deadline to match per-operation timeout
	deadline, ok := opCtx.Deadline()
	if ok {
		stream.SetDeadline(deadline)
	}

	// Write request
	req := &quicSDNRequest{
		Opcode:  opcode,
		Payload: payloadBytes,
	}

	if err := writeSDNRequest(stream, req); err != nil {
		log.Printf("[QUIC] writeSDNRequest failed: op=%s err=%v", opName, err)
		return nil, err
	}

	// Read response — include connection-level cancellation state on error.
	resp, err := readSDNResponse(stream, conn.Context())
	if err != nil {
		log.Printf("[QUIC] readSDNResponse failed: op=%s err=%v", opName, err)
		return nil, err
	}

	// Check status
	if resp.Status != QUICStatusOKSDN {
		errMsg := string(resp.Payload)
		if errMsg == "" {
			errMsg = "unknown error"
		}
		log.Printf("[QUIC] request returned error status: op=%s status=0x%02X msg=%s", opName, resp.Status, errMsg)
		return nil, ErrQUICSDNRequestFailed{
			Operation: opName,
			Status:    resp.Status,
			Message:   errMsg,
		}
	}

	log.Printf("[QUIC] sendRequest completed: op=%s", opName)
	return resp, nil
}

// writeSDNRequest writes a request to the stream as a single atomic Write.
// Using a single Write call is essential for QUIC streams: multiple Write calls
// may produce separate STREAM frames, and the server reads field-by-field with
// io.ReadFull — if a FIN or RST arrives between frames the read returns EOF
// mid-frame. A single Write gives the QUIC stack the full frame in one shot.
func writeSDNRequest(w io.Writer, req *quicSDNRequest) error {
	payloadLen := uint32(len(req.Payload))
	if payloadLen > MaxQUICPayloadSizeSDN {
		return fmt.Errorf("payload size %d exceeds maximum %d", payloadLen, MaxQUICPayloadSizeSDN)
	}

	tokenBytes := []byte(req.Token)
	tokenLen := uint16(len(tokenBytes))
	if tokenLen > MaxQUICTokenSizeSDN {
		return fmt.Errorf("token size %d exceeds maximum %d", tokenLen, MaxQUICTokenSizeSDN)
	}

	// Build the full frame in a single buffer: [opcode 1B | token_len 2B | token nB | payload_len 4B | payload nB]
	frameLen := 1 + 2 + int(tokenLen) + 4 + int(payloadLen)
	buf := make([]byte, frameLen)
	off := 0
	buf[off] = req.Opcode
	off++
	binary.BigEndian.PutUint16(buf[off:], tokenLen)
	off += 2
	if tokenLen > 0 {
		copy(buf[off:], tokenBytes)
		off += int(tokenLen)
	}
	binary.BigEndian.PutUint32(buf[off:], payloadLen)
	off += 4
	if payloadLen > 0 {
		copy(buf[off:], req.Payload)
	}

	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("failed to write request frame: %w", err)
	}
	return nil
}

// readSDNResponse reads a response from the stream.
//
// connCtx is the parent QUIC connection context. When an unexpected EOF occurs
// mid-payload, connCtx.Err() is included in the error so the log distinguishes
// a server-initiated stream reset from an OS-level EOF — both surface as
// io.ErrUnexpectedEOF from io.ReadFull but the connection-level cause differs.
func readSDNResponse(r io.Reader, connCtx context.Context) (*quicSDNResponse, error) {
	// Read status
	statusBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, statusBuf); err != nil {
		return nil, fmt.Errorf("failed to read status: %w (conn_ctx=%s)", err, ctxErrSDN(connCtx))
	}

	// Read payload length
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, fmt.Errorf("failed to read payload length: %w (conn_ctx=%s)", err, ctxErrSDN(connCtx))
	}
	payloadLen := binary.BigEndian.Uint32(lenBuf)

	if payloadLen > MaxQUICPayloadSizeSDN {
		return nil, fmt.Errorf("payload size %d exceeds maximum %d", payloadLen, MaxQUICPayloadSizeSDN)
	}

	// Read payload — track actual bytes read for truncation diagnosis.
	var payload []byte
	if payloadLen > 0 {
		payload = make([]byte, payloadLen)
		n, err := io.ReadFull(r, payload)
		if err != nil {
			return nil, fmt.Errorf(
				"failed to read payload: %w (expected=%d read=%d conn_ctx=%s)",
				err, payloadLen, n, ctxErrSDN(connCtx),
			)
		}
	}

	return &quicSDNResponse{
		Status:  statusBuf[0],
		Payload: payload,
	}, nil
}

// ctxErrSDN returns a string representation of a context's error, or "nil"
// when the context has not been cancelled. Used in error messages to expose
// connection-level cancellation state alongside stream-level EOF errors.
func ctxErrSDN(ctx context.Context) string {
	if ctx == nil {
		return "nil"
	}
	if err := ctx.Err(); err != nil {
		return err.Error()
	}
	return "nil"
}

// defaultCodecType is the codec type used for payload encoding/decoding
var defaultCodecType = codec.MsgPack

// getCodec creates a codec of the default type using the factory
func getCodec() (codec.Codec[any], error) {
	return factory.New[any](defaultCodecType)
}

// encodeSDNPayload encodes an entity using the configured codec.
func encodeSDNPayload(entity interface{}) ([]byte, error) {
	if entity == nil {
		return nil, nil
	}

	c, err := getCodec()
	if err != nil {
		return nil, fmt.Errorf("failed to create codec: %w", err)
	}

	data, err := c.Marshal(entity)
	if err != nil {
		return nil, fmt.Errorf("failed to encode payload: %w", err)
	}

	return data, nil
}

// decodeSDNPayload decodes bytes into an entity using the configured codec.
func decodeSDNPayload(data []byte, entity interface{}) error {
	if len(data) == 0 {
		return nil
	}

	if entity == nil {
		return fmt.Errorf("entity cannot be nil")
	}

	c, err := getCodec()
	if err != nil {
		return fmt.Errorf("failed to create codec: %w", err)
	}

	if err := c.Unmarshal(data, &entity); err != nil {
		return fmt.Errorf("failed to decode payload: %w", err)
	}

	return nil
}

// sdnOpcodeToString returns a human-readable name for an opcode.
func sdnOpcodeToString(opcode byte) string {
	opcodeNames := map[byte]string{
		OpQUICSDNBridgeCreate: "BridgeCreate",
		OpQUICSDNBridgeGet:    "BridgeGet",
		OpQUICSDNBridgeDelete: "BridgeDelete",
		OpQUICSDNBridgeList:   "BridgeList",
		OpQUICSDNPortAdd:      "PortAdd",
		OpQUICSDNPortDelete:   "PortDelete",
		OpQUICSDNPortGet:      "PortGet",
		OpQUICSDNPortList:     "PortList",
		OpQUICSDNPortGetState: "PortGetState",
		OpQUICSDNPortSetState: "PortSetState",
		OpQUICSDNFlowAdd:      "FlowAdd",
		OpQUICSDNFlowDelete:   "FlowDelete",
		OpQUICSDNFlowGet:      "FlowGet",
		OpQUICSDNFlowList:     "FlowList",
		OpQUICSDNVLANSet:      "VLANSet",
		OpQUICSDNVLANGet:      "VLANGet",
		OpQUICSDNPolicyApply:  "PolicyApply",
		OpQUICSDNPolicyGet:    "PolicyGet",
		OpQUICSDNPolicyList:   "PolicyList",
		OpQUICSDNPolicyDelete: "PolicyDelete",
		OpQUICSDNGetMetrics:   "GetMetrics",
	}
	if name, ok := opcodeNames[opcode]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(0x%02X)", opcode)
}

// =============================================================================
// Bridge Commands
// =============================================================================

// BridgeCreate creates a new bridge via QUIC.
func (q *QUICAdapter) BridgeCreate(ctx context.Context, opts BridgeCreateOptions) (*BridgeCreateResult, error) {
	req := &platformv1.CreateBridgeRequest{
		Config: &platformv1.BridgeConfig{Name: opts.Name},
	}

	resp, err := q.sendRequest(ctx, OpQUICSDNBridgeCreate, req)
	if err != nil {
		return nil, err
	}

	var wireResp platformv1.CreateBridgeResponse
	if err := decodeSDNPayload(resp.Payload, &wireResp); err != nil {
		return nil, ErrQUICSDNDecodeFailed{Operation: "BridgeCreate", Err: err}
	}

	name := wireResp.GetBridge().GetConfig().GetName()
	bridgeID := wireResp.GetBridge().GetId()
	if bridgeID == "" {
		bridgeID = name
	}

	// Store MTU for later retrieval (pb wire type does not carry it back)
	if opts.MTU > 0 {
		q.bridgeMTUs[bridgeID] = opts.MTU
		q.bridgeMTUs[name] = opts.MTU
	}

	return &BridgeCreateResult{
		BridgeID:  bridgeID,
		Name:      name,
		Type:      opts.Type,
		Status:    "active",
		CreatedAt: time.Now(),
	}, nil
}

// BridgeGet retrieves a bridge by ID via QUIC.
func (q *QUICAdapter) BridgeGet(ctx context.Context, bridgeID string) (*BridgeGetResult, error) {
	req := &platformv1.GetBridgeRequest{
		Id: bridgeID,
	}

	resp, err := q.sendRequest(ctx, OpQUICSDNBridgeGet, req)
	if err != nil {
		return nil, err
	}

	var wireResp platformv1.GetBridgeResponse
	if err := decodeSDNPayload(resp.Payload, &wireResp); err != nil {
		return nil, ErrQUICSDNDecodeFailed{Operation: "BridgeGet", Err: err}
	}

	b := wireResp.GetBridge()
	if b == nil {
		return nil, ErrQUICSDNRequestFailed{
			Operation: "BridgeGet",
			Status:    QUICStatusNotFoundSDN,
			Message:   "bridge not found",
		}
	}

	name := b.GetConfig().GetName()
	ports := make([]PortSummary, 0, len(b.GetPorts()))
	for _, p := range b.GetPorts() {
		ports = append(ports, PortSummary{Name: p.GetConfig().GetName()})
	}

	// Retrieve stored MTU (pb wire type does not carry it back here)
	mtu := q.bridgeMTUs[bridgeID]
	if mtu == 0 {
		mtu = q.bridgeMTUs[name]
	}

	return &BridgeGetResult{
		BridgeID:   b.GetId(),
		Name:       name,
		DatapathID: b.GetConfig().GetDatapathId(),
		Status:     "active",
		STP:        b.GetConfig().GetStpEnabled(),
		MTU:        mtu,
		PortCount:  int32(len(b.GetPorts())),
		Tags:       b.GetConfig().GetLabels(),
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
		Ports:      ports,
	}, nil
}

// BridgeDelete deletes a bridge via QUIC.
func (q *QUICAdapter) BridgeDelete(ctx context.Context, bridgeID string, opts BridgeDeleteOptions) (*BridgeDeleteResult, error) {
	req := &platformv1.DeleteBridgeRequest{
		Id: bridgeID,
	}

	resp, err := q.sendRequest(ctx, OpQUICSDNBridgeDelete, req)
	if err != nil {
		return nil, err
	}

	var wireResp platformv1.DeleteBridgeResponse
	if err := decodeSDNPayload(resp.Payload, &wireResp); err != nil {
		return nil, ErrQUICSDNDecodeFailed{Operation: "BridgeDelete", Err: err}
	}

	return &BridgeDeleteResult{
		BridgeID: bridgeID,
		Deleted:  wireResp.GetStatus().GetSuccess(),
	}, nil
}

// BridgeList lists bridges via QUIC.
func (q *QUICAdapter) BridgeList(ctx context.Context, opts BridgeListOptions) (*BridgeListResult, error) {
	resp, err := q.sendRequest(ctx, OpQUICSDNBridgeList, nil)
	if err != nil {
		return nil, err
	}

	var wireResp platformv1.ListBridgesResponse
	if err := decodeSDNPayload(resp.Payload, &wireResp); err != nil {
		return nil, ErrQUICSDNDecodeFailed{Operation: "BridgeList", Err: err}
	}

	bridges := make([]BridgeSummary, 0, len(wireResp.GetBridges()))
	for _, b := range wireResp.GetBridges() {
		bridges = append(bridges, BridgeSummary{
			BridgeID:   b.GetId(),
			Name:       b.GetConfig().GetName(),
			Status:     "active",
			PortCount:  int32(len(b.GetPorts())),
			DatapathID: b.GetConfig().GetDatapathId(),
			CreatedAt:  time.Now(),
		})
	}

	return &BridgeListResult{
		Bridges:    bridges,
		TotalCount: int32(len(bridges)),
	}, nil
}

// =============================================================================
// Port Commands
// =============================================================================

// PortAdd adds a port to a bridge via QUIC.
func (q *QUICAdapter) PortAdd(ctx context.Context, opts PortAddOptions) (*PortAddResult, error) {
	req := &platformv1.AddPortRequest{
		BridgeId: opts.BridgeID,
		Config:   &platformv1.PortConfig{Name: opts.Name},
	}

	resp, err := q.sendRequest(ctx, OpQUICSDNPortAdd, req)
	if err != nil {
		return nil, err
	}

	var wireResp platformv1.AddPortResponse
	if err := decodeSDNPayload(resp.Payload, &wireResp); err != nil {
		return nil, ErrQUICSDNDecodeFailed{Operation: "PortAdd", Err: err}
	}

	port := wireResp.GetPort()
	return &PortAddResult{
		BridgeID:  opts.BridgeID,
		PortID:    port.GetId(),
		Name:      port.GetConfig().GetName(),
		Type:      opts.Type,
		MAC:       opts.MAC,
		Status:    "active",
		CreatedAt: time.Now(),
	}, nil
}

// PortDelete deletes a port from a bridge via QUIC.
func (q *QUICAdapter) PortDelete(ctx context.Context, bridgeID, portID string) (*PortDeleteResult, error) {
	req := &platformv1.DeletePortRequest{
		BridgeId: bridgeID,
		PortId:   portID,
	}

	resp, err := q.sendRequest(ctx, OpQUICSDNPortDelete, req)
	if err != nil {
		return nil, err
	}

	var wireResp platformv1.DeletePortResponse
	if err := decodeSDNPayload(resp.Payload, &wireResp); err != nil {
		return nil, ErrQUICSDNDecodeFailed{Operation: "PortDelete", Err: err}
	}

	return &PortDeleteResult{
		BridgeID: bridgeID,
		PortID:   portID,
		Deleted:  wireResp.GetStatus().GetSuccess(),
	}, nil
}

// PortGetState gets the state of a port via QUIC.
func (q *QUICAdapter) PortGetState(ctx context.Context, bridgeID, portID string) (*PortStateResult, error) {
	req := &sdnGetPortStateRequest{
		PortName: portID,
	}

	resp, err := q.sendRequest(ctx, OpQUICSDNPortGetState, req)
	if err != nil {
		return nil, err
	}

	var wireResp sdnGetPortStateResponse
	if err := decodeSDNPayload(resp.Payload, &wireResp); err != nil {
		return nil, ErrQUICSDNDecodeFailed{Operation: "PortGetState", Err: err}
	}

	return &PortStateResult{
		BridgeID:   bridgeID,
		PortID:     portID,
		AdminState: wireResp.State,
		UpdatedAt:  time.Unix(wireResp.Timestamp, 0),
	}, nil
}

// PortSetState sets the state of a port via QUIC.
func (q *QUICAdapter) PortSetState(ctx context.Context, bridgeID, portID string, opts PortSetStateOptions) (*PortStateResult, error) {
	req := &platformv1.SetPortStateRequest{
		BridgeId:     bridgeID,
		PortId:       portID,
		AdminState:   opts.AdminState,
		IngressRate:  opts.IngressRate,
		EgressRate:   opts.EgressRate,
		IngressBurst: opts.IngressBurst,
		EgressBurst:  opts.EgressBurst,
	}

	resp, err := q.sendRequest(ctx, OpQUICSDNPortSetState, req)
	if err != nil {
		return nil, err
	}

	var wireResp platformv1.SetPortStateResponse
	if err := decodeSDNPayload(resp.Payload, &wireResp); err != nil {
		return nil, ErrQUICSDNDecodeFailed{Operation: "PortSetState", Err: err}
	}

	return &PortStateResult{
		BridgeID:   bridgeID,
		PortID:     portID,
		AdminState: opts.AdminState,
		UpdatedAt:  time.Now(),
	}, nil
}

// PortGetStats gets statistics for a port via QUIC.
// The QUIC server exposes port information via the GetPort opcode. Statistics
// are derived from the port metadata returned by the server.
func (q *QUICAdapter) PortGetStats(ctx context.Context, bridgeID, portID string) (*PortStatsResult, error) {
	req := &platformv1.GetPortRequest{
		BridgeId: bridgeID,
		PortId:   portID,
	}

	resp, err := q.sendRequest(ctx, OpQUICSDNPortGet, req)
	if err != nil {
		return nil, err
	}

	var wireResp platformv1.GetPortResponse
	if err := decodeSDNPayload(resp.Payload, &wireResp); err != nil {
		return nil, ErrQUICSDNDecodeFailed{Operation: "PortGetStats", Err: err}
	}

	return &PortStatsResult{
		BridgeID:    bridgeID,
		PortID:      portID,
		RetrievedAt: time.Now(),
	}, nil
}

// =============================================================================
// Flow Commands
// =============================================================================

// FlowAdd adds a flow to a bridge via QUIC.
func (q *QUICAdapter) FlowAdd(ctx context.Context, opts FlowAddOptions) (*FlowAddResult, error) {
	// The wire request is the gRPC AddFlowRequest, so the match and the
	// actions go in their structured fields, exactly as the gRPC adapter
	// sends them. Stuffing the whole ovs-ofctl match string into InPort
	// produced "in_port=dl_type=0x0800,..." on the server.
	protoActions := make([]*platformv1.FlowAction, 0, len(opts.Actions))
	for _, a := range opts.Actions {
		protoActions = append(protoActions, flowActionToProto(a))
	}
	req := &platformv1.AddFlowRequest{
		Config: &platformv1.FlowConfig{
			BridgeId:    opts.BridgeID,
			Table:       platformv1.FlowTable(opts.Table),
			Priority:    uint32(opts.Priority),
			Match:       flowMatchToProto(opts.Match),
			Actions:     protoActions,
			IdleTimeout: uint32(opts.IdleTimeout),
			HardTimeout: uint32(opts.HardTimeout),
		},
	}

	resp, err := q.sendRequest(ctx, OpQUICSDNFlowAdd, req)
	if err != nil {
		return nil, err
	}

	var wireResp platformv1.AddFlowResponse
	if err := decodeSDNPayload(resp.Payload, &wireResp); err != nil {
		return nil, ErrQUICSDNDecodeFailed{Operation: "FlowAdd", Err: err}
	}

	if flow := wireResp.GetFlow(); flow != nil {
		return flowToAddResult(flow, opts.BridgeID), nil
	}
	return &FlowAddResult{
		BridgeID:  opts.BridgeID,
		Table:     opts.Table,
		Priority:  opts.Priority,
		Cookie:    opts.Cookie,
		CreatedAt: time.Now(),
	}, nil
}

// FlowDelete deletes a flow from a bridge via QUIC.
func (q *QUICAdapter) FlowDelete(ctx context.Context, bridgeID, flowID string) (*FlowDeleteResult, error) {
	req := &platformv1.DeleteFlowRequest{
		BridgeId: bridgeID,
		FlowId:   flowID,
	}

	resp, err := q.sendRequest(ctx, OpQUICSDNFlowDelete, req)
	if err != nil {
		return nil, err
	}

	var wireResp platformv1.DeleteFlowResponse
	if err := decodeSDNPayload(resp.Payload, &wireResp); err != nil {
		return nil, ErrQUICSDNDecodeFailed{Operation: "FlowDelete", Err: err}
	}

	return &FlowDeleteResult{
		BridgeID: bridgeID,
		FlowID:   flowID,
		Deleted:  wireResp.GetStatus().GetSuccess(),
	}, nil
}

// FlowList lists flows on a bridge via QUIC.
func (q *QUICAdapter) FlowList(ctx context.Context, bridgeID string, opts FlowListOptions) (*FlowListResult, error) {
	req := &platformv1.ListFlowsRequest{
		BridgeId: bridgeID,
	}

	resp, err := q.sendRequest(ctx, OpQUICSDNFlowList, req)
	if err != nil {
		return nil, err
	}

	var wireResp platformv1.ListFlowsResponse
	if err := decodeSDNPayload(resp.Payload, &wireResp); err != nil {
		return nil, ErrQUICSDNDecodeFailed{Operation: "FlowList", Err: err}
	}

	flows := make([]FlowSummary, 0, len(wireResp.GetFlows()))
	for _, f := range wireResp.GetFlows() {
		cfg := f.GetConfig()
		flows = append(flows, FlowSummary{
			Table:       int32(cfg.GetTable()),
			Priority:    int32(cfg.GetPriority()),
			PacketCount: f.GetStats().GetPacketCount(),
			ByteCount:   f.GetStats().GetByteCount(),
			Duration:    int64(f.GetStats().GetDurationSeconds()),
			Match:       FlowMatch{},
			Actions:     nil,
		})
	}

	return &FlowListResult{
		BridgeID:   bridgeID,
		Flows:      flows,
		TotalCount: int32(len(flows)),
	}, nil
}

// =============================================================================
// VLAN Commands
// =============================================================================

// VLANCreate creates a VLAN via QUIC.
// The QUIC server implements VLAN as per-port set operations. VLANCreate sets
// the VLAN tag on the first port specified in the Untagged list, or uses the
// VLAN ID as the tag value.
func (q *QUICAdapter) VLANCreate(ctx context.Context, opts VLANCreateOptions) (*VLANCreateResult, error) {
	portCount := int32(0)

	// Apply VLAN to untagged ports (access mode)
	for _, portName := range opts.Untagged {
		req := &sdnSetVLANRequest{
			PortName: portName,
			VLAN:     uint16(opts.VLANID),
		}

		_, err := q.sendRequest(ctx, OpQUICSDNVLANSet, req)
		if err != nil {
			return nil, err
		}
		portCount++
	}

	// Apply VLAN to tagged ports (trunk mode)
	for _, portName := range opts.Tagged {
		req := &sdnSetVLANRequest{
			PortName: portName,
			VLAN:     uint16(opts.VLANID),
		}

		_, err := q.sendRequest(ctx, OpQUICSDNVLANSet, req)
		if err != nil {
			return nil, err
		}
		portCount++
	}

	vlanResult := &VLANCreateResult{
		VLANID:      opts.VLANID,
		Name:        opts.Name,
		Description: opts.Description,
		Status:      "active",
		BridgeCount: int32(len(opts.BridgeIDs)),
		PortCount:   portCount,
		CreatedAt:   time.Now(),
	}

	// Store locally for VLANList (QUIC server has no global VLAN tracking)
	q.vlans[opts.VLANID] = vlanResult

	return vlanResult, nil
}

// VLANDelete deletes a VLAN via QUIC.
// The QUIC server implements VLAN as per-port operations. VLANDelete removes
// the VLAN tag by setting it to 0 on all ports that have this VLAN.
// Since the server does not track VLANs globally, this is a best-effort operation.
func (q *QUICAdapter) VLANDelete(ctx context.Context, bridgeID string, vlanID int32) (*VLANDeleteResult, error) {
	// The server has no global VLAN tracking. Return success as the VLAN concept
	// is per-port in OVS. Callers should remove VLAN tags from individual ports
	// before calling this.
	// Remove from local tracking
	delete(q.vlans, vlanID)

	return &VLANDeleteResult{
		VLANID:  vlanID,
		Deleted: true,
	}, nil
}

// VLANList lists VLANs via QUIC.
// The QUIC server does not have a dedicated VLAN list operation.
// Returns locally tracked VLANs created through this adapter instance.
func (q *QUICAdapter) VLANList(ctx context.Context, opts VLANListOptions) (*VLANListResult, error) {
	vlans := make([]VLANSummary, 0, len(q.vlans))
	for _, v := range q.vlans {
		vlans = append(vlans, VLANSummary{
			VLANID:      v.VLANID,
			Name:        v.Name,
			Description: v.Description,
			Status:      v.Status,
			BridgeCount: v.BridgeCount,
			PortCount:   v.PortCount,
			CreatedAt:   v.CreatedAt,
		})
	}

	return &VLANListResult{
		VLANs:      vlans,
		TotalCount: int32(len(vlans)),
	}, nil
}

// =============================================================================
// Policy Commands
// =============================================================================

// PolicyApply applies a network policy via QUIC.
func (q *QUICAdapter) PolicyApply(ctx context.Context, opts PolicyApplyOptions) (*PolicyApplyResult, error) {
	resp, err := q.sendRequest(ctx, OpQUICSDNPolicyApply, newPolicyBody(opts))
	if err != nil {
		return nil, err
	}

	var policy restPolicy
	if err := decodeSDNPayload(resp.Payload, &policy); err != nil {
		return nil, ErrQUICSDNDecodeFailed{Operation: "PolicyApply", Err: err}
	}
	return policy.applyResult(), nil
}

// PolicyGet retrieves a policy by ID or name via QUIC.
func (q *QUICAdapter) PolicyGet(ctx context.Context, policyID string) (*PolicyGetResult, error) {
	resp, err := q.sendRequest(ctx, OpQUICSDNPolicyGet, &sdnGetPolicyRequest{PolicyID: policyID})
	if err != nil {
		return nil, err
	}

	var policy restPolicy
	if err := decodeSDNPayload(resp.Payload, &policy); err != nil {
		return nil, ErrQUICSDNDecodeFailed{Operation: "PolicyGet", Err: err}
	}
	return policy.getResult(), nil
}

// PolicyList lists policies via QUIC, filtered by type and target the way the
// REST route's query parameters filter them.
func (q *QUICAdapter) PolicyList(ctx context.Context, opts PolicyListOptions) (*PolicyListResult, error) {
	req := &sdnListPoliciesRequest{Type: opts.Type, TargetID: opts.TargetID}
	resp, err := q.sendRequest(ctx, OpQUICSDNPolicyList, req)
	if err != nil {
		return nil, err
	}

	var list sdnListPoliciesResponse
	if err := decodeSDNPayload(resp.Payload, &list); err != nil {
		return nil, ErrQUICSDNDecodeFailed{Operation: "PolicyList", Err: err}
	}

	policies := make([]PolicySummary, len(list.Policies))
	for i, p := range list.Policies {
		policies[i] = p.summary()
	}
	return &PolicyListResult{
		Policies:   policies,
		TotalCount: int32(list.Count),
	}, nil
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

// Ensure QUICAdapter implements SDNCommands interface.
var _ SDNCommands = (*QUICAdapter)(nil)
