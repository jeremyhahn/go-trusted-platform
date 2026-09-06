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

// Package pxe provides integration test adapters for PXE provisioning services.
// This file implements the PXECommands interface using QUIC.

//go:build integration

package pxe

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"sync"
	"time"

	"github.com/jeremyhahn/go-codec"
	"github.com/jeremyhahn/go-codec/pkg/factory"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	quicgo "github.com/quic-go/quic-go"
)

// =============================================================================
// QUIC Constants
// =============================================================================

const (
	// quicTimeout is the default timeout for QUIC operations.
	quicTimeout = 30 * time.Second

	// quicMaxIdleTimeout is the default max idle timeout for connections.
	quicMaxIdleTimeout = 60 * time.Second

	// quicMaxPayloadSize is the maximum payload size (16MB).
	quicMaxPayloadSize uint32 = 16 * 1024 * 1024

	// quicMaxTokenSize is the maximum token size (8KB).
	quicMaxTokenSize uint16 = 8 * 1024
)

// QUIC status codes.
const (
	quicStatusOK byte = 0x00
)

// PXE QUIC opcodes matching server-side definitions in pkg/api/quic/protocol.go
// and pkg/api/daemon/quic_pxe.go.
const (
	// Primary PXE Operations (0xEC-0xEF)
	opPXEListDevices    byte = 0xEC
	opPXEGetDevice      byte = 0xED
	opPXERegisterDevice byte = 0xEE
	opPXEUpdateState    byte = 0xEF

	// Extended PXE Operations (0xFC-0xFF)
	opPXEAuthorize    byte = 0xFC
	opPXEQuarantine   byte = 0xFD
	opPXERetry        byte = 0xFE
	opPXERemoveDevice byte = 0xFF

	// PXE Extended Opcodes (two-byte opcode space, currently shares range
	// with other subsystems so routing may not work for all ops)
	opPXEStatus            byte = 0x00
	opPXEGetDeviceByMAC    byte = 0x04
	opPXESetDeviceEnrolled byte = 0x05
	opPXEGetEvents         byte = 0x06
)

// =============================================================================
// QUIC Error Types
// =============================================================================

// ErrQUICConnectionFailed indicates a QUIC connection failure.
type ErrQUICConnectionFailed struct {
	Endpoint string
	Err      error
}

func (e ErrQUICConnectionFailed) Error() string {
	return fmt.Sprintf("QUIC connection to %s failed: %v", e.Endpoint, e.Err)
}

func (e ErrQUICConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrQUICClientClosed indicates the QUIC client has been closed.
type ErrQUICClientClosed struct{}

func (e ErrQUICClientClosed) Error() string {
	return "QUIC client is closed"
}

// ErrQUICEncodeFailed indicates payload encoding failed.
type ErrQUICEncodeFailed struct {
	Operation string
	Err       error
}

func (e ErrQUICEncodeFailed) Error() string {
	return fmt.Sprintf("QUIC encode failed for %s: %v", e.Operation, e.Err)
}

func (e ErrQUICEncodeFailed) Unwrap() error {
	return e.Err
}

// ErrQUICDecodeFailed indicates payload decoding failed.
type ErrQUICDecodeFailed struct {
	Operation string
	Err       error
}

func (e ErrQUICDecodeFailed) Error() string {
	return fmt.Sprintf("QUIC decode failed for %s: %v", e.Operation, e.Err)
}

func (e ErrQUICDecodeFailed) Unwrap() error {
	return e.Err
}

// ErrQUICStreamFailed indicates a QUIC stream operation failed.
type ErrQUICStreamFailed struct {
	Operation string
	Err       error
}

func (e ErrQUICStreamFailed) Error() string {
	return fmt.Sprintf("QUIC stream %s failed: %v", e.Operation, e.Err)
}

func (e ErrQUICStreamFailed) Unwrap() error {
	return e.Err
}

// ErrQUICRequestFailed indicates a QUIC request returned a non-OK status.
type ErrQUICRequestFailed struct {
	Operation string
	Status    byte
	Message   string
}

func (e ErrQUICRequestFailed) Error() string {
	return fmt.Sprintf("QUIC request %s failed (status 0x%02X): %s", e.Operation, e.Status, e.Message)
}

// =============================================================================
// Wire Protocol Types
// =============================================================================

type quicRequest struct {
	Opcode  byte
	Token   string
	Payload []byte
}

type quicResponse struct {
	Status  byte
	Payload []byte
}

// =============================================================================
// Request/Response Payload Types (MessagePack encoded)
// These MUST match the server-side types in pkg/api/daemon/quic_pxe.go
// =============================================================================

type quicPXEDevice struct {
	ID                string            `codec:"id"`
	MACAddress        string            `codec:"mac_address"`
	PortID            string            `codec:"port_id"`
	State             string            `codec:"state"`
	StateReason       string            `codec:"state_reason,omitempty"`
	CertificateSerial string            `codec:"certificate_serial,omitempty"`
	CurrentVLAN       uint16            `codec:"current_vlan"`
	TargetVLAN        uint16            `codec:"target_vlan"`
	CreatedAt         int64             `codec:"created_at"`
	UpdatedAt         int64             `codec:"updated_at"`
	StateChangedAt    int64             `codec:"state_changed_at"`
	RetryCount        int               `codec:"retry_count"`
	ProfileID         string            `codec:"profile_id,omitempty"`
	ProfileName       string            `codec:"profile_name,omitempty"`
	Metadata          map[string]string `codec:"metadata,omitempty"`
}

type quicPXEListDevicesRequest struct {
	State      string `codec:"state,omitempty"`
	MACAddress string `codec:"mac_address,omitempty"`
	VLAN       uint16 `codec:"vlan,omitempty"`
	Limit      int    `codec:"limit,omitempty"`
	Offset     int    `codec:"offset,omitempty"`
}

type quicPXEListDevicesResponse struct {
	Devices   []*quicPXEDevice `codec:"devices"`
	Total     int              `codec:"total"`
	Timestamp int64            `codec:"timestamp"`
}

type quicPXEGetDeviceRequest struct {
	DeviceID   string `codec:"device_id,omitempty"`
	MACAddress string `codec:"mac_address,omitempty"`
}

type quicPXEGetDeviceResponse struct {
	Device    *quicPXEDevice `codec:"device"`
	Timestamp int64          `codec:"timestamp"`
}

type quicPXEGetDeviceByMACRequest struct {
	MACAddress string `codec:"mac_address"`
}

type quicPXEGetDeviceByMACResponse struct {
	Device    *quicPXEDevice `codec:"device"`
	Timestamp int64          `codec:"timestamp"`
}

type quicPXERegisterDeviceRequest struct {
	MACAddress string `codec:"mac_address"`
	PortID     string `codec:"port_id"`
}

type quicPXERegisterDeviceResponse struct {
	Device    *quicPXEDevice `codec:"device"`
	Timestamp int64          `codec:"timestamp"`
}

type quicPXEUpdateStateRequest struct {
	DeviceID string `codec:"device_id"`
	State    string `codec:"state"`
	Reason   string `codec:"reason,omitempty"`
}

type quicPXEUpdateStateResponse struct {
	DeviceID  string `codec:"device_id"`
	OldState  string `codec:"old_state"`
	NewState  string `codec:"new_state"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

type quicPXESetDeviceEnrolledRequest struct {
	DeviceID          string `codec:"device_id"`
	CertificateSerial string `codec:"certificate_serial"`
}

type quicPXESetDeviceEnrolledResponse struct {
	Device    *quicPXEDevice `codec:"device"`
	Success   bool           `codec:"success"`
	Timestamp int64          `codec:"timestamp"`
}

type quicPXEAuthorizeRequest struct {
	DeviceID   string `codec:"device_id"`
	TargetVLAN uint16 `codec:"target_vlan"`
}

type quicPXEAuthorizeResponse struct {
	DeviceID   string `codec:"device_id"`
	TargetVLAN uint16 `codec:"target_vlan"`
	Success    bool   `codec:"success"`
	Timestamp  int64  `codec:"timestamp"`
}

type quicPXEQuarantineRequest struct {
	DeviceID string `codec:"device_id"`
	Reason   string `codec:"reason"`
}

type quicPXEQuarantineResponse struct {
	DeviceID  string `codec:"device_id"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

type quicPXERetryRequest struct {
	DeviceID string `codec:"device_id"`
}

type quicPXERetryResponse struct {
	DeviceID   string `codec:"device_id"`
	RetryCount int    `codec:"retry_count"`
	Success    bool   `codec:"success"`
	Timestamp  int64  `codec:"timestamp"`
}

type quicPXERemoveDeviceRequest struct {
	DeviceID string `codec:"device_id"`
}

type quicPXERemoveDeviceResponse struct {
	DeviceID  string `codec:"device_id"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

type quicPXEGetEventsRequest struct {
	DeviceID string `codec:"device_id"`
}

type quicPXEEvent struct {
	ID        string            `codec:"id"`
	DeviceID  string            `codec:"device_id"`
	Timestamp int64             `codec:"timestamp"`
	EventType string            `codec:"event_type"`
	FromState string            `codec:"from_state"`
	ToState   string            `codec:"to_state"`
	Details   map[string]string `codec:"details,omitempty"`
	Error     string            `codec:"error,omitempty"`
}

type quicPXEGetEventsResponse struct {
	Events    []*quicPXEEvent `codec:"events"`
	Timestamp int64           `codec:"timestamp"`
}

type quicPXEStatusResponse struct {
	Running          bool   `codec:"running"`
	DeviceCount      int    `codec:"device_count"`
	StartTime        int64  `codec:"start_time"`
	IPXEServerAddr   string `codec:"ipxe_server_addr"`
	QuarantineVLAN   uint16 `codec:"quarantine_vlan"`
	ProvisioningVLAN uint16 `codec:"provisioning_vlan"`
	Timestamp        int64  `codec:"timestamp"`
}

// =============================================================================
// QUIC Adapter Implementation
// =============================================================================

// QUICAdapter implements PXECommands using QUIC calls to platformd.
// This adapter makes QUIC calls to the platformd server for testing
// the QUIC transport layer consistency with other protocol adapters.
type QUICAdapter struct {
	endpoint       string
	conn           *quicgo.Conn
	tlsConfig      *tls.Config
	timeout        time.Duration
	maxIdleTimeout time.Duration

	mu     sync.RWMutex
	closed bool
}

// NewQUICAdapter creates a new QUIC protocol adapter instance.
func NewQUICAdapter() *QUICAdapter {
	endpoint := os.Getenv(EnvPlatformQUICEndpoint)
	if endpoint == "" {
		endpoint = GetServiceEndpoints().PlatformQUIC
	}

	return &QUICAdapter{
		endpoint:       endpoint,
		timeout:        quicTimeout,
		maxIdleTimeout: quicMaxIdleTimeout,
		tlsConfig:      helpers.QUICTLSConfig(),
	}
}

// Name returns the protocol adapter identifier.
func (q *QUICAdapter) Name() string {
	return "QUIC"
}

// Setup establishes the QUIC connection to the platform endpoint.
func (q *QUICAdapter) Setup(ctx context.Context) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.closed {
		return ErrQUICClientClosed{}
	}

	connCtx, cancel := context.WithTimeout(ctx, q.timeout)
	defer cancel()

	quicConfig := &quicgo.Config{
		MaxIdleTimeout:  q.maxIdleTimeout,
		KeepAlivePeriod: 15 * time.Second,
	}

	conn, err := quicgo.DialAddr(connCtx, q.endpoint, q.tlsConfig, quicConfig)
	if err != nil {
		return ErrQUICConnectionFailed{Endpoint: q.endpoint, Err: err}
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

func (q *QUICAdapter) sendRequest(ctx context.Context, opcode byte, payload interface{}) (*quicResponse, error) {
	q.mu.RLock()
	if q.closed {
		q.mu.RUnlock()
		return nil, ErrQUICClientClosed{}
	}
	conn := q.conn
	q.mu.RUnlock()

	var payloadBytes []byte
	if payload != nil {
		var err error
		payloadBytes, err = quicEncodePayload(payload)
		if err != nil {
			return nil, ErrQUICEncodeFailed{Operation: pxeOpcodeToString(opcode), Err: err}
		}
	}

	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, ErrQUICStreamFailed{Operation: "OpenStream", Err: err}
	}
	defer stream.Close()

	req := &quicRequest{
		Opcode:  opcode,
		Payload: payloadBytes,
	}

	if err := quicWriteRequest(stream, req); err != nil {
		return nil, ErrQUICStreamFailed{Operation: "WriteRequest", Err: err}
	}

	resp, err := quicReadResponse(stream)
	if err != nil {
		return nil, ErrQUICStreamFailed{Operation: "ReadResponse", Err: err}
	}

	if resp.Status != quicStatusOK {
		errMsg := string(resp.Payload)
		if errMsg == "" {
			errMsg = "unknown error"
		}
		return nil, ErrQUICRequestFailed{
			Operation: pxeOpcodeToString(opcode),
			Status:    resp.Status,
			Message:   errMsg,
		}
	}

	return resp, nil
}

func quicWriteRequest(w io.Writer, req *quicRequest) error {
	payloadLen := uint32(len(req.Payload))
	if payloadLen > quicMaxPayloadSize {
		return fmt.Errorf("payload size %d exceeds maximum %d", payloadLen, quicMaxPayloadSize)
	}

	tokenLen := uint16(len(req.Token))
	if tokenLen > quicMaxTokenSize {
		return fmt.Errorf("token size %d exceeds maximum %d", tokenLen, quicMaxTokenSize)
	}

	if _, err := w.Write([]byte{req.Opcode}); err != nil {
		return fmt.Errorf("failed to write opcode: %w", err)
	}

	tokenLenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(tokenLenBuf, tokenLen)
	if _, err := w.Write(tokenLenBuf); err != nil {
		return fmt.Errorf("failed to write token length: %w", err)
	}

	if tokenLen > 0 {
		if _, err := w.Write([]byte(req.Token)); err != nil {
			return fmt.Errorf("failed to write token: %w", err)
		}
	}

	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, payloadLen)
	if _, err := w.Write(lenBuf); err != nil {
		return fmt.Errorf("failed to write payload length: %w", err)
	}

	if payloadLen > 0 {
		if _, err := w.Write(req.Payload); err != nil {
			return fmt.Errorf("failed to write payload: %w", err)
		}
	}

	return nil
}

func quicReadResponse(r io.Reader) (*quicResponse, error) {
	statusBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, statusBuf); err != nil {
		return nil, fmt.Errorf("failed to read status: %w", err)
	}

	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, fmt.Errorf("failed to read payload length: %w", err)
	}
	payloadLen := binary.BigEndian.Uint32(lenBuf)

	if payloadLen > quicMaxPayloadSize {
		return nil, fmt.Errorf("payload size %d exceeds maximum %d", payloadLen, quicMaxPayloadSize)
	}

	var payload []byte
	if payloadLen > 0 {
		payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, fmt.Errorf("failed to read payload: %w", err)
		}
	}

	return &quicResponse{
		Status:  statusBuf[0],
		Payload: payload,
	}, nil
}

// quicCodecType is the codec type used for payload encoding/decoding.
var quicCodecType = codec.MsgPack

func quicEncodePayload(entity interface{}) ([]byte, error) {
	if entity == nil {
		return nil, nil
	}

	c, err := factory.New[any](quicCodecType)
	if err != nil {
		return nil, fmt.Errorf("failed to create codec: %w", err)
	}

	data, err := c.Marshal(entity)
	if err != nil {
		return nil, fmt.Errorf("failed to encode payload: %w", err)
	}

	return data, nil
}

func quicDecodePayload(data []byte, entity interface{}) error {
	if len(data) == 0 {
		return nil
	}

	if entity == nil {
		return fmt.Errorf("entity cannot be nil")
	}

	c, err := factory.New[any](quicCodecType)
	if err != nil {
		return fmt.Errorf("failed to create codec: %w", err)
	}

	if err := c.Unmarshal(data, &entity); err != nil {
		return fmt.Errorf("failed to decode payload: %w", err)
	}

	return nil
}

func pxeOpcodeToString(opcode byte) string {
	opcodeNames := map[byte]string{
		opPXEListDevices:       "PXEListDevices",
		opPXEGetDevice:         "PXEGetDevice",
		opPXERegisterDevice:    "PXERegisterDevice",
		opPXEUpdateState:       "PXEUpdateState",
		opPXEAuthorize:         "PXEAuthorize",
		opPXEQuarantine:        "PXEQuarantine",
		opPXERetry:             "PXERetry",
		opPXERemoveDevice:      "PXERemoveDevice",
		opPXEStatus:            "PXEStatus",
		opPXEGetDeviceByMAC:    "PXEGetDeviceByMAC",
		opPXESetDeviceEnrolled: "PXESetDeviceEnrolled",
		opPXEGetEvents:         "PXEGetEvents",
	}
	if name, ok := opcodeNames[opcode]; ok {
		return name
	}
	return fmt.Sprintf("Unknown(0x%02X)", opcode)
}

// =============================================================================
// Conversion Helpers
// =============================================================================

func quicDeviceToGetResult(d *quicPXEDevice) *GetDeviceResult {
	if d == nil {
		return nil
	}
	return &GetDeviceResult{
		ID:                d.ID,
		MACAddress:        d.MACAddress,
		PortID:            d.PortID,
		State:             d.State,
		StateReason:       d.StateReason,
		CertificateSerial: d.CertificateSerial,
		CurrentVLAN:       d.CurrentVLAN,
		TargetVLAN:        d.TargetVLAN,
		RetryCount:        d.RetryCount,
		CreatedAt:         time.Unix(d.CreatedAt, 0),
		UpdatedAt:         time.Unix(d.UpdatedAt, 0),
		StateChangedAt:    time.Unix(d.StateChangedAt, 0),
	}
}

func quicDeviceToRegisterResult(d *quicPXEDevice) *RegisterDeviceResult {
	if d == nil {
		return nil
	}
	return &RegisterDeviceResult{
		ID:          d.ID,
		MACAddress:  d.MACAddress,
		PortID:      d.PortID,
		State:       d.State,
		StateReason: d.StateReason,
		CurrentVLAN: d.CurrentVLAN,
		CreatedAt:   time.Unix(d.CreatedAt, 0),
	}
}

// =============================================================================
// Device Management Commands
// =============================================================================

// RegisterDevice registers a new device via QUIC.
func (q *QUICAdapter) RegisterDevice(ctx context.Context, opts RegisterDeviceOptions) (*RegisterDeviceResult, error) {
	req := &quicPXERegisterDeviceRequest{
		MACAddress: opts.MACAddress,
		PortID:     opts.PortID,
	}

	resp, err := q.sendRequest(ctx, opPXERegisterDevice, req)
	if err != nil {
		return nil, err
	}

	var result quicPXERegisterDeviceResponse
	if err := quicDecodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "RegisterDevice", Err: err}
	}

	return quicDeviceToRegisterResult(result.Device), nil
}

// GetDevice retrieves device information via QUIC.
func (q *QUICAdapter) GetDevice(ctx context.Context, deviceID string) (*GetDeviceResult, error) {
	req := &quicPXEGetDeviceRequest{
		DeviceID: deviceID,
	}

	resp, err := q.sendRequest(ctx, opPXEGetDevice, req)
	if err != nil {
		return nil, err
	}

	var result quicPXEGetDeviceResponse
	if err := quicDecodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "GetDevice", Err: err}
	}

	return quicDeviceToGetResult(result.Device), nil
}

// GetDeviceByMAC retrieves a device by MAC address via QUIC.
func (q *QUICAdapter) GetDeviceByMAC(ctx context.Context, mac string) (*GetDeviceResult, error) {
	req := &quicPXEGetDeviceByMACRequest{
		MACAddress: mac,
	}

	resp, err := q.sendRequest(ctx, opPXEGetDeviceByMAC, req)
	if err != nil {
		return nil, err
	}

	var result quicPXEGetDeviceByMACResponse
	if err := quicDecodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "GetDeviceByMAC", Err: err}
	}

	return quicDeviceToGetResult(result.Device), nil
}

// ListDevices lists devices via QUIC.
func (q *QUICAdapter) ListDevices(ctx context.Context, opts ListDevicesOptions) (*ListDevicesResult, error) {
	req := &quicPXEListDevicesRequest{
		State:      opts.State,
		MACAddress: opts.MACAddress,
		VLAN:       opts.VLAN,
		Limit:      int(opts.Limit),
		Offset:     int(opts.Offset),
	}

	resp, err := q.sendRequest(ctx, opPXEListDevices, req)
	if err != nil {
		return nil, err
	}

	var result quicPXEListDevicesResponse
	if err := quicDecodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "ListDevices", Err: err}
	}

	listResult := &ListDevicesResult{
		TotalCount: int32(result.Total),
	}

	for _, d := range result.Devices {
		listResult.Devices = append(listResult.Devices, DeviceSummary{
			ID:          d.ID,
			MACAddress:  d.MACAddress,
			PortID:      d.PortID,
			State:       d.State,
			CurrentVLAN: d.CurrentVLAN,
			CreatedAt:   time.Unix(d.CreatedAt, 0),
			UpdatedAt:   time.Unix(d.UpdatedAt, 0),
		})
	}

	return listResult, nil
}

// RemoveDevice removes a device via QUIC.
func (q *QUICAdapter) RemoveDevice(ctx context.Context, deviceID string) (*RemoveDeviceResult, error) {
	req := &quicPXERemoveDeviceRequest{
		DeviceID: deviceID,
	}

	resp, err := q.sendRequest(ctx, opPXERemoveDevice, req)
	if err != nil {
		return nil, err
	}

	var result quicPXERemoveDeviceResponse
	if err := quicDecodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "RemoveDevice", Err: err}
	}

	return &RemoveDeviceResult{
		ID:      result.DeviceID,
		Removed: result.Success,
	}, nil
}

// =============================================================================
// State Management Commands
// =============================================================================

// UpdateDeviceState updates device state via QUIC.
func (q *QUICAdapter) UpdateDeviceState(ctx context.Context, opts UpdateStateOptions) (*UpdateStateResult, error) {
	req := &quicPXEUpdateStateRequest{
		DeviceID: opts.DeviceID,
		State:    opts.State,
		Reason:   opts.Reason,
	}

	resp, err := q.sendRequest(ctx, opPXEUpdateState, req)
	if err != nil {
		return nil, err
	}

	var result quicPXEUpdateStateResponse
	if err := quicDecodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "UpdateDeviceState", Err: err}
	}

	return &UpdateStateResult{
		ID:        result.DeviceID,
		FromState: result.OldState,
		ToState:   result.NewState,
		UpdatedAt: time.Unix(result.Timestamp, 0),
	}, nil
}

// SetDeviceEnrolled sets a device as enrolled via QUIC.
func (q *QUICAdapter) SetDeviceEnrolled(ctx context.Context, deviceID, certSerial string) (*SetEnrolledResult, error) {
	req := &quicPXESetDeviceEnrolledRequest{
		DeviceID:          deviceID,
		CertificateSerial: certSerial,
	}

	resp, err := q.sendRequest(ctx, opPXESetDeviceEnrolled, req)
	if err != nil {
		return nil, err
	}

	var result quicPXESetDeviceEnrolledResponse
	if err := quicDecodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "SetDeviceEnrolled", Err: err}
	}

	enrolled := &SetEnrolledResult{
		UpdatedAt: time.Unix(result.Timestamp, 0),
	}

	if result.Device != nil {
		enrolled.ID = result.Device.ID
		enrolled.State = result.Device.State
		enrolled.CertificateSerial = result.Device.CertificateSerial
	}

	return enrolled, nil
}

// AuthorizeDevice authorizes a device via QUIC.
func (q *QUICAdapter) AuthorizeDevice(ctx context.Context, deviceID string, targetVLAN uint16) (*AuthorizeResult, error) {
	req := &quicPXEAuthorizeRequest{
		DeviceID:   deviceID,
		TargetVLAN: targetVLAN,
	}

	resp, err := q.sendRequest(ctx, opPXEAuthorize, req)
	if err != nil {
		return nil, err
	}

	var result quicPXEAuthorizeResponse
	if err := quicDecodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "AuthorizeDevice", Err: err}
	}

	return &AuthorizeResult{
		ID:         result.DeviceID,
		State:      StateAuthorized,
		TargetVLAN: result.TargetVLAN,
		UpdatedAt:  time.Unix(result.Timestamp, 0),
	}, nil
}

// QuarantineDevice quarantines a device via QUIC.
func (q *QUICAdapter) QuarantineDevice(ctx context.Context, deviceID, reason string) (*QuarantineResult, error) {
	req := &quicPXEQuarantineRequest{
		DeviceID: deviceID,
		Reason:   reason,
	}

	resp, err := q.sendRequest(ctx, opPXEQuarantine, req)
	if err != nil {
		return nil, err
	}

	var result quicPXEQuarantineResponse
	if err := quicDecodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "QuarantineDevice", Err: err}
	}

	return &QuarantineResult{
		ID:        result.DeviceID,
		State:     StateQuarantined,
		Reason:    reason,
		UpdatedAt: time.Unix(result.Timestamp, 0),
	}, nil
}

// RetryDevice retries a device via QUIC.
func (q *QUICAdapter) RetryDevice(ctx context.Context, deviceID string) (*RetryResult, error) {
	req := &quicPXERetryRequest{
		DeviceID: deviceID,
	}

	resp, err := q.sendRequest(ctx, opPXERetry, req)
	if err != nil {
		return nil, err
	}

	var result quicPXERetryResponse
	if err := quicDecodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "RetryDevice", Err: err}
	}

	return &RetryResult{
		ID:         result.DeviceID,
		State:      StateDiscovered,
		RetryCount: result.RetryCount,
		UpdatedAt:  time.Unix(result.Timestamp, 0),
	}, nil
}

// =============================================================================
// Event Commands
// =============================================================================

// GetEvents retrieves device events via QUIC.
func (q *QUICAdapter) GetEvents(ctx context.Context, deviceID string) (*GetEventsResult, error) {
	req := &quicPXEGetEventsRequest{
		DeviceID: deviceID,
	}

	resp, err := q.sendRequest(ctx, opPXEGetEvents, req)
	if err != nil {
		return nil, err
	}

	var result quicPXEGetEventsResponse
	if err := quicDecodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "GetEvents", Err: err}
	}

	eventsResult := &GetEventsResult{
		DeviceID: deviceID,
	}

	for _, e := range result.Events {
		eventsResult.Events = append(eventsResult.Events, ProvisioningEventInfo{
			ID:        e.ID,
			DeviceID:  e.DeviceID,
			EventType: e.EventType,
			FromState: e.FromState,
			ToState:   e.ToState,
			Details:   e.Details,
			Error:     e.Error,
			Timestamp: time.Unix(e.Timestamp, 0),
		})
	}

	return eventsResult, nil
}

// =============================================================================
// Service Status Commands
// =============================================================================

// GetStatus retrieves service status via QUIC.
func (q *QUICAdapter) GetStatus(ctx context.Context) (*GetStatusResult, error) {
	resp, err := q.sendRequest(ctx, opPXEStatus, nil)
	if err != nil {
		return nil, err
	}

	var result quicPXEStatusResponse
	if err := quicDecodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "GetStatus", Err: err}
	}

	return &GetStatusResult{
		Running:          result.Running,
		DeviceCount:      result.DeviceCount,
		StartTime:        time.Unix(result.StartTime, 0),
		IPXEServerAddr:   result.IPXEServerAddr,
		QuarantineVLAN:   result.QuarantineVLAN,
		ProvisioningVLAN: result.ProvisioningVLAN,
	}, nil
}

// Ensure QUICAdapter implements PXECommands interface.
var _ PXECommands = (*QUICAdapter)(nil)
