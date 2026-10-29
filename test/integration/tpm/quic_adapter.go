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

//go:build integration

package tpm

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
	quicapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	quicgo "github.com/quic-go/quic-go"
)

// =============================================================================
// QUIC Constants
// =============================================================================

const (
	// DefaultQUICTimeoutTPM is the default timeout for QUIC TPM operations.
	DefaultQUICTimeoutTPM = 30 * time.Second

	// MaxQUICPayloadSizeTPM is the maximum payload size (16MB).
	MaxQUICPayloadSizeTPM uint32 = 16 * 1024 * 1024

	// MaxQUICTokenSizeTPM is the maximum token size (8KB).
	MaxQUICTokenSizeTPM uint16 = 8 * 1024
)

// QUIC status codes.
const (
	QUICStatusOKTPM byte = 0x00
)

// =============================================================================
// Error Types
// =============================================================================

// ErrQUICTPMConnectionFailed indicates a QUIC connection failure.
type ErrQUICTPMConnectionFailed struct {
	Endpoint string
	Err      error
}

func (e ErrQUICTPMConnectionFailed) Error() string {
	return fmt.Sprintf("QUIC TPM connection to %s failed: %v", e.Endpoint, e.Err)
}

func (e ErrQUICTPMConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrQUICTPMRequestFailed indicates a QUIC request failure.
type ErrQUICTPMRequestFailed struct {
	Operation string
	Status    byte
	Message   string
}

func (e ErrQUICTPMRequestFailed) Error() string {
	return fmt.Sprintf("QUIC TPM request %s failed (status 0x%02X): %s", e.Operation, e.Status, e.Message)
}

// ErrQUICTPMEncodeFailed indicates payload encoding failure.
type ErrQUICTPMEncodeFailed struct {
	Operation string
	Err       error
}

func (e ErrQUICTPMEncodeFailed) Error() string {
	return fmt.Sprintf("QUIC TPM encode failed for %s: %v", e.Operation, e.Err)
}

func (e ErrQUICTPMEncodeFailed) Unwrap() error {
	return e.Err
}

// ErrQUICTPMDecodeFailed indicates payload decoding failure.
type ErrQUICTPMDecodeFailed struct {
	Operation string
	Err       error
}

func (e ErrQUICTPMDecodeFailed) Error() string {
	return fmt.Sprintf("QUIC TPM decode failed for %s: %v", e.Operation, e.Err)
}

func (e ErrQUICTPMDecodeFailed) Unwrap() error {
	return e.Err
}

// ErrQUICTPMClientClosed indicates the client is closed.
type ErrQUICTPMClientClosed struct{}

func (e ErrQUICTPMClientClosed) Error() string {
	return "QUIC TPM client is closed"
}

// =============================================================================
// QUIC Wire Protocol Types
// =============================================================================

// quicTPMRequest represents a QUIC protocol request.
type quicTPMRequest struct {
	Opcode  byte
	Token   string
	Payload []byte
}

// quicTPMResponse represents a QUIC protocol response.
type quicTPMResponse struct {
	Status  byte
	Payload []byte
}

// =============================================================================
// QUIC Adapter
// =============================================================================

// QUICAdapter implements TPMCommands using QUIC calls to platformd.
// Uses category opcode 0x99 (OpTPM2Category) with sub-opcodes in payload[0].
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
		timeout:        DefaultQUICTimeoutTPM,
		maxIdleTimeout: 60 * time.Second,
		tlsConfig:      helpers.QUICTLSConfig(),
	}
}

// Name returns the protocol adapter identifier.
func (q *QUICAdapter) Name() string {
	return "QUIC"
}

// Setup establishes the QUIC connection to platformd.
func (q *QUICAdapter) Setup(ctx context.Context) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.closed {
		return ErrQUICTPMClientClosed{}
	}

	connCtx, cancel := context.WithTimeout(ctx, q.timeout)
	defer cancel()

	quicConfig := &quicgo.Config{
		MaxIdleTimeout:  q.maxIdleTimeout,
		KeepAlivePeriod: 15 * time.Second,
	}

	conn, err := quicgo.DialAddr(connCtx, q.endpoint, q.tlsConfig, quicConfig)
	if err != nil {
		return ErrQUICTPMConnectionFailed{Endpoint: q.endpoint, Err: err}
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

// sendCategoryRequest sends a TPM2 category request with a sub-opcode.
// The category opcode is 0x99 and the sub-opcode is prepended to the encoded payload.
func (q *QUICAdapter) sendCategoryRequest(ctx context.Context, subOpcode byte, payload interface{}) (*quicTPMResponse, error) {
	q.mu.RLock()
	if q.closed {
		q.mu.RUnlock()
		return nil, ErrQUICTPMClientClosed{}
	}
	conn := q.conn
	q.mu.RUnlock()

	// Encode payload with sub-opcode prepended
	var payloadBytes []byte
	payloadBytes = append(payloadBytes, subOpcode)

	if payload != nil {
		encoded, err := encodeTPMPayload(payload)
		if err != nil {
			return nil, ErrQUICTPMEncodeFailed{Operation: fmt.Sprintf("sub-opcode 0x%02X", subOpcode), Err: err}
		}
		payloadBytes = append(payloadBytes, encoded...)
	}

	// Open stream
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, ErrQUICTPMConnectionFailed{Endpoint: q.endpoint, Err: err}
	}
	defer stream.Close()

	// Write request using category opcode
	req := &quicTPMRequest{
		Opcode:  quicwire.OpTPM2Category,
		Payload: payloadBytes,
	}

	if err := writeTPMRequest(stream, req); err != nil {
		return nil, err
	}

	// Read response
	resp, err := readTPMResponse(stream)
	if err != nil {
		return nil, err
	}

	// Check status
	if resp.Status != QUICStatusOKTPM {
		errMsg := string(resp.Payload)
		if errMsg == "" {
			errMsg = "unknown error"
		}
		return nil, ErrQUICTPMRequestFailed{
			Operation: fmt.Sprintf("sub-opcode 0x%02X", subOpcode),
			Status:    resp.Status,
			Message:   errMsg,
		}
	}

	return resp, nil
}

// writeTPMRequest writes a request to the QUIC stream.
func writeTPMRequest(w io.Writer, req *quicTPMRequest) error {
	payloadLen := uint32(len(req.Payload))
	if payloadLen > MaxQUICPayloadSizeTPM {
		return fmt.Errorf("payload size %d exceeds maximum %d", payloadLen, MaxQUICPayloadSizeTPM)
	}

	tokenLen := uint16(len(req.Token))
	if tokenLen > MaxQUICTokenSizeTPM {
		return fmt.Errorf("token size %d exceeds maximum %d", tokenLen, MaxQUICTokenSizeTPM)
	}

	// Write opcode
	if _, err := w.Write([]byte{req.Opcode}); err != nil {
		return fmt.Errorf("failed to write opcode: %w", err)
	}

	// Write token length
	tokenLenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(tokenLenBuf, tokenLen)
	if _, err := w.Write(tokenLenBuf); err != nil {
		return fmt.Errorf("failed to write token length: %w", err)
	}

	// Write token
	if tokenLen > 0 {
		if _, err := w.Write([]byte(req.Token)); err != nil {
			return fmt.Errorf("failed to write token: %w", err)
		}
	}

	// Write payload length
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, payloadLen)
	if _, err := w.Write(lenBuf); err != nil {
		return fmt.Errorf("failed to write payload length: %w", err)
	}

	// Write payload
	if payloadLen > 0 {
		if _, err := w.Write(req.Payload); err != nil {
			return fmt.Errorf("failed to write payload: %w", err)
		}
	}

	return nil
}

// readTPMResponse reads a response from the QUIC stream.
func readTPMResponse(r io.Reader) (*quicTPMResponse, error) {
	// Read status
	statusBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, statusBuf); err != nil {
		return nil, fmt.Errorf("failed to read status: %w", err)
	}

	// Read payload length
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, fmt.Errorf("failed to read payload length: %w", err)
	}
	payloadLen := binary.BigEndian.Uint32(lenBuf)

	if payloadLen > MaxQUICPayloadSizeTPM {
		return nil, fmt.Errorf("payload size %d exceeds maximum %d", payloadLen, MaxQUICPayloadSizeTPM)
	}

	// Read payload
	var payload []byte
	if payloadLen > 0 {
		payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, fmt.Errorf("failed to read payload: %w", err)
		}
	}

	return &quicTPMResponse{
		Status:  statusBuf[0],
		Payload: payload,
	}, nil
}

// defaultTPMCodecType is the codec type used for TPM payload encoding/decoding.
var defaultTPMCodecType = codec.MsgPack

// getTPMCodec creates a codec of the default type using the factory.
func getTPMCodec() (codec.Codec[any], error) {
	return factory.New[any](defaultTPMCodecType)
}

// encodeTPMPayload encodes an entity using the configured codec.
func encodeTPMPayload(entity interface{}) ([]byte, error) {
	if entity == nil {
		return nil, nil
	}

	c, err := getTPMCodec()
	if err != nil {
		return nil, fmt.Errorf("failed to create codec: %w", err)
	}

	data, err := c.Marshal(entity)
	if err != nil {
		return nil, fmt.Errorf("failed to encode payload: %w", err)
	}

	return data, nil
}

// decodeTPMPayload decodes a payload using the configured codec.
func decodeTPMPayload(data []byte, entity interface{}) error {
	if len(data) == 0 {
		return nil
	}

	if entity == nil {
		return fmt.Errorf("entity cannot be nil")
	}

	c, err := getTPMCodec()
	if err != nil {
		return fmt.Errorf("failed to create codec: %w", err)
	}

	if err := c.Unmarshal(data, &entity); err != nil {
		return fmt.Errorf("failed to decode payload: %w", err)
	}

	return nil
}

// =============================================================================
// TPM Info Operations
// =============================================================================

// Info retrieves TPM information via QUIC.
func (q *QUICAdapter) Info(ctx context.Context) (*InfoResult, error) {
	resp, err := q.sendCategoryRequest(ctx, quicwire.SubOpTPM2Info, nil)
	if err != nil {
		return nil, err
	}

	var tpmResp quicapi.TPM2InfoResponse
	if err := decodeTPMPayload(resp.Payload, &tpmResp); err != nil {
		return nil, ErrQUICTPMDecodeFailed{Operation: "Info", Err: err}
	}

	result := &InfoResult{
		Version:      tpmResp.Version,
		IsSimulator:  tpmResp.IsSimulator,
		FIPSMode:     tpmResp.FIPSMode,
		MaxNVRAMSize: tpmResp.MaxNVRAMSize,
		PCRBanks:     tpmResp.PCRBanks,
	}

	if tpmResp.Manufacturer != "" {
		result.Manufacturer = &ManufacturerInfo{
			Name:            tpmResp.Manufacturer,
			Model:           tpmResp.Model,
			FirmwareVersion: tpmResp.FWVersion,
		}
	}

	return result, nil
}

// =============================================================================
// TPM Provision Operations
// =============================================================================

// Provision provisions the TPM via QUIC.
func (q *QUICAdapter) Provision(ctx context.Context, opts ProvisionOptions) (*ProvisionResult, error) {
	req := &quicapi.TPM2ProvisionRequest{
		OwnerPassword: opts.OwnerPassword,
	}

	resp, err := q.sendCategoryRequest(ctx, quicwire.SubOpTPM2Provision, req)
	if err != nil {
		return nil, err
	}

	var statusResp quicapi.TPM2StatusResponse
	if err := decodeTPMPayload(resp.Payload, &statusResp); err != nil {
		return nil, ErrQUICTPMDecodeFailed{Operation: "Provision", Err: err}
	}

	return &ProvisionResult{
		Success:    statusResp.Success,
		Message:    statusResp.Message,
		EKCreated:  statusResp.Success,
		SRKCreated: statusResp.Success,
		AKCreated:  statusResp.Success,
	}, nil
}

// =============================================================================
// TPM Clear Operations
// =============================================================================

// Clear clears the TPM via QUIC.
func (q *QUICAdapter) Clear(ctx context.Context, opts ClearOptions) (*ClearResult, error) {
	req := &quicapi.TPM2ClearRequest{
		OwnerPassword: opts.OwnerPassword,
	}

	resp, err := q.sendCategoryRequest(ctx, quicwire.SubOpTPM2Clear, req)
	if err != nil {
		return nil, err
	}

	var statusResp quicapi.TPM2StatusResponse
	if err := decodeTPMPayload(resp.Payload, &statusResp); err != nil {
		return nil, ErrQUICTPMDecodeFailed{Operation: "Clear", Err: err}
	}

	return &ClearResult{
		Success: statusResp.Success,
		Message: statusResp.Message,
	}, nil
}

// =============================================================================
// EK Operations
// =============================================================================

// EKCreate creates an EK via QUIC.
func (q *QUICAdapter) EKCreate(ctx context.Context, opts EKCreateOptions) (*EKCreateResult, error) {
	resp, err := q.sendCategoryRequest(ctx, quicwire.SubOpTPM2CreateEK, nil)
	if err != nil {
		return nil, err
	}

	var keyResp quicapi.TPM2KeyResponse
	if err := decodeTPMPayload(resp.Payload, &keyResp); err != nil {
		return nil, ErrQUICTPMDecodeFailed{Operation: "EKCreate", Err: err}
	}

	return &EKCreateResult{
		Success:   true,
		Handle:    keyResp.Handle,
		Algorithm: keyResp.Algorithm,
		PublicKey: keyResp.PublicKey,
		CreatedAt: time.Now(),
	}, nil
}

// EKInfo retrieves EK information via QUIC.
func (q *QUICAdapter) EKInfo(ctx context.Context, handle uint32) (*EKInfoResult, error) {
	resp, err := q.sendCategoryRequest(ctx, quicwire.SubOpTPM2GetEK, nil)
	if err != nil {
		return nil, err
	}

	var keyResp quicapi.TPM2KeyResponse
	if err := decodeTPMPayload(resp.Payload, &keyResp); err != nil {
		return nil, ErrQUICTPMDecodeFailed{Operation: "EKInfo", Err: err}
	}

	return &EKInfoResult{
		Handle:    keyResp.Handle,
		Algorithm: keyResp.Algorithm,
		PublicKey: keyResp.PublicKey,
	}, nil
}

// EKCertificate retrieves the EK certificate via QUIC.
func (q *QUICAdapter) EKCertificate(ctx context.Context) (*EKCertificateResult, error) {
	resp, err := q.sendCategoryRequest(ctx, quicwire.SubOpTPM2GetEKCert, nil)
	if err != nil {
		return nil, err
	}

	var certResp quicapi.TPM2CertificateResponse
	if err := decodeTPMPayload(resp.Payload, &certResp); err != nil {
		return nil, ErrQUICTPMDecodeFailed{Operation: "EKCertificate", Err: err}
	}

	return &EKCertificateResult{
		Format:      "DER",
		Certificate: certResp.Certificate,
	}, nil
}

// EKDelete deletes the EK via QUIC.
func (q *QUICAdapter) EKDelete(ctx context.Context, handle uint32, password string) (*EKDeleteResult, error) {
	resp, err := q.sendCategoryRequest(ctx, quicwire.SubOpTPM2DeleteEK, nil)
	if err != nil {
		return nil, err
	}

	var statusResp quicapi.TPM2StatusResponse
	if err := decodeTPMPayload(resp.Payload, &statusResp); err != nil {
		return nil, ErrQUICTPMDecodeFailed{Operation: "EKDelete", Err: err}
	}

	return &EKDeleteResult{
		Success: statusResp.Success,
		Message: statusResp.Message,
	}, nil
}

// =============================================================================
// SRK Operations
// =============================================================================

// SRKCreate creates an SRK via QUIC.
func (q *QUICAdapter) SRKCreate(ctx context.Context, opts SRKCreateOptions) (*SRKCreateResult, error) {
	resp, err := q.sendCategoryRequest(ctx, quicwire.SubOpTPM2CreateSRK, nil)
	if err != nil {
		return nil, err
	}

	var keyResp quicapi.TPM2KeyResponse
	if err := decodeTPMPayload(resp.Payload, &keyResp); err != nil {
		return nil, ErrQUICTPMDecodeFailed{Operation: "SRKCreate", Err: err}
	}

	return &SRKCreateResult{
		Success:   true,
		Handle:    keyResp.Handle,
		Algorithm: keyResp.Algorithm,
		PublicKey: keyResp.PublicKey,
		CreatedAt: time.Now(),
	}, nil
}

// SRKInfo retrieves SRK information via QUIC.
func (q *QUICAdapter) SRKInfo(ctx context.Context, handle uint32) (*SRKInfoResult, error) {
	resp, err := q.sendCategoryRequest(ctx, quicwire.SubOpTPM2GetSRK, nil)
	if err != nil {
		return nil, err
	}

	var keyResp quicapi.TPM2KeyResponse
	if err := decodeTPMPayload(resp.Payload, &keyResp); err != nil {
		return nil, ErrQUICTPMDecodeFailed{Operation: "SRKInfo", Err: err}
	}

	return &SRKInfoResult{
		Handle:    keyResp.Handle,
		Algorithm: keyResp.Algorithm,
		PublicKey: keyResp.PublicKey,
	}, nil
}

// SRKDelete deletes the SRK via QUIC.
func (q *QUICAdapter) SRKDelete(ctx context.Context, handle uint32, password string) (*SRKDeleteResult, error) {
	resp, err := q.sendCategoryRequest(ctx, quicwire.SubOpTPM2DeleteSRK, quicapi.TPM2DeleteSRKRequest{Handle: handle})
	if err != nil {
		return nil, err
	}

	var statusResp quicapi.TPM2StatusResponse
	if err := decodeTPMPayload(resp.Payload, &statusResp); err != nil {
		return nil, ErrQUICTPMDecodeFailed{Operation: "SRKDelete", Err: err}
	}

	return &SRKDeleteResult{
		Success: statusResp.Success,
		Message: statusResp.Message,
	}, nil
}

// =============================================================================
// Seal/Unseal Operations
// =============================================================================

// Seal seals data to the TPM via QUIC.
func (q *QUICAdapter) Seal(ctx context.Context, opts SealOptions) (*SealResult, error) {
	req := &quicapi.TPM2SealRequest{
		Data: opts.Data,
	}

	resp, err := q.sendCategoryRequest(ctx, quicwire.SubOpTPM2Seal, req)
	if err != nil {
		return nil, err
	}

	var sealResp quicapi.TPM2SealResponse
	if err := decodeTPMPayload(resp.Payload, &sealResp); err != nil {
		return nil, ErrQUICTPMDecodeFailed{Operation: "Seal", Err: err}
	}

	return &SealResult{
		Success: true,
		Message: "data sealed successfully",
	}, nil
}

// Unseal unseals data from the TPM via QUIC.
func (q *QUICAdapter) Unseal(ctx context.Context, opts UnsealOptions) (*UnsealResult, error) {
	req := &quicapi.TPM2UnsealRequest{
		CN: opts.CN,
	}

	resp, err := q.sendCategoryRequest(ctx, quicwire.SubOpTPM2Unseal, req)
	if err != nil {
		return nil, err
	}

	var unsealResp quicapi.TPM2UnsealResponse
	if err := decodeTPMPayload(resp.Payload, &unsealResp); err != nil {
		return nil, ErrQUICTPMDecodeFailed{Operation: "Unseal", Err: err}
	}

	return &UnsealResult{
		Success: true,
		Data:    unsealResp.Data,
	}, nil
}

// =============================================================================
// Event Log Operations
// =============================================================================

// EventLog reads the TPM event log via QUIC.
func (q *QUICAdapter) EventLog(ctx context.Context) (*EventLogResult, error) {
	resp, err := q.sendCategoryRequest(ctx, quicwire.SubOpTPM2EventLog, nil)
	if err != nil {
		return nil, err
	}

	var eventResp quicapi.TPM2EventLogResponse
	if err := decodeTPMPayload(resp.Payload, &eventResp); err != nil {
		return nil, ErrQUICTPMDecodeFailed{Operation: "EventLog", Err: err}
	}

	result := &EventLogResult{
		Events: make([]EventLogEntry, 0),
	}

	if len(eventResp.EventLog) > 0 {
		result.Events = append(result.Events, EventLogEntry{
			EventData: eventResp.EventLog,
		})
	}

	return result, nil
}

// Ensure QUICAdapter implements TPMCommands interface.
var _ TPMCommands = (*QUICAdapter)(nil)
