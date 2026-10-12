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

package vtpm

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/jeremyhahn/go-codec"
	"github.com/jeremyhahn/go-codec/pkg/factory"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	quicgo "github.com/quic-go/quic-go"
)

// =============================================================================
// QUIC Constants and Operation Codes
// =============================================================================

const (
	// DefaultQUICTimeoutVTPM is the default timeout for QUIC operations.
	DefaultQUICTimeoutVTPM = 30 * time.Second

	// MaxQUICPayloadSizeVTPM is the maximum payload size (16MB).
	MaxQUICPayloadSizeVTPM uint32 = 16 * 1024 * 1024

	// MaxQUICTokenSizeVTPM is the maximum token size (8KB).
	MaxQUICTokenSizeVTPM uint16 = 8 * 1024
)

// QUIC Status codes.
const (
	QUICStatusOKVTPM             byte = 0x00
	QUICStatusInvalidRequestVTPM byte = 0x01
	QUICStatusNotFoundVTPM       byte = 0x02
	QUICStatusInternalErrorVTPM  byte = 0x04
)

// =============================================================================
// Error Types
// =============================================================================

// ErrQUICVTPMNotImplemented indicates a method is not yet implemented.
type ErrQUICVTPMNotImplemented struct {
	Method string
}

func (e ErrQUICVTPMNotImplemented) Error() string {
	return fmt.Sprintf("QUIC vTPM method %s not implemented", e.Method)
}

// ErrQUICVTPMConnectionFailed indicates a QUIC connection failure.
type ErrQUICVTPMConnectionFailed struct {
	Endpoint string
	Err      error
}

func (e ErrQUICVTPMConnectionFailed) Error() string {
	return fmt.Sprintf("QUIC vTPM connection to %s failed: %v", e.Endpoint, e.Err)
}

func (e ErrQUICVTPMConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrQUICVTPMRequestFailed indicates a QUIC request failure.
type ErrQUICVTPMRequestFailed struct {
	Operation string
	Status    byte
	Message   string
}

func (e ErrQUICVTPMRequestFailed) Error() string {
	return fmt.Sprintf("QUIC vTPM request %s failed (status 0x%02X): %s", e.Operation, e.Status, e.Message)
}

// ErrQUICVTPMEncodeFailed indicates payload encoding failure.
type ErrQUICVTPMEncodeFailed struct {
	Operation string
	Err       error
}

func (e ErrQUICVTPMEncodeFailed) Error() string {
	return fmt.Sprintf("QUIC vTPM encode failed for %s: %v", e.Operation, e.Err)
}

func (e ErrQUICVTPMEncodeFailed) Unwrap() error {
	return e.Err
}

// ErrQUICVTPMDecodeFailed indicates payload decoding failure.
type ErrQUICVTPMDecodeFailed struct {
	Operation string
	Err       error
}

func (e ErrQUICVTPMDecodeFailed) Error() string {
	return fmt.Sprintf("QUIC vTPM decode failed for %s: %v", e.Operation, e.Err)
}

func (e ErrQUICVTPMDecodeFailed) Unwrap() error {
	return e.Err
}

// ErrQUICVTPMClientClosed indicates the client is closed.
type ErrQUICVTPMClientClosed struct{}

func (e ErrQUICVTPMClientClosed) Error() string {
	return "QUIC vTPM client is closed"
}

// ErrQUICVTPMValidationFailed indicates bundle validation returned errors.
type ErrQUICVTPMValidationFailed struct {
	BundleID string
	Errors   []string
}

func (e ErrQUICVTPMValidationFailed) Error() string {
	return fmt.Sprintf("QUIC vTPM bundle %s validation failed: %s", e.BundleID, strings.Join(e.Errors, "; "))
}

// ErrQUICVTPMTempFileFailed indicates a temp file creation or write failure.
type ErrQUICVTPMTempFileFailed struct {
	Operation string
	Err       error
}

func (e ErrQUICVTPMTempFileFailed) Error() string {
	return fmt.Sprintf("QUIC vTPM temp file %s failed: %v", e.Operation, e.Err)
}

func (e ErrQUICVTPMTempFileFailed) Unwrap() error {
	return e.Err
}

// =============================================================================
// Wire Protocol Types
// =============================================================================

// quicVTPMRequest represents a QUIC protocol request.
type quicVTPMRequest struct {
	Opcode  byte
	Token   string
	Payload []byte
}

// quicVTPMResponse represents a QUIC protocol response.
type quicVTPMResponse struct {
	Status  byte
	Payload []byte
}

// =============================================================================
// QUIC Request/Response Types (matching daemon/quic_vtpm.go)
// =============================================================================

// CreateBundle request matches daemon VTPMCreateRequest
type quicVTPMCreateBundleReq struct {
	ID                string            `codec:"id"`
	Hostname          string            `codec:"hostname"`
	EKAlgorithm       string            `codec:"ek_algorithm"`
	SecureBootEnabled bool              `codec:"secure_boot_enabled"`
	Labels            map[string]string `codec:"labels"`
}

// CreateBundle response matches daemon VTPMCreateResponse
type quicVTPMCreateBundleResp struct {
	BundleID   string `codec:"bundle_id"`
	Hostname   string `codec:"hostname"`
	Mode       string `codec:"mode"`
	CreatedAt  int64  `codec:"created_at"`
	SocketPath string `codec:"socket_path"`
	Timestamp  int64  `codec:"timestamp"`
}

type quicVTPMGetBundleReq struct {
	ID string `codec:"id"`
}

type quicVTPMGetBundleResp struct {
	ID                string            `codec:"id"`
	Mode              string            `codec:"mode"`
	Hostname          string            `codec:"hostname"`
	EKAlgorithm       string            `codec:"ek_algorithm"`
	SecureBootEnabled bool              `codec:"secure_boot_enabled"`
	CreatedAt         int64             `codec:"created_at"`
	ClonedFrom        string            `codec:"cloned_from"`
	Labels            map[string]string `codec:"labels"`
	Checksums         map[string]string `codec:"checksums"`
	Timestamp         int64             `codec:"timestamp"`
}

// DeleteBundle request matches daemon VTPMDeleteRequest
type quicVTPMDeleteBundleReq struct {
	BundleID string `codec:"bundle_id"`
}

// DeleteBundle response matches daemon VTPMDeleteResponse
type quicVTPMDeleteBundleResp struct {
	BundleID  string `codec:"bundle_id"`
	Deleted   bool   `codec:"deleted"`
	Timestamp int64  `codec:"timestamp"`
}

// ListBundles request matches daemon VTPMListRequest
type quicVTPMListBundlesReq struct {
	Mode string `codec:"mode"`
}

type quicVTPMBundleSummary struct {
	ID                string `codec:"id"`
	Mode              string `codec:"mode"`
	Hostname          string `codec:"hostname"`
	EKAlgorithm       string `codec:"ek_algorithm"`
	SecureBootEnabled bool   `codec:"secure_boot_enabled"`
	CreatedAt         int64  `codec:"created_at"`
	Running           bool   `codec:"running"`
}

// ListBundles response matches daemon VTPMListResponse
type quicVTPMListBundlesResp struct {
	Bundles   []*quicVTPMBundleSummary `codec:"bundles"`
	Total     int                      `codec:"total"`
	Timestamp int64                    `codec:"timestamp"`
}

type quicVTPMCreateTemplateReq struct {
	ID                string `codec:"id"`
	Description       string `codec:"description"`
	EKAlgorithm       string `codec:"ek_algorithm"`
	SecureBootEnabled bool   `codec:"secure_boot_enabled"`
}

type quicVTPMCreateTemplateResp struct {
	ID                string `codec:"id"`
	Description       string `codec:"description"`
	EKAlgorithm       string `codec:"ek_algorithm"`
	SecureBootEnabled bool   `codec:"secure_boot_enabled"`
	CreatedAt         int64  `codec:"created_at"`
	Timestamp         int64  `codec:"timestamp"`
}

type quicVTPMGetTemplateReq struct {
	ID string `codec:"id"`
}

type quicVTPMGetTemplateResp struct {
	ID                string `codec:"id"`
	Description       string `codec:"description"`
	TPMStateDir       string `codec:"tpm_state_dir"`
	NVRAMPath         string `codec:"nvram_path"`
	SecureBootKeysDir string `codec:"secure_boot_keys_dir"`
	EKAlgorithm       string `codec:"ek_algorithm"`
	SecureBootEnabled bool   `codec:"secure_boot_enabled"`
	CreatedAt         int64  `codec:"created_at"`
	Timestamp         int64  `codec:"timestamp"`
}

type quicVTPMDeleteTemplateReq struct {
	ID string `codec:"id"`
}

type quicVTPMDeleteTemplateResp struct {
	ID        string `codec:"id"`
	Deleted   bool   `codec:"deleted"`
	Timestamp int64  `codec:"timestamp"`
}

type quicVTPMTemplateSummary struct {
	ID                string `codec:"id"`
	Description       string `codec:"description"`
	EKAlgorithm       string `codec:"ek_algorithm"`
	SecureBootEnabled bool   `codec:"secure_boot_enabled"`
	CreatedAt         int64  `codec:"created_at"`
}

type quicVTPMListTemplatesResp struct {
	Templates []*quicVTPMTemplateSummary `codec:"templates"`
	Total     int                        `codec:"total"`
	Timestamp int64                      `codec:"timestamp"`
}

type quicVTPMCloneTemplateReq struct {
	TemplateID string            `codec:"template_id"`
	Hostname   string            `codec:"hostname"`
	Labels     map[string]string `codec:"labels"`
}

type quicVTPMExportBundleReq struct {
	ID string `codec:"id"`
}

type quicVTPMExportBundleResp struct {
	ID        string `codec:"id"`
	Data      []byte `codec:"data"`
	Size      int64  `codec:"size"`
	Timestamp int64  `codec:"timestamp"`
}

type quicVTPMImportBundleReq struct {
	Data []byte `codec:"data"`
}

type quicVTPMImportBundleResp struct {
	BundleID  string `codec:"bundle_id"`
	Hostname  string `codec:"hostname"`
	Mode      string `codec:"mode"`
	CreatedAt int64  `codec:"created_at"`
	Timestamp int64  `codec:"timestamp"`
}

type quicVTPMValidateBundleReq struct {
	ID string `codec:"id"`
}

type quicVTPMValidateBundleResp struct {
	ID        string   `codec:"id"`
	Valid     bool     `codec:"valid"`
	Errors    []string `codec:"errors"`
	Timestamp int64    `codec:"timestamp"`
}

type quicVTPMGetPathReq struct {
	ID string `codec:"id"`
}

type quicVTPMGetPathResp struct {
	ID        string `codec:"id"`
	Path      string `codec:"path"`
	Timestamp int64  `codec:"timestamp"`
}

// Runtime TPM operation request/response types
type quicVTPMStartReq struct {
	BundleID string `codec:"bundle_id"`
}

type quicVTPMStartResp struct {
	BundleID   string `codec:"bundle_id"`
	Running    bool   `codec:"running"`
	SocketPath string `codec:"socket_path"`
	Timestamp  int64  `codec:"timestamp"`
}

type quicVTPMStopReq struct {
	BundleID string `codec:"bundle_id"`
}

type quicVTPMStopResp struct {
	BundleID  string `codec:"bundle_id"`
	Stopped   bool   `codec:"stopped"`
	Timestamp int64  `codec:"timestamp"`
}

type quicVTPMIsRunningReq struct {
	BundleID string `codec:"bundle_id"`
}

type quicVTPMIsRunningResp struct {
	BundleID  string `codec:"bundle_id"`
	Running   bool   `codec:"running"`
	Timestamp int64  `codec:"timestamp"`
}

type quicVTPMQuoteReq struct {
	BundleID string `codec:"bundle_id"`
	Nonce    []byte `codec:"nonce"`
	PCRs     []int  `codec:"pcrs"`
}

type quicVTPMQuoteResp struct {
	BundleID      string         `codec:"bundle_id"`
	Quote         []byte         `codec:"quote"`
	Signature     []byte         `codec:"signature"`
	PCRValues     map[int][]byte `codec:"pcr_values"`
	HashAlgorithm string         `codec:"hash_algorithm"`
	Timestamp     int64          `codec:"timestamp"`
}

type quicVTPMSealReq struct {
	BundleID  string `codec:"bundle_id"`
	Data      []byte `codec:"data"`
	PCRs      []int  `codec:"pcrs"`
	AuthValue string `codec:"auth_value"`
}

type quicVTPMSealResp struct {
	BundleID   string `codec:"bundle_id"`
	SealedData []byte `codec:"sealed_data"`
	Timestamp  int64  `codec:"timestamp"`
}

type quicVTPMUnsealReq struct {
	BundleID   string `codec:"bundle_id"`
	SealedData []byte `codec:"sealed_data"`
	AuthValue  string `codec:"auth_value"`
}

type quicVTPMUnsealResp struct {
	BundleID  string `codec:"bundle_id"`
	Data      []byte `codec:"data"`
	Timestamp int64  `codec:"timestamp"`
}

type quicVTPMExtendPCRReq struct {
	BundleID string `codec:"bundle_id"`
	PCRIndex int    `codec:"pcr_index"`
	Data     []byte `codec:"data"`
}

type quicVTPMExtendPCRResp struct {
	BundleID  string `codec:"bundle_id"`
	PCRIndex  int    `codec:"pcr_index"`
	Extended  bool   `codec:"extended"`
	Timestamp int64  `codec:"timestamp"`
}

type quicVTPMReadPCRReq struct {
	BundleID string `codec:"bundle_id"`
	PCRIndex int    `codec:"pcr_index"`
}

type quicVTPMReadPCRResp struct {
	BundleID  string `codec:"bundle_id"`
	PCRIndex  int    `codec:"pcr_index"`
	Value     []byte `codec:"value"`
	Timestamp int64  `codec:"timestamp"`
}

// =============================================================================
// QUIC Adapter
// =============================================================================

// QUICAdapter implements VTPMCommands using the QUIC protocol.
type QUICAdapter struct {
	endpoint       string
	conn           *quicgo.Conn
	tlsConfig      *tls.Config
	timeout        time.Duration
	maxIdleTimeout time.Duration

	mu     sync.RWMutex
	closed bool
}

// NewQUICAdapter creates a new QUIC adapter for vTPM integration testing.
func NewQUICAdapter() *QUICAdapter {
	return &QUICAdapter{
		endpoint:       GetQUICEndpoint(),
		timeout:        DefaultQUICTimeoutVTPM,
		maxIdleTimeout: 60 * time.Second,
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
		return ErrQUICVTPMClientClosed{}
	}

	connCtx, cancel := context.WithTimeout(ctx, q.timeout)
	defer cancel()

	quicConfig := &quicgo.Config{
		MaxIdleTimeout:  q.maxIdleTimeout,
		KeepAlivePeriod: 15 * time.Second,
	}

	conn, err := quicgo.DialAddr(connCtx, q.endpoint, q.tlsConfig, quicConfig)
	if err != nil {
		return ErrQUICVTPMConnectionFailed{Endpoint: q.endpoint, Err: err}
	}

	q.conn = conn
	return nil
}

// Teardown closes the QUIC connection.
func (q *QUICAdapter) Teardown(ctx context.Context) error {
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
func (q *QUICAdapter) sendRequest(ctx context.Context, opcode byte, payload interface{}) (*quicVTPMResponse, error) {
	q.mu.RLock()
	if q.closed {
		q.mu.RUnlock()
		return nil, ErrQUICVTPMClientClosed{}
	}
	conn := q.conn
	q.mu.RUnlock()

	// Encode payload
	var payloadBytes []byte
	if payload != nil {
		var err error
		payloadBytes, err = encodeVTPMPayload(payload)
		if err != nil {
			return nil, ErrQUICVTPMEncodeFailed{Operation: vtpmOpcodeToString(opcode), Err: err}
		}
	}

	// Open stream
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, ErrQUICVTPMConnectionFailed{Endpoint: q.endpoint, Err: err}
	}
	defer stream.Close()

	// Write request
	req := &quicVTPMRequest{
		Opcode:  opcode,
		Payload: payloadBytes,
	}

	if err := writeVTPMRequest(stream, req); err != nil {
		return nil, err
	}

	// Read response
	resp, err := readVTPMResponse(stream)
	if err != nil {
		return nil, err
	}

	// Check status
	if resp.Status != QUICStatusOKVTPM {
		errMsg := string(resp.Payload)
		if errMsg == "" {
			errMsg = "unknown error"
		}
		return nil, ErrQUICVTPMRequestFailed{
			Operation: vtpmOpcodeToString(opcode),
			Status:    resp.Status,
			Message:   errMsg,
		}
	}

	return resp, nil
}

// writeVTPMRequest writes a request to the stream.
func writeVTPMRequest(w io.Writer, req *quicVTPMRequest) error {
	payloadLen := uint32(len(req.Payload))
	if payloadLen > MaxQUICPayloadSizeVTPM {
		return fmt.Errorf("payload size %d exceeds maximum %d", payloadLen, MaxQUICPayloadSizeVTPM)
	}

	tokenLen := uint16(len(req.Token))
	if tokenLen > MaxQUICTokenSizeVTPM {
		return fmt.Errorf("token size %d exceeds maximum %d", tokenLen, MaxQUICTokenSizeVTPM)
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

// readVTPMResponse reads a response from the stream.
func readVTPMResponse(r io.Reader) (*quicVTPMResponse, error) {
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

	if payloadLen > MaxQUICPayloadSizeVTPM {
		return nil, fmt.Errorf("payload size %d exceeds maximum %d", payloadLen, MaxQUICPayloadSizeVTPM)
	}

	// Read payload
	var payload []byte
	if payloadLen > 0 {
		payload = make([]byte, payloadLen)
		if _, err := io.ReadFull(r, payload); err != nil {
			return nil, fmt.Errorf("failed to read payload: %w", err)
		}
	}

	return &quicVTPMResponse{
		Status:  statusBuf[0],
		Payload: payload,
	}, nil
}

// defaultCodecType is the codec type used for payload encoding/decoding
var defaultCodecType = codec.MsgPack

// getCodec creates a codec of the default type using the factory
func getCodec() (codec.Codec[any], error) {
	return factory.New[any](defaultCodecType)
}

// encodeVTPMPayload encodes an entity using the configured codec.
func encodeVTPMPayload(entity interface{}) ([]byte, error) {
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

// decodeVTPMPayload decodes bytes into an entity using the configured codec.
func decodeVTPMPayload(data []byte, entity interface{}) error {
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

// vtpmOpcodeToString returns a human-readable name for an opcode.
func vtpmOpcodeToString(opcode byte) string {
	switch opcode {
	case quicwire.OpVTPMCreate:
		return "VTPMCreate"
	case quicwire.OpVTPMDelete:
		return "VTPMDelete"
	case quicwire.OpVTPMStart:
		return "VTPMStart"
	case quicwire.OpVTPMStop:
		return "VTPMStop"
	case quicwire.OpVTPMGetState:
		return "VTPMGetState"
	case quicwire.OpVTPMList:
		return "VTPMList"
	case quicwire.OpVTPMQuote:
		return "VTPMQuote"
	case quicwire.OpVTPMSeal:
		return "VTPMSeal"
	case quicwire.OpVTPMUnseal:
		return "VTPMUnseal"
	case quicwire.OpVTPMExtendPCR:
		return "VTPMExtendPCR"
	case quicwire.OpVTPMReadPCR:
		return "VTPMReadPCR"
	case quicwire.OpVTPMCreateTemplate:
		return "VTPMCreateTemplate"
	case quicwire.OpVTPMGetTemplate:
		return "VTPMGetTemplate"
	case quicwire.OpVTPMDeleteTemplate:
		return "VTPMDeleteTemplate"
	case quicwire.OpVTPMListTemplates:
		return "VTPMListTemplates"
	case quicwire.OpVTPMCloneTemplate:
		return "VTPMCloneTemplate"
	case quicwire.OpVTPMExportBundle:
		return "VTPMExportBundle"
	case quicwire.OpVTPMImportBundle:
		return "VTPMImportBundle"
	case quicwire.OpVTPMValidateBundle:
		return "VTPMValidateBundle"
	case quicwire.OpVTPMGetBundlePath:
		return "VTPMGetBundlePath"
	case quicwire.OpVTPMGetSocketPath:
		return "VTPMGetSocketPath"
	case quicwire.OpVTPMGetNVRAMPath:
		return "VTPMGetNVRAMPath"
	case quicwire.OpVTPMGetBundle:
		return "VTPMGetBundle"
	case quicwire.OpVTPMIsRunning:
		return "VTPMIsRunning"
	default:
		return fmt.Sprintf("Unknown(0x%02X)", opcode)
	}
}

// =============================================================================
// Bundle CRUD Commands
// =============================================================================

// CreateBundle creates a new vTPM bundle via QUIC.
func (q *QUICAdapter) CreateBundle(ctx context.Context, opts CreateBundleOptions) (*CreateBundleResult, error) {
	req := &quicVTPMCreateBundleReq{
		Hostname:          opts.Hostname,
		EKAlgorithm:       string(opts.EKAlgorithm),
		SecureBootEnabled: opts.SecureBootEnabled,
		Labels:            opts.Labels,
	}

	resp, err := q.sendRequest(ctx, quicwire.OpVTPMCreate, req)
	if err != nil {
		return nil, err
	}

	var createResp quicVTPMCreateBundleResp
	if err := decodeVTPMPayload(resp.Payload, &createResp); err != nil {
		return nil, ErrQUICVTPMDecodeFailed{Operation: "CreateBundle", Err: err}
	}

	bundle := &vtpm.Bundle{
		ID:   createResp.BundleID,
		Mode: vtpm.BundleMode(createResp.Mode),
		Manifest: &vtpm.Manifest{
			Hostname: createResp.Hostname,
		},
		CreatedAt: time.Unix(createResp.CreatedAt, 0),
	}

	return &CreateBundleResult{Bundle: bundle}, nil
}

// GetBundle retrieves a bundle by ID via QUIC.
func (q *QUICAdapter) GetBundle(ctx context.Context, opts GetBundleOptions) (*GetBundleResult, error) {
	req := &quicVTPMGetBundleReq{ID: opts.ID}

	resp, err := q.sendRequest(ctx, quicwire.OpVTPMGetBundle, req)
	if err != nil {
		return nil, err
	}

	var getResp quicVTPMGetBundleResp
	if err := decodeVTPMPayload(resp.Payload, &getResp); err != nil {
		return nil, ErrQUICVTPMDecodeFailed{Operation: "GetBundle", Err: err}
	}

	bundle := &vtpm.Bundle{
		ID:         getResp.ID,
		Mode:       vtpm.BundleMode(getResp.Mode),
		ClonedFrom: getResp.ClonedFrom,
		CreatedAt:  time.Unix(getResp.CreatedAt, 0),
		Manifest: &vtpm.Manifest{
			Hostname:          getResp.Hostname,
			EKAlgorithm:       vtpm.EKAlgorithm(getResp.EKAlgorithm),
			SecureBootEnabled: getResp.SecureBootEnabled,
			Labels:            getResp.Labels,
			Checksums:         getResp.Checksums,
		},
	}

	return &GetBundleResult{Bundle: bundle}, nil
}

// DeleteBundle deletes a bundle via QUIC.
func (q *QUICAdapter) DeleteBundle(ctx context.Context, opts DeleteBundleOptions) (*DeleteBundleResult, error) {
	req := &quicVTPMDeleteBundleReq{BundleID: opts.ID}

	resp, err := q.sendRequest(ctx, quicwire.OpVTPMDelete, req)
	if err != nil {
		return nil, err
	}

	var deleteResp quicVTPMDeleteBundleResp
	if err := decodeVTPMPayload(resp.Payload, &deleteResp); err != nil {
		return nil, ErrQUICVTPMDecodeFailed{Operation: "DeleteBundle", Err: err}
	}

	return &DeleteBundleResult{Success: deleteResp.Deleted}, nil
}

// ListBundles lists bundles via QUIC.
// The server does not support pagination natively, so limit and offset
// are applied client-side after receiving the full result set.
func (q *QUICAdapter) ListBundles(ctx context.Context, opts ListBundlesOptions) (*ListBundlesResult, error) {
	req := &quicVTPMListBundlesReq{
		Mode: string(opts.Mode),
	}

	resp, err := q.sendRequest(ctx, quicwire.OpVTPMList, req)
	if err != nil {
		return nil, err
	}

	var listResp quicVTPMListBundlesResp
	if err := decodeVTPMPayload(resp.Payload, &listResp); err != nil {
		return nil, ErrQUICVTPMDecodeFailed{Operation: "ListBundles", Err: err}
	}

	// Convert to vtpm.Bundle slice
	allBundles := make([]*vtpm.Bundle, 0, len(listResp.Bundles))
	for _, b := range listResp.Bundles {
		allBundles = append(allBundles, &vtpm.Bundle{
			ID:        b.ID,
			Mode:      vtpm.BundleMode(b.Mode),
			CreatedAt: time.Unix(b.CreatedAt, 0),
			Manifest: &vtpm.Manifest{
				Hostname:          b.Hostname,
				EKAlgorithm:       vtpm.EKAlgorithm(b.EKAlgorithm),
				SecureBootEnabled: b.SecureBootEnabled,
			},
		})
	}

	total := len(allBundles)

	// Apply client-side offset
	if opts.Offset > 0 && opts.Offset < len(allBundles) {
		allBundles = allBundles[opts.Offset:]
	} else if opts.Offset >= len(allBundles) {
		allBundles = nil
	}

	// Apply client-side limit
	if opts.Limit > 0 && opts.Limit < len(allBundles) {
		allBundles = allBundles[:opts.Limit]
	}

	return &ListBundlesResult{
		Bundles: allBundles,
		Total:   total,
	}, nil
}

// =============================================================================
// Template CRUD Commands
// =============================================================================

// CreateTemplate creates a new vTPM template via QUIC.
func (q *QUICAdapter) CreateTemplate(ctx context.Context, opts CreateTemplateOptions) (*CreateTemplateResult, error) {
	req := &quicVTPMCreateTemplateReq{
		ID:                opts.ID,
		Description:       opts.Description,
		EKAlgorithm:       string(opts.EKAlgorithm),
		SecureBootEnabled: opts.SecureBootEnabled,
	}

	resp, err := q.sendRequest(ctx, quicwire.OpVTPMCreateTemplate, req)
	if err != nil {
		return nil, err
	}

	var createResp quicVTPMCreateTemplateResp
	if err := decodeVTPMPayload(resp.Payload, &createResp); err != nil {
		return nil, ErrQUICVTPMDecodeFailed{Operation: "CreateTemplate", Err: err}
	}

	template := &vtpm.Template{
		ID:                createResp.ID,
		Description:       createResp.Description,
		EKAlgorithm:       vtpm.EKAlgorithm(createResp.EKAlgorithm),
		SecureBootEnabled: createResp.SecureBootEnabled,
		CreatedAt:         time.Unix(createResp.CreatedAt, 0),
	}

	return &CreateTemplateResult{Template: template}, nil
}

// GetTemplate retrieves a template by ID via QUIC.
func (q *QUICAdapter) GetTemplate(ctx context.Context, opts GetTemplateOptions) (*GetTemplateResult, error) {
	req := &quicVTPMGetTemplateReq{ID: opts.ID}

	resp, err := q.sendRequest(ctx, quicwire.OpVTPMGetTemplate, req)
	if err != nil {
		return nil, err
	}

	var getResp quicVTPMGetTemplateResp
	if err := decodeVTPMPayload(resp.Payload, &getResp); err != nil {
		return nil, ErrQUICVTPMDecodeFailed{Operation: "GetTemplate", Err: err}
	}

	template := &vtpm.Template{
		ID:                getResp.ID,
		Description:       getResp.Description,
		TPMStateDir:       getResp.TPMStateDir,
		NVRAMPath:         getResp.NVRAMPath,
		SecureBootKeysDir: getResp.SecureBootKeysDir,
		EKAlgorithm:       vtpm.EKAlgorithm(getResp.EKAlgorithm),
		SecureBootEnabled: getResp.SecureBootEnabled,
		CreatedAt:         time.Unix(getResp.CreatedAt, 0),
	}

	return &GetTemplateResult{Template: template}, nil
}

// DeleteTemplate deletes a template via QUIC.
func (q *QUICAdapter) DeleteTemplate(ctx context.Context, opts DeleteTemplateOptions) (*DeleteTemplateResult, error) {
	req := &quicVTPMDeleteTemplateReq{ID: opts.ID}

	resp, err := q.sendRequest(ctx, quicwire.OpVTPMDeleteTemplate, req)
	if err != nil {
		return nil, err
	}

	var deleteResp quicVTPMDeleteTemplateResp
	if err := decodeVTPMPayload(resp.Payload, &deleteResp); err != nil {
		return nil, ErrQUICVTPMDecodeFailed{Operation: "DeleteTemplate", Err: err}
	}

	return &DeleteTemplateResult{Success: deleteResp.Deleted}, nil
}

// ListTemplates lists templates via QUIC.
func (q *QUICAdapter) ListTemplates(ctx context.Context, opts ListTemplatesOptions) (*ListTemplatesResult, error) {
	resp, err := q.sendRequest(ctx, quicwire.OpVTPMListTemplates, nil)
	if err != nil {
		return nil, err
	}

	var listResp quicVTPMListTemplatesResp
	if err := decodeVTPMPayload(resp.Payload, &listResp); err != nil {
		return nil, ErrQUICVTPMDecodeFailed{Operation: "ListTemplates", Err: err}
	}

	templates := make([]*vtpm.Template, len(listResp.Templates))
	for i, t := range listResp.Templates {
		templates[i] = &vtpm.Template{
			ID:                t.ID,
			Description:       t.Description,
			EKAlgorithm:       vtpm.EKAlgorithm(t.EKAlgorithm),
			SecureBootEnabled: t.SecureBootEnabled,
			CreatedAt:         time.Unix(t.CreatedAt, 0),
		}
	}

	return &ListTemplatesResult{
		Templates: templates,
		Total:     listResp.Total,
	}, nil
}

// CloneTemplate clones a template to create a new bundle via QUIC.
// The server handler returns a VTPMGetBundleResponse via bundleToQUICResponse,
// so we decode using the quicVTPMGetBundleResp type.
func (q *QUICAdapter) CloneTemplate(ctx context.Context, opts CloneTemplateOptions) (*CloneTemplateResult, error) {
	req := &quicVTPMCloneTemplateReq{
		TemplateID: opts.TemplateID,
		Hostname:   opts.Hostname,
		Labels:     opts.Labels,
	}

	resp, err := q.sendRequest(ctx, quicwire.OpVTPMCloneTemplate, req)
	if err != nil {
		return nil, err
	}

	var cloneResp quicVTPMGetBundleResp
	if err := decodeVTPMPayload(resp.Payload, &cloneResp); err != nil {
		return nil, ErrQUICVTPMDecodeFailed{Operation: "CloneTemplate", Err: err}
	}

	bundle := &vtpm.Bundle{
		ID:         cloneResp.ID,
		Mode:       vtpm.BundleMode(cloneResp.Mode),
		ClonedFrom: cloneResp.ClonedFrom,
		CreatedAt:  time.Unix(cloneResp.CreatedAt, 0),
		Manifest: &vtpm.Manifest{
			Hostname:          cloneResp.Hostname,
			EKAlgorithm:       vtpm.EKAlgorithm(cloneResp.EKAlgorithm),
			SecureBootEnabled: cloneResp.SecureBootEnabled,
			Labels:            cloneResp.Labels,
		},
	}

	return &CloneTemplateResult{Bundle: bundle}, nil
}

// =============================================================================
// Export/Import Commands
// =============================================================================

// ExportBundle exports a bundle to a tar.gz archive via QUIC.
// When OutputPath is empty, the exported data is written to a temporary file
// so that ArchivePath is always populated for downstream import tests.
func (q *QUICAdapter) ExportBundle(ctx context.Context, opts ExportBundleOptions) (*ExportBundleResult, error) {
	req := &quicVTPMExportBundleReq{ID: opts.ID}

	resp, err := q.sendRequest(ctx, quicwire.OpVTPMExportBundle, req)
	if err != nil {
		return nil, err
	}

	var exportResp quicVTPMExportBundleResp
	if err := decodeVTPMPayload(resp.Payload, &exportResp); err != nil {
		return nil, ErrQUICVTPMDecodeFailed{Operation: "ExportBundle", Err: err}
	}

	checksum := sha256.Sum256(exportResp.Data)
	result := &ExportBundleResult{
		Size:     exportResp.Size,
		Checksum: hex.EncodeToString(checksum[:]),
	}

	// Write to the specified output path or a temp file so that
	// the ArchivePath is always populated for downstream import tests.
	archivePath := opts.OutputPath
	if archivePath == "" {
		tmpFile, tmpErr := os.CreateTemp("", "vtpm-export-*.tar.gz")
		if tmpErr != nil {
			return nil, ErrQUICVTPMTempFileFailed{Operation: "ExportBundle.CreateTemp", Err: tmpErr}
		}
		archivePath = tmpFile.Name()
		tmpFile.Close()
	}
	if writeErr := os.WriteFile(archivePath, exportResp.Data, 0600); writeErr != nil {
		return nil, ErrQUICVTPMTempFileFailed{Operation: "ExportBundle.WriteFile", Err: writeErr}
	}
	result.ArchivePath = archivePath

	return result, nil
}

// ImportBundle imports a bundle from a tar.gz archive via QUIC.
func (q *QUICAdapter) ImportBundle(ctx context.Context, opts ImportBundleOptions) (*ImportBundleResult, error) {
	var data []byte

	if opts.ArchivePath != "" {
		var err error
		data, err = os.ReadFile(opts.ArchivePath)
		if err != nil {
			return nil, fmt.Errorf("failed to read archive: %w", err)
		}
	} else if len(opts.ArchiveData) > 0 {
		data = opts.ArchiveData
	} else {
		return nil, fmt.Errorf("archive path or data required")
	}

	req := &quicVTPMImportBundleReq{Data: data}

	resp, err := q.sendRequest(ctx, quicwire.OpVTPMImportBundle, req)
	if err != nil {
		return nil, err
	}

	var importResp quicVTPMImportBundleResp
	if err := decodeVTPMPayload(resp.Payload, &importResp); err != nil {
		return nil, ErrQUICVTPMDecodeFailed{Operation: "ImportBundle", Err: err}
	}

	bundle := &vtpm.Bundle{
		ID:        importResp.BundleID,
		Mode:      vtpm.BundleMode(importResp.Mode),
		CreatedAt: time.Unix(importResp.CreatedAt, 0),
		Manifest: &vtpm.Manifest{
			Hostname: importResp.Hostname,
		},
	}

	return &ImportBundleResult{Bundle: bundle}, nil
}

// =============================================================================
// Validation Commands
// =============================================================================

// ValidateBundle validates bundle integrity via QUIC.
// The server always returns StatusOK with a Valid flag. When Valid is false
// and errors are present, this method returns an error to match the behavior
// expected by the test suite.
func (q *QUICAdapter) ValidateBundle(ctx context.Context, opts ValidateBundleOptions) (*ValidateBundleResult, error) {
	req := &quicVTPMValidateBundleReq{ID: opts.ID}

	resp, err := q.sendRequest(ctx, quicwire.OpVTPMValidateBundle, req)
	if err != nil {
		return nil, err
	}

	var validateResp quicVTPMValidateBundleResp
	if err := decodeVTPMPayload(resp.Payload, &validateResp); err != nil {
		return nil, ErrQUICVTPMDecodeFailed{Operation: "ValidateBundle", Err: err}
	}

	// The server returns StatusOK even for validation failures, encoding the
	// result in the Valid flag and Errors slice. When the bundle does not exist
	// or validation fails, surface an error so callers can distinguish success
	// from failure without inspecting the result struct.
	if !validateResp.Valid && len(validateResp.Errors) > 0 {
		return nil, ErrQUICVTPMValidationFailed{
			BundleID: opts.ID,
			Errors:   validateResp.Errors,
		}
	}

	return &ValidateBundleResult{
		Valid:            validateResp.Valid,
		Errors:           validateResp.Errors,
		ChecksumVerified: validateResp.Valid,
	}, nil
}

// =============================================================================
// Path Commands
// =============================================================================

// GetBundlePath returns the filesystem path to a bundle via QUIC.
func (q *QUICAdapter) GetBundlePath(ctx context.Context, opts GetBundlePathOptions) (*GetBundlePathResult, error) {
	req := &quicVTPMGetPathReq{ID: opts.ID}

	resp, err := q.sendRequest(ctx, quicwire.OpVTPMGetBundlePath, req)
	if err != nil {
		return nil, err
	}

	var pathResp quicVTPMGetPathResp
	if err := decodeVTPMPayload(resp.Payload, &pathResp); err != nil {
		return nil, ErrQUICVTPMDecodeFailed{Operation: "GetBundlePath", Err: err}
	}

	return &GetBundlePathResult{Path: pathResp.Path}, nil
}

// GetTPMSocketPath returns the TPM socket path for a bundle via QUIC.
func (q *QUICAdapter) GetTPMSocketPath(ctx context.Context, opts GetTPMSocketPathOptions) (*GetTPMSocketPathResult, error) {
	req := &quicVTPMGetPathReq{ID: opts.ID}

	resp, err := q.sendRequest(ctx, quicwire.OpVTPMGetSocketPath, req)
	if err != nil {
		return nil, err
	}

	var pathResp quicVTPMGetPathResp
	if err := decodeVTPMPayload(resp.Payload, &pathResp); err != nil {
		return nil, ErrQUICVTPMDecodeFailed{Operation: "GetTPMSocketPath", Err: err}
	}

	return &GetTPMSocketPathResult{Path: pathResp.Path}, nil
}

// GetNVRAMPath returns the OVMF NVRAM path for a bundle via QUIC.
func (q *QUICAdapter) GetNVRAMPath(ctx context.Context, opts GetNVRAMPathOptions) (*GetNVRAMPathResult, error) {
	req := &quicVTPMGetPathReq{ID: opts.ID}

	resp, err := q.sendRequest(ctx, quicwire.OpVTPMGetNVRAMPath, req)
	if err != nil {
		return nil, err
	}

	var pathResp quicVTPMGetPathResp
	if err := decodeVTPMPayload(resp.Payload, &pathResp); err != nil {
		return nil, ErrQUICVTPMDecodeFailed{Operation: "GetNVRAMPath", Err: err}
	}

	return &GetNVRAMPathResult{Path: pathResp.Path}, nil
}

// =============================================================================
// Runtime TPM Commands
// =============================================================================

// Start starts the swtpm daemon for a bundle via QUIC.
func (q *QUICAdapter) Start(ctx context.Context, opts StartOptions) (*StartResult, error) {
	req := &quicVTPMStartReq{BundleID: opts.BundleID}

	resp, err := q.sendRequest(ctx, quicwire.OpVTPMStart, req)
	if err != nil {
		return nil, err
	}

	var startResp quicVTPMStartResp
	if err := decodeVTPMPayload(resp.Payload, &startResp); err != nil {
		return nil, ErrQUICVTPMDecodeFailed{Operation: "Start", Err: err}
	}

	return &StartResult{
		BundleID:   startResp.BundleID,
		Running:    startResp.Running,
		SocketPath: startResp.SocketPath,
	}, nil
}

// Stop stops the swtpm daemon for a bundle via QUIC.
func (q *QUICAdapter) Stop(ctx context.Context, opts StopOptions) (*StopResult, error) {
	req := &quicVTPMStopReq{BundleID: opts.BundleID}

	resp, err := q.sendRequest(ctx, quicwire.OpVTPMStop, req)
	if err != nil {
		return nil, err
	}

	var stopResp quicVTPMStopResp
	if err := decodeVTPMPayload(resp.Payload, &stopResp); err != nil {
		return nil, ErrQUICVTPMDecodeFailed{Operation: "Stop", Err: err}
	}

	return &StopResult{
		BundleID: stopResp.BundleID,
		Stopped:  stopResp.Stopped,
	}, nil
}

// IsRunning checks if the vTPM for a bundle is running via QUIC.
func (q *QUICAdapter) IsRunning(ctx context.Context, opts IsRunningOptions) (*IsRunningResult, error) {
	req := &quicVTPMIsRunningReq{BundleID: opts.BundleID}

	resp, err := q.sendRequest(ctx, quicwire.OpVTPMIsRunning, req)
	if err != nil {
		return nil, err
	}

	var runningResp quicVTPMIsRunningResp
	if err := decodeVTPMPayload(resp.Payload, &runningResp); err != nil {
		return nil, ErrQUICVTPMDecodeFailed{Operation: "IsRunning", Err: err}
	}

	return &IsRunningResult{
		BundleID: runningResp.BundleID,
		Running:  runningResp.Running,
	}, nil
}

// Quote generates a TPM quote over specified PCRs via QUIC.
func (q *QUICAdapter) Quote(ctx context.Context, opts QuoteOptions) (*QuoteResult, error) {
	req := &quicVTPMQuoteReq{
		BundleID: opts.BundleID,
		Nonce:    opts.Nonce,
		PCRs:     opts.PCRs,
	}

	resp, err := q.sendRequest(ctx, quicwire.OpVTPMQuote, req)
	if err != nil {
		return nil, err
	}

	var quoteResp quicVTPMQuoteResp
	if err := decodeVTPMPayload(resp.Payload, &quoteResp); err != nil {
		return nil, ErrQUICVTPMDecodeFailed{Operation: "Quote", Err: err}
	}

	return &QuoteResult{
		BundleID:      quoteResp.BundleID,
		Quote:         quoteResp.Quote,
		Signature:     quoteResp.Signature,
		PCRValues:     quoteResp.PCRValues,
		HashAlgorithm: quoteResp.HashAlgorithm,
	}, nil
}

// Seal encrypts data to the TPM via QUIC.
func (q *QUICAdapter) Seal(ctx context.Context, opts SealOptions) (*SealResult, error) {
	req := &quicVTPMSealReq{
		BundleID:  opts.BundleID,
		Data:      opts.Data,
		PCRs:      opts.PCRs,
		AuthValue: opts.AuthValue,
	}

	resp, err := q.sendRequest(ctx, quicwire.OpVTPMSeal, req)
	if err != nil {
		return nil, err
	}

	var sealResp quicVTPMSealResp
	if err := decodeVTPMPayload(resp.Payload, &sealResp); err != nil {
		return nil, ErrQUICVTPMDecodeFailed{Operation: "Seal", Err: err}
	}

	return &SealResult{
		BundleID:   sealResp.BundleID,
		SealedData: sealResp.SealedData,
	}, nil
}

// Unseal decrypts data from the TPM via QUIC.
func (q *QUICAdapter) Unseal(ctx context.Context, opts UnsealOptions) (*UnsealResult, error) {
	req := &quicVTPMUnsealReq{
		BundleID:   opts.BundleID,
		SealedData: opts.SealedData,
		AuthValue:  opts.AuthValue,
	}

	resp, err := q.sendRequest(ctx, quicwire.OpVTPMUnseal, req)
	if err != nil {
		return nil, err
	}

	var unsealResp quicVTPMUnsealResp
	if err := decodeVTPMPayload(resp.Payload, &unsealResp); err != nil {
		return nil, ErrQUICVTPMDecodeFailed{Operation: "Unseal", Err: err}
	}

	return &UnsealResult{
		BundleID: unsealResp.BundleID,
		Data:     unsealResp.Data,
	}, nil
}

// ExtendPCR extends a PCR with the provided data via QUIC.
func (q *QUICAdapter) ExtendPCR(ctx context.Context, opts ExtendPCROptions) (*ExtendPCRResult, error) {
	req := &quicVTPMExtendPCRReq{
		BundleID: opts.BundleID,
		PCRIndex: opts.PCRIndex,
		Data:     opts.Data,
	}

	resp, err := q.sendRequest(ctx, quicwire.OpVTPMExtendPCR, req)
	if err != nil {
		return nil, err
	}

	var extendResp quicVTPMExtendPCRResp
	if err := decodeVTPMPayload(resp.Payload, &extendResp); err != nil {
		return nil, ErrQUICVTPMDecodeFailed{Operation: "ExtendPCR", Err: err}
	}

	return &ExtendPCRResult{
		BundleID: extendResp.BundleID,
		PCRIndex: extendResp.PCRIndex,
		Extended: extendResp.Extended,
	}, nil
}

// ReadPCR reads the current value of a PCR via QUIC.
func (q *QUICAdapter) ReadPCR(ctx context.Context, opts ReadPCROptions) (*ReadPCRResult, error) {
	req := &quicVTPMReadPCRReq{
		BundleID: opts.BundleID,
		PCRIndex: opts.PCRIndex,
	}

	resp, err := q.sendRequest(ctx, quicwire.OpVTPMReadPCR, req)
	if err != nil {
		return nil, err
	}

	var readResp quicVTPMReadPCRResp
	if err := decodeVTPMPayload(resp.Payload, &readResp); err != nil {
		return nil, ErrQUICVTPMDecodeFailed{Operation: "ReadPCR", Err: err}
	}

	return &ReadPCRResult{
		BundleID: readResp.BundleID,
		PCRIndex: readResp.PCRIndex,
		Value:    readResp.Value,
	}, nil
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

// Ensure QUICAdapter implements VTPMCommands interface.
var _ VTPMCommands = (*QUICAdapter)(nil)
