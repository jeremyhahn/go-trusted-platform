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

// Package secrets provides integration test adapters for Secrets services.
// This file implements the SecretsCommands interface using the QUIC protocol.

//go:build integration

package secrets

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
// Environment Variables and Constants
// =============================================================================

const (
	// EnvPlatformQUICEndpoint is the environment variable for the QUIC endpoint.
	EnvPlatformQUICEndpoint = "PLATFORM_QUIC_ENDPOINT"

	// DefaultQUICEndpoint is the default QUIC endpoint address.
	DefaultQUICEndpoint = "localhost:9444"

	// DefaultQUICTimeout is the default timeout for QUIC operations.
	DefaultQUICTimeout = 30 * time.Second

	// DefaultQUICMaxIdleTimeout is the default max idle timeout for connections.
	DefaultQUICMaxIdleTimeout = 60 * time.Second

	// QUICProtocolVersion is the QUIC wire protocol version.
	QUICProtocolVersion byte = 0x01

	// MaxQUICPayloadSize is the maximum payload size (16MB).
	MaxQUICPayloadSize uint32 = 16 * 1024 * 1024

	// MaxQUICTokenSize is the maximum token size (8KB).
	MaxQUICTokenSize uint16 = 8 * 1024
)

// QUIC Status codes.
const (
	QUICStatusOK                byte = 0x00
	QUICStatusInvalidRequest    byte = 0x01
	QUICStatusNotFound          byte = 0x02
	QUICStatusUnauthorized      byte = 0x03
	QUICStatusInternalError     byte = 0x04
	QUICStatusTimeout           byte = 0x05
	QUICStatusAlreadyExists     byte = 0x06
	QUICStatusPermissionDenied  byte = 0x07
	QUICStatusResourceExhausted byte = 0x08
	QUICStatusInvalidArgument   byte = 0x09
	QUICStatusUnavailable       byte = 0x0A
)

// QUIC Operation codes for Secrets operations.
const (
	OpQUICSecretsStore        byte = 0xE0
	OpQUICSecretsGet          byte = 0xE1
	OpQUICSecretsList         byte = 0xE2
	OpQUICSecretsDelete       byte = 0xE3
	OpQUICSecretsListVersions byte = 0xE4
	OpQUICSecretsRollback     byte = 0xE5
	OpQUICSecretsRotate       byte = 0xE6
	OpQUICSecretsStatus       byte = 0xFA
	OpQUICSecretsVersion      byte = 0xFB
	OpQUICSecretsPolicy       byte = 0xFC
	OpQUICSecretsPolicySet    byte = 0xFD
	OpQUICSecretsPrefix       byte = 0xFE
)

// =============================================================================
// Error Types
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

// ErrQUICRequestFailed indicates a QUIC request failure.
type ErrQUICRequestFailed struct {
	Operation string
	Status    byte
	Message   string
}

func (e ErrQUICRequestFailed) Error() string {
	return fmt.Sprintf("QUIC request %s failed (status 0x%02X): %s", e.Operation, e.Status, e.Message)
}

// ErrQUICEncodeFailed indicates payload encoding failure.
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

// ErrQUICDecodeFailed indicates payload decoding failure.
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

// ErrQUICStreamFailed indicates a stream operation failure.
type ErrQUICStreamFailed struct {
	Operation string
	Err       error
}

func (e ErrQUICStreamFailed) Error() string {
	return fmt.Sprintf("QUIC stream operation %s failed: %v", e.Operation, e.Err)
}

func (e ErrQUICStreamFailed) Unwrap() error {
	return e.Err
}

// ErrQUICClientClosed indicates the client is closed.
type ErrQUICClientClosed struct{}

func (e ErrQUICClientClosed) Error() string {
	return "QUIC client is closed"
}

// =============================================================================
// Wire Protocol Types
// =============================================================================

// quicRequest represents a QUIC protocol request.
type quicRequest struct {
	Opcode  byte
	Token   string
	Payload []byte
}

// quicResponse represents a QUIC protocol response.
type quicResponse struct {
	Status  byte
	Payload []byte
}

// =============================================================================
// Request/Response Payload Types (MessagePack encoded)
// =============================================================================

type secretsStoreRequest struct {
	Name        string `codec:"name"`
	Data        []byte `codec:"data"`
	Description string `codec:"description"`
	TenantID    string `codec:"tenant_id"`
	KeyID       string `codec:"key_id"`
	Algorithm   string `codec:"algorithm"`
}

type secretsStoreResponse struct {
	SecretID  string `codec:"secret_id"`
	Version   uint64 `codec:"version"`
	Timestamp int64  `codec:"timestamp"`
}

type secretsGetRequest struct {
	Name string `codec:"name"`
}

type secretsGetResponse struct {
	SecretID      string            `codec:"secret_id"`
	Version       uint64            `codec:"version"`
	Data          []byte            `codec:"data"`
	Metadata      map[string]string `codec:"metadata"`
	Algorithm     string            `codec:"algorithm"`
	KeyIdentifier string            `codec:"key_identifier"`
	CreatedAt     int64             `codec:"created_at"`
	Timestamp     int64             `codec:"timestamp"`
}

type secretsListRequest struct {
	Limit  int32  `codec:"limit"`
	Cursor string `codec:"cursor"`
}

type secretsListResponse struct {
	Secrets    []secretSummary `codec:"secrets"`
	TotalCount int32           `codec:"total_count"`
	HasMore    bool            `codec:"has_more"`
	NextCursor string          `codec:"next_cursor"`
}

type secretSummary struct {
	SecretID       string `codec:"secret_id"`
	Name           string `codec:"name"`
	CurrentVersion uint64 `codec:"current_version"`
	Description    string `codec:"description"`
	Owner          string `codec:"owner"`
	CreatedAt      int64  `codec:"created_at"`
	UpdatedAt      int64  `codec:"updated_at"`
}

type secretsDeleteRequest struct {
	Name      string `codec:"name"`
	Permanent bool   `codec:"permanent"`
}

type secretsDeleteResponse struct {
	SecretID  string `codec:"secret_id"`
	Deleted   bool   `codec:"deleted"`
	Timestamp int64  `codec:"timestamp"`
}

type secretsRotateRequest struct {
	Name    string `codec:"name"`
	NewData []byte `codec:"new_data"`
}

type secretsRotateResponse struct {
	SecretID   string `codec:"secret_id"`
	OldVersion uint64 `codec:"old_version"`
	NewVersion uint64 `codec:"new_version"`
	Timestamp  int64  `codec:"timestamp"`
}

type secretsVersionsRequest struct {
	Name string `codec:"name"`
}

type secretsVersionsResponse struct {
	SecretID   string              `codec:"secret_id"`
	Versions   []secretVersionInfo `codec:"versions"`
	HasMore    bool                `codec:"has_more"`
	NextCursor string              `codec:"next_cursor"`
}

type secretVersionInfo struct {
	Version   uint64 `codec:"version"`
	CreatedAt int64  `codec:"created_at"`
	CreatedBy string `codec:"created_by"`
	ExpiresAt int64  `codec:"expires_at"`
	DeletedAt int64  `codec:"deleted_at"`
}

type secretsVersionRequest struct {
	Name    string `codec:"name"`
	Version int    `codec:"version"`
}

type secretsVersionResponse struct {
	SecretID  string            `codec:"secret_id"`
	Version   uint64            `codec:"version"`
	Data      []byte            `codec:"data"`
	Metadata  map[string]string `codec:"metadata"`
	CreatedAt int64             `codec:"created_at"`
	CreatedBy string            `codec:"created_by"`
	ExpiresAt int64             `codec:"expires_at"`
	Timestamp int64             `codec:"timestamp"`
}

type secretsRollbackRequest struct {
	Name          string `codec:"name"`
	TargetVersion int    `codec:"target_version"`
}

type secretsRollbackResponse struct {
	SecretID   string `codec:"secret_id"`
	NewVersion uint64 `codec:"new_version"`
	Timestamp  int64  `codec:"timestamp"`
}

type secretsStatusRequest struct {
	Name    string `codec:"name"`
	Enabled bool   `codec:"enabled"`
}

type secretsStatusResponse struct {
	SecretID  string `codec:"secret_id"`
	Status    string `codec:"status"`
	Timestamp int64  `codec:"timestamp"`
}

type secretsPolicyRequest struct {
	Name string `codec:"name"`
}

type secretsPolicyResponse struct {
	SecretID        string `codec:"secret_id"`
	Enabled         bool   `codec:"enabled"`
	IntervalSeconds int64  `codec:"interval_seconds"`
	NextRotation    int64  `codec:"next_rotation"`
	RetainVersions  int32  `codec:"retain_versions"`
	RotationLambda  string `codec:"rotation_lambda"`
	UpdatedAt       int64  `codec:"updated_at"`
}

type secretsPolicySetRequest struct {
	Name            string `codec:"name"`
	Enabled         bool   `codec:"enabled"`
	IntervalSeconds int64  `codec:"interval_seconds"`
	RetainVersions  int32  `codec:"retain_versions"`
	RotationLambda  string `codec:"rotation_lambda"`
}

type secretsPolicySetResponse struct {
	SecretID  string `codec:"secret_id"`
	Timestamp int64  `codec:"timestamp"`
}

type secretsPrefixRequest struct {
	Prefix      string `codec:"prefix"`
	IncludeData bool   `codec:"include_data"`
}

type secretsPrefixResponse struct {
	Secrets    map[string]prefixSecretData `codec:"secrets"`
	TotalCount int32                       `codec:"total_count"`
	HasMore    bool                        `codec:"has_more"`
	NextCursor string                      `codec:"next_cursor"`
}

type prefixSecretData struct {
	Data     []byte            `codec:"data"`
	Metadata map[string]string `codec:"metadata"`
	Version  int64             `codec:"version"`
}

// =============================================================================
// QUIC Adapter Implementation
// =============================================================================

// QUICAdapter implements SecretsCommands using the QUIC protocol.
type QUICAdapter struct {
	endpoint       string
	conn           *quicgo.Conn
	tlsConfig      *tls.Config
	timeout        time.Duration
	maxIdleTimeout time.Duration

	mu     sync.RWMutex
	closed bool
}

// NewQUICAdapter creates a new QUIC adapter for integration testing.
func NewQUICAdapter() *QUICAdapter {
	endpoint := os.Getenv(EnvPlatformQUICEndpoint)
	if endpoint == "" {
		endpoint = DefaultQUICEndpoint
	}

	return &QUICAdapter{
		endpoint:       endpoint,
		timeout:        DefaultQUICTimeout,
		maxIdleTimeout: DefaultQUICMaxIdleTimeout,
		tlsConfig:      helpers.QUICTLSConfig([]string{"platform-quic"}),
	}
}

// NewQUICAdapterWithConfig creates a QUIC adapter with explicit configuration.
func NewQUICAdapterWithConfig(endpoint string, tlsConfig *tls.Config, timeout time.Duration) *QUICAdapter {
	if tlsConfig == nil {
		tlsConfig = helpers.QUICTLSConfig([]string{"platform-quic"})
	}

	return &QUICAdapter{
		endpoint:       endpoint,
		tlsConfig:      tlsConfig,
		timeout:        timeout,
		maxIdleTimeout: DefaultQUICMaxIdleTimeout,
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
		payloadBytes, err = encodePayload(payload)
		if err != nil {
			return nil, ErrQUICEncodeFailed{Operation: opcodeToString(opcode), Err: err}
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

	if err := writeRequest(stream, req); err != nil {
		return nil, ErrQUICStreamFailed{Operation: "WriteRequest", Err: err}
	}

	resp, err := readResponse(stream)
	if err != nil {
		return nil, ErrQUICStreamFailed{Operation: "ReadResponse", Err: err}
	}

	if resp.Status != QUICStatusOK {
		errMsg := string(resp.Payload)
		if errMsg == "" {
			errMsg = "unknown error"
		}
		return nil, ErrQUICRequestFailed{
			Operation: opcodeToString(opcode),
			Status:    resp.Status,
			Message:   errMsg,
		}
	}

	return resp, nil
}

func writeRequest(w io.Writer, req *quicRequest) error {
	payloadLen := uint32(len(req.Payload))
	if payloadLen > MaxQUICPayloadSize {
		return fmt.Errorf("payload size %d exceeds maximum %d", payloadLen, MaxQUICPayloadSize)
	}

	tokenLen := uint16(len(req.Token))
	if tokenLen > MaxQUICTokenSize {
		return fmt.Errorf("token size %d exceeds maximum %d", tokenLen, MaxQUICTokenSize)
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

func readResponse(r io.Reader) (*quicResponse, error) {
	statusBuf := make([]byte, 1)
	if _, err := io.ReadFull(r, statusBuf); err != nil {
		return nil, fmt.Errorf("failed to read status: %w", err)
	}

	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, fmt.Errorf("failed to read payload length: %w", err)
	}
	payloadLen := binary.BigEndian.Uint32(lenBuf)

	if payloadLen > MaxQUICPayloadSize {
		return nil, fmt.Errorf("payload size %d exceeds maximum %d", payloadLen, MaxQUICPayloadSize)
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

// defaultCodecType is the codec type used for payload encoding/decoding
var defaultCodecType = codec.MsgPack

// getCodec creates a codec of the default type using the factory
func getCodec() (codec.Codec[any], error) {
	return factory.New[any](defaultCodecType)
}

func encodePayload(entity interface{}) ([]byte, error) {
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

func decodePayload(data []byte, entity interface{}) error {
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

func opcodeToString(opcode byte) string {
	switch opcode {
	case OpQUICSecretsStore:
		return "SecretsStore"
	case OpQUICSecretsGet:
		return "SecretsGet"
	case OpQUICSecretsList:
		return "SecretsList"
	case OpQUICSecretsDelete:
		return "SecretsDelete"
	case OpQUICSecretsRotate:
		return "SecretsRotate"
	case OpQUICSecretsListVersions:
		return "SecretsVersions"
	case OpQUICSecretsVersion:
		return "SecretsVersion"
	case OpQUICSecretsRollback:
		return "SecretsRollback"
	case OpQUICSecretsStatus:
		return "SecretsStatus"
	case OpQUICSecretsPolicy:
		return "SecretsPolicy"
	case OpQUICSecretsPolicySet:
		return "SecretsPolicySet"
	case OpQUICSecretsPrefix:
		return "SecretsPrefix"
	default:
		return fmt.Sprintf("Unknown(0x%02X)", opcode)
	}
}

// =============================================================================
// SecretsCommands Interface Implementation
// =============================================================================

// Store stores a new secret via QUIC protocol.
func (q *QUICAdapter) Store(ctx context.Context, opts StoreOptions) (*StoreResult, error) {
	req := &secretsStoreRequest{
		Name:        opts.Name,
		Data:        opts.Data,
		Description: opts.Description,
		TenantID:    opts.TenantID,
		KeyID:       opts.KeyID,
		Algorithm:   opts.Algorithm,
	}

	resp, err := q.sendRequest(ctx, OpQUICSecretsStore, req)
	if err != nil {
		return nil, err
	}

	var result secretsStoreResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "Store", Err: err}
	}

	return &StoreResult{
		SecretID:  result.SecretID,
		Version:   result.Version,
		Timestamp: time.Unix(result.Timestamp, 0),
	}, nil
}

// Get retrieves a secret via QUIC protocol.
func (q *QUICAdapter) Get(ctx context.Context, name string) (*GetResult, error) {
	req := &secretsGetRequest{
		Name: name,
	}

	resp, err := q.sendRequest(ctx, OpQUICSecretsGet, req)
	if err != nil {
		return nil, err
	}

	var result secretsGetResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "Get", Err: err}
	}

	return &GetResult{
		SecretID:      result.SecretID,
		Version:       result.Version,
		Data:          result.Data,
		Metadata:      result.Metadata,
		Algorithm:     result.Algorithm,
		KeyIdentifier: result.KeyIdentifier,
		CreatedAt:     time.Unix(result.CreatedAt, 0),
		Timestamp:     time.Unix(result.Timestamp, 0),
	}, nil
}

// List lists secrets via QUIC protocol.
func (q *QUICAdapter) List(ctx context.Context, opts ListOptions) (*ListResult, error) {
	req := &secretsListRequest{
		Limit:  opts.Limit,
		Cursor: opts.Cursor,
	}

	resp, err := q.sendRequest(ctx, OpQUICSecretsList, req)
	if err != nil {
		return nil, err
	}

	var result secretsListResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "List", Err: err}
	}

	secrets := make([]SecretSummary, len(result.Secrets))
	for i, s := range result.Secrets {
		secrets[i] = SecretSummary{
			SecretID:       s.SecretID,
			Name:           s.Name,
			CurrentVersion: s.CurrentVersion,
			Description:    s.Description,
			Owner:          s.Owner,
			CreatedAt:      time.Unix(s.CreatedAt, 0),
			UpdatedAt:      time.Unix(s.UpdatedAt, 0),
		}
	}

	return &ListResult{
		Secrets:    secrets,
		TotalCount: result.TotalCount,
		HasMore:    result.HasMore,
		NextCursor: result.NextCursor,
	}, nil
}

// Delete deletes a secret via QUIC protocol.
func (q *QUICAdapter) Delete(ctx context.Context, name string, permanent bool) (*DeleteResult, error) {
	req := &secretsDeleteRequest{
		Name:      name,
		Permanent: permanent,
	}

	resp, err := q.sendRequest(ctx, OpQUICSecretsDelete, req)
	if err != nil {
		return nil, err
	}

	var result secretsDeleteResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "Delete", Err: err}
	}

	return &DeleteResult{
		SecretID:  result.SecretID,
		Deleted:   result.Deleted,
		Timestamp: time.Unix(result.Timestamp, 0),
	}, nil
}

// Rotate rotates a secret to a new value via QUIC protocol.
func (q *QUICAdapter) Rotate(ctx context.Context, name string, newData []byte) (*RotateResult, error) {
	req := &secretsRotateRequest{
		Name:    name,
		NewData: newData,
	}

	resp, err := q.sendRequest(ctx, OpQUICSecretsRotate, req)
	if err != nil {
		return nil, err
	}

	var result secretsRotateResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "Rotate", Err: err}
	}

	return &RotateResult{
		SecretID:   result.SecretID,
		OldVersion: result.OldVersion,
		NewVersion: result.NewVersion,
		Timestamp:  time.Unix(result.Timestamp, 0),
	}, nil
}

// Versions lists secret versions via QUIC protocol.
func (q *QUICAdapter) Versions(ctx context.Context, name string) (*VersionsResult, error) {
	req := &secretsVersionsRequest{
		Name: name,
	}

	resp, err := q.sendRequest(ctx, OpQUICSecretsListVersions, req)
	if err != nil {
		return nil, err
	}

	var result secretsVersionsResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "Versions", Err: err}
	}

	versions := make([]VersionInfo, len(result.Versions))
	for i, v := range result.Versions {
		versions[i] = VersionInfo{
			Version:   v.Version,
			CreatedAt: time.Unix(v.CreatedAt, 0),
			CreatedBy: v.CreatedBy,
			ExpiresAt: time.Unix(v.ExpiresAt, 0),
			DeletedAt: time.Unix(v.DeletedAt, 0),
		}
	}

	return &VersionsResult{
		SecretID:   result.SecretID,
		Versions:   versions,
		HasMore:    result.HasMore,
		NextCursor: result.NextCursor,
	}, nil
}

// Version retrieves a specific secret version via QUIC protocol.
func (q *QUICAdapter) Version(ctx context.Context, name string, version int) (*VersionResult, error) {
	req := &secretsVersionRequest{
		Name:    name,
		Version: version,
	}

	resp, err := q.sendRequest(ctx, OpQUICSecretsVersion, req)
	if err != nil {
		return nil, err
	}

	var result secretsVersionResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "Version", Err: err}
	}

	return &VersionResult{
		SecretID:  result.SecretID,
		Version:   result.Version,
		Data:      result.Data,
		Metadata:  result.Metadata,
		CreatedAt: time.Unix(result.CreatedAt, 0),
		CreatedBy: result.CreatedBy,
		ExpiresAt: time.Unix(result.ExpiresAt, 0),
		Timestamp: time.Unix(result.Timestamp, 0),
	}, nil
}

// Rollback rolls back to a previous secret version via QUIC protocol.
func (q *QUICAdapter) Rollback(ctx context.Context, name string, targetVersion int) (*RollbackResult, error) {
	req := &secretsRollbackRequest{
		Name:          name,
		TargetVersion: targetVersion,
	}

	resp, err := q.sendRequest(ctx, OpQUICSecretsRollback, req)
	if err != nil {
		return nil, err
	}

	var result secretsRollbackResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "Rollback", Err: err}
	}

	return &RollbackResult{
		SecretID:   result.SecretID,
		NewVersion: result.NewVersion,
		Timestamp:  time.Unix(result.Timestamp, 0),
	}, nil
}

// Status updates the status of a secret via QUIC protocol.
func (q *QUICAdapter) Status(ctx context.Context, name string, enabled bool) (*StatusResult, error) {
	req := &secretsStatusRequest{
		Name:    name,
		Enabled: enabled,
	}

	resp, err := q.sendRequest(ctx, OpQUICSecretsStatus, req)
	if err != nil {
		return nil, err
	}

	var result secretsStatusResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "Status", Err: err}
	}

	return &StatusResult{
		SecretID:  result.SecretID,
		Status:    result.Status,
		Timestamp: time.Unix(result.Timestamp, 0),
	}, nil
}

// Policy retrieves the rotation policy for a secret via QUIC protocol.
func (q *QUICAdapter) Policy(ctx context.Context, name string) (*PolicyResult, error) {
	req := &secretsPolicyRequest{
		Name: name,
	}

	resp, err := q.sendRequest(ctx, OpQUICSecretsPolicy, req)
	if err != nil {
		return nil, err
	}

	var result secretsPolicyResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "Policy", Err: err}
	}

	return &PolicyResult{
		SecretID:        result.SecretID,
		Enabled:         result.Enabled,
		IntervalSeconds: result.IntervalSeconds,
		NextRotation:    time.Unix(result.NextRotation, 0),
		RetainVersions:  result.RetainVersions,
		RotationLambda:  result.RotationLambda,
		UpdatedAt:       time.Unix(result.UpdatedAt, 0),
	}, nil
}

// PolicySet sets the rotation policy for a secret via QUIC protocol.
func (q *QUICAdapter) PolicySet(ctx context.Context, name string, opts PolicySetOptions) (*PolicySetResult, error) {
	req := &secretsPolicySetRequest{
		Name:            name,
		Enabled:         opts.Enabled,
		IntervalSeconds: opts.IntervalSeconds,
		RetainVersions:  opts.RetainVersions,
		RotationLambda:  opts.RotationLambda,
	}

	resp, err := q.sendRequest(ctx, OpQUICSecretsPolicySet, req)
	if err != nil {
		return nil, err
	}

	var result secretsPolicySetResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "PolicySet", Err: err}
	}

	return &PolicySetResult{
		SecretID:  result.SecretID,
		Timestamp: time.Unix(result.Timestamp, 0),
	}, nil
}

// Prefix searches for secrets by prefix via QUIC protocol.
func (q *QUICAdapter) Prefix(ctx context.Context, prefix string, includeData bool) (*PrefixResult, error) {
	req := &secretsPrefixRequest{
		Prefix:      prefix,
		IncludeData: includeData,
	}

	resp, err := q.sendRequest(ctx, OpQUICSecretsPrefix, req)
	if err != nil {
		return nil, err
	}

	var result secretsPrefixResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "Prefix", Err: err}
	}

	secrets := make(map[string]PrefixSecretData, len(result.Secrets))
	for name, s := range result.Secrets {
		secrets[name] = PrefixSecretData{
			Data:     s.Data,
			Metadata: s.Metadata,
			Version:  s.Version,
		}
	}

	return &PrefixResult{
		Secrets:    secrets,
		TotalCount: result.TotalCount,
		HasMore:    result.HasMore,
		NextCursor: result.NextCursor,
	}, nil
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

// Ensure QUICAdapter implements SecretsCommands interface.
var _ SecretsCommands = (*QUICAdapter)(nil)
