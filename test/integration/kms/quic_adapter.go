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

// Package kms provides integration test adapters for KMS services.
// This file implements the KMSCommands interface using the QUIC protocol.

//go:build integration

package kms

import (
	"context"
	"crypto/tls"
	"encoding/binary"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"time"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/daemon"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
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

// ErrQUICUnsupportedValue indicates a test value with no QUIC KMS wire form.
type ErrQUICUnsupportedValue struct {
	Kind  string
	Value string
}

func (e ErrQUICUnsupportedValue) Error() string {
	return fmt.Sprintf("QUIC KMS does not support %s %q", e.Kind, e.Value)
}

// ErrQUICMissingInResponse indicates a QUIC answer without a required field.
type ErrQUICMissingInResponse struct {
	Operation string
	Field     string
}

func (e ErrQUICMissingInResponse) Error() string {
	return fmt.Sprintf("QUIC %s response carries no %s", e.Operation, e.Field)
}

// =============================================================================
// Wire Protocol Types
// =============================================================================

// quicRequest represents a QUIC protocol request.
// Wire format: [opcode:1][tokenLen:2][token:N][payloadLen:4][payload:M].
type quicRequest struct {
	Opcode  byte
	Token   string
	Payload []byte
}

// quicResponse represents a QUIC protocol response.
// Wire format: [status:1][payloadLen:4][payload:N].
type quicResponse struct {
	Status  byte
	Payload []byte
}

// =============================================================================
// QUIC Adapter Implementation
// =============================================================================

// QUICAdapter implements KMSCommands using the QUIC protocol.
// It provides high-performance, low-latency communication with the platform
// using a binary protocol over QUIC streams with MessagePack encoding.
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
// It reads the endpoint from the PLATFORM_QUIC_ENDPOINT environment variable,
// defaulting to localhost:9444.
func NewQUICAdapter() *QUICAdapter {
	endpoint := os.Getenv(EnvPlatformQUICEndpoint)
	if endpoint == "" {
		endpoint = DefaultQUICEndpoint
	}

	return &QUICAdapter{
		endpoint:       endpoint,
		timeout:        DefaultQUICTimeout,
		maxIdleTimeout: DefaultQUICMaxIdleTimeout,
		tlsConfig:      helpers.QUICTLSConfig(),
	}
}

// NewQUICAdapterWithConfig creates a QUIC adapter with explicit configuration.
func NewQUICAdapterWithConfig(endpoint string, tlsConfig *tls.Config, timeout time.Duration) *QUICAdapter {
	if tlsConfig == nil {
		tlsConfig = helpers.QUICTLSConfig()
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

	// Create connection context with timeout
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

// call encodes req with the server's payload codec, sends it on opcode and
// decodes the answer into resp.
func (q *QUICAdapter) call(ctx context.Context, operation string, opcode byte, req, resp interface{}) error {
	body, err := quicwire.EncodePayload(req)
	if err != nil {
		return ErrQUICEncodeFailed{Operation: operation, Err: err}
	}
	return q.roundTrip(ctx, operation, opcode, body, resp)
}

// category sends req on a category opcode, the sub-opcode byte first, and
// decodes the answer into resp.
func (q *QUICAdapter) category(ctx context.Context, operation string, opcode, sub byte, req, resp interface{}) error {
	body, err := quicwire.EncodePayload(req)
	if err != nil {
		return ErrQUICEncodeFailed{Operation: operation, Err: err}
	}
	return q.roundTrip(ctx, operation, opcode, append([]byte{sub}, body...), resp)
}

// roundTrip sends an encoded payload and decodes the answer into resp.
func (q *QUICAdapter) roundTrip(ctx context.Context, operation string, opcode byte, payload []byte, resp interface{}) error {
	answer, err := q.sendPayload(ctx, operation, opcode, payload)
	if err != nil {
		return err
	}
	if err := quicwire.DecodePayload(answer.Payload, resp); err != nil {
		return ErrQUICDecodeFailed{Operation: operation, Err: err}
	}
	return nil
}

// sendPayload sends already-encoded payload bytes and returns the response.
func (q *QUICAdapter) sendPayload(ctx context.Context, operation string, opcode byte, payloadBytes []byte) (*quicResponse, error) {
	q.mu.RLock()
	if q.closed {
		q.mu.RUnlock()
		return nil, ErrQUICClientClosed{}
	}
	conn := q.conn
	q.mu.RUnlock()

	// Open stream
	stream, err := conn.OpenStreamSync(ctx)
	if err != nil {
		return nil, ErrQUICStreamFailed{Operation: "OpenStream", Err: err}
	}
	defer stream.Close()

	// Write request
	req := &quicRequest{
		Opcode:  opcode,
		Payload: payloadBytes,
	}

	if err := writeRequest(stream, req); err != nil {
		return nil, ErrQUICStreamFailed{Operation: "WriteRequest", Err: err}
	}

	// Read response
	resp, err := readResponse(stream)
	if err != nil {
		return nil, ErrQUICStreamFailed{Operation: "ReadResponse", Err: err}
	}

	// Check status
	if resp.Status != QUICStatusOK {
		errMsg := string(resp.Payload)
		if errMsg == "" {
			errMsg = "unknown error"
		}
		return nil, ErrQUICRequestFailed{
			Operation: operation,
			Status:    resp.Status,
			Message:   errMsg,
		}
	}

	return resp, nil
}

// writeRequest writes a request to the stream.
func writeRequest(w io.Writer, req *quicRequest) error {
	payloadLen := uint32(len(req.Payload))
	if payloadLen > MaxQUICPayloadSize {
		return fmt.Errorf("payload size %d exceeds maximum %d", payloadLen, MaxQUICPayloadSize)
	}

	tokenLen := uint16(len(req.Token))
	if tokenLen > MaxQUICTokenSize {
		return fmt.Errorf("token size %d exceeds maximum %d", tokenLen, MaxQUICTokenSize)
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

// readResponse reads a response from the stream.
func readResponse(r io.Reader) (*quicResponse, error) {
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

	if payloadLen > MaxQUICPayloadSize {
		return nil, fmt.Errorf("payload size %d exceeds maximum %d", payloadLen, MaxQUICPayloadSize)
	}

	// Read payload
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

// =============================================================================
// KMSCommands Interface Implementation - Key Management
// =============================================================================

// KeyGenerate creates a key on OpKMSGenerateKey. The request's name is the
// key ID (docs/kms/api.md §2), its usages follow the test's purpose, and the
// display name and description are applied as metadata afterwards.
func (q *QUICAdapter) KeyGenerate(ctx context.Context, opts KeyGenerateOptions) (*KeyGenerateResult, error) {
	algorithm, err := quicKeyAlgorithm(opts.Algorithm)
	if err != nil {
		return nil, err
	}
	usages, err := quicUsages(opts.Purpose, algorithm)
	if err != nil {
		return nil, err
	}
	req := &daemon.KMSGenerateKeyRequest{
		KeySpec: &daemon.KMSKeySpecRequest{
			Algorithm:          algorithm,
			Usage:              usages,
			Exportable:         opts.Exportable,
			DeletionProtection: opts.DeletionProtection,
		},
		Name:        keyName(opts),
		Description: opts.Description,
		Owner:       opts.Owner,
	}

	var resp daemon.KMSGenerateKeyResponse
	if err := q.call(ctx, "KeyGenerate", quicwire.OpKMSGenerateKey, req, &resp); err != nil {
		return nil, err
	}
	if resp.Key == nil || resp.Metadata == nil {
		return nil, ErrQUICMissingInResponse{Operation: "KeyGenerate", Field: "key"}
	}

	result := &KeyGenerateResult{
		KeyID:              resp.Key.KeyId,
		Version:            resp.Key.Version,
		Algorithm:          quicAlgorithmName(resp.Key.Algorithm),
		Status:             quicStatusName(resp.Key.Status),
		CreatedAt:          grpcUnixToTime(resp.Key.CreatedAt),
		Name:               resp.Metadata.Name,
		Description:        resp.Metadata.Description,
		Exportable:         resp.Metadata.Exportable,
		DeletionProtection: resp.Metadata.DeletionProtection,
	}
	if err := applyKeyDisplay(ctx, q, opts, result); err != nil {
		return nil, err
	}
	return result, nil
}

// KeyGet reads a key on OpKMSGetKey.
func (q *QUICAdapter) KeyGet(ctx context.Context, keyID string, version uint64) (*KeyGetResult, error) {
	req := &daemon.KMSGetKeyRequest{KeyId: keyID, Version: version}

	var resp daemon.KMSGetKeyResponse
	if err := q.call(ctx, "KeyGet", quicwire.OpKMSGetKey, req, &resp); err != nil {
		return nil, err
	}
	if resp.Key == nil || resp.Metadata == nil {
		return nil, ErrQUICMissingInResponse{Operation: "KeyGet", Field: "key"}
	}

	return &KeyGetResult{
		KeyID:              resp.Key.KeyId,
		Version:            resp.Key.Version,
		Algorithm:          quicAlgorithmName(resp.Key.Algorithm),
		Status:             quicStatusName(resp.Key.Status),
		CreatedAt:          grpcUnixToTime(resp.Key.CreatedAt),
		UpdatedAt:          grpcUnixToTime(resp.Metadata.UpdatedAt),
		LastUsedAt:         grpcUnixToTime(resp.Metadata.LastUsedAt),
		Name:               resp.Metadata.Name,
		Description:        resp.Metadata.Description,
		Owner:              resp.Metadata.Owner,
		Exportable:         resp.Metadata.Exportable,
		DeletionProtection: resp.Metadata.DeletionProtection,
		Usage:              quicUsageNames(resp.Metadata.Usage),
	}, nil
}

// KeyList lists keys on OpKMSListKeys.
func (q *QUICAdapter) KeyList(ctx context.Context, opts KeyListOptions) (*KeyListResult, error) {
	req := &daemon.KMSListKeysRequest{Limit: opts.Limit, Cursor: opts.Cursor}

	var resp daemon.KMSListKeysResponse
	if err := q.call(ctx, "KeyList", quicwire.OpKMSListKeys, req, &resp); err != nil {
		return nil, err
	}

	keys := make([]KeySummary, 0, len(resp.Keys))
	for _, k := range resp.Keys {
		keys = append(keys, KeySummary{
			KeyID:     k.KeyId,
			Version:   k.Version,
			Algorithm: quicAlgorithmName(k.Algorithm),
			Status:    quicStatusName(k.Status),
			CreatedAt: grpcUnixToTime(k.CreatedAt),
		})
	}

	return &KeyListResult{
		Keys:       keys,
		TotalCount: resp.TotalCount,
		HasMore:    resp.HasMore,
		NextCursor: resp.NextCursor,
	}, nil
}

// KeyDelete schedules a key for deletion on OpKMSDeleteKey.
func (q *QUICAdapter) KeyDelete(ctx context.Context, keyID string, opts KeyDeleteOptions) (*KeyDeleteResult, error) {
	req := &daemon.KMSDeleteKeyRequest{
		KeyId:             keyID,
		PendingWindowDays: opts.PendingWindowDays,
		Force:             opts.Force,
	}

	var resp daemon.KMSDeleteKeyResponse
	if err := q.call(ctx, "KeyDelete", quicwire.OpKMSDeleteKey, req, &resp); err != nil {
		return nil, err
	}

	return &KeyDeleteResult{
		KeyID:        resp.KeyId,
		Status:       quicStatusName(resp.KeyStatus),
		DeletionDate: grpcUnixToTime(resp.DeletionDate),
	}, nil
}

// KeyRotate rotates a key on OpKMSRotateKey.
func (q *QUICAdapter) KeyRotate(ctx context.Context, keyID string, retainOldVersion bool) (*KeyRotateResult, error) {
	req := &daemon.KMSRotateKeyRequest{KeyId: keyID, RetainOldVersion: retainOldVersion}

	var resp daemon.KMSRotateKeyResponse
	if err := q.call(ctx, "KeyRotate", quicwire.OpKMSRotateKey, req, &resp); err != nil {
		return nil, err
	}

	return &KeyRotateResult{
		KeyID:      resp.KeyId,
		OldVersion: resp.OldVersion,
		NewVersion: resp.NewVersion,
		RotatedAt:  grpcUnixToTime(resp.Timestamp),
	}, nil
}

// KeyVersions lists a key's versions on OpKMSGetKeyVersions.
func (q *QUICAdapter) KeyVersions(ctx context.Context, keyID string, opts KeyVersionsOptions) (*KeyVersionsResult, error) {
	req := &daemon.KMSGetKeyVersionsRequest{KeyId: keyID, Limit: opts.Limit, Cursor: opts.Cursor}

	var resp daemon.KMSGetKeyVersionsResponse
	if err := q.call(ctx, "KeyVersions", quicwire.OpKMSGetKeyVersions, req, &resp); err != nil {
		return nil, err
	}

	versions := make([]KeyVersionInfo, 0, len(resp.Versions))
	for _, v := range resp.Versions {
		versions = append(versions, KeyVersionInfo{
			Version:    v.Version,
			Algorithm:  quicAlgorithmName(v.Algorithm),
			Status:     quicStatusName(v.Status),
			CreatedAt:  grpcUnixToTime(v.CreatedAt),
			DisabledAt: grpcUnixToTime(v.DisabledAt),
		})
	}

	return &KeyVersionsResult{
		KeyID:      resp.KeyId,
		Versions:   versions,
		HasMore:    resp.HasMore,
		NextCursor: resp.NextCursor,
	}, nil
}

// KeyStatus enables or disables a key version on OpKMSUpdateKeyStatus.
func (q *QUICAdapter) KeyStatus(ctx context.Context, keyID string, version uint64, enabled bool) (*KeyStatusResult, error) {
	status := platformv1.KeyStatus_KEY_STATUS_DISABLED
	if enabled {
		status = platformv1.KeyStatus_KEY_STATUS_ENABLED
	}
	req := &daemon.KMSUpdateKeyStatusRequest{KeyId: keyID, Version: version, Status: int32(status)}

	var resp daemon.KMSUpdateKeyStatusResponse
	if err := q.call(ctx, "KeyStatus", quicwire.OpKMSUpdateKeyStatus, req, &resp); err != nil {
		return nil, err
	}

	return &KeyStatusResult{
		KeyID:     resp.KeyId,
		Version:   resp.Version,
		Status:    quicStatusName(resp.KeyStatus),
		UpdatedAt: grpcUnixToTime(resp.Timestamp),
	}, nil
}

// kmsCategory sends req on the KMS extended category opcode (0xCD).
func (q *QUICAdapter) kmsCategory(ctx context.Context, operation string, sub byte, req, resp interface{}) error {
	return q.category(ctx, operation, quicwire.OpKMSExtendedCategory, sub, req, resp)
}

// KeyRevoke revokes a key through KMSSubRevokeKey. The server reports the
// status by its enum name (KEY_STATUS_COMPROMISED); the prefix is dropped to
// match the other transports.
func (q *QUICAdapter) KeyRevoke(ctx context.Context, keyID string, reason string) (*KeyRevokeResult, error) {
	req := &daemon.KMSRevokeKeyRequest{KeyID: keyID, Reason: reason}

	var resp daemon.KMSRevokeKeyResponse
	if err := q.kmsCategory(ctx, "KeyRevoke", quicwire.KMSSubRevokeKey, req, &resp); err != nil {
		return nil, err
	}

	return &KeyRevokeResult{
		KeyID:     resp.KeyID,
		Status:    strings.TrimPrefix(resp.Status, keyStatusPrefix),
		RevokedAt: grpcUnixToTime(resp.Timestamp),
	}, nil
}

// KeyMetadata reads a key's metadata through KMSSubGetKeyMetadata.
func (q *QUICAdapter) KeyMetadata(ctx context.Context, keyID string) (*KeyMetadataResult, error) {
	var resp daemon.KMSGetKeyMetadataResponse
	if err := q.kmsCategory(ctx, "KeyMetadata", quicwire.KMSSubGetKeyMetadata, &daemon.KMSGetKeyMetadataRequest{KeyID: keyID}, &resp); err != nil {
		return nil, err
	}
	m := resp.Metadata
	if m == nil {
		return nil, ErrQUICMissingInResponse{Operation: "KeyMetadata", Field: "metadata"}
	}

	return &KeyMetadataResult{
		KeyID:              m.KeyId,
		Name:               m.Name,
		Description:        m.Description,
		Algorithm:          quicAlgorithmName(m.Algorithm),
		Status:             quicStatusName(m.Status),
		Version:            m.Version,
		Exportable:         m.Exportable,
		DeletionProtection: m.DeletionProtection,
		Usage:              quicUsageNames(m.Usage),
		Owner:              m.Owner,
		CreatedAt:          grpcUnixToTime(m.CreatedAt),
		UpdatedAt:          grpcUnixToTime(m.UpdatedAt),
		LastUsedAt:         grpcUnixToTime(m.LastUsedAt),
		Tags:               m.Tags,
	}, nil
}

// KeyMetadataUpdate updates a key's metadata through KMSSubUpdateKeyMetadata.
func (q *QUICAdapter) KeyMetadataUpdate(ctx context.Context, keyID string, opts KeyMetadataUpdateOptions) (*KeyMetadataUpdateResult, error) {
	req := &daemon.KMSUpdateKeyMetadataRequest{
		KeyID:       keyID,
		Name:        opts.Name,
		Description: opts.Description,
		Tags:        opts.Tags,
		RemoveTags:  opts.RemoveTags,
	}

	var resp daemon.KMSUpdateKeyMetadataResponse
	if err := q.kmsCategory(ctx, "KeyMetadataUpdate", quicwire.KMSSubUpdateKeyMetadata, req, &resp); err != nil {
		return nil, err
	}
	m := resp.Metadata
	if m == nil {
		return nil, ErrQUICMissingInResponse{Operation: "KeyMetadataUpdate", Field: "metadata"}
	}

	return &KeyMetadataUpdateResult{
		KeyID:     m.KeyId,
		Name:      m.Name,
		UpdatedAt: grpcUnixToTime(m.UpdatedAt),
		Tags:      m.Tags,
	}, nil
}

// KeyPolicy reads a key's policy through KMSSubGetKeyPolicy.
func (q *QUICAdapter) KeyPolicy(ctx context.Context, keyID string) (*KeyPolicyResult, error) {
	var resp daemon.KMSGetKeyPolicyResponse
	if err := q.kmsCategory(ctx, "KeyPolicy", quicwire.KMSSubGetKeyPolicy, &daemon.KMSGetKeyPolicyRequest{KeyID: keyID}, &resp); err != nil {
		return nil, err
	}
	p := resp.Policy
	if p == nil {
		return nil, ErrQUICMissingInResponse{Operation: "KeyPolicy", Field: "policy"}
	}

	return &KeyPolicyResult{
		KeyID:             p.KeyID,
		Version:           int32(p.Version),
		AllowedOperations: p.AllowedOperations,
		AllowedPrincipals: p.AllowedPrincipals,
		DeniedPrincipals:  p.DeniedPrincipals,
		ExpiresAt:         grpcUnixToTime(p.ExpiresAt),
		RotationRequired:  p.RotationRequired,
		MaxUsageCount:     p.MaxUsageCount,
		RequireMFA:        p.RequireMFA,
		UpdatedAt:         grpcUnixToTime(p.UpdatedAt),
	}, nil
}

// KeyPolicySet sets a key's policy through KMSSubSetKeyPolicy. ExpiresIn is a
// Go duration counted from now.
func (q *QUICAdapter) KeyPolicySet(ctx context.Context, keyID string, opts KeyPolicySetOptions) (*KeyPolicySetResult, error) {
	expiresAt, err := quicExpiresAt(opts.ExpiresIn, time.Now())
	if err != nil {
		return nil, err
	}
	req := &daemon.KMSSetKeyPolicyRequest{
		KeyID: keyID,
		Policy: &daemon.KMSKeyPolicyPayload{
			KeyID:             keyID,
			AllowedOperations: opts.Operations,
			AllowedPrincipals: opts.AllowPrincipals,
			DeniedPrincipals:  opts.DenyPrincipals,
			ExpiresAt:         expiresAt,
			RotationRequired:  opts.RotationRequired,
			MaxUsageCount:     opts.MaxUsageCount,
			RequireMFA:        opts.RequireMFA,
		},
	}

	var resp daemon.KMSSetKeyPolicyResponse
	if err := q.kmsCategory(ctx, "KeyPolicySet", quicwire.KMSSubSetKeyPolicy, req, &resp); err != nil {
		return nil, err
	}

	return &KeyPolicySetResult{
		KeyID:         resp.KeyID,
		PolicyVersion: int32(resp.PolicyVersion),
		UpdatedAt:     grpcUnixToTime(resp.Timestamp),
	}, nil
}

// KeyAlgorithms lists the supported algorithms through
// KMSSubGetSupportedAlgorithms.
func (q *QUICAdapter) KeyAlgorithms(ctx context.Context) (*KeyAlgorithmsResult, error) {
	var resp daemon.KMSGetSupportedAlgorithmsResponse
	if err := q.kmsCategory(ctx, "KeyAlgorithms", quicwire.KMSSubGetSupportedAlgorithms, struct{}{}, &resp); err != nil {
		return nil, err
	}
	return &KeyAlgorithmsResult{Algorithms: resp.Algorithms}, nil
}

// =============================================================================
// KMSCommands Interface Implementation - Crypto Operations
// =============================================================================

// CryptoEncrypt encrypts on OpKMSEncrypt.
func (q *QUICAdapter) CryptoEncrypt(ctx context.Context, opts CryptoEncryptOptions) (*CryptoEncryptResult, error) {
	req := &daemon.KMSEncryptRequest{
		KeyId:     opts.KeyID,
		Plaintext: opts.Plaintext,
		Context:   opts.Context,
		Nonce:     opts.Nonce,
	}

	var resp daemon.KMSEncryptResponse
	if err := q.call(ctx, "CryptoEncrypt", quicwire.OpKMSEncrypt, req, &resp); err != nil {
		return nil, err
	}

	return &CryptoEncryptResult{
		KeyID:      resp.KeyId,
		KeyVersion: resp.KeyVersion,
		Ciphertext: resp.Ciphertext,
		Nonce:      resp.Nonce,
		Timestamp:  grpcUnixToTime(resp.Timestamp),
	}, nil
}

// CryptoDecrypt decrypts on OpKMSDecrypt.
func (q *QUICAdapter) CryptoDecrypt(ctx context.Context, opts CryptoDecryptOptions) (*CryptoDecryptResult, error) {
	req := &daemon.KMSDecryptRequest{
		KeyId:      opts.KeyID,
		Ciphertext: opts.Ciphertext,
		Context:    opts.Context,
		Nonce:      opts.Nonce,
		KeyVersion: opts.KeyVersion,
	}

	var resp daemon.KMSDecryptResponse
	if err := q.call(ctx, "CryptoDecrypt", quicwire.OpKMSDecrypt, req, &resp); err != nil {
		return nil, err
	}

	return &CryptoDecryptResult{
		KeyID:      resp.KeyId,
		KeyVersion: resp.KeyVersion,
		Plaintext:  resp.Plaintext,
		Timestamp:  grpcUnixToTime(resp.Timestamp),
	}, nil
}

// CryptoSign signs on OpKMSSign.
func (q *QUICAdapter) CryptoSign(ctx context.Context, opts CryptoSignOptions) (*CryptoSignResult, error) {
	hash, err := quicHashAlgorithm(opts.HashAlgorithm)
	if err != nil {
		return nil, err
	}
	req := &daemon.KMSSignRequest{KeyId: opts.KeyID, Message: opts.Message, HashAlgorithm: hash}

	var resp daemon.KMSSignResponse
	if err := q.call(ctx, "CryptoSign", quicwire.OpKMSSign, req, &resp); err != nil {
		return nil, err
	}

	return &CryptoSignResult{
		KeyID:         resp.KeyId,
		KeyVersion:    resp.KeyVersion,
		Signature:     resp.Signature,
		HashAlgorithm: quicHashName(resp.HashAlgorithm),
		Timestamp:     grpcUnixToTime(resp.Timestamp),
	}, nil
}

// CryptoVerify verifies a signature on OpKMSVerify.
func (q *QUICAdapter) CryptoVerify(ctx context.Context, opts CryptoVerifyOptions) (*CryptoVerifyResult, error) {
	hash, err := quicHashAlgorithm(opts.HashAlgorithm)
	if err != nil {
		return nil, err
	}
	req := &daemon.KMSVerifyRequest{
		KeyId:         opts.KeyID,
		Message:       opts.Message,
		Signature:     opts.Signature,
		HashAlgorithm: hash,
		KeyVersion:    opts.KeyVersion,
	}

	var resp daemon.KMSVerifyResponse
	if err := q.call(ctx, "CryptoVerify", quicwire.OpKMSVerify, req, &resp); err != nil {
		return nil, err
	}

	return &CryptoVerifyResult{
		KeyID:      resp.KeyId,
		KeyVersion: resp.KeyVersion,
		Valid:      resp.Valid,
		Timestamp:  grpcUnixToTime(resp.Timestamp),
	}, nil
}

// CryptoHash hashes data on OpKMSHash.
func (q *QUICAdapter) CryptoHash(ctx context.Context, data []byte, algorithm string) (*CryptoHashResult, error) {
	hash, err := quicHashAlgorithm(algorithm)
	if err != nil {
		return nil, err
	}

	var resp daemon.KMSHashResponse
	if err := q.call(ctx, "CryptoHash", quicwire.OpKMSHash, &daemon.KMSHashRequest{Data: data, Algorithm: hash}, &resp); err != nil {
		return nil, err
	}

	return &CryptoHashResult{
		Algorithm: quicHashName(resp.Algorithm),
		Hash:      resp.Hash,
		Timestamp: grpcUnixToTime(resp.Timestamp),
	}, nil
}

// CryptoHMAC computes an HMAC on OpKMSHMAC.
func (q *QUICAdapter) CryptoHMAC(ctx context.Context, opts CryptoHMACOptions) (*CryptoHMACResult, error) {
	hash, err := quicHashAlgorithm(opts.HashAlgorithm)
	if err != nil {
		return nil, err
	}
	req := &daemon.KMSHMACRequest{KeyId: opts.KeyID, Message: opts.Message, HashAlgorithm: hash}

	var resp daemon.KMSHMACResponse
	if err := q.call(ctx, "CryptoHMAC", quicwire.OpKMSHMAC, req, &resp); err != nil {
		return nil, err
	}

	return &CryptoHMACResult{
		KeyID:         resp.KeyId,
		KeyVersion:    resp.KeyVersion,
		HMAC:          resp.Hmac,
		HashAlgorithm: quicHashName(resp.HashAlgorithm),
		Timestamp:     grpcUnixToTime(resp.Timestamp),
	}, nil
}

// CryptoVerifyHMAC verifies an HMAC on OpKMSVerifyHMAC.
func (q *QUICAdapter) CryptoVerifyHMAC(ctx context.Context, opts CryptoVerifyHMACOptions) (*CryptoVerifyHMACResult, error) {
	hash, err := quicHashAlgorithm(opts.HashAlgorithm)
	if err != nil {
		return nil, err
	}
	req := &daemon.KMSVerifyHMACRequest{
		KeyId:         opts.KeyID,
		Message:       opts.Message,
		Hmac:          opts.HMAC,
		HashAlgorithm: hash,
		KeyVersion:    opts.KeyVersion,
	}

	var resp daemon.KMSVerifyHMACResponse
	if err := q.call(ctx, "CryptoVerifyHMAC", quicwire.OpKMSVerifyHMAC, req, &resp); err != nil {
		return nil, err
	}

	return &CryptoVerifyHMACResult{
		KeyID:      resp.KeyId,
		KeyVersion: resp.KeyVersion,
		Valid:      resp.Valid,
		Timestamp:  grpcUnixToTime(resp.Timestamp),
	}, nil
}

// CryptoRandom draws random bytes on OpKMSGenerateRandom.
func (q *QUICAdapter) CryptoRandom(ctx context.Context, numBytes int) (*CryptoRandomResult, error) {
	var resp daemon.KMSGenerateRandomResponse
	if err := q.call(ctx, "CryptoRandom", quicwire.OpKMSGenerateRandom, &daemon.KMSGenerateRandomRequest{NumBytes: int32(numBytes)}, &resp); err != nil {
		return nil, err
	}
	return &CryptoRandomResult{
		RandomBytes: resp.RandomBytes,
		Timestamp:   grpcUnixToTime(resp.Timestamp),
	}, nil
}

// =============================================================================
// KMSCommands Interface Implementation - DEK Operations
// =============================================================================
//
// DEK operations ride the KMS extended category (0xCD) on sub-opcodes
// KMSSubCreateDEK..KMSSubDeleteDEK and carry the QuicBaaS DEK messages.

// DEKCreate creates a DEK through KMSSubCreateDEK.
func (q *QUICAdapter) DEKCreate(ctx context.Context, opts DEKCreateOptions) (*DEKCreateResult, error) {
	var resp pb.CreateDEKResponse
	if err := q.kmsCategory(ctx, "DEKCreate", quicwire.KMSSubCreateDEK, newCreateDEKRequest(opts), &resp); err != nil {
		return nil, err
	}
	return dekCreateResult(&resp)
}

// DEKGet reads a DEK through KMSSubGetDEK.
func (q *QUICAdapter) DEKGet(ctx context.Context, path string) (*DEKGetResult, error) {
	var resp pb.GetDEKResponse
	if err := q.kmsCategory(ctx, "DEKGet", quicwire.KMSSubGetDEK, &pb.GetDEKRequest{Path: path}, &resp); err != nil {
		return nil, err
	}
	return dekGetResult(&resp)
}

// DEKList lists DEKs through KMSSubListDEKs.
func (q *QUICAdapter) DEKList(ctx context.Context, opts DEKListOptions) (*DEKListResult, error) {
	var resp pb.ListDEKsResponse
	if err := q.kmsCategory(ctx, "DEKList", quicwire.KMSSubListDEKs, newListDEKsRequest(opts), &resp); err != nil {
		return nil, err
	}
	return dekListResult(&resp), nil
}

// DEKDelete deletes a DEK through KMSSubDeleteDEK.
func (q *QUICAdapter) DEKDelete(ctx context.Context, path string, opts DEKDeleteOptions) (*DEKDeleteResult, error) {
	req := &pb.DeleteDEKRequest{Path: path, Force: opts.Force, MigrateTo: opts.MigrateTo}

	var resp pb.DeleteDEKResponse
	if err := q.kmsCategory(ctx, "DEKDelete", quicwire.KMSSubDeleteDEK, req, &resp); err != nil {
		return nil, err
	}
	return &DEKDeleteResult{Path: resp.Path, Deleted: resp.Deleted}, nil
}

// DEKRotate rotates a DEK through KMSSubRotateDEK.
func (q *QUICAdapter) DEKRotate(ctx context.Context, path string, background bool) (*DEKRotateResult, error) {
	req := &pb.RotateDEKRequest{Path: path, Background: background}

	var resp pb.RotateDEKResponse
	if err := q.kmsCategory(ctx, "DEKRotate", quicwire.KMSSubRotateDEK, req, &resp); err != nil {
		return nil, err
	}
	return &DEKRotateResult{Path: resp.Path, OldVersion: resp.OldVersion, NewVersion: resp.NewVersion}, nil
}

// DEKStatus reads a DEK's status through KMSSubGetDEKStatus.
func (q *QUICAdapter) DEKStatus(ctx context.Context, path string) (*DEKStatusResult, error) {
	var resp pb.GetDEKStatusResponse
	if err := q.kmsCategory(ctx, "DEKStatus", quicwire.KMSSubGetDEKStatus, &pb.GetDEKStatusRequest{Path: path}, &resp); err != nil {
		return nil, err
	}
	return dekStatusResult(&resp)
}

// =============================================================================
// QUIC KMS wire value conversions
// =============================================================================
//
// The QUIC KMS messages carry platform.v1 enum numbers. Requests map the
// test vocabulary onto them; answers are named by the enum with its prefix
// dropped (ENABLED, SHA256, AES_256), matching the Unix and REST transports.

const (
	keyAlgorithmPrefix  = "KMS_KEY_ALGORITHM_"
	keyStatusPrefix     = "KEY_STATUS_"
	keyUsagePrefix      = "KEY_USAGE_"
	hashAlgorithmPrefix = "HASH_ALGORITHM_"
)

// quicKeyAlgorithms holds the key algorithms the QUIC KMS server accepts,
// keyed by upper-case test name. An empty name lets the server pick.
var quicKeyAlgorithms = map[string]platformv1.KMSKeyAlgorithm{
	"":                  platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_UNSPECIFIED,
	"AES-256":           platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256,
	"AES-256-GCM":       platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256,
	"CHACHA20-POLY1305": platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_CHACHA20_POLY1305,
	"RSA-2048":          platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_2048,
	"RSA-4096":          platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_4096,
	"ECDSA-P256":        platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P256,
	"ECDSA-P384":        platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P384,
	"ED25519":           platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ED25519,
}

// quicHashAlgorithms holds the hash algorithms the QUIC KMS server accepts,
// keyed by upper-case test name. An empty name means the SHA-256 default.
var quicHashAlgorithms = map[string]platformv1.HashAlgorithm{
	"":        platformv1.HashAlgorithm_HASH_ALGORITHM_UNSPECIFIED,
	"SHA256":  platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256,
	"SHA-256": platformv1.HashAlgorithm_HASH_ALGORITHM_SHA256,
	"SHA384":  platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384,
	"SHA-384": platformv1.HashAlgorithm_HASH_ALGORITHM_SHA384,
	"SHA512":  platformv1.HashAlgorithm_HASH_ALGORITHM_SHA512,
	"SHA-512": platformv1.HashAlgorithm_HASH_ALGORITHM_SHA512,
}

// quicKeyAlgorithm maps a test algorithm name to its wire number.
func quicKeyAlgorithm(name string) (int32, error) {
	alg, ok := quicKeyAlgorithms[strings.ToUpper(name)]
	if !ok {
		return 0, ErrQUICUnsupportedValue{Kind: "key algorithm", Value: name}
	}
	return int32(alg), nil
}

var (
	quicEncryptUsages = []int32{
		int32(platformv1.KeyUsage_KEY_USAGE_ENCRYPT),
		int32(platformv1.KeyUsage_KEY_USAGE_DECRYPT),
	}
	quicSignUsages = []int32{
		int32(platformv1.KeyUsage_KEY_USAGE_SIGN),
		int32(platformv1.KeyUsage_KEY_USAGE_VERIFY),
	}
	quicWrapUsages = []int32{int32(platformv1.KeyUsage_KEY_USAGE_WRAP)}
)

// quicPurposes maps the suite's key purposes to wire key usages.
var quicPurposes = map[string][]int32{
	"encrypt":         quicEncryptUsages,
	"encrypt_decrypt": quicEncryptUsages,
	"sign":            quicSignUsages,
	"sign_verify":     quicSignUsages,
	"wrap":            quicWrapUsages,
}

// quicSigningAlgorithms are the algorithms whose default purpose is signing.
var quicSigningAlgorithms = map[platformv1.KMSKeyAlgorithm]bool{
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P256: true,
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P384: true,
	platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ED25519:    true,
}

// quicUsages resolves a purpose to wire usages; an empty purpose follows the
// algorithm (signing algorithms sign, everything else encrypts).
func quicUsages(purpose string, alg int32) ([]int32, error) {
	if purpose == "" {
		if quicSigningAlgorithms[platformv1.KMSKeyAlgorithm(alg)] {
			return quicSignUsages, nil
		}
		return quicEncryptUsages, nil
	}
	usages, ok := quicPurposes[strings.ToLower(purpose)]
	if !ok {
		return nil, ErrQUICUnsupportedValue{Kind: "key purpose", Value: purpose}
	}
	return usages, nil
}

// quicHashAlgorithm maps a test hash name to its wire number.
func quicHashAlgorithm(name string) (int32, error) {
	hash, ok := quicHashAlgorithms[strings.ToUpper(name)]
	if !ok {
		return 0, ErrQUICUnsupportedValue{Kind: "hash algorithm", Value: name}
	}
	return int32(hash), nil
}

// quicExpiresAt turns a policy ExpiresIn duration into a Unix time counted
// from now. An empty duration means the policy does not expire.
func quicExpiresAt(expiresIn string, now time.Time) (int64, error) {
	if expiresIn == "" {
		return 0, nil
	}
	d, err := time.ParseDuration(expiresIn)
	if err != nil || d <= 0 {
		return 0, ErrQUICUnsupportedValue{Kind: "policy expires-in", Value: expiresIn}
	}
	return now.Add(d).Unix(), nil
}

func quicAlgorithmName(v int32) string {
	return strings.TrimPrefix(platformv1.KMSKeyAlgorithm(v).String(), keyAlgorithmPrefix)
}

func quicStatusName(v int32) string {
	return strings.TrimPrefix(platformv1.KeyStatus(v).String(), keyStatusPrefix)
}

func quicHashName(v int32) string {
	return strings.TrimPrefix(platformv1.HashAlgorithm(v).String(), hashAlgorithmPrefix)
}

func quicUsageNames(usages []int32) []string {
	names := make([]string, 0, len(usages))
	for _, u := range usages {
		names = append(names, strings.TrimPrefix(platformv1.KeyUsage(u).String(), keyUsagePrefix))
	}
	return names
}

// =============================================================================
// KMSCommands Interface Implementation - Secrets Operations
// =============================================================================

// secretsCategory sends req under OpSecretsCategory with sub in payload[0]
// and decodes the answer into resp with the daemon's codec.
func (q *QUICAdapter) secretsCategory(ctx context.Context, operation string, sub byte, req, resp interface{}) error {
	return q.category(ctx, operation, quicwire.OpSecretsCategory, sub, req, resp)
}

// SecretsStore stores a secret through secrets sub 0x01. The QUIC store
// takes an id, data and metadata, so the description travels as metadata.
func (q *QUICAdapter) SecretsStore(ctx context.Context, opts SecretsStoreOptions) (*SecretsStoreResult, error) {
	req := &daemon.SecretsStoreRequest{SecretID: opts.Name, Data: opts.Data}
	if opts.Description != "" {
		req.Metadata = map[string]string{"description": opts.Description}
	}
	var result daemon.SecretsStoreResponse
	if err := q.secretsCategory(ctx, "SecretsStore", quicwire.SecretsSubStore, req, &result); err != nil {
		return nil, err
	}
	return &SecretsStoreResult{
		SecretID:  result.SecretID,
		Version:   result.Version,
		Timestamp: time.Unix(result.Timestamp, 0),
	}, nil
}

// SecretsGet retrieves the current version of a secret through secrets sub 0x02.
func (q *QUICAdapter) SecretsGet(ctx context.Context, name string) (*SecretsGetResult, error) {
	var result daemon.SecretsGetResponse
	if err := q.secretsCategory(ctx, "SecretsGet", quicwire.SecretsSubGet, &daemon.SecretsGetRequest{SecretID: name}, &result); err != nil {
		return nil, err
	}
	return &SecretsGetResult{
		SecretID:  result.SecretID,
		Version:   result.Version,
		Data:      result.Data,
		Metadata:  result.Metadata,
		Timestamp: time.Unix(result.Timestamp, 0),
	}, nil
}

// SecretsList lists secret ids through secrets sub 0x03.
func (q *QUICAdapter) SecretsList(ctx context.Context, opts SecretsListOptions) (*SecretsListResult, error) {
	req := &daemon.SecretsListRequest{Limit: opts.Limit, Cursor: opts.Cursor}
	var result daemon.SecretsListResponse
	if err := q.secretsCategory(ctx, "SecretsList", quicwire.SecretsSubList, req, &result); err != nil {
		return nil, err
	}
	secrets := make([]SecretSummary, 0, len(result.SecretIDs))
	for _, id := range result.SecretIDs {
		secrets = append(secrets, SecretSummary{Name: id})
	}
	return &SecretsListResult{
		Secrets:    secrets,
		TotalCount: int32(len(secrets)),
	}, nil
}

// SecretsDelete deletes a secret through secrets sub 0x04. QUIC delete is
// always permanent, so permanent is not sent.
func (q *QUICAdapter) SecretsDelete(ctx context.Context, name string, permanent bool) (*SecretsDeleteResult, error) {
	var result daemon.SecretsDeleteResponse
	if err := q.secretsCategory(ctx, "SecretsDelete", quicwire.SecretsSubDelete, &daemon.SecretsDeleteRequest{SecretID: name}, &result); err != nil {
		return nil, err
	}
	return &SecretsDeleteResult{
		SecretID:  result.SecretID,
		Deleted:   result.Deleted,
		Timestamp: time.Unix(result.Timestamp, 0),
	}, nil
}

// SecretsRotate rotates a secret to a new value through secrets sub 0x09.
func (q *QUICAdapter) SecretsRotate(ctx context.Context, opts SecretsRotateOptions) (*SecretsRotateResult, error) {
	req := &pb.RotateSecretRequest{
		SecretId:  opts.Name,
		NewData:   opts.NewData,
		TenantId:  opts.TenantID,
		KeyId:     opts.KeyID,
		Algorithm: opts.Algorithm,
	}
	var result pb.RotateSecretResponse
	if err := q.secretsCategory(ctx, "SecretsRotate", quicwire.SecretsSubRotate, req, &result); err != nil {
		return nil, err
	}
	return &SecretsRotateResult{
		SecretID:   result.GetSecretId(),
		OldVersion: result.GetOldVersion(),
		NewVersion: result.GetNewVersion(),
		Timestamp:  time.Unix(result.GetTimestamp(), 0),
	}, nil
}

// SecretsVersions lists the versions of a secret through secrets sub 0x08.
func (q *QUICAdapter) SecretsVersions(ctx context.Context, name string, opts SecretsVersionsOptions) (*SecretsVersionsResult, error) {
	req := &pb.ListSecretVersionsRequest{SecretId: name, Limit: opts.Limit, Cursor: opts.Cursor}
	var result pb.ListSecretVersionsResponse
	if err := q.secretsCategory(ctx, "SecretsVersions", quicwire.SecretsSubListVersions, req, &result); err != nil {
		return nil, err
	}
	versions := make([]SecretVersionInfo, 0, len(result.GetVersions()))
	for _, v := range result.GetVersions() {
		versions = append(versions, SecretVersionInfo{
			Version:   v.GetVersion(),
			CreatedAt: time.Unix(v.GetCreatedAt(), 0),
			CreatedBy: v.GetCreatedBy(),
			ExpiresAt: time.Unix(v.GetExpiresAt(), 0),
		})
	}
	return &SecretsVersionsResult{
		SecretID:   name,
		Versions:   versions,
		HasMore:    result.GetHasMore(),
		NextCursor: result.GetNextCursor(),
	}, nil
}

// SecretsVersion retrieves one version of a secret through secrets sub 0x07.
func (q *QUICAdapter) SecretsVersion(ctx context.Context, name string, version uint64) (*SecretsVersionResult, error) {
	req := &pb.GetSecretVersionRequest{SecretId: name, Version: version}
	var result pb.GetSecretVersionResponse
	if err := q.secretsCategory(ctx, "SecretsVersion", quicwire.SecretsSubGetVersion, req, &result); err != nil {
		return nil, err
	}
	info := result.GetVersion()
	return &SecretsVersionResult{
		SecretID:  name,
		Version:   info.GetVersion(),
		Data:      result.GetData(),
		Metadata:  info.GetMetadata(),
		CreatedAt: time.Unix(info.GetCreatedAt(), 0),
		CreatedBy: info.GetCreatedBy(),
		ExpiresAt: time.Unix(info.GetExpiresAt(), 0),
		Timestamp: time.Unix(result.GetTimestamp(), 0),
	}, nil
}

// SecretsRollback rolls a secret back to targetVersion through secrets sub 0x0A.
func (q *QUICAdapter) SecretsRollback(ctx context.Context, name string, targetVersion uint64) (*SecretsRollbackResult, error) {
	req := &pb.RollbackSecretRequest{SecretId: name, TargetVersion: targetVersion}
	var result pb.RollbackSecretResponse
	if err := q.secretsCategory(ctx, "SecretsRollback", quicwire.SecretsSubRollback, req, &result); err != nil {
		return nil, err
	}
	return &SecretsRollbackResult{
		SecretID:   result.GetSecretId(),
		NewVersion: result.GetNewVersion(),
		Timestamp:  time.Unix(result.GetTimestamp(), 0),
	}, nil
}

// SecretsStatus enables or disables a secret through secrets sub 0x0B.
func (q *QUICAdapter) SecretsStatus(ctx context.Context, name string, enabled bool) (*SecretsStatusResult, error) {
	status := pb.SecretStatus_SECRET_STATUS_DISABLED
	if enabled {
		status = pb.SecretStatus_SECRET_STATUS_ENABLED
	}
	req := &pb.UpdateSecretStatusRequest{SecretId: name, Status: status}
	var result pb.UpdateSecretStatusResponse
	if err := q.secretsCategory(ctx, "SecretsStatus", quicwire.SecretsSubUpdateStatus, req, &result); err != nil {
		return nil, err
	}
	return &SecretsStatusResult{
		SecretID:  result.GetSecretId(),
		Status:    strings.TrimPrefix(result.GetStatus().String(), "SECRET_STATUS_"),
		Timestamp: time.Unix(result.GetTimestamp(), 0),
	}, nil
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

// Ensure QUICAdapter implements KMSCommands interface.
var _ KMSCommands = (*QUICAdapter)(nil)
