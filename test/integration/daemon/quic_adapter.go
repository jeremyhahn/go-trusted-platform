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

// Package daemon provides integration test adapters for daemon services.
// This file implements the DaemonCommands interface using the QUIC protocol.

//go:build integration

package daemon

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
	// DefaultQUICTimeout is the default timeout for QUIC operations.
	DefaultQUICTimeout = 30 * time.Second

	// DefaultQUICMaxIdleTimeout is the default max idle timeout for connections.
	DefaultQUICMaxIdleTimeout = 60 * time.Second

	// MaxQUICPayloadSize is the maximum payload size (16MB).
	MaxQUICPayloadSize uint32 = 16 * 1024 * 1024

	// MaxQUICTokenSize is the maximum token size (8KB).
	MaxQUICTokenSize uint16 = 8 * 1024
)

// QUIC Status codes.
const (
	QUICStatusOK             byte = 0x00
	QUICStatusInvalidRequest byte = 0x01
	QUICStatusNotFound       byte = 0x02
	QUICStatusUnauthorized   byte = 0x03
	QUICStatusInternalError  byte = 0x04
	QUICStatusAlreadyExists  byte = 0x06
)

// QUIC Operation codes for Daemon operations.
// These MUST match the server-side opcodes defined in sdk/go/wire/quicwire/protocol.go.
const (
	// Health uses the global health opcode (0x00)
	OpQUICDaemonHealth byte = 0x00

	// Daemon Management Operations (0x89-0x8F, 0x98)
	OpQUICDaemonStatus         byte = 0x89
	OpQUICDaemonVersion        byte = 0x8A
	OpQUICDaemonListServices   byte = 0x8B
	OpQUICDaemonGetService     byte = 0x8C
	OpQUICDaemonStartService   byte = 0x8D
	OpQUICDaemonStopService    byte = 0x8E
	OpQUICDaemonRestartService byte = 0x8F
	OpQUICDaemonListProtocols  byte = 0x98
)

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
// =============================================================================

// quicHealthResponse matches the server-side HealthCheckResponse wire format.
// The server sends Components as map[string]string (component name -> status),
// not as a slice of structs.
type quicHealthResponse struct {
	Healthy    bool              `codec:"healthy"`
	Status     string            `codec:"status"`
	Components map[string]string `codec:"components"`
	Timestamp  int64             `codec:"timestamp"`
}

type quicStatusResponse struct {
	Status    string         `codec:"status"`
	Version   string         `codec:"version"`
	BuildTime string         `codec:"build_time"`
	GitCommit string         `codec:"git_commit"`
	GoVersion string         `codec:"go_version"`
	System    quicSystemInfo `codec:"system"`
	Timestamp int64          `codec:"timestamp"`
}

type quicSystemInfo struct {
	OS                string `codec:"os"`
	Arch              string `codec:"arch"`
	NumCPUs           int    `codec:"num_cpus"`
	TotalMemoryMB     uint64 `codec:"total_memory_mb"`
	AvailableMemoryMB uint64 `codec:"available_memory_mb"`
	Uptime            string `codec:"uptime"`
}

type quicVersionResponse struct {
	Version   string `codec:"version"`
	BuildTime string `codec:"build_time"`
	GitCommit string `codec:"git_commit"`
	GoVersion string `codec:"go_version"`
}

type quicListServicesResponse struct {
	Services  []quicServiceInfo `codec:"services"`
	Count     int               `codec:"count"`
	Timestamp int64             `codec:"timestamp"`
}

type quicServiceInfo struct {
	Name       string `codec:"name"`
	Status     string `codec:"status"`
	StartedAt  int64  `codec:"started_at"`
	Uptime     string `codec:"uptime"`
	StartCount uint64 `codec:"start_count"`
	StopCount  uint64 `codec:"stop_count"`
	LastError  string `codec:"last_error"`
}

type quicServiceRequest struct {
	Name string `codec:"name"`
}

type quicServiceActionResponse struct {
	Service string `codec:"service"`
	Action  string `codec:"action"`
	Success bool   `codec:"success"`
	Message string `codec:"message"`
}

type quicListProtocolsResponse struct {
	Protocols []quicProtocolInfo `codec:"protocols"`
	Timestamp int64              `codec:"timestamp"`
}

type quicProtocolInfo struct {
	Name    string `codec:"name"`
	Enabled bool   `codec:"enabled"`
	Address string `codec:"address"`
	Port    int    `codec:"port"`
	Status  string `codec:"status"`
	TLS     bool   `codec:"tls"`
}

// =============================================================================
// QUIC Adapter Implementation
// =============================================================================

// QUICAdapter implements DaemonCommands using the QUIC protocol.
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
		endpoint = DefaultPlatformQUICEndpoint
	}

	return &QUICAdapter{
		endpoint:       endpoint,
		timeout:        DefaultQUICTimeout,
		maxIdleTimeout: DefaultQUICMaxIdleTimeout,
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
	case OpQUICDaemonHealth:
		return "Health"
	case OpQUICDaemonStatus:
		return "Status"
	case OpQUICDaemonVersion:
		return "Version"
	case OpQUICDaemonListServices:
		return "ListServices"
	case OpQUICDaemonGetService:
		return "GetService"
	case OpQUICDaemonStartService:
		return "StartService"
	case OpQUICDaemonStopService:
		return "StopService"
	case OpQUICDaemonRestartService:
		return "RestartService"
	case OpQUICDaemonListProtocols:
		return "ListProtocols"
	default:
		return fmt.Sprintf("Unknown(0x%02X)", opcode)
	}
}

// =============================================================================
// Health Operations
// =============================================================================

// Health retrieves health status via QUIC.
func (q *QUICAdapter) Health(ctx context.Context) (*HealthResult, error) {
	resp, err := q.sendRequest(ctx, OpQUICDaemonHealth, nil)
	if err != nil {
		return nil, err
	}

	var result quicHealthResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "Health", Err: err}
	}

	healthResult := &HealthResult{
		Status:    result.Status,
		Timestamp: time.Unix(result.Timestamp, 0),
	}

	// Convert map[string]string components to []ComponentHealth
	for name, status := range result.Components {
		healthResult.Components = append(healthResult.Components, ComponentHealth{
			Name:   name,
			Status: normalizeHealthStatus(status),
		})
	}

	return healthResult, nil
}

// =============================================================================
// Status Operations
// =============================================================================

// Status retrieves daemon status via QUIC.
func (q *QUICAdapter) Status(ctx context.Context) (*StatusResult, error) {
	resp, err := q.sendRequest(ctx, OpQUICDaemonStatus, nil)
	if err != nil {
		return nil, err
	}

	var result quicStatusResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "Status", Err: err}
	}

	return &StatusResult{
		Status:    result.Status,
		Version:   result.Version,
		BuildTime: result.BuildTime,
		GitCommit: result.GitCommit,
		GoVersion: result.GoVersion,
		System: SystemInfo{
			OS:                result.System.OS,
			Arch:              result.System.Arch,
			NumCPUs:           result.System.NumCPUs,
			TotalMemoryMB:     result.System.TotalMemoryMB,
			AvailableMemoryMB: result.System.AvailableMemoryMB,
			Uptime:            result.System.Uptime,
		},
		Timestamp: time.Unix(result.Timestamp, 0),
	}, nil
}

// =============================================================================
// Version Operations
// =============================================================================

// Version retrieves version information via QUIC.
func (q *QUICAdapter) Version(ctx context.Context) (*VersionResult, error) {
	resp, err := q.sendRequest(ctx, OpQUICDaemonVersion, nil)
	if err != nil {
		return nil, err
	}

	var result quicVersionResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "Version", Err: err}
	}

	return &VersionResult{
		Version:   result.Version,
		BuildTime: result.BuildTime,
		GitCommit: result.GitCommit,
		GoVersion: result.GoVersion,
	}, nil
}

// =============================================================================
// Service Operations
// =============================================================================

// ListServices lists all services via QUIC.
func (q *QUICAdapter) ListServices(ctx context.Context) (*ListServicesResult, error) {
	resp, err := q.sendRequest(ctx, OpQUICDaemonListServices, nil)
	if err != nil {
		return nil, err
	}

	var result quicListServicesResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "ListServices", Err: err}
	}

	listResult := &ListServicesResult{
		Count:     result.Count,
		Timestamp: time.Unix(result.Timestamp, 0),
	}

	for _, s := range result.Services {
		info := ServiceInfoResult{
			Name:       s.Name,
			Status:     s.Status,
			Uptime:     s.Uptime,
			StartCount: s.StartCount,
			StopCount:  s.StopCount,
			LastError:  s.LastError,
		}
		if s.StartedAt > 0 {
			info.StartedAt = time.Unix(s.StartedAt, 0)
		}
		listResult.Services = append(listResult.Services, info)
	}

	return listResult, nil
}

// GetService retrieves a single service's information via QUIC.
func (q *QUICAdapter) GetService(ctx context.Context, serviceName string) (*ServiceInfoResult, error) {
	req := &quicServiceRequest{Name: serviceName}

	resp, err := q.sendRequest(ctx, OpQUICDaemonGetService, req)
	if err != nil {
		return nil, err
	}

	var result quicServiceInfo
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "GetService", Err: err}
	}

	info := &ServiceInfoResult{
		Name:       result.Name,
		Status:     result.Status,
		Uptime:     result.Uptime,
		StartCount: result.StartCount,
		StopCount:  result.StopCount,
		LastError:  result.LastError,
	}

	if result.StartedAt > 0 {
		info.StartedAt = time.Unix(result.StartedAt, 0)
	}

	return info, nil
}

// StartService starts a service via QUIC.
func (q *QUICAdapter) StartService(ctx context.Context, serviceName string) (*ServiceActionResult, error) {
	req := &quicServiceRequest{Name: serviceName}

	resp, err := q.sendRequest(ctx, OpQUICDaemonStartService, req)
	if err != nil {
		return nil, err
	}

	var result quicServiceActionResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "StartService", Err: err}
	}

	return &ServiceActionResult{
		Service: result.Service,
		Action:  result.Action,
		Success: result.Success,
		Message: result.Message,
	}, nil
}

// StopService stops a service via QUIC.
func (q *QUICAdapter) StopService(ctx context.Context, serviceName string) (*ServiceActionResult, error) {
	req := &quicServiceRequest{Name: serviceName}

	resp, err := q.sendRequest(ctx, OpQUICDaemonStopService, req)
	if err != nil {
		return nil, err
	}

	var result quicServiceActionResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "StopService", Err: err}
	}

	return &ServiceActionResult{
		Service: result.Service,
		Action:  result.Action,
		Success: result.Success,
		Message: result.Message,
	}, nil
}

// RestartService restarts a service via QUIC.
func (q *QUICAdapter) RestartService(ctx context.Context, serviceName string) (*ServiceActionResult, error) {
	req := &quicServiceRequest{Name: serviceName}

	resp, err := q.sendRequest(ctx, OpQUICDaemonRestartService, req)
	if err != nil {
		return nil, err
	}

	var result quicServiceActionResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "RestartService", Err: err}
	}

	return &ServiceActionResult{
		Service: result.Service,
		Action:  result.Action,
		Success: result.Success,
		Message: result.Message,
	}, nil
}

// =============================================================================
// Protocol Operations
// =============================================================================

// ListProtocols lists all protocols via QUIC.
func (q *QUICAdapter) ListProtocols(ctx context.Context) (*ListProtocolsResult, error) {
	resp, err := q.sendRequest(ctx, OpQUICDaemonListProtocols, nil)
	if err != nil {
		return nil, err
	}

	var result quicListProtocolsResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "ListProtocols", Err: err}
	}

	listResult := &ListProtocolsResult{
		Timestamp: time.Unix(result.Timestamp, 0),
	}

	for _, p := range result.Protocols {
		listResult.Protocols = append(listResult.Protocols, ProtocolInfo{
			Name:    p.Name,
			Enabled: p.Enabled,
			Address: p.Address,
			Port:    p.Port,
			Status:  p.Status,
			TLS:     p.TLS,
		})
	}

	return listResult, nil
}

// Ensure QUICAdapter implements DaemonCommands interface.
var _ DaemonCommands = (*QUICAdapter)(nil)
