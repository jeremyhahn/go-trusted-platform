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

// Package dns provides integration test adapters for DNS services.
// This file implements the DNSCommands interface using the QUIC protocol.

//go:build integration

package dns

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
	QUICStatusOK             byte = 0x00
	QUICStatusInvalidRequest byte = 0x01
	QUICStatusNotFound       byte = 0x02
	QUICStatusUnauthorized   byte = 0x03
	QUICStatusInternalError  byte = 0x04
	QUICStatusAlreadyExists  byte = 0x06
)

// QUIC Operation codes for DNS operations.
const (
	// Zone Operations (0xA0-0xA4).
	OpQUICDNSCreateZone byte = 0xA0
	OpQUICDNSGetZone    byte = 0xA1
	OpQUICDNSUpdateZone byte = 0xA2
	OpQUICDNSDeleteZone byte = 0xA3
	OpQUICDNSListZones  byte = 0xA4

	// Record Operations (0xA5-0xA9).
	OpQUICDNSAddRecord    byte = 0xA5
	OpQUICDNSGetRecord    byte = 0xA6
	OpQUICDNSUpdateRecord byte = 0xA7
	OpQUICDNSDeleteRecord byte = 0xA8
	OpQUICDNSListRecords  byte = 0xA9

	// Resolution Operations (0xAA).
	OpQUICDNSResolve byte = 0xAA

	// TLSA Operations (0xAB).
	OpQUICDNSAddTLSA byte = 0xAB
)

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

// Zone management types

type createZoneRequest struct {
	Name        string      `codec:"name"`
	TTL         uint32      `codec:"ttl"`
	Description string      `codec:"description"`
	Internal    bool        `codec:"internal"`
	SOA         *soaRequest `codec:"soa"`
}

type soaRequest struct {
	MName      string `codec:"mname"`
	RName      string `codec:"rname"`
	Serial     uint32 `codec:"serial"`
	Refresh    uint32 `codec:"refresh"`
	Retry      uint32 `codec:"retry"`
	Expire     uint32 `codec:"expire"`
	MinimumTTL uint32 `codec:"minimum_ttl"`
}

type createZoneResponse struct {
	Name      string `codec:"name"`
	ID        string `codec:"id"`
	TTL       uint32 `codec:"ttl"`
	Internal  bool   `codec:"internal"`
	CreatedAt int64  `codec:"created_at"`
}

type getZoneRequest struct {
	Name string `codec:"name"`
}

type getZoneResponse struct {
	Name        string       `codec:"name"`
	ID          string       `codec:"id"`
	TTL         uint32       `codec:"ttl"`
	Description string       `codec:"description"`
	Internal    bool         `codec:"internal"`
	RecordCount int32        `codec:"record_count"`
	SOA         *soaResponse `codec:"soa"`
	CreatedAt   int64        `codec:"created_at"`
	UpdatedAt   int64        `codec:"updated_at"`
}

type soaResponse struct {
	MName      string `codec:"mname"`
	RName      string `codec:"rname"`
	Serial     uint32 `codec:"serial"`
	Refresh    uint32 `codec:"refresh"`
	Retry      uint32 `codec:"retry"`
	Expire     uint32 `codec:"expire"`
	MinimumTTL uint32 `codec:"minimum_ttl"`
	TTL        uint32 `codec:"ttl"`
}

type updateZoneRequest struct {
	Name        string `codec:"name"`
	TTL         uint32 `codec:"ttl"`
	Description string `codec:"description"`
}

type updateZoneResponse struct {
	Name      string `codec:"name"`
	TTL       uint32 `codec:"ttl"`
	UpdatedAt int64  `codec:"updated_at"`
}

type deleteZoneRequest struct {
	Name string `codec:"name"`
}

type deleteZoneResponse struct {
	Name    string `codec:"name"`
	Deleted bool   `codec:"deleted"`
}

type listZonesRequest struct {
	Limit    int32  `codec:"limit"`
	Cursor   string `codec:"cursor"`
	Internal *bool  `codec:"internal"`
}

type listZonesResponse struct {
	Zones      []zoneSummary `codec:"zones"`
	TotalCount int32         `codec:"total_count"`
	HasMore    bool          `codec:"has_more"`
	NextCursor string        `codec:"next_cursor"`
}

type zoneSummary struct {
	Name        string `codec:"name"`
	ID          string `codec:"id"`
	TTL         uint32 `codec:"ttl"`
	Internal    bool   `codec:"internal"`
	RecordCount int32  `codec:"record_count"`
	CreatedAt   int64  `codec:"created_at"`
}

// Record management types

type addRecordRequest struct {
	ZoneName   string `codec:"zone_name"`
	Name       string `codec:"name"`
	RecordType string `codec:"record_type"`
	Value      string `codec:"value"`
	TTL        uint32 `codec:"ttl"`
	Priority   uint16 `codec:"priority"`
	Weight     uint16 `codec:"weight"`
	Port       uint16 `codec:"port"`
}

type addRecordResponse struct {
	Name       string `codec:"name"`
	RecordType string `codec:"record_type"`
	Value      string `codec:"value"`
	TTL        uint32 `codec:"ttl"`
	CreatedAt  int64  `codec:"created_at"`
}

type getRecordRequest struct {
	Name       string `codec:"name"`
	RecordType string `codec:"record_type"`
}

type getRecordResponse struct {
	Name       string `codec:"name"`
	RecordType string `codec:"record_type"`
	Value      string `codec:"value"`
	TTL        uint32 `codec:"ttl"`
	Priority   uint16 `codec:"priority"`
	Weight     uint16 `codec:"weight"`
	Port       uint16 `codec:"port"`
	CreatedAt  int64  `codec:"created_at"`
	UpdatedAt  int64  `codec:"updated_at"`
}

type updateRecordRequest struct {
	ZoneName   string `codec:"zone_name"`
	Name       string `codec:"name"`
	RecordType string `codec:"record_type"`
	Value      string `codec:"value"`
	TTL        uint32 `codec:"ttl"`
	Priority   uint16 `codec:"priority"`
	Weight     uint16 `codec:"weight"`
	Port       uint16 `codec:"port"`
}

type updateRecordResponse struct {
	Name       string `codec:"name"`
	RecordType string `codec:"record_type"`
	Value      string `codec:"value"`
	TTL        uint32 `codec:"ttl"`
	UpdatedAt  int64  `codec:"updated_at"`
}

type deleteRecordRequest struct {
	Name       string `codec:"name"`
	RecordType string `codec:"record_type"`
}

type deleteRecordResponse struct {
	Name       string `codec:"name"`
	RecordType string `codec:"record_type"`
	Deleted    bool   `codec:"deleted"`
}

type listRecordsRequest struct {
	ZoneName   string `codec:"zone_name"`
	RecordType string `codec:"record_type"`
	Limit      int32  `codec:"limit"`
	Cursor     string `codec:"cursor"`
}

type listRecordsResponse struct {
	Records    []recordSummary `codec:"records"`
	TotalCount int32           `codec:"total_count"`
	HasMore    bool            `codec:"has_more"`
	NextCursor string          `codec:"next_cursor"`
}

type recordSummary struct {
	Name       string `codec:"name"`
	RecordType string `codec:"record_type"`
	Value      string `codec:"value"`
	TTL        uint32 `codec:"ttl"`
	Priority   uint16 `codec:"priority"`
}

// Resolution types

type resolveRequest struct {
	Name       string `codec:"name"`
	RecordType string `codec:"record_type"`
}

type resolveResponse struct {
	Name       string   `codec:"name"`
	RecordType string   `codec:"record_type"`
	Values     []string `codec:"values"`
	TTL        uint32   `codec:"ttl"`
	Timestamp  int64    `codec:"timestamp"`
}

// TLSA types

type addTLSARequest struct {
	ZoneName     string `codec:"zone_name"`
	Name         string `codec:"name"`
	Usage        uint8  `codec:"usage"`
	Selector     uint8  `codec:"selector"`
	MatchingType uint8  `codec:"matching_type"`
	Data         string `codec:"data"`
	TTL          uint32 `codec:"ttl"`
}

type addTLSAResponse struct {
	Name         string `codec:"name"`
	Usage        uint8  `codec:"usage"`
	Selector     uint8  `codec:"selector"`
	MatchingType uint8  `codec:"matching_type"`
	Data         string `codec:"data"`
	TTL          uint32 `codec:"ttl"`
	CreatedAt    int64  `codec:"created_at"`
}

// =============================================================================
// QUIC Adapter Implementation
// =============================================================================

// QUICAdapter implements DNSCommands using the QUIC protocol.
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
		tlsConfig:      helpers.QUICTLSConfig([]string{"platform-quic"}),
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
	case OpQUICDNSCreateZone:
		return "CreateZone"
	case OpQUICDNSGetZone:
		return "GetZone"
	case OpQUICDNSUpdateZone:
		return "UpdateZone"
	case OpQUICDNSDeleteZone:
		return "DeleteZone"
	case OpQUICDNSListZones:
		return "ListZones"
	case OpQUICDNSAddRecord:
		return "AddRecord"
	case OpQUICDNSGetRecord:
		return "GetRecord"
	case OpQUICDNSUpdateRecord:
		return "UpdateRecord"
	case OpQUICDNSDeleteRecord:
		return "DeleteRecord"
	case OpQUICDNSListRecords:
		return "ListRecords"
	case OpQUICDNSResolve:
		return "Resolve"
	case OpQUICDNSAddTLSA:
		return "AddTLSARecord"
	default:
		return fmt.Sprintf("Unknown(0x%02X)", opcode)
	}
}

// =============================================================================
// DNSCommands Interface Implementation - Zone Management
// =============================================================================

// CreateZone creates a new DNS zone via QUIC protocol.
func (q *QUICAdapter) CreateZone(ctx context.Context, opts CreateZoneOptions) (*CreateZoneResult, error) {
	req := &createZoneRequest{
		Name:        opts.Name,
		TTL:         opts.TTL,
		Description: opts.Description,
		Internal:    opts.Internal,
	}

	if opts.SOA != nil {
		req.SOA = &soaRequest{
			MName:      opts.SOA.MName,
			RName:      opts.SOA.RName,
			Serial:     opts.SOA.Serial,
			Refresh:    opts.SOA.Refresh,
			Retry:      opts.SOA.Retry,
			Expire:     opts.SOA.Expire,
			MinimumTTL: opts.SOA.MinimumTTL,
		}
	}

	resp, err := q.sendRequest(ctx, OpQUICDNSCreateZone, req)
	if err != nil {
		return nil, err
	}

	var result createZoneResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "CreateZone", Err: err}
	}

	return &CreateZoneResult{
		Name:      result.Name,
		ID:        result.ID,
		TTL:       result.TTL,
		Internal:  result.Internal,
		CreatedAt: time.Unix(result.CreatedAt, 0),
	}, nil
}

// GetZone retrieves a DNS zone via QUIC protocol.
func (q *QUICAdapter) GetZone(ctx context.Context, zoneName string) (*GetZoneResult, error) {
	req := &getZoneRequest{Name: zoneName}

	resp, err := q.sendRequest(ctx, OpQUICDNSGetZone, req)
	if err != nil {
		return nil, err
	}

	var result getZoneResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "GetZone", Err: err}
	}

	zoneResult := &GetZoneResult{
		Name:        result.Name,
		ID:          result.ID,
		TTL:         result.TTL,
		Description: result.Description,
		Internal:    result.Internal,
		RecordCount: int(result.RecordCount),
		CreatedAt:   time.Unix(result.CreatedAt, 0),
		UpdatedAt:   time.Unix(result.UpdatedAt, 0),
	}

	if result.SOA != nil {
		zoneResult.SOA = &SOARecordInfo{
			Name:       result.Name,
			MName:      result.SOA.MName,
			RName:      result.SOA.RName,
			Serial:     result.SOA.Serial,
			Refresh:    result.SOA.Refresh,
			Retry:      result.SOA.Retry,
			Expire:     result.SOA.Expire,
			MinimumTTL: result.SOA.MinimumTTL,
			TTL:        result.SOA.TTL,
		}
	}

	return zoneResult, nil
}

// UpdateZone updates a DNS zone via QUIC protocol.
func (q *QUICAdapter) UpdateZone(ctx context.Context, zoneName string, opts UpdateZoneOptions) (*UpdateZoneResult, error) {
	req := &updateZoneRequest{
		Name:        zoneName,
		TTL:         opts.TTL,
		Description: opts.Description,
	}

	resp, err := q.sendRequest(ctx, OpQUICDNSUpdateZone, req)
	if err != nil {
		return nil, err
	}

	var result updateZoneResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "UpdateZone", Err: err}
	}

	return &UpdateZoneResult{
		Name:      result.Name,
		TTL:       result.TTL,
		UpdatedAt: time.Unix(result.UpdatedAt, 0),
	}, nil
}

// DeleteZone deletes a DNS zone via QUIC protocol.
func (q *QUICAdapter) DeleteZone(ctx context.Context, zoneName string) (*DeleteZoneResult, error) {
	req := &deleteZoneRequest{Name: zoneName}

	resp, err := q.sendRequest(ctx, OpQUICDNSDeleteZone, req)
	if err != nil {
		return nil, err
	}

	var result deleteZoneResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "DeleteZone", Err: err}
	}

	return &DeleteZoneResult{
		Name:    result.Name,
		Deleted: result.Deleted,
	}, nil
}

// ListZones lists DNS zones via QUIC protocol.
func (q *QUICAdapter) ListZones(ctx context.Context, opts ListZonesOptions) (*ListZonesResult, error) {
	req := &listZonesRequest{
		Limit:    opts.Limit,
		Cursor:   opts.Cursor,
		Internal: opts.Internal,
	}

	resp, err := q.sendRequest(ctx, OpQUICDNSListZones, req)
	if err != nil {
		return nil, err
	}

	var result listZonesResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "ListZones", Err: err}
	}

	zones := make([]ZoneSummary, len(result.Zones))
	for i, z := range result.Zones {
		zones[i] = ZoneSummary{
			Name:        z.Name,
			ID:          z.ID,
			TTL:         z.TTL,
			Internal:    z.Internal,
			RecordCount: int(z.RecordCount),
			CreatedAt:   time.Unix(z.CreatedAt, 0),
		}
	}

	return &ListZonesResult{
		Zones:      zones,
		TotalCount: result.TotalCount,
		HasMore:    result.HasMore,
		NextCursor: result.NextCursor,
	}, nil
}

// =============================================================================
// DNSCommands Interface Implementation - Record Management
// =============================================================================

// AddRecord adds a DNS record via QUIC protocol.
func (q *QUICAdapter) AddRecord(ctx context.Context, opts AddRecordOptions) (*AddRecordResult, error) {
	req := &addRecordRequest{
		ZoneName:   opts.ZoneName,
		Name:       opts.Name,
		RecordType: opts.RecordType,
		Value:      opts.Value,
		TTL:        opts.TTL,
		Priority:   opts.Priority,
		Weight:     opts.Weight,
		Port:       opts.Port,
	}

	resp, err := q.sendRequest(ctx, OpQUICDNSAddRecord, req)
	if err != nil {
		return nil, err
	}

	var result addRecordResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "AddRecord", Err: err}
	}

	return &AddRecordResult{
		Name:       result.Name,
		RecordType: result.RecordType,
		Value:      result.Value,
		TTL:        result.TTL,
		CreatedAt:  time.Unix(result.CreatedAt, 0),
	}, nil
}

// GetRecord retrieves a DNS record via QUIC protocol.
func (q *QUICAdapter) GetRecord(ctx context.Context, name string, recordType string) (*GetRecordResult, error) {
	req := &getRecordRequest{
		Name:       name,
		RecordType: recordType,
	}

	resp, err := q.sendRequest(ctx, OpQUICDNSGetRecord, req)
	if err != nil {
		return nil, err
	}

	var result getRecordResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "GetRecord", Err: err}
	}

	return &GetRecordResult{
		Name:       result.Name,
		RecordType: result.RecordType,
		Value:      result.Value,
		TTL:        result.TTL,
		Priority:   result.Priority,
		Weight:     result.Weight,
		Port:       result.Port,
		CreatedAt:  time.Unix(result.CreatedAt, 0),
		UpdatedAt:  time.Unix(result.UpdatedAt, 0),
	}, nil
}

// UpdateRecord updates a DNS record via QUIC protocol.
func (q *QUICAdapter) UpdateRecord(ctx context.Context, opts UpdateRecordOptions) (*UpdateRecordResult, error) {
	req := &updateRecordRequest{
		ZoneName:   opts.ZoneName,
		Name:       opts.Name,
		RecordType: opts.RecordType,
		Value:      opts.Value,
		TTL:        opts.TTL,
		Priority:   opts.Priority,
		Weight:     opts.Weight,
		Port:       opts.Port,
	}

	resp, err := q.sendRequest(ctx, OpQUICDNSUpdateRecord, req)
	if err != nil {
		return nil, err
	}

	var result updateRecordResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "UpdateRecord", Err: err}
	}

	return &UpdateRecordResult{
		Name:       result.Name,
		RecordType: result.RecordType,
		Value:      result.Value,
		TTL:        result.TTL,
		UpdatedAt:  time.Unix(result.UpdatedAt, 0),
	}, nil
}

// DeleteRecord deletes a DNS record via QUIC protocol.
func (q *QUICAdapter) DeleteRecord(ctx context.Context, name string, recordType string) (*DeleteRecordResult, error) {
	req := &deleteRecordRequest{
		Name:       name,
		RecordType: recordType,
	}

	resp, err := q.sendRequest(ctx, OpQUICDNSDeleteRecord, req)
	if err != nil {
		return nil, err
	}

	var result deleteRecordResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "DeleteRecord", Err: err}
	}

	return &DeleteRecordResult{
		Name:       result.Name,
		RecordType: result.RecordType,
		Deleted:    result.Deleted,
	}, nil
}

// ListRecords lists DNS records via QUIC protocol.
func (q *QUICAdapter) ListRecords(ctx context.Context, zoneName string, opts ListRecordsOptions) (*ListRecordsResult, error) {
	req := &listRecordsRequest{
		ZoneName:   zoneName,
		RecordType: opts.RecordType,
		Limit:      opts.Limit,
		Cursor:     opts.Cursor,
	}

	resp, err := q.sendRequest(ctx, OpQUICDNSListRecords, req)
	if err != nil {
		return nil, err
	}

	var result listRecordsResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "ListRecords", Err: err}
	}

	records := make([]RecordSummary, len(result.Records))
	for i, r := range result.Records {
		records[i] = RecordSummary{
			Name:       r.Name,
			RecordType: r.RecordType,
			Value:      r.Value,
			TTL:        r.TTL,
			Priority:   r.Priority,
		}
	}

	return &ListRecordsResult{
		Records:    records,
		TotalCount: result.TotalCount,
		HasMore:    result.HasMore,
		NextCursor: result.NextCursor,
	}, nil
}

// =============================================================================
// DNSCommands Interface Implementation - Resolution
// =============================================================================

// Resolve performs DNS resolution via QUIC protocol.
func (q *QUICAdapter) Resolve(ctx context.Context, name string, recordType string) (*ResolveResult, error) {
	req := &resolveRequest{
		Name:       name,
		RecordType: recordType,
	}

	resp, err := q.sendRequest(ctx, OpQUICDNSResolve, req)
	if err != nil {
		return nil, err
	}

	var result resolveResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "Resolve", Err: err}
	}

	return &ResolveResult{
		Name:       result.Name,
		RecordType: result.RecordType,
		Values:     result.Values,
		TTL:        result.TTL,
		Timestamp:  time.Unix(result.Timestamp, 0),
	}, nil
}

// =============================================================================
// DNSCommands Interface Implementation - TLSA/DANE
// =============================================================================

// AddTLSARecord adds a TLSA record via QUIC protocol.
func (q *QUICAdapter) AddTLSARecord(ctx context.Context, opts AddTLSARecordOptions) (*AddTLSARecordResult, error) {
	req := &addTLSARequest{
		ZoneName:     opts.ZoneName,
		Name:         opts.Name,
		Usage:        opts.Usage,
		Selector:     opts.Selector,
		MatchingType: opts.MatchingType,
		Data:         opts.Data,
		TTL:          opts.TTL,
	}

	resp, err := q.sendRequest(ctx, OpQUICDNSAddTLSA, req)
	if err != nil {
		return nil, err
	}

	var result addTLSAResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "AddTLSARecord", Err: err}
	}

	return &AddTLSARecordResult{
		Name:         result.Name,
		Usage:        result.Usage,
		Selector:     result.Selector,
		MatchingType: result.MatchingType,
		Data:         result.Data,
		TTL:          result.TTL,
		CreatedAt:    time.Unix(result.CreatedAt, 0),
	}, nil
}

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

// Ensure QUICAdapter implements DNSCommands interface.
var _ DNSCommands = (*QUICAdapter)(nil)
