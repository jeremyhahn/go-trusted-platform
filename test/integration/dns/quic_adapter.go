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

// Package dns provides integration test adapters for DNS services. This file
// implements the DNSCommands interface using the platform binary QUIC protocol
// (custom opcodes + MessagePack), exercising the SAME wire contract the SDK
// QUIC transport speaks.
//
// The DNS QUIC surface converged onto the platform.v1 protobuf wire contract:
// the SDK-mapped operations (AddRecord 0x20, DeleteRecord 0x21,
// ListRecords 0x24, AddZone/CreateZone 0x25, DeleteZone 0x26, ListZones 0x28,
// Resolve 0x29) encode the generated pb request struct directly (the codec
// keys on exact Go field names). The remaining operations (GetRecord 0x23,
// UpdateRecord 0x22, GetZone 0x27) are daemon-native flat structs and use
// field-name-identical wire structs here. Record-bearing responses (ListRecords,
// Resolve) carry the protobuf oneof, which cannot decode into raw pb — the
// daemon encodes a flat mirror, so this adapter decodes the same mirror shape.
//
// UpdateZone has NO QUIC opcode (the 0x20-0x2D space is allocated or retired and
// the gRPC UpdateZone RPC is not SDK-mapped over QUIC); it returns a typed
// unsupported error.

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
	pb "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	quicgo "github.com/quic-go/quic-go"
)

// =============================================================================
// Constants
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

// QUIC status codes (sdk/go/wire/quicwire/protocol.go).
const (
	QUICStatusOK              byte = 0x00
	QUICStatusInvalidRequest  byte = 0x01
	QUICStatusNotFound        byte = 0x02
	QUICStatusUnauthorized    byte = 0x03
	QUICStatusInternalError   byte = 0x04
	QUICStatusAlreadyExists   byte = 0x06
	QUICStatusInvalidArgument byte = 0x09
	QUICStatusUnavailable     byte = 0x0A
	QUICStatusNotImplemented  byte = 0x0B
)

// DNS opcodes — MUST match sdk/go/wire/quicwire/protocol.go.
const (
	OpDNSAddRecord    byte = 0x20
	OpDNSDeleteRecord byte = 0x21
	OpDNSUpdateRecord byte = 0x22
	OpDNSGetRecord    byte = 0x23
	OpDNSListRecords  byte = 0x24
	OpDNSAddZone      byte = 0x25
	OpDNSDeleteZone   byte = 0x26
	OpDNSGetZone      byte = 0x27
	OpDNSListZones    byte = 0x28
	OpDNSResolve      byte = 0x29
)

// =============================================================================
// Daemon-native flat wire structs (field names match pkg/api/daemon/quic_dns.go)
// =============================================================================

// The QUIC payload codec keys on EXACT Go field names and ignores codec/json
// struct tags, so these field names — not the tags — are the wire contract.

type quicDNSGetZoneReq struct {
	Zone string `codec:"zone"`
}

type quicDNSZone struct {
	ID          uint64 `codec:"id"`
	Name        string `codec:"name"`
	TTL         uint32 `codec:"ttl"`
	Description string `codec:"description"`
	Internal    bool   `codec:"internal"`
	RecordCount int    `codec:"record_count"`
}

type quicDNSGetZoneResp struct {
	Zone      *quicDNSZone `codec:"zone"`
	Timestamp int64        `codec:"timestamp"`
}

type quicDNSGetRecordReq struct {
	Zone       string `codec:"zone"`
	Name       string `codec:"name"`
	RecordType string `codec:"record_type"`
}

type quicDNSRecord struct {
	Name       string `codec:"name"`
	RecordType string `codec:"record_type"`
	Value      string `codec:"value"`
	TTL        uint32 `codec:"ttl"`
	Priority   uint16 `codec:"priority"`
}

type quicDNSGetRecordResp struct {
	Record    *quicDNSRecord `codec:"record"`
	Zone      string         `codec:"zone"`
	Timestamp int64          `codec:"timestamp"`
}

type quicDNSUpdateRecordReq struct {
	Zone       string `codec:"zone"`
	Name       string `codec:"name"`
	RecordType string `codec:"record_type"`
	Value      string `codec:"value"`
	TTL        int    `codec:"ttl"`
	Priority   uint16 `codec:"priority"`
}

type quicDNSUpdateRecordResp struct {
	Success   bool   `codec:"success"`
	Zone      string `codec:"zone"`
	Name      string `codec:"name"`
	Timestamp int64  `codec:"timestamp"`
}

// =============================================================================
// Record oneof mirror (field names match the daemon dnsRecordWire mirror)
// =============================================================================

type quicSimpleRecordWire struct {
	Name  string `codec:"Name"`
	Value string `codec:"Value"`
	Ttl   uint32 `codec:"Ttl"`
}

type quicMXRecordWire struct {
	Name     string `codec:"Name"`
	Value    string `codec:"Value"`
	Priority uint32 `codec:"Priority"`
	Ttl      uint32 `codec:"Ttl"`
}

type quicSRVRecordWire struct {
	Name     string `codec:"Name"`
	Target   string `codec:"Target"`
	Port     uint32 `codec:"Port"`
	Priority uint32 `codec:"Priority"`
	Weight   uint32 `codec:"Weight"`
	Ttl      uint32 `codec:"Ttl"`
}

type quicCAARecordWire struct {
	Name  string `codec:"Name"`
	Flags uint32 `codec:"Flags"`
	Tag   string `codec:"Tag"`
	Value string `codec:"Value"`
	Ttl   uint32 `codec:"Ttl"`
}

type quicTLSARecordWire struct {
	Name         string `codec:"Name"`
	Usage        uint32 `codec:"Usage"`
	Selector     uint32 `codec:"Selector"`
	MatchingType uint32 `codec:"MatchingType"`
	Data         string `codec:"Data"`
	Ttl          uint32 `codec:"Ttl"`
}

type quicRecordOneofWire struct {
	A     *quicSimpleRecordWire `codec:"A"`
	Aaaa  *quicSimpleRecordWire `codec:"Aaaa"`
	Cname *quicSimpleRecordWire `codec:"Cname"`
	Mx    *quicMXRecordWire     `codec:"Mx"`
	Ns    *quicSimpleRecordWire `codec:"Ns"`
	Txt   *quicSimpleRecordWire `codec:"Txt"`
	Srv   *quicSRVRecordWire    `codec:"Srv"`
	Caa   *quicCAARecordWire    `codec:"Caa"`
	Tlsa  *quicTLSARecordWire   `codec:"Tlsa"`
}

type quicRecordWire struct {
	Type   int32                `codec:"Type"`
	Record *quicRecordOneofWire `codec:"Record"`
}

// toPB rebuilds a pb Record from the mirror so the shared extractRecordInfo /
// recordTypeProtoToString helpers can be reused.
func (w *quicRecordWire) toPB() *pb.Record {
	if w == nil {
		return nil
	}
	rec := &pb.Record{Type: pb.RecordType(w.Type)}
	o := w.Record
	if o == nil {
		return rec
	}
	switch {
	case o.A != nil:
		rec.Record = &pb.Record_A{A: &pb.ARecord{Name: o.A.Name, Value: o.A.Value, Ttl: o.A.Ttl}}
	case o.Aaaa != nil:
		rec.Record = &pb.Record_Aaaa{Aaaa: &pb.AAAARecord{Name: o.Aaaa.Name, Value: o.Aaaa.Value, Ttl: o.Aaaa.Ttl}}
	case o.Cname != nil:
		rec.Record = &pb.Record_Cname{Cname: &pb.CNAMERecord{Name: o.Cname.Name, Value: o.Cname.Value, Ttl: o.Cname.Ttl}}
	case o.Mx != nil:
		rec.Record = &pb.Record_Mx{Mx: &pb.MXRecord{Name: o.Mx.Name, Value: o.Mx.Value, Priority: o.Mx.Priority, Ttl: o.Mx.Ttl}}
	case o.Ns != nil:
		rec.Record = &pb.Record_Ns{Ns: &pb.NSRecord{Name: o.Ns.Name, Value: o.Ns.Value, Ttl: o.Ns.Ttl}}
	case o.Txt != nil:
		rec.Record = &pb.Record_Txt{Txt: &pb.TXTRecord{Name: o.Txt.Name, Value: o.Txt.Value, Ttl: o.Txt.Ttl}}
	case o.Srv != nil:
		rec.Record = &pb.Record_Srv{Srv: &pb.SRVRecord{Name: o.Srv.Name, Target: o.Srv.Target, Port: o.Srv.Port, Priority: o.Srv.Priority, Weight: o.Srv.Weight, Ttl: o.Srv.Ttl}}
	case o.Caa != nil:
		rec.Record = &pb.Record_Caa{Caa: &pb.CAARecord{Name: o.Caa.Name, Flags: o.Caa.Flags, Tag: o.Caa.Tag, Value: o.Caa.Value, Ttl: o.Caa.Ttl}}
	case o.Tlsa != nil:
		rec.Record = &pb.Record_Tlsa{Tlsa: &pb.TLSARecord{Name: o.Tlsa.Name, Usage: o.Tlsa.Usage, Selector: o.Tlsa.Selector, MatchingType: o.Tlsa.MatchingType, Data: o.Tlsa.Data, Ttl: o.Tlsa.Ttl}}
	}
	return rec
}

type quicListRecordsWire struct {
	Records []*quicRecordWire `codec:"Records"`
	Total   uint64            `codec:"Total"`
}

type quicResolveWire struct {
	Records       []*quicRecordWire `codec:"Records"`
	Authoritative bool              `codec:"Authoritative"`
}

// =============================================================================
// Adapter
// =============================================================================

// QUICAdapter implements DNSCommands using the platform binary QUIC protocol.
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
func (q *QUICAdapter) Name() string { return "QUIC" }

// Setup establishes the QUIC connection to the platform endpoint.
func (q *QUICAdapter) Setup(ctx context.Context) error {
	q.mu.Lock()
	defer q.mu.Unlock()

	if q.closed {
		return ErrQUICClientClosed{}
	}

	connCtx, cancel := context.WithTimeout(ctx, q.timeout)
	defer cancel()

	conn, err := quicgo.DialAddr(connCtx, q.endpoint, q.tlsConfig, &quicgo.Config{
		MaxIdleTimeout:  q.maxIdleTimeout,
		KeepAlivePeriod: 15 * time.Second,
	})
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
// Wire framing
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

	if err := writeRequest(stream, opcode, payloadBytes); err != nil {
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
		return nil, ErrQUICRequestFailed{Operation: opcodeToString(opcode), Status: resp.Status, Message: errMsg}
	}

	return resp, nil
}

// quicResponse represents a QUIC protocol response.
type quicResponse struct {
	Status  byte
	Payload []byte
}

func writeRequest(w io.Writer, opcode byte, payload []byte) error {
	payloadLen := uint32(len(payload))
	if payloadLen > MaxQUICPayloadSize {
		return fmt.Errorf("payload size %d exceeds maximum %d", payloadLen, MaxQUICPayloadSize)
	}

	buf := make([]byte, 0, 1+2+4+len(payload))
	buf = append(buf, opcode)
	buf = append(buf, 0, 0) // token_len = 0 (no auth token in integration tests)
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, payloadLen)
	buf = append(buf, lenBuf...)
	buf = append(buf, payload...)

	_, err := w.Write(buf)
	return err
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

	return &quicResponse{Status: statusBuf[0], Payload: payload}, nil
}

func encodePayload(entity interface{}) ([]byte, error) {
	if entity == nil {
		return nil, nil
	}
	c, err := factory.New[any](codec.MsgPack)
	if err != nil {
		return nil, fmt.Errorf("failed to create codec: %w", err)
	}
	return c.Marshal(entity)
}

func decodePayload(data []byte, entity interface{}) error {
	if len(data) == 0 {
		return nil
	}
	c, err := factory.New[any](codec.MsgPack)
	if err != nil {
		return fmt.Errorf("failed to create codec: %w", err)
	}
	return c.Unmarshal(data, &entity)
}

func opcodeToString(opcode byte) string {
	switch opcode {
	case OpDNSAddRecord:
		return "AddRecord"
	case OpDNSDeleteRecord:
		return "DeleteRecord"
	case OpDNSUpdateRecord:
		return "UpdateRecord"
	case OpDNSGetRecord:
		return "GetRecord"
	case OpDNSListRecords:
		return "ListRecords"
	case OpDNSAddZone:
		return "CreateZone"
	case OpDNSDeleteZone:
		return "DeleteZone"
	case OpDNSGetZone:
		return "GetZone"
	case OpDNSListZones:
		return "ListZones"
	case OpDNSResolve:
		return "Resolve"
	default:
		return fmt.Sprintf("Unknown(0x%02X)", opcode)
	}
}

// =============================================================================
// Zone management
// =============================================================================

// CreateZone creates a new DNS zone (0x25, pb CreateZoneRequest).
func (q *QUICAdapter) CreateZone(ctx context.Context, opts CreateZoneOptions) (*CreateZoneResult, error) {
	req := &pb.CreateZoneRequest{
		Name:        opts.Name,
		Ttl:         opts.TTL,
		Description: opts.Description,
		Internal:    opts.Internal,
	}
	if opts.SOA != nil {
		req.Soa = &pb.SOARecord{
			Name:       opts.Name,
			Mname:      opts.SOA.MName,
			Rname:      opts.SOA.RName,
			Serial:     opts.SOA.Serial,
			Refresh:    opts.SOA.Refresh,
			Retry:      opts.SOA.Retry,
			Expire:     opts.SOA.Expire,
			MinimumTtl: opts.SOA.MinimumTTL,
			Ttl:        opts.TTL,
		}
	}

	resp, err := q.sendRequest(ctx, OpDNSAddZone, req)
	if err != nil {
		return nil, err
	}
	var result pb.CreateZoneResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "CreateZone", Err: err}
	}
	return &CreateZoneResult{
		Name:      result.GetZone().GetName(),
		ID:        fmt.Sprintf("%d", result.GetZone().GetId()),
		TTL:       result.GetZone().GetTtl(),
		Internal:  result.GetZone().GetInternal(),
		CreatedAt: time.Now(),
	}, nil
}

// GetZone retrieves a DNS zone (0x27, daemon-native flat).
func (q *QUICAdapter) GetZone(ctx context.Context, zoneName string) (*GetZoneResult, error) {
	resp, err := q.sendRequest(ctx, OpDNSGetZone, &quicDNSGetZoneReq{Zone: zoneName})
	if err != nil {
		return nil, err
	}
	var result quicDNSGetZoneResp
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "GetZone", Err: err}
	}
	if result.Zone == nil {
		return nil, ErrQUICDecodeFailed{Operation: "GetZone", Err: fmt.Errorf("empty zone")}
	}
	return &GetZoneResult{
		Name:        result.Zone.Name,
		ID:          fmt.Sprintf("%d", result.Zone.ID),
		TTL:         result.Zone.TTL,
		Description: result.Zone.Description,
		Internal:    result.Zone.Internal,
		RecordCount: result.Zone.RecordCount,
	}, nil
}

// UpdateZone has no QUIC opcode (not SDK-mapped and the 0x20-0x2D space is
// allocated or retired). It reports the operation as unsupported over QUIC.
func (q *QUICAdapter) UpdateZone(ctx context.Context, zoneName string, opts UpdateZoneOptions) (*UpdateZoneResult, error) {
	return nil, ErrQUICDNSUnsupported{Method: "UpdateZone"}
}

// DeleteZone deletes a DNS zone (0x26, pb DeleteZoneRequest).
func (q *QUICAdapter) DeleteZone(ctx context.Context, zoneName string) (*DeleteZoneResult, error) {
	resp, err := q.sendRequest(ctx, OpDNSDeleteZone, &pb.DeleteZoneRequest{Name: zoneName})
	if err != nil {
		return nil, err
	}
	var result pb.DeleteZoneResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "DeleteZone", Err: err}
	}
	return &DeleteZoneResult{
		Name:    zoneName,
		Deleted: result.GetStatus().GetSuccess(),
	}, nil
}

// ListZones lists DNS zones (0x28, pb ListZonesRequest).
func (q *QUICAdapter) ListZones(ctx context.Context, opts ListZonesOptions) (*ListZonesResult, error) {
	req := &pb.ListZonesRequest{}
	if opts.Internal != nil {
		if *opts.Internal {
			req.InternalOnly = true
		} else {
			req.PublicOnly = true
		}
	}
	if opts.Limit > 0 {
		req.Pagination = &pb.PaginationRequest{PageSize: uint32(opts.Limit)}
	}

	resp, err := q.sendRequest(ctx, OpDNSListZones, req)
	if err != nil {
		return nil, err
	}
	var result pb.ListZonesResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "ListZones", Err: err}
	}

	zones := make([]ZoneSummary, 0, len(result.GetZones()))
	for _, z := range result.GetZones() {
		zones = append(zones, ZoneSummary{
			Name:        z.GetName(),
			ID:          fmt.Sprintf("%d", z.GetId()),
			TTL:         z.GetTtl(),
			Internal:    z.GetInternal(),
			RecordCount: countRecords(z.GetRecords()),
		})
	}
	out := &ListZonesResult{Zones: zones}
	if result.GetPagination() != nil {
		out.TotalCount = int32(result.GetPagination().GetTotalItems())
		out.HasMore = result.GetPagination().GetPage() < result.GetPagination().GetTotalPages()
	}
	return out, nil
}

// =============================================================================
// Record management
// =============================================================================

// AddRecord adds a DNS record (0x20, pb AddRecordRequest carrying the oneof).
func (q *QUICAdapter) AddRecord(ctx context.Context, opts AddRecordOptions) (*AddRecordResult, error) {
	req := &pb.AddRecordRequest{
		ZoneName: opts.ZoneName,
		Record:   buildProtoRecordMessage(opts),
	}
	if _, err := q.sendRequest(ctx, OpDNSAddRecord, req); err != nil {
		return nil, err
	}
	return &AddRecordResult{
		Name:       opts.Name,
		RecordType: opts.RecordType,
		Value:      opts.Value,
		TTL:        opts.TTL,
		CreatedAt:  time.Now(),
	}, nil
}

// GetRecord retrieves a DNS record (0x23, daemon-native flat).
func (q *QUICAdapter) GetRecord(ctx context.Context, name string, recordType string) (*GetRecordResult, error) {
	req := &quicDNSGetRecordReq{Zone: extractZoneName(name), Name: name, RecordType: recordType}
	resp, err := q.sendRequest(ctx, OpDNSGetRecord, req)
	if err != nil {
		return nil, err
	}
	var result quicDNSGetRecordResp
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "GetRecord", Err: err}
	}
	if result.Record == nil {
		return nil, ErrRecordNotFound{Name: name, Type: recordType}
	}
	return &GetRecordResult{
		Name:       result.Record.Name,
		RecordType: result.Record.RecordType,
		Value:      result.Record.Value,
		TTL:        result.Record.TTL,
		Priority:   result.Record.Priority,
	}, nil
}

// UpdateRecord updates a DNS record (0x22, daemon-native flat).
func (q *QUICAdapter) UpdateRecord(ctx context.Context, opts UpdateRecordOptions) (*UpdateRecordResult, error) {
	req := &quicDNSUpdateRecordReq{
		Zone:       opts.ZoneName,
		Name:       opts.Name,
		RecordType: opts.RecordType,
		Value:      opts.Value,
		TTL:        int(opts.TTL),
		Priority:   opts.Priority,
	}
	resp, err := q.sendRequest(ctx, OpDNSUpdateRecord, req)
	if err != nil {
		return nil, err
	}
	var result quicDNSUpdateRecordResp
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "UpdateRecord", Err: err}
	}
	return &UpdateRecordResult{
		Name:       opts.Name,
		RecordType: opts.RecordType,
		Value:      opts.Value,
		TTL:        opts.TTL,
		UpdatedAt:  time.Now(),
	}, nil
}

// DeleteRecord deletes a DNS record (0x21, pb DeleteRecordRequest).
func (q *QUICAdapter) DeleteRecord(ctx context.Context, name string, recordType string) (*DeleteRecordResult, error) {
	req := &pb.DeleteRecordRequest{
		ZoneName: extractZoneName(name),
		Type:     recordTypeStringToProto(recordType),
		Name:     name,
	}
	resp, err := q.sendRequest(ctx, OpDNSDeleteRecord, req)
	if err != nil {
		return nil, err
	}
	var result pb.DeleteRecordResponse
	if err := decodePayload(resp.Payload, &result); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "DeleteRecord", Err: err}
	}
	return &DeleteRecordResult{
		Name:       name,
		RecordType: recordType,
		Deleted:    result.GetStatus().GetSuccess(),
	}, nil
}

// ListRecords lists DNS records (0x24, pb request, mirror response).
func (q *QUICAdapter) ListRecords(ctx context.Context, zoneName string, opts ListRecordsOptions) (*ListRecordsResult, error) {
	req, err := listRecordsRequest(zoneName, opts)
	if err != nil {
		return nil, err
	}
	resp, err := q.sendRequest(ctx, OpDNSListRecords, req)
	if err != nil {
		return nil, err
	}
	var wire quicListRecordsWire
	if err := decodePayload(resp.Payload, &wire); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "ListRecords", Err: err}
	}
	records := make([]*pb.Record, 0, len(wire.Records))
	for _, w := range wire.Records {
		records = append(records, w.toPB())
	}
	return listRecordsResult(req, records, wire.Total), nil
}

// =============================================================================
// Resolution
// =============================================================================

// Resolve performs DNS resolution (0x29, pb request, mirror response).
func (q *QUICAdapter) Resolve(ctx context.Context, name string, recordType string) (*ResolveResult, error) {
	req := &pb.ResolveRequest{Fqdn: name, Type: recordTypeStringToProto(recordType)}
	resp, err := q.sendRequest(ctx, OpDNSResolve, req)
	if err != nil {
		return nil, err
	}
	var wire quicResolveWire
	if err := decodePayload(resp.Payload, &wire); err != nil {
		return nil, ErrQUICDecodeFailed{Operation: "Resolve", Err: err}
	}
	values := make([]string, 0, len(wire.Records))
	var ttl uint32
	for _, w := range wire.Records {
		rec := w.toPB()
		_, value, recTTL, _, _, _ := extractRecordInfo(rec)
		values = append(values, value)
		if ttl == 0 {
			ttl = recTTL
		}
	}
	if len(values) == 0 {
		return nil, ErrRecordNotFound{Name: name, Type: recordType}
	}
	return &ResolveResult{
		Name:       name,
		RecordType: recordType,
		Values:     values,
		TTL:        ttl,
		Timestamp:  time.Now(),
	}, nil
}

// =============================================================================
// TLSA / DANE
// =============================================================================

// AddTLSARecord adds a TLSA record (0x20, pb AddRecordRequest with the TLSA
// oneof arm).
func (q *QUICAdapter) AddTLSARecord(ctx context.Context, opts AddTLSARecordOptions) (*AddTLSARecordResult, error) {
	req := &pb.AddRecordRequest{
		ZoneName: opts.ZoneName,
		Record: &pb.Record{
			Type: pb.RecordType_RECORD_TYPE_TLSA,
			Record: &pb.Record_Tlsa{
				Tlsa: &pb.TLSARecord{
					Name:         opts.Name,
					Usage:        uint32(opts.Usage),
					Selector:     uint32(opts.Selector),
					MatchingType: uint32(opts.MatchingType),
					Data:         opts.Data,
					Ttl:          opts.TTL,
				},
			},
		},
	}
	if _, err := q.sendRequest(ctx, OpDNSAddRecord, req); err != nil {
		return nil, err
	}
	return &AddTLSARecordResult{
		Name:         opts.Name,
		Usage:        opts.Usage,
		Selector:     opts.Selector,
		MatchingType: opts.MatchingType,
		Data:         opts.Data,
		TTL:          opts.TTL,
		CreatedAt:    time.Now(),
	}, nil
}

// =============================================================================
// Error types
// =============================================================================

// ErrQUICConnectionFailed indicates a QUIC connection failure.
type ErrQUICConnectionFailed struct {
	Endpoint string
	Err      error
}

func (e ErrQUICConnectionFailed) Error() string {
	return fmt.Sprintf("QUIC connection to %s failed: %v", e.Endpoint, e.Err)
}
func (e ErrQUICConnectionFailed) Unwrap() error { return e.Err }

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
func (e ErrQUICEncodeFailed) Unwrap() error { return e.Err }

// ErrQUICDecodeFailed indicates payload decoding failure.
type ErrQUICDecodeFailed struct {
	Operation string
	Err       error
}

func (e ErrQUICDecodeFailed) Error() string {
	return fmt.Sprintf("QUIC decode failed for %s: %v", e.Operation, e.Err)
}
func (e ErrQUICDecodeFailed) Unwrap() error { return e.Err }

// ErrQUICStreamFailed indicates a stream operation failure.
type ErrQUICStreamFailed struct {
	Operation string
	Err       error
}

func (e ErrQUICStreamFailed) Error() string {
	return fmt.Sprintf("QUIC stream operation %s failed: %v", e.Operation, e.Err)
}
func (e ErrQUICStreamFailed) Unwrap() error { return e.Err }

// ErrQUICClientClosed indicates the client is closed.
type ErrQUICClientClosed struct{}

func (e ErrQUICClientClosed) Error() string { return "QUIC client is closed" }

// ErrQUICDNSUnsupported indicates a DNS operation with no QUIC opcode.
type ErrQUICDNSUnsupported struct {
	Method string
}

func (e ErrQUICDNSUnsupported) Error() string {
	return fmt.Sprintf("DNS operation %s is not supported over QUIC", e.Method)
}

// Ensure QUICAdapter implements DNSCommands interface.
var _ DNSCommands = (*QUICAdapter)(nil)
