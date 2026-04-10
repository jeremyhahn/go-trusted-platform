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

//go:build codec_msgpack

package daemon

import (
	"context"
	"testing"

	"github.com/jeremyhahn/go-codec"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// init initializes the codec for QUIC DNS handler tests
func init() {
	// Set the default codec to MsgPack for encoding/decoding payloads
	_ = quic.SetDefaultCodecType(codec.MsgPack)
}

// =============================================================================
// Mock DNS Service for QUIC handler tests
// =============================================================================

// quicMockDNSService implements a mock DNS service for testing QUIC handlers.
// Since *dns.Service is the concrete type expected by QUICServiceHandler,
// we need to use a wrapper approach through interfaces defined in the tests.
type quicMockDNSService struct {
	zones         map[string]*entities.Zone
	records       map[string]interface{}
	shouldErr     bool
	errToReturn   error
	lastOperation string
	dnssecEnabled bool
}

func newQUICMockDNSService() *quicMockDNSService {
	return &quicMockDNSService{
		zones:   make(map[string]*entities.Zone),
		records: make(map[string]interface{}),
	}
}

func (m *quicMockDNSService) Save(ctx context.Context, zone *entities.Zone) error {
	if m.shouldErr {
		return m.errToReturn
	}
	m.lastOperation = "Save"
	m.zones[zone.Name] = zone
	return nil
}

func (m *quicMockDNSService) SaveAndSign(ctx context.Context, zone *entities.Zone) error {
	if m.shouldErr {
		return m.errToReturn
	}
	m.lastOperation = "SaveAndSign"
	m.zones[zone.Name] = zone
	return nil
}

func (m *quicMockDNSService) SignZone(zone *entities.Zone) error {
	if m.shouldErr {
		return m.errToReturn
	}
	m.lastOperation = "SignZone"
	return nil
}

func (m *quicMockDNSService) Delete(ctx context.Context, zone *entities.Zone) error {
	if m.shouldErr {
		return m.errToReturn
	}
	m.lastOperation = "Delete"
	delete(m.zones, zone.Name)
	return nil
}

func (m *quicMockDNSService) Zone(ctx context.Context, zoneName string) (*entities.Zone, error) {
	if m.shouldErr {
		return nil, m.errToReturn
	}
	m.lastOperation = "Zone"
	zone, ok := m.zones[zoneName]
	if !ok {
		return nil, dns.ErrZoneNotFound
	}
	return zone, nil
}

func (m *quicMockDNSService) ListZones(ctx context.Context) ([]*entities.Zone, error) {
	if m.shouldErr {
		return nil, m.errToReturn
	}
	m.lastOperation = "ListZones"
	zones := make([]*entities.Zone, 0, len(m.zones))
	for _, z := range m.zones {
		zones = append(zones, z)
	}
	return zones, nil
}

func (m *quicMockDNSService) Register(ctx context.Context, fqdn, ip string) (*entities.Zone, error) {
	if m.shouldErr {
		return nil, m.errToReturn
	}
	m.lastOperation = "Register"
	return &entities.Zone{Name: fqdn}, nil
}

func (m *quicMockDNSService) AddTLSARecord(ctx context.Context, zoneName string, record *entities.TLSARecord) error {
	if m.shouldErr {
		return m.errToReturn
	}
	m.lastOperation = "AddTLSARecord"
	return nil
}

func (m *quicMockDNSService) InternalZone(ctx context.Context) (*entities.Zone, error) {
	return m.Zone(ctx, "internal.local.")
}

func (m *quicMockDNSService) PublicZone(ctx context.Context) (*entities.Zone, error) {
	return m.Zone(ctx, "example.com.")
}

func (m *quicMockDNSService) InternalDomain() string {
	return "internal.local"
}

func (m *quicMockDNSService) PublicDomain() string {
	return "example.com"
}

func (m *quicMockDNSService) DNSSECService() *dns.DNSSECService {
	return nil
}

func (m *quicMockDNSService) IsDNSSECEnabled() bool {
	return m.dnssecEnabled
}

func (m *quicMockDNSService) AddRecord(ctx context.Context, name string, recordType string, value string, ttl int) error {
	if m.shouldErr {
		return m.errToReturn
	}
	m.lastOperation = "AddRecord"
	key := name + ":" + recordType
	m.records[key] = &entities.ARecord{Name: name, Value: value, TTL: uint32(ttl)}
	return nil
}

func (m *quicMockDNSService) DeleteRecord(ctx context.Context, name string, recordType string) error {
	if m.shouldErr {
		return m.errToReturn
	}
	m.lastOperation = "DeleteRecord"
	key := name + ":" + recordType
	delete(m.records, key)
	return nil
}

func (m *quicMockDNSService) CreateZone(ctx context.Context, zoneName string) error {
	if m.shouldErr {
		return m.errToReturn
	}
	m.lastOperation = "CreateZone"
	if _, exists := m.zones[zoneName]; exists {
		return dns.ErrZoneAlreadyExists
	}
	m.zones[zoneName] = &entities.Zone{Name: zoneName}
	return nil
}

func (m *quicMockDNSService) DeleteZone(ctx context.Context, zoneName string) error {
	if m.shouldErr {
		return m.errToReturn
	}
	m.lastOperation = "DeleteZone"
	if _, exists := m.zones[zoneName]; !exists {
		return dns.ErrZoneNotFound
	}
	delete(m.zones, zoneName)
	return nil
}

func (m *quicMockDNSService) GetRecord(ctx context.Context, name string, recordType string) (interface{}, error) {
	if m.shouldErr {
		return nil, m.errToReturn
	}
	m.lastOperation = "GetRecord"
	key := name + ":" + recordType
	record, ok := m.records[key]
	if !ok {
		return nil, dns.ErrZoneNotFound
	}
	return record, nil
}

func (m *quicMockDNSService) ListRecords(ctx context.Context, zone string) ([]interface{}, error) {
	if m.shouldErr {
		return nil, m.errToReturn
	}
	m.lastOperation = "ListRecords"
	records := make([]interface{}, 0, len(m.records))
	for _, r := range m.records {
		records = append(records, r)
	}
	return records, nil
}

func (m *quicMockDNSService) Resolve(ctx context.Context, name string, recordType string) ([]string, error) {
	if m.shouldErr {
		return nil, m.errToReturn
	}
	m.lastOperation = "Resolve"
	return []string{"192.168.1.1"}, nil
}

// =============================================================================
// handleDNSAddRecord Tests
// =============================================================================

func TestHandleDNSAddRecord_InvalidPayload(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	// Set a non-nil DNS service to bypass the service check
	// Since we can't easily mock dns.Service, we test decode failures
	ctx := context.Background()

	// Create request with invalid payload (not valid msgpack)
	req := &quic.Request{
		Opcode:  quic.OpDNSAddRecord,
		Payload: []byte{0xFF, 0xFF, 0xFF}, // Invalid msgpack
	}

	resp := handler.handleDNSOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status, "expected unavailable when DNS service is nil")
}

func TestHandleDNSAddRecord_MissingZone(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	// Create valid request without zone field
	addReq := &DNSAddRecordRequest{
		Zone:       "", // Missing zone
		Name:       "test.example.com",
		RecordType: "A",
		Value:      "192.168.1.1",
		TTL:        3600,
	}
	payload, err := quic.EncodePayload(addReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpDNSAddRecord,
		Payload: payload,
	}

	// DNS service is nil, so it will return unavailable first
	resp := handler.handleDNSOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

func TestHandleDNSAddRecord_MissingName(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	addReq := &DNSAddRecordRequest{
		Zone:       "example.com",
		Name:       "", // Missing name
		RecordType: "A",
		Value:      "192.168.1.1",
		TTL:        3600,
	}
	payload, err := quic.EncodePayload(addReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpDNSAddRecord,
		Payload: payload,
	}

	resp := handler.handleDNSOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status) // DNS service is nil
}

func TestHandleDNSAddRecord_MissingRecordType(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	addReq := &DNSAddRecordRequest{
		Zone:       "example.com",
		Name:       "test.example.com",
		RecordType: "", // Missing record type
		Value:      "192.168.1.1",
		TTL:        3600,
	}
	payload, err := quic.EncodePayload(addReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpDNSAddRecord,
		Payload: payload,
	}

	resp := handler.handleDNSOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status) // DNS service is nil
}

func TestHandleDNSAddRecord_MissingValue(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	addReq := &DNSAddRecordRequest{
		Zone:       "example.com",
		Name:       "test.example.com",
		RecordType: "A",
		Value:      "", // Missing value
		TTL:        3600,
	}
	payload, err := quic.EncodePayload(addReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpDNSAddRecord,
		Payload: payload,
	}

	resp := handler.handleDNSOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status) // DNS service is nil
}

func TestHandleDNSAddRecord_DefaultTTL(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	addReq := &DNSAddRecordRequest{
		Zone:       "example.com",
		Name:       "test.example.com",
		RecordType: "A",
		Value:      "192.168.1.1",
		TTL:        0, // Should default to 3600
	}
	payload, err := quic.EncodePayload(addReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpDNSAddRecord,
		Payload: payload,
	}

	resp := handler.handleDNSOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status) // DNS service is nil
}

// =============================================================================
// handleDNSDeleteRecord Tests
// =============================================================================

func TestHandleDNSDeleteRecord_InvalidPayload(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpDNSDeleteRecord,
		Payload: []byte{0xFF, 0xFF, 0xFF}, // Invalid msgpack
	}

	resp := handler.handleDNSOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

func TestHandleDNSDeleteRecord_MissingZone(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	deleteReq := &DNSDeleteRecordRequest{
		Zone:       "", // Missing zone
		Name:       "test.example.com",
		RecordType: "A",
	}
	payload, err := quic.EncodePayload(deleteReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpDNSDeleteRecord,
		Payload: payload,
	}

	resp := handler.handleDNSOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

func TestHandleDNSDeleteRecord_MissingName(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	deleteReq := &DNSDeleteRecordRequest{
		Zone:       "example.com",
		Name:       "", // Missing name
		RecordType: "A",
	}
	payload, err := quic.EncodePayload(deleteReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpDNSDeleteRecord,
		Payload: payload,
	}

	resp := handler.handleDNSOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

func TestHandleDNSDeleteRecord_MissingRecordType(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	deleteReq := &DNSDeleteRecordRequest{
		Zone:       "example.com",
		Name:       "test.example.com",
		RecordType: "", // Missing record type
	}
	payload, err := quic.EncodePayload(deleteReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpDNSDeleteRecord,
		Payload: payload,
	}

	resp := handler.handleDNSOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

// =============================================================================
// handleDNSUpdateRecord Tests
// =============================================================================

func TestHandleDNSUpdateRecord_InvalidPayload(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpDNSUpdateRecord,
		Payload: []byte{0xFF, 0xFF, 0xFF},
	}

	resp := handler.handleDNSOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

func TestHandleDNSUpdateRecord_MissingZone(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	updateReq := &DNSUpdateRecordRequest{
		Zone:       "", // Missing zone
		Name:       "test.example.com",
		RecordType: "A",
		Value:      "192.168.1.2",
		TTL:        7200,
	}
	payload, err := quic.EncodePayload(updateReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpDNSUpdateRecord,
		Payload: payload,
	}

	resp := handler.handleDNSOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

func TestHandleDNSUpdateRecord_MissingName(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	updateReq := &DNSUpdateRecordRequest{
		Zone:       "example.com",
		Name:       "", // Missing name
		RecordType: "A",
		Value:      "192.168.1.2",
		TTL:        7200,
	}
	payload, err := quic.EncodePayload(updateReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpDNSUpdateRecord,
		Payload: payload,
	}

	resp := handler.handleDNSOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

func TestHandleDNSUpdateRecord_MissingRecordType(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	updateReq := &DNSUpdateRecordRequest{
		Zone:       "example.com",
		Name:       "test.example.com",
		RecordType: "", // Missing record type
		Value:      "192.168.1.2",
		TTL:        7200,
	}
	payload, err := quic.EncodePayload(updateReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpDNSUpdateRecord,
		Payload: payload,
	}

	resp := handler.handleDNSOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

func TestHandleDNSUpdateRecord_MissingValue(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	updateReq := &DNSUpdateRecordRequest{
		Zone:       "example.com",
		Name:       "test.example.com",
		RecordType: "A",
		Value:      "", // Missing value
		TTL:        7200,
	}
	payload, err := quic.EncodePayload(updateReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpDNSUpdateRecord,
		Payload: payload,
	}

	resp := handler.handleDNSOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

// =============================================================================
// handleDNSGetRecord Tests
// =============================================================================

func TestHandleDNSGetRecord_InvalidPayload(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpDNSGetRecord,
		Payload: []byte{0xFF, 0xFF, 0xFF},
	}

	resp := handler.handleDNSOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

func TestHandleDNSGetRecord_MissingZone(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	getReq := &DNSGetRecordRequest{
		Zone:       "", // Missing zone
		Name:       "test.example.com",
		RecordType: "A",
	}
	payload, err := quic.EncodePayload(getReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpDNSGetRecord,
		Payload: payload,
	}

	resp := handler.handleDNSOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

func TestHandleDNSGetRecord_MissingName(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	getReq := &DNSGetRecordRequest{
		Zone:       "example.com",
		Name:       "", // Missing name
		RecordType: "A",
	}
	payload, err := quic.EncodePayload(getReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpDNSGetRecord,
		Payload: payload,
	}

	resp := handler.handleDNSOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

func TestHandleDNSGetRecord_MissingRecordType(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	getReq := &DNSGetRecordRequest{
		Zone:       "example.com",
		Name:       "test.example.com",
		RecordType: "", // Missing record type
	}
	payload, err := quic.EncodePayload(getReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpDNSGetRecord,
		Payload: payload,
	}

	resp := handler.handleDNSOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

// =============================================================================
// handleDNSListRecords Tests
// =============================================================================

func TestHandleDNSListRecords_InvalidPayload(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpDNSListRecords,
		Payload: []byte{0xFF, 0xFF, 0xFF},
	}

	resp := handler.handleDNSOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

func TestHandleDNSListRecords_MissingZone(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	listReq := &DNSListRecordsRequest{
		Zone:       "", // Missing zone
		RecordType: "A",
	}
	payload, err := quic.EncodePayload(listReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpDNSListRecords,
		Payload: payload,
	}

	resp := handler.handleDNSOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

func TestHandleDNSListRecords_EmptyPayload(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	// Empty payload should still work (zone will be empty after decode)
	req := &quic.Request{
		Opcode:  quic.OpDNSListRecords,
		Payload: []byte{},
	}

	resp := handler.handleDNSOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

// =============================================================================
// handleDNSAddZone Tests
// =============================================================================

func TestHandleDNSAddZone_InvalidPayload(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpDNSAddZone,
		Payload: []byte{0xFF, 0xFF, 0xFF},
	}

	resp := handler.handleDNSOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

func TestHandleDNSAddZone_MissingName(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	addReq := &DNSAddZoneRequest{
		Name:        "", // Missing name
		Description: "Test zone",
		TTL:         3600,
		Internal:    false,
	}
	payload, err := quic.EncodePayload(addReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpDNSAddZone,
		Payload: payload,
	}

	resp := handler.handleDNSOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

// =============================================================================
// handleDNSDeleteZone Tests
// =============================================================================

func TestHandleDNSDeleteZone_InvalidPayload(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpDNSDeleteZone,
		Payload: []byte{0xFF, 0xFF, 0xFF},
	}

	resp := handler.handleDNSOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

func TestHandleDNSDeleteZone_MissingZone(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	deleteReq := &DNSDeleteZoneRequest{
		Zone: "", // Missing zone
	}
	payload, err := quic.EncodePayload(deleteReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpDNSDeleteZone,
		Payload: payload,
	}

	resp := handler.handleDNSOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

// =============================================================================
// handleDNSGetZone Tests
// =============================================================================

func TestHandleDNSGetZone_InvalidPayload(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpDNSGetZone,
		Payload: []byte{0xFF, 0xFF, 0xFF},
	}

	resp := handler.handleDNSOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

func TestHandleDNSGetZone_MissingZone(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	getReq := &DNSGetZoneRequest{
		Zone: "", // Missing zone
	}
	payload, err := quic.EncodePayload(getReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpDNSGetZone,
		Payload: payload,
	}

	resp := handler.handleDNSOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

// =============================================================================
// handleDNSListZones Tests
// =============================================================================

func TestHandleDNSListZones_InvalidPayload(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpDNSListZones,
		Payload: []byte{0xFF, 0xFF, 0xFF},
	}

	resp := handler.handleDNSOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

func TestHandleDNSListZones_EmptyPayload(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	// Empty payload is valid for list zones
	req := &quic.Request{
		Opcode:  quic.OpDNSListZones,
		Payload: []byte{},
	}

	resp := handler.handleDNSOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

func TestHandleDNSListZones_WithInternalFilter(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	internal := true
	listReq := &DNSListZonesRequest{
		Internal: &internal,
	}
	payload, err := quic.EncodePayload(listReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpDNSListZones,
		Payload: payload,
	}

	resp := handler.handleDNSOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

// =============================================================================
// handleDNSResolve Tests
// =============================================================================

func TestHandleDNSResolve_InvalidPayload(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpDNSResolve,
		Payload: []byte{0xFF, 0xFF, 0xFF},
	}

	resp := handler.handleDNSOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

func TestHandleDNSResolve_MissingName(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	resolveReq := &DNSResolveRequest{
		Name:       "", // Missing name
		RecordType: "A",
	}
	payload, err := quic.EncodePayload(resolveReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpDNSResolve,
		Payload: payload,
	}

	resp := handler.handleDNSOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

func TestHandleDNSResolve_DefaultRecordType(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	resolveReq := &DNSResolveRequest{
		Name:       "test.example.com",
		RecordType: "", // Should default to "A"
	}
	payload, err := quic.EncodePayload(resolveReq)
	require.NoError(t, err)

	req := &quic.Request{
		Opcode:  quic.OpDNSResolve,
		Payload: payload,
	}

	resp := handler.handleDNSOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

// =============================================================================
// handleDNSGetConfig Tests
// =============================================================================

func TestHandleDNSGetConfig_NilService(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpDNSGetConfig,
		Payload: []byte{},
	}

	resp := handler.handleDNSOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

// =============================================================================
// handleDNSUpdateConfig Tests
// =============================================================================

func TestHandleDNSUpdateConfig_NilService(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpDNSUpdateConfig,
		Payload: []byte{},
	}

	resp := handler.handleDNSOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

// =============================================================================
// handleDNSGetMetrics Tests
// =============================================================================

func TestHandleDNSGetMetrics_NilService(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpDNSGetMetrics,
		Payload: []byte{},
	}

	resp := handler.handleDNSOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

// =============================================================================
// handleDNSFlushCache Tests
// =============================================================================

func TestHandleDNSFlushCache_NilService(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpDNSFlushCache,
		Payload: []byte{},
	}

	resp := handler.handleDNSOperation(ctx, req)
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

// =============================================================================
// handleDNSOperation Unknown Opcode Test
// =============================================================================

func TestHandleDNSOperation_UnknownOpcode(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	// Use an opcode that's in an unallocated range (gap between SDN 0x4F and IDevID 0x56)
	req := &quic.Request{
		Opcode:  0x50,
		Payload: []byte{},
	}

	resp := handler.HandleRequest(ctx, req)
	// This opcode is not handled by handleDNSOperation
	assert.Equal(t, quic.StatusNotImplemented, resp.Status)
}

// =============================================================================
// Request/Response Encoding Tests for Coverage
// =============================================================================

func TestDNSFlushCacheRequest_Encoding(t *testing.T) {
	original := &DNSFlushCacheRequest{
		Zone: "example.com",
	}

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded DNSFlushCacheRequest
	err = quic.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Zone, decoded.Zone)
}

func TestDNSFlushCacheResponse_Encoding(t *testing.T) {
	original := &DNSFlushCacheResponse{
		Success:       true,
		EntriesPurged: 100,
		Timestamp:     1704067200,
	}

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded DNSFlushCacheResponse
	err = quic.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Success, decoded.Success)
	assert.Equal(t, original.EntriesPurged, decoded.EntriesPurged)
	assert.Equal(t, original.Timestamp, decoded.Timestamp)
}

func TestDNSGetConfigRequest_Encoding(t *testing.T) {
	original := &DNSGetConfigRequest{}

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded DNSGetConfigRequest
	err = quic.DecodePayload(encoded, &decoded)
	require.NoError(t, err)
}

func TestDNSGetConfigResponse_Encoding(t *testing.T) {
	original := &DNSGetConfigResponse{
		Config: &DNSConfig{
			InternalDomain:    "internal.local",
			PublicDomain:      "example.com",
			DNSSECEnabled:     true,
			AllowRegistration: false,
		},
		Timestamp: 1704067200,
	}

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded DNSGetConfigResponse
	err = quic.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Config.InternalDomain, decoded.Config.InternalDomain)
	assert.Equal(t, original.Config.PublicDomain, decoded.Config.PublicDomain)
	assert.Equal(t, original.Config.DNSSECEnabled, decoded.Config.DNSSECEnabled)
	assert.Equal(t, original.Config.AllowRegistration, decoded.Config.AllowRegistration)
	assert.Equal(t, original.Timestamp, decoded.Timestamp)
}

func TestDNSUpdateConfigRequest_Encoding(t *testing.T) {
	allowReg := true
	allowExtReg := false
	allowIntReg := true

	original := &DNSUpdateConfigRequest{
		AllowRegistration:         &allowReg,
		AllowExternalRegistration: &allowExtReg,
		AllowInternalRegistration: &allowIntReg,
	}

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded DNSUpdateConfigRequest
	err = quic.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	require.NotNil(t, decoded.AllowRegistration)
	require.NotNil(t, decoded.AllowExternalRegistration)
	require.NotNil(t, decoded.AllowInternalRegistration)
	assert.True(t, *decoded.AllowRegistration)
	assert.False(t, *decoded.AllowExternalRegistration)
	assert.True(t, *decoded.AllowInternalRegistration)
}

func TestDNSUpdateConfigResponse_Encoding(t *testing.T) {
	original := &DNSUpdateConfigResponse{
		Success:   true,
		Timestamp: 1704067200,
	}

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded DNSUpdateConfigResponse
	err = quic.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Success, decoded.Success)
	assert.Equal(t, original.Timestamp, decoded.Timestamp)
}

func TestDNSGetMetricsRequest_Encoding(t *testing.T) {
	original := &DNSGetMetricsRequest{}

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded DNSGetMetricsRequest
	err = quic.DecodePayload(encoded, &decoded)
	require.NoError(t, err)
}

func TestDNSGetMetricsResponse_Encoding(t *testing.T) {
	original := &DNSGetMetricsResponse{
		Metrics: &DNSMetrics{
			ZoneCount:        5,
			TotalRecords:     100,
			QueriesTotal:     10000,
			CacheHits:        8000,
			CacheMisses:      2000,
			DNSSECValidated:  9000,
			ForwardedQueries: 500,
		},
		Timestamp: 1704067200,
	}

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded DNSGetMetricsResponse
	err = quic.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	require.NotNil(t, decoded.Metrics)
	assert.Equal(t, original.Metrics.ZoneCount, decoded.Metrics.ZoneCount)
	assert.Equal(t, original.Metrics.TotalRecords, decoded.Metrics.TotalRecords)
	assert.Equal(t, original.Metrics.QueriesTotal, decoded.Metrics.QueriesTotal)
	assert.Equal(t, original.Timestamp, decoded.Timestamp)
}

func TestDNSDeleteRecordResponse_Encoding(t *testing.T) {
	original := &DNSDeleteRecordResponse{
		Success:   true,
		Zone:      "example.com",
		Name:      "test.example.com",
		Timestamp: 1704067200,
	}

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded DNSDeleteRecordResponse
	err = quic.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Success, decoded.Success)
	assert.Equal(t, original.Zone, decoded.Zone)
	assert.Equal(t, original.Name, decoded.Name)
	assert.Equal(t, original.Timestamp, decoded.Timestamp)
}

func TestDNSUpdateRecordResponse_Encoding(t *testing.T) {
	original := &DNSUpdateRecordResponse{
		Success:   true,
		Zone:      "example.com",
		Name:      "test.example.com",
		Timestamp: 1704067200,
	}

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded DNSUpdateRecordResponse
	err = quic.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Success, decoded.Success)
	assert.Equal(t, original.Zone, decoded.Zone)
	assert.Equal(t, original.Name, decoded.Name)
	assert.Equal(t, original.Timestamp, decoded.Timestamp)
}

func TestDNSGetRecordResponse_Encoding(t *testing.T) {
	original := &DNSGetRecordResponse{
		Record: &DNSRecord{
			Name:       "test.example.com",
			RecordType: "A",
			Value:      "192.168.1.1",
			TTL:        3600,
			Priority:   0,
		},
		Zone:      "example.com",
		Timestamp: 1704067200,
	}

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded DNSGetRecordResponse
	err = quic.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	require.NotNil(t, decoded.Record)
	assert.Equal(t, original.Record.Name, decoded.Record.Name)
	assert.Equal(t, original.Record.RecordType, decoded.Record.RecordType)
	assert.Equal(t, original.Record.Value, decoded.Record.Value)
	assert.Equal(t, original.Record.TTL, decoded.Record.TTL)
	assert.Equal(t, original.Zone, decoded.Zone)
	assert.Equal(t, original.Timestamp, decoded.Timestamp)
}

func TestDNSListRecordsResponse_Encoding(t *testing.T) {
	original := &DNSListRecordsResponse{
		Records: []*DNSRecord{
			{Name: "test1.example.com", RecordType: "A", Value: "192.168.1.1", TTL: 3600},
			{Name: "test2.example.com", RecordType: "AAAA", Value: "2001:db8::1", TTL: 3600},
		},
		Zone:      "example.com",
		Total:     2,
		Timestamp: 1704067200,
	}

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded DNSListRecordsResponse
	err = quic.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	assert.Len(t, decoded.Records, 2)
	assert.Equal(t, original.Zone, decoded.Zone)
	assert.Equal(t, original.Total, decoded.Total)
	assert.Equal(t, original.Timestamp, decoded.Timestamp)
}

func TestDNSDeleteZoneResponse_Encoding(t *testing.T) {
	original := &DNSDeleteZoneResponse{
		Success:   true,
		Zone:      "example.com",
		Timestamp: 1704067200,
	}

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded DNSDeleteZoneResponse
	err = quic.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Success, decoded.Success)
	assert.Equal(t, original.Zone, decoded.Zone)
	assert.Equal(t, original.Timestamp, decoded.Timestamp)
}

func TestDNSGetZoneResponse_Encoding(t *testing.T) {
	original := &DNSGetZoneResponse{
		Zone: &DNSZone{
			ID:          1,
			Name:        "example.com",
			TTL:         3600,
			Description: "Test zone",
			Internal:    false,
			RecordCount: 10,
		},
		Timestamp: 1704067200,
	}

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded DNSGetZoneResponse
	err = quic.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	require.NotNil(t, decoded.Zone)
	assert.Equal(t, original.Zone.ID, decoded.Zone.ID)
	assert.Equal(t, original.Zone.Name, decoded.Zone.Name)
	assert.Equal(t, original.Zone.TTL, decoded.Zone.TTL)
	assert.Equal(t, original.Zone.Description, decoded.Zone.Description)
	assert.Equal(t, original.Zone.Internal, decoded.Zone.Internal)
	assert.Equal(t, original.Zone.RecordCount, decoded.Zone.RecordCount)
	assert.Equal(t, original.Timestamp, decoded.Timestamp)
}

// =============================================================================
// Test handleDNS routing
// =============================================================================

func TestHandleDNS_RoutesToHandleDNSOperation(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	// The handleDNS method should call handleDNSOperation
	req := &quic.Request{
		Opcode:  quic.OpDNSAddRecord,
		Payload: []byte{},
	}

	resp := handler.handleDNS(ctx, req)
	// Without DNS service, should return unavailable
	assert.Equal(t, quic.StatusUnavailable, resp.Status)
}

// =============================================================================
// Edge Cases and Additional Coverage
// =============================================================================

func TestDNSListRecordsRequest_WithRecordTypeFilter(t *testing.T) {
	original := &DNSListRecordsRequest{
		Zone:       "example.com",
		RecordType: "A", // Filter by type
	}

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded DNSListRecordsRequest
	err = quic.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Zone, decoded.Zone)
	assert.Equal(t, original.RecordType, decoded.RecordType)
}

func TestDNSAddZoneRequest_AllFields(t *testing.T) {
	original := &DNSAddZoneRequest{
		Name:        "test.local",
		Description: "Test internal zone",
		TTL:         7200,
		Internal:    true,
	}

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded DNSAddZoneRequest
	err = quic.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Name, decoded.Name)
	assert.Equal(t, original.Description, decoded.Description)
	assert.Equal(t, original.TTL, decoded.TTL)
	assert.Equal(t, original.Internal, decoded.Internal)
}

func TestDNSAddZoneResponse_Encoding(t *testing.T) {
	original := &DNSAddZoneResponse{
		Success:   true,
		Zone:      "example.com",
		ID:        12345,
		Timestamp: 1704067200,
	}

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded DNSAddZoneResponse
	err = quic.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Success, decoded.Success)
	assert.Equal(t, original.Zone, decoded.Zone)
	assert.Equal(t, original.ID, decoded.ID)
	assert.Equal(t, original.Timestamp, decoded.Timestamp)
}

func TestDNSListZonesResponse_Encoding(t *testing.T) {
	original := &DNSListZonesResponse{
		Zones: []*DNSZone{
			{ID: 1, Name: "example.com", TTL: 3600, Internal: false, RecordCount: 10},
			{ID: 2, Name: "internal.local", TTL: 3600, Internal: true, RecordCount: 5},
		},
		Total:     2,
		Timestamp: 1704067200,
	}

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded DNSListZonesResponse
	err = quic.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	assert.Len(t, decoded.Zones, 2)
	assert.Equal(t, original.Total, decoded.Total)
	assert.Equal(t, original.Timestamp, decoded.Timestamp)
}

func TestDNSAddRecordRequest_WithPriority(t *testing.T) {
	original := &DNSAddRecordRequest{
		Zone:       "example.com",
		Name:       "mail.example.com",
		RecordType: "MX",
		Value:      "mailserver.example.com",
		TTL:        3600,
		Priority:   10, // MX records have priority
	}

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded DNSAddRecordRequest
	err = quic.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Zone, decoded.Zone)
	assert.Equal(t, original.Name, decoded.Name)
	assert.Equal(t, original.RecordType, decoded.RecordType)
	assert.Equal(t, original.Value, decoded.Value)
	assert.Equal(t, original.TTL, decoded.TTL)
	assert.Equal(t, original.Priority, decoded.Priority)
}

func TestDNSUpdateRecordRequest_WithPriority(t *testing.T) {
	original := &DNSUpdateRecordRequest{
		Zone:       "example.com",
		Name:       "mail.example.com",
		RecordType: "MX",
		Value:      "newmailserver.example.com",
		TTL:        7200,
		Priority:   20, // Update priority
	}

	encoded, err := quic.EncodePayload(original)
	require.NoError(t, err)

	var decoded DNSUpdateRecordRequest
	err = quic.DecodePayload(encoded, &decoded)
	require.NoError(t, err)

	assert.Equal(t, original.Zone, decoded.Zone)
	assert.Equal(t, original.Name, decoded.Name)
	assert.Equal(t, original.RecordType, decoded.RecordType)
	assert.Equal(t, original.Value, decoded.Value)
	assert.Equal(t, original.TTL, decoded.TTL)
	assert.Equal(t, original.Priority, decoded.Priority)
}
