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

package quic

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-codec"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// init initializes the codec for DNS handler tests
func init() {
	// Set the default codec to MsgPack for encoding/decoding payloads
	_ = SetDefaultCodecType(codec.MsgPack)
}

// =============================================================================
// Mock DNS Service
// =============================================================================

// mockDNSService implements dns.DNSService for testing
type mockDNSService struct {
	zones          map[string]*entities.Zone
	saveError      error
	zoneError      error
	deleteError    error
	listError      error
	resolveError   error
	resolveValues  []string
	getRecordError error
	getRecordValue interface{}
}

func newMockDNSService() *mockDNSService {
	return &mockDNSService{
		zones: make(map[string]*entities.Zone),
	}
}

func (m *mockDNSService) Save(ctx context.Context, zone *entities.Zone) error {
	if m.saveError != nil {
		return m.saveError
	}
	m.zones[zone.Name] = zone
	return nil
}

func (m *mockDNSService) SaveAndSign(ctx context.Context, zone *entities.Zone) error {
	return m.Save(ctx, zone)
}

func (m *mockDNSService) SignZone(zone *entities.Zone) error {
	return nil
}

func (m *mockDNSService) Delete(ctx context.Context, zone *entities.Zone) error {
	if m.deleteError != nil {
		return m.deleteError
	}
	delete(m.zones, zone.Name)
	return nil
}

func (m *mockDNSService) Zone(ctx context.Context, zoneName string) (*entities.Zone, error) {
	if m.zoneError != nil {
		return nil, m.zoneError
	}
	zone, ok := m.zones[zoneName]
	if !ok {
		return nil, dns.ErrZoneNotFound
	}
	return zone, nil
}

func (m *mockDNSService) ListZones(ctx context.Context) ([]*entities.Zone, error) {
	if m.listError != nil {
		return nil, m.listError
	}
	zones := make([]*entities.Zone, 0, len(m.zones))
	for _, z := range m.zones {
		zones = append(zones, z)
	}
	return zones, nil
}

func (m *mockDNSService) Register(ctx context.Context, fqdn, ip string) (*entities.Zone, error) {
	return nil, nil
}

func (m *mockDNSService) RegisterWithNetworkZone(ctx context.Context, host, networkZone, ip string) error {
	return nil
}

func (m *mockDNSService) AddTLSARecord(ctx context.Context, zoneName string, record *entities.TLSARecord) error {
	return nil
}

func (m *mockDNSService) InternalZone(ctx context.Context) (*entities.Zone, error) {
	return nil, nil
}

func (m *mockDNSService) PublicZone(ctx context.Context) (*entities.Zone, error) {
	return nil, nil
}

func (m *mockDNSService) InternalDomain() string {
	return "internal.test"
}

func (m *mockDNSService) PublicDomain() string {
	return "public.test"
}

func (m *mockDNSService) DNSSECService() *dns.DNSSECService {
	return nil
}

func (m *mockDNSService) IsDNSSECEnabled() bool {
	return false
}

func (m *mockDNSService) CreateZone(ctx context.Context, zoneName string) error {
	zone := &entities.Zone{Name: zoneName, TTL: 3600}
	return m.Save(ctx, zone)
}

func (m *mockDNSService) DeleteZone(ctx context.Context, zoneName string) error {
	if m.deleteError != nil {
		return m.deleteError
	}
	if _, ok := m.zones[zoneName]; !ok {
		return dns.ErrZoneNotFound
	}
	delete(m.zones, zoneName)
	return nil
}

func (m *mockDNSService) AddRecord(ctx context.Context, name string, recordType string, value string, ttl int) error {
	return nil
}

func (m *mockDNSService) DeleteRecord(ctx context.Context, name string, recordType string) error {
	return nil
}

func (m *mockDNSService) GetRecord(ctx context.Context, name string, recordType string) (interface{}, error) {
	if m.getRecordError != nil {
		return nil, m.getRecordError
	}
	if m.getRecordValue != nil {
		return m.getRecordValue, nil
	}
	return &entities.ARecord{Name: name, Value: "192.168.1.1", TTL: 3600}, nil
}

func (m *mockDNSService) ListRecords(ctx context.Context, zone string) ([]interface{}, error) {
	return nil, nil
}

func (m *mockDNSService) Resolve(ctx context.Context, name string, recordType string) ([]string, error) {
	if m.resolveError != nil {
		return nil, m.resolveError
	}
	if m.resolveValues != nil {
		return m.resolveValues, nil
	}
	return []string{"192.168.1.1"}, nil
}

// =============================================================================
// Test Helper Functions
// =============================================================================

func newDNSTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelInfo, nil)
}

func createTestDNSHandler() (*DNSHandler, *mockDNSService) {
	logger := newDNSTestLogger()
	dnsService := newMockDNSService()
	handler := NewDNSHandler(logger, dnsService)
	return handler, dnsService
}

func createTestZone(dnsService *mockDNSService, name string) *entities.Zone {
	zone := &entities.Zone{
		ID:          1,
		Name:        name,
		TTL:         3600,
		Description: "Test zone",
		Internal:    false,
	}
	zone.RecordSet.SOARecord = entities.SOARecord{
		Name:       name,
		MName:      "ns1." + name,
		RName:      "admin." + name,
		Serial:     1,
		Refresh:    86400,
		Retry:      7200,
		Expire:     86400,
		MinimumTTL: 3600,
		TTL:        3600,
	}
	dnsService.zones[name] = zone
	return zone
}

// =============================================================================
// Test: NewDNSHandler
// =============================================================================

func TestNewDNSHandler(t *testing.T) {
	t.Run("creates handler with valid inputs", func(t *testing.T) {
		logger := newDNSTestLogger()
		dnsService := newMockDNSService()
		handler := NewDNSHandler(logger, dnsService)

		assert.NotNil(t, handler)
		assert.Equal(t, logger, handler.logger)
		assert.Equal(t, dnsService, handler.dnsService)
	})

	t.Run("creates handler with nil dns service", func(t *testing.T) {
		logger := newDNSTestLogger()
		handler := NewDNSHandler(logger, nil)

		assert.NotNil(t, handler)
		assert.Nil(t, handler.dnsService)
	})
}

// =============================================================================
// Test: HandleRequest
// =============================================================================

func TestDNSHandleRequest(t *testing.T) {
	t.Run("returns error for nil request", func(t *testing.T) {
		handler, _ := createTestDNSHandler()

		resp := handler.HandleRequest(context.Background(), nil)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
		assert.Contains(t, string(resp.Payload), "nil")
	})

	t.Run("returns error for unknown opcode", func(t *testing.T) {
		handler, _ := createTestDNSHandler()

		req := &Request{
			Opcode: 0x00, // Unknown opcode for DNS handler
		}

		resp := handler.HandleRequest(context.Background(), req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
		assert.Contains(t, string(resp.Payload), "unknown dns operation")
	})
}

// =============================================================================
// Test: AddZone
// =============================================================================

func TestHandleAddZone(t *testing.T) {
	ctx := context.Background()

	t.Run("creates zone successfully", func(t *testing.T) {
		handler, _ := createTestDNSHandler()

		addReq := &DNSAddZoneRequest{
			Name:        "example.com",
			TTL:         3600,
			Description: "Test zone",
			Internal:    false,
			SOA: &DNSSOARecordRequest{
				MName:      "ns1.example.com",
				RName:      "admin.example.com",
				Serial:     1,
				Refresh:    86400,
				Retry:      7200,
				Expire:     86400,
				MinimumTTL: 3600,
				TTL:        3600,
			},
			NSRecords: []DNSNSRecordRequest{
				{Name: "example.com", Value: "ns1.example.com", TTL: 3600},
			},
		}

		payload, err := EncodePayload(addReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSAddZone,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var addResp DNSAddZoneResponse
		err = DecodePayload(resp.Payload, &addResp)
		require.NoError(t, err)

		assert.NotNil(t, addResp.Zone)
		assert.Equal(t, "example.com", addResp.Zone.Name)
		assert.Equal(t, uint32(3600), addResp.Zone.TTL)
		assert.Greater(t, addResp.Timestamp, int64(0))
	})

	t.Run("creates zone with default TTL", func(t *testing.T) {
		handler, _ := createTestDNSHandler()

		addReq := &DNSAddZoneRequest{
			Name: "default-ttl.com",
		}

		payload, err := EncodePayload(addReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSAddZone,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var addResp DNSAddZoneResponse
		err = DecodePayload(resp.Payload, &addResp)
		require.NoError(t, err)

		assert.Equal(t, uint32(3600), addResp.Zone.TTL)
	})

	t.Run("returns error when dns service unavailable", func(t *testing.T) {
		handler := NewDNSHandler(newDNSTestLogger(), nil)

		addReq := &DNSAddZoneRequest{
			Name: "example.com",
		}

		payload, err := EncodePayload(addReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSAddZone,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
		assert.Contains(t, string(resp.Payload), "not available")
	})

	t.Run("returns error for missing name", func(t *testing.T) {
		handler, _ := createTestDNSHandler()

		addReq := &DNSAddZoneRequest{
			TTL: 3600,
		}

		payload, err := EncodePayload(addReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSAddZone,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
		assert.Contains(t, string(resp.Payload), "zone name")
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createTestDNSHandler()

		req := &Request{
			Opcode:  OpDNSAddZone,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error when save fails", func(t *testing.T) {
		handler, dnsService := createTestDNSHandler()
		dnsService.saveError = errors.New("save failed")

		addReq := &DNSAddZoneRequest{
			Name: "example.com",
		}

		payload, err := EncodePayload(addReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSAddZone,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInternalError, resp.Status)
	})
}

// =============================================================================
// Test: GetZone
// =============================================================================

func TestHandleGetZone(t *testing.T) {
	ctx := context.Background()

	t.Run("gets zone successfully", func(t *testing.T) {
		handler, dnsService := createTestDNSHandler()
		createTestZone(dnsService, "example.com")

		getReq := &DNSGetZoneRequest{
			Name: "example.com",
		}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSGetZone,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var getResp DNSGetZoneResponse
		err = DecodePayload(resp.Payload, &getResp)
		require.NoError(t, err)

		assert.NotNil(t, getResp.Zone)
		assert.Equal(t, "example.com", getResp.Zone.Name)
	})

	t.Run("returns error when dns service unavailable", func(t *testing.T) {
		handler := NewDNSHandler(newDNSTestLogger(), nil)

		getReq := &DNSGetZoneRequest{
			Name: "example.com",
		}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSGetZone,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing name", func(t *testing.T) {
		handler, _ := createTestDNSHandler()

		getReq := &DNSGetZoneRequest{}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSGetZone,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for zone not found", func(t *testing.T) {
		handler, _ := createTestDNSHandler()

		getReq := &DNSGetZoneRequest{
			Name: "nonexistent.com",
		}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSGetZone,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: DeleteZone
// =============================================================================

func TestHandleDeleteZone(t *testing.T) {
	ctx := context.Background()

	t.Run("deletes zone successfully", func(t *testing.T) {
		handler, dnsService := createTestDNSHandler()
		createTestZone(dnsService, "example.com")

		deleteReq := &DNSDeleteZoneRequest{
			Name: "example.com",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSDeleteZone,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var deleteResp DNSDeleteZoneResponse
		err = DecodePayload(resp.Payload, &deleteResp)
		require.NoError(t, err)

		assert.Equal(t, "example.com", deleteResp.Name)
		assert.True(t, deleteResp.Success)
	})

	t.Run("returns error when dns service unavailable", func(t *testing.T) {
		handler := NewDNSHandler(newDNSTestLogger(), nil)

		deleteReq := &DNSDeleteZoneRequest{
			Name: "example.com",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSDeleteZone,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing name", func(t *testing.T) {
		handler, _ := createTestDNSHandler()

		deleteReq := &DNSDeleteZoneRequest{}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSDeleteZone,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for zone not found", func(t *testing.T) {
		handler, _ := createTestDNSHandler()

		deleteReq := &DNSDeleteZoneRequest{
			Name: "nonexistent.com",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSDeleteZone,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: ListZones
// =============================================================================

func TestHandleListZones(t *testing.T) {
	ctx := context.Background()

	t.Run("lists zones successfully", func(t *testing.T) {
		handler, dnsService := createTestDNSHandler()
		createTestZone(dnsService, "example1.com")
		createTestZone(dnsService, "example2.com")

		listReq := &DNSListZonesRequest{
			Limit: 10,
		}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSListZones,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var listResp DNSListZonesResponse
		err = DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Equal(t, int32(2), listResp.Count)
		assert.Len(t, listResp.Zones, 2)
	})

	t.Run("uses default limit when not specified", func(t *testing.T) {
		handler, _ := createTestDNSHandler()

		listReq := &DNSListZonesRequest{}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSListZones,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)
	})

	t.Run("caps limit at max", func(t *testing.T) {
		handler, _ := createTestDNSHandler()

		listReq := &DNSListZonesRequest{
			Limit: 5000, // exceeds max
		}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSListZones,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)
	})

	t.Run("applies pagination offset", func(t *testing.T) {
		handler, dnsService := createTestDNSHandler()
		createTestZone(dnsService, "example1.com")
		createTestZone(dnsService, "example2.com")
		createTestZone(dnsService, "example3.com")

		listReq := &DNSListZonesRequest{
			Limit:  1,
			Offset: 1,
		}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSListZones,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var listResp DNSListZonesResponse
		err = DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Equal(t, int32(1), listResp.Count)
	})

	t.Run("returns error when dns service unavailable", func(t *testing.T) {
		handler := NewDNSHandler(newDNSTestLogger(), nil)

		listReq := &DNSListZonesRequest{}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSListZones,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error when list fails", func(t *testing.T) {
		handler, dnsService := createTestDNSHandler()
		dnsService.listError = errors.New("list failed")

		listReq := &DNSListZonesRequest{}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSListZones,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInternalError, resp.Status)
	})
}

// =============================================================================
// Test: AddRecord
// =============================================================================

func TestHandleAddRecord(t *testing.T) {
	ctx := context.Background()

	t.Run("adds A record successfully", func(t *testing.T) {
		handler, dnsService := createTestDNSHandler()
		createTestZone(dnsService, "example.com")

		addReq := &DNSAddRecordRequest{
			ZoneName: "example.com",
			Type:     "A",
			Name:     "www.example.com",
			Value:    "192.168.1.1",
			TTL:      3600,
		}

		payload, err := EncodePayload(addReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSAddRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var addResp DNSAddRecordResponse
		err = DecodePayload(resp.Payload, &addResp)
		require.NoError(t, err)

		assert.NotNil(t, addResp.Zone)
	})

	t.Run("adds AAAA record successfully", func(t *testing.T) {
		handler, dnsService := createTestDNSHandler()
		createTestZone(dnsService, "example.com")

		addReq := &DNSAddRecordRequest{
			ZoneName: "example.com",
			Type:     "AAAA",
			Name:     "www.example.com",
			Value:    "2001:db8::1",
			TTL:      3600,
		}

		payload, err := EncodePayload(addReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSAddRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)
	})

	t.Run("adds CNAME record successfully", func(t *testing.T) {
		handler, dnsService := createTestDNSHandler()
		createTestZone(dnsService, "example.com")

		addReq := &DNSAddRecordRequest{
			ZoneName: "example.com",
			Type:     "CNAME",
			Name:     "alias.example.com",
			Value:    "www.example.com",
		}

		payload, err := EncodePayload(addReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSAddRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)
	})

	t.Run("adds MX record successfully", func(t *testing.T) {
		handler, dnsService := createTestDNSHandler()
		createTestZone(dnsService, "example.com")

		addReq := &DNSAddRecordRequest{
			ZoneName: "example.com",
			Type:     "MX",
			Name:     "example.com",
			Value:    "mail.example.com",
			Priority: 10,
		}

		payload, err := EncodePayload(addReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSAddRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)
	})

	t.Run("adds NS record successfully", func(t *testing.T) {
		handler, dnsService := createTestDNSHandler()
		createTestZone(dnsService, "example.com")

		addReq := &DNSAddRecordRequest{
			ZoneName: "example.com",
			Type:     "NS",
			Name:     "example.com",
			Value:    "ns1.example.com",
		}

		payload, err := EncodePayload(addReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSAddRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)
	})

	t.Run("adds TXT record successfully", func(t *testing.T) {
		handler, dnsService := createTestDNSHandler()
		createTestZone(dnsService, "example.com")

		addReq := &DNSAddRecordRequest{
			ZoneName: "example.com",
			Type:     "TXT",
			Name:     "example.com",
			Value:    "v=spf1 include:_spf.example.com ~all",
		}

		payload, err := EncodePayload(addReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSAddRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)
	})

	t.Run("adds SRV record successfully", func(t *testing.T) {
		handler, dnsService := createTestDNSHandler()
		createTestZone(dnsService, "example.com")

		addReq := &DNSAddRecordRequest{
			ZoneName: "example.com",
			Type:     "SRV",
			Name:     "_sip._tcp.example.com",
			Target:   "sipserver.example.com",
			Port:     5060,
			Priority: 10,
			Weight:   5,
		}

		payload, err := EncodePayload(addReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSAddRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)
	})

	t.Run("adds CAA record successfully", func(t *testing.T) {
		handler, dnsService := createTestDNSHandler()
		createTestZone(dnsService, "example.com")

		addReq := &DNSAddRecordRequest{
			ZoneName: "example.com",
			Type:     "CAA",
			Name:     "example.com",
			Flags:    0,
			Tag:      "issue",
			Value:    "letsencrypt.org",
		}

		payload, err := EncodePayload(addReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSAddRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)
	})

	t.Run("adds TLSA record successfully", func(t *testing.T) {
		handler, dnsService := createTestDNSHandler()
		createTestZone(dnsService, "example.com")

		addReq := &DNSAddRecordRequest{
			ZoneName:     "example.com",
			Type:         "TLSA",
			Name:         "_443._tcp.www.example.com",
			Usage:        3,
			Selector:     1,
			MatchingType: 1,
			Data:         "abc123",
		}

		payload, err := EncodePayload(addReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSAddRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)
	})

	t.Run("returns error when dns service unavailable", func(t *testing.T) {
		handler := NewDNSHandler(newDNSTestLogger(), nil)

		addReq := &DNSAddRecordRequest{
			ZoneName: "example.com",
			Type:     "A",
			Name:     "www.example.com",
			Value:    "192.168.1.1",
		}

		payload, err := EncodePayload(addReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSAddRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing zone name", func(t *testing.T) {
		handler, _ := createTestDNSHandler()

		addReq := &DNSAddRecordRequest{
			Type:  "A",
			Name:  "www.example.com",
			Value: "192.168.1.1",
		}

		payload, err := EncodePayload(addReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSAddRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing record type", func(t *testing.T) {
		handler, _ := createTestDNSHandler()

		addReq := &DNSAddRecordRequest{
			ZoneName: "example.com",
			Name:     "www.example.com",
			Value:    "192.168.1.1",
		}

		payload, err := EncodePayload(addReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSAddRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing record name", func(t *testing.T) {
		handler, _ := createTestDNSHandler()

		addReq := &DNSAddRecordRequest{
			ZoneName: "example.com",
			Type:     "A",
			Value:    "192.168.1.1",
		}

		payload, err := EncodePayload(addReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSAddRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for invalid record type", func(t *testing.T) {
		handler, dnsService := createTestDNSHandler()
		createTestZone(dnsService, "example.com")

		addReq := &DNSAddRecordRequest{
			ZoneName: "example.com",
			Type:     "INVALID",
			Name:     "www.example.com",
			Value:    "192.168.1.1",
		}

		payload, err := EncodePayload(addReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSAddRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for zone not found", func(t *testing.T) {
		handler, _ := createTestDNSHandler()

		addReq := &DNSAddRecordRequest{
			ZoneName: "nonexistent.com",
			Type:     "A",
			Name:     "www.nonexistent.com",
			Value:    "192.168.1.1",
		}

		payload, err := EncodePayload(addReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSAddRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})

	t.Run("returns error when save fails", func(t *testing.T) {
		handler, dnsService := createTestDNSHandler()
		createTestZone(dnsService, "example.com")
		dnsService.saveError = errors.New("save operation failed")

		addReq := &DNSAddRecordRequest{
			ZoneName: "example.com",
			Type:     "A",
			Name:     "www.example.com",
			Value:    "192.168.1.1",
		}

		payload, err := EncodePayload(addReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSAddRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInternalError, resp.Status)
	})
}

// =============================================================================
// Test: GetRecord
// =============================================================================

func TestHandleGetRecord(t *testing.T) {
	ctx := context.Background()

	t.Run("gets record successfully", func(t *testing.T) {
		handler, dnsService := createTestDNSHandler()
		createTestZone(dnsService, "example.com")

		getReq := &DNSGetRecordRequest{
			ZoneName:   "example.com",
			RecordName: "www.example.com",
			RecordType: "A",
		}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSGetRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var getResp DNSGetRecordResponse
		err = DecodePayload(resp.Payload, &getResp)
		require.NoError(t, err)

		assert.NotNil(t, getResp.Record)
	})

	t.Run("returns error when dns service unavailable", func(t *testing.T) {
		handler := NewDNSHandler(newDNSTestLogger(), nil)

		getReq := &DNSGetRecordRequest{
			ZoneName:   "example.com",
			RecordName: "www.example.com",
			RecordType: "A",
		}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSGetRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing zone name", func(t *testing.T) {
		handler, _ := createTestDNSHandler()

		getReq := &DNSGetRecordRequest{
			RecordName: "www.example.com",
			RecordType: "A",
		}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSGetRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing record name", func(t *testing.T) {
		handler, _ := createTestDNSHandler()

		getReq := &DNSGetRecordRequest{
			ZoneName:   "example.com",
			RecordType: "A",
		}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSGetRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing record type", func(t *testing.T) {
		handler, _ := createTestDNSHandler()

		getReq := &DNSGetRecordRequest{
			ZoneName:   "example.com",
			RecordName: "www.example.com",
		}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSGetRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error when record operation fails", func(t *testing.T) {
		handler, dnsService := createTestDNSHandler()
		createTestZone(dnsService, "example.com")
		dnsService.getRecordError = errors.New("database error")

		getReq := &DNSGetRecordRequest{
			ZoneName:   "example.com",
			RecordName: "nonexistent.example.com",
			RecordType: "A",
		}

		payload, err := EncodePayload(getReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSGetRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInternalError, resp.Status)
	})
}

// =============================================================================
// Test: UpdateRecord
// =============================================================================

func TestHandleUpdateRecord(t *testing.T) {
	ctx := context.Background()

	t.Run("updates A record successfully", func(t *testing.T) {
		handler, dnsService := createTestDNSHandler()
		zone := createTestZone(dnsService, "example.com")
		zone.AddARecord(&entities.ARecord{Name: "www.example.com", Value: "192.168.1.1", TTL: 3600})

		updateReq := &DNSUpdateRecordRequest{
			ZoneName: "example.com",
			Type:     "A",
			Name:     "www.example.com",
			Value:    "192.168.1.2",
			TTL:      7200,
		}

		payload, err := EncodePayload(updateReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSUpdateRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)
	})

	t.Run("returns error when dns service unavailable", func(t *testing.T) {
		handler := NewDNSHandler(newDNSTestLogger(), nil)

		updateReq := &DNSUpdateRecordRequest{
			ZoneName: "example.com",
			Type:     "A",
			Name:     "www.example.com",
			Value:    "192.168.1.2",
		}

		payload, err := EncodePayload(updateReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSUpdateRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing zone name", func(t *testing.T) {
		handler, _ := createTestDNSHandler()

		updateReq := &DNSUpdateRecordRequest{
			Type:  "A",
			Name:  "www.example.com",
			Value: "192.168.1.2",
		}

		payload, err := EncodePayload(updateReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSUpdateRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for record not found", func(t *testing.T) {
		handler, dnsService := createTestDNSHandler()
		createTestZone(dnsService, "example.com")

		updateReq := &DNSUpdateRecordRequest{
			ZoneName: "example.com",
			Type:     "A",
			Name:     "nonexistent.example.com",
			Value:    "192.168.1.2",
		}

		payload, err := EncodePayload(updateReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSUpdateRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: DeleteRecord
// =============================================================================

func TestHandleDeleteRecord(t *testing.T) {
	ctx := context.Background()

	t.Run("deletes A record successfully", func(t *testing.T) {
		handler, dnsService := createTestDNSHandler()
		zone := createTestZone(dnsService, "example.com")
		zone.AddARecord(&entities.ARecord{Name: "www.example.com", Value: "192.168.1.1", TTL: 3600})

		deleteReq := &DNSDeleteRecordRequest{
			ZoneName:   "example.com",
			RecordName: "www.example.com",
			RecordType: "A",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSDeleteRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var deleteResp DNSDeleteRecordResponse
		err = DecodePayload(resp.Payload, &deleteResp)
		require.NoError(t, err)

		assert.True(t, deleteResp.Success)
	})

	t.Run("returns error when dns service unavailable", func(t *testing.T) {
		handler := NewDNSHandler(newDNSTestLogger(), nil)

		deleteReq := &DNSDeleteRecordRequest{
			ZoneName:   "example.com",
			RecordName: "www.example.com",
			RecordType: "A",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSDeleteRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing zone name", func(t *testing.T) {
		handler, _ := createTestDNSHandler()

		deleteReq := &DNSDeleteRecordRequest{
			RecordName: "www.example.com",
			RecordType: "A",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSDeleteRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for record not found", func(t *testing.T) {
		handler, dnsService := createTestDNSHandler()
		createTestZone(dnsService, "example.com")

		deleteReq := &DNSDeleteRecordRequest{
			ZoneName:   "example.com",
			RecordName: "nonexistent.example.com",
			RecordType: "A",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSDeleteRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: ListRecords
// =============================================================================

func TestHandleListRecords(t *testing.T) {
	ctx := context.Background()

	t.Run("lists all records successfully", func(t *testing.T) {
		handler, dnsService := createTestDNSHandler()
		zone := createTestZone(dnsService, "example.com")
		zone.AddARecord(&entities.ARecord{Name: "www.example.com", Value: "192.168.1.1", TTL: 3600})
		zone.AddAAAARecord(&entities.AAAARecord{Name: "www.example.com", Value: "2001:db8::1", TTL: 3600})

		listReq := &DNSListRecordsRequest{
			ZoneName: "example.com",
		}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSListRecords,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var listResp DNSListRecordsResponse
		err = DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Equal(t, int32(2), listResp.Count)
	})

	t.Run("filters records by type", func(t *testing.T) {
		handler, dnsService := createTestDNSHandler()
		zone := createTestZone(dnsService, "example.com")
		zone.AddARecord(&entities.ARecord{Name: "www.example.com", Value: "192.168.1.1", TTL: 3600})
		zone.AddAAAARecord(&entities.AAAARecord{Name: "www.example.com", Value: "2001:db8::1", TTL: 3600})

		listReq := &DNSListRecordsRequest{
			ZoneName:   "example.com",
			TypeFilter: "A",
		}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSListRecords,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var listResp DNSListRecordsResponse
		err = DecodePayload(resp.Payload, &listResp)
		require.NoError(t, err)

		assert.Equal(t, int32(1), listResp.Count)
	})

	t.Run("returns error when dns service unavailable", func(t *testing.T) {
		handler := NewDNSHandler(newDNSTestLogger(), nil)

		listReq := &DNSListRecordsRequest{
			ZoneName: "example.com",
		}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSListRecords,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing zone name", func(t *testing.T) {
		handler, _ := createTestDNSHandler()

		listReq := &DNSListRecordsRequest{}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSListRecords,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for zone not found", func(t *testing.T) {
		handler, _ := createTestDNSHandler()

		listReq := &DNSListRecordsRequest{
			ZoneName: "nonexistent.com",
		}

		payload, err := EncodePayload(listReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSListRecords,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: Resolve
// =============================================================================

func TestHandleResolve(t *testing.T) {
	ctx := context.Background()

	t.Run("resolves DNS query successfully", func(t *testing.T) {
		handler, dnsService := createTestDNSHandler()
		dnsService.resolveValues = []string{"192.168.1.1", "192.168.1.2"}

		resolveReq := &DNSResolveRequest{
			FQDN: "www.example.com",
			Type: "A",
		}

		payload, err := EncodePayload(resolveReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSResolve,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var resolveResp DNSResolveResponse
		err = DecodePayload(resp.Payload, &resolveResp)
		require.NoError(t, err)

		assert.Equal(t, "www.example.com", resolveResp.FQDN)
		assert.Equal(t, "A", resolveResp.Type)
		assert.Equal(t, []string{"192.168.1.1", "192.168.1.2"}, resolveResp.Values)
		assert.True(t, resolveResp.Authoritative)
	})

	t.Run("defaults to A record type", func(t *testing.T) {
		handler, dnsService := createTestDNSHandler()
		dnsService.resolveValues = []string{"192.168.1.1"}

		resolveReq := &DNSResolveRequest{
			FQDN: "www.example.com",
		}

		payload, err := EncodePayload(resolveReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSResolve,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusOK, resp.Status)

		var resolveResp DNSResolveResponse
		err = DecodePayload(resp.Payload, &resolveResp)
		require.NoError(t, err)

		assert.Equal(t, "A", resolveResp.Type)
	})

	t.Run("returns error when dns service unavailable", func(t *testing.T) {
		handler := NewDNSHandler(newDNSTestLogger(), nil)

		resolveReq := &DNSResolveRequest{
			FQDN: "www.example.com",
			Type: "A",
		}

		payload, err := EncodePayload(resolveReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSResolve,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for missing FQDN", func(t *testing.T) {
		handler, _ := createTestDNSHandler()

		resolveReq := &DNSResolveRequest{
			Type: "A",
		}

		payload, err := EncodePayload(resolveReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSResolve,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error when resolve fails", func(t *testing.T) {
		handler, dnsService := createTestDNSHandler()
		dnsService.resolveError = dns.ErrZoneNotFound

		resolveReq := &DNSResolveRequest{
			FQDN: "www.nonexistent.com",
			Type: "A",
		}

		payload, err := EncodePayload(resolveReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSResolve,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: Error Types
// =============================================================================

func TestDNSErrorTypes(t *testing.T) {
	t.Run("ErrDNSEncodingFailed", func(t *testing.T) {
		cause := errors.New("encoding error")
		err := ErrDNSEncodingFailed{Cause: cause}

		assert.Contains(t, err.Error(), "encoding error")
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("ErrDNSDecodingFailed", func(t *testing.T) {
		cause := errors.New("decoding error")
		err := ErrDNSDecodingFailed{Cause: cause}

		assert.Contains(t, err.Error(), "decoding error")
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("ErrDNSRecordNotFound", func(t *testing.T) {
		err := ErrDNSRecordNotFound{Name: "www.example.com", Type: "A"}

		assert.Contains(t, err.Error(), "www.example.com")
		assert.Contains(t, err.Error(), "A")
	})

	t.Run("ErrDNSOperationFailed", func(t *testing.T) {
		cause := errors.New("operation error")
		err := ErrDNSOperationFailed{
			Operation: "create_zone",
			Cause:     cause,
		}

		assert.Contains(t, err.Error(), "create_zone")
		assert.Contains(t, err.Error(), "operation error")
		assert.Equal(t, cause, err.Unwrap())
	})
}

// =============================================================================
// Test: dnsErrorResponse - Comprehensive Error Mapping
// =============================================================================

func TestDNSErrorResponse(t *testing.T) {
	handler, _ := createTestDNSHandler()

	testCases := []struct {
		name           string
		err            error
		expectedStatus byte
	}{
		{"zone not found", dns.ErrZoneNotFound, StatusNotFound},
		{"zone already exists", dns.ErrZoneAlreadyExists, StatusAlreadyExists},
		{"DNSSEC not enabled", dns.ErrDNSSECNotEnabled, StatusInvalidRequest},
		{"registration disabled", dns.ErrRegistrationDisabled, StatusPermissionDenied},
		{"external registration disabled", dns.ErrExternalRegistrationDisabled, StatusPermissionDenied},
		{"internal registration disabled", dns.ErrInternalRegistrationDisabled, StatusPermissionDenied},
		{"invalid IP address", dns.ErrInvalidIPAddress, StatusInvalidArgument},
		{"invalid private IP", dns.ErrInvalidPrivateIP, StatusInvalidArgument},
		{"invalid public IP", dns.ErrInvalidPublicIP, StatusInvalidArgument},
		{"invalid private TLD", dns.ErrInvalidPrivateTLD, StatusInvalidArgument},
		{"invalid public TLD", dns.ErrInvalidPublicTLD, StatusInvalidArgument},
		{"parsing domain name", dns.ErrParsingDomainName, StatusInvalidArgument},
		{"context canceled", context.Canceled, StatusTimeout},
		{"context deadline exceeded", context.DeadlineExceeded, StatusTimeout},
		{"generic error", errors.New("unknown error"), StatusInternalError},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			resp := handler.dnsErrorResponse(tc.err)
			assert.Equal(t, tc.expectedStatus, resp.Status)
		})
	}
}

// =============================================================================
// Test: buildZoneFromRequest
// =============================================================================

func TestBuildZoneFromRequest(t *testing.T) {
	handler, _ := createTestDNSHandler()

	t.Run("builds complete zone", func(t *testing.T) {
		req := &DNSAddZoneRequest{
			Name:        "example.com",
			TTL:         7200,
			Description: "Test zone",
			Internal:    true,
			SOA: &DNSSOARecordRequest{
				MName:      "ns1.example.com",
				RName:      "admin.example.com",
				Serial:     1,
				Refresh:    86400,
				Retry:      7200,
				Expire:     86400,
				MinimumTTL: 3600,
				TTL:        3600,
			},
			NSRecords: []DNSNSRecordRequest{
				{Name: "example.com", Value: "ns1.example.com", TTL: 3600},
				{Name: "example.com", Value: "ns2.example.com", TTL: 3600},
			},
		}

		zone := handler.buildZoneFromRequest(req)

		assert.Equal(t, "example.com", zone.Name)
		assert.Equal(t, uint32(7200), zone.TTL)
		assert.Equal(t, "Test zone", zone.Description)
		assert.True(t, zone.Internal)
		assert.Equal(t, "ns1.example.com", zone.RecordSet.SOARecord.MName)
		assert.Len(t, zone.RecordSet.NSRecords, 2)
	})

	t.Run("builds minimal zone with defaults", func(t *testing.T) {
		req := &DNSAddZoneRequest{
			Name: "minimal.com",
		}

		zone := handler.buildZoneFromRequest(req)

		assert.Equal(t, "minimal.com", zone.Name)
		assert.Equal(t, uint32(3600), zone.TTL)
		assert.Empty(t, zone.RecordSet.NSRecords)
	})

	t.Run("applies SOA defaults", func(t *testing.T) {
		req := &DNSAddZoneRequest{
			Name: "example.com",
			SOA: &DNSSOARecordRequest{
				MName: "ns1.example.com",
				RName: "admin.example.com",
			},
		}

		zone := handler.buildZoneFromRequest(req)

		assert.Equal(t, uint32(86400), zone.RecordSet.SOARecord.Refresh)
		assert.Equal(t, uint32(7200), zone.RecordSet.SOARecord.Retry)
		assert.Equal(t, uint32(86400), zone.RecordSet.SOARecord.Expire)
		assert.Equal(t, uint32(3600), zone.RecordSet.SOARecord.MinimumTTL)
		assert.Equal(t, uint32(3600), zone.RecordSet.SOARecord.TTL)
	})
}

// =============================================================================
// Test: zoneToInfo
// =============================================================================

func TestZoneToInfo(t *testing.T) {
	handler, _ := createTestDNSHandler()

	t.Run("converts complete zone", func(t *testing.T) {
		zone := &entities.Zone{
			ID:          1,
			Name:        "example.com",
			TTL:         3600,
			Description: "Test zone",
			Internal:    true,
		}
		zone.RecordSet.SOARecord = entities.SOARecord{
			Name:       "example.com",
			MName:      "ns1.example.com",
			RName:      "admin.example.com",
			Serial:     1,
			Refresh:    86400,
			Retry:      7200,
			Expire:     86400,
			MinimumTTL: 3600,
			TTL:        3600,
		}
		zone.AddARecord(&entities.ARecord{Name: "www", Value: "192.168.1.1", TTL: 3600})

		info := handler.zoneToInfo(zone)

		assert.Equal(t, uint64(1), info.ID)
		assert.Equal(t, "example.com", info.Name)
		assert.Equal(t, uint32(3600), info.TTL)
		assert.Equal(t, "Test zone", info.Description)
		assert.True(t, info.Internal)
		assert.NotNil(t, info.Records)
		assert.NotNil(t, info.Records.SOA)
		assert.Len(t, info.Records.A, 1)
	})

	t.Run("handles nil zone", func(t *testing.T) {
		info := handler.zoneToInfo(nil)
		assert.Nil(t, info)
	})

	t.Run("handles empty zone", func(t *testing.T) {
		zone := &entities.Zone{
			Name: "empty.com",
		}

		info := handler.zoneToInfo(zone)

		assert.NotNil(t, info)
		assert.Equal(t, "empty.com", info.Name)
		assert.Nil(t, info.Records.SOA)
	})
}

// =============================================================================
// Test: Pagination Constants
// =============================================================================

func TestDNSPaginationConstants(t *testing.T) {
	assert.Equal(t, int32(100), dnsDefaultLimit)
	assert.Equal(t, int32(1000), dnsMaxLimit)
	assert.Less(t, dnsDefaultLimit, dnsMaxLimit)
}

// =============================================================================
// Test: Sentinel Error Variables
// =============================================================================

func TestDNSSentinelErrors(t *testing.T) {
	assert.NotNil(t, ErrDNSServiceNotAvailable)
	assert.NotNil(t, ErrDNSMissingZoneName)
	assert.NotNil(t, ErrDNSMissingRecordName)
	assert.NotNil(t, ErrDNSMissingRecordType)
	assert.NotNil(t, ErrDNSMissingFQDN)
	assert.NotNil(t, ErrDNSMissingIP)
	assert.NotNil(t, ErrDNSInvalidRecordType)

	assert.Contains(t, ErrDNSServiceNotAvailable.Error(), "not available")
	assert.Contains(t, ErrDNSMissingZoneName.Error(), "zone name")
	assert.Contains(t, ErrDNSMissingRecordName.Error(), "record name")
	assert.Contains(t, ErrDNSMissingRecordType.Error(), "record type")
	assert.Contains(t, ErrDNSMissingFQDN.Error(), "fqdn")
	assert.Contains(t, ErrDNSMissingIP.Error(), "ip address")
	assert.Contains(t, ErrDNSInvalidRecordType.Error(), "invalid record type")
}

// =============================================================================
// Test: Update Record - Error Paths
// =============================================================================

func TestHandleUpdateRecordErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when service unavailable", func(t *testing.T) {
		logger := newDNSTestLogger()
		handler := NewDNSHandler(logger, nil)

		updateReq := &DNSUpdateRecordRequest{
			ZoneName: "example.com",
			Type:     "A",
			Name:     "www.example.com",
			Value:    "192.168.1.2",
		}

		payload, err := EncodePayload(updateReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSUpdateRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createTestDNSHandler()

		req := &Request{
			Opcode:  OpDNSUpdateRecord,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error for missing zone name", func(t *testing.T) {
		handler, _ := createTestDNSHandler()

		updateReq := &DNSUpdateRecordRequest{
			Type:  "A",
			Name:  "www.example.com",
			Value: "192.168.1.2",
		}

		payload, err := EncodePayload(updateReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSUpdateRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing record type", func(t *testing.T) {
		handler, _ := createTestDNSHandler()

		updateReq := &DNSUpdateRecordRequest{
			ZoneName: "example.com",
			Name:     "www.example.com",
			Value:    "192.168.1.2",
		}

		payload, err := EncodePayload(updateReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSUpdateRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing record name", func(t *testing.T) {
		handler, _ := createTestDNSHandler()

		updateReq := &DNSUpdateRecordRequest{
			ZoneName: "example.com",
			Type:     "A",
			Value:    "192.168.1.2",
		}

		payload, err := EncodePayload(updateReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSUpdateRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for zone not found", func(t *testing.T) {
		handler, _ := createTestDNSHandler()

		updateReq := &DNSUpdateRecordRequest{
			ZoneName: "nonexistent.com",
			Type:     "A",
			Name:     "www.nonexistent.com",
			Value:    "192.168.1.2",
		}

		payload, err := EncodePayload(updateReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSUpdateRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})

	t.Run("returns error for record not found", func(t *testing.T) {
		handler, dnsService := createTestDNSHandler()
		createTestZone(dnsService, "example.com")

		updateReq := &DNSUpdateRecordRequest{
			ZoneName: "example.com",
			Type:     "A",
			Name:     "nonexistent.example.com",
			Value:    "192.168.1.2",
		}

		payload, err := EncodePayload(updateReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSUpdateRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: Delete Record - Error Paths
// =============================================================================

func TestHandleDeleteRecordErrors(t *testing.T) {
	ctx := context.Background()

	t.Run("returns error when service unavailable", func(t *testing.T) {
		logger := newDNSTestLogger()
		handler := NewDNSHandler(logger, nil)

		deleteReq := &DNSDeleteRecordRequest{
			ZoneName:   "example.com",
			RecordName: "www.example.com",
			RecordType: "A",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSDeleteRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusUnavailable, resp.Status)
	})

	t.Run("returns error for invalid payload", func(t *testing.T) {
		handler, _ := createTestDNSHandler()

		req := &Request{
			Opcode:  OpDNSDeleteRecord,
			Payload: []byte("invalid payload"),
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidRequest, resp.Status)
	})

	t.Run("returns error for missing zone name", func(t *testing.T) {
		handler, _ := createTestDNSHandler()

		deleteReq := &DNSDeleteRecordRequest{
			RecordName: "www.example.com",
			RecordType: "A",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSDeleteRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing record name", func(t *testing.T) {
		handler, _ := createTestDNSHandler()

		deleteReq := &DNSDeleteRecordRequest{
			ZoneName:   "example.com",
			RecordType: "A",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSDeleteRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for missing record type", func(t *testing.T) {
		handler, _ := createTestDNSHandler()

		deleteReq := &DNSDeleteRecordRequest{
			ZoneName:   "example.com",
			RecordName: "www.example.com",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSDeleteRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusInvalidArgument, resp.Status)
	})

	t.Run("returns error for zone not found", func(t *testing.T) {
		handler, _ := createTestDNSHandler()

		deleteReq := &DNSDeleteRecordRequest{
			ZoneName:   "nonexistent.com",
			RecordName: "www.nonexistent.com",
			RecordType: "A",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSDeleteRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})

	t.Run("returns error for record not found in zone", func(t *testing.T) {
		handler, dnsService := createTestDNSHandler()
		createTestZone(dnsService, "example.com")

		deleteReq := &DNSDeleteRecordRequest{
			ZoneName:   "example.com",
			RecordName: "nonexistent.example.com",
			RecordType: "A",
		}

		payload, err := EncodePayload(deleteReq)
		require.NoError(t, err)

		req := &Request{
			Opcode:  OpDNSDeleteRecord,
			Payload: payload,
		}

		resp := handler.HandleRequest(ctx, req)

		assert.Equal(t, StatusNotFound, resp.Status)
	})
}

// =============================================================================
// Test: collectRecords Coverage
// =============================================================================

func TestCollectRecordsFilters(t *testing.T) {
	handler, dnsService := createTestDNSHandler()
	zone := createTestZoneWithRecords(dnsService, "filter-test.com")

	t.Run("collects only AAAA records", func(t *testing.T) {
		records := handler.collectRecords(zone, "AAAA")
		for _, r := range records {
			assert.Equal(t, "AAAA", r.Type)
		}
	})

	t.Run("collects only CNAME records", func(t *testing.T) {
		records := handler.collectRecords(zone, "CNAME")
		for _, r := range records {
			assert.Equal(t, "CNAME", r.Type)
		}
	})

	t.Run("collects only MX records", func(t *testing.T) {
		records := handler.collectRecords(zone, "MX")
		for _, r := range records {
			assert.Equal(t, "MX", r.Type)
		}
	})

	t.Run("collects only NS records", func(t *testing.T) {
		records := handler.collectRecords(zone, "NS")
		for _, r := range records {
			assert.Equal(t, "NS", r.Type)
		}
	})

	t.Run("collects only TXT records", func(t *testing.T) {
		records := handler.collectRecords(zone, "TXT")
		for _, r := range records {
			assert.Equal(t, "TXT", r.Type)
		}
	})

	t.Run("collects only SRV records", func(t *testing.T) {
		records := handler.collectRecords(zone, "SRV")
		for _, r := range records {
			assert.Equal(t, "SRV", r.Type)
		}
	})

	t.Run("collects only CAA records", func(t *testing.T) {
		records := handler.collectRecords(zone, "CAA")
		for _, r := range records {
			assert.Equal(t, "CAA", r.Type)
		}
	})
}

// Helper function to create a zone with multiple record types
func createTestZoneWithRecords(dnsService *mockDNSService, name string) *entities.Zone {
	zone := &entities.Zone{
		Name:        name,
		TTL:         3600,
		Description: "Test zone with multiple records",
		RecordSet: entities.RecordSet{
			ARecords:     []*entities.ARecord{{Name: "www." + name, Value: "192.168.1.1", TTL: 3600}},
			AAAARecords:  []*entities.AAAARecord{{Name: "www." + name, Value: "2001:db8::1", TTL: 3600}},
			CNAMERecords: []*entities.CNAMERecord{{Name: "alias." + name, Value: "www." + name, TTL: 3600}},
			MXRecords:    []*entities.MXRecord{{Name: name, Value: "mail." + name, Priority: 10, TTL: 3600}},
			NSRecords:    []*entities.NSRecord{{Name: name, Value: "ns1." + name, TTL: 3600}},
			TXTRecords:   []*entities.TXTRecord{{Name: name, Value: "v=spf1 include:_spf.example.com ~all", TTL: 3600}},
			SRVRecords:   []*entities.SRVRecord{{Name: "_sip._tcp." + name, Target: "sipserver." + name, Priority: 10, Weight: 5, Port: 5060, TTL: 3600}},
			CAARecords:   []*entities.CAARecord{{Name: name, Flags: 0, Tag: "issue", Value: "letsencrypt.org", TTL: 3600}},
		},
	}
	dnsService.zones[name] = zone
	return zone
}
