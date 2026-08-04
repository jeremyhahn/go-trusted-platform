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

package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	miekgdns "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Mock DNS Service
// =============================================================================

type mockDNSService struct {
	zones                      map[string]*entities.Zone
	saveErr                    error
	deleteErr                  error
	zoneErr                    error
	listErr                    error
	signErr                    error
	registerErr                error
	resolveErr                 error
	resolveValues              []string
	dnssecEnabled              bool
	registerWithNetworkZoneErr error
}

func newMockDNSService() *mockDNSService {
	return &mockDNSService{
		zones: make(map[string]*entities.Zone),
	}
}

// mockTransferDNSService augments the mock with the optional ZoneTransferrer
// capability so the REST zone-export path can be exercised.
type mockTransferDNSService struct {
	*mockDNSService
	secondaries []string
	transferErr error
	transferRRs []miekgdns.RR
}

func (m *mockTransferDNSService) ZoneTransfer(ctx context.Context, zoneName string) ([]miekgdns.RR, error) {
	if m.transferErr != nil {
		return nil, m.transferErr
	}
	return m.transferRRs, nil
}

func (m *mockTransferDNSService) TransferSecondaries() []string {
	return m.secondaries
}

func (m *mockDNSService) Save(ctx context.Context, zone *entities.Zone) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.zones[zone.Name] = zone
	return nil
}

func (m *mockDNSService) SaveAndSign(ctx context.Context, zone *entities.Zone) error {
	return m.Save(ctx, zone)
}

func (m *mockDNSService) SignZone(zone *entities.Zone) error {
	if m.signErr != nil {
		return m.signErr
	}
	if !m.dnssecEnabled {
		return dns.ErrDNSSECNotEnabled
	}
	return nil
}

func (m *mockDNSService) Delete(ctx context.Context, zone *entities.Zone) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.zones, zone.Name)
	return nil
}

func (m *mockDNSService) Zone(ctx context.Context, zoneName string) (*entities.Zone, error) {
	if m.zoneErr != nil {
		return nil, m.zoneErr
	}
	zone, ok := m.zones[zoneName]
	if !ok {
		return nil, dns.ErrZoneNotFound
	}
	return zone, nil
}

func (m *mockDNSService) ListZones(ctx context.Context) ([]*entities.Zone, error) {
	if m.listErr != nil {
		return nil, m.listErr
	}
	zones := make([]*entities.Zone, 0, len(m.zones))
	for _, z := range m.zones {
		zones = append(zones, z)
	}
	return zones, nil
}

func (m *mockDNSService) Register(ctx context.Context, fqdn, ip string) (*entities.Zone, error) {
	if m.registerErr != nil {
		return nil, m.registerErr
	}
	return nil, nil
}

func (m *mockDNSService) AddTLSARecord(ctx context.Context, zoneName string, record *entities.TLSARecord) error {
	zone, ok := m.zones[zoneName]
	if !ok {
		return dns.ErrZoneNotFound
	}
	zone.AddTLSARecord(record)
	return nil
}

func (m *mockDNSService) InternalZone(ctx context.Context) (*entities.Zone, error) {
	return m.Zone(ctx, "internal.test.")
}

func (m *mockDNSService) PublicZone(ctx context.Context) (*entities.Zone, error) {
	return m.Zone(ctx, "public.test.")
}

func (m *mockDNSService) InternalDomain() string {
	return "internal.test."
}

func (m *mockDNSService) PublicDomain() string {
	return "public.test."
}

func (m *mockDNSService) DNSSECService() *dns.DNSSECService {
	return nil
}

func (m *mockDNSService) IsDNSSECEnabled() bool {
	return m.dnssecEnabled
}

func (m *mockDNSService) CreateZone(ctx context.Context, zoneName string) error {
	zone := &entities.Zone{Name: zoneName, TTL: 3600}
	return m.Save(ctx, zone)
}

func (m *mockDNSService) DeleteZone(ctx context.Context, zoneName string) error {
	if m.deleteErr != nil {
		return m.deleteErr
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
	return nil, nil
}

func (m *mockDNSService) ListRecords(ctx context.Context, zoneName string) ([]interface{}, error) {
	return nil, nil
}

func (m *mockDNSService) Resolve(ctx context.Context, name string, recordType string) ([]string, error) {
	if m.resolveErr != nil {
		return nil, m.resolveErr
	}
	if len(m.resolveValues) > 0 {
		return m.resolveValues, nil
	}
	return []string{"192.168.1.1"}, nil
}

func (m *mockDNSService) RegisterWithNetworkZone(ctx context.Context, host, networkZone, ip string) error {
	return m.registerWithNetworkZoneErr
}

func (m *mockDNSService) addTestZone(name string) *entities.Zone {
	zone := &entities.Zone{
		ID:          1,
		Name:        name,
		TTL:         3600,
		Description: "Test zone",
		Internal:    false,
		RecordSet: entities.RecordSet{
			SOARecord: entities.SOARecord{
				Name:       name,
				MName:      "ns1." + name,
				RName:      "hostmaster." + name,
				Serial:     1,
				Refresh:    86400,
				Retry:      7200,
				Expire:     86400,
				MinimumTTL: 3600,
				TTL:        3600,
			},
			ARecords: []*entities.ARecord{
				{Name: "@", Value: "192.168.1.1", TTL: 3600},
				{Name: "www", Value: "192.168.1.2", TTL: 3600},
			},
			NSRecords: []*entities.NSRecord{
				{Name: "ns1", Value: "ns1." + name, TTL: 3600},
			},
		},
	}
	m.zones[name] = zone
	return zone
}

// =============================================================================
// Test Helpers
// =============================================================================

func setupDNSTestHandler(svc *mockDNSService) (*DNSHandlers, *mux.Router) {
	logger := slog.Default()
	handlers := NewDNSHandlers(svc, logger)
	router := mux.NewRouter()
	handlers.RegisterRoutes(router)
	return handlers, router
}

func decodeDNSResponse(t *testing.T, body *bytes.Buffer, v interface{}) {
	t.Helper()
	err := json.NewDecoder(body).Decode(v)
	require.NoError(t, err)
}

// =============================================================================
// Error Type Tests
// =============================================================================

func TestDNSHandlerErrors(t *testing.T) {
	t.Run("ErrDNSServiceNotAvailable", func(t *testing.T) {
		err := ErrDNSServiceNotAvailable{}
		assert.Equal(t, "dns service not available", err.Error())
	})

	t.Run("ErrInvalidZoneName with empty name", func(t *testing.T) {
		err := ErrInvalidZoneName{}
		assert.Equal(t, "zone name is required", err.Error())
	})

	t.Run("ErrInvalidZoneName with name", func(t *testing.T) {
		err := ErrInvalidZoneName{Name: "bad-zone"}
		assert.Equal(t, "invalid zone name: bad-zone", err.Error())
	})

	t.Run("ErrInvalidRecordID with empty ID", func(t *testing.T) {
		err := ErrInvalidRecordID{}
		assert.Equal(t, "record ID is required", err.Error())
	})

	t.Run("ErrInvalidRecordID with ID", func(t *testing.T) {
		err := ErrInvalidRecordID{ID: "bad-id"}
		assert.Equal(t, "invalid record ID: bad-id", err.Error())
	})

	t.Run("ErrDNSOperationFailed", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := ErrDNSOperationFailed{Operation: "create", Cause: cause}
		assert.Equal(t, "dns operation create failed: underlying error", err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("ErrInvalidRecordType", func(t *testing.T) {
		err := ErrInvalidRecordType{Type: "INVALID"}
		assert.Equal(t, "invalid record type: INVALID", err.Error())
	})

	t.Run("ErrRecordNotFound", func(t *testing.T) {
		err := ErrRecordNotFound{Name: "www", Type: "A"}
		assert.Equal(t, "record not found: www A", err.Error())
	})
}

// =============================================================================
// Zone Operations Tests
// =============================================================================

func TestCreateZone(t *testing.T) {
	t.Run("successful zone creation", func(t *testing.T) {
		svc := newMockDNSService()
		_, router := setupDNSTestHandler(svc)

		req := CreateZoneRequest{
			Name:        "example.com.",
			TTL:         3600,
			Description: "Test zone",
			Internal:    false,
			SOA: &SOARecordRequest{
				MName:      "ns1.example.com.",
				RName:      "hostmaster.example.com.",
				Serial:     1,
				Refresh:    86400,
				Retry:      7200,
				Expire:     604800,
				MinimumTTL: 3600,
				TTL:        3600,
			},
			NSRecords: []NSRecordRequest{
				{Name: "ns1", Value: "ns1.example.com.", TTL: 3600},
			},
		}
		body, err := json.Marshal(req)
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/zones", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusCreated, w.Code)

		var resp ZoneResponse
		decodeDNSResponse(t, w.Body, &resp)
		assert.Equal(t, "example.com.", resp.Name)
		assert.Equal(t, uint32(3600), resp.TTL)
	})

	t.Run("missing zone name", func(t *testing.T) {
		svc := newMockDNSService()
		_, router := setupDNSTestHandler(svc)

		req := CreateZoneRequest{TTL: 3600}
		body, err := json.Marshal(req)
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/zones", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("invalid request body", func(t *testing.T) {
		svc := newMockDNSService()
		_, router := setupDNSTestHandler(svc)

		r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/zones", bytes.NewReader([]byte("invalid json")))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("service not available", func(t *testing.T) {
		logger := slog.Default()
		handlers := NewDNSHandlers(nil, logger)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := CreateZoneRequest{Name: "example.com."}
		body, err := json.Marshal(req)
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/zones", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})

	t.Run("save error", func(t *testing.T) {
		svc := newMockDNSService()
		svc.saveErr = errors.New("save failed")
		_, router := setupDNSTestHandler(svc)

		req := CreateZoneRequest{Name: "example.com."}
		body, err := json.Marshal(req)
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/zones", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestListZones(t *testing.T) {
	t.Run("successful list", func(t *testing.T) {
		svc := newMockDNSService()
		svc.addTestZone("example.com.")
		svc.addTestZone("test.com.")
		_, router := setupDNSTestHandler(svc)

		r := httptest.NewRequest(http.MethodGet, "/api/v1/dns/zones", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp ZoneListResponse
		decodeDNSResponse(t, w.Body, &resp)
		assert.Equal(t, 2, resp.Count)
	})

	t.Run("empty list", func(t *testing.T) {
		svc := newMockDNSService()
		_, router := setupDNSTestHandler(svc)

		r := httptest.NewRequest(http.MethodGet, "/api/v1/dns/zones", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp ZoneListResponse
		decodeDNSResponse(t, w.Body, &resp)
		assert.Equal(t, 0, resp.Count)
	})

	t.Run("list error", func(t *testing.T) {
		svc := newMockDNSService()
		svc.listErr = errors.New("list failed")
		_, router := setupDNSTestHandler(svc)

		r := httptest.NewRequest(http.MethodGet, "/api/v1/dns/zones", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("service not available", func(t *testing.T) {
		logger := slog.Default()
		handlers := NewDNSHandlers(nil, logger)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		r := httptest.NewRequest(http.MethodGet, "/api/v1/dns/zones", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestGetZone(t *testing.T) {
	t.Run("successful get", func(t *testing.T) {
		svc := newMockDNSService()
		svc.addTestZone("example.com.")
		_, router := setupDNSTestHandler(svc)

		r := httptest.NewRequest(http.MethodGet, "/api/v1/dns/zones/example.com.", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp ZoneResponse
		decodeDNSResponse(t, w.Body, &resp)
		assert.Equal(t, "example.com.", resp.Name)
	})

	t.Run("zone not found", func(t *testing.T) {
		svc := newMockDNSService()
		_, router := setupDNSTestHandler(svc)

		r := httptest.NewRequest(http.MethodGet, "/api/v1/dns/zones/nonexistent.com.", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("service not available", func(t *testing.T) {
		logger := slog.Default()
		handlers := NewDNSHandlers(nil, logger)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		r := httptest.NewRequest(http.MethodGet, "/api/v1/dns/zones/example.com.", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestDeleteZone(t *testing.T) {
	t.Run("successful delete", func(t *testing.T) {
		svc := newMockDNSService()
		svc.addTestZone("example.com.")
		_, router := setupDNSTestHandler(svc)

		r := httptest.NewRequest(http.MethodDelete, "/api/v1/dns/zones/example.com.", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp DNSActionResponse
		decodeDNSResponse(t, w.Body, &resp)
		assert.True(t, resp.Success)
		assert.Equal(t, "delete_zone", resp.Action)
	})

	t.Run("zone not found", func(t *testing.T) {
		svc := newMockDNSService()
		_, router := setupDNSTestHandler(svc)

		r := httptest.NewRequest(http.MethodDelete, "/api/v1/dns/zones/nonexistent.com.", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("service not available", func(t *testing.T) {
		logger := slog.Default()
		handlers := NewDNSHandlers(nil, logger)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		r := httptest.NewRequest(http.MethodDelete, "/api/v1/dns/zones/example.com.", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestSignZone(t *testing.T) {
	t.Run("successful sign", func(t *testing.T) {
		svc := newMockDNSService()
		svc.dnssecEnabled = true
		svc.addTestZone("example.com.")
		_, router := setupDNSTestHandler(svc)

		r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/zones/example.com./sign", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp SignZoneResponse
		decodeDNSResponse(t, w.Body, &resp)
		assert.True(t, resp.Signed)
		assert.Equal(t, "example.com.", resp.ZoneName)
	})

	t.Run("dnssec not enabled", func(t *testing.T) {
		svc := newMockDNSService()
		svc.dnssecEnabled = false
		svc.addTestZone("example.com.")
		_, router := setupDNSTestHandler(svc)

		r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/zones/example.com./sign", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("zone not found", func(t *testing.T) {
		svc := newMockDNSService()
		svc.dnssecEnabled = true
		_, router := setupDNSTestHandler(svc)

		r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/zones/nonexistent.com./sign", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("service not available", func(t *testing.T) {
		logger := slog.Default()
		handlers := NewDNSHandlers(nil, logger)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/zones/example.com./sign", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

// =============================================================================
// Record Operations Tests
// =============================================================================

func TestAddRecord(t *testing.T) {
	t.Run("successful A record", func(t *testing.T) {
		svc := newMockDNSService()
		svc.addTestZone("example.com.")
		_, router := setupDNSTestHandler(svc)

		req := AddRecordRequest{
			Type:  "A",
			Name:  "test",
			Value: "192.168.1.100",
			TTL:   3600,
		}
		body, err := json.Marshal(req)
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/zones/example.com./records", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("successful AAAA record", func(t *testing.T) {
		svc := newMockDNSService()
		svc.addTestZone("example.com.")
		_, router := setupDNSTestHandler(svc)

		req := AddRecordRequest{
			Type:  "AAAA",
			Name:  "ipv6",
			Value: "2001:db8::1",
			TTL:   3600,
		}
		body, err := json.Marshal(req)
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/zones/example.com./records", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("successful CNAME record", func(t *testing.T) {
		svc := newMockDNSService()
		svc.addTestZone("example.com.")
		_, router := setupDNSTestHandler(svc)

		req := AddRecordRequest{
			Type:  "CNAME",
			Name:  "alias",
			Value: "www.example.com.",
			TTL:   3600,
		}
		body, err := json.Marshal(req)
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/zones/example.com./records", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("successful MX record", func(t *testing.T) {
		svc := newMockDNSService()
		svc.addTestZone("example.com.")
		_, router := setupDNSTestHandler(svc)

		req := AddRecordRequest{
			Type:     "MX",
			Name:     "@",
			Value:    "mail.example.com.",
			Priority: 10,
			TTL:      3600,
		}
		body, err := json.Marshal(req)
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/zones/example.com./records", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("successful TXT record", func(t *testing.T) {
		svc := newMockDNSService()
		svc.addTestZone("example.com.")
		_, router := setupDNSTestHandler(svc)

		req := AddRecordRequest{
			Type:  "TXT",
			Name:  "@",
			Value: "v=spf1 include:example.com ~all",
			TTL:   3600,
		}
		body, err := json.Marshal(req)
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/zones/example.com./records", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("successful SRV record", func(t *testing.T) {
		svc := newMockDNSService()
		svc.addTestZone("example.com.")
		_, router := setupDNSTestHandler(svc)

		req := AddRecordRequest{
			Type:     "SRV",
			Name:     "_ldap._tcp",
			Target:   "ldap.example.com.",
			Port:     389,
			Priority: 10,
			Weight:   5,
			TTL:      3600,
		}
		body, err := json.Marshal(req)
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/zones/example.com./records", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("successful CAA record", func(t *testing.T) {
		svc := newMockDNSService()
		svc.addTestZone("example.com.")
		_, router := setupDNSTestHandler(svc)

		req := AddRecordRequest{
			Type:  "CAA",
			Name:  "@",
			Flags: 0,
			Tag:   "issue",
			Value: "letsencrypt.org",
			TTL:   3600,
		}
		body, err := json.Marshal(req)
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/zones/example.com./records", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("successful TLSA record", func(t *testing.T) {
		svc := newMockDNSService()
		svc.addTestZone("example.com.")
		_, router := setupDNSTestHandler(svc)

		req := AddRecordRequest{
			Type:         "TLSA",
			Name:         "_443._tcp.www",
			Usage:        3,
			Selector:     1,
			MatchingType: 1,
			Data:         "abc123def456",
			TTL:          3600,
		}
		body, err := json.Marshal(req)
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/zones/example.com./records", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusCreated, w.Code)
	})

	t.Run("invalid record type", func(t *testing.T) {
		svc := newMockDNSService()
		svc.addTestZone("example.com.")
		_, router := setupDNSTestHandler(svc)

		req := AddRecordRequest{
			Type:  "INVALID",
			Name:  "test",
			Value: "test",
		}
		body, err := json.Marshal(req)
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/zones/example.com./records", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("missing record type", func(t *testing.T) {
		svc := newMockDNSService()
		svc.addTestZone("example.com.")
		_, router := setupDNSTestHandler(svc)

		req := AddRecordRequest{Name: "test", Value: "192.168.1.1"}
		body, err := json.Marshal(req)
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/zones/example.com./records", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("missing record name", func(t *testing.T) {
		svc := newMockDNSService()
		svc.addTestZone("example.com.")
		_, router := setupDNSTestHandler(svc)

		req := AddRecordRequest{Type: "A", Value: "192.168.1.1"}
		body, err := json.Marshal(req)
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/zones/example.com./records", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("zone not found", func(t *testing.T) {
		svc := newMockDNSService()
		_, router := setupDNSTestHandler(svc)

		req := AddRecordRequest{Type: "A", Name: "test", Value: "192.168.1.1"}
		body, err := json.Marshal(req)
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/zones/nonexistent.com./records", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("service not available", func(t *testing.T) {
		logger := slog.Default()
		handlers := NewDNSHandlers(nil, logger)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := AddRecordRequest{Type: "A", Name: "test", Value: "192.168.1.1"}
		body, err := json.Marshal(req)
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/zones/example.com./records", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestListRecords(t *testing.T) {
	t.Run("successful list all records", func(t *testing.T) {
		svc := newMockDNSService()
		svc.addTestZone("example.com.")
		_, router := setupDNSTestHandler(svc)

		r := httptest.NewRequest(http.MethodGet, "/api/v1/dns/zones/example.com./records", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp RecordListResponse
		decodeDNSResponse(t, w.Body, &resp)
		assert.True(t, resp.Count > 0)
	})

	t.Run("list filtered by type", func(t *testing.T) {
		svc := newMockDNSService()
		svc.addTestZone("example.com.")
		_, router := setupDNSTestHandler(svc)

		r := httptest.NewRequest(http.MethodGet, "/api/v1/dns/zones/example.com./records?type=A", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp RecordListResponse
		decodeDNSResponse(t, w.Body, &resp)
		for _, rec := range resp.Records {
			assert.Equal(t, "A", rec.Type)
		}
	})

	t.Run("zone not found", func(t *testing.T) {
		svc := newMockDNSService()
		_, router := setupDNSTestHandler(svc)

		r := httptest.NewRequest(http.MethodGet, "/api/v1/dns/zones/nonexistent.com./records", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("service not available", func(t *testing.T) {
		logger := slog.Default()
		handlers := NewDNSHandlers(nil, logger)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		r := httptest.NewRequest(http.MethodGet, "/api/v1/dns/zones/example.com./records", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestUpdateRecord(t *testing.T) {
	t.Run("successful update A record", func(t *testing.T) {
		svc := newMockDNSService()
		svc.addTestZone("example.com.")
		_, router := setupDNSTestHandler(svc)

		req := UpdateRecordRequest{
			Type:  "A",
			Value: "192.168.1.200",
			TTL:   7200,
		}
		body, err := json.Marshal(req)
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodPut, "/api/v1/dns/zones/example.com./records/www", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Code)
	})

	t.Run("record not found", func(t *testing.T) {
		svc := newMockDNSService()
		svc.addTestZone("example.com.")
		_, router := setupDNSTestHandler(svc)

		req := UpdateRecordRequest{Type: "A", Value: "192.168.1.200"}
		body, err := json.Marshal(req)
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodPut, "/api/v1/dns/zones/example.com./records/nonexistent", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("missing record type", func(t *testing.T) {
		svc := newMockDNSService()
		svc.addTestZone("example.com.")
		_, router := setupDNSTestHandler(svc)

		req := UpdateRecordRequest{Value: "192.168.1.200"}
		body, err := json.Marshal(req)
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodPut, "/api/v1/dns/zones/example.com./records/www", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("zone not found", func(t *testing.T) {
		svc := newMockDNSService()
		_, router := setupDNSTestHandler(svc)

		req := UpdateRecordRequest{Type: "A", Value: "192.168.1.200"}
		body, err := json.Marshal(req)
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodPut, "/api/v1/dns/zones/nonexistent.com./records/www", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("service not available", func(t *testing.T) {
		logger := slog.Default()
		handlers := NewDNSHandlers(nil, logger)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := UpdateRecordRequest{Type: "A", Value: "192.168.1.200"}
		body, err := json.Marshal(req)
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodPut, "/api/v1/dns/zones/example.com./records/www", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestDeleteRecord(t *testing.T) {
	t.Run("successful delete A record", func(t *testing.T) {
		svc := newMockDNSService()
		svc.addTestZone("example.com.")
		_, router := setupDNSTestHandler(svc)

		r := httptest.NewRequest(http.MethodDelete, "/api/v1/dns/zones/example.com./records/www?type=A", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp DNSActionResponse
		decodeDNSResponse(t, w.Body, &resp)
		assert.True(t, resp.Success)
	})

	t.Run("missing record type parameter", func(t *testing.T) {
		svc := newMockDNSService()
		svc.addTestZone("example.com.")
		_, router := setupDNSTestHandler(svc)

		r := httptest.NewRequest(http.MethodDelete, "/api/v1/dns/zones/example.com./records/www", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("record not found", func(t *testing.T) {
		svc := newMockDNSService()
		svc.addTestZone("example.com.")
		_, router := setupDNSTestHandler(svc)

		r := httptest.NewRequest(http.MethodDelete, "/api/v1/dns/zones/example.com./records/nonexistent?type=A", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("zone not found", func(t *testing.T) {
		svc := newMockDNSService()
		_, router := setupDNSTestHandler(svc)

		r := httptest.NewRequest(http.MethodDelete, "/api/v1/dns/zones/nonexistent.com./records/www?type=A", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("service not available", func(t *testing.T) {
		logger := slog.Default()
		handlers := NewDNSHandlers(nil, logger)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		r := httptest.NewRequest(http.MethodDelete, "/api/v1/dns/zones/example.com./records/www?type=A", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

// =============================================================================
// Resolution and Registration Tests
// =============================================================================

func TestResolve(t *testing.T) {
	t.Run("successful resolve", func(t *testing.T) {
		svc := newMockDNSService()
		svc.resolveValues = []string{"192.168.1.1", "192.168.1.2"}
		_, router := setupDNSTestHandler(svc)

		req := ResolveRequest{
			FQDN: "www.example.com.",
			Type: "A",
		}
		body, err := json.Marshal(req)
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/resolve", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp ResolveResponse
		decodeDNSResponse(t, w.Body, &resp)
		assert.Equal(t, "www.example.com.", resp.FQDN)
		assert.Equal(t, "A", resp.Type)
		assert.Len(t, resp.Values, 2)
		assert.True(t, resp.Authoritative)
	})

	t.Run("resolve with default type", func(t *testing.T) {
		svc := newMockDNSService()
		_, router := setupDNSTestHandler(svc)

		req := ResolveRequest{FQDN: "www.example.com."}
		body, err := json.Marshal(req)
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/resolve", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusOK, w.Code)

		var resp ResolveResponse
		decodeDNSResponse(t, w.Body, &resp)
		assert.Equal(t, "A", resp.Type)
	})

	t.Run("missing fqdn", func(t *testing.T) {
		svc := newMockDNSService()
		_, router := setupDNSTestHandler(svc)

		req := ResolveRequest{Type: "A"}
		body, err := json.Marshal(req)
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/resolve", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("resolve error", func(t *testing.T) {
		svc := newMockDNSService()
		svc.resolveErr = errors.New("resolution failed")
		_, router := setupDNSTestHandler(svc)

		req := ResolveRequest{FQDN: "www.example.com.", Type: "A"}
		body, err := json.Marshal(req)
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/resolve", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})

	t.Run("service not available", func(t *testing.T) {
		logger := slog.Default()
		handlers := NewDNSHandlers(nil, logger)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := ResolveRequest{FQDN: "www.example.com.", Type: "A"}
		body, err := json.Marshal(req)
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/resolve", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestRegister(t *testing.T) {
	t.Run("successful register", func(t *testing.T) {
		svc := newMockDNSService()
		_, router := setupDNSTestHandler(svc)

		req := RegisterRequest{
			FQDN: "host.example.com.",
			IP:   "192.168.1.100",
		}
		body, err := json.Marshal(req)
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/register", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusCreated, w.Code)

		var resp RegisterResponse
		decodeDNSResponse(t, w.Body, &resp)
		assert.True(t, resp.Success)
	})

	t.Run("missing fqdn", func(t *testing.T) {
		svc := newMockDNSService()
		_, router := setupDNSTestHandler(svc)

		req := RegisterRequest{IP: "192.168.1.100"}
		body, err := json.Marshal(req)
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/register", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("missing ip", func(t *testing.T) {
		svc := newMockDNSService()
		_, router := setupDNSTestHandler(svc)

		req := RegisterRequest{FQDN: "host.example.com."}
		body, err := json.Marshal(req)
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/register", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("registration disabled", func(t *testing.T) {
		svc := newMockDNSService()
		svc.registerErr = dns.ErrRegistrationDisabled
		_, router := setupDNSTestHandler(svc)

		req := RegisterRequest{FQDN: "host.example.com.", IP: "192.168.1.100"}
		body, err := json.Marshal(req)
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/register", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusForbidden, w.Code)
	})

	t.Run("invalid ip", func(t *testing.T) {
		svc := newMockDNSService()
		svc.registerErr = dns.ErrInvalidIPAddress
		_, router := setupDNSTestHandler(svc)

		req := RegisterRequest{FQDN: "host.example.com.", IP: "invalid"}
		body, err := json.Marshal(req)
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/register", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("service not available", func(t *testing.T) {
		logger := slog.Default()
		handlers := NewDNSHandlers(nil, logger)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := RegisterRequest{FQDN: "host.example.com.", IP: "192.168.1.100"}
		body, err := json.Marshal(req)
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/register", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

func TestTransfer(t *testing.T) {
	t.Run("export not supported by service", func(t *testing.T) {
		svc := newMockDNSService()
		_, router := setupDNSTestHandler(svc)

		req := TransferRequest{ZoneName: "example.com."}
		body, err := json.Marshal(req)
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/transfer", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusNotImplemented, w.Code)
	})

	t.Run("missing zone_name", func(t *testing.T) {
		svc := newMockDNSService()
		_, router := setupDNSTestHandler(svc)

		req := TransferRequest{Server: "ns1.example.com"}
		body, err := json.Marshal(req)
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/transfer", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("export success", func(t *testing.T) {
		soa := &miekgdns.SOA{
			Hdr:  miekgdns.RR_Header{Name: "example.com.", Rrtype: miekgdns.TypeSOA, Class: miekgdns.ClassINET, Ttl: 3600},
			Ns:   "ns1.example.com.",
			Mbox: "hostmaster.example.com.",
		}
		a := &miekgdns.A{
			Hdr: miekgdns.RR_Header{Name: "www.example.com.", Rrtype: miekgdns.TypeA, Class: miekgdns.ClassINET, Ttl: 3600},
			A:   []byte{192, 0, 2, 1},
		}
		svc := &mockTransferDNSService{
			mockDNSService: newMockDNSService(),
			secondaries:    []string{"secondary1."},
			transferRRs:    []miekgdns.RR{soa, a, soa},
		}
		handlers := NewDNSHandlers(svc, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := TransferRequest{ZoneName: "example.com."}
		body, err := json.Marshal(req)
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/transfer", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		require.Equal(t, http.StatusOK, w.Code)
		var resp ZoneTransferResponse
		require.NoError(t, json.Unmarshal(w.Body.Bytes(), &resp))
		assert.Equal(t, "example.com.", resp.ZoneName)
		assert.Equal(t, "primary", resp.Model)
		assert.Equal(t, 3, resp.RecordCount)
		assert.Len(t, resp.Records, 3)
		assert.Equal(t, []string{"secondary1."}, resp.Secondaries)
	})

	t.Run("export zone error", func(t *testing.T) {
		svc := &mockTransferDNSService{
			mockDNSService: newMockDNSService(),
			transferErr:    dns.ErrZoneNotFound,
		}
		handlers := NewDNSHandlers(svc, slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := TransferRequest{ZoneName: "missing.example.com."}
		body, err := json.Marshal(req)
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/transfer", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("service not available", func(t *testing.T) {
		logger := slog.Default()
		handlers := NewDNSHandlers(nil, logger)
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := TransferRequest{ZoneName: "example.com."}
		body, err := json.Marshal(req)
		require.NoError(t, err)

		r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/transfer", bytes.NewReader(body))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, r)

		assert.Equal(t, http.StatusServiceUnavailable, w.Code)
	})
}

// =============================================================================
// Helper Method Tests
// =============================================================================

func TestBuildZoneFromRequest(t *testing.T) {
	logger := slog.Default()
	handlers := NewDNSHandlers(newMockDNSService(), logger)

	t.Run("full zone request", func(t *testing.T) {
		req := &CreateZoneRequest{
			Name:        "example.com.",
			TTL:         7200,
			Description: "Test zone",
			Internal:    true,
			SOA: &SOARecordRequest{
				MName:      "ns1.example.com.",
				RName:      "admin.example.com.",
				Serial:     100,
				Refresh:    86400,
				Retry:      3600,
				Expire:     604800,
				MinimumTTL: 1800,
				TTL:        3600,
			},
			NSRecords: []NSRecordRequest{
				{Name: "ns1", Value: "ns1.example.com.", TTL: 3600},
				{Name: "ns2", Value: "ns2.example.com.", TTL: 3600},
			},
		}

		zone := handlers.buildZoneFromRequest(req)

		assert.Equal(t, "example.com.", zone.Name)
		assert.Equal(t, uint32(7200), zone.TTL)
		assert.Equal(t, "Test zone", zone.Description)
		assert.True(t, zone.Internal)
		assert.Equal(t, "ns1.example.com.", zone.RecordSet.SOARecord.MName)
		assert.Len(t, zone.RecordSet.NSRecords, 2)
	})

	t.Run("minimal zone request with defaults", func(t *testing.T) {
		req := &CreateZoneRequest{
			Name: "minimal.com.",
		}

		zone := handlers.buildZoneFromRequest(req)

		assert.Equal(t, "minimal.com.", zone.Name)
		assert.Equal(t, uint32(3600), zone.TTL)
	})

	t.Run("SOA defaults applied", func(t *testing.T) {
		req := &CreateZoneRequest{
			Name: "defaults.com.",
			SOA: &SOARecordRequest{
				MName: "ns1.defaults.com.",
				RName: "admin.defaults.com.",
			},
		}

		zone := handlers.buildZoneFromRequest(req)

		assert.Equal(t, uint32(86400), zone.RecordSet.SOARecord.Refresh)
		assert.Equal(t, uint32(7200), zone.RecordSet.SOARecord.Retry)
		assert.Equal(t, uint32(86400), zone.RecordSet.SOARecord.Expire)
		assert.Equal(t, uint32(3600), zone.RecordSet.SOARecord.MinimumTTL)
	})
}

func TestCollectRecords(t *testing.T) {
	logger := slog.Default()
	handlers := NewDNSHandlers(newMockDNSService(), logger)

	zone := &entities.Zone{
		Name: "test.com.",
		TTL:  3600,
		RecordSet: entities.RecordSet{
			ARecords:      []*entities.ARecord{{Name: "www", Value: "1.2.3.4", TTL: 3600}},
			AAAARecords:   []*entities.AAAARecord{{Name: "www", Value: "2001:db8::1", TTL: 3600}},
			CNAMERecords:  []*entities.CNAMERecord{{Name: "alias", Value: "www.test.com.", TTL: 3600}},
			MXRecords:     []*entities.MXRecord{{Name: "@", Value: "mail.test.com.", Priority: 10, TTL: 3600}},
			NSRecords:     []*entities.NSRecord{{Name: "ns1", Value: "ns1.test.com.", TTL: 3600}},
			TXTRecords:    []*entities.TXTRecord{{Name: "@", Value: "v=spf1", TTL: 3600}},
			SRVRecords:    []*entities.SRVRecord{{Name: "_ldap._tcp", Target: "ldap.test.com.", Port: 389, Priority: 10, Weight: 5, TTL: 3600}},
			CAARecords:    []*entities.CAARecord{{Name: "@", Flags: 0, Tag: "issue", Value: "letsencrypt.org", TTL: 3600}},
			TLSARecords:   []*entities.TLSARecord{{Name: "_443._tcp.www", Usage: 3, Selector: 1, MatchingType: 1, Data: "abc", TTL: 3600}},
			DNSKEYRecords: []*entities.DNSKEYRecord{{Name: "@", Flags: 257, Protocol: 3, Algorithm: 13, Key: "key", TTL: 3600}},
			DSRecords:     []*entities.DSRecord{{Name: "@", KeyTag: 12345, Algorithm: 13, DigestType: 2, Digest: "digest", TTL: 3600}},
		},
	}

	t.Run("collect all records", func(t *testing.T) {
		records := handlers.collectRecords(zone, "")
		assert.Equal(t, 11, len(records))
	})

	t.Run("filter by A type", func(t *testing.T) {
		records := handlers.collectRecords(zone, "A")
		assert.Equal(t, 1, len(records))
		assert.Equal(t, "A", records[0].Type)
	})

	t.Run("filter by MX type", func(t *testing.T) {
		records := handlers.collectRecords(zone, "MX")
		assert.Equal(t, 1, len(records))
		assert.Equal(t, "MX", records[0].Type)
	})

	t.Run("filter by TXT type", func(t *testing.T) {
		records := handlers.collectRecords(zone, "TXT")
		assert.Equal(t, 1, len(records))
		assert.Equal(t, "TXT", records[0].Type)
	})
}

func TestZoneToResponse(t *testing.T) {
	logger := slog.Default()
	handlers := NewDNSHandlers(newMockDNSService(), logger)

	zone := &entities.Zone{
		ID:          123,
		Name:        "test.com.",
		TTL:         3600,
		Description: "Test description",
		Internal:    true,
		RecordSet: entities.RecordSet{
			SOARecord: entities.SOARecord{
				Name:       "test.com.",
				MName:      "ns1.test.com.",
				RName:      "admin.test.com.",
				Serial:     1,
				Refresh:    86400,
				Retry:      7200,
				Expire:     604800,
				MinimumTTL: 3600,
				TTL:        3600,
			},
			ARecords: []*entities.ARecord{
				{Name: "www", Value: "1.2.3.4", TTL: 3600},
			},
		},
	}

	resp := handlers.zoneToResponse(zone)

	assert.Equal(t, uint64(123), resp.ID)
	assert.Equal(t, "test.com.", resp.Name)
	assert.Equal(t, uint32(3600), resp.TTL)
	assert.Equal(t, "Test description", resp.Description)
	assert.True(t, resp.Internal)
	assert.NotNil(t, resp.Records)
	assert.NotNil(t, resp.Records.SOA)
	assert.Len(t, resp.Records.A, 1)
}

// =============================================================================
// Update Record Tests for Different Types
// =============================================================================

func TestUpdateRecordTypes(t *testing.T) {
	testCases := []struct {
		name       string
		recordType string
		setupZone  func(zone *entities.Zone)
		recordID   string
	}{
		{
			name:       "AAAA record",
			recordType: "AAAA",
			setupZone: func(zone *entities.Zone) {
				zone.AddAAAARecord(&entities.AAAARecord{Name: "ipv6", Value: "2001:db8::1", TTL: 3600})
			},
			recordID: "ipv6",
		},
		{
			name:       "CNAME record",
			recordType: "CNAME",
			setupZone: func(zone *entities.Zone) {
				zone.AddCNAMERecord(&entities.CNAMERecord{Name: "alias", Value: "www.example.com.", TTL: 3600})
			},
			recordID: "alias",
		},
		{
			name:       "MX record",
			recordType: "MX",
			setupZone: func(zone *entities.Zone) {
				zone.AddMXRecord(&entities.MXRecord{Name: "mail", Value: "mail.example.com.", Priority: 10, TTL: 3600})
			},
			recordID: "mail",
		},
		{
			name:       "NS record",
			recordType: "NS",
			setupZone: func(zone *entities.Zone) {
				zone.AddNSRecord(&entities.NSRecord{Name: "ns2", Value: "ns2.example.com.", TTL: 3600})
			},
			recordID: "ns2",
		},
		{
			name:       "TXT record",
			recordType: "TXT",
			setupZone: func(zone *entities.Zone) {
				zone.AddTXTRecord(&entities.TXTRecord{Name: "spf", Value: "v=spf1", TTL: 3600})
			},
			recordID: "spf",
		},
		{
			name:       "SRV record",
			recordType: "SRV",
			setupZone: func(zone *entities.Zone) {
				zone.AddSRVRecord(&entities.SRVRecord{Name: "_sip._tcp", Target: "sip.example.com.", Port: 5060, Priority: 10, Weight: 5, TTL: 3600})
			},
			recordID: "_sip._tcp",
		},
		{
			name:       "CAA record",
			recordType: "CAA",
			setupZone: func(zone *entities.Zone) {
				zone.AddCAARecord(&entities.CAARecord{Name: "caa", Flags: 0, Tag: "issue", Value: "ca.example.com", TTL: 3600})
			},
			recordID: "caa",
		},
		{
			name:       "TLSA record",
			recordType: "TLSA",
			setupZone: func(zone *entities.Zone) {
				zone.AddTLSARecord(&entities.TLSARecord{Name: "_443._tcp", Usage: 3, Selector: 1, MatchingType: 1, Data: "abc", TTL: 3600})
			},
			recordID: "_443._tcp",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			svc := newMockDNSService()
			zone := svc.addTestZone("example.com.")
			tc.setupZone(zone)
			_, router := setupDNSTestHandler(svc)

			req := UpdateRecordRequest{
				Type: tc.recordType,
				TTL:  7200,
			}
			body, err := json.Marshal(req)
			require.NoError(t, err)

			r := httptest.NewRequest(http.MethodPut, "/api/v1/dns/zones/example.com./records/"+tc.recordID, bytes.NewReader(body))
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)

			assert.Equal(t, http.StatusOK, w.Code)
		})
	}
}

// =============================================================================
// Delete Record Tests for Different Types
// =============================================================================

func TestDeleteRecordTypes(t *testing.T) {
	testCases := []struct {
		name       string
		recordType string
		setupZone  func(zone *entities.Zone)
		recordID   string
	}{
		{
			name:       "AAAA record",
			recordType: "AAAA",
			setupZone: func(zone *entities.Zone) {
				zone.AddAAAARecord(&entities.AAAARecord{Name: "ipv6", Value: "2001:db8::1", TTL: 3600})
			},
			recordID: "ipv6",
		},
		{
			name:       "CNAME record",
			recordType: "CNAME",
			setupZone: func(zone *entities.Zone) {
				zone.AddCNAMERecord(&entities.CNAMERecord{Name: "alias", Value: "www.example.com.", TTL: 3600})
			},
			recordID: "alias",
		},
		{
			name:       "MX record",
			recordType: "MX",
			setupZone: func(zone *entities.Zone) {
				zone.AddMXRecord(&entities.MXRecord{Name: "mail", Value: "mail.example.com.", Priority: 10, TTL: 3600})
			},
			recordID: "mail",
		},
		{
			name:       "NS record",
			recordType: "NS",
			setupZone: func(zone *entities.Zone) {
				zone.AddNSRecord(&entities.NSRecord{Name: "ns2", Value: "ns2.example.com.", TTL: 3600})
			},
			recordID: "ns2",
		},
		{
			name:       "TXT record",
			recordType: "TXT",
			setupZone: func(zone *entities.Zone) {
				zone.AddTXTRecord(&entities.TXTRecord{Name: "spf", Value: "v=spf1", TTL: 3600})
			},
			recordID: "spf",
		},
		{
			name:       "SRV record",
			recordType: "SRV",
			setupZone: func(zone *entities.Zone) {
				zone.AddSRVRecord(&entities.SRVRecord{Name: "_sip._tcp", Target: "sip.example.com.", Port: 5060, Priority: 10, Weight: 5, TTL: 3600})
			},
			recordID: "_sip._tcp",
		},
		{
			name:       "CAA record",
			recordType: "CAA",
			setupZone: func(zone *entities.Zone) {
				zone.AddCAARecord(&entities.CAARecord{Name: "caa", Flags: 0, Tag: "issue", Value: "ca.example.com", TTL: 3600})
			},
			recordID: "caa",
		},
		{
			name:       "TLSA record",
			recordType: "TLSA",
			setupZone: func(zone *entities.Zone) {
				zone.AddTLSARecord(&entities.TLSARecord{Name: "_443._tcp", Usage: 3, Selector: 1, MatchingType: 1, Data: "abc", TTL: 3600})
			},
			recordID: "_443._tcp",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			svc := newMockDNSService()
			zone := svc.addTestZone("example.com.")
			tc.setupZone(zone)
			_, router := setupDNSTestHandler(svc)

			r := httptest.NewRequest(http.MethodDelete, "/api/v1/dns/zones/example.com./records/"+tc.recordID+"?type="+tc.recordType, nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)

			assert.Equal(t, http.StatusOK, w.Code)
		})
	}
}

// =============================================================================
// Error Mapping Tests
// =============================================================================

func TestHandleDNSError(t *testing.T) {
	logger := slog.Default()
	handlers := NewDNSHandlers(newMockDNSService(), logger)

	testCases := []struct {
		name           string
		err            error
		expectedStatus int
	}{
		{"zone not found", dns.ErrZoneNotFound, http.StatusNotFound},
		{"zone already exists", dns.ErrZoneAlreadyExists, http.StatusConflict},
		{"dnssec not enabled", dns.ErrDNSSECNotEnabled, http.StatusBadRequest},
		{"registration disabled", dns.ErrRegistrationDisabled, http.StatusForbidden},
		{"external registration disabled", dns.ErrExternalRegistrationDisabled, http.StatusForbidden},
		{"internal registration disabled", dns.ErrInternalRegistrationDisabled, http.StatusForbidden},
		{"invalid ip", dns.ErrInvalidIPAddress, http.StatusBadRequest},
		{"invalid private ip", dns.ErrInvalidPrivateIP, http.StatusBadRequest},
		{"invalid public ip", dns.ErrInvalidPublicIP, http.StatusBadRequest},
		{"invalid private tld", dns.ErrInvalidPrivateTLD, http.StatusBadRequest},
		{"invalid public tld", dns.ErrInvalidPublicTLD, http.StatusBadRequest},
		{"parsing domain", dns.ErrParsingDomainName, http.StatusBadRequest},
		{"context canceled", context.Canceled, http.StatusRequestTimeout},
		{"deadline exceeded", context.DeadlineExceeded, http.StatusGatewayTimeout},
		{"unknown error", errors.New("unknown"), http.StatusInternalServerError},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			handlers.handleDNSError(w, "test", tc.err)
			assert.Equal(t, tc.expectedStatus, w.Code)
		})
	}
}

// =============================================================================
// Invalid Record Type Tests
// =============================================================================

func TestInvalidRecordTypeOperations(t *testing.T) {
	logger := slog.Default()
	handlers := NewDNSHandlers(newMockDNSService(), logger)

	zone := &entities.Zone{Name: "test.com.", TTL: 3600}

	t.Run("add invalid record type", func(t *testing.T) {
		req := &AddRecordRequest{Type: "INVALID", Name: "test", Value: "test"}
		err := handlers.addRecordToZone(zone, req)
		assert.Error(t, err)
		var invalidTypeErr ErrInvalidRecordType
		assert.True(t, errors.As(err, &invalidTypeErr))
	})

	t.Run("update invalid record type", func(t *testing.T) {
		req := &UpdateRecordRequest{Type: "INVALID", Value: "test"}
		err := handlers.updateRecordInZone(zone, "test", req)
		assert.Error(t, err)
		var invalidTypeErr ErrInvalidRecordType
		assert.True(t, errors.As(err, &invalidTypeErr))
	})

	t.Run("delete invalid record type", func(t *testing.T) {
		err := handlers.deleteRecordFromZone(zone, "test", "INVALID")
		assert.Error(t, err)
		var invalidTypeErr ErrInvalidRecordType
		assert.True(t, errors.As(err, &invalidTypeErr))
	})
}

// =============================================================================
// NewDNSHandlers Tests
// =============================================================================

func TestNewDNSHandlers(t *testing.T) {
	t.Run("with logger", func(t *testing.T) {
		logger := slog.Default()
		svc := newMockDNSService()
		handlers := NewDNSHandlers(svc, logger)
		assert.NotNil(t, handlers)
		assert.Equal(t, svc, handlers.dnsService)
		assert.Equal(t, logger, handlers.logger)
	})

	t.Run("without logger uses default", func(t *testing.T) {
		svc := newMockDNSService()
		handlers := NewDNSHandlers(svc, nil)
		assert.NotNil(t, handlers)
		assert.NotNil(t, handlers.logger)
	})
}

// =============================================================================
// Response Type Tests
// =============================================================================

func TestResponseTypes(t *testing.T) {
	t.Run("ZoneResponse timestamp", func(t *testing.T) {
		resp := ZoneListResponse{
			Zones:     []ZoneResponse{},
			Count:     0,
			Timestamp: time.Now().UTC(),
		}
		assert.NotZero(t, resp.Timestamp)
	})

	t.Run("RecordListResponse timestamp", func(t *testing.T) {
		resp := RecordListResponse{
			Records:   []RecordResponse{},
			Count:     0,
			Timestamp: time.Now().UTC(),
		}
		assert.NotZero(t, resp.Timestamp)
	})

	t.Run("ResolveResponse", func(t *testing.T) {
		resp := ResolveResponse{
			FQDN:          "www.example.com.",
			Type:          "A",
			Values:        []string{"192.168.1.1"},
			Authoritative: true,
			Timestamp:     time.Now().UTC(),
		}
		assert.Equal(t, "www.example.com.", resp.FQDN)
		assert.Equal(t, "A", resp.Type)
		assert.Len(t, resp.Values, 1)
		assert.True(t, resp.Authoritative)
	})

	t.Run("RegisterResponse", func(t *testing.T) {
		resp := RegisterResponse{
			Success:   true,
			Message:   "registered",
			Timestamp: time.Now().UTC(),
		}
		assert.True(t, resp.Success)
		assert.Equal(t, "registered", resp.Message)
	})

	t.Run("TransferResponse", func(t *testing.T) {
		resp := TransferResponse{
			Success:   false,
			Message:   "not implemented",
			Timestamp: time.Now().UTC(),
		}
		assert.False(t, resp.Success)
	})

	t.Run("SignZoneResponse", func(t *testing.T) {
		resp := SignZoneResponse{
			ZoneName:  "example.com.",
			Signed:    true,
			Message:   "signed",
			Timestamp: time.Now().UTC(),
		}
		assert.Equal(t, "example.com.", resp.ZoneName)
		assert.True(t, resp.Signed)
	})
}

// =============================================================================
// Invalid Request Body Tests
// =============================================================================

func TestInvalidRequestBodies(t *testing.T) {
	svc := newMockDNSService()
	_, router := setupDNSTestHandler(svc)

	endpoints := []struct {
		method string
		path   string
	}{
		{http.MethodPost, "/api/v1/dns/zones"},
		{http.MethodPost, "/api/v1/dns/zones/example.com./records"},
		{http.MethodPut, "/api/v1/dns/zones/example.com./records/www"},
		{http.MethodPost, "/api/v1/dns/resolve"},
		{http.MethodPost, "/api/v1/dns/register"},
		{http.MethodPost, "/api/v1/dns/transfer"},
	}

	for _, ep := range endpoints {
		t.Run(ep.method+" "+ep.path, func(t *testing.T) {
			r := httptest.NewRequest(ep.method, ep.path, bytes.NewReader([]byte("invalid json")))
			w := httptest.NewRecorder()
			router.ServeHTTP(w, r)
			assert.Equal(t, http.StatusBadRequest, w.Code)
		})
	}
}

// =============================================================================
// Empty Zone Name Tests
// =============================================================================

func TestEmptyZoneNameInPath(t *testing.T) {
	t.Run("get zone with empty name in vars", func(t *testing.T) {
		svc := newMockDNSService()
		handlers, _ := setupDNSTestHandler(svc)

		// Create request without using router (to bypass mux vars)
		r := httptest.NewRequest(http.MethodGet, "/api/v1/dns/zones/", nil)
		w := httptest.NewRecorder()

		// Call handler directly with empty vars
		handlers.handleGetZone(w, r)

		assert.Equal(t, http.StatusBadRequest, w.Code)
	})
}

// =============================================================================
// NS Record Add Test
// =============================================================================

func TestAddNSRecord(t *testing.T) {
	svc := newMockDNSService()
	svc.addTestZone("example.com.")
	_, router := setupDNSTestHandler(svc)

	req := AddRecordRequest{
		Type:  "NS",
		Name:  "ns3",
		Value: "ns3.example.com.",
		TTL:   3600,
	}
	body, err := json.Marshal(req)
	require.NoError(t, err)

	r := httptest.NewRequest(http.MethodPost, "/api/v1/dns/zones/example.com./records", bytes.NewReader(body))
	w := httptest.NewRecorder()
	router.ServeHTTP(w, r)

	assert.Equal(t, http.StatusCreated, w.Code)
}
