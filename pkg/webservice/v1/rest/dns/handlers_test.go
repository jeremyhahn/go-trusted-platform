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

package dns

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// mockDNSService implements dns.DNSService for testing
type mockDNSService struct {
	zones          map[string]*entities.Zone
	dnssecEnabled  bool
	saveErr        error
	deleteErr      error
	signErr        error
	registerErr    error
	listZonesErr   error
	registerResult *entities.Zone
}

func newMockDNSService() *mockDNSService {
	return &mockDNSService{
		zones:         make(map[string]*entities.Zone),
		dnssecEnabled: false,
	}
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
	// Add mock DNSKEY record
	zone.AddDNSKEYRecord(&entities.DNSKEYRecord{
		Name:      zone.Name,
		Flags:     257,
		Protocol:  3,
		Algorithm: 13,
		Key:       "mock-key",
		TTL:       3600,
	})
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
	zone, ok := m.zones[zoneName]
	if !ok {
		return nil, dns.ErrZoneNotFound
	}
	return zone, nil
}

func (m *mockDNSService) ListZones(ctx context.Context) ([]*entities.Zone, error) {
	if m.listZonesErr != nil {
		return nil, m.listZonesErr
	}
	var zones []*entities.Zone
	for _, z := range m.zones {
		zones = append(zones, z)
	}
	return zones, nil
}

func (m *mockDNSService) Register(ctx context.Context, fqdn, ip string) (*entities.Zone, error) {
	if m.registerErr != nil {
		return nil, m.registerErr
	}
	return m.registerResult, nil
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
	return m.Zone(ctx, "internal.")
}

func (m *mockDNSService) PublicZone(ctx context.Context) (*entities.Zone, error) {
	return m.Zone(ctx, "public.")
}

func (m *mockDNSService) InternalDomain() string {
	return "internal."
}

func (m *mockDNSService) PublicDomain() string {
	return "public."
}

func (m *mockDNSService) DNSSECService() *dns.DNSSECService {
	return nil
}

func (m *mockDNSService) IsDNSSECEnabled() bool {
	return m.dnssecEnabled
}

func (m *mockDNSService) CreateZone(ctx context.Context, zoneName string) error {
	return m.Save(ctx, &entities.Zone{Name: zoneName, TTL: 3600})
}

func (m *mockDNSService) DeleteZone(ctx context.Context, zoneName string) error {
	zone, err := m.Zone(ctx, zoneName)
	if err != nil {
		return err
	}
	return m.Delete(ctx, zone)
}

func (m *mockDNSService) AddRecord(ctx context.Context, name, recordType, value string, ttl int) error {
	return nil
}

func (m *mockDNSService) DeleteRecord(ctx context.Context, name, recordType string) error {
	return nil
}

func (m *mockDNSService) GetRecord(ctx context.Context, name, recordType string) (interface{}, error) {
	return nil, nil
}

func (m *mockDNSService) ListRecords(ctx context.Context, zone string) ([]interface{}, error) {
	return nil, nil
}

func (m *mockDNSService) Resolve(ctx context.Context, name, recordType string) ([]string, error) {
	return nil, nil
}

func (m *mockDNSService) RegisterWithNetworkZone(ctx context.Context, host, networkZone, ip string) error {
	return nil
}

// mockHttpWriter implements response.HttpWriter for testing
type mockHttpWriter struct {
	lastStatus  int
	lastPayload interface{}
	lastError   error
}

func (m *mockHttpWriter) Write(w http.ResponseWriter, r *http.Request, status int, resp interface{}) {
	m.lastStatus = status
	m.lastPayload = resp
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}

func (m *mockHttpWriter) WriteYaml(w http.ResponseWriter, status int, resp interface{}) {
	m.lastStatus = status
	m.lastPayload = resp
	w.WriteHeader(status)
}

func (m *mockHttpWriter) WriteJson(w http.ResponseWriter, status int, resp interface{}) {
	m.lastStatus = status
	m.lastPayload = resp
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}

func (m *mockHttpWriter) Success200(w http.ResponseWriter, r *http.Request, payload interface{}) {
	m.lastStatus = http.StatusOK
	m.lastPayload = payload
	w.WriteHeader(http.StatusOK)
	resp := response.WebServiceResponse{Code: 200, Success: true, Payload: payload}
	json.NewEncoder(w).Encode(resp)
}

func (m *mockHttpWriter) Success201(w http.ResponseWriter, r *http.Request, payload interface{}) {
	m.lastStatus = http.StatusCreated
	m.lastPayload = payload
	w.WriteHeader(http.StatusCreated)
	resp := response.WebServiceResponse{Code: 201, Success: true, Payload: payload}
	json.NewEncoder(w).Encode(resp)
}

func (m *mockHttpWriter) Success404(w http.ResponseWriter, r *http.Request, payload interface{}, err error) {
	m.lastStatus = http.StatusNotFound
	m.lastPayload = payload
	m.lastError = err
	w.WriteHeader(http.StatusNotFound)
}

func (m *mockHttpWriter) Error200(w http.ResponseWriter, r *http.Request, err error) {
	m.lastStatus = http.StatusOK
	m.lastError = err
	w.WriteHeader(http.StatusOK)
}

func (m *mockHttpWriter) Error400(w http.ResponseWriter, r *http.Request, err error) {
	m.lastStatus = http.StatusBadRequest
	m.lastError = err
	w.WriteHeader(http.StatusBadRequest)
	resp := response.WebServiceResponse{Code: 400, Success: false, Error: err.Error()}
	json.NewEncoder(w).Encode(resp)
}

func (m *mockHttpWriter) Error401(w http.ResponseWriter, r *http.Request, err error) {
	m.lastStatus = http.StatusUnauthorized
	m.lastError = err
	w.WriteHeader(http.StatusUnauthorized)
}

func (m *mockHttpWriter) Error403(w http.ResponseWriter, r *http.Request, err error, payload interface{}) {
	m.lastStatus = http.StatusForbidden
	m.lastError = err
	m.lastPayload = payload
	w.WriteHeader(http.StatusForbidden)
}

func (m *mockHttpWriter) Error404(w http.ResponseWriter, r *http.Request, err error) {
	m.lastStatus = http.StatusNotFound
	m.lastError = err
	w.WriteHeader(http.StatusNotFound)
	resp := response.WebServiceResponse{Code: 404, Success: false, Error: err.Error()}
	json.NewEncoder(w).Encode(resp)
}

func (m *mockHttpWriter) Error500(w http.ResponseWriter, r *http.Request, err error) {
	m.lastStatus = http.StatusInternalServerError
	m.lastError = err
	w.WriteHeader(http.StatusInternalServerError)
	resp := response.WebServiceResponse{Code: 500, Success: false, Error: err.Error()}
	json.NewEncoder(w).Encode(resp)
}

// Helper functions

func newTestLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelDebug, os.Stdout)
}

func newTestHandlers(service *mockDNSService) (*DNSHandlers, *mockHttpWriter) {
	logger := newTestLogger()
	writer := &mockHttpWriter{}
	handlers := NewDNSHandlers(logger, service, writer)
	return handlers, writer
}

func createRequest(method, path string, body interface{}) *http.Request {
	var reqBody bytes.Buffer
	if body != nil {
		json.NewEncoder(&reqBody).Encode(body)
	}

	req := httptest.NewRequest(method, path, &reqBody)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	return req
}

func createRequestWithVars(method, path string, body interface{}, vars map[string]string) *http.Request {
	req := createRequest(method, path, body)
	if vars != nil {
		req = mux.SetURLVars(req, vars)
	}
	return req
}

func createTestZone(name string) *entities.Zone {
	return &entities.Zone{
		ID:          1,
		Name:        name,
		TTL:         3600,
		Description: "Test zone",
		Internal:    false,
		RecordSet: entities.RecordSet{
			SOARecord: entities.SOARecord{
				Name:       name,
				MName:      "ns1." + name,
				RName:      "admin." + name,
				Serial:     1,
				Refresh:    7200,
				Retry:      3600,
				Expire:     1209600,
				MinimumTTL: 3600,
				TTL:        3600,
			},
		},
	}
}

// Test NewDNSHandlers

func TestNewDNSHandlers(t *testing.T) {
	logger := newTestLogger()
	service := newMockDNSService()
	writer := &mockHttpWriter{}

	handlers := NewDNSHandlers(logger, service, writer)

	require.NotNil(t, handlers)
	assert.NotNil(t, handlers.logger)
	assert.NotNil(t, handlers.service)
	assert.NotNil(t, handlers.respWriter)
}

// Test CreateZone

func TestCreateZone_Success(t *testing.T) {
	service := newMockDNSService()
	handlers, writer := newTestHandlers(service)

	body := CreateZoneRequest{
		Name:        "example.com.",
		TTL:         3600,
		Description: "Test zone",
		Internal:    false,
		SOA: &SOARequest{
			Name:       "example.com.",
			MName:      "ns1.example.com.",
			RName:      "admin.example.com.",
			Serial:     1,
			Refresh:    7200,
			Retry:      3600,
			Expire:     1209600,
			MinimumTTL: 3600,
			TTL:        3600,
		},
		NSRecords: []*NSRequest{
			{Name: "@", Value: "ns1.example.com.", TTL: 3600},
		},
	}

	req := createRequest(http.MethodPost, "/api/v1/dns/zones", body)
	rec := httptest.NewRecorder()

	handlers.CreateZone(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(ZoneResponse)
	require.True(t, ok)
	assert.Equal(t, "example.com.", payload.Name)
}

func TestCreateZone_MissingName(t *testing.T) {
	service := newMockDNSService()
	handlers, writer := newTestHandlers(service)

	body := CreateZoneRequest{
		TTL: 3600,
	}

	req := createRequest(http.MethodPost, "/api/v1/dns/zones", body)
	rec := httptest.NewRecorder()

	handlers.CreateZone(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingZoneName)
	assert.True(t, ok)
}

func TestCreateZone_InvalidRequestBody(t *testing.T) {
	service := newMockDNSService()
	handlers, writer := newTestHandlers(service)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/dns/zones", bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.CreateZone(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrInvalidRequestBody)
	assert.True(t, ok)
}

func TestCreateZone_SaveError(t *testing.T) {
	service := newMockDNSService()
	service.saveErr = errors.New("database error")
	handlers, writer := newTestHandlers(service)

	body := CreateZoneRequest{
		Name: "example.com.",
		TTL:  3600,
	}

	req := createRequest(http.MethodPost, "/api/v1/dns/zones", body)
	rec := httptest.NewRecorder()

	handlers.CreateZone(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

// Test GetZone

func TestGetZone_Success(t *testing.T) {
	service := newMockDNSService()
	testZone := createTestZone("example.com.")
	service.zones["example.com."] = testZone
	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodGet, "/api/v1/dns/zones/example.com.", nil, map[string]string{"zone": "example.com."})
	rec := httptest.NewRecorder()

	handlers.GetZone(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(ZoneResponse)
	require.True(t, ok)
	assert.Equal(t, "example.com.", payload.Name)
}

func TestGetZone_MissingZoneName(t *testing.T) {
	service := newMockDNSService()
	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodGet, "/api/v1/dns/zones/", nil, map[string]string{})
	rec := httptest.NewRecorder()

	handlers.GetZone(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingZoneName)
	assert.True(t, ok)
}

func TestGetZone_NotFound(t *testing.T) {
	service := newMockDNSService()
	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodGet, "/api/v1/dns/zones/nonexistent.com.", nil, map[string]string{"zone": "nonexistent.com."})
	rec := httptest.NewRecorder()

	handlers.GetZone(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

// Test UpdateZone

func TestUpdateZone_Success(t *testing.T) {
	service := newMockDNSService()
	testZone := createTestZone("example.com.")
	service.zones["example.com."] = testZone
	handlers, writer := newTestHandlers(service)

	body := UpdateZoneRequest{
		TTL:         7200,
		Description: "Updated description",
	}

	req := createRequestWithVars(http.MethodPut, "/api/v1/dns/zones/example.com.", body, map[string]string{"zone": "example.com."})
	rec := httptest.NewRecorder()

	handlers.UpdateZone(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(ZoneResponse)
	require.True(t, ok)
	assert.Equal(t, uint32(7200), payload.TTL)
	assert.Equal(t, "Updated description", payload.Description)
}

func TestUpdateZone_MissingZoneName(t *testing.T) {
	service := newMockDNSService()
	handlers, writer := newTestHandlers(service)

	body := UpdateZoneRequest{TTL: 7200}
	req := createRequestWithVars(http.MethodPut, "/api/v1/dns/zones/", body, map[string]string{})
	rec := httptest.NewRecorder()

	handlers.UpdateZone(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestUpdateZone_InvalidRequestBody(t *testing.T) {
	service := newMockDNSService()
	handlers, writer := newTestHandlers(service)

	req := httptest.NewRequest(http.MethodPut, "/api/v1/dns/zones/example.com.", bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	req = mux.SetURLVars(req, map[string]string{"zone": "example.com."})
	rec := httptest.NewRecorder()

	handlers.UpdateZone(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestUpdateZone_NotFound(t *testing.T) {
	service := newMockDNSService()
	handlers, writer := newTestHandlers(service)

	body := UpdateZoneRequest{TTL: 7200}
	req := createRequestWithVars(http.MethodPut, "/api/v1/dns/zones/nonexistent.com.", body, map[string]string{"zone": "nonexistent.com."})
	rec := httptest.NewRecorder()

	handlers.UpdateZone(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestUpdateZone_SaveError(t *testing.T) {
	service := newMockDNSService()
	testZone := createTestZone("example.com.")
	service.zones["example.com."] = testZone
	service.saveErr = errors.New("database error")
	handlers, writer := newTestHandlers(service)

	body := UpdateZoneRequest{TTL: 7200}
	req := createRequestWithVars(http.MethodPut, "/api/v1/dns/zones/example.com.", body, map[string]string{"zone": "example.com."})
	rec := httptest.NewRecorder()

	handlers.UpdateZone(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

// Test DeleteZone

func TestDeleteZone_Success(t *testing.T) {
	service := newMockDNSService()
	testZone := createTestZone("example.com.")
	service.zones["example.com."] = testZone
	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodDelete, "/api/v1/dns/zones/example.com.", nil, map[string]string{"zone": "example.com."})
	rec := httptest.NewRecorder()

	handlers.DeleteZone(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(SuccessResponse)
	require.True(t, ok)
	assert.True(t, payload.Success)
	assert.Equal(t, "zone deleted successfully", payload.Message)
}

func TestDeleteZone_MissingZoneName(t *testing.T) {
	service := newMockDNSService()
	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodDelete, "/api/v1/dns/zones/", nil, map[string]string{})
	rec := httptest.NewRecorder()

	handlers.DeleteZone(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestDeleteZone_NotFound(t *testing.T) {
	service := newMockDNSService()
	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodDelete, "/api/v1/dns/zones/nonexistent.com.", nil, map[string]string{"zone": "nonexistent.com."})
	rec := httptest.NewRecorder()

	handlers.DeleteZone(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestDeleteZone_DeleteError(t *testing.T) {
	service := newMockDNSService()
	testZone := createTestZone("example.com.")
	service.zones["example.com."] = testZone
	service.deleteErr = errors.New("database error")
	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodDelete, "/api/v1/dns/zones/example.com.", nil, map[string]string{"zone": "example.com."})
	rec := httptest.NewRecorder()

	handlers.DeleteZone(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

// Test ListZones

func TestListZones_Success(t *testing.T) {
	service := newMockDNSService()
	service.zones["example.com."] = createTestZone("example.com.")
	service.zones["test.com."] = createTestZone("test.com.")
	handlers, writer := newTestHandlers(service)

	req := createRequest(http.MethodGet, "/api/v1/dns/zones", nil)
	rec := httptest.NewRecorder()

	handlers.ListZones(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(ListZonesResponse)
	require.True(t, ok)
	assert.Equal(t, int64(2), payload.Total)
	assert.Len(t, payload.Zones, 2)
}

func TestListZones_Empty(t *testing.T) {
	service := newMockDNSService()
	handlers, writer := newTestHandlers(service)

	req := createRequest(http.MethodGet, "/api/v1/dns/zones", nil)
	rec := httptest.NewRecorder()

	handlers.ListZones(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(ListZonesResponse)
	require.True(t, ok)
	assert.Equal(t, int64(0), payload.Total)
}

func TestListZones_InternalFilter(t *testing.T) {
	service := newMockDNSService()
	internalZone := createTestZone("internal.local.")
	internalZone.Internal = true
	service.zones["internal.local."] = internalZone
	service.zones["public.com."] = createTestZone("public.com.")
	handlers, writer := newTestHandlers(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/dns/zones?internal=true", nil)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()

	handlers.ListZones(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(ListZonesResponse)
	require.True(t, ok)
	assert.Equal(t, int64(1), payload.Total)
	assert.Equal(t, "internal.local.", payload.Zones[0].Name)
}

func TestListZones_PublicFilter(t *testing.T) {
	service := newMockDNSService()
	internalZone := createTestZone("internal.local.")
	internalZone.Internal = true
	service.zones["internal.local."] = internalZone
	service.zones["public.com."] = createTestZone("public.com.")
	handlers, writer := newTestHandlers(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/dns/zones?public=true", nil)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()

	handlers.ListZones(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(ListZonesResponse)
	require.True(t, ok)
	assert.Equal(t, int64(1), payload.Total)
	assert.Equal(t, "public.com.", payload.Zones[0].Name)
}

func TestListZones_ServiceError(t *testing.T) {
	service := newMockDNSService()
	service.listZonesErr = errors.New("database error")
	handlers, writer := newTestHandlers(service)

	req := createRequest(http.MethodGet, "/api/v1/dns/zones", nil)
	rec := httptest.NewRecorder()

	handlers.ListZones(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestListZones_Pagination(t *testing.T) {
	service := newMockDNSService()
	service.zones["example.com."] = createTestZone("example.com.")
	handlers, writer := newTestHandlers(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/dns/zones?limit=10&offset=5", nil)
	req.Header.Set("Accept", "application/json")
	rec := httptest.NewRecorder()

	handlers.ListZones(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(ListZonesResponse)
	require.True(t, ok)
	assert.Equal(t, int32(10), payload.Limit)
	assert.Equal(t, int32(5), payload.Offset)
}

// Test AddRecord

func TestAddRecord_ARecord_Success(t *testing.T) {
	service := newMockDNSService()
	service.zones["example.com."] = createTestZone("example.com.")
	handlers, writer := newTestHandlers(service)

	body := AddRecordRequest{
		Type: "A",
		A: &ARequest{
			Name:  "www",
			Value: "192.168.1.1",
			TTL:   3600,
		},
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/dns/zones/example.com./records", body, map[string]string{"zone": "example.com."})
	rec := httptest.NewRecorder()

	handlers.AddRecord(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	zone := service.zones["example.com."]
	require.Len(t, zone.RecordSet.ARecords, 1)
	assert.Equal(t, "www", zone.RecordSet.ARecords[0].Name)
}

func TestAddRecord_AAAARecord_Success(t *testing.T) {
	service := newMockDNSService()
	service.zones["example.com."] = createTestZone("example.com.")
	handlers, writer := newTestHandlers(service)

	body := AddRecordRequest{
		Type: "AAAA",
		AAAA: &AAAARequest{
			Name:  "www",
			Value: "2001:db8::1",
			TTL:   3600,
		},
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/dns/zones/example.com./records", body, map[string]string{"zone": "example.com."})
	rec := httptest.NewRecorder()

	handlers.AddRecord(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestAddRecord_CNAMERecord_Success(t *testing.T) {
	service := newMockDNSService()
	service.zones["example.com."] = createTestZone("example.com.")
	handlers, writer := newTestHandlers(service)

	body := AddRecordRequest{
		Type: "CNAME",
		CNAME: &CNAMERequest{
			Name:  "alias",
			Value: "www.example.com.",
			TTL:   3600,
		},
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/dns/zones/example.com./records", body, map[string]string{"zone": "example.com."})
	rec := httptest.NewRecorder()

	handlers.AddRecord(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestAddRecord_MXRecord_Success(t *testing.T) {
	service := newMockDNSService()
	service.zones["example.com."] = createTestZone("example.com.")
	handlers, writer := newTestHandlers(service)

	body := AddRecordRequest{
		Type: "MX",
		MX: &MXRequest{
			Name:     "@",
			Value:    "mail.example.com.",
			Priority: 10,
			TTL:      3600,
		},
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/dns/zones/example.com./records", body, map[string]string{"zone": "example.com."})
	rec := httptest.NewRecorder()

	handlers.AddRecord(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestAddRecord_NSRecord_Success(t *testing.T) {
	service := newMockDNSService()
	service.zones["example.com."] = createTestZone("example.com.")
	handlers, writer := newTestHandlers(service)

	body := AddRecordRequest{
		Type: "NS",
		NS: &NSRequest{
			Name:  "@",
			Value: "ns2.example.com.",
			TTL:   3600,
		},
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/dns/zones/example.com./records", body, map[string]string{"zone": "example.com."})
	rec := httptest.NewRecorder()

	handlers.AddRecord(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestAddRecord_TXTRecord_Success(t *testing.T) {
	service := newMockDNSService()
	service.zones["example.com."] = createTestZone("example.com.")
	handlers, writer := newTestHandlers(service)

	body := AddRecordRequest{
		Type: "TXT",
		TXT: &TXTRequest{
			Name:  "_dmarc",
			Value: "v=DMARC1; p=reject",
			TTL:   3600,
		},
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/dns/zones/example.com./records", body, map[string]string{"zone": "example.com."})
	rec := httptest.NewRecorder()

	handlers.AddRecord(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestAddRecord_SRVRecord_Success(t *testing.T) {
	service := newMockDNSService()
	service.zones["example.com."] = createTestZone("example.com.")
	handlers, writer := newTestHandlers(service)

	body := AddRecordRequest{
		Type: "SRV",
		SRV: &SRVRequest{
			Name:     "_sip._tcp",
			Target:   "sip.example.com.",
			Port:     5060,
			Priority: 10,
			Weight:   100,
			TTL:      3600,
		},
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/dns/zones/example.com./records", body, map[string]string{"zone": "example.com."})
	rec := httptest.NewRecorder()

	handlers.AddRecord(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestAddRecord_CAARecord_Success(t *testing.T) {
	service := newMockDNSService()
	service.zones["example.com."] = createTestZone("example.com.")
	handlers, writer := newTestHandlers(service)

	body := AddRecordRequest{
		Type: "CAA",
		CAA: &CAARequest{
			Name:  "@",
			Flags: 0,
			Tag:   "issue",
			Value: "letsencrypt.org",
			TTL:   3600,
		},
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/dns/zones/example.com./records", body, map[string]string{"zone": "example.com."})
	rec := httptest.NewRecorder()

	handlers.AddRecord(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestAddRecord_TLSARecord_Success(t *testing.T) {
	service := newMockDNSService()
	service.zones["example.com."] = createTestZone("example.com.")
	handlers, writer := newTestHandlers(service)

	body := AddRecordRequest{
		Type: "TLSA",
		TLSA: &TLSARequest{
			Name:         "_443._tcp.www",
			Usage:        3,
			Selector:     1,
			MatchingType: 1,
			Data:         "abc123",
			TTL:          3600,
		},
	}

	req := createRequestWithVars(http.MethodPost, "/api/v1/dns/zones/example.com./records", body, map[string]string{"zone": "example.com."})
	rec := httptest.NewRecorder()

	handlers.AddRecord(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestAddRecord_MissingZoneName(t *testing.T) {
	service := newMockDNSService()
	handlers, writer := newTestHandlers(service)

	body := AddRecordRequest{Type: "A"}
	req := createRequestWithVars(http.MethodPost, "/api/v1/dns/zones//records", body, map[string]string{})
	rec := httptest.NewRecorder()

	handlers.AddRecord(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestAddRecord_MissingRecordType(t *testing.T) {
	service := newMockDNSService()
	service.zones["example.com."] = createTestZone("example.com.")
	handlers, writer := newTestHandlers(service)

	body := AddRecordRequest{}
	req := createRequestWithVars(http.MethodPost, "/api/v1/dns/zones/example.com./records", body, map[string]string{"zone": "example.com."})
	rec := httptest.NewRecorder()

	handlers.AddRecord(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingRecordType)
	assert.True(t, ok)
}

func TestAddRecord_InvalidRecordType(t *testing.T) {
	service := newMockDNSService()
	service.zones["example.com."] = createTestZone("example.com.")
	handlers, writer := newTestHandlers(service)

	body := AddRecordRequest{Type: "INVALID"}
	req := createRequestWithVars(http.MethodPost, "/api/v1/dns/zones/example.com./records", body, map[string]string{"zone": "example.com."})
	rec := httptest.NewRecorder()

	handlers.AddRecord(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrInvalidRecordType)
	assert.True(t, ok)
}

func TestAddRecord_ZoneNotFound(t *testing.T) {
	service := newMockDNSService()
	handlers, writer := newTestHandlers(service)

	body := AddRecordRequest{
		Type: "A",
		A:    &ARequest{Name: "www", Value: "192.168.1.1", TTL: 3600},
	}
	req := createRequestWithVars(http.MethodPost, "/api/v1/dns/zones/nonexistent.com./records", body, map[string]string{"zone": "nonexistent.com."})
	rec := httptest.NewRecorder()

	handlers.AddRecord(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestAddRecord_InvalidRequestBody(t *testing.T) {
	service := newMockDNSService()
	handlers, writer := newTestHandlers(service)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/dns/zones/example.com./records", bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	req = mux.SetURLVars(req, map[string]string{"zone": "example.com."})
	rec := httptest.NewRecorder()

	handlers.AddRecord(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestAddRecord_SaveError(t *testing.T) {
	service := newMockDNSService()
	service.zones["example.com."] = createTestZone("example.com.")
	service.saveErr = errors.New("database error")
	handlers, writer := newTestHandlers(service)

	body := AddRecordRequest{
		Type: "A",
		A:    &ARequest{Name: "www", Value: "192.168.1.1", TTL: 3600},
	}
	req := createRequestWithVars(http.MethodPost, "/api/v1/dns/zones/example.com./records", body, map[string]string{"zone": "example.com."})
	rec := httptest.NewRecorder()

	handlers.AddRecord(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

// Test DeleteRecord

func TestDeleteRecord_ARecord_Success(t *testing.T) {
	service := newMockDNSService()
	zone := createTestZone("example.com.")
	zone.AddARecord(&entities.ARecord{Name: "www", Value: "192.168.1.1", TTL: 3600})
	service.zones["example.com."] = zone
	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodDelete, "/api/v1/dns/zones/example.com./records/A/www", nil, map[string]string{
		"zone": "example.com.",
		"type": "A",
		"name": "www",
	})
	rec := httptest.NewRecorder()

	handlers.DeleteRecord(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestDeleteRecord_AAAARecord_Success(t *testing.T) {
	service := newMockDNSService()
	zone := createTestZone("example.com.")
	zone.AddAAAARecord(&entities.AAAARecord{Name: "www", Value: "2001:db8::1", TTL: 3600})
	service.zones["example.com."] = zone
	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodDelete, "/api/v1/dns/zones/example.com./records/AAAA/www", nil, map[string]string{
		"zone": "example.com.",
		"type": "AAAA",
		"name": "www",
	})
	rec := httptest.NewRecorder()

	handlers.DeleteRecord(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestDeleteRecord_CNAMERecord_Success(t *testing.T) {
	service := newMockDNSService()
	zone := createTestZone("example.com.")
	zone.AddCNAMERecord(&entities.CNAMERecord{Name: "alias", Value: "www.example.com.", TTL: 3600})
	service.zones["example.com."] = zone
	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodDelete, "/api/v1/dns/zones/example.com./records/CNAME/alias", nil, map[string]string{
		"zone": "example.com.",
		"type": "CNAME",
		"name": "alias",
	})
	rec := httptest.NewRecorder()

	handlers.DeleteRecord(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestDeleteRecord_MXRecord_Success(t *testing.T) {
	service := newMockDNSService()
	zone := createTestZone("example.com.")
	zone.AddMXRecord(&entities.MXRecord{Name: "@", Value: "mail.example.com.", Priority: 10, TTL: 3600})
	service.zones["example.com."] = zone
	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodDelete, "/api/v1/dns/zones/example.com./records/MX/@", nil, map[string]string{
		"zone": "example.com.",
		"type": "MX",
		"name": "@",
	})
	rec := httptest.NewRecorder()

	handlers.DeleteRecord(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestDeleteRecord_NSRecord_Success(t *testing.T) {
	service := newMockDNSService()
	zone := createTestZone("example.com.")
	zone.AddNSRecord(&entities.NSRecord{Name: "@", Value: "ns1.example.com.", TTL: 3600})
	service.zones["example.com."] = zone
	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodDelete, "/api/v1/dns/zones/example.com./records/NS/@", nil, map[string]string{
		"zone": "example.com.",
		"type": "NS",
		"name": "@",
	})
	rec := httptest.NewRecorder()

	handlers.DeleteRecord(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestDeleteRecord_TXTRecord_Success(t *testing.T) {
	service := newMockDNSService()
	zone := createTestZone("example.com.")
	zone.AddTXTRecord(&entities.TXTRecord{Name: "_dmarc", Value: "v=DMARC1", TTL: 3600})
	service.zones["example.com."] = zone
	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodDelete, "/api/v1/dns/zones/example.com./records/TXT/_dmarc", nil, map[string]string{
		"zone": "example.com.",
		"type": "TXT",
		"name": "_dmarc",
	})
	rec := httptest.NewRecorder()

	handlers.DeleteRecord(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestDeleteRecord_SRVRecord_Success(t *testing.T) {
	service := newMockDNSService()
	zone := createTestZone("example.com.")
	zone.AddSRVRecord(&entities.SRVRecord{Name: "_sip._tcp", Target: "sip.example.com.", Port: 5060, TTL: 3600})
	service.zones["example.com."] = zone
	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodDelete, "/api/v1/dns/zones/example.com./records/SRV/_sip._tcp", nil, map[string]string{
		"zone": "example.com.",
		"type": "SRV",
		"name": "_sip._tcp",
	})
	rec := httptest.NewRecorder()

	handlers.DeleteRecord(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestDeleteRecord_CAARecord_Success(t *testing.T) {
	service := newMockDNSService()
	zone := createTestZone("example.com.")
	zone.AddCAARecord(&entities.CAARecord{Name: "@", Flags: 0, Tag: "issue", Value: "letsencrypt.org", TTL: 3600})
	service.zones["example.com."] = zone
	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodDelete, "/api/v1/dns/zones/example.com./records/CAA/@", nil, map[string]string{
		"zone": "example.com.",
		"type": "CAA",
		"name": "@",
	})
	rec := httptest.NewRecorder()

	handlers.DeleteRecord(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestDeleteRecord_TLSARecord_Success(t *testing.T) {
	service := newMockDNSService()
	zone := createTestZone("example.com.")
	zone.AddTLSARecord(&entities.TLSARecord{Name: "_443._tcp.www", Usage: 3, Selector: 1, MatchingType: 1, Data: "abc123", TTL: 3600})
	service.zones["example.com."] = zone
	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodDelete, "/api/v1/dns/zones/example.com./records/TLSA/_443._tcp.www", nil, map[string]string{
		"zone": "example.com.",
		"type": "TLSA",
		"name": "_443._tcp.www",
	})
	rec := httptest.NewRecorder()

	handlers.DeleteRecord(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestDeleteRecord_MissingZoneName(t *testing.T) {
	service := newMockDNSService()
	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodDelete, "/api/v1/dns/zones//records/A/www", nil, map[string]string{
		"type": "A",
		"name": "www",
	})
	rec := httptest.NewRecorder()

	handlers.DeleteRecord(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestDeleteRecord_MissingRecordType(t *testing.T) {
	service := newMockDNSService()
	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodDelete, "/api/v1/dns/zones/example.com./records//www", nil, map[string]string{
		"zone": "example.com.",
		"name": "www",
	})
	rec := httptest.NewRecorder()

	handlers.DeleteRecord(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestDeleteRecord_MissingRecordName(t *testing.T) {
	service := newMockDNSService()
	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodDelete, "/api/v1/dns/zones/example.com./records/A/", nil, map[string]string{
		"zone": "example.com.",
		"type": "A",
	})
	rec := httptest.NewRecorder()

	handlers.DeleteRecord(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestDeleteRecord_InvalidRecordType(t *testing.T) {
	service := newMockDNSService()
	service.zones["example.com."] = createTestZone("example.com.")
	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodDelete, "/api/v1/dns/zones/example.com./records/INVALID/www", nil, map[string]string{
		"zone": "example.com.",
		"type": "INVALID",
		"name": "www",
	})
	rec := httptest.NewRecorder()

	handlers.DeleteRecord(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestDeleteRecord_ZoneNotFound(t *testing.T) {
	service := newMockDNSService()
	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodDelete, "/api/v1/dns/zones/nonexistent.com./records/A/www", nil, map[string]string{
		"zone": "nonexistent.com.",
		"type": "A",
		"name": "www",
	})
	rec := httptest.NewRecorder()

	handlers.DeleteRecord(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestDeleteRecord_SaveError(t *testing.T) {
	service := newMockDNSService()
	zone := createTestZone("example.com.")
	zone.AddARecord(&entities.ARecord{Name: "www", Value: "192.168.1.1", TTL: 3600})
	service.zones["example.com."] = zone
	service.saveErr = errors.New("database error")
	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodDelete, "/api/v1/dns/zones/example.com./records/A/www", nil, map[string]string{
		"zone": "example.com.",
		"type": "A",
		"name": "www",
	})
	rec := httptest.NewRecorder()

	handlers.DeleteRecord(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

// Test ListRecords

func TestListRecords_Success(t *testing.T) {
	service := newMockDNSService()
	zone := createTestZone("example.com.")
	zone.AddARecord(&entities.ARecord{Name: "www", Value: "192.168.1.1", TTL: 3600})
	zone.AddAAAARecord(&entities.AAAARecord{Name: "www", Value: "2001:db8::1", TTL: 3600})
	zone.AddMXRecord(&entities.MXRecord{Name: "@", Value: "mail.example.com.", Priority: 10, TTL: 3600})
	service.zones["example.com."] = zone
	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodGet, "/api/v1/dns/zones/example.com./records", nil, map[string]string{"zone": "example.com."})
	rec := httptest.NewRecorder()

	handlers.ListRecords(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(ListRecordsResponse)
	require.True(t, ok)
	assert.Len(t, payload.Records, 3)
}

func TestListRecords_FilterByType(t *testing.T) {
	service := newMockDNSService()
	zone := createTestZone("example.com.")
	zone.AddARecord(&entities.ARecord{Name: "www", Value: "192.168.1.1", TTL: 3600})
	zone.AddAAAARecord(&entities.AAAARecord{Name: "www", Value: "2001:db8::1", TTL: 3600})
	service.zones["example.com."] = zone
	handlers, writer := newTestHandlers(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/dns/zones/example.com./records?type=A", nil)
	req.Header.Set("Accept", "application/json")
	req = mux.SetURLVars(req, map[string]string{"zone": "example.com."})
	rec := httptest.NewRecorder()

	handlers.ListRecords(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(ListRecordsResponse)
	require.True(t, ok)
	assert.Len(t, payload.Records, 1)
	assert.Equal(t, "A", payload.Records[0].Type)
}

func TestListRecords_AllRecordTypes(t *testing.T) {
	service := newMockDNSService()
	zone := createTestZone("example.com.")
	zone.AddARecord(&entities.ARecord{Name: "www", Value: "192.168.1.1", TTL: 3600})
	zone.AddAAAARecord(&entities.AAAARecord{Name: "www", Value: "2001:db8::1", TTL: 3600})
	zone.AddCNAMERecord(&entities.CNAMERecord{Name: "alias", Value: "www.example.com.", TTL: 3600})
	zone.AddMXRecord(&entities.MXRecord{Name: "@", Value: "mail.example.com.", Priority: 10, TTL: 3600})
	zone.AddNSRecord(&entities.NSRecord{Name: "@", Value: "ns1.example.com.", TTL: 3600})
	zone.AddTXTRecord(&entities.TXTRecord{Name: "_dmarc", Value: "v=DMARC1", TTL: 3600})
	zone.AddSRVRecord(&entities.SRVRecord{Name: "_sip._tcp", Target: "sip.example.com.", Port: 5060, TTL: 3600})
	zone.AddCAARecord(&entities.CAARecord{Name: "@", Flags: 0, Tag: "issue", Value: "letsencrypt.org", TTL: 3600})
	zone.AddTLSARecord(&entities.TLSARecord{Name: "_443._tcp.www", Usage: 3, Selector: 1, MatchingType: 1, Data: "abc", TTL: 3600})
	service.zones["example.com."] = zone
	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodGet, "/api/v1/dns/zones/example.com./records", nil, map[string]string{"zone": "example.com."})
	rec := httptest.NewRecorder()

	handlers.ListRecords(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(ListRecordsResponse)
	require.True(t, ok)
	assert.Len(t, payload.Records, 9)
}

func TestListRecords_MissingZoneName(t *testing.T) {
	service := newMockDNSService()
	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodGet, "/api/v1/dns/zones//records", nil, map[string]string{})
	rec := httptest.NewRecorder()

	handlers.ListRecords(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestListRecords_ZoneNotFound(t *testing.T) {
	service := newMockDNSService()
	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodGet, "/api/v1/dns/zones/nonexistent.com./records", nil, map[string]string{"zone": "nonexistent.com."})
	rec := httptest.NewRecorder()

	handlers.ListRecords(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

// Test SignZone

func TestSignZone_Success(t *testing.T) {
	service := newMockDNSService()
	service.zones["example.com."] = createTestZone("example.com.")
	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodPost, "/api/v1/dns/zones/example.com./sign", nil, map[string]string{"zone": "example.com."})
	rec := httptest.NewRecorder()

	handlers.SignZone(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(ZoneResponse)
	require.True(t, ok)
	require.NotNil(t, payload.Records)
	assert.NotEmpty(t, payload.Records.DNSKEY)
}

func TestSignZone_MissingZoneName(t *testing.T) {
	service := newMockDNSService()
	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodPost, "/api/v1/dns/zones//sign", nil, map[string]string{})
	rec := httptest.NewRecorder()

	handlers.SignZone(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestSignZone_ZoneNotFound(t *testing.T) {
	service := newMockDNSService()
	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodPost, "/api/v1/dns/zones/nonexistent.com./sign", nil, map[string]string{"zone": "nonexistent.com."})
	rec := httptest.NewRecorder()

	handlers.SignZone(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

func TestSignZone_SignError(t *testing.T) {
	service := newMockDNSService()
	service.zones["example.com."] = createTestZone("example.com.")
	service.signErr = errors.New("DNSSEC not enabled")
	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodPost, "/api/v1/dns/zones/example.com./sign", nil, map[string]string{"zone": "example.com."})
	rec := httptest.NewRecorder()

	handlers.SignZone(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

func TestSignZone_SaveError(t *testing.T) {
	service := newMockDNSService()
	service.zones["example.com."] = createTestZone("example.com.")
	service.saveErr = errors.New("database error")
	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodPost, "/api/v1/dns/zones/example.com./sign", nil, map[string]string{"zone": "example.com."})
	rec := httptest.NewRecorder()

	handlers.SignZone(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

// Test GetDNSSECStatus

func TestGetDNSSECStatus_Success(t *testing.T) {
	service := newMockDNSService()
	service.dnssecEnabled = true
	zone := createTestZone("example.com.")
	zone.AddDNSKEYRecord(&entities.DNSKEYRecord{
		Name:      "example.com.",
		Flags:     257,
		Protocol:  3,
		Algorithm: 13,
		Key:       "test-key",
		TTL:       3600,
	})
	zone.AddDSRecord(&entities.DSRecord{
		Name:       "example.com.",
		KeyTag:     12345,
		Algorithm:  13,
		DigestType: 2,
		Digest:     "abcd1234",
		TTL:        3600,
	})
	service.zones["example.com."] = zone
	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodGet, "/api/v1/dns/zones/example.com./dnssec", nil, map[string]string{"zone": "example.com."})
	rec := httptest.NewRecorder()

	handlers.GetDNSSECStatus(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(DNSSECStatusResponse)
	require.True(t, ok)
	assert.True(t, payload.Enabled)
	assert.True(t, payload.ZoneSigned)
	assert.Len(t, payload.Keys, 1)
	assert.Len(t, payload.DSRecords, 1)
}

func TestGetDNSSECStatus_Disabled(t *testing.T) {
	service := newMockDNSService()
	service.dnssecEnabled = false
	service.zones["example.com."] = createTestZone("example.com.")
	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodGet, "/api/v1/dns/zones/example.com./dnssec", nil, map[string]string{"zone": "example.com."})
	rec := httptest.NewRecorder()

	handlers.GetDNSSECStatus(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
	payload, ok := writer.lastPayload.(DNSSECStatusResponse)
	require.True(t, ok)
	assert.False(t, payload.Enabled)
	assert.False(t, payload.ZoneSigned)
}

func TestGetDNSSECStatus_MissingZoneName(t *testing.T) {
	service := newMockDNSService()
	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodGet, "/api/v1/dns/zones//dnssec", nil, map[string]string{})
	rec := httptest.NewRecorder()

	handlers.GetDNSSECStatus(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestGetDNSSECStatus_ZoneNotFound(t *testing.T) {
	service := newMockDNSService()
	handlers, writer := newTestHandlers(service)

	req := createRequestWithVars(http.MethodGet, "/api/v1/dns/zones/nonexistent.com./dnssec", nil, map[string]string{"zone": "nonexistent.com."})
	rec := httptest.NewRecorder()

	handlers.GetDNSSECStatus(rec, req)

	assert.Equal(t, http.StatusNotFound, writer.lastStatus)
}

// Test Register

func TestRegister_Success(t *testing.T) {
	service := newMockDNSService()
	service.registerResult = createTestZone("device.local.")
	handlers, writer := newTestHandlers(service)

	body := RegisterRequest{
		FQDN: "device.local.",
		IP:   "192.168.1.100",
	}

	req := createRequest(http.MethodPost, "/api/v1/dns/register", body)
	rec := httptest.NewRecorder()

	handlers.Register(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestRegister_SuccessWithNilZone(t *testing.T) {
	service := newMockDNSService()
	service.registerResult = nil
	handlers, writer := newTestHandlers(service)

	body := RegisterRequest{
		FQDN: "device.local.",
		IP:   "192.168.1.100",
	}

	req := createRequest(http.MethodPost, "/api/v1/dns/register", body)
	rec := httptest.NewRecorder()

	handlers.Register(rec, req)

	assert.Equal(t, http.StatusOK, writer.lastStatus)
}

func TestRegister_MissingFQDN(t *testing.T) {
	service := newMockDNSService()
	handlers, writer := newTestHandlers(service)

	body := RegisterRequest{
		IP: "192.168.1.100",
	}

	req := createRequest(http.MethodPost, "/api/v1/dns/register", body)
	rec := httptest.NewRecorder()

	handlers.Register(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingFQDN)
	assert.True(t, ok)
}

func TestRegister_MissingIP(t *testing.T) {
	service := newMockDNSService()
	handlers, writer := newTestHandlers(service)

	body := RegisterRequest{
		FQDN: "device.local.",
	}

	req := createRequest(http.MethodPost, "/api/v1/dns/register", body)
	rec := httptest.NewRecorder()

	handlers.Register(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
	_, ok := writer.lastError.(ErrMissingIP)
	assert.True(t, ok)
}

func TestRegister_InvalidRequestBody(t *testing.T) {
	service := newMockDNSService()
	handlers, writer := newTestHandlers(service)

	req := httptest.NewRequest(http.MethodPost, "/api/v1/dns/register", bytes.NewBufferString("invalid json"))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	handlers.Register(rec, req)

	assert.Equal(t, http.StatusBadRequest, writer.lastStatus)
}

func TestRegister_ServiceError(t *testing.T) {
	service := newMockDNSService()
	service.registerErr = errors.New("registration failed")
	handlers, writer := newTestHandlers(service)

	body := RegisterRequest{
		FQDN: "device.local.",
		IP:   "192.168.1.100",
	}

	req := createRequest(http.MethodPost, "/api/v1/dns/register", body)
	rec := httptest.NewRecorder()

	handlers.Register(rec, req)

	assert.Equal(t, http.StatusInternalServerError, writer.lastStatus)
}

// Test helper methods

func TestGetPaginationParams_Defaults(t *testing.T) {
	service := newMockDNSService()
	handlers, _ := newTestHandlers(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/dns/zones", nil)
	limit, offset := handlers.getPaginationParams(req)

	assert.Equal(t, int32(50), limit)
	assert.Equal(t, int32(0), offset)
}

func TestGetPaginationParams_Custom(t *testing.T) {
	service := newMockDNSService()
	handlers, _ := newTestHandlers(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/dns/zones?limit=25&offset=10", nil)
	limit, offset := handlers.getPaginationParams(req)

	assert.Equal(t, int32(25), limit)
	assert.Equal(t, int32(10), offset)
}

func TestGetPaginationParams_MaxLimit(t *testing.T) {
	service := newMockDNSService()
	handlers, _ := newTestHandlers(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/dns/zones?limit=5000", nil)
	limit, _ := handlers.getPaginationParams(req)

	assert.Equal(t, int32(1000), limit)
}

func TestGetPaginationParams_InvalidLimit(t *testing.T) {
	service := newMockDNSService()
	handlers, _ := newTestHandlers(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/dns/zones?limit=0", nil)
	limit, _ := handlers.getPaginationParams(req)

	assert.Equal(t, int32(50), limit)
}

func TestGetPaginationParams_NegativeOffset(t *testing.T) {
	service := newMockDNSService()
	handlers, _ := newTestHandlers(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/dns/zones?offset=-5", nil)
	_, offset := handlers.getPaginationParams(req)

	assert.Equal(t, int32(0), offset)
}

func TestGetPaginationParams_InvalidStrings(t *testing.T) {
	service := newMockDNSService()
	handlers, _ := newTestHandlers(service)

	req := httptest.NewRequest(http.MethodGet, "/api/v1/dns/zones?limit=abc&offset=xyz", nil)
	limit, offset := handlers.getPaginationParams(req)

	assert.Equal(t, int32(50), limit)
	assert.Equal(t, int32(0), offset)
}

// Test zoneToResponse with nil zone

func TestZoneToResponse_NilZone(t *testing.T) {
	service := newMockDNSService()
	handlers, _ := newTestHandlers(service)

	resp := handlers.zoneToResponse(nil)

	assert.Equal(t, ZoneResponse{}, resp)
}

// Test recordSetToResponse with nil recordset

func TestRecordSetToResponse_NilRecordSet(t *testing.T) {
	service := newMockDNSService()
	handlers, _ := newTestHandlers(service)

	resp := handlers.recordSetToResponse(nil)

	assert.Nil(t, resp)
}

// Test extractRecords with various record types

func TestExtractRecords_FilteredByType(t *testing.T) {
	service := newMockDNSService()
	handlers, _ := newTestHandlers(service)

	zone := createTestZone("example.com.")
	zone.AddARecord(&entities.ARecord{Name: "www", Value: "192.168.1.1", TTL: 3600})
	zone.AddAAAARecord(&entities.AAAARecord{Name: "www", Value: "2001:db8::1", TTL: 3600})
	zone.AddCNAMERecord(&entities.CNAMERecord{Name: "alias", Value: "www.example.com.", TTL: 3600})
	zone.AddMXRecord(&entities.MXRecord{Name: "@", Value: "mail.example.com.", Priority: 10, TTL: 3600})
	zone.AddNSRecord(&entities.NSRecord{Name: "@", Value: "ns1.example.com.", TTL: 3600})
	zone.AddTXTRecord(&entities.TXTRecord{Name: "_dmarc", Value: "v=DMARC1", TTL: 3600})
	zone.AddSRVRecord(&entities.SRVRecord{Name: "_sip._tcp", Target: "sip.example.com.", Port: 5060, TTL: 3600})
	zone.AddCAARecord(&entities.CAARecord{Name: "@", Flags: 0, Tag: "issue", Value: "letsencrypt.org", TTL: 3600})
	zone.AddTLSARecord(&entities.TLSARecord{Name: "_443._tcp.www", Usage: 3, Selector: 1, MatchingType: 1, Data: "abc", TTL: 3600})

	// Test each record type filter
	tests := []struct {
		typeFilter    string
		expectedCount int
	}{
		{"A", 1},
		{"AAAA", 1},
		{"CNAME", 1},
		{"MX", 1},
		{"NS", 1},
		{"TXT", 1},
		{"SRV", 1},
		{"CAA", 1},
		{"TLSA", 1},
		{"", 9}, // No filter - all records
	}

	for _, tc := range tests {
		t.Run("Filter_"+tc.typeFilter, func(t *testing.T) {
			records := handlers.extractRecords(zone, tc.typeFilter)
			assert.Len(t, records, tc.expectedCount)
		})
	}
}

// Test decodeJSON error handling

func TestDecodeJSON_UnknownFields(t *testing.T) {
	service := newMockDNSService()
	handlers, _ := newTestHandlers(service)

	body := `{"name": "test.com.", "unknown_field": "value"}`
	req := httptest.NewRequest(http.MethodPost, "/test", bytes.NewBufferString(body))

	var reqData CreateZoneRequest
	err := handlers.decodeJSON(req, &reqData)

	assert.Error(t, err)
}

// Test createContext

func TestCreateContext(t *testing.T) {
	service := newMockDNSService()
	handlers, _ := newTestHandlers(service)

	ctx, cancel := handlers.createContext()
	defer cancel()

	assert.NotNil(t, ctx)
	deadline, ok := ctx.Deadline()
	assert.True(t, ok)
	assert.False(t, deadline.IsZero())
}

// Test handler getters

func TestGetZoneName(t *testing.T) {
	service := newMockDNSService()
	handlers, _ := newTestHandlers(service)

	req := createRequestWithVars(http.MethodGet, "/test", nil, map[string]string{"zone": "example.com."})
	zoneName := handlers.getZoneName(req)

	assert.Equal(t, "example.com.", zoneName)
}

func TestGetRecordType(t *testing.T) {
	service := newMockDNSService()
	handlers, _ := newTestHandlers(service)

	req := createRequestWithVars(http.MethodGet, "/test", nil, map[string]string{"type": "A"})
	recordType := handlers.getRecordType(req)

	assert.Equal(t, "A", recordType)
}

func TestGetRecordName(t *testing.T) {
	service := newMockDNSService()
	handlers, _ := newTestHandlers(service)

	req := createRequestWithVars(http.MethodGet, "/test", nil, map[string]string{"name": "www"})
	recordName := handlers.getRecordName(req)

	assert.Equal(t, "www", recordName)
}

// Table-driven tests for AddRecord with nil record data

func TestAddRecord_NilRecordData(t *testing.T) {
	tests := []struct {
		name       string
		recordType string
	}{
		{"A_nil", "A"},
		{"AAAA_nil", "AAAA"},
		{"CNAME_nil", "CNAME"},
		{"MX_nil", "MX"},
		{"NS_nil", "NS"},
		{"TXT_nil", "TXT"},
		{"SRV_nil", "SRV"},
		{"CAA_nil", "CAA"},
		{"TLSA_nil", "TLSA"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			service := newMockDNSService()
			service.zones["example.com."] = createTestZone("example.com.")
			handlers, writer := newTestHandlers(service)

			body := AddRecordRequest{Type: tc.recordType}
			req := createRequestWithVars(http.MethodPost, "/api/v1/dns/zones/example.com./records", body, map[string]string{"zone": "example.com."})
			rec := httptest.NewRecorder()

			handlers.AddRecord(rec, req)

			// Should succeed but not add any records since record data is nil
			assert.Equal(t, http.StatusOK, writer.lastStatus)
		})
	}
}
