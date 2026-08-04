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

package grpc

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// mockDNSService implements dns.DNSService for testing.
type mockDNSService struct {
	zones          map[string]*entities.Zone
	createZoneErr  error
	zoneErr        error
	deleteZoneErr  error
	listZonesErr   error
	signZoneErr    error
	saveErr        error
	addRecordErr   error
	deleteRecErr   error
	listRecordsErr error
	resolveErr     error
	registerErr    error
	dnssecEnabled  bool
	internalDomain string
	publicDomain   string
}

func newMockDNSService() *mockDNSService {
	return &mockDNSService{
		zones:          make(map[string]*entities.Zone),
		internalDomain: "internal.example.com",
		publicDomain:   "example.com",
		dnssecEnabled:  true,
	}
}

func (m *mockDNSService) CreateZone(ctx context.Context, zoneName string) error {
	if m.createZoneErr != nil {
		return m.createZoneErr
	}
	m.zones[zoneName] = &entities.Zone{
		ID:   1,
		Name: zoneName,
		TTL:  3600,
	}
	return nil
}

func (m *mockDNSService) Zone(ctx context.Context, zoneName string) (*entities.Zone, error) {
	if m.zoneErr != nil {
		return nil, m.zoneErr
	}
	zone, ok := m.zones[zoneName]
	if !ok {
		return nil, errors.New("zone not found")
	}
	return zone, nil
}

func (m *mockDNSService) DeleteZone(ctx context.Context, zoneName string) error {
	if m.deleteZoneErr != nil {
		return m.deleteZoneErr
	}
	delete(m.zones, zoneName)
	return nil
}

func (m *mockDNSService) ListZones(ctx context.Context) ([]*entities.Zone, error) {
	if m.listZonesErr != nil {
		return nil, m.listZonesErr
	}
	zones := make([]*entities.Zone, 0, len(m.zones))
	for _, z := range m.zones {
		zones = append(zones, z)
	}
	return zones, nil
}

func (m *mockDNSService) SignZone(zone *entities.Zone) error {
	if m.signZoneErr != nil {
		return m.signZoneErr
	}
	zone.RecordSet.RRSIGRecords = append(zone.RecordSet.RRSIGRecords, &entities.RRSIGRecord{
		TypeCovered: "A",
		Algorithm:   13,
		SignerName:  zone.Name,
	})
	return nil
}

func (m *mockDNSService) Save(ctx context.Context, zone *entities.Zone) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.zones[zone.Name] = zone
	return nil
}

func (m *mockDNSService) AddRecord(ctx context.Context, name string, recordType string, value string, ttl int) error {
	if m.addRecordErr != nil {
		return m.addRecordErr
	}
	return nil
}

func (m *mockDNSService) DeleteRecord(ctx context.Context, name string, recordType string) error {
	if m.deleteRecErr != nil {
		return m.deleteRecErr
	}
	return nil
}

func (m *mockDNSService) GetRecord(ctx context.Context, name string, recordType string) (interface{}, error) {
	return &entities.ARecord{Name: name, Value: "192.168.1.1", TTL: 3600}, nil
}

func (m *mockDNSService) ListRecords(ctx context.Context, zoneName string) ([]interface{}, error) {
	if m.listRecordsErr != nil {
		return nil, m.listRecordsErr
	}
	return []interface{}{
		&entities.ARecord{Name: "www", Value: "192.168.1.1", TTL: 3600},
		&entities.AAAARecord{Name: "www", Value: "::1", TTL: 3600},
		&entities.CNAMERecord{Name: "alias", Value: "www.example.com", TTL: 3600},
		&entities.MXRecord{Name: "@", Value: "mail.example.com", Priority: 10, TTL: 3600},
		&entities.NSRecord{Name: "@", Value: "ns1.example.com", TTL: 86400},
		&entities.TXTRecord{Name: "@", Value: "v=spf1 include:_spf.example.com ~all", TTL: 3600},
		&entities.SRVRecord{Name: "_ldap._tcp", Target: "ldap.example.com", Port: 389, Priority: 0, Weight: 100, TTL: 3600},
		&entities.CAARecord{Name: "@", Flags: 0, Tag: "issue", Value: "letsencrypt.org", TTL: 3600},
		&entities.TLSARecord{Name: "_443._tcp", Usage: 3, Selector: 1, MatchingType: 1, Data: "abc123", TTL: 3600},
	}, nil
}

func (m *mockDNSService) Resolve(ctx context.Context, name string, recordType string) ([]string, error) {
	if m.resolveErr != nil {
		return nil, m.resolveErr
	}
	return []string{"192.168.1.1", "192.168.1.2"}, nil
}

func (m *mockDNSService) Register(ctx context.Context, fqdn string, ip string) (*entities.Zone, error) {
	if m.registerErr != nil {
		return nil, m.registerErr
	}
	zone := &entities.Zone{
		ID:   1,
		Name: "example.com.",
		TTL:  3600,
	}
	zone.AddARecord(&entities.ARecord{Name: fqdn, Value: ip, TTL: 3600})
	return zone, nil
}

func (m *mockDNSService) AddTLSARecord(ctx context.Context, zoneName string, record *entities.TLSARecord) error {
	return nil
}

func (m *mockDNSService) InternalDomain() string {
	return m.internalDomain
}

func (m *mockDNSService) PublicDomain() string {
	return m.publicDomain
}

func (m *mockDNSService) IsDNSSECEnabled() bool {
	return m.dnssecEnabled
}

func (m *mockDNSService) DNSSECService() *dns.DNSSECService {
	return nil
}

func (m *mockDNSService) InternalZone(ctx context.Context) (*entities.Zone, error) {
	return m.zones[m.internalDomain], nil
}

func (m *mockDNSService) PublicZone(ctx context.Context) (*entities.Zone, error) {
	return m.zones[m.publicDomain], nil
}

func (m *mockDNSService) SaveAndSign(ctx context.Context, zone *entities.Zone) error {
	m.zones[zone.Name] = zone
	return nil
}

func (m *mockDNSService) Delete(ctx context.Context, zone *entities.Zone) error {
	delete(m.zones, zone.Name)
	return nil
}

func (m *mockDNSService) RegisterWithNetworkZone(ctx context.Context, host, networkZone, ip string) error {
	return nil
}

func newTestDNSService() (*DNSGRPCService, *mockDNSService) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	mock := newMockDNSService()
	service := NewDNSGRPCService(logger, mock)
	return service, mock
}

// Test CreateZone

func TestDNSGRPCService_CreateZone_Success(t *testing.T) {
	service, _ := newTestDNSService()
	ctx := context.Background()

	req := &platformv1.CreateZoneRequest{
		Name:        "test.example.com.",
		Ttl:         3600,
		Description: "Test zone",
		Internal:    false,
	}

	resp, err := service.CreateZone(ctx, req)
	if err != nil {
		t.Fatalf("CreateZone failed: %v", err)
	}

	if resp.GetStatus() == nil || !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}

	if resp.GetZone() == nil {
		t.Error("Expected zone in response")
	}

	if resp.GetZone().GetName() != "test.example.com." {
		t.Errorf("Expected zone name 'test.example.com.', got '%s'", resp.GetZone().GetName())
	}
}

func TestDNSGRPCService_CreateZone_WithSOA(t *testing.T) {
	service, _ := newTestDNSService()
	ctx := context.Background()

	req := &platformv1.CreateZoneRequest{
		Name:        "test.example.com.",
		Ttl:         3600,
		Description: "Test zone with SOA",
		Soa: &platformv1.SOARecord{
			Name:       "test.example.com.",
			Mname:      "ns1.example.com.",
			Rname:      "admin.example.com.",
			Serial:     2024010101,
			Refresh:    7200,
			Retry:      3600,
			Expire:     1209600,
			MinimumTtl: 300,
			Ttl:        86400,
		},
		NsRecords: []*platformv1.NSRecord{
			{Name: "@", Value: "ns1.example.com.", Ttl: 86400},
			{Name: "@", Value: "ns2.example.com.", Ttl: 86400},
		},
	}

	resp, err := service.CreateZone(ctx, req)
	if err != nil {
		t.Fatalf("CreateZone with SOA failed: %v", err)
	}

	if resp.GetZone().GetRecords().GetSoa() == nil {
		t.Error("Expected SOA record in zone")
	}
}

func TestDNSGRPCService_CreateZone_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewDNSGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.CreateZoneRequest{Name: "test.example.com."}

	_, err := service.CreateZone(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestDNSGRPCService_CreateZone_MissingName(t *testing.T) {
	service, _ := newTestDNSService()
	ctx := context.Background()

	req := &platformv1.CreateZoneRequest{}

	_, err := service.CreateZone(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing zone name")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestDNSGRPCService_CreateZone_ServiceError(t *testing.T) {
	service, mock := newTestDNSService()
	mock.createZoneErr = errors.New("database connection failed")
	ctx := context.Background()

	req := &platformv1.CreateZoneRequest{Name: "test.example.com."}

	_, err := service.CreateZone(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.Internal {
		t.Errorf("Expected Internal error, got %v", st.Code())
	}
}

// Test GetZone

func TestDNSGRPCService_GetZone_Success(t *testing.T) {
	service, mock := newTestDNSService()
	ctx := context.Background()

	// Create a zone first
	mock.zones["test.example.com."] = &entities.Zone{
		ID:          1,
		Name:        "test.example.com.",
		TTL:         3600,
		Description: "Test zone",
	}

	req := &platformv1.GetZoneRequest{Name: "test.example.com."}

	resp, err := service.GetZone(ctx, req)
	if err != nil {
		t.Fatalf("GetZone failed: %v", err)
	}

	if resp.GetZone() == nil {
		t.Error("Expected zone in response")
	}

	if resp.GetZone().GetName() != "test.example.com." {
		t.Errorf("Expected zone name 'test.example.com.', got '%s'", resp.GetZone().GetName())
	}
}

func TestDNSGRPCService_GetZone_NotFound(t *testing.T) {
	service, _ := newTestDNSService()
	ctx := context.Background()

	req := &platformv1.GetZoneRequest{Name: "nonexistent.example.com."}

	_, err := service.GetZone(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nonexistent zone")
	}

	st, ok := status.FromError(err)
	if !ok {
		t.Fatal("Expected gRPC status error")
	}

	if st.Code() != codes.NotFound {
		t.Errorf("Expected NotFound, got %v", st.Code())
	}
}

func TestDNSGRPCService_GetZone_MissingName(t *testing.T) {
	service, _ := newTestDNSService()
	ctx := context.Background()

	req := &platformv1.GetZoneRequest{}

	_, err := service.GetZone(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing zone name")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// Test UpdateZone

func TestDNSGRPCService_UpdateZone_Success(t *testing.T) {
	service, mock := newTestDNSService()
	ctx := context.Background()

	mock.zones["test.example.com."] = &entities.Zone{
		ID:   1,
		Name: "test.example.com.",
		TTL:  3600,
	}

	req := &platformv1.UpdateZoneRequest{
		Name:        "test.example.com.",
		Ttl:         7200,
		Description: "Updated description",
	}

	resp, err := service.UpdateZone(ctx, req)
	if err != nil {
		t.Fatalf("UpdateZone failed: %v", err)
	}

	if resp.GetStatus() == nil || !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}

	if resp.GetZone().GetTtl() != 7200 {
		t.Errorf("Expected TTL 7200, got %d", resp.GetZone().GetTtl())
	}
}

func TestDNSGRPCService_UpdateZone_NotFound(t *testing.T) {
	service, _ := newTestDNSService()
	ctx := context.Background()

	req := &platformv1.UpdateZoneRequest{
		Name: "nonexistent.example.com.",
		Ttl:  7200,
	}

	_, err := service.UpdateZone(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nonexistent zone")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.NotFound {
		t.Errorf("Expected NotFound, got %v", st.Code())
	}
}

func TestDNSGRPCService_UpdateZone_MissingName(t *testing.T) {
	service, _ := newTestDNSService()
	ctx := context.Background()

	req := &platformv1.UpdateZoneRequest{Ttl: 7200}

	_, err := service.UpdateZone(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing zone name")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// Test DeleteZone

func TestDNSGRPCService_DeleteZone_Success(t *testing.T) {
	service, mock := newTestDNSService()
	ctx := context.Background()

	mock.zones["test.example.com."] = &entities.Zone{
		ID:   1,
		Name: "test.example.com.",
	}

	req := &platformv1.DeleteZoneRequest{Name: "test.example.com."}

	resp, err := service.DeleteZone(ctx, req)
	if err != nil {
		t.Fatalf("DeleteZone failed: %v", err)
	}

	if resp.GetStatus() == nil || !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}

	if _, ok := mock.zones["test.example.com."]; ok {
		t.Error("Expected zone to be deleted")
	}
}

func TestDNSGRPCService_DeleteZone_MissingName(t *testing.T) {
	service, _ := newTestDNSService()
	ctx := context.Background()

	req := &platformv1.DeleteZoneRequest{}

	_, err := service.DeleteZone(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing zone name")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestDNSGRPCService_DeleteZone_ServiceError(t *testing.T) {
	service, mock := newTestDNSService()
	mock.deleteZoneErr = errors.New("deletion failed")
	ctx := context.Background()

	req := &platformv1.DeleteZoneRequest{Name: "test.example.com."}

	_, err := service.DeleteZone(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.Internal {
		t.Errorf("Expected Internal error, got %v", st.Code())
	}
}

// Test ListZones

func TestDNSGRPCService_ListZones_Success(t *testing.T) {
	service, mock := newTestDNSService()
	ctx := context.Background()

	mock.zones["zone1.example.com."] = &entities.Zone{ID: 1, Name: "zone1.example.com.", Internal: false}
	mock.zones["zone2.example.com."] = &entities.Zone{ID: 2, Name: "zone2.example.com.", Internal: true}

	req := &platformv1.ListZonesRequest{}

	resp, err := service.ListZones(ctx, req)
	if err != nil {
		t.Fatalf("ListZones failed: %v", err)
	}

	if len(resp.GetZones()) != 2 {
		t.Errorf("Expected 2 zones, got %d", len(resp.GetZones()))
	}
}

func TestDNSGRPCService_ListZones_InternalOnly(t *testing.T) {
	service, mock := newTestDNSService()
	ctx := context.Background()

	mock.zones["public.example.com."] = &entities.Zone{ID: 1, Name: "public.example.com.", Internal: false}
	mock.zones["internal.example.com."] = &entities.Zone{ID: 2, Name: "internal.example.com.", Internal: true}

	req := &platformv1.ListZonesRequest{InternalOnly: true}

	resp, err := service.ListZones(ctx, req)
	if err != nil {
		t.Fatalf("ListZones failed: %v", err)
	}

	if len(resp.GetZones()) != 1 {
		t.Errorf("Expected 1 internal zone, got %d", len(resp.GetZones()))
	}

	if !resp.GetZones()[0].GetInternal() {
		t.Error("Expected internal zone")
	}
}

func TestDNSGRPCService_ListZones_PublicOnly(t *testing.T) {
	service, mock := newTestDNSService()
	ctx := context.Background()

	mock.zones["public.example.com."] = &entities.Zone{ID: 1, Name: "public.example.com.", Internal: false}
	mock.zones["internal.example.com."] = &entities.Zone{ID: 2, Name: "internal.example.com.", Internal: true}

	req := &platformv1.ListZonesRequest{PublicOnly: true}

	resp, err := service.ListZones(ctx, req)
	if err != nil {
		t.Fatalf("ListZones failed: %v", err)
	}

	if len(resp.GetZones()) != 1 {
		t.Errorf("Expected 1 public zone, got %d", len(resp.GetZones()))
	}

	if resp.GetZones()[0].GetInternal() {
		t.Error("Expected public zone")
	}
}

func TestDNSGRPCService_ListZones_WithPagination(t *testing.T) {
	service, mock := newTestDNSService()
	ctx := context.Background()

	for i := 1; i <= 10; i++ {
		name := "zone" + string(rune('0'+i)) + ".example.com."
		mock.zones[name] = &entities.Zone{ID: uint64(i), Name: name}
	}

	req := &platformv1.ListZonesRequest{
		Pagination: &platformv1.PaginationRequest{
			Page:     1,
			PageSize: 3,
		},
	}

	resp, err := service.ListZones(ctx, req)
	if err != nil {
		t.Fatalf("ListZones failed: %v", err)
	}

	if len(resp.GetZones()) != 3 {
		t.Errorf("Expected 3 zones, got %d", len(resp.GetZones()))
	}

	if resp.GetPagination() == nil {
		t.Error("Expected pagination in response")
	}

	if resp.GetPagination().GetTotalItems() != 10 {
		t.Errorf("Expected total_items 10, got %d", resp.GetPagination().GetTotalItems())
	}

	if resp.GetPagination().GetTotalPages() != 4 {
		t.Errorf("Expected total_pages 4, got %d", resp.GetPagination().GetTotalPages())
	}

	if resp.GetPagination().GetPage() != 1 {
		t.Errorf("Expected page 1, got %d", resp.GetPagination().GetPage())
	}

	if resp.GetPagination().GetPageSize() != 3 {
		t.Errorf("Expected page_size 3, got %d", resp.GetPagination().GetPageSize())
	}
}

func TestDNSGRPCService_ListZones_WithPagination_Page2(t *testing.T) {
	service, mock := newTestDNSService()
	ctx := context.Background()

	for i := 1; i <= 10; i++ {
		name := "zone" + string(rune('0'+i)) + ".example.com."
		mock.zones[name] = &entities.Zone{ID: uint64(i), Name: name}
	}

	req := &platformv1.ListZonesRequest{
		Pagination: &platformv1.PaginationRequest{
			Page:     2,
			PageSize: 3,
		},
	}

	resp, err := service.ListZones(ctx, req)
	if err != nil {
		t.Fatalf("ListZones failed: %v", err)
	}

	if len(resp.GetZones()) != 3 {
		t.Errorf("Expected 3 zones, got %d", len(resp.GetZones()))
	}

	if resp.GetPagination().GetPage() != 2 {
		t.Errorf("Expected page 2, got %d", resp.GetPagination().GetPage())
	}
}

func TestDNSGRPCService_ListZones_WithPagination_LastPage(t *testing.T) {
	service, mock := newTestDNSService()
	ctx := context.Background()

	for i := 1; i <= 10; i++ {
		name := "zone" + string(rune('0'+i)) + ".example.com."
		mock.zones[name] = &entities.Zone{ID: uint64(i), Name: name}
	}

	req := &platformv1.ListZonesRequest{
		Pagination: &platformv1.PaginationRequest{
			Page:     4,
			PageSize: 3,
		},
	}

	resp, err := service.ListZones(ctx, req)
	if err != nil {
		t.Fatalf("ListZones failed: %v", err)
	}

	// Last page should have only 1 item (10 total, 3 per page = pages of 3,3,3,1)
	if len(resp.GetZones()) != 1 {
		t.Errorf("Expected 1 zone on last page, got %d", len(resp.GetZones()))
	}
}

func TestDNSGRPCService_ListZones_ServiceError(t *testing.T) {
	service, mock := newTestDNSService()
	mock.listZonesErr = errors.New("database error")
	ctx := context.Background()

	req := &platformv1.ListZonesRequest{}

	_, err := service.ListZones(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}
}

// Test AddRecord

func TestDNSGRPCService_AddRecord_Success(t *testing.T) {
	service, mock := newTestDNSService()
	ctx := context.Background()

	mock.zones["example.com."] = &entities.Zone{ID: 1, Name: "example.com."}

	req := &platformv1.AddRecordRequest{
		ZoneName: "example.com.",
		Record: &platformv1.Record{
			Type: platformv1.RecordType_RECORD_TYPE_A,
			Record: &platformv1.Record_A{
				A: &platformv1.ARecord{
					Name:  "www",
					Value: "192.168.1.1",
					Ttl:   3600,
				},
			},
		},
	}

	resp, err := service.AddRecord(ctx, req)
	if err != nil {
		t.Fatalf("AddRecord failed: %v", err)
	}

	if resp.GetStatus() == nil || !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}
}

func TestDNSGRPCService_AddRecord_AAAARecord(t *testing.T) {
	service, mock := newTestDNSService()
	ctx := context.Background()

	mock.zones["example.com."] = &entities.Zone{ID: 1, Name: "example.com."}

	req := &platformv1.AddRecordRequest{
		ZoneName: "example.com.",
		Record: &platformv1.Record{
			Type: platformv1.RecordType_RECORD_TYPE_AAAA,
			Record: &platformv1.Record_Aaaa{
				Aaaa: &platformv1.AAAARecord{
					Name:  "www",
					Value: "2001:db8::1",
					Ttl:   3600,
				},
			},
		},
	}

	resp, err := service.AddRecord(ctx, req)
	if err != nil {
		t.Fatalf("AddRecord failed: %v", err)
	}

	if resp.GetStatus() == nil || !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}
}

func TestDNSGRPCService_AddRecord_MissingZoneName(t *testing.T) {
	service, _ := newTestDNSService()
	ctx := context.Background()

	req := &platformv1.AddRecordRequest{
		Record: &platformv1.Record{
			Type: platformv1.RecordType_RECORD_TYPE_A,
			Record: &platformv1.Record_A{
				A: &platformv1.ARecord{Name: "www", Value: "192.168.1.1"},
			},
		},
	}

	_, err := service.AddRecord(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing zone name")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestDNSGRPCService_AddRecord_MissingRecord(t *testing.T) {
	service, _ := newTestDNSService()
	ctx := context.Background()

	req := &platformv1.AddRecordRequest{
		ZoneName: "example.com.",
	}

	_, err := service.AddRecord(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing record")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestDNSGRPCService_AddRecord_ServiceError(t *testing.T) {
	service, mock := newTestDNSService()
	mock.addRecordErr = errors.New("add record failed")
	mock.zones["example.com."] = &entities.Zone{ID: 1, Name: "example.com."}
	ctx := context.Background()

	req := &platformv1.AddRecordRequest{
		ZoneName: "example.com.",
		Record: &platformv1.Record{
			Type: platformv1.RecordType_RECORD_TYPE_A,
			Record: &platformv1.Record_A{
				A: &platformv1.ARecord{Name: "www", Value: "192.168.1.1"},
			},
		},
	}

	_, err := service.AddRecord(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}
}

// Test DeleteRecord

func TestDNSGRPCService_DeleteRecord_Success(t *testing.T) {
	service, mock := newTestDNSService()
	ctx := context.Background()

	mock.zones["example.com."] = &entities.Zone{ID: 1, Name: "example.com."}

	req := &platformv1.DeleteRecordRequest{
		ZoneName: "example.com.",
		Type:     platformv1.RecordType_RECORD_TYPE_A,
		Name:     "www",
	}

	resp, err := service.DeleteRecord(ctx, req)
	if err != nil {
		t.Fatalf("DeleteRecord failed: %v", err)
	}

	if resp.GetStatus() == nil || !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}
}

func TestDNSGRPCService_DeleteRecord_MissingZoneName(t *testing.T) {
	service, _ := newTestDNSService()
	ctx := context.Background()

	req := &platformv1.DeleteRecordRequest{
		Type: platformv1.RecordType_RECORD_TYPE_A,
		Name: "www",
	}

	_, err := service.DeleteRecord(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing zone name")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestDNSGRPCService_DeleteRecord_MissingName(t *testing.T) {
	service, _ := newTestDNSService()
	ctx := context.Background()

	req := &platformv1.DeleteRecordRequest{
		ZoneName: "example.com.",
		Type:     platformv1.RecordType_RECORD_TYPE_A,
	}

	_, err := service.DeleteRecord(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing record name")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestDNSGRPCService_DeleteRecord_MissingType(t *testing.T) {
	service, _ := newTestDNSService()
	ctx := context.Background()

	req := &platformv1.DeleteRecordRequest{
		ZoneName: "example.com.",
		Name:     "www",
	}

	_, err := service.DeleteRecord(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing record type")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// Test UpdateRecord

func TestDNSGRPCService_UpdateRecord_Success(t *testing.T) {
	service, mock := newTestDNSService()
	ctx := context.Background()

	mock.zones["example.com."] = &entities.Zone{ID: 1, Name: "example.com."}

	req := &platformv1.UpdateRecordRequest{
		ZoneName: "example.com.",
		OldRecord: &platformv1.Record{
			Type: platformv1.RecordType_RECORD_TYPE_A,
			Record: &platformv1.Record_A{
				A: &platformv1.ARecord{Name: "www", Value: "192.168.1.1"},
			},
		},
		NewRecord: &platformv1.Record{
			Type: platformv1.RecordType_RECORD_TYPE_A,
			Record: &platformv1.Record_A{
				A: &platformv1.ARecord{Name: "www", Value: "192.168.1.2", Ttl: 7200},
			},
		},
	}

	resp, err := service.UpdateRecord(ctx, req)
	if err != nil {
		t.Fatalf("UpdateRecord failed: %v", err)
	}

	if resp.GetStatus() == nil || !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}
}

func TestDNSGRPCService_UpdateRecord_MissingOldRecord(t *testing.T) {
	service, _ := newTestDNSService()
	ctx := context.Background()

	req := &platformv1.UpdateRecordRequest{
		ZoneName: "example.com.",
		NewRecord: &platformv1.Record{
			Type: platformv1.RecordType_RECORD_TYPE_A,
			Record: &platformv1.Record_A{
				A: &platformv1.ARecord{Name: "www", Value: "192.168.1.2"},
			},
		},
	}

	_, err := service.UpdateRecord(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing old record")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestDNSGRPCService_UpdateRecord_MissingNewRecord(t *testing.T) {
	service, _ := newTestDNSService()
	ctx := context.Background()

	req := &platformv1.UpdateRecordRequest{
		ZoneName: "example.com.",
		OldRecord: &platformv1.Record{
			Type: platformv1.RecordType_RECORD_TYPE_A,
			Record: &platformv1.Record_A{
				A: &platformv1.ARecord{Name: "www", Value: "192.168.1.1"},
			},
		},
	}

	_, err := service.UpdateRecord(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing new record")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// Test ListRecords

func TestDNSGRPCService_ListRecords_Success(t *testing.T) {
	service, mock := newTestDNSService()
	ctx := context.Background()

	mock.zones["example.com."] = &entities.Zone{ID: 1, Name: "example.com."}

	req := &platformv1.ListRecordsRequest{
		ZoneName: "example.com.",
	}

	resp, err := service.ListRecords(ctx, req)
	if err != nil {
		t.Fatalf("ListRecords failed: %v", err)
	}

	if len(resp.GetRecords()) == 0 {
		t.Error("Expected records in response")
	}
}

func TestDNSGRPCService_ListRecords_FilterByType(t *testing.T) {
	service, mock := newTestDNSService()
	ctx := context.Background()

	mock.zones["example.com."] = &entities.Zone{ID: 1, Name: "example.com."}

	req := &platformv1.ListRecordsRequest{
		ZoneName: "example.com.",
		Type:     platformv1.RecordType_RECORD_TYPE_A,
	}

	resp, err := service.ListRecords(ctx, req)
	if err != nil {
		t.Fatalf("ListRecords failed: %v", err)
	}

	for _, rec := range resp.GetRecords() {
		if rec.GetType() != platformv1.RecordType_RECORD_TYPE_A {
			t.Errorf("Expected only A records, got %v", rec.GetType())
		}
	}
}

func TestDNSGRPCService_ListRecords_MissingZoneName(t *testing.T) {
	service, _ := newTestDNSService()
	ctx := context.Background()

	req := &platformv1.ListRecordsRequest{}

	_, err := service.ListRecords(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing zone name")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// Test SignZone

func TestDNSGRPCService_SignZone_Success(t *testing.T) {
	service, mock := newTestDNSService()
	ctx := context.Background()

	mock.zones["example.com."] = &entities.Zone{ID: 1, Name: "example.com."}

	req := &platformv1.SignZoneRequest{
		ZoneName: "example.com.",
	}

	resp, err := service.SignZone(ctx, req)
	if err != nil {
		t.Fatalf("SignZone failed: %v", err)
	}

	if resp.GetStatus() == nil || !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}
}

func TestDNSGRPCService_SignZone_MissingZoneName(t *testing.T) {
	service, _ := newTestDNSService()
	ctx := context.Background()

	req := &platformv1.SignZoneRequest{}

	_, err := service.SignZone(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing zone name")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestDNSGRPCService_SignZone_ZoneNotFound(t *testing.T) {
	service, _ := newTestDNSService()
	ctx := context.Background()

	req := &platformv1.SignZoneRequest{
		ZoneName: "nonexistent.example.com.",
	}

	_, err := service.SignZone(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nonexistent zone")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.NotFound {
		t.Errorf("Expected NotFound, got %v", st.Code())
	}
}

func TestDNSGRPCService_SignZone_ServiceError(t *testing.T) {
	service, mock := newTestDNSService()
	mock.signZoneErr = errors.New("signing failed")
	mock.zones["example.com."] = &entities.Zone{ID: 1, Name: "example.com."}
	ctx := context.Background()

	req := &platformv1.SignZoneRequest{
		ZoneName: "example.com.",
	}

	_, err := service.SignZone(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}
}

// Test GetDNSSECStatus

func TestDNSGRPCService_GetDNSSECStatus_Success(t *testing.T) {
	service, mock := newTestDNSService()
	ctx := context.Background()

	mock.zones["example.com."] = &entities.Zone{
		ID:   1,
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			RRSIGRecords: []*entities.RRSIGRecord{
				{TypeCovered: "A", Algorithm: 13, SignerName: "example.com."},
			},
			DNSKEYRecords: []*entities.DNSKEYRecord{
				{Name: "example.com.", Flags: 257, Protocol: 3, Algorithm: 13, Key: "testkey"},
			},
			DSRecords: []*entities.DSRecord{
				{Name: "example.com.", KeyTag: 12345, Algorithm: 13, DigestType: 2, Digest: "abc123"},
			},
		},
	}

	req := &platformv1.GetDNSSECStatusRequest{
		ZoneName: "example.com.",
	}

	resp, err := service.GetDNSSECStatus(ctx, req)
	if err != nil {
		t.Fatalf("GetDNSSECStatus failed: %v", err)
	}

	if resp.GetStatus() == nil {
		t.Error("Expected DNSSEC status in response")
	}

	if !resp.GetStatus().GetEnabled() {
		t.Error("Expected DNSSEC to be enabled")
	}

	if !resp.GetStatus().GetZoneSigned() {
		t.Error("Expected zone to be signed")
	}

	if len(resp.GetStatus().GetKeys()) != 1 {
		t.Errorf("Expected 1 DNSKEY, got %d", len(resp.GetStatus().GetKeys()))
	}

	if len(resp.GetStatus().GetDsRecords()) != 1 {
		t.Errorf("Expected 1 DS record, got %d", len(resp.GetStatus().GetDsRecords()))
	}
}

func TestDNSGRPCService_GetDNSSECStatus_MissingZoneName(t *testing.T) {
	service, _ := newTestDNSService()
	ctx := context.Background()

	req := &platformv1.GetDNSSECStatusRequest{}

	_, err := service.GetDNSSECStatus(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing zone name")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// Test Resolve

func TestDNSGRPCService_Resolve_Success(t *testing.T) {
	service, mock := newTestDNSService()
	ctx := context.Background()

	mock.zones["example.com."] = &entities.Zone{ID: 1, Name: "example.com."}

	req := &platformv1.ResolveRequest{
		Fqdn: "www.example.com.",
		Type: platformv1.RecordType_RECORD_TYPE_A,
	}

	resp, err := service.Resolve(ctx, req)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	if len(resp.GetRecords()) == 0 {
		t.Error("Expected records in response")
	}
}

func TestDNSGRPCService_Resolve_DefaultType(t *testing.T) {
	service, _ := newTestDNSService()
	ctx := context.Background()

	req := &platformv1.ResolveRequest{
		Fqdn: "www.example.com.",
	}

	resp, err := service.Resolve(ctx, req)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	if len(resp.GetRecords()) == 0 {
		t.Error("Expected records in response")
	}
}

func TestDNSGRPCService_Resolve_MissingFQDN(t *testing.T) {
	service, _ := newTestDNSService()
	ctx := context.Background()

	req := &platformv1.ResolveRequest{}

	_, err := service.Resolve(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing FQDN")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestDNSGRPCService_Resolve_ServiceError(t *testing.T) {
	service, mock := newTestDNSService()
	mock.resolveErr = errors.New("resolution failed")
	ctx := context.Background()

	req := &platformv1.ResolveRequest{
		Fqdn: "www.example.com.",
	}

	_, err := service.Resolve(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}
}

func TestDNSGRPCService_Resolve_AAAAType(t *testing.T) {
	service, _ := newTestDNSService()
	ctx := context.Background()

	req := &platformv1.ResolveRequest{
		Fqdn: "www.example.com.",
		Type: platformv1.RecordType_RECORD_TYPE_AAAA,
	}

	resp, err := service.Resolve(ctx, req)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	if len(resp.GetRecords()) == 0 {
		t.Error("Expected records in response")
	}
}

func TestDNSGRPCService_Resolve_TXTType(t *testing.T) {
	service, _ := newTestDNSService()
	ctx := context.Background()

	req := &platformv1.ResolveRequest{
		Fqdn: "www.example.com.",
		Type: platformv1.RecordType_RECORD_TYPE_TXT,
	}

	resp, err := service.Resolve(ctx, req)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	if len(resp.GetRecords()) == 0 {
		t.Error("Expected records in response")
	}
}

func TestDNSGRPCService_Resolve_CNAMEType(t *testing.T) {
	service, _ := newTestDNSService()
	ctx := context.Background()

	req := &platformv1.ResolveRequest{
		Fqdn: "www.example.com.",
		Type: platformv1.RecordType_RECORD_TYPE_CNAME,
	}

	resp, err := service.Resolve(ctx, req)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	if len(resp.GetRecords()) == 0 {
		t.Error("Expected records in response")
	}
}

func TestDNSGRPCService_Resolve_OtherType(t *testing.T) {
	service, _ := newTestDNSService()
	ctx := context.Background()

	req := &platformv1.ResolveRequest{
		Fqdn: "www.example.com.",
		Type: platformv1.RecordType_RECORD_TYPE_MX,
	}

	resp, err := service.Resolve(ctx, req)
	if err != nil {
		t.Fatalf("Resolve failed: %v", err)
	}

	if len(resp.GetRecords()) == 0 {
		t.Error("Expected records in response")
	}
}

// Test Register

func TestDNSGRPCService_Register_Success(t *testing.T) {
	service, _ := newTestDNSService()
	ctx := context.Background()

	req := &platformv1.RegisterRequest{
		Fqdn: "server1.example.com.",
		Ip:   "192.168.1.100",
	}

	resp, err := service.Register(ctx, req)
	if err != nil {
		t.Fatalf("Register failed: %v", err)
	}

	if resp.GetStatus() == nil || !resp.GetStatus().GetSuccess() {
		t.Error("Expected success status")
	}

	if resp.GetZone() == nil {
		t.Error("Expected zone in response")
	}
}

func TestDNSGRPCService_Register_MissingFQDN(t *testing.T) {
	service, _ := newTestDNSService()
	ctx := context.Background()

	req := &platformv1.RegisterRequest{
		Ip: "192.168.1.100",
	}

	_, err := service.Register(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing FQDN")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestDNSGRPCService_Register_MissingIP(t *testing.T) {
	service, _ := newTestDNSService()
	ctx := context.Background()

	req := &platformv1.RegisterRequest{
		Fqdn: "server1.example.com.",
	}

	_, err := service.Register(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing IP")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

func TestDNSGRPCService_Register_ServiceError(t *testing.T) {
	service, mock := newTestDNSService()
	mock.registerErr = errors.New("registration failed")
	ctx := context.Background()

	req := &platformv1.RegisterRequest{
		Fqdn: "server1.example.com.",
		Ip:   "192.168.1.100",
	}

	_, err := service.Register(ctx, req)
	if err == nil {
		t.Fatal("Expected error from service")
	}
}

// Test helper functions

func TestExtractRecordInfo_AllTypes(t *testing.T) {
	tests := []struct {
		name      string
		record    *platformv1.Record
		wantType  string
		wantName  string
		wantValue string
		wantTTL   uint32
		wantErr   bool
	}{
		{
			name: "A record",
			record: &platformv1.Record{
				Type: platformv1.RecordType_RECORD_TYPE_A,
				Record: &platformv1.Record_A{
					A: &platformv1.ARecord{Name: "www", Value: "192.168.1.1", Ttl: 3600},
				},
			},
			wantType:  "A",
			wantName:  "www",
			wantValue: "192.168.1.1",
			wantTTL:   3600,
		},
		{
			name: "AAAA record",
			record: &platformv1.Record{
				Type: platformv1.RecordType_RECORD_TYPE_AAAA,
				Record: &platformv1.Record_Aaaa{
					Aaaa: &platformv1.AAAARecord{Name: "www", Value: "::1", Ttl: 3600},
				},
			},
			wantType:  "AAAA",
			wantName:  "www",
			wantValue: "::1",
			wantTTL:   3600,
		},
		{
			name: "CNAME record",
			record: &platformv1.Record{
				Type: platformv1.RecordType_RECORD_TYPE_CNAME,
				Record: &platformv1.Record_Cname{
					Cname: &platformv1.CNAMERecord{Name: "alias", Value: "www.example.com", Ttl: 3600},
				},
			},
			wantType:  "CNAME",
			wantName:  "alias",
			wantValue: "www.example.com",
			wantTTL:   3600,
		},
		{
			name: "MX record",
			record: &platformv1.Record{
				Type: platformv1.RecordType_RECORD_TYPE_MX,
				Record: &platformv1.Record_Mx{
					Mx: &platformv1.MXRecord{Name: "@", Value: "mail.example.com", Ttl: 3600},
				},
			},
			wantType:  "MX",
			wantName:  "@",
			wantValue: "mail.example.com",
			wantTTL:   3600,
		},
		{
			name: "NS record",
			record: &platformv1.Record{
				Type: platformv1.RecordType_RECORD_TYPE_NS,
				Record: &platformv1.Record_Ns{
					Ns: &platformv1.NSRecord{Name: "@", Value: "ns1.example.com", Ttl: 86400},
				},
			},
			wantType:  "NS",
			wantName:  "@",
			wantValue: "ns1.example.com",
			wantTTL:   86400,
		},
		{
			name: "TXT record",
			record: &platformv1.Record{
				Type: platformv1.RecordType_RECORD_TYPE_TXT,
				Record: &platformv1.Record_Txt{
					Txt: &platformv1.TXTRecord{Name: "@", Value: "v=spf1", Ttl: 3600},
				},
			},
			wantType:  "TXT",
			wantName:  "@",
			wantValue: "v=spf1",
			wantTTL:   3600,
		},
		{
			name: "SRV record",
			record: &platformv1.Record{
				Type: platformv1.RecordType_RECORD_TYPE_SRV,
				Record: &platformv1.Record_Srv{
					Srv: &platformv1.SRVRecord{Name: "_ldap._tcp", Target: "ldap.example.com", Ttl: 3600},
				},
			},
			wantType:  "SRV",
			wantName:  "_ldap._tcp",
			wantValue: "ldap.example.com",
			wantTTL:   3600,
		},
		{
			name: "CAA record",
			record: &platformv1.Record{
				Type: platformv1.RecordType_RECORD_TYPE_CAA,
				Record: &platformv1.Record_Caa{
					Caa: &platformv1.CAARecord{Name: "@", Value: "letsencrypt.org", Ttl: 3600},
				},
			},
			wantType:  "CAA",
			wantName:  "@",
			wantValue: "letsencrypt.org",
			wantTTL:   3600,
		},
		{
			name: "TLSA record",
			record: &platformv1.Record{
				Type: platformv1.RecordType_RECORD_TYPE_TLSA,
				Record: &platformv1.Record_Tlsa{
					Tlsa: &platformv1.TLSARecord{Name: "_443._tcp", Data: "abc123", Ttl: 3600},
				},
			},
			wantType:  "TLSA",
			wantName:  "_443._tcp",
			wantValue: "abc123",
			wantTTL:   3600,
		},
		{
			name:    "nil record",
			record:  nil,
			wantErr: true,
		},
		{
			name: "nil A record inner",
			record: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_A,
				Record: &platformv1.Record_A{A: nil},
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotType, gotName, gotValue, gotTTL, err := extractRecordInfo(tt.record)

			if tt.wantErr {
				if err == nil {
					t.Error("Expected error")
				}
				return
			}

			if err != nil {
				t.Fatalf("Unexpected error: %v", err)
			}

			if gotType != tt.wantType {
				t.Errorf("Expected type %s, got %s", tt.wantType, gotType)
			}
			if gotName != tt.wantName {
				t.Errorf("Expected name %s, got %s", tt.wantName, gotName)
			}
			if gotValue != tt.wantValue {
				t.Errorf("Expected value %s, got %s", tt.wantValue, gotValue)
			}
			if gotTTL != tt.wantTTL {
				t.Errorf("Expected TTL %d, got %d", tt.wantTTL, gotTTL)
			}
		})
	}
}

func TestProtoRecordTypeToString(t *testing.T) {
	tests := []struct {
		input    platformv1.RecordType
		expected string
	}{
		{platformv1.RecordType_RECORD_TYPE_A, "A"},
		{platformv1.RecordType_RECORD_TYPE_AAAA, "AAAA"},
		{platformv1.RecordType_RECORD_TYPE_CNAME, "CNAME"},
		{platformv1.RecordType_RECORD_TYPE_MX, "MX"},
		{platformv1.RecordType_RECORD_TYPE_NS, "NS"},
		{platformv1.RecordType_RECORD_TYPE_TXT, "TXT"},
		{platformv1.RecordType_RECORD_TYPE_SRV, "SRV"},
		{platformv1.RecordType_RECORD_TYPE_SOA, "SOA"},
		{platformv1.RecordType_RECORD_TYPE_CAA, "CAA"},
		{platformv1.RecordType_RECORD_TYPE_TLSA, "TLSA"},
		{platformv1.RecordType_RECORD_TYPE_DNSKEY, "DNSKEY"},
		{platformv1.RecordType_RECORD_TYPE_DS, "DS"},
		{platformv1.RecordType_RECORD_TYPE_RRSIG, "RRSIG"},
		{platformv1.RecordType_RECORD_TYPE_NSEC, "NSEC"},
		{platformv1.RecordType_RECORD_TYPE_NSEC3, "NSEC3"},
		{platformv1.RecordType_RECORD_TYPE_NSEC3PARAM, "NSEC3PARAM"},
		{platformv1.RecordType_RECORD_TYPE_UNSPECIFIED, "A"},
	}

	for _, tt := range tests {
		t.Run(tt.expected, func(t *testing.T) {
			got := protoRecordTypeToString(tt.input)
			if got != tt.expected {
				t.Errorf("Expected %s, got %s", tt.expected, got)
			}
		})
	}
}

func TestEntityZoneToProto_Nil(t *testing.T) {
	result := entityZoneToProto(nil)
	if result != nil {
		t.Error("Expected nil result for nil input")
	}
}

func TestEntityRecordSetToProto_Nil(t *testing.T) {
	result := entityRecordSetToProto(nil)
	if result != nil {
		t.Error("Expected nil result for nil input")
	}
}

func TestEntityRecordToProto_Nil(t *testing.T) {
	result := entityRecordToProto(nil)
	if result != nil {
		t.Error("Expected nil result for nil input")
	}
}

func TestEntityRecordToProto_UnknownType(t *testing.T) {
	result := entityRecordToProto("unknown type")
	if result != nil {
		t.Error("Expected nil result for unknown type")
	}
}

func TestProtoSOAToEntity(t *testing.T) {
	soa := &platformv1.SOARecord{
		Name:       "example.com.",
		Mname:      "ns1.example.com.",
		Rname:      "admin.example.com.",
		Serial:     2024010101,
		Refresh:    7200,
		Retry:      3600,
		Expire:     1209600,
		MinimumTtl: 300,
		Ttl:        86400,
	}

	result := protoSOAToEntity(soa)

	if result.Name != soa.Name {
		t.Errorf("Expected name %s, got %s", soa.Name, result.Name)
	}
	if result.MName != soa.Mname {
		t.Errorf("Expected mname %s, got %s", soa.Mname, result.MName)
	}
	if result.RName != soa.Rname {
		t.Errorf("Expected rname %s, got %s", soa.Rname, result.RName)
	}
	if result.Serial != soa.Serial {
		t.Errorf("Expected serial %d, got %d", soa.Serial, result.Serial)
	}
}

func TestProtoSOAToEntity_Nil(t *testing.T) {
	result := protoSOAToEntity(nil)
	if result.Name != "" {
		t.Error("Expected empty SOARecord for nil input")
	}
}

// Test error types

func TestErrNilDNSService(t *testing.T) {
	err := ErrNilDNSService{}
	if err.Error() != "dns service is nil" {
		t.Errorf("Unexpected error message: %s", err.Error())
	}
}

func TestErrMissingZoneName(t *testing.T) {
	err := ErrMissingZoneName{}
	if err.Error() != "zone name is required" {
		t.Errorf("Unexpected error message: %s", err.Error())
	}
}

func TestErrMissingRecordName(t *testing.T) {
	err := ErrMissingRecordName{}
	if err.Error() != "record name is required" {
		t.Errorf("Unexpected error message: %s", err.Error())
	}
}

func TestErrMissingRecordType(t *testing.T) {
	err := ErrMissingRecordType{}
	if err.Error() != "record type is required" {
		t.Errorf("Unexpected error message: %s", err.Error())
	}
}

func TestErrMissingRecord(t *testing.T) {
	err := ErrMissingRecord{}
	if err.Error() != "record is required" {
		t.Errorf("Unexpected error message: %s", err.Error())
	}
}

func TestErrMissingFQDN(t *testing.T) {
	err := ErrMissingFQDN{}
	if err.Error() != "fqdn is required" {
		t.Errorf("Unexpected error message: %s", err.Error())
	}
}

func TestErrMissingIP(t *testing.T) {
	err := ErrMissingIP{}
	if err.Error() != "ip address is required" {
		t.Errorf("Unexpected error message: %s", err.Error())
	}
}

func TestErrInvalidRecordType(t *testing.T) {
	err := ErrInvalidRecordType{Type: "INVALID"}
	if err.Error() != "invalid record type: INVALID" {
		t.Errorf("Unexpected error message: %s", err.Error())
	}
}

func TestErrDNSOperationFailed(t *testing.T) {
	err := ErrDNSOperationFailed{Operation: "CreateZone", Cause: errors.New("database error")}
	expected := "dns operation CreateZone failed: database error"
	if err.Error() != expected {
		t.Errorf("Expected error message %s, got %s", expected, err.Error())
	}

	errNoCause := ErrDNSOperationFailed{Operation: "CreateZone"}
	expectedNoCause := "dns operation CreateZone failed"
	if errNoCause.Error() != expectedNoCause {
		t.Errorf("Expected error message %s, got %s", expectedNoCause, errNoCause.Error())
	}
}

// Test nil service checks for all methods

func TestDNSGRPCService_GetZone_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewDNSGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.GetZoneRequest{Name: "test.example.com."}

	_, err := service.GetZone(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestDNSGRPCService_UpdateZone_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewDNSGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.UpdateZoneRequest{Name: "test.example.com."}

	_, err := service.UpdateZone(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestDNSGRPCService_DeleteZone_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewDNSGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.DeleteZoneRequest{Name: "test.example.com."}

	_, err := service.DeleteZone(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestDNSGRPCService_ListZones_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewDNSGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.ListZonesRequest{}

	_, err := service.ListZones(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestDNSGRPCService_AddRecord_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewDNSGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.AddRecordRequest{ZoneName: "test.example.com."}

	_, err := service.AddRecord(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestDNSGRPCService_DeleteRecord_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewDNSGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.DeleteRecordRequest{ZoneName: "test.example.com."}

	_, err := service.DeleteRecord(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestDNSGRPCService_UpdateRecord_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewDNSGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.UpdateRecordRequest{ZoneName: "test.example.com."}

	_, err := service.UpdateRecord(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestDNSGRPCService_ListRecords_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewDNSGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.ListRecordsRequest{ZoneName: "test.example.com."}

	_, err := service.ListRecords(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestDNSGRPCService_SignZone_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewDNSGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.SignZoneRequest{ZoneName: "test.example.com."}

	_, err := service.SignZone(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestDNSGRPCService_GetDNSSECStatus_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewDNSGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.GetDNSSECStatusRequest{ZoneName: "test.example.com."}

	_, err := service.GetDNSSECStatus(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestDNSGRPCService_Resolve_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewDNSGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.ResolveRequest{Fqdn: "www.example.com."}

	_, err := service.Resolve(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

func TestDNSGRPCService_Register_NilService(t *testing.T) {
	logger := logging.NewLogger(slog.LevelError, io.Discard)
	service := NewDNSGRPCService(logger, nil)
	ctx := context.Background()

	req := &platformv1.RegisterRequest{Fqdn: "server1.example.com.", Ip: "192.168.1.100"}

	_, err := service.Register(ctx, req)
	if err == nil {
		t.Fatal("Expected error for nil service")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.FailedPrecondition {
		t.Errorf("Expected FailedPrecondition, got %v", st.Code())
	}
}

// Test mapError with different error conditions

func TestDNSGRPCService_MapError_AlreadyExists(t *testing.T) {
	service, mock := newTestDNSService()
	mock.createZoneErr = errors.New("zone already exists")
	ctx := context.Background()

	req := &platformv1.CreateZoneRequest{Name: "test.example.com."}

	_, err := service.CreateZone(ctx, req)
	if err == nil {
		t.Fatal("Expected error")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.AlreadyExists {
		t.Errorf("Expected AlreadyExists, got %v", st.Code())
	}
}

func TestDNSGRPCService_MapError_InvalidArgument(t *testing.T) {
	service, mock := newTestDNSService()
	mock.createZoneErr = errors.New("invalid zone name")
	ctx := context.Background()

	req := &platformv1.CreateZoneRequest{Name: "test.example.com."}

	_, err := service.CreateZone(ctx, req)
	if err == nil {
		t.Fatal("Expected error")
	}

	st, _ := status.FromError(err)
	if st.Code() != codes.InvalidArgument {
		t.Errorf("Expected InvalidArgument, got %v", st.Code())
	}
}

// Test entityRecordSetToProto with full record set

func TestEntityRecordSetToProto_FullRecordSet(t *testing.T) {
	rs := &entities.RecordSet{
		SOARecord: entities.SOARecord{
			Name:  "example.com.",
			MName: "ns1.example.com.",
		},
		ARecords:          []*entities.ARecord{{Name: "www", Value: "192.168.1.1", TTL: 3600}},
		AAAARecords:       []*entities.AAAARecord{{Name: "www", Value: "::1", TTL: 3600}},
		CNAMERecords:      []*entities.CNAMERecord{{Name: "alias", Value: "www.example.com", TTL: 3600}},
		MXRecords:         []*entities.MXRecord{{Name: "@", Value: "mail.example.com", Priority: 10, TTL: 3600}},
		NSRecords:         []*entities.NSRecord{{Name: "@", Value: "ns1.example.com", TTL: 86400}},
		TXTRecords:        []*entities.TXTRecord{{Name: "@", Value: "v=spf1", TTL: 3600}},
		SRVRecords:        []*entities.SRVRecord{{Name: "_ldap._tcp", Target: "ldap.example.com", Port: 389, TTL: 3600}},
		CAARecords:        []*entities.CAARecord{{Name: "@", Flags: 0, Tag: "issue", Value: "letsencrypt.org", TTL: 3600}},
		TLSARecords:       []*entities.TLSARecord{{Name: "_443._tcp", Usage: 3, Selector: 1, MatchingType: 1, Data: "abc", TTL: 3600}},
		DNSKEYRecords:     []*entities.DNSKEYRecord{{Name: "example.com.", Flags: 257, Protocol: 3, Algorithm: 13, Key: "key", TTL: 86400}},
		DSRecords:         []*entities.DSRecord{{Name: "example.com.", KeyTag: 12345, Algorithm: 13, DigestType: 2, Digest: "abc", TTL: 86400}},
		RRSIGRecords:      []*entities.RRSIGRecord{{TypeCovered: "A", Algorithm: 13, Labels: 2, SignerName: "example.com."}},
		NSECRecords:       []*entities.NSECRecord{{Name: "example.com.", NextDomain: "a.example.com.", TypeBitMap: []uint16{1, 2}, TTL: 3600}},
		NSEC3Records:      []*entities.NSEC3Record{{Name: "abc", Algorithm: 1, Flags: 0, Iterations: 10, Salt: "salt", NextHashed: "def", TypeBitMap: []uint16{1, 2}, TTL: 3600}},
		NSEC3PARAMRecords: []*entities.NSEC3PARAMRecord{{Name: "example.com.", Algorithm: 1, Flags: 0, Iterations: 10, Salt: "salt", TTL: 3600}},
	}

	result := entityRecordSetToProto(rs)

	if result.GetSoa() == nil {
		t.Error("Expected SOA record")
	}
	if len(result.GetARecords()) != 1 {
		t.Error("Expected 1 A record")
	}
	if len(result.GetAaaaRecords()) != 1 {
		t.Error("Expected 1 AAAA record")
	}
	if len(result.GetCnameRecords()) != 1 {
		t.Error("Expected 1 CNAME record")
	}
	if len(result.GetMxRecords()) != 1 {
		t.Error("Expected 1 MX record")
	}
	if len(result.GetNsRecords()) != 1 {
		t.Error("Expected 1 NS record")
	}
	if len(result.GetTxtRecords()) != 1 {
		t.Error("Expected 1 TXT record")
	}
	if len(result.GetSrvRecords()) != 1 {
		t.Error("Expected 1 SRV record")
	}
	if len(result.GetCaaRecords()) != 1 {
		t.Error("Expected 1 CAA record")
	}
	if len(result.GetTlsaRecords()) != 1 {
		t.Error("Expected 1 TLSA record")
	}
	if len(result.GetDnskeyRecords()) != 1 {
		t.Error("Expected 1 DNSKEY record")
	}
	if len(result.GetDsRecords()) != 1 {
		t.Error("Expected 1 DS record")
	}
	if len(result.GetRrsigRecords()) != 1 {
		t.Error("Expected 1 RRSIG record")
	}
	if len(result.GetNsecRecords()) != 1 {
		t.Error("Expected 1 NSEC record")
	}
	if len(result.GetNsec3Records()) != 1 {
		t.Error("Expected 1 NSEC3 record")
	}
	if len(result.GetNsec3ParamRecords()) != 1 {
		t.Error("Expected 1 NSEC3PARAM record")
	}
}

// Test entityDNSKEYToProto and entityDSToProto nil handling

func TestEntityDNSKEYToProto_Nil(t *testing.T) {
	result := entityDNSKEYToProto(nil)
	if result != nil {
		t.Error("Expected nil result for nil input")
	}
}

func TestEntityDSToProto_Nil(t *testing.T) {
	result := entityDSToProto(nil)
	if result != nil {
		t.Error("Expected nil result for nil input")
	}
}

// Test extractRecordInfo with invalid record type

func TestExtractRecordInfo_InvalidType(t *testing.T) {
	record := &platformv1.Record{
		Type:   platformv1.RecordType_RECORD_TYPE_DNSKEY,
		Record: nil,
	}

	_, _, _, _, err := extractRecordInfo(record)
	if err == nil {
		t.Error("Expected error for invalid record type")
	}
}

// Test updateRecord with service errors

func TestDNSGRPCService_UpdateRecord_ZoneMissing(t *testing.T) {
	service, _ := newTestDNSService()
	ctx := context.Background()

	req := &platformv1.UpdateRecordRequest{
		ZoneName: "nonexistent.example.com.",
		OldRecord: &platformv1.Record{
			Type: platformv1.RecordType_RECORD_TYPE_A,
			Record: &platformv1.Record_A{
				A: &platformv1.ARecord{Name: "www", Value: "192.168.1.1"},
			},
		},
		NewRecord: &platformv1.Record{
			Type: platformv1.RecordType_RECORD_TYPE_A,
			Record: &platformv1.Record_A{
				A: &platformv1.ARecord{Name: "www", Value: "192.168.1.2"},
			},
		},
	}

	_, err := service.UpdateRecord(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing zone")
	}
}

func TestDNSGRPCService_UpdateRecord_MissingZoneName(t *testing.T) {
	service, _ := newTestDNSService()
	ctx := context.Background()

	req := &platformv1.UpdateRecordRequest{
		OldRecord: &platformv1.Record{
			Type: platformv1.RecordType_RECORD_TYPE_A,
			Record: &platformv1.Record_A{
				A: &platformv1.ARecord{Name: "www", Value: "192.168.1.1"},
			},
		},
		NewRecord: &platformv1.Record{
			Type: platformv1.RecordType_RECORD_TYPE_A,
			Record: &platformv1.Record_A{
				A: &platformv1.ARecord{Name: "www", Value: "192.168.1.2"},
			},
		},
	}

	_, err := service.UpdateRecord(ctx, req)
	if err == nil {
		t.Fatal("Expected error for missing zone name")
	}
}

func TestDNSGRPCService_UpdateRecord_AddRecordError(t *testing.T) {
	service, mock := newTestDNSService()
	mock.zones["example.com."] = &entities.Zone{ID: 1, Name: "example.com."}
	mock.addRecordErr = errors.New("add record failed")
	ctx := context.Background()

	req := &platformv1.UpdateRecordRequest{
		ZoneName: "example.com.",
		OldRecord: &platformv1.Record{
			Type: platformv1.RecordType_RECORD_TYPE_A,
			Record: &platformv1.Record_A{
				A: &platformv1.ARecord{Name: "www", Value: "192.168.1.1"},
			},
		},
		NewRecord: &platformv1.Record{
			Type: platformv1.RecordType_RECORD_TYPE_A,
			Record: &platformv1.Record_A{
				A: &platformv1.ARecord{Name: "www", Value: "192.168.1.2"},
			},
		},
	}

	_, err := service.UpdateRecord(ctx, req)
	if err == nil {
		t.Fatal("Expected error for add record failure")
	}
}

// Test interface compliance
var _ platformv1.DNSServiceServer = (*DNSGRPCService)(nil)

// =============================================================================
// Helper Function Tests
// =============================================================================

func TestDNSTimestamp(t *testing.T) {
	t.Parallel()

	before := time.Now().UTC().Unix()
	result := dnsTimestamp()
	after := time.Now().UTC().Unix()

	// The timestamp should be within the range [before, after]
	if result < before || result > after {
		t.Errorf("timestamp %d not in expected range [%d, %d]", result, before, after)
	}
}
