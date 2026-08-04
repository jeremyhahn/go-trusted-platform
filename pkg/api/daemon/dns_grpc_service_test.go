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

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// mockDNSService implements dns.DNSService for testing
type mockDNSService struct {
	zones         map[string]*entities.Zone
	saveErr       error
	deleteErr     error
	zoneErr       error
	listErr       error
	registerErr   error
	signErr       error
	dnssecEnabled bool
}

func newMockDNSService() *mockDNSService {
	return &mockDNSService{
		zones: make(map[string]*entities.Zone),
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
	if m.saveErr != nil {
		return m.saveErr
	}
	m.zones[zone.Name] = zone
	return nil
}

func (m *mockDNSService) SignZone(zone *entities.Zone) error {
	if m.signErr != nil {
		return m.signErr
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
	zone := &entities.Zone{
		Name: fqdn,
	}
	m.zones[fqdn] = zone
	return zone, nil
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

func (m *mockDNSService) AddRecord(ctx context.Context, name string, recordType string, value string, ttl int) error {
	return nil
}

func (m *mockDNSService) DeleteRecord(ctx context.Context, name string, recordType string) error {
	return nil
}

func (m *mockDNSService) CreateZone(ctx context.Context, zoneName string) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.zones[zoneName] = &entities.Zone{Name: zoneName}
	return nil
}

func (m *mockDNSService) DeleteZone(ctx context.Context, zoneName string) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.zones, zoneName)
	return nil
}

func (m *mockDNSService) GetRecord(ctx context.Context, name string, recordType string) (interface{}, error) {
	return nil, nil
}

func (m *mockDNSService) ListRecords(ctx context.Context, zone string) ([]interface{}, error) {
	return nil, nil
}

func (m *mockDNSService) Resolve(ctx context.Context, name string, recordType string) ([]string, error) {
	return nil, nil
}

func (m *mockDNSService) RegisterWithNetworkZone(ctx context.Context, host, networkZone, ip string) error {
	return nil
}

// Test helper to create logger
func testLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError}))
}

// Zone CRUD Tests

func TestDNSServiceServer_CreateZone_Success(t *testing.T) {
	mock := newMockDNSService()
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.CreateZoneRequest{
		Name:        "example.com.",
		Ttl:         3600,
		Description: "Test zone",
		Internal:    false,
		Soa: &platformv1.SOARecord{
			Name:       "example.com.",
			Mname:      "ns1.example.com.",
			Rname:      "hostmaster.example.com.",
			Serial:     1,
			Refresh:    86400,
			Retry:      7200,
			Expire:     86400,
			MinimumTtl: 3600,
			Ttl:        3600,
		},
	}

	resp, err := server.CreateZone(context.Background(), req)

	require.NoError(t, err)
	assert.True(t, resp.Status.Success)
	assert.Equal(t, "example.com.", resp.Zone.Name)
	assert.Equal(t, uint32(3600), resp.Zone.Ttl)
}

func TestDNSServiceServer_CreateZone_WithNSRecords(t *testing.T) {
	mock := newMockDNSService()
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.CreateZoneRequest{
		Name:        "example.com.",
		Ttl:         3600,
		Description: "Test zone with NS records",
		Internal:    false,
		Soa: &platformv1.SOARecord{
			Name:       "example.com.",
			Mname:      "ns1.example.com.",
			Rname:      "hostmaster.example.com.",
			Serial:     1,
			Refresh:    86400,
			Retry:      7200,
			Expire:     86400,
			MinimumTtl: 3600,
			Ttl:        3600,
		},
		NsRecords: []*platformv1.NSRecord{
			{Name: "@", Value: "ns1.example.com.", Ttl: 3600},
			{Name: "@", Value: "ns2.example.com.", Ttl: 3600},
		},
	}

	resp, err := server.CreateZone(context.Background(), req)

	require.NoError(t, err)
	assert.True(t, resp.Status.Success)
	assert.NotNil(t, resp.Zone.Records)
	assert.Len(t, resp.Zone.Records.NsRecords, 2)
}

func TestDNSServiceServer_CreateZone_MissingName(t *testing.T) {
	mock := newMockDNSService()
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.CreateZoneRequest{}

	_, err := server.CreateZone(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestDNSServiceServer_CreateZone_SaveError(t *testing.T) {
	mock := newMockDNSService()
	mock.saveErr = errors.New("save failed")
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.CreateZoneRequest{
		Name: "example.com.",
	}

	_, err := server.CreateZone(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

func TestDNSServiceServer_GetZone_Success(t *testing.T) {
	mock := newMockDNSService()
	mock.zones["example.com."] = &entities.Zone{
		ID:          1,
		Name:        "example.com.",
		TTL:         3600,
		Description: "Test zone",
	}
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.GetZoneRequest{Name: "example.com."}

	resp, err := server.GetZone(context.Background(), req)

	require.NoError(t, err)
	assert.Equal(t, "example.com.", resp.Zone.Name)
}

func TestDNSServiceServer_GetZone_NotFound(t *testing.T) {
	mock := newMockDNSService()
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.GetZoneRequest{Name: "nonexistent.com."}

	_, err := server.GetZone(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestDNSServiceServer_GetZone_MissingName(t *testing.T) {
	mock := newMockDNSService()
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.GetZoneRequest{}

	_, err := server.GetZone(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestDNSServiceServer_UpdateZone_Success(t *testing.T) {
	mock := newMockDNSService()
	mock.zones["example.com."] = &entities.Zone{
		ID:   1,
		Name: "example.com.",
		TTL:  3600,
	}
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.UpdateZoneRequest{
		Name:        "example.com.",
		Ttl:         7200,
		Description: "Updated description",
	}

	resp, err := server.UpdateZone(context.Background(), req)

	require.NoError(t, err)
	assert.True(t, resp.Status.Success)
	assert.Equal(t, uint32(7200), resp.Zone.Ttl)
	assert.Equal(t, "Updated description", resp.Zone.Description)
}

func TestDNSServiceServer_UpdateZone_NotFound(t *testing.T) {
	mock := newMockDNSService()
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.UpdateZoneRequest{Name: "nonexistent.com."}

	_, err := server.UpdateZone(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestDNSServiceServer_UpdateZone_MissingName(t *testing.T) {
	mock := newMockDNSService()
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.UpdateZoneRequest{}

	_, err := server.UpdateZone(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestDNSServiceServer_UpdateZone_SaveError(t *testing.T) {
	mock := newMockDNSService()
	mock.zones["example.com."] = &entities.Zone{
		ID:   1,
		Name: "example.com.",
		TTL:  3600,
	}
	mock.saveErr = errors.New("save failed")
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.UpdateZoneRequest{
		Name: "example.com.",
		Ttl:  7200,
	}

	_, err := server.UpdateZone(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

func TestDNSServiceServer_DeleteZone_Success(t *testing.T) {
	mock := newMockDNSService()
	mock.zones["example.com."] = &entities.Zone{
		ID:   1,
		Name: "example.com.",
	}
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.DeleteZoneRequest{Name: "example.com."}

	resp, err := server.DeleteZone(context.Background(), req)

	require.NoError(t, err)
	assert.True(t, resp.Status.Success)
	_, exists := mock.zones["example.com."]
	assert.False(t, exists)
}

func TestDNSServiceServer_DeleteZone_NotFound(t *testing.T) {
	mock := newMockDNSService()
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.DeleteZoneRequest{Name: "nonexistent.com."}

	_, err := server.DeleteZone(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestDNSServiceServer_DeleteZone_MissingName(t *testing.T) {
	mock := newMockDNSService()
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.DeleteZoneRequest{}

	_, err := server.DeleteZone(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestDNSServiceServer_DeleteZone_DeleteError(t *testing.T) {
	mock := newMockDNSService()
	mock.zones["example.com."] = &entities.Zone{
		ID:   1,
		Name: "example.com.",
	}
	mock.deleteErr = errors.New("delete failed")
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.DeleteZoneRequest{Name: "example.com."}

	_, err := server.DeleteZone(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

func TestDNSServiceServer_ListZones_Success(t *testing.T) {
	mock := newMockDNSService()
	mock.zones["internal.example.com."] = &entities.Zone{
		ID:       1,
		Name:     "internal.example.com.",
		Internal: true,
	}
	mock.zones["public.example.com."] = &entities.Zone{
		ID:       2,
		Name:     "public.example.com.",
		Internal: false,
	}
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.ListZonesRequest{}

	resp, err := server.ListZones(context.Background(), req)

	require.NoError(t, err)
	assert.Len(t, resp.Zones, 2)
}

func TestDNSServiceServer_ListZones_InternalOnly(t *testing.T) {
	mock := newMockDNSService()
	mock.zones["internal.example.com."] = &entities.Zone{
		ID:       1,
		Name:     "internal.example.com.",
		Internal: true,
	}
	mock.zones["public.example.com."] = &entities.Zone{
		ID:       2,
		Name:     "public.example.com.",
		Internal: false,
	}
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.ListZonesRequest{InternalOnly: true}

	resp, err := server.ListZones(context.Background(), req)

	require.NoError(t, err)
	assert.Len(t, resp.Zones, 1)
	assert.True(t, resp.Zones[0].Internal)
}

func TestDNSServiceServer_ListZones_PublicOnly(t *testing.T) {
	mock := newMockDNSService()
	mock.zones["internal.example.com."] = &entities.Zone{
		ID:       1,
		Name:     "internal.example.com.",
		Internal: true,
	}
	mock.zones["public.example.com."] = &entities.Zone{
		ID:       2,
		Name:     "public.example.com.",
		Internal: false,
	}
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.ListZonesRequest{PublicOnly: true}

	resp, err := server.ListZones(context.Background(), req)

	require.NoError(t, err)
	assert.Len(t, resp.Zones, 1)
	assert.False(t, resp.Zones[0].Internal)
}

func TestDNSServiceServer_ListZones_Error(t *testing.T) {
	mock := newMockDNSService()
	mock.listErr = errors.New("list failed")
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.ListZonesRequest{}

	_, err := server.ListZones(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

// Record Tests

func TestDNSServiceServer_AddRecord_Success(t *testing.T) {
	mock := newMockDNSService()
	mock.zones["example.com."] = &entities.Zone{
		ID:   1,
		Name: "example.com.",
	}
	server := NewDNSServiceServer(mock, testLogger())

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

	resp, err := server.AddRecord(context.Background(), req)

	require.NoError(t, err)
	assert.True(t, resp.Status.Success)
	assert.Len(t, resp.Zone.Records.ARecords, 1)
	assert.Equal(t, "www", resp.Zone.Records.ARecords[0].Name)
}

func TestDNSServiceServer_AddRecord_AllTypes(t *testing.T) {
	mock := newMockDNSService()
	server := NewDNSServiceServer(mock, testLogger())

	tests := []struct {
		name       string
		recordType platformv1.RecordType
		record     *platformv1.Record
	}{
		{
			name:       "A record",
			recordType: platformv1.RecordType_RECORD_TYPE_A,
			record: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_A,
				Record: &platformv1.Record_A{A: &platformv1.ARecord{Name: "www", Value: "192.168.1.1", Ttl: 3600}},
			},
		},
		{
			name:       "AAAA record",
			recordType: platformv1.RecordType_RECORD_TYPE_AAAA,
			record: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_AAAA,
				Record: &platformv1.Record_Aaaa{Aaaa: &platformv1.AAAARecord{Name: "www", Value: "::1", Ttl: 3600}},
			},
		},
		{
			name:       "CNAME record",
			recordType: platformv1.RecordType_RECORD_TYPE_CNAME,
			record: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_CNAME,
				Record: &platformv1.Record_Cname{Cname: &platformv1.CNAMERecord{Name: "alias", Value: "www.example.com.", Ttl: 3600}},
			},
		},
		{
			name:       "MX record",
			recordType: platformv1.RecordType_RECORD_TYPE_MX,
			record: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_MX,
				Record: &platformv1.Record_Mx{Mx: &platformv1.MXRecord{Name: "@", Value: "mail.example.com.", Priority: 10, Ttl: 3600}},
			},
		},
		{
			name:       "NS record",
			recordType: platformv1.RecordType_RECORD_TYPE_NS,
			record: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_NS,
				Record: &platformv1.Record_Ns{Ns: &platformv1.NSRecord{Name: "@", Value: "ns1.example.com.", Ttl: 3600}},
			},
		},
		{
			name:       "TXT record",
			recordType: platformv1.RecordType_RECORD_TYPE_TXT,
			record: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_TXT,
				Record: &platformv1.Record_Txt{Txt: &platformv1.TXTRecord{Name: "@", Value: "v=spf1 include:_spf.example.com ~all", Ttl: 3600}},
			},
		},
		{
			name:       "SRV record",
			recordType: platformv1.RecordType_RECORD_TYPE_SRV,
			record: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_SRV,
				Record: &platformv1.Record_Srv{Srv: &platformv1.SRVRecord{Name: "_sip._tcp", Target: "sip.example.com.", Port: 5060, Priority: 10, Weight: 20, Ttl: 3600}},
			},
		},
		{
			name:       "CAA record",
			recordType: platformv1.RecordType_RECORD_TYPE_CAA,
			record: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_CAA,
				Record: &platformv1.Record_Caa{Caa: &platformv1.CAARecord{Name: "@", Flags: 0, Tag: "issue", Value: "letsencrypt.org", Ttl: 3600}},
			},
		},
		{
			name:       "TLSA record",
			recordType: platformv1.RecordType_RECORD_TYPE_TLSA,
			record: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_TLSA,
				Record: &platformv1.Record_Tlsa{Tlsa: &platformv1.TLSARecord{Name: "_443._tcp.www", Usage: 3, Selector: 1, MatchingType: 1, Data: "aabbccdd", Ttl: 3600}},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create fresh zone for each test
			mock.zones["example.com."] = &entities.Zone{
				ID:   1,
				Name: "example.com.",
			}

			req := &platformv1.AddRecordRequest{
				ZoneName: "example.com.",
				Record:   tt.record,
			}

			resp, err := server.AddRecord(context.Background(), req)
			require.NoError(t, err)
			assert.True(t, resp.Status.Success)
		})
	}
}

func TestDNSServiceServer_AddRecord_UnsupportedType(t *testing.T) {
	mock := newMockDNSService()
	mock.zones["example.com."] = &entities.Zone{
		ID:   1,
		Name: "example.com.",
	}
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.AddRecordRequest{
		ZoneName: "example.com.",
		Record: &platformv1.Record{
			Type: platformv1.RecordType_RECORD_TYPE_UNSPECIFIED,
		},
	}

	_, err := server.AddRecord(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestDNSServiceServer_AddRecord_MissingZone(t *testing.T) {
	mock := newMockDNSService()
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.AddRecordRequest{
		Record: &platformv1.Record{
			Type: platformv1.RecordType_RECORD_TYPE_A,
		},
	}

	_, err := server.AddRecord(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestDNSServiceServer_AddRecord_MissingRecord(t *testing.T) {
	mock := newMockDNSService()
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.AddRecordRequest{
		ZoneName: "example.com.",
	}

	_, err := server.AddRecord(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestDNSServiceServer_AddRecord_ZoneNotFound(t *testing.T) {
	mock := newMockDNSService()
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.AddRecordRequest{
		ZoneName: "nonexistent.com.",
		Record: &platformv1.Record{
			Type: platformv1.RecordType_RECORD_TYPE_A,
		},
	}

	_, err := server.AddRecord(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestDNSServiceServer_AddRecord_SaveError(t *testing.T) {
	mock := newMockDNSService()
	mock.zones["example.com."] = &entities.Zone{
		ID:   1,
		Name: "example.com.",
	}
	mock.saveErr = errors.New("save failed")
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.AddRecordRequest{
		ZoneName: "example.com.",
		Record: &platformv1.Record{
			Type: platformv1.RecordType_RECORD_TYPE_A,
			Record: &platformv1.Record_A{
				A: &platformv1.ARecord{Name: "www", Value: "192.168.1.1", Ttl: 3600},
			},
		},
	}

	_, err := server.AddRecord(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

func TestDNSServiceServer_DeleteRecord_Success(t *testing.T) {
	mock := newMockDNSService()
	mock.zones["example.com."] = &entities.Zone{
		ID:   1,
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			ARecords: []*entities.ARecord{
				{Name: "www", Value: "192.168.1.1", TTL: 3600},
			},
		},
	}
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.DeleteRecordRequest{
		ZoneName: "example.com.",
		Type:     platformv1.RecordType_RECORD_TYPE_A,
		Name:     "www",
	}

	resp, err := server.DeleteRecord(context.Background(), req)

	require.NoError(t, err)
	assert.True(t, resp.Status.Success)
	assert.Len(t, resp.Zone.Records.ARecords, 0)
}

func TestDNSServiceServer_DeleteRecord_AllTypes(t *testing.T) {
	mock := newMockDNSService()
	server := NewDNSServiceServer(mock, testLogger())

	tests := []struct {
		name       string
		recordType platformv1.RecordType
		recordName string
		recordSet  entities.RecordSet
	}{
		{
			name:       "A record",
			recordType: platformv1.RecordType_RECORD_TYPE_A,
			recordName: "www",
			recordSet:  entities.RecordSet{ARecords: []*entities.ARecord{{Name: "www", Value: "192.168.1.1"}}},
		},
		{
			name:       "AAAA record",
			recordType: platformv1.RecordType_RECORD_TYPE_AAAA,
			recordName: "www",
			recordSet:  entities.RecordSet{AAAARecords: []*entities.AAAARecord{{Name: "www", Value: "::1"}}},
		},
		{
			name:       "CNAME record",
			recordType: platformv1.RecordType_RECORD_TYPE_CNAME,
			recordName: "alias",
			recordSet:  entities.RecordSet{CNAMERecords: []*entities.CNAMERecord{{Name: "alias", Value: "www.example.com."}}},
		},
		{
			name:       "MX record",
			recordType: platformv1.RecordType_RECORD_TYPE_MX,
			recordName: "@",
			recordSet:  entities.RecordSet{MXRecords: []*entities.MXRecord{{Name: "@", Value: "mail.example.com."}}},
		},
		{
			name:       "NS record",
			recordType: platformv1.RecordType_RECORD_TYPE_NS,
			recordName: "@",
			recordSet:  entities.RecordSet{NSRecords: []*entities.NSRecord{{Name: "@", Value: "ns1.example.com."}}},
		},
		{
			name:       "TXT record",
			recordType: platformv1.RecordType_RECORD_TYPE_TXT,
			recordName: "@",
			recordSet:  entities.RecordSet{TXTRecords: []*entities.TXTRecord{{Name: "@", Value: "v=spf1"}}},
		},
		{
			name:       "SRV record",
			recordType: platformv1.RecordType_RECORD_TYPE_SRV,
			recordName: "_sip._tcp",
			recordSet:  entities.RecordSet{SRVRecords: []*entities.SRVRecord{{Name: "_sip._tcp", Target: "sip.example.com."}}},
		},
		{
			name:       "CAA record",
			recordType: platformv1.RecordType_RECORD_TYPE_CAA,
			recordName: "@",
			recordSet:  entities.RecordSet{CAARecords: []*entities.CAARecord{{Name: "@", Tag: "issue", Value: "letsencrypt.org"}}},
		},
		{
			name:       "TLSA record",
			recordType: platformv1.RecordType_RECORD_TYPE_TLSA,
			recordName: "_443._tcp.www",
			recordSet:  entities.RecordSet{TLSARecords: []*entities.TLSARecord{{Name: "_443._tcp.www", Data: "aabbccdd"}}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock.zones["example.com."] = &entities.Zone{
				ID:        1,
				Name:      "example.com.",
				RecordSet: tt.recordSet,
			}

			req := &platformv1.DeleteRecordRequest{
				ZoneName: "example.com.",
				Type:     tt.recordType,
				Name:     tt.recordName,
			}

			resp, err := server.DeleteRecord(context.Background(), req)
			require.NoError(t, err)
			assert.True(t, resp.Status.Success)
		})
	}
}

func TestDNSServiceServer_DeleteRecord_MissingZone(t *testing.T) {
	mock := newMockDNSService()
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.DeleteRecordRequest{
		Type: platformv1.RecordType_RECORD_TYPE_A,
		Name: "www",
	}

	_, err := server.DeleteRecord(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestDNSServiceServer_DeleteRecord_MissingName(t *testing.T) {
	mock := newMockDNSService()
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.DeleteRecordRequest{
		ZoneName: "example.com.",
		Type:     platformv1.RecordType_RECORD_TYPE_A,
	}

	_, err := server.DeleteRecord(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestDNSServiceServer_DeleteRecord_SaveError(t *testing.T) {
	mock := newMockDNSService()
	mock.zones["example.com."] = &entities.Zone{
		ID:   1,
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			ARecords: []*entities.ARecord{
				{Name: "www", Value: "192.168.1.1", TTL: 3600},
			},
		},
	}
	mock.saveErr = errors.New("save failed")
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.DeleteRecordRequest{
		ZoneName: "example.com.",
		Type:     platformv1.RecordType_RECORD_TYPE_A,
		Name:     "www",
	}

	_, err := server.DeleteRecord(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

func TestDNSServiceServer_UpdateRecord_Success(t *testing.T) {
	mock := newMockDNSService()
	mock.zones["example.com."] = &entities.Zone{
		ID:   1,
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			ARecords: []*entities.ARecord{
				{Name: "www", Value: "192.168.1.1", TTL: 3600},
			},
		},
	}
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.UpdateRecordRequest{
		ZoneName: "example.com.",
		OldRecord: &platformv1.Record{
			Type:   platformv1.RecordType_RECORD_TYPE_A,
			Record: &platformv1.Record_A{A: &platformv1.ARecord{Name: "www", Value: "192.168.1.1", Ttl: 3600}},
		},
		NewRecord: &platformv1.Record{
			Type:   platformv1.RecordType_RECORD_TYPE_A,
			Record: &platformv1.Record_A{A: &platformv1.ARecord{Name: "www", Value: "192.168.1.2", Ttl: 7200}},
		},
	}

	resp, err := server.UpdateRecord(context.Background(), req)

	require.NoError(t, err)
	assert.True(t, resp.Status.Success)
}

func TestDNSServiceServer_UpdateRecord_MissingZone(t *testing.T) {
	mock := newMockDNSService()
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.UpdateRecordRequest{
		OldRecord: &platformv1.Record{Type: platformv1.RecordType_RECORD_TYPE_A},
		NewRecord: &platformv1.Record{Type: platformv1.RecordType_RECORD_TYPE_A},
	}

	_, err := server.UpdateRecord(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestDNSServiceServer_UpdateRecord_MissingOldRecord(t *testing.T) {
	mock := newMockDNSService()
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.UpdateRecordRequest{
		ZoneName:  "example.com.",
		NewRecord: &platformv1.Record{Type: platformv1.RecordType_RECORD_TYPE_A},
	}

	_, err := server.UpdateRecord(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestDNSServiceServer_ListRecords_Success(t *testing.T) {
	mock := newMockDNSService()
	mock.zones["example.com."] = &entities.Zone{
		ID:   1,
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			ARecords: []*entities.ARecord{
				{Name: "www", Value: "192.168.1.1", TTL: 3600},
				{Name: "mail", Value: "192.168.1.2", TTL: 3600},
			},
		},
	}
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.ListRecordsRequest{
		ZoneName: "example.com.",
		Type:     platformv1.RecordType_RECORD_TYPE_A,
	}

	resp, err := server.ListRecords(context.Background(), req)

	require.NoError(t, err)
	assert.Len(t, resp.Records, 2)
}

func TestDNSServiceServer_ListRecords_AllTypes(t *testing.T) {
	mock := newMockDNSService()
	mock.zones["example.com."] = &entities.Zone{
		ID:   1,
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			ARecords:     []*entities.ARecord{{Name: "www", Value: "192.168.1.1"}},
			AAAARecords:  []*entities.AAAARecord{{Name: "www", Value: "::1"}},
			CNAMERecords: []*entities.CNAMERecord{{Name: "alias", Value: "www.example.com."}},
			MXRecords:    []*entities.MXRecord{{Name: "@", Value: "mail.example.com."}},
			NSRecords:    []*entities.NSRecord{{Name: "@", Value: "ns1.example.com."}},
			TXTRecords:   []*entities.TXTRecord{{Name: "@", Value: "v=spf1"}},
			SRVRecords:   []*entities.SRVRecord{{Name: "_sip._tcp", Target: "sip.example.com."}},
			CAARecords:   []*entities.CAARecord{{Name: "@", Tag: "issue", Value: "letsencrypt.org"}},
			TLSARecords:  []*entities.TLSARecord{{Name: "_443._tcp.www", Data: "aabbccdd"}},
		},
	}
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.ListRecordsRequest{
		ZoneName: "example.com.",
		Type:     platformv1.RecordType_RECORD_TYPE_UNSPECIFIED, // All types
	}

	resp, err := server.ListRecords(context.Background(), req)

	require.NoError(t, err)
	assert.Len(t, resp.Records, 9)
}

func TestDNSServiceServer_ListRecords_MissingZone(t *testing.T) {
	mock := newMockDNSService()
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.ListRecordsRequest{}

	_, err := server.ListRecords(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

// DNSSEC Tests

func TestDNSServiceServer_SignZone_Success(t *testing.T) {
	mock := newMockDNSService()
	mock.zones["example.com."] = &entities.Zone{
		ID:   1,
		Name: "example.com.",
	}
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.SignZoneRequest{ZoneName: "example.com."}

	resp, err := server.SignZone(context.Background(), req)

	require.NoError(t, err)
	assert.True(t, resp.Status.Success)
}

func TestDNSServiceServer_SignZone_MissingName(t *testing.T) {
	mock := newMockDNSService()
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.SignZoneRequest{}

	_, err := server.SignZone(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestDNSServiceServer_SignZone_NotFound(t *testing.T) {
	mock := newMockDNSService()
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.SignZoneRequest{ZoneName: "nonexistent.com."}

	_, err := server.SignZone(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestDNSServiceServer_SignZone_Error(t *testing.T) {
	mock := newMockDNSService()
	mock.zones["example.com."] = &entities.Zone{
		ID:   1,
		Name: "example.com.",
	}
	mock.signErr = errors.New("DNSSEC not enabled")
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.SignZoneRequest{ZoneName: "example.com."}

	_, err := server.SignZone(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

func TestDNSServiceServer_SignZone_SaveError(t *testing.T) {
	mock := newMockDNSService()
	mock.zones["example.com."] = &entities.Zone{
		ID:   1,
		Name: "example.com.",
	}
	mock.saveErr = errors.New("save failed")
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.SignZoneRequest{ZoneName: "example.com."}

	_, err := server.SignZone(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

func TestDNSServiceServer_GetDNSSECStatus_Success(t *testing.T) {
	mock := newMockDNSService()
	mock.dnssecEnabled = true
	mock.zones["example.com."] = &entities.Zone{
		ID:   1,
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			DNSKEYRecords: []*entities.DNSKEYRecord{
				{Name: "example.com.", Flags: 257, Protocol: 3, Algorithm: 13, Key: "testkey"},
			},
			DSRecords: []*entities.DSRecord{
				{Name: "example.com.", KeyTag: 12345, Algorithm: 13, DigestType: 2, Digest: "aabbccdd"},
			},
		},
	}
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.GetDNSSECStatusRequest{ZoneName: "example.com."}

	resp, err := server.GetDNSSECStatus(context.Background(), req)

	require.NoError(t, err)
	assert.True(t, resp.Status.Enabled)
	assert.True(t, resp.Status.ZoneSigned)
	assert.Len(t, resp.Status.Keys, 1)
	assert.Len(t, resp.Status.DsRecords, 1)
}

func TestDNSServiceServer_GetDNSSECStatus_MissingName(t *testing.T) {
	mock := newMockDNSService()
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.GetDNSSECStatusRequest{}

	_, err := server.GetDNSSECStatus(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestDNSServiceServer_GetDNSSECStatus_NotFound(t *testing.T) {
	mock := newMockDNSService()
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.GetDNSSECStatusRequest{ZoneName: "nonexistent.com."}

	_, err := server.GetDNSSECStatus(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

// Registration Tests

func TestDNSServiceServer_Register_Success(t *testing.T) {
	mock := newMockDNSService()
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.RegisterRequest{
		Fqdn: "host.example.com",
		Ip:   "192.168.1.100",
	}

	resp, err := server.Register(context.Background(), req)

	require.NoError(t, err)
	assert.True(t, resp.Status.Success)
}

func TestDNSServiceServer_Register_MissingFQDN(t *testing.T) {
	mock := newMockDNSService()
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.RegisterRequest{
		Ip: "192.168.1.100",
	}

	_, err := server.Register(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestDNSServiceServer_Register_MissingIP(t *testing.T) {
	mock := newMockDNSService()
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.RegisterRequest{
		Fqdn: "host.example.com",
	}

	_, err := server.Register(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestDNSServiceServer_Register_Error(t *testing.T) {
	mock := newMockDNSService()
	mock.registerErr = errors.New("registration failed")
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.RegisterRequest{
		Fqdn: "host.example.com",
		Ip:   "192.168.1.100",
	}

	_, err := server.Register(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

// Resolve Tests

func TestDNSServiceServer_Resolve_Success(t *testing.T) {
	mock := newMockDNSService()
	mock.zones["example.com."] = &entities.Zone{
		ID:   1,
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			ARecords: []*entities.ARecord{
				{Name: "@", Value: "192.168.1.1", TTL: 3600},
			},
		},
	}
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.ResolveRequest{
		Fqdn: "example.com.",
		Type: platformv1.RecordType_RECORD_TYPE_A,
	}

	resp, err := server.Resolve(context.Background(), req)

	require.NoError(t, err)
	assert.True(t, resp.Authoritative)
	assert.Len(t, resp.Records, 1)
}

func TestDNSServiceServer_Resolve_NotFound(t *testing.T) {
	mock := newMockDNSService()
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.ResolveRequest{
		Fqdn: "nonexistent.com.",
	}

	resp, err := server.Resolve(context.Background(), req)

	require.NoError(t, err)
	assert.False(t, resp.Authoritative)
	assert.Empty(t, resp.Records)
}

func TestDNSServiceServer_Resolve_MissingFQDN(t *testing.T) {
	mock := newMockDNSService()
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.ResolveRequest{}

	_, err := server.Resolve(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

// Helper function tests

func TestDNSServiceServer_ZoneToProto_NilZone(t *testing.T) {
	mock := newMockDNSService()
	server := NewDNSServiceServer(mock, testLogger())

	result := server.zoneToProto(nil)

	assert.Nil(t, result)
}

func TestDNSServiceServer_RecordSetToProto_NilRecordSet(t *testing.T) {
	mock := newMockDNSService()
	server := NewDNSServiceServer(mock, testLogger())

	result := server.recordSetToProto(nil)

	assert.Nil(t, result)
}

func TestDNSServiceServer_RecordSetToProto_WithAllRecordTypes(t *testing.T) {
	mock := newMockDNSService()
	server := NewDNSServiceServer(mock, testLogger())

	rs := &entities.RecordSet{
		SOARecord: entities.SOARecord{
			Name:       "example.com.",
			MName:      "ns1.example.com.",
			RName:      "hostmaster.example.com.",
			Serial:     1,
			Refresh:    86400,
			Retry:      7200,
			Expire:     86400,
			MinimumTTL: 3600,
			TTL:        3600,
		},
		ARecords:      []*entities.ARecord{{Name: "www", Value: "192.168.1.1", TTL: 3600}},
		AAAARecords:   []*entities.AAAARecord{{Name: "www", Value: "::1", TTL: 3600}},
		CNAMERecords:  []*entities.CNAMERecord{{Name: "alias", Value: "www.example.com.", TTL: 3600}},
		MXRecords:     []*entities.MXRecord{{Name: "@", Value: "mail.example.com.", Priority: 10, TTL: 3600}},
		NSRecords:     []*entities.NSRecord{{Name: "@", Value: "ns1.example.com.", TTL: 3600}},
		TXTRecords:    []*entities.TXTRecord{{Name: "@", Value: "v=spf1", TTL: 3600}},
		SRVRecords:    []*entities.SRVRecord{{Name: "_sip._tcp", Target: "sip.example.com.", Port: 5060, Priority: 10, Weight: 20, TTL: 3600}},
		CAARecords:    []*entities.CAARecord{{Name: "@", Flags: 0, Tag: "issue", Value: "letsencrypt.org", TTL: 3600}},
		TLSARecords:   []*entities.TLSARecord{{Name: "_443._tcp.www", Usage: 3, Selector: 1, MatchingType: 1, Data: "aabbccdd", TTL: 3600}},
		DNSKEYRecords: []*entities.DNSKEYRecord{{Name: "example.com.", Flags: 257, Protocol: 3, Algorithm: 13, Key: "testkey", TTL: 3600}},
		DSRecords:     []*entities.DSRecord{{Name: "example.com.", KeyTag: 12345, Algorithm: 13, DigestType: 2, Digest: "aabbccdd", TTL: 3600}},
		RRSIGRecords:  []*entities.RRSIGRecord{{TypeCovered: "A", Algorithm: 13, Labels: 2, OriginalTTL: 3600, Expiration: "20260101000000", Inception: "20250101000000", KeyTag: 12345, SignerName: "example.com.", Signature: "sig"}},
	}

	result := server.recordSetToProto(rs)

	require.NotNil(t, result)
	assert.NotNil(t, result.Soa)
	assert.Len(t, result.ARecords, 1)
	assert.Len(t, result.AaaaRecords, 1)
	assert.Len(t, result.CnameRecords, 1)
	assert.Len(t, result.MxRecords, 1)
	assert.Len(t, result.NsRecords, 1)
	assert.Len(t, result.TxtRecords, 1)
	assert.Len(t, result.SrvRecords, 1)
	assert.Len(t, result.CaaRecords, 1)
	assert.Len(t, result.TlsaRecords, 1)
	assert.Len(t, result.DnskeyRecords, 1)
	assert.Len(t, result.DsRecords, 1)
	assert.Len(t, result.RrsigRecords, 1)
}

func TestDNSServiceServer_ExtractRecords_ByType(t *testing.T) {
	mock := newMockDNSService()
	server := NewDNSServiceServer(mock, testLogger())

	zone := &entities.Zone{
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			ARecords:     []*entities.ARecord{{Name: "www", Value: "192.168.1.1"}},
			AAAARecords:  []*entities.AAAARecord{{Name: "www", Value: "::1"}},
			CNAMERecords: []*entities.CNAMERecord{{Name: "alias", Value: "www.example.com."}},
			MXRecords:    []*entities.MXRecord{{Name: "@", Value: "mail.example.com.", Priority: 10}},
			NSRecords:    []*entities.NSRecord{{Name: "@", Value: "ns1.example.com."}},
			TXTRecords:   []*entities.TXTRecord{{Name: "@", Value: "v=spf1"}},
			SRVRecords:   []*entities.SRVRecord{{Name: "_sip._tcp", Target: "sip.example.com.", Port: 5060, Priority: 10, Weight: 20}},
			CAARecords:   []*entities.CAARecord{{Name: "@", Flags: 0, Tag: "issue", Value: "letsencrypt.org"}},
			TLSARecords:  []*entities.TLSARecord{{Name: "_443._tcp.www", Usage: 3, Selector: 1, MatchingType: 1, Data: "aabbccdd"}},
		},
	}

	tests := []struct {
		name       string
		recordType platformv1.RecordType
		expected   int
	}{
		{"A records", platformv1.RecordType_RECORD_TYPE_A, 1},
		{"AAAA records", platformv1.RecordType_RECORD_TYPE_AAAA, 1},
		{"CNAME records", platformv1.RecordType_RECORD_TYPE_CNAME, 1},
		{"MX records", platformv1.RecordType_RECORD_TYPE_MX, 1},
		{"NS records", platformv1.RecordType_RECORD_TYPE_NS, 1},
		{"TXT records", platformv1.RecordType_RECORD_TYPE_TXT, 1},
		{"SRV records", platformv1.RecordType_RECORD_TYPE_SRV, 1},
		{"CAA records", platformv1.RecordType_RECORD_TYPE_CAA, 1},
		{"TLSA records", platformv1.RecordType_RECORD_TYPE_TLSA, 1},
		{"All records", platformv1.RecordType_RECORD_TYPE_UNSPECIFIED, 9},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			records := server.extractRecords(zone, tt.recordType)
			assert.Len(t, records, tt.expected)
		})
	}
}

func TestDNSServiceServer_GetRecordName_AllTypes(t *testing.T) {
	mock := newMockDNSService()
	server := NewDNSServiceServer(mock, testLogger())

	tests := []struct {
		name     string
		record   *platformv1.Record
		expected string
	}{
		{
			name: "A record",
			record: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_A,
				Record: &platformv1.Record_A{A: &platformv1.ARecord{Name: "www"}},
			},
			expected: "www",
		},
		{
			name: "AAAA record",
			record: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_AAAA,
				Record: &platformv1.Record_Aaaa{Aaaa: &platformv1.AAAARecord{Name: "ipv6"}},
			},
			expected: "ipv6",
		},
		{
			name: "CNAME record",
			record: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_CNAME,
				Record: &platformv1.Record_Cname{Cname: &platformv1.CNAMERecord{Name: "alias"}},
			},
			expected: "alias",
		},
		{
			name: "MX record",
			record: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_MX,
				Record: &platformv1.Record_Mx{Mx: &platformv1.MXRecord{Name: "mail"}},
			},
			expected: "mail",
		},
		{
			name: "NS record",
			record: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_NS,
				Record: &platformv1.Record_Ns{Ns: &platformv1.NSRecord{Name: "ns1"}},
			},
			expected: "ns1",
		},
		{
			name: "TXT record",
			record: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_TXT,
				Record: &platformv1.Record_Txt{Txt: &platformv1.TXTRecord{Name: "spf"}},
			},
			expected: "spf",
		},
		{
			name: "SRV record",
			record: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_SRV,
				Record: &platformv1.Record_Srv{Srv: &platformv1.SRVRecord{Name: "_sip._tcp"}},
			},
			expected: "_sip._tcp",
		},
		{
			name: "CAA record",
			record: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_CAA,
				Record: &platformv1.Record_Caa{Caa: &platformv1.CAARecord{Name: "caa"}},
			},
			expected: "caa",
		},
		{
			name: "TLSA record",
			record: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_TLSA,
				Record: &platformv1.Record_Tlsa{Tlsa: &platformv1.TLSARecord{Name: "_443._tcp.www"}},
			},
			expected: "_443._tcp.www",
		},
		{
			name: "Empty record",
			record: &platformv1.Record{
				Type: platformv1.RecordType_RECORD_TYPE_UNSPECIFIED,
			},
			expected: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := server.getRecordName(tt.record)
			assert.Equal(t, tt.expected, result)
		})
	}
}
