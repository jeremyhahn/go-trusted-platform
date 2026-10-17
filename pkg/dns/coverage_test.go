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
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"math/big"
	"net"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/mocks"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/miekg/dns"

	kms "github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// service.go coverage - functions not yet tested
// =============================================================================

// helper to create a service with mock DAO backed by in-memory storage.
func createServiceWithMockDAO(t *testing.T, tenantID string) (*Service, *mocks.MockZoneDAO) {
	t.Helper()
	logger := logging.DefaultLogger()
	mockStorage := quicbaas.NewMockStorage()
	err := mockStorage.Start(context.Background())
	require.NoError(t, err)
	ds := NewDatastore(mockStorage, logger)

	svcParams := &Params{
		TenantID:  tenantID,
		Config:    &Config{Logger: logger},
		Datastore: ds,
	}
	svc, err := NewService(svcParams)
	require.NoError(t, err)

	// Replace zoneDAO with a mock so we can control behavior
	mockDAO := mocks.NewMockZoneDAO()
	svc.zoneDAO = mockDAO
	return svc, mockDAO
}

func TestCoverage_Service_DNSSECService_ReturnsNil(t *testing.T) {
	svc, _ := createServiceWithMockDAO(t, "tenant-1")
	assert.Nil(t, svc.DNSSECService())
}

func TestCoverage_Service_IsDNSSECEnabled_False(t *testing.T) {
	svc, _ := createServiceWithMockDAO(t, "tenant-1")
	assert.False(t, svc.IsDNSSECEnabled())
}

func TestCoverage_Service_ListZones_Success(t *testing.T) {
	svc, mockDAO := createServiceWithMockDAO(t, "tenant-1")
	ctx := context.Background()

	zone := &entities.Zone{
		ID:       util.NewID([]byte("example.com.")),
		Name:     "example.com.",
		TenantID: "tenant-1",
		TTL:      3600,
	}
	mockDAO.AddZone(zone)

	// Override ForEachPageFunc to return zones directly, avoiding 0-based page bug in mock
	mockDAO.ForEachPageFunc = func(_ context.Context, _ datastore.PageQuery, fn datastore.PagerFunc[*entities.Zone]) error {
		return fn(datastore.PageResult[*entities.Zone]{
			Entities: []*entities.Zone{zone},
			Total:    1,
		})
	}

	zones, err := svc.ListZones(ctx)
	require.NoError(t, err)
	assert.Len(t, zones, 1)
	assert.Equal(t, "example.com.", zones[0].Name)
}

func TestCoverage_Service_ListZones_MissingTenantContext(t *testing.T) {
	svc, _ := createServiceWithMockDAO(t, "")
	ctx := context.Background()

	_, err := svc.ListZones(ctx)
	assert.ErrorIs(t, err, ErrMissingTenantContext)
}

func TestCoverage_Service_ListZones_FiltersOtherTenants(t *testing.T) {
	svc, mockDAO := createServiceWithMockDAO(t, "tenant-1")
	ctx := context.Background()

	zone := &entities.Zone{
		ID:       util.NewID([]byte("other.com.")),
		Name:     "other.com.",
		TenantID: "tenant-2",
		TTL:      3600,
	}
	mockDAO.AddZone(zone)

	// Override ForEachPageFunc to return the zone so tenant filtering is exercised
	mockDAO.ForEachPageFunc = func(_ context.Context, _ datastore.PageQuery, fn datastore.PagerFunc[*entities.Zone]) error {
		return fn(datastore.PageResult[*entities.Zone]{
			Entities: []*entities.Zone{zone},
			Total:    1,
		})
	}

	zones, err := svc.ListZones(ctx)
	require.NoError(t, err)
	assert.Len(t, zones, 0)
}

func TestCoverage_Service_GetRecord_Success(t *testing.T) {
	svc, mockDAO := createServiceWithMockDAO(t, "tenant-1")
	ctx := context.Background()

	zoneName := "example.com."
	zone := &entities.Zone{
		ID:       util.NewID([]byte(zoneName)),
		Name:     zoneName,
		TenantID: "tenant-1",
		TTL:      3600,
		RecordSet: entities.RecordSet{
			ARecords: []*entities.ARecord{
				{Name: "www.example.com", Value: "1.2.3.4", TTL: 3600},
			},
		},
	}
	mockDAO.AddZone(zone)

	rec, err := svc.GetRecord(ctx, "www.example.com", "A")
	require.NoError(t, err)
	assert.Equal(t, "www.example.com", rec.(*entities.ARecord).Name)
}

func TestCoverage_Service_GetRecord_NotFound(t *testing.T) {
	svc, mockDAO := createServiceWithMockDAO(t, "tenant-1")
	ctx := context.Background()

	zoneName := "example.com."
	zone := &entities.Zone{
		ID:       util.NewID([]byte(zoneName)),
		Name:     zoneName,
		TenantID: "tenant-1",
		TTL:      3600,
		RecordSet: entities.RecordSet{
			ARecords: []*entities.ARecord{},
		},
	}
	mockDAO.AddZone(zone)

	_, err := svc.GetRecord(ctx, "www.example.com", "A")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "record not found")
}

func TestCoverage_Service_GetRecord_UnsupportedType(t *testing.T) {
	svc, mockDAO := createServiceWithMockDAO(t, "tenant-1")
	ctx := context.Background()

	zoneName := "example.com."
	zone := &entities.Zone{
		ID:       util.NewID([]byte(zoneName)),
		Name:     zoneName,
		TenantID: "tenant-1",
		TTL:      3600,
	}
	mockDAO.AddZone(zone)

	_, err := svc.GetRecord(ctx, "www.example.com", "UNSUPPORTED")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported record type")
}

func TestCoverage_Service_GetRecord_AllTypes(t *testing.T) {
	svc, mockDAO := createServiceWithMockDAO(t, "tenant-1")
	ctx := context.Background()

	zoneName := "example.com."
	zone := &entities.Zone{
		ID:       util.NewID([]byte(zoneName)),
		Name:     zoneName,
		TenantID: "tenant-1",
		TTL:      3600,
		RecordSet: entities.RecordSet{
			AAAARecords:  []*entities.AAAARecord{{Name: "ipv6.example.com", Value: "::1", TTL: 3600}},
			CNAMERecords: []*entities.CNAMERecord{{Name: "alias.example.com", Value: "example.com.", TTL: 3600}},
			TXTRecords:   []*entities.TXTRecord{{Name: "txt.example.com", Value: "v=spf1", TTL: 3600}},
			MXRecords:    []*entities.MXRecord{{Name: "mx.example.com", Value: "mail.example.com.", Priority: 10, TTL: 3600}},
			NSRecords:    []*entities.NSRecord{{Name: "ns.example.com", Value: "ns1.example.com.", TTL: 3600}},
		},
	}
	mockDAO.AddZone(zone)

	tests := []struct {
		name       string
		recordName string
		recordType string
	}{
		{"AAAA", "ipv6.example.com", "AAAA"},
		{"CNAME", "alias.example.com", "CNAME"},
		{"TXT", "txt.example.com", "TXT"},
		{"MX", "mx.example.com", "MX"},
		{"NS", "ns.example.com", "NS"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rec, err := svc.GetRecord(ctx, tt.recordName, tt.recordType)
			require.NoError(t, err)
			assert.NotNil(t, rec)
		})
	}
}

func TestCoverage_Service_ListRecords_Success(t *testing.T) {
	svc, mockDAO := createServiceWithMockDAO(t, "tenant-1")
	ctx := context.Background()

	zoneName := "example.com."
	zone := &entities.Zone{
		ID:       util.NewID([]byte(zoneName)),
		Name:     zoneName,
		TenantID: "tenant-1",
		TTL:      3600,
		RecordSet: entities.RecordSet{
			ARecords:     []*entities.ARecord{{Name: "www", Value: "1.2.3.4", TTL: 3600}},
			AAAARecords:  []*entities.AAAARecord{{Name: "ipv6", Value: "::1", TTL: 3600}},
			CNAMERecords: []*entities.CNAMERecord{{Name: "alias", Value: "example.com.", TTL: 3600}},
			TXTRecords:   []*entities.TXTRecord{{Name: "txt", Value: "v=spf1", TTL: 3600}},
			MXRecords:    []*entities.MXRecord{{Name: "mx", Value: "mail.example.com.", Priority: 10, TTL: 3600}},
			NSRecords:    []*entities.NSRecord{{Name: "ns", Value: "ns1.example.com.", TTL: 3600}},
		},
	}
	mockDAO.AddZone(zone)

	records, err := svc.ListRecords(ctx, zoneName)
	require.NoError(t, err)
	assert.Len(t, records, 6)
}

func TestCoverage_Service_ListRecords_ZoneNotFound(t *testing.T) {
	svc, _ := createServiceWithMockDAO(t, "tenant-1")
	ctx := context.Background()

	_, err := svc.ListRecords(ctx, "nonexistent.com.")
	assert.Error(t, err)
}

func TestCoverage_Service_Resolve_Success(t *testing.T) {
	svc, mockDAO := createServiceWithMockDAO(t, "tenant-1")
	ctx := context.Background()

	zoneName := "example.com."
	zone := &entities.Zone{
		ID:       util.NewID([]byte(zoneName)),
		Name:     zoneName,
		TenantID: "tenant-1",
		TTL:      3600,
		RecordSet: entities.RecordSet{
			ARecords: []*entities.ARecord{
				{Name: "www.example.com", Value: "1.2.3.4", TTL: 3600},
				{Name: "www.example.com", Value: "5.6.7.8", TTL: 3600},
			},
		},
	}
	mockDAO.AddZone(zone)

	results, err := svc.Resolve(ctx, "www.example.com", "A")
	require.NoError(t, err)
	assert.Len(t, results, 2)
}

func TestCoverage_Service_Resolve_NotFound(t *testing.T) {
	svc, mockDAO := createServiceWithMockDAO(t, "tenant-1")
	ctx := context.Background()

	zoneName := "example.com."
	zone := &entities.Zone{
		ID:       util.NewID([]byte(zoneName)),
		Name:     zoneName,
		TenantID: "tenant-1",
		TTL:      3600,
		RecordSet: entities.RecordSet{
			ARecords: []*entities.ARecord{},
		},
	}
	mockDAO.AddZone(zone)

	_, err := svc.Resolve(ctx, "missing.example.com", "A")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no records found")
}

func TestCoverage_Service_Resolve_UnsupportedType(t *testing.T) {
	svc, mockDAO := createServiceWithMockDAO(t, "tenant-1")
	ctx := context.Background()

	zoneName := "example.com."
	zone := &entities.Zone{
		ID:       util.NewID([]byte(zoneName)),
		Name:     zoneName,
		TenantID: "tenant-1",
		TTL:      3600,
	}
	mockDAO.AddZone(zone)

	_, err := svc.Resolve(ctx, "www.example.com", "UNSUPPORTED")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported record type")
}

func TestCoverage_Service_Resolve_AllTypes(t *testing.T) {
	svc, mockDAO := createServiceWithMockDAO(t, "tenant-1")
	ctx := context.Background()

	zoneName := "example.com."
	zone := &entities.Zone{
		ID:       util.NewID([]byte(zoneName)),
		Name:     zoneName,
		TenantID: "tenant-1",
		TTL:      3600,
		RecordSet: entities.RecordSet{
			AAAARecords:  []*entities.AAAARecord{{Name: "ipv6.example.com", Value: "::1", TTL: 3600}},
			CNAMERecords: []*entities.CNAMERecord{{Name: "alias.example.com", Value: "example.com.", TTL: 3600}},
			TXTRecords:   []*entities.TXTRecord{{Name: "txt.example.com", Value: "v=spf1", TTL: 3600}},
			MXRecords:    []*entities.MXRecord{{Name: "mx.example.com", Value: "mail.example.com.", Priority: 10, TTL: 3600}},
			NSRecords:    []*entities.NSRecord{{Name: "ns.example.com", Value: "ns1.example.com.", TTL: 3600}},
		},
	}
	mockDAO.AddZone(zone)

	tests := []struct {
		name       string
		recordName string
		recordType string
		expected   string
	}{
		{"AAAA", "ipv6.example.com", "AAAA", "::1"},
		{"CNAME", "alias.example.com", "CNAME", "example.com."},
		{"TXT", "txt.example.com", "TXT", "v=spf1"},
		{"MX", "mx.example.com", "MX", "mail.example.com."},
		{"NS", "ns.example.com", "NS", "ns1.example.com."},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			results, err := svc.Resolve(ctx, tt.recordName, tt.recordType)
			require.NoError(t, err)
			assert.Contains(t, results, tt.expected)
		})
	}
}

func TestCoverage_ExtractHostnameFromCN(t *testing.T) {
	tests := []struct {
		name     string
		cn       string
		zoneName string
		expected string
	}{
		{"simple hostname", "server.example.internal.", "example.internal.", "server"},
		{"deep subdomain", "a.b.example.internal.", "example.internal.", "a.b"},
		{"bare zone", "example.internal.", "example.internal.", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := extractHostnameFromCN(tt.cn, tt.zoneName)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestService_RecordZone_LongestSuffixWins(t *testing.T) {
	svc, mockDAO := createServiceWithMockDAO(t, "tenant-1")
	ctx := context.Background()

	for _, zoneName := range []string{"example.test.", "app.example.test."} {
		mockDAO.AddZone(&entities.Zone{
			ID:       util.NewID([]byte(zoneName)),
			Name:     zoneName,
			TenantID: "tenant-1",
			TTL:      3600,
		})
	}

	tests := []struct {
		name     string
		record   string
		expected string
	}{
		{"record in the deeper zone", "api.app.example.test.", "app.example.test."},
		{"deeper zone without the trailing dot", "api.app.example.test", "app.example.test."},
		{"zone apex", "app.example.test.", "app.example.test."},
		{"record in the shallower zone", "www.example.test.", "example.test."},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			zone, err := svc.recordZone(ctx, tt.record)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, zone.Name)
		})
	}
}

func TestService_RecordZone_NoEnclosingZone(t *testing.T) {
	svc, mockDAO := createServiceWithMockDAO(t, "tenant-1")
	ctx := context.Background()
	mockDAO.AddZone(&entities.Zone{
		ID:       util.NewID([]byte("example.test.")),
		Name:     "example.test.",
		TenantID: "tenant-1",
	})

	_, err := svc.recordZone(ctx, "api.other.test.")
	assert.ErrorIs(t, err, ErrZoneNotFound)
	assert.Contains(t, err.Error(), "failed to get zone for record api.other.test.")
}

func TestService_AddRecord_LandsInLongestSuffixZone(t *testing.T) {
	svc, mockDAO := createServiceWithMockDAO(t, "tenant-1")
	ctx := context.Background()
	for _, zoneName := range []string{"example.test.", "app.example.test."} {
		mockDAO.AddZone(&entities.Zone{
			ID:       util.NewID([]byte(zoneName)),
			Name:     zoneName,
			TenantID: "tenant-1",
			TTL:      3600,
		})
	}

	require.NoError(t, svc.AddRecord(ctx, "api.app.example.test.", "A", "192.0.2.10", 300))

	rec, err := svc.GetRecord(ctx, "api.app.example.test.", "A")
	require.NoError(t, err)
	assert.Equal(t, "192.0.2.10", rec.(*entities.ARecord).Value)

	shallow, err := svc.Zone(ctx, "example.test.")
	require.NoError(t, err)
	assert.Empty(t, shallow.RecordSet.ARecords, "the record must not land in the shorter zone")
}

func TestCoverage_Service_AddRecord_AllTypes(t *testing.T) {
	svc, mockDAO := createServiceWithMockDAO(t, "tenant-1")
	ctx := context.Background()

	zoneName := "example.com."
	zone := &entities.Zone{
		ID:       util.NewID([]byte(zoneName)),
		Name:     zoneName,
		TenantID: "tenant-1",
		TTL:      3600,
	}
	mockDAO.AddZone(zone)

	types := []struct {
		recordType string
		name       string
		value      string
	}{
		{"A", "www.example.com", "1.2.3.4"},
		{"AAAA", "ipv6.example.com", "::1"},
		{"CNAME", "alias.example.com", "example.com."},
		{"TXT", "txt.example.com", "v=spf1"},
		{"MX", "mx.example.com", "mail.example.com."},
		{"NS", "ns.example.com", "ns1.example.com."},
	}

	for _, tt := range types {
		t.Run(tt.recordType, func(t *testing.T) {
			err := svc.AddRecord(ctx, tt.name, tt.recordType, tt.value, 3600)
			require.NoError(t, err)
		})
	}
}

func TestCoverage_Service_AddRecord_UnsupportedType(t *testing.T) {
	svc, mockDAO := createServiceWithMockDAO(t, "tenant-1")
	ctx := context.Background()

	zoneName := "example.com."
	zone := &entities.Zone{
		ID:       util.NewID([]byte(zoneName)),
		Name:     zoneName,
		TenantID: "tenant-1",
		TTL:      3600,
	}
	mockDAO.AddZone(zone)

	err := svc.AddRecord(ctx, "www.example.com", "SRV", "target", 3600)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported record type")
}

func TestService_AddRecord_RefusesInvalidRecordsBeforeStoring(t *testing.T) {
	svc, mockDAO := createServiceWithMockDAO(t, "tenant-1")
	ctx := context.Background()

	zoneName := "example.com."
	zone := &entities.Zone{
		ID:       util.NewID([]byte(zoneName)),
		Name:     zoneName,
		TenantID: "tenant-1",
		TTL:      3600,
	}
	mockDAO.AddZone(zone)

	var invalid ErrInvalidRecordAddress
	err := svc.AddRecord(ctx, "www.example.com", "A", "not-an-ip", 3600)
	require.True(t, errors.As(err, &invalid), "err = %v", err)
	err = svc.AddRecord(ctx, "www.example.com", "AAAA", "192.168.1.1", 3600)
	require.True(t, errors.As(err, &invalid), "err = %v", err)

	var required ErrRecordNameRequired
	err = svc.AddRecord(ctx, "", "A", "192.168.1.1", 3600)
	require.True(t, errors.As(err, &required), "err = %v", err)

	stored, err := svc.Zone(ctx, zoneName)
	require.NoError(t, err)
	assert.Empty(t, stored.RecordSet.ARecords)
	assert.Empty(t, stored.RecordSet.AAAARecords)
}

func TestCoverage_Service_DeleteRecord_AllTypes(t *testing.T) {
	svc, mockDAO := createServiceWithMockDAO(t, "tenant-1")
	ctx := context.Background()

	zoneName := "example.com."
	zone := &entities.Zone{
		ID:       util.NewID([]byte(zoneName)),
		Name:     zoneName,
		TenantID: "tenant-1",
		TTL:      3600,
		RecordSet: entities.RecordSet{
			ARecords:     []*entities.ARecord{{Name: "www.example.com", Value: "1.2.3.4", TTL: 3600}},
			AAAARecords:  []*entities.AAAARecord{{Name: "ipv6.example.com", Value: "::1", TTL: 3600}},
			CNAMERecords: []*entities.CNAMERecord{{Name: "alias.example.com", Value: "example.com.", TTL: 3600}},
			TXTRecords:   []*entities.TXTRecord{{Name: "txt.example.com", Value: "v=spf1", TTL: 3600}},
			MXRecords:    []*entities.MXRecord{{Name: "mx.example.com", Value: "mail.example.com.", Priority: 10, TTL: 3600}},
			NSRecords:    []*entities.NSRecord{{Name: "ns.example.com", Value: "ns1.example.com.", TTL: 3600}},
		},
	}
	mockDAO.AddZone(zone)

	types := []string{"A", "AAAA", "CNAME", "TXT", "MX", "NS"}
	names := []string{"www.example.com", "ipv6.example.com", "alias.example.com", "txt.example.com", "mx.example.com", "ns.example.com"}

	for i, rt := range types {
		t.Run(rt, func(t *testing.T) {
			err := svc.DeleteRecord(ctx, names[i], rt)
			require.NoError(t, err)
		})
	}
}

func TestCoverage_Service_DeleteRecord_UnsupportedType(t *testing.T) {
	svc, mockDAO := createServiceWithMockDAO(t, "tenant-1")
	ctx := context.Background()

	zoneName := "example.com."
	zone := &entities.Zone{
		ID:       util.NewID([]byte(zoneName)),
		Name:     zoneName,
		TenantID: "tenant-1",
		TTL:      3600,
	}
	mockDAO.AddZone(zone)

	err := svc.DeleteRecord(ctx, "www.example.com", "SRV")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "unsupported record type")
}

func TestCoverage_IsRunning_WhenNotStarted(t *testing.T) {
	assert.False(t, IsRunning())
}

func TestCoverage_Stop_WhenNotRunning(t *testing.T) {
	err := Stop()
	assert.ErrorIs(t, err, ErrDNSNotRunning)
}

func TestCoverage_Service_SignZone_DNSSECNotEnabled(t *testing.T) {
	svc, _ := createServiceWithMockDAO(t, "tenant-1")

	zone := &entities.Zone{
		Name:     "example.com.",
		TenantID: "tenant-1",
	}

	err := svc.SignZone(zone)
	assert.ErrorIs(t, err, ErrDNSSECNotEnabled)
}

func TestCoverage_Service_Save_MissingTenantContext(t *testing.T) {
	svc, _ := createServiceWithMockDAO(t, "")
	ctx := context.Background()

	zone := &entities.Zone{Name: "example.com.", TTL: 3600}
	err := svc.Save(ctx, zone)
	assert.ErrorIs(t, err, ErrMissingTenantContext)
}

func TestCoverage_Service_Save_UnauthorizedAccess(t *testing.T) {
	svc, _ := createServiceWithMockDAO(t, "tenant-1")
	ctx := context.Background()

	zone := &entities.Zone{
		Name:     "example.com.",
		TenantID: "other-tenant",
		TTL:      3600,
	}
	err := svc.Save(ctx, zone)
	assert.ErrorIs(t, err, ErrUnauthorizedZoneAccess)
}

func TestCoverage_Service_SaveAndSign_MissingTenantContext(t *testing.T) {
	svc, _ := createServiceWithMockDAO(t, "")
	ctx := context.Background()

	zone := &entities.Zone{Name: "example.com.", TTL: 3600}
	err := svc.SaveAndSign(ctx, zone)
	assert.ErrorIs(t, err, ErrMissingTenantContext)
}

func TestCoverage_Service_SaveAndSign_UnauthorizedAccess(t *testing.T) {
	svc, _ := createServiceWithMockDAO(t, "tenant-1")
	ctx := context.Background()

	zone := &entities.Zone{
		Name:     "example.com.",
		TenantID: "other-tenant",
		TTL:      3600,
	}
	err := svc.SaveAndSign(ctx, zone)
	assert.ErrorIs(t, err, ErrUnauthorizedZoneAccess)
}

func TestCoverage_Service_Delete_UnauthorizedAccess(t *testing.T) {
	svc, _ := createServiceWithMockDAO(t, "tenant-1")
	ctx := context.Background()

	zone := &entities.Zone{
		Name:     "example.com.",
		TenantID: "other-tenant",
		TTL:      3600,
	}
	err := svc.Delete(ctx, zone)
	assert.ErrorIs(t, err, ErrUnauthorizedZoneAccess)
}

func TestCoverage_Service_RegisterWebservice_EmptyCN(t *testing.T) {
	svc, _ := createServiceWithMockDAO(t, "tenant-1")
	ctx := context.Background()

	err := svc.RegisterWebservice(ctx, "")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "certificate CN is required")
}

func TestCoverage_Service_RegisterWebservice_NoMatchingZone(t *testing.T) {
	svc, _ := createServiceWithMockDAO(t, "tenant-1")
	svc.params.Config.InternalServer = &InternalServer{
		Zone: entities.Zone{Name: "internal.local."},
	}
	svc.params.Config.PublicServer = &PublicServer{
		Zone: entities.Zone{Name: "example.com."},
	}
	ctx := context.Background()

	err := svc.RegisterWebservice(ctx, "server.unknown.net")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "does not match any configured zone")
}

func TestCoverage_Service_RegisterWebservice_InternalZone_NoIP(t *testing.T) {
	svc, mockDAO := createServiceWithMockDAO(t, "tenant-1")
	svc.params.Config.InternalServer = &InternalServer{
		Zone: entities.Zone{Name: "internal.local."},
	}
	svc.params.Config.PublicServer = nil

	zoneName := "internal.local."
	zone := &entities.Zone{
		ID:       util.NewID([]byte(zoneName)),
		Name:     zoneName,
		TenantID: "tenant-1",
		TTL:      3600,
	}
	mockDAO.AddZone(zone)

	ctx := context.Background()
	err := svc.RegisterWebservice(ctx, "server.internal.local")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no IP address available")
}

func TestCoverage_Service_RegisterWebservice_InternalZone_Success(t *testing.T) {
	svc, mockDAO := createServiceWithMockDAO(t, "tenant-1")
	svc.params.Config.InternalServer = &InternalServer{
		Zone: entities.Zone{Name: "internal.local."},
	}
	svc.params.Config.PublicServer = nil
	svc.params.PrivateIPv4 = net.ParseIP("192.168.1.10")

	zoneName := "internal.local."
	zone := &entities.Zone{
		ID:       util.NewID([]byte(zoneName)),
		Name:     zoneName,
		TenantID: "tenant-1",
		TTL:      3600,
	}
	mockDAO.AddZone(zone)

	ctx := context.Background()
	err := svc.RegisterWebservice(ctx, "server.internal.local")
	require.NoError(t, err)
}

func TestCoverage_Service_RegisterWebservice_DuplicateSkipped(t *testing.T) {
	svc, mockDAO := createServiceWithMockDAO(t, "tenant-1")
	svc.params.Config.InternalServer = &InternalServer{
		Zone: entities.Zone{Name: "internal.local."},
	}
	svc.params.Config.PublicServer = nil
	svc.params.PrivateIPv4 = net.ParseIP("192.168.1.10")

	zoneName := "internal.local."
	zone := &entities.Zone{
		ID:       util.NewID([]byte(zoneName)),
		Name:     zoneName,
		TenantID: "tenant-1",
		TTL:      3600,
		RecordSet: entities.RecordSet{
			ARecords: []*entities.ARecord{
				{Name: "server", Value: "192.168.1.10", TTL: 3600},
			},
		},
	}
	mockDAO.AddZone(zone)

	ctx := context.Background()
	err := svc.RegisterWebservice(ctx, "server.internal.local")
	require.NoError(t, err)
}

func TestCoverage_Service_RegisterWebservice_PublicZone(t *testing.T) {
	svc, mockDAO := createServiceWithMockDAO(t, "tenant-1")
	svc.params.Config.InternalServer = nil
	svc.params.Config.PublicServer = &PublicServer{
		Zone: entities.Zone{Name: "example.com."},
	}
	svc.params.PublicIPv4 = net.ParseIP("203.0.113.1")

	zoneName := "example.com."
	zone := &entities.Zone{
		ID:       util.NewID([]byte(zoneName)),
		Name:     zoneName,
		TenantID: "tenant-1",
		TTL:      3600,
	}
	mockDAO.AddZone(zone)

	ctx := context.Background()
	err := svc.RegisterWebservice(ctx, "api.example.com")
	require.NoError(t, err)
}

func TestCoverage_Service_RegisterWebservice_ConfigIP(t *testing.T) {
	svc, mockDAO := createServiceWithMockDAO(t, "tenant-1")
	svc.params.Config.InternalServer = &InternalServer{
		Zone: entities.Zone{Name: "internal.local."},
	}
	svc.params.Config.PrivateIPv4 = "10.0.0.1"
	svc.params.Config.PublicServer = nil

	zoneName := "internal.local."
	zone := &entities.Zone{
		ID:       util.NewID([]byte(zoneName)),
		Name:     zoneName,
		TenantID: "tenant-1",
		TTL:      3600,
	}
	mockDAO.AddZone(zone)

	ctx := context.Background()
	err := svc.RegisterWebservice(ctx, "myhost.internal.local")
	require.NoError(t, err)
}

func TestCoverage_Service_RegisterWebservice_PublicConfigIP(t *testing.T) {
	svc, mockDAO := createServiceWithMockDAO(t, "tenant-1")
	svc.params.Config.InternalServer = nil
	svc.params.Config.PublicServer = &PublicServer{
		Zone: entities.Zone{Name: "example.com."},
	}
	svc.params.Config.PublicIPv4 = "198.51.100.1"

	zoneName := "example.com."
	zone := &entities.Zone{
		ID:       util.NewID([]byte(zoneName)),
		Name:     zoneName,
		TenantID: "tenant-1",
		TTL:      3600,
	}
	mockDAO.AddZone(zone)

	ctx := context.Background()
	err := svc.RegisterWebservice(ctx, "web.example.com")
	require.NoError(t, err)
}

// TestRegisterWebservice_ConfiguredAddressWins pins the record a webservice
// registers to the configured dns.private-ipv4 / dns.public-ipv4 when the host
// also detected an address. A boot node detects its default-route address,
// not the VLAN it serves; registering that beside the zone's static record
// hands clients an address they cannot reach.
func TestRegisterWebservice_ConfiguredAddressWins(t *testing.T) {
	cases := []struct {
		name      string
		zoneName  string
		cn        string
		configure func(*Service)
		want      string
		notWant   string
	}{
		{
			name:     "internal",
			zoneName: "example.internal.",
			cn:       "cp.example.internal",
			configure: func(s *Service) {
				s.params.Config.InternalServer = &InternalServer{Zone: entities.Zone{Name: "example.internal."}}
				s.params.Config.PrivateIPv4 = "192.0.2.1"
				s.params.PrivateIPv4 = net.ParseIP("192.0.2.60")
			},
			want:    "192.0.2.1",
			notWant: "192.0.2.60",
		},
		{
			name:     "public",
			zoneName: "example.com.",
			cn:       "cp.example.com",
			configure: func(s *Service) {
				s.params.Config.PublicServer = &PublicServer{Zone: entities.Zone{Name: "example.com."}}
				s.params.Config.PublicIPv4 = "198.51.100.1"
				s.params.PublicIPv4 = net.ParseIP("203.0.113.1")
			},
			want:    "198.51.100.1",
			notWant: "203.0.113.1",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			svc, mockDAO := createServiceWithMockDAO(t, "tenant-1")
			tc.configure(svc)
			mockDAO.AddZone(&entities.Zone{
				ID:       util.NewID([]byte(tc.zoneName)),
				Name:     tc.zoneName,
				TenantID: "tenant-1",
				TTL:      3600,
			})

			ctx := context.Background()
			require.NoError(t, svc.RegisterWebservice(ctx, tc.cn))

			zone, err := mockDAO.GetByName(ctx, tc.zoneName)
			require.NoError(t, err)
			var values []string
			for _, rec := range zone.RecordSet.ARecords {
				if rec.Name == "cp" {
					values = append(values, rec.Value)
				}
			}
			assert.Equal(t, []string{tc.want}, values,
				"the record must carry the configured address, never the detected %s", tc.notWant)
		})
	}
}

func TestConfiguredOrDetected(t *testing.T) {
	assert.Equal(t, "192.0.2.1", configuredOrDetected("192.0.2.1", net.ParseIP("192.0.2.60")))
	assert.Equal(t, "192.0.2.60", configuredOrDetected("", net.ParseIP("192.0.2.60")))
	assert.Equal(t, "", configuredOrDetected("", nil))
}

func TestCoverage_NewService_DNSSECEnabled_NoKeyStore(t *testing.T) {
	logger := logging.DefaultLogger()
	mockStorage := quicbaas.NewMockStorage()
	err := mockStorage.Start(context.Background())
	require.NoError(t, err)
	ds := NewDatastore(mockStorage, logger)

	svcParams := &Params{
		TenantID: "tenant-1",
		Config: &Config{
			Logger: logger,
			DNSSEC: &DNSSECConfig{
				Enabled: true,
				DefaultKey: &common.KeyConfig{
					KeyAlgorithm: "ECDSA",
					ECCConfig:    &common.ECCConfig{Curve: "P-256"},
				},
			},
		},
		Datastore: ds,
	}

	_, err = NewService(svcParams)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "DNSSEC is enabled but no key store")
}

func TestCoverage_NewService_DNSSECEnabled_WithKeyStore(t *testing.T) {
	logger := logging.DefaultLogger()
	mockStorage := quicbaas.NewMockStorage()
	err := mockStorage.Start(context.Background())
	require.NoError(t, err)
	ds := NewDatastore(mockStorage, logger)

	store := NewMockKeyStore()
	svcParams := &Params{
		TenantID: "tenant-1",
		Config: &Config{
			Logger: logger,
			DNSSEC: &DNSSECConfig{
				Enabled: true,
				DefaultKey: &common.KeyConfig{
					KeyAlgorithm: "ECDSA",
					ECCConfig:    &common.ECCConfig{Curve: "P-256"},
				},
				SignatureExpiry: "30d",
				NSECMode:        "nsec",
			},
		},
		Datastore:      ds,
		DNSSECKeyStore: store,
	}

	svc, err := NewService(svcParams)
	require.NoError(t, err)
	assert.True(t, svc.IsDNSSECEnabled())
	assert.NotNil(t, svc.DNSSECService())
}

func TestCoverage_Service_CreateZone(t *testing.T) {
	svc, mockDAO := createServiceWithMockDAO(t, "tenant-1")
	ctx := context.Background()

	err := svc.CreateZone(ctx, "newzone.com.")
	require.NoError(t, err)
	assert.Equal(t, 1, mockDAO.ZoneCount())
}

func TestCoverage_Service_DeleteZone_Success(t *testing.T) {
	svc, mockDAO := createServiceWithMockDAO(t, "tenant-1")
	ctx := context.Background()

	zoneName := "example.com."
	zone := &entities.Zone{
		ID:       util.NewID([]byte(zoneName)),
		Name:     zoneName,
		TenantID: "tenant-1",
		TTL:      3600,
	}
	mockDAO.AddZone(zone)

	err := svc.DeleteZone(ctx, zoneName)
	require.NoError(t, err)
	assert.Equal(t, 0, mockDAO.ZoneCount())
}

func TestCoverage_Service_DeleteZone_NotFound(t *testing.T) {
	svc, _ := createServiceWithMockDAO(t, "tenant-1")
	ctx := context.Background()

	err := svc.DeleteZone(ctx, "nonexistent.com.")
	assert.Error(t, err)
}

// =============================================================================
// plugin.go coverage
// =============================================================================

func TestCoverage_IsNotFoundError(t *testing.T) {
	tests := []struct {
		name     string
		err      error
		expected bool
	}{
		{"nil error", nil, false},
		{"ErrNotFound type", quicbaas.ErrNotFound{EntityType: "zone"}, true},
		{"ErrNotFoundByIndex type", quicbaas.ErrNotFoundByIndex{EntityType: "zone", IndexField: "name"}, true},
		{"string contains not found", errors.New("entity not found in store"), true},
		{"unrelated error", errors.New("connection refused"), false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := isNotFoundError(tt.err)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCoverage_SignUnsignedZones_NilConfiguration(t *testing.T) {
	origConfig := Configuration
	defer func() { Configuration = origConfig }()

	Configuration = nil
	err := SignUnsignedZones()
	assert.NoError(t, err)
}

func TestCoverage_SignUnsignedZones_DNSSECDisabled(t *testing.T) {
	origConfig := Configuration
	defer func() { Configuration = origConfig }()

	Configuration = &Config{
		DNSSEC: &DNSSECConfig{Enabled: false},
	}
	err := SignUnsignedZones()
	assert.NoError(t, err)
}

func TestCoverage_SignUnsignedZones_NoKeyStoreOrAdapter(t *testing.T) {
	origConfig := Configuration
	origKeyStore := KeyStore
	origAdapter := XKMSAdapter
	defer func() {
		Configuration = origConfig
		KeyStore = origKeyStore
		XKMSAdapter = origAdapter
	}()

	Configuration = &Config{
		DNSSEC: &DNSSECConfig{Enabled: true},
	}
	KeyStore = nil
	XKMSAdapter = nil
	err := SignUnsignedZones()
	assert.NoError(t, err)
}

func TestCoverage_SignUnsignedZones_NilZoneDAO(t *testing.T) {
	origConfig := Configuration
	origKeyStore := KeyStore
	origDAO := zoneDAO
	defer func() {
		Configuration = origConfig
		KeyStore = origKeyStore
		zoneDAO = origDAO
	}()

	Configuration = &Config{
		DNSSEC: &DNSSECConfig{Enabled: true},
	}
	KeyStore = NewMockKeyStore()
	zoneDAO = nil
	err := SignUnsignedZones()
	assert.NoError(t, err)
}

func TestCoverage_SignZoneIfEnabled_NilConfiguration(t *testing.T) {
	origConfig := Configuration
	defer func() { Configuration = origConfig }()

	Configuration = nil
	zone := &entities.Zone{Name: "test.com."}
	err := signZoneIfEnabled(zone)
	assert.NoError(t, err)
}

func TestCoverage_SignZoneIfEnabled_DNSSECDisabled(t *testing.T) {
	origConfig := Configuration
	defer func() { Configuration = origConfig }()

	Configuration = &Config{
		DNSSEC: &DNSSECConfig{Enabled: false},
	}
	zone := &entities.Zone{Name: "test.com."}
	err := signZoneIfEnabled(zone)
	assert.NoError(t, err)
}

func TestCoverage_SignZoneIfEnabled_NoAdapterOrKeyStore(t *testing.T) {
	origConfig := Configuration
	origKeyStore := KeyStore
	origAdapter := XKMSAdapter
	defer func() {
		Configuration = origConfig
		KeyStore = origKeyStore
		XKMSAdapter = origAdapter
	}()

	Configuration = &Config{
		Logger: logging.DefaultLogger(),
		DNSSEC: &DNSSECConfig{Enabled: true},
	}
	KeyStore = nil
	XKMSAdapter = nil

	zone := &entities.Zone{Name: "test.com."}
	err := signZoneIfEnabled(zone)
	// HARD FAIL: DNSSEC enabled but no backend configured. The function
	// must not silently skip — operators required this behavior in 2026-04
	// after a regression where unsigned zones were persisted as "signed".
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "no key store and no XKMS adapter are configured")
}

func TestCoverage_SetDNSSECKeyStore(t *testing.T) {
	origConfig := Configuration
	origKeyStore := KeyStore
	origDAO := zoneDAO
	defer func() {
		Configuration = origConfig
		KeyStore = origKeyStore
		zoneDAO = origDAO
	}()

	Configuration = nil
	zoneDAO = nil

	store := NewMockKeyStore()
	err := SetDNSSECKeyStore(store)
	assert.NoError(t, err)
	assert.Equal(t, store, KeyStore)
}

// =============================================================================
// dnssec.go coverage
// =============================================================================

func TestCoverage_DNSSECService_IsEnabled(t *testing.T) {
	svc := &DNSSECService{
		config: &DNSSECConfig{Enabled: true},
	}
	assert.True(t, svc.IsEnabled())

	svc.config.Enabled = false
	assert.False(t, svc.IsEnabled())
}

func TestCoverage_NewDNSSECServiceWithXKMS_NilConfig(t *testing.T) {
	_, err := NewDNSSECServiceWithXKMS(nil, logging.DefaultLogger(), nil)
	assert.ErrorIs(t, err, ErrDNSSECConfigNil)
}

func TestCoverage_NewDNSSECServiceWithXKMS_NilLogger(t *testing.T) {
	_, err := NewDNSSECServiceWithXKMS(&DNSSECConfig{}, nil, nil)
	assert.ErrorIs(t, err, ErrLoggerNil)
}

func TestCoverage_NewDNSSECServiceWithXKMS_NilAdapter(t *testing.T) {
	_, err := NewDNSSECServiceWithXKMS(&DNSSECConfig{}, logging.DefaultLogger(), nil)
	assert.ErrorIs(t, err, ErrKeyStoreNil)
}

func TestCoverage_NewDNSSECServiceWithXKMSAndBackend_NilConfig(t *testing.T) {
	_, err := NewDNSSECServiceWithXKMSAndBackend(nil, logging.DefaultLogger(), nil, "software")
	assert.ErrorIs(t, err, ErrDNSSECConfigNil)
}

func TestCoverage_NewDNSSECServiceWithXKMSAndBackend_NilLogger(t *testing.T) {
	_, err := NewDNSSECServiceWithXKMSAndBackend(&DNSSECConfig{}, nil, nil, "software")
	assert.ErrorIs(t, err, ErrLoggerNil)
}

func TestCoverage_NewDNSSECServiceWithXKMSAndBackend_NilAdapter(t *testing.T) {
	_, err := NewDNSSECServiceWithXKMSAndBackend(&DNSSECConfig{}, logging.DefaultLogger(), nil, "software")
	assert.ErrorIs(t, err, ErrKeyStoreNil)
}

func TestCoverage_DNSSECService_GetAlgorithm(t *testing.T) {
	logger := createTestLogger()

	tests := []struct {
		name     string
		config   *DNSSECConfig
		expected uint8
	}{
		{
			name: "from KSK config",
			config: &DNSSECConfig{
				KSK: &DNSSECKeyConfig{Key: &common.KeyConfig{KeyAlgorithm: "ED25519"}},
			},
			expected: dns.ED25519,
		},
		{
			name: "from ZSK config when no KSK key",
			config: &DNSSECConfig{
				ZSK: &DNSSECKeyConfig{Key: &common.KeyConfig{KeyAlgorithm: "ED25519"}},
			},
			expected: dns.ED25519,
		},
		{
			name: "from default key",
			config: &DNSSECConfig{
				DefaultKey: &common.KeyConfig{KeyAlgorithm: "ED25519"},
			},
			expected: dns.ED25519,
		},
		{
			name:     "no config, default ECDSA",
			config:   &DNSSECConfig{},
			expected: dns.ECDSAP256SHA256,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &DNSSECService{config: tt.config, logger: logger}
			result := svc.getAlgorithm()
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCoverage_DNSSECService_GetAlgorithmForZone(t *testing.T) {
	logger := createTestLogger()

	tests := []struct {
		name     string
		config   *DNSSECConfig
		zone     *entities.Zone
		expected uint8
	}{
		{
			name:     "per-zone KSK override",
			config:   &DNSSECConfig{},
			zone:     &entities.Zone{KSK: &common.KeyConfig{KeyAlgorithm: "ED25519"}},
			expected: dns.ED25519,
		},
		{
			name:     "per-zone ZSK override",
			config:   &DNSSECConfig{},
			zone:     &entities.Zone{ZSK: &common.KeyConfig{KeyAlgorithm: "ED25519"}},
			expected: dns.ED25519,
		},
		{
			name:     "fallback to global",
			config:   &DNSSECConfig{DefaultKey: &common.KeyConfig{KeyAlgorithm: "RSA"}},
			zone:     &entities.Zone{},
			expected: dns.RSASHA256,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			svc := &DNSSECService{config: tt.config, logger: logger}
			result := svc.getAlgorithmForZone(tt.zone)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCoverage_DNSSECService_GetEffectiveKeyConfig(t *testing.T) {
	logger := createTestLogger()
	defaultKey := &common.KeyConfig{KeyAlgorithm: "RSA"}
	overrideKey := &common.KeyConfig{KeyAlgorithm: "ED25519"}

	svc := &DNSSECService{
		config: &DNSSECConfig{DefaultKey: defaultKey},
		logger: logger,
	}

	result := svc.getEffectiveKeyConfig(&DNSSECKeyConfig{Key: overrideKey})
	assert.Equal(t, overrideKey, result)

	result = svc.getEffectiveKeyConfig(&DNSSECKeyConfig{})
	assert.Equal(t, defaultKey, result)

	result = svc.getEffectiveKeyConfig(nil)
	assert.Equal(t, defaultKey, result)

	svc2 := &DNSSECService{config: &DNSSECConfig{}, logger: logger}
	result = svc2.getEffectiveKeyConfig(nil)
	assert.Nil(t, result)
}

// =============================================================================
// dnssec_keystore_sdk.go coverage
// =============================================================================

func TestCoverage_ExtractPublicKey(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pub, err := extractPublicKey(rsaKey)
	require.NoError(t, err)
	assert.IsType(t, &rsa.PublicKey{}, pub)

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pub, err = extractPublicKey(ecdsaKey)
	require.NoError(t, err)
	assert.IsType(t, &ecdsa.PublicKey{}, pub)

	_, ed25519Key, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pub, err = extractPublicKey(ed25519Key)
	require.NoError(t, err)
	assert.IsType(t, ed25519.PublicKey{}, pub)

	_, err = extractPublicKey("not-a-key")
	assert.Error(t, err)
}

func TestCoverage_ExtractPublicKey_CryptoSigner(t *testing.T) {
	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	var signer crypto.Signer = ecdsaKey
	pub, err := extractPublicKey(signer)
	require.NoError(t, err)
	assert.NotNil(t, pub)
}

func TestCoverage_PublicKeyToDNSSECAlgorithm(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	alg, err := publicKeyToDNSSECAlgorithm(&rsaKey.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, dns.RSASHA256, alg)

	ecdsaP256Key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	alg, err = publicKeyToDNSSECAlgorithm(&ecdsaP256Key.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, dns.ECDSAP256SHA256, alg)

	ecdsaP384Key, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	require.NoError(t, err)
	alg, err = publicKeyToDNSSECAlgorithm(&ecdsaP384Key.PublicKey)
	require.NoError(t, err)
	assert.Equal(t, dns.ECDSAP384SHA384, alg)

	ed25519Pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	alg, err = publicKeyToDNSSECAlgorithm(ed25519Pub)
	require.NoError(t, err)
	assert.Equal(t, dns.ED25519, alg)

	ecdsaP521Key, err := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	require.NoError(t, err)
	_, err = publicKeyToDNSSECAlgorithm(&ecdsaP521Key.PublicKey)
	assert.Error(t, err)

	_, err = publicKeyToDNSSECAlgorithm("not-a-key")
	assert.Error(t, err)
}

func TestCoverage_NewSDKKeyStore(t *testing.T) {
	store := NewSDKKeyStore()
	assert.NotNil(t, store)
	assert.Equal(t, defaultBackend, store.backend)
}

func TestCoverage_NewSDKKeyStoreWithBackend(t *testing.T) {
	store := NewSDKKeyStoreWithBackend("tpm")
	assert.NotNil(t, store)
	assert.Equal(t, "tpm", store.backend)

	store = NewSDKKeyStoreWithBackend("")
	assert.Equal(t, defaultBackend, store.backend)
}

func TestCoverage_SDKKeyStore_BuildKeyAttributes(t *testing.T) {
	store := NewSDKKeyStore()

	tests := []struct {
		name      string
		algorithm uint8
		wantAlg   x509.PublicKeyAlgorithm
		wantErr   bool
	}{
		{"RSASHA256", dns.RSASHA256, x509.RSA, false},
		{"RSASHA512", dns.RSASHA512, x509.RSA, false},
		{"ECDSAP256SHA256", dns.ECDSAP256SHA256, x509.ECDSA, false},
		{"ECDSAP384SHA384", dns.ECDSAP384SHA384, x509.ECDSA, false},
		{"ED25519", dns.ED25519, x509.Ed25519, false},
		{"unsupported", 0, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			attrs, err := store.buildKeyAttributes("test-key", tt.algorithm)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantAlg, attrs.KeyAlgorithm)
				assert.Equal(t, "test-key", attrs.CN)
			}
		})
	}
}

// =============================================================================
// dnssec_keystore_quicbaas.go coverage
// =============================================================================

func TestCoverage_KeyIDToEntityID(t *testing.T) {
	id1 := keyIDToEntityID("dnssec_test_example-com_ksk")
	id2 := keyIDToEntityID("dnssec_test_example-com_zsk")
	assert.NotEqual(t, uint64(0), id1)
	assert.NotEqual(t, id1, id2)

	id3 := keyIDToEntityID("dnssec_test_example-com_ksk")
	assert.Equal(t, id1, id3)
}

func TestCoverage_NewQuicBaaSKMSKeyStore_NilClient(t *testing.T) {
	_, err := NewQuicBaaSKMSKeyStore(nil)
	assert.ErrorIs(t, err, ErrKeyStoreNil)
}

func TestCoverage_DnssecAlgorithmToQuicBaaSAlgorithm(t *testing.T) {
	tests := []struct {
		name      string
		algorithm uint8
		wantAlg   kms.KeyAlgorithm
		wantErr   bool
	}{
		{"RSASHA256", dns.RSASHA256, kms.AlgorithmRSA2048, false},
		{"RSASHA512", dns.RSASHA512, kms.AlgorithmRSA2048, false},
		{"ECDSAP256SHA256", dns.ECDSAP256SHA256, kms.AlgorithmECDSAP256, false},
		{"ECDSAP384SHA384", dns.ECDSAP384SHA384, kms.AlgorithmECDSAP384, false},
		{"ED25519", dns.ED25519, kms.AlgorithmED25519, false},
		{"unsupported", 0, 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := dnssecAlgorithmToQuicBaaSAlgorithm(tt.algorithm)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.Equal(t, tt.wantAlg, result)
			}
		})
	}
}

func TestCoverage_QuicbaasAlgorithmToString(t *testing.T) {
	tests := []struct {
		name     string
		alg      kms.KeyAlgorithm
		expected string
	}{
		{"RSA2048", kms.AlgorithmRSA2048, "RSA2048"},
		{"RSA4096", kms.AlgorithmRSA4096, "RSA4096"},
		{"ECDSA-P256", kms.AlgorithmECDSAP256, "ECDSA-P256"},
		{"ECDSA-P384", kms.AlgorithmECDSAP384, "ECDSA-P384"},
		{"ED25519", kms.AlgorithmED25519, "ED25519"},
		{"unknown", kms.KeyAlgorithm(255), "UNKNOWN"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := quicbaasAlgorithmToString(tt.alg)
			assert.Equal(t, tt.expected, result)
		})
	}
}

func TestCoverage_GenerateLocalPublicKey(t *testing.T) {
	tests := []struct {
		name    string
		alg     kms.KeyAlgorithm
		wantErr bool
	}{
		{"RSA2048", kms.AlgorithmRSA2048, false},
		{"RSA4096", kms.AlgorithmRSA4096, false},
		{"ECDSAP256", kms.AlgorithmECDSAP256, false},
		{"ECDSAP384", kms.AlgorithmECDSAP384, false},
		{"ED25519", kms.AlgorithmED25519, false},
		{"unsupported", kms.KeyAlgorithm(255), true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pubKey, pemStr, err := generateLocalPublicKey(tt.alg)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				require.NoError(t, err)
				assert.NotNil(t, pubKey)
				assert.NotEmpty(t, pemStr)
				assert.Contains(t, pemStr, "PUBLIC KEY")
			}
		})
	}
}

func TestCoverage_EncodePublicKeyToPEM(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pemStr, err := encodePublicKeyToPEM(&rsaKey.PublicKey)
	require.NoError(t, err)
	assert.Contains(t, pemStr, "BEGIN PUBLIC KEY")

	ecdsaKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	pemStr, err = encodePublicKeyToPEM(&ecdsaKey.PublicKey)
	require.NoError(t, err)
	assert.Contains(t, pemStr, "BEGIN PUBLIC KEY")

	ed25519Pub, _, err := ed25519.GenerateKey(rand.Reader)
	require.NoError(t, err)
	pemStr, err = encodePublicKeyToPEM(ed25519Pub)
	require.NoError(t, err)
	assert.Contains(t, pemStr, "BEGIN PUBLIC KEY")
}

// =============================================================================
// dnssec_keystore.go additional coverage
// =============================================================================

func TestCoverage_RsaPublicKeyToBase64_LargeExponent(t *testing.T) {
	key := &rsa.PublicKey{
		N: big.NewInt(1),
		E: 65537,
	}
	encoded := rsaPublicKeyToBase64(key)
	assert.NotEmpty(t, encoded)
}

func TestCoverage_ParsePublicKeyFromPEM_Ed25519RawBytes(t *testing.T) {
	rawKey := make([]byte, ed25519.PublicKeySize)
	for i := range rawKey {
		rawKey[i] = byte(i)
	}

	block := &pem.Block{Type: "PUBLIC KEY", Bytes: rawKey}
	pemData := string(pem.EncodeToMemory(block))

	parsed, err := parsePublicKeyFromPEM(pemData, "ED25519")
	require.NoError(t, err)
	assert.IsType(t, ed25519.PublicKey{}, parsed)
}

func TestCoverage_ParsePublicKeyFromPEM_PKCS1RSA(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	pkcs1Bytes := x509.MarshalPKCS1PublicKey(&rsaKey.PublicKey)
	block := &pem.Block{Type: "RSA PUBLIC KEY", Bytes: pkcs1Bytes}
	pemData := string(pem.EncodeToMemory(block))

	parsed, err := parsePublicKeyFromPEM(pemData, "RSA")
	require.NoError(t, err)
	assert.IsType(t, &rsa.PublicKey{}, parsed)
}

func TestCoverage_ParsePublicKeyFromPEM_InvalidBytes(t *testing.T) {
	block := &pem.Block{Type: "PUBLIC KEY", Bytes: []byte{0x01, 0x02, 0x03}}
	pemData := string(pem.EncodeToMemory(block))

	_, err := parsePublicKeyFromPEM(pemData, "RSA")
	assert.Error(t, err)
}

func TestCoverage_ParsePublicKeyFromXKMS_InvalidAlgorithm(t *testing.T) {
	_, err := parsePublicKeyFromXKMS([]byte{0x01}, "UNKNOWN")
	assert.Error(t, err)
}

// xkmsSigner.Public coverage
func TestCoverage_XkmsSigner_Public(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer := &xkmsSigner{publicKey: &rsaKey.PublicKey}
	assert.Equal(t, &rsaKey.PublicKey, signer.Public())
}

// quicbaasKMSSigner.Public coverage
func TestCoverage_QuicbaasKMSSigner_Public(t *testing.T) {
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	signer := &quicbaasKMSSigner{publicKey: &rsaKey.PublicKey}
	assert.Equal(t, &rsaKey.PublicKey, signer.Public())
}

// =============================================================================
// plugin.go Save function coverage
// =============================================================================

func TestCoverage_Plugin_Save_NilZoneDAO(t *testing.T) {
	origDAO := zoneDAO
	defer func() { zoneDAO = origDAO }()

	zoneDAO = nil

	ctx := context.Background()
	zone := &entities.Zone{Name: "test.com.", TTL: 3600}

	err := Save(ctx, zone)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "zone DAO not initialized")
}

func TestCoverage_Plugin_Save_Success(t *testing.T) {
	origDAO := zoneDAO
	origConfig := Configuration
	origKeyStore := KeyStore
	origAdapter := XKMSAdapter
	defer func() {
		zoneDAO = origDAO
		Configuration = origConfig
		KeyStore = origKeyStore
		XKMSAdapter = origAdapter
	}()

	// No DNSSEC
	Configuration = nil
	KeyStore = nil
	XKMSAdapter = nil

	mockDAO := mocks.NewMockZoneDAO()
	zoneDAO = mockDAO

	ctx := context.Background()
	zone := &entities.Zone{Name: "test.com.", TTL: 3600}

	err := Save(ctx, zone)
	require.NoError(t, err)
	assert.NotEqual(t, uint64(0), zone.ID) // ID should be assigned
}

func TestCoverage_Plugin_Save_AssignsIDWhenZero(t *testing.T) {
	origDAO := zoneDAO
	origConfig := Configuration
	defer func() {
		zoneDAO = origDAO
		Configuration = origConfig
	}()

	Configuration = nil
	mockDAO := mocks.NewMockZoneDAO()
	zoneDAO = mockDAO

	ctx := context.Background()
	zone := &entities.Zone{ID: 0, Name: "assign-id.com.", TTL: 3600}

	err := Save(ctx, zone)
	require.NoError(t, err)
	assert.Equal(t, util.NewID([]byte("assign-id.com.")), zone.ID)
}

func TestCoverage_Plugin_Save_PreservesExistingID(t *testing.T) {
	origDAO := zoneDAO
	origConfig := Configuration
	defer func() {
		zoneDAO = origDAO
		Configuration = origConfig
	}()

	Configuration = nil
	mockDAO := mocks.NewMockZoneDAO()
	zoneDAO = mockDAO

	ctx := context.Background()
	zone := &entities.Zone{ID: 42, Name: "has-id.com.", TTL: 3600}

	err := Save(ctx, zone)
	require.NoError(t, err)
	assert.Equal(t, uint64(42), zone.ID)
}

func TestCoverage_Plugin_Save_DAOError(t *testing.T) {
	origDAO := zoneDAO
	origConfig := Configuration
	defer func() {
		zoneDAO = origDAO
		Configuration = origConfig
	}()

	Configuration = nil
	mockDAO := mocks.NewMockZoneDAO()
	mockDAO.SaveFunc = func(_ context.Context, _ *entities.Zone) error {
		return mocks.ErrMockSave
	}
	zoneDAO = mockDAO

	ctx := context.Background()
	zone := &entities.Zone{Name: "fail.com.", TTL: 3600}

	err := Save(ctx, zone)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "failed to save zone")
}

// =============================================================================
// plugin.go signZoneIfEnabled with KeyStore
// =============================================================================

func TestCoverage_SignZoneIfEnabled_WithKeyStore(t *testing.T) {
	origConfig := Configuration
	origKeyStore := KeyStore
	origAdapter := XKMSAdapter
	defer func() {
		Configuration = origConfig
		KeyStore = origKeyStore
		XKMSAdapter = origAdapter
	}()

	Configuration = &Config{
		Logger: logging.DefaultLogger(),
		DNSSEC: &DNSSECConfig{
			Enabled: true,
			DefaultKey: &common.KeyConfig{
				KeyAlgorithm: "ECDSA",
				ECCConfig:    &common.ECCConfig{Curve: "P-256"},
			},
			SignatureExpiry: "30d",
			NSECMode:        "nsec",
		},
	}
	KeyStore = NewMockKeyStore()
	XKMSAdapter = nil

	zone := createTestZone()
	err := signZoneIfEnabled(zone)
	require.NoError(t, err)

	// Zone should now have DNSSEC records
	assert.Greater(t, len(zone.RecordSet.DNSKEYRecords), 0)
	assert.Greater(t, len(zone.RecordSet.RRSIGRecords), 0)
}

// =============================================================================
// plugin.go processZone coverage
// =============================================================================

func TestCoverage_ProcessZone_EmptyName(t *testing.T) {
	mockDAO := mocks.NewMockZoneDAO()
	zone := entities.Zone{Name: ""}

	err := processZone(zone, mockDAO, "internal")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "not defined in configuration")
}

func TestCoverage_ProcessZone_NewZone(t *testing.T) {
	origConfig := Configuration
	defer func() { Configuration = origConfig }()

	Configuration = &Config{
		Logger: logging.DefaultLogger(),
	}

	mockDAO := mocks.NewMockZoneDAO()
	zone := entities.Zone{
		Name: "newzone.com.",
		TTL:  3600,
		RecordSet: entities.RecordSet{
			SOARecord: entities.SOARecord{
				Name:  "newzone.com.",
				MName: "ns1.newzone.com.",
			},
		},
	}

	err := processZone(zone, mockDAO, "public")
	require.NoError(t, err)
	assert.Equal(t, 1, mockDAO.ZoneCount())
}

func TestCoverage_ProcessZone_ExistingZone(t *testing.T) {
	origConfig := Configuration
	defer func() { Configuration = origConfig }()

	// DNSSEC disabled
	Configuration = &Config{
		Logger: logging.DefaultLogger(),
	}

	mockDAO := mocks.NewMockZoneDAO()
	existing := &entities.Zone{
		ID:   util.NewID([]byte("existing.com.")),
		Name: "existing.com.",
		TTL:  3600,
	}
	mockDAO.AddZone(existing)

	zone := entities.Zone{
		Name: "existing.com.",
		TTL:  3600,
	}

	err := processZone(zone, mockDAO, "internal")
	require.NoError(t, err)
}

// =============================================================================
// plugin.go SignUnsignedZones with zones
// =============================================================================

func TestCoverage_SignUnsignedZones_WithZones(t *testing.T) {
	origConfig := Configuration
	origKeyStore := KeyStore
	origAdapter := XKMSAdapter
	origDAO := zoneDAO
	defer func() {
		Configuration = origConfig
		KeyStore = origKeyStore
		XKMSAdapter = origAdapter
		zoneDAO = origDAO
	}()

	Configuration = &Config{
		Logger: logging.DefaultLogger(),
		DNSSEC: &DNSSECConfig{
			Enabled: true,
			DefaultKey: &common.KeyConfig{
				KeyAlgorithm: "ECDSA",
				ECCConfig:    &common.ECCConfig{Curve: "P-256"},
			},
			SignatureExpiry: "30d",
			NSECMode:        "nsec",
		},
		InternalServer: &InternalServer{
			Zone: entities.Zone{Name: "internal.test."},
		},
		PublicServer: &PublicServer{
			Zone: entities.Zone{Name: "public.test."},
		},
	}

	KeyStore = NewMockKeyStore()
	XKMSAdapter = nil

	mockDAO := mocks.NewMockZoneDAO()

	// Add an unsigned zone
	unsignedZone := &entities.Zone{
		ID:       util.NewID([]byte("internal.test.")),
		Name:     "internal.test.",
		TenantID: "platform",
		TTL:      3600,
		RecordSet: entities.RecordSet{
			SOARecord: entities.SOARecord{
				Name:  "internal.test.",
				MName: "ns1.internal.test.",
				RName: "hostmaster.internal.test.",
			},
			ARecords: []*entities.ARecord{
				{Name: "@", Value: "192.168.1.1", TTL: 3600},
			},
		},
	}
	mockDAO.AddZone(unsignedZone)

	// Set up GetByName to return the zone
	mockDAO.GetByNameFunc = func(_ context.Context, name string) (*entities.Zone, error) {
		if name == "internal.test." {
			return unsignedZone, nil
		}
		return nil, mocks.ErrZoneNotFound
	}

	zoneDAO = mockDAO

	err := SignUnsignedZones()
	require.NoError(t, err)

	// The zone should now have DNSSEC records
	assert.Greater(t, len(unsignedZone.RecordSet.DNSKEYRecords), 0)
}

// =============================================================================
// service.go SaveAndSign success path coverage
// =============================================================================

func TestCoverage_Service_SaveAndSign_Success(t *testing.T) {
	svc, mockDAO := createServiceWithMockDAO(t, "tenant-1")
	ctx := context.Background()

	zone := &entities.Zone{
		Name:     "example.com.",
		TenantID: "tenant-1",
		TTL:      3600,
	}

	err := svc.SaveAndSign(ctx, zone)
	require.NoError(t, err)
	assert.Equal(t, 1, mockDAO.ZoneCount())
}

// =============================================================================
// service.go Save with DNSSEC enabled
// =============================================================================

func TestCoverage_Service_Save_WithDNSSEC(t *testing.T) {
	logger := logging.DefaultLogger()
	mockStorage := quicbaas.NewMockStorage()
	err := mockStorage.Start(context.Background())
	require.NoError(t, err)
	ds := NewDatastore(mockStorage, logger)

	store := NewMockKeyStore()
	svcParams := &Params{
		TenantID: "tenant-1",
		Config: &Config{
			Logger: logger,
			DNSSEC: &DNSSECConfig{
				Enabled: true,
				DefaultKey: &common.KeyConfig{
					KeyAlgorithm: "ECDSA",
					ECCConfig:    &common.ECCConfig{Curve: "P-256"},
				},
				SignatureExpiry: "30d",
				NSECMode:        "nsec",
			},
		},
		Datastore:      ds,
		DNSSECKeyStore: store,
	}

	svc, err := NewService(svcParams)
	require.NoError(t, err)

	mockDAO := mocks.NewMockZoneDAO()
	svc.zoneDAO = mockDAO

	ctx := context.Background()
	zone := createTestZone()
	zone.TenantID = "tenant-1"

	err = svc.Save(ctx, zone)
	require.NoError(t, err)

	// Zone should have DNSSEC records after save
	assert.Greater(t, len(zone.RecordSet.DNSKEYRecords), 0)
}

// =============================================================================
// service.go SaveAndSign with DNSSEC enabled
// =============================================================================

func TestCoverage_Service_SaveAndSign_WithDNSSEC(t *testing.T) {
	logger := logging.DefaultLogger()
	mockStorage := quicbaas.NewMockStorage()
	err := mockStorage.Start(context.Background())
	require.NoError(t, err)
	ds := NewDatastore(mockStorage, logger)

	store := NewMockKeyStore()
	svcParams := &Params{
		TenantID: "tenant-1",
		Config: &Config{
			Logger: logger,
			DNSSEC: &DNSSECConfig{
				Enabled: true,
				DefaultKey: &common.KeyConfig{
					KeyAlgorithm: "ECDSA",
					ECCConfig:    &common.ECCConfig{Curve: "P-256"},
				},
				SignatureExpiry: "30d",
				NSECMode:        "nsec",
			},
		},
		Datastore:      ds,
		DNSSECKeyStore: store,
	}

	svc, err := NewService(svcParams)
	require.NoError(t, err)

	mockDAO := mocks.NewMockZoneDAO()
	svc.zoneDAO = mockDAO

	ctx := context.Background()
	zone := createTestZone()
	zone.TenantID = "tenant-1"

	err = svc.SaveAndSign(ctx, zone)
	require.NoError(t, err)

	assert.Greater(t, len(zone.RecordSet.DNSKEYRecords), 0)
}
