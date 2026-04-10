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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
)

// DeleteRecord Coverage Tests

func TestDNSServiceServer_DeleteRecord_ZoneNotFound(t *testing.T) {
	mock := newMockDNSService()
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.DeleteRecordRequest{
		ZoneName: "nonexistent.com.",
		Type:     platformv1.RecordType_RECORD_TYPE_A,
		Name:     "www",
	}

	_, err := server.DeleteRecord(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
	assert.Contains(t, st.Message(), "not found")
}

func TestDNSServiceServer_DeleteRecord_ZoneError(t *testing.T) {
	mock := newMockDNSService()
	mock.zoneErr = errors.New("database connection failed")
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
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestDNSServiceServer_DeleteRecord_NonExistentRecord(t *testing.T) {
	mock := newMockDNSService()
	mock.zones["example.com."] = &entities.Zone{
		ID:   1,
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			ARecords: []*entities.ARecord{
				{Name: "existing", Value: "192.168.1.1", TTL: 3600},
			},
		},
	}
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.DeleteRecordRequest{
		ZoneName: "example.com.",
		Type:     platformv1.RecordType_RECORD_TYPE_A,
		Name:     "nonexistent",
	}

	resp, err := server.DeleteRecord(context.Background(), req)

	require.NoError(t, err)
	assert.True(t, resp.Status.Success)
	assert.Len(t, resp.Zone.Records.ARecords, 1)
}

func TestDNSServiceServer_DeleteRecord_UnspecifiedType(t *testing.T) {
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
		Type:     platformv1.RecordType_RECORD_TYPE_UNSPECIFIED,
		Name:     "www",
	}

	resp, err := server.DeleteRecord(context.Background(), req)

	require.NoError(t, err)
	assert.True(t, resp.Status.Success)
	assert.Len(t, resp.Zone.Records.ARecords, 1)
}

// UpdateRecord Coverage Tests

func TestDNSServiceServer_UpdateRecord_ZoneNotFound(t *testing.T) {
	mock := newMockDNSService()
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.UpdateRecordRequest{
		ZoneName: "nonexistent.com.",
		OldRecord: &platformv1.Record{
			Type:   platformv1.RecordType_RECORD_TYPE_A,
			Record: &platformv1.Record_A{A: &platformv1.ARecord{Name: "www", Value: "192.168.1.1"}},
		},
		NewRecord: &platformv1.Record{
			Type:   platformv1.RecordType_RECORD_TYPE_A,
			Record: &platformv1.Record_A{A: &platformv1.ARecord{Name: "www", Value: "192.168.1.2"}},
		},
	}

	_, err := server.UpdateRecord(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestDNSServiceServer_UpdateRecord_ZoneError(t *testing.T) {
	mock := newMockDNSService()
	mock.zoneErr = errors.New("database error")
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.UpdateRecordRequest{
		ZoneName: "example.com.",
		OldRecord: &platformv1.Record{
			Type:   platformv1.RecordType_RECORD_TYPE_A,
			Record: &platformv1.Record_A{A: &platformv1.ARecord{Name: "www", Value: "192.168.1.1"}},
		},
		NewRecord: &platformv1.Record{
			Type:   platformv1.RecordType_RECORD_TYPE_A,
			Record: &platformv1.Record_A{A: &platformv1.ARecord{Name: "www", Value: "192.168.1.2"}},
		},
	}

	_, err := server.UpdateRecord(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestDNSServiceServer_UpdateRecord_MissingNewRecord(t *testing.T) {
	mock := newMockDNSService()
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.UpdateRecordRequest{
		ZoneName: "example.com.",
		OldRecord: &platformv1.Record{
			Type:   platformv1.RecordType_RECORD_TYPE_A,
			Record: &platformv1.Record_A{A: &platformv1.ARecord{Name: "www", Value: "192.168.1.1"}},
		},
	}

	_, err := server.UpdateRecord(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
	assert.Contains(t, st.Message(), "old and new records are required")
}

func TestDNSServiceServer_UpdateRecord_InvalidNewRecordType(t *testing.T) {
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
			Record: &platformv1.Record_A{A: &platformv1.ARecord{Name: "www", Value: "192.168.1.1"}},
		},
		NewRecord: &platformv1.Record{
			Type: platformv1.RecordType_RECORD_TYPE_UNSPECIFIED,
		},
	}

	_, err := server.UpdateRecord(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.InvalidArgument, st.Code())
}

func TestDNSServiceServer_UpdateRecord_SaveError(t *testing.T) {
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

	req := &platformv1.UpdateRecordRequest{
		ZoneName: "example.com.",
		OldRecord: &platformv1.Record{
			Type:   platformv1.RecordType_RECORD_TYPE_A,
			Record: &platformv1.Record_A{A: &platformv1.ARecord{Name: "www", Value: "192.168.1.1"}},
		},
		NewRecord: &platformv1.Record{
			Type:   platformv1.RecordType_RECORD_TYPE_A,
			Record: &platformv1.Record_A{A: &platformv1.ARecord{Name: "www", Value: "192.168.1.2", Ttl: 7200}},
		},
	}

	_, err := server.UpdateRecord(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.Internal, st.Code())
}

func TestDNSServiceServer_UpdateRecord_AllRecordTypes(t *testing.T) {
	tests := []struct {
		name       string
		recordType platformv1.RecordType
		oldRecord  *platformv1.Record
		newRecord  *platformv1.Record
		recordSet  entities.RecordSet
	}{
		{
			name:       "AAAA record",
			recordType: platformv1.RecordType_RECORD_TYPE_AAAA,
			oldRecord: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_AAAA,
				Record: &platformv1.Record_Aaaa{Aaaa: &platformv1.AAAARecord{Name: "www", Value: "::1"}},
			},
			newRecord: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_AAAA,
				Record: &platformv1.Record_Aaaa{Aaaa: &platformv1.AAAARecord{Name: "www", Value: "::2", Ttl: 7200}},
			},
			recordSet: entities.RecordSet{AAAARecords: []*entities.AAAARecord{{Name: "www", Value: "::1"}}},
		},
		{
			name:       "CNAME record",
			recordType: platformv1.RecordType_RECORD_TYPE_CNAME,
			oldRecord: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_CNAME,
				Record: &platformv1.Record_Cname{Cname: &platformv1.CNAMERecord{Name: "alias", Value: "www.example.com."}},
			},
			newRecord: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_CNAME,
				Record: &platformv1.Record_Cname{Cname: &platformv1.CNAMERecord{Name: "alias", Value: "new.example.com.", Ttl: 7200}},
			},
			recordSet: entities.RecordSet{CNAMERecords: []*entities.CNAMERecord{{Name: "alias", Value: "www.example.com."}}},
		},
		{
			name:       "MX record",
			recordType: platformv1.RecordType_RECORD_TYPE_MX,
			oldRecord: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_MX,
				Record: &platformv1.Record_Mx{Mx: &platformv1.MXRecord{Name: "@", Value: "mail.example.com.", Priority: 10}},
			},
			newRecord: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_MX,
				Record: &platformv1.Record_Mx{Mx: &platformv1.MXRecord{Name: "@", Value: "mail2.example.com.", Priority: 20, Ttl: 7200}},
			},
			recordSet: entities.RecordSet{MXRecords: []*entities.MXRecord{{Name: "@", Value: "mail.example.com.", Priority: 10}}},
		},
		{
			name:       "NS record",
			recordType: platformv1.RecordType_RECORD_TYPE_NS,
			oldRecord: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_NS,
				Record: &platformv1.Record_Ns{Ns: &platformv1.NSRecord{Name: "@", Value: "ns1.example.com."}},
			},
			newRecord: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_NS,
				Record: &platformv1.Record_Ns{Ns: &platformv1.NSRecord{Name: "@", Value: "ns3.example.com.", Ttl: 7200}},
			},
			recordSet: entities.RecordSet{NSRecords: []*entities.NSRecord{{Name: "@", Value: "ns1.example.com."}}},
		},
		{
			name:       "TXT record",
			recordType: platformv1.RecordType_RECORD_TYPE_TXT,
			oldRecord: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_TXT,
				Record: &platformv1.Record_Txt{Txt: &platformv1.TXTRecord{Name: "@", Value: "v=spf1 old"}},
			},
			newRecord: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_TXT,
				Record: &platformv1.Record_Txt{Txt: &platformv1.TXTRecord{Name: "@", Value: "v=spf1 include:new.com ~all", Ttl: 7200}},
			},
			recordSet: entities.RecordSet{TXTRecords: []*entities.TXTRecord{{Name: "@", Value: "v=spf1 old"}}},
		},
		{
			name:       "SRV record",
			recordType: platformv1.RecordType_RECORD_TYPE_SRV,
			oldRecord: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_SRV,
				Record: &platformv1.Record_Srv{Srv: &platformv1.SRVRecord{Name: "_sip._tcp", Target: "sip.example.com.", Port: 5060, Priority: 10, Weight: 20}},
			},
			newRecord: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_SRV,
				Record: &platformv1.Record_Srv{Srv: &platformv1.SRVRecord{Name: "_sip._tcp", Target: "sip2.example.com.", Port: 5061, Priority: 5, Weight: 30, Ttl: 7200}},
			},
			recordSet: entities.RecordSet{SRVRecords: []*entities.SRVRecord{{Name: "_sip._tcp", Target: "sip.example.com.", Port: 5060, Priority: 10, Weight: 20}}},
		},
		{
			name:       "CAA record",
			recordType: platformv1.RecordType_RECORD_TYPE_CAA,
			oldRecord: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_CAA,
				Record: &platformv1.Record_Caa{Caa: &platformv1.CAARecord{Name: "@", Flags: 0, Tag: "issue", Value: "letsencrypt.org"}},
			},
			newRecord: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_CAA,
				Record: &platformv1.Record_Caa{Caa: &platformv1.CAARecord{Name: "@", Flags: 0, Tag: "issue", Value: "digicert.com", Ttl: 7200}},
			},
			recordSet: entities.RecordSet{CAARecords: []*entities.CAARecord{{Name: "@", Flags: 0, Tag: "issue", Value: "letsencrypt.org"}}},
		},
		{
			name:       "TLSA record",
			recordType: platformv1.RecordType_RECORD_TYPE_TLSA,
			oldRecord: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_TLSA,
				Record: &platformv1.Record_Tlsa{Tlsa: &platformv1.TLSARecord{Name: "_443._tcp.www", Usage: 3, Selector: 1, MatchingType: 1, Data: "olddata"}},
			},
			newRecord: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_TLSA,
				Record: &platformv1.Record_Tlsa{Tlsa: &platformv1.TLSARecord{Name: "_443._tcp.www", Usage: 3, Selector: 1, MatchingType: 1, Data: "newdata", Ttl: 7200}},
			},
			recordSet: entities.RecordSet{TLSARecords: []*entities.TLSARecord{{Name: "_443._tcp.www", Usage: 3, Selector: 1, MatchingType: 1, Data: "olddata"}}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := newMockDNSService()
			mock.zones["example.com."] = &entities.Zone{
				ID:        1,
				Name:      "example.com.",
				RecordSet: tt.recordSet,
			}
			server := NewDNSServiceServer(mock, testLogger())

			req := &platformv1.UpdateRecordRequest{
				ZoneName:  "example.com.",
				OldRecord: tt.oldRecord,
				NewRecord: tt.newRecord,
			}

			resp, err := server.UpdateRecord(context.Background(), req)
			require.NoError(t, err)
			assert.True(t, resp.Status.Success)
		})
	}
}

func TestDNSServiceServer_UpdateRecord_NilRecordData(t *testing.T) {
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
			Type: platformv1.RecordType_RECORD_TYPE_A,
		},
		NewRecord: &platformv1.Record{
			Type: platformv1.RecordType_RECORD_TYPE_A,
		},
	}

	resp, err := server.UpdateRecord(context.Background(), req)

	require.NoError(t, err)
	assert.True(t, resp.Status.Success)
}

// ListRecords Coverage Tests

func TestDNSServiceServer_ListRecords_ZoneNotFound(t *testing.T) {
	mock := newMockDNSService()
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.ListRecordsRequest{
		ZoneName: "nonexistent.com.",
		Type:     platformv1.RecordType_RECORD_TYPE_A,
	}

	_, err := server.ListRecords(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestDNSServiceServer_ListRecords_ZoneError(t *testing.T) {
	mock := newMockDNSService()
	mock.zoneErr = errors.New("database connection error")
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.ListRecordsRequest{
		ZoneName: "example.com.",
		Type:     platformv1.RecordType_RECORD_TYPE_A,
	}

	_, err := server.ListRecords(context.Background(), req)

	require.Error(t, err)
	st, ok := status.FromError(err)
	require.True(t, ok)
	assert.Equal(t, codes.NotFound, st.Code())
}

func TestDNSServiceServer_ListRecords_EmptyZone(t *testing.T) {
	mock := newMockDNSService()
	mock.zones["example.com."] = &entities.Zone{
		ID:        1,
		Name:      "example.com.",
		RecordSet: entities.RecordSet{},
	}
	server := NewDNSServiceServer(mock, testLogger())

	req := &platformv1.ListRecordsRequest{
		ZoneName: "example.com.",
		Type:     platformv1.RecordType_RECORD_TYPE_A,
	}

	resp, err := server.ListRecords(context.Background(), req)

	require.NoError(t, err)
	assert.Empty(t, resp.Records)
}

func TestDNSServiceServer_ListRecords_FilterBySpecificType(t *testing.T) {
	mock := newMockDNSService()
	mock.zones["example.com."] = &entities.Zone{
		ID:   1,
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			ARecords:    []*entities.ARecord{{Name: "www", Value: "192.168.1.1"}},
			AAAARecords: []*entities.AAAARecord{{Name: "www", Value: "::1"}},
			TXTRecords:  []*entities.TXTRecord{{Name: "@", Value: "v=spf1"}},
		},
	}
	server := NewDNSServiceServer(mock, testLogger())

	tests := []struct {
		name       string
		recordType platformv1.RecordType
		expected   int
	}{
		{"A records only", platformv1.RecordType_RECORD_TYPE_A, 1},
		{"AAAA records only", platformv1.RecordType_RECORD_TYPE_AAAA, 1},
		{"TXT records only", platformv1.RecordType_RECORD_TYPE_TXT, 1},
		{"MX records (none)", platformv1.RecordType_RECORD_TYPE_MX, 0},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := &platformv1.ListRecordsRequest{
				ZoneName: "example.com.",
				Type:     tt.recordType,
			}

			resp, err := server.ListRecords(context.Background(), req)

			require.NoError(t, err)
			assert.Len(t, resp.Records, tt.expected)
		})
	}
}

func TestDNSServiceServer_ListRecords_MultipleRecordsSameType(t *testing.T) {
	mock := newMockDNSService()
	mock.zones["example.com."] = &entities.Zone{
		ID:   1,
		Name: "example.com.",
		RecordSet: entities.RecordSet{
			ARecords: []*entities.ARecord{
				{Name: "www", Value: "192.168.1.1", TTL: 3600},
				{Name: "mail", Value: "192.168.1.2", TTL: 3600},
				{Name: "ftp", Value: "192.168.1.3", TTL: 3600},
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
	assert.Len(t, resp.Records, 3)
}

// getRecordName coverage tests for nil inner records

func TestDNSServiceServer_GetRecordName_NilInnerRecords(t *testing.T) {
	mock := newMockDNSService()
	server := NewDNSServiceServer(mock, testLogger())

	tests := []struct {
		name   string
		record *platformv1.Record
	}{
		{
			name: "A with nil inner",
			record: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_A,
				Record: &platformv1.Record_A{A: nil},
			},
		},
		{
			name: "AAAA with nil inner",
			record: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_AAAA,
				Record: &platformv1.Record_Aaaa{Aaaa: nil},
			},
		},
		{
			name: "CNAME with nil inner",
			record: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_CNAME,
				Record: &platformv1.Record_Cname{Cname: nil},
			},
		},
		{
			name: "MX with nil inner",
			record: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_MX,
				Record: &platformv1.Record_Mx{Mx: nil},
			},
		},
		{
			name: "NS with nil inner",
			record: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_NS,
				Record: &platformv1.Record_Ns{Ns: nil},
			},
		},
		{
			name: "TXT with nil inner",
			record: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_TXT,
				Record: &platformv1.Record_Txt{Txt: nil},
			},
		},
		{
			name: "SRV with nil inner",
			record: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_SRV,
				Record: &platformv1.Record_Srv{Srv: nil},
			},
		},
		{
			name: "CAA with nil inner",
			record: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_CAA,
				Record: &platformv1.Record_Caa{Caa: nil},
			},
		},
		{
			name: "TLSA with nil inner",
			record: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_TLSA,
				Record: &platformv1.Record_Tlsa{Tlsa: nil},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := server.getRecordName(tt.record)
			assert.Equal(t, "", result)
		})
	}
}

// addRecordToZone coverage tests for nil inner records

func TestDNSServiceServer_AddRecordToZone_NilInnerRecords(t *testing.T) {
	mock := newMockDNSService()
	server := NewDNSServiceServer(mock, testLogger())

	zone := &entities.Zone{
		ID:   1,
		Name: "example.com.",
	}

	tests := []struct {
		name   string
		record *platformv1.Record
	}{
		{
			name: "A with nil inner",
			record: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_A,
				Record: &platformv1.Record_A{A: nil},
			},
		},
		{
			name: "AAAA with nil inner",
			record: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_AAAA,
				Record: &platformv1.Record_Aaaa{Aaaa: nil},
			},
		},
		{
			name: "CNAME with nil inner",
			record: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_CNAME,
				Record: &platformv1.Record_Cname{Cname: nil},
			},
		},
		{
			name: "MX with nil inner",
			record: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_MX,
				Record: &platformv1.Record_Mx{Mx: nil},
			},
		},
		{
			name: "NS with nil inner",
			record: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_NS,
				Record: &platformv1.Record_Ns{Ns: nil},
			},
		},
		{
			name: "TXT with nil inner",
			record: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_TXT,
				Record: &platformv1.Record_Txt{Txt: nil},
			},
		},
		{
			name: "SRV with nil inner",
			record: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_SRV,
				Record: &platformv1.Record_Srv{Srv: nil},
			},
		},
		{
			name: "CAA with nil inner",
			record: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_CAA,
				Record: &platformv1.Record_Caa{Caa: nil},
			},
		},
		{
			name: "TLSA with nil inner",
			record: &platformv1.Record{
				Type:   platformv1.RecordType_RECORD_TYPE_TLSA,
				Record: &platformv1.Record_Tlsa{Tlsa: nil},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := server.addRecordToZone(zone, tt.record)
			require.NoError(t, err)
		})
	}
}
