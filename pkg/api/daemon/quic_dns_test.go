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

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHandleDNSOperation_ServiceNotAvailable tests that DNS operations return
// StatusUnavailable when the DNS service is not configured
func TestHandleDNSOperation_ServiceNotAvailable(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)

	ctx := context.Background()

	testCases := []struct {
		name   string
		opcode byte
	}{
		{"AddRecord", quic.OpDNSAddRecord},
		{"DeleteRecord", quic.OpDNSDeleteRecord},
		{"UpdateRecord", quic.OpDNSUpdateRecord},
		{"GetRecord", quic.OpDNSGetRecord},
		{"ListRecords", quic.OpDNSListRecords},
		{"AddZone", quic.OpDNSAddZone},
		{"DeleteZone", quic.OpDNSDeleteZone},
		{"GetZone", quic.OpDNSGetZone},
		{"ListZones", quic.OpDNSListZones},
		{"Resolve", quic.OpDNSResolve},
		{"GetConfig", quic.OpDNSGetConfig},
		{"UpdateConfig", quic.OpDNSUpdateConfig},
		{"GetMetrics", quic.OpDNSGetMetrics},
		{"FlushCache", quic.OpDNSFlushCache},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := &quic.Request{
				Opcode:  tc.opcode,
				Payload: []byte{},
			}
			resp := handler.HandleRequest(ctx, req)

			assert.Equal(t, quic.StatusUnavailable, resp.Status)
			assert.Contains(t, string(resp.Payload), "DNS service not available")
		})
	}
}

// TestConvertToQUICRecord tests record type conversion
func TestConvertToQUICRecord(t *testing.T) {
	t.Run("nil record returns nil", func(t *testing.T) {
		result := convertToQUICRecord(nil, "A")
		assert.Nil(t, result)
	})

	t.Run("A record conversion", func(t *testing.T) {
		record := &entities.ARecord{
			Name:  "test.example.com",
			Value: "192.168.1.1",
			TTL:   3600,
		}
		result := convertToQUICRecord(record, "A")
		require.NotNil(t, result)
		assert.Equal(t, "test.example.com", result.Name)
		assert.Equal(t, "192.168.1.1", result.Value)
		assert.Equal(t, uint32(3600), result.TTL)
		assert.Equal(t, "A", result.RecordType)
	})

	t.Run("AAAA record conversion", func(t *testing.T) {
		record := &entities.AAAARecord{
			Name:  "test.example.com",
			Value: "2001:db8::1",
			TTL:   3600,
		}
		result := convertToQUICRecord(record, "AAAA")
		require.NotNil(t, result)
		assert.Equal(t, "test.example.com", result.Name)
		assert.Equal(t, "2001:db8::1", result.Value)
	})

	t.Run("CNAME record conversion", func(t *testing.T) {
		record := &entities.CNAMERecord{
			Name:  "www.example.com",
			Value: "example.com",
			TTL:   3600,
		}
		result := convertToQUICRecord(record, "CNAME")
		require.NotNil(t, result)
		assert.Equal(t, "www.example.com", result.Name)
		assert.Equal(t, "example.com", result.Value)
	})

	t.Run("TXT record conversion", func(t *testing.T) {
		record := &entities.TXTRecord{
			Name:  "example.com",
			Value: "v=spf1 include:_spf.google.com ~all",
			TTL:   3600,
		}
		result := convertToQUICRecord(record, "TXT")
		require.NotNil(t, result)
		assert.Equal(t, "example.com", result.Name)
		assert.Contains(t, result.Value, "spf1")
	})

	t.Run("MX record conversion", func(t *testing.T) {
		record := &entities.MXRecord{
			Name:     "example.com",
			Value:    "mail.example.com",
			Priority: 10,
			TTL:      3600,
		}
		result := convertToQUICRecord(record, "MX")
		require.NotNil(t, result)
		assert.Equal(t, "example.com", result.Name)
		assert.Equal(t, "mail.example.com", result.Value)
		assert.Equal(t, uint16(10), result.Priority)
	})

	t.Run("NS record conversion", func(t *testing.T) {
		record := &entities.NSRecord{
			Name:  "example.com",
			Value: "ns1.example.com",
			TTL:   86400,
		}
		result := convertToQUICRecord(record, "NS")
		require.NotNil(t, result)
		assert.Equal(t, "example.com", result.Name)
		assert.Equal(t, "ns1.example.com", result.Value)
	})

	t.Run("unknown record type returns nil", func(t *testing.T) {
		result := convertToQUICRecord("unknown", "UNKNOWN")
		assert.Nil(t, result)
	})
}

// TestConvertInterfaceToQUICRecord tests generic interface conversion
func TestConvertInterfaceToQUICRecord(t *testing.T) {
	t.Run("nil record returns nil", func(t *testing.T) {
		result := convertInterfaceToQUICRecord(nil)
		assert.Nil(t, result)
	})

	t.Run("A record sets correct type", func(t *testing.T) {
		record := &entities.ARecord{
			Name:  "test.example.com",
			Value: "192.168.1.1",
			TTL:   3600,
		}
		result := convertInterfaceToQUICRecord(record)
		require.NotNil(t, result)
		assert.Equal(t, "A", result.RecordType)
	})

	t.Run("AAAA record sets correct type", func(t *testing.T) {
		record := &entities.AAAARecord{
			Name:  "test.example.com",
			Value: "2001:db8::1",
			TTL:   3600,
		}
		result := convertInterfaceToQUICRecord(record)
		require.NotNil(t, result)
		assert.Equal(t, "AAAA", result.RecordType)
	})

	t.Run("CNAME record sets correct type", func(t *testing.T) {
		record := &entities.CNAMERecord{
			Name:  "www.example.com",
			Value: "example.com",
			TTL:   3600,
		}
		result := convertInterfaceToQUICRecord(record)
		require.NotNil(t, result)
		assert.Equal(t, "CNAME", result.RecordType)
	})

	t.Run("TXT record sets correct type", func(t *testing.T) {
		record := &entities.TXTRecord{
			Name:  "example.com",
			Value: "test",
			TTL:   3600,
		}
		result := convertInterfaceToQUICRecord(record)
		require.NotNil(t, result)
		assert.Equal(t, "TXT", result.RecordType)
	})

	t.Run("MX record sets correct type", func(t *testing.T) {
		record := &entities.MXRecord{
			Name:     "example.com",
			Value:    "mail.example.com",
			Priority: 10,
			TTL:      3600,
		}
		result := convertInterfaceToQUICRecord(record)
		require.NotNil(t, result)
		assert.Equal(t, "MX", result.RecordType)
		assert.Equal(t, uint16(10), result.Priority)
	})

	t.Run("NS record sets correct type", func(t *testing.T) {
		record := &entities.NSRecord{
			Name:  "example.com",
			Value: "ns1.example.com",
			TTL:   86400,
		}
		result := convertInterfaceToQUICRecord(record)
		require.NotNil(t, result)
		assert.Equal(t, "NS", result.RecordType)
	})

	t.Run("unknown type returns nil", func(t *testing.T) {
		result := convertInterfaceToQUICRecord("unknown")
		assert.Nil(t, result)
	})
}

// TestCountZoneRecords tests zone record counting
func TestCountZoneRecords(t *testing.T) {
	t.Run("nil zone returns 0", func(t *testing.T) {
		count := countZoneRecords(nil)
		assert.Equal(t, 0, count)
	})

	t.Run("empty zone returns 0", func(t *testing.T) {
		zone := &entities.Zone{}
		count := countZoneRecords(zone)
		assert.Equal(t, 0, count)
	})

	t.Run("zone with SOA record counts 1", func(t *testing.T) {
		zone := &entities.Zone{
			RecordSet: entities.RecordSet{
				SOARecord: entities.SOARecord{
					Name: "example.com",
				},
			},
		}
		count := countZoneRecords(zone)
		assert.Equal(t, 1, count)
	})

	t.Run("zone with multiple records counts correctly", func(t *testing.T) {
		zone := &entities.Zone{
			RecordSet: entities.RecordSet{
				SOARecord: entities.SOARecord{Name: "example.com"},
				ARecords: []*entities.ARecord{
					{Name: "test1", Value: "1.2.3.4"},
					{Name: "test2", Value: "5.6.7.8"},
				},
				AAAARecords: []*entities.AAAARecord{
					{Name: "test1", Value: "2001:db8::1"},
				},
				MXRecords: []*entities.MXRecord{
					{Name: "example.com", Value: "mail.example.com"},
				},
			},
		}
		count := countZoneRecords(zone)
		assert.Equal(t, 5, count) // 1 SOA + 2 A + 1 AAAA + 1 MX
	})

	t.Run("zone with all record types counts correctly", func(t *testing.T) {
		zone := &entities.Zone{
			RecordSet: entities.RecordSet{
				SOARecord: entities.SOARecord{Name: "example.com"},
				ARecords: []*entities.ARecord{
					{Name: "test1", Value: "1.2.3.4"},
				},
				AAAARecords: []*entities.AAAARecord{
					{Name: "test1", Value: "2001:db8::1"},
				},
				CNAMERecords: []*entities.CNAMERecord{
					{Name: "www", Value: "example.com"},
				},
				TXTRecords: []*entities.TXTRecord{
					{Name: "@", Value: "v=spf1"},
				},
				MXRecords: []*entities.MXRecord{
					{Name: "example.com", Value: "mail.example.com"},
				},
				NSRecords: []*entities.NSRecord{
					{Name: "ns1", Value: "ns1.example.com"},
				},
				SRVRecords: []*entities.SRVRecord{
					{Name: "_sip._tcp", Target: "sip.example.com"},
				},
				CAARecords: []*entities.CAARecord{
					{Name: "example.com", Tag: "issue", Value: "letsencrypt.org"},
				},
				TLSARecords: []*entities.TLSARecord{
					{Name: "_443._tcp", Data: "abc123"},
				},
				DNSKEYRecords: []*entities.DNSKEYRecord{
					{Name: "example.com", Key: "key123"},
				},
				DSRecords: []*entities.DSRecord{
					{Name: "example.com", Digest: "digest123"},
				},
				RRSIGRecords: []*entities.RRSIGRecord{
					{SignerName: "example.com", Signature: "sig123"},
				},
				NSECRecords: []*entities.NSECRecord{
					{Name: "example.com", NextDomain: "next.example.com"},
				},
				NSEC3Records: []*entities.NSEC3Record{
					{Name: "hash.example.com", NextHashed: "nexthash"},
				},
				NSEC3PARAMRecords: []*entities.NSEC3PARAMRecord{
					{Name: "example.com", Salt: "salt123"},
				},
			},
		}
		count := countZoneRecords(zone)
		// 1 SOA + 1 A + 1 AAAA + 1 CNAME + 1 TXT + 1 MX + 1 NS + 1 SRV + 1 CAA +
		// 1 TLSA + 1 DNSKEY + 1 DS + 1 RRSIG + 1 NSEC + 1 NSEC3 + 1 NSEC3PARAM = 16
		assert.Equal(t, 16, count)
	})
}

// TestDNSRequestResponse_Encoding tests that request/response types encode/decode correctly
func TestDNSRequestResponse_Encoding(t *testing.T) {
	t.Run("DNSAddRecordRequest roundtrip", func(t *testing.T) {
		original := &DNSAddRecordRequest{
			Zone:       "example.com",
			Name:       "test.example.com",
			RecordType: "A",
			Value:      "192.168.1.1",
			TTL:        3600,
			Priority:   10,
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
	})

	t.Run("DNSAddRecordResponse roundtrip", func(t *testing.T) {
		original := &DNSAddRecordResponse{
			Success:   true,
			Zone:      "example.com",
			Name:      "test.example.com",
			Timestamp: 1704067200,
		}

		encoded, err := quic.EncodePayload(original)
		require.NoError(t, err)

		var decoded DNSAddRecordResponse
		err = quic.DecodePayload(encoded, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.Success, decoded.Success)
		assert.Equal(t, original.Zone, decoded.Zone)
		assert.Equal(t, original.Name, decoded.Name)
		assert.Equal(t, original.Timestamp, decoded.Timestamp)
	})

	t.Run("DNSDeleteRecordRequest roundtrip", func(t *testing.T) {
		original := &DNSDeleteRecordRequest{
			Zone:       "example.com",
			Name:       "test.example.com",
			RecordType: "A",
		}

		encoded, err := quic.EncodePayload(original)
		require.NoError(t, err)

		var decoded DNSDeleteRecordRequest
		err = quic.DecodePayload(encoded, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.Zone, decoded.Zone)
		assert.Equal(t, original.Name, decoded.Name)
		assert.Equal(t, original.RecordType, decoded.RecordType)
	})

	t.Run("DNSUpdateRecordRequest roundtrip", func(t *testing.T) {
		original := &DNSUpdateRecordRequest{
			Zone:       "example.com",
			Name:       "test.example.com",
			RecordType: "A",
			Value:      "192.168.1.2",
			TTL:        7200,
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
	})

	t.Run("DNSResolveResponse roundtrip", func(t *testing.T) {
		original := &DNSResolveResponse{
			Name:      "test.example.com",
			Type:      "A",
			Values:    []string{"192.168.1.1", "192.168.1.2"},
			Timestamp: 1704067200,
		}

		encoded, err := quic.EncodePayload(original)
		require.NoError(t, err)

		var decoded DNSResolveResponse
		err = quic.DecodePayload(encoded, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.Name, decoded.Name)
		assert.Equal(t, original.Type, decoded.Type)
		assert.Equal(t, original.Values, decoded.Values)
		assert.Equal(t, original.Timestamp, decoded.Timestamp)
	})

	t.Run("DNSZone roundtrip", func(t *testing.T) {
		original := &DNSZone{
			ID:          1,
			Name:        "example.com",
			TTL:         3600,
			Description: "Test zone",
			Internal:    true,
			RecordCount: 10,
		}

		encoded, err := quic.EncodePayload(original)
		require.NoError(t, err)

		var decoded DNSZone
		err = quic.DecodePayload(encoded, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.ID, decoded.ID)
		assert.Equal(t, original.Name, decoded.Name)
		assert.Equal(t, original.TTL, decoded.TTL)
		assert.Equal(t, original.Description, decoded.Description)
		assert.Equal(t, original.Internal, decoded.Internal)
		assert.Equal(t, original.RecordCount, decoded.RecordCount)
	})

	t.Run("DNSConfig roundtrip", func(t *testing.T) {
		original := &DNSConfig{
			InternalDomain:    "internal.local",
			PublicDomain:      "example.com",
			DNSSECEnabled:     true,
			AllowRegistration: false,
		}

		encoded, err := quic.EncodePayload(original)
		require.NoError(t, err)

		var decoded DNSConfig
		err = quic.DecodePayload(encoded, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.InternalDomain, decoded.InternalDomain)
		assert.Equal(t, original.PublicDomain, decoded.PublicDomain)
		assert.Equal(t, original.DNSSECEnabled, decoded.DNSSECEnabled)
		assert.Equal(t, original.AllowRegistration, decoded.AllowRegistration)
	})

	t.Run("DNSMetrics roundtrip", func(t *testing.T) {
		original := &DNSMetrics{
			ZoneCount:        5,
			TotalRecords:     100,
			QueriesTotal:     10000,
			CacheHits:        8000,
			CacheMisses:      2000,
			DNSSECValidated:  9000,
			ForwardedQueries: 500,
		}

		encoded, err := quic.EncodePayload(original)
		require.NoError(t, err)

		var decoded DNSMetrics
		err = quic.DecodePayload(encoded, &decoded)
		require.NoError(t, err)

		assert.Equal(t, original.ZoneCount, decoded.ZoneCount)
		assert.Equal(t, original.TotalRecords, decoded.TotalRecords)
		assert.Equal(t, original.QueriesTotal, decoded.QueriesTotal)
		assert.Equal(t, original.CacheHits, decoded.CacheHits)
		assert.Equal(t, original.CacheMisses, decoded.CacheMisses)
		assert.Equal(t, original.DNSSECValidated, decoded.DNSSECValidated)
		assert.Equal(t, original.ForwardedQueries, decoded.ForwardedQueries)
	})

	t.Run("DNSListZonesRequest with nil internal roundtrip", func(t *testing.T) {
		original := &DNSListZonesRequest{
			Internal: nil,
		}

		encoded, err := quic.EncodePayload(original)
		require.NoError(t, err)

		var decoded DNSListZonesRequest
		err = quic.DecodePayload(encoded, &decoded)
		require.NoError(t, err)

		assert.Nil(t, decoded.Internal)
	})

	t.Run("DNSListZonesRequest with internal=true roundtrip", func(t *testing.T) {
		internal := true
		original := &DNSListZonesRequest{
			Internal: &internal,
		}

		encoded, err := quic.EncodePayload(original)
		require.NoError(t, err)

		var decoded DNSListZonesRequest
		err = quic.DecodePayload(encoded, &decoded)
		require.NoError(t, err)

		require.NotNil(t, decoded.Internal)
		assert.True(t, *decoded.Internal)
	})
}

// TestDNSRecord_Fields tests DNSRecord struct field handling
func TestDNSRecord_Fields(t *testing.T) {
	t.Run("all fields set correctly", func(t *testing.T) {
		record := &DNSRecord{
			Name:       "test.example.com",
			RecordType: "MX",
			Value:      "mail.example.com",
			TTL:        3600,
			Priority:   10,
		}

		assert.Equal(t, "test.example.com", record.Name)
		assert.Equal(t, "MX", record.RecordType)
		assert.Equal(t, "mail.example.com", record.Value)
		assert.Equal(t, uint32(3600), record.TTL)
		assert.Equal(t, uint16(10), record.Priority)
	})
}

// TestDNSErrors tests error type behaviors
func TestDNSErrors(t *testing.T) {
	t.Run("ErrDNSServiceNotAvailable error message", func(t *testing.T) {
		err := ErrDNSServiceNotAvailable{}
		assert.Equal(t, "DNS service not available", err.Error())
	})

	t.Run("ErrDNSConfigUpdateNotSupported error message", func(t *testing.T) {
		err := ErrDNSConfigUpdateNotSupported{}
		assert.Equal(t, "DNS configuration updates are not supported at runtime", err.Error())
	})

	t.Run("ErrDNSCacheFlushNotSupported error message", func(t *testing.T) {
		err := ErrDNSCacheFlushNotSupported{}
		assert.Equal(t, "DNS cache flushing is not supported", err.Error())
	})

	t.Run("ErrDNSZoneNotFound error message", func(t *testing.T) {
		err := ErrDNSZoneNotFound{Zone: "example.com"}
		assert.Equal(t, "DNS zone not found: example.com", err.Error())
	})

	t.Run("ErrDNSRecordNotFound error message", func(t *testing.T) {
		err := ErrDNSRecordNotFound{Name: "test.example.com", RecordType: "A"}
		assert.Equal(t, "DNS record not found: test.example.com A", err.Error())
	})

	t.Run("ErrDNSOperationFailed error message and unwrap", func(t *testing.T) {
		cause := assert.AnError
		err := ErrDNSOperationFailed{Operation: "AddRecord", Cause: cause}
		assert.Contains(t, err.Error(), "DNS operation AddRecord failed")
		assert.Equal(t, cause, err.Unwrap())
	})
}

// TestQUICServiceHandler_SetDNSService tests the SetDNSService method
func TestQUICServiceHandler_SetDNSService(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)

	// Initially nil
	assert.Nil(t, handler.dnsService)

	// After setting to nil explicitly
	handler.SetDNSService(nil)
	assert.Nil(t, handler.dnsService)
}

// TestWithQUICDNSService tests the functional option
func TestWithQUICDNSService(t *testing.T) {
	logger := logging.DefaultLogger()

	t.Run("with nil service", func(t *testing.T) {
		handler := NewQUICServiceHandler(logger, WithQUICDNSService(nil))
		assert.Nil(t, handler.dnsService)
	})
}
