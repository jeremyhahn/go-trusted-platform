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

// =============================================================================
// Shared test harness (used by all quic_dns*_test.go files)
// =============================================================================

// skipIfNoCodec skips the test if the QUIC codec is not available. The codec
// requires building with -tags codec_msgpack.
func skipIfNoCodec(t *testing.T) {
	t.Helper()
	if _, err := quic.EncodePayload(struct{}{}); err != nil {
		t.Skip("Skipping test - no codec available (build with -tags codec_msgpack)")
	}
}

// createDNSUnitTestHandler creates a QUICServiceHandler wired to the given DNS
// service. SetDNSService rebuilds the shared *DNSServiceServer delegate when
// the service implements the full dns.DNSService interface.
func createDNSUnitTestHandler(svc DNSService) *QUICServiceHandler {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	handler.SetDNSService(svc)
	return handler
}

// createDNSUnitTestRequest encodes payload into a QUIC request with the given
// opcode. A nil payload yields an empty body.
func createDNSUnitTestRequest(t *testing.T, opcode byte, payload interface{}) *quic.Request {
	t.Helper()
	skipIfNoCodec(t)

	var data []byte
	if payload != nil {
		var err error
		data, err = quic.EncodePayload(payload)
		if err != nil {
			t.Fatalf("failed to encode payload: %v", err)
		}
	}
	return &quic.Request{Opcode: opcode, Payload: data}
}

// =============================================================================
// Service availability
// =============================================================================

func TestHandleDNSOperation_ServiceNotAvailable(t *testing.T) {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	ctx := context.Background()

	opcodes := []struct {
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

	for _, tc := range opcodes {
		t.Run(tc.name, func(t *testing.T) {
			req := &quic.Request{Opcode: tc.opcode, Payload: []byte{}}
			resp := handler.HandleRequest(ctx, req)
			assert.Equal(t, quic.StatusUnavailable, resp.Status)
			assert.Contains(t, string(resp.Payload), "DNS service not available")
		})
	}
}

// =============================================================================
// Record conversion helpers
// =============================================================================

func TestConvertToQUICRecord(t *testing.T) {
	t.Run("nil returns nil", func(t *testing.T) {
		assert.Nil(t, convertToQUICRecord(nil, "A"))
	})
	t.Run("A", func(t *testing.T) {
		r := convertToQUICRecord(&entities.ARecord{Name: "www", Value: "1.2.3.4", TTL: 3600}, "A")
		require.NotNil(t, r)
		assert.Equal(t, "www", r.Name)
		assert.Equal(t, "1.2.3.4", r.Value)
		assert.Equal(t, uint32(3600), r.TTL)
		assert.Equal(t, "A", r.RecordType)
	})
	t.Run("MX carries priority", func(t *testing.T) {
		r := convertToQUICRecord(&entities.MXRecord{Name: "mail", Value: "mx1.", Priority: 10, TTL: 300}, "MX")
		require.NotNil(t, r)
		assert.Equal(t, uint16(10), r.Priority)
	})
	t.Run("unsupported type returns nil", func(t *testing.T) {
		assert.Nil(t, convertToQUICRecord(&entities.SRVRecord{Name: "x"}, "SRV"))
	})
}

func TestConvertInterfaceToQUICRecord(t *testing.T) {
	t.Run("nil returns nil", func(t *testing.T) {
		assert.Nil(t, convertInterfaceToQUICRecord(nil))
	})
	cases := []struct {
		name   string
		record interface{}
		typ    string
	}{
		{"A", &entities.ARecord{Name: "www", Value: "1.2.3.4", TTL: 300}, "A"},
		{"AAAA", &entities.AAAARecord{Name: "www", Value: "::1", TTL: 300}, "AAAA"},
		{"CNAME", &entities.CNAMERecord{Name: "a", Value: "b.", TTL: 300}, "CNAME"},
		{"TXT", &entities.TXTRecord{Name: "@", Value: "v=spf1", TTL: 300}, "TXT"},
		{"MX", &entities.MXRecord{Name: "mail", Value: "mx.", Priority: 5, TTL: 300}, "MX"},
		{"NS", &entities.NSRecord{Name: "@", Value: "ns1.", TTL: 300}, "NS"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := convertInterfaceToQUICRecord(tc.record)
			require.NotNil(t, r)
			assert.Equal(t, tc.typ, r.RecordType)
		})
	}
	t.Run("unsupported returns nil", func(t *testing.T) {
		assert.Nil(t, convertInterfaceToQUICRecord(&entities.SRVRecord{Name: "x"}))
	})
}

func TestCountZoneRecords(t *testing.T) {
	t.Run("nil zone", func(t *testing.T) {
		assert.Equal(t, 0, countZoneRecords(nil))
	})
	t.Run("counts across record sets", func(t *testing.T) {
		zone := &entities.Zone{
			RecordSet: entities.RecordSet{
				ARecords:    []*entities.ARecord{{Name: "a"}, {Name: "b"}},
				AAAARecords: []*entities.AAAARecord{{Name: "c"}},
				MXRecords:   []*entities.MXRecord{{Name: "mail"}},
			},
		}
		assert.Equal(t, 4, countZoneRecords(zone))
	})
	t.Run("counts SOA when present", func(t *testing.T) {
		zone := &entities.Zone{
			RecordSet: entities.RecordSet{
				SOARecord: entities.SOARecord{Name: "@"},
			},
		}
		assert.Equal(t, 1, countZoneRecords(zone))
	})
}

// =============================================================================
// Wire struct + error behaviors
// =============================================================================

func TestDNSRecord_Fields(t *testing.T) {
	record := &DNSRecord{Name: "mail", RecordType: "MX", Value: "mx.", TTL: 3600, Priority: 10}
	assert.Equal(t, "mail", record.Name)
	assert.Equal(t, "MX", record.RecordType)
	assert.Equal(t, uint32(3600), record.TTL)
	assert.Equal(t, uint16(10), record.Priority)
}

func TestDNSErrors(t *testing.T) {
	assert.Equal(t, "DNS service not available", ErrDNSServiceNotAvailable{}.Error())
	assert.Equal(t, "DNS configuration updates are not supported at runtime", ErrDNSConfigUpdateNotSupported{}.Error())
	assert.Equal(t, "DNS cache flushing is not supported", ErrDNSCacheFlushNotSupported{}.Error())
	assert.Equal(t, "DNS zone not found: example.com", ErrDNSZoneNotFound{Zone: "example.com"}.Error())
	assert.Equal(t, "DNS record not found: www.example.com A", ErrDNSRecordNotFound{Name: "www.example.com", RecordType: "A"}.Error())

	cause := assert.AnError
	opErr := ErrDNSOperationFailed{Operation: "AddRecord", Cause: cause}
	assert.Contains(t, opErr.Error(), "DNS operation AddRecord failed")
	assert.Equal(t, cause, opErr.Unwrap())
}

// =============================================================================
// Setters
// =============================================================================

func TestQUICServiceHandler_SetDNSService(t *testing.T) {
	handler := NewQUICServiceHandler(logging.DefaultLogger())
	assert.Nil(t, handler.dnsService)

	handler.SetDNSService(nil)
	assert.Nil(t, handler.dnsService)

	mock := NewMockDNSService()
	handler.SetDNSService(mock)
	assert.NotNil(t, handler.dnsService)
}

func TestWithQUICDNSService(t *testing.T) {
	t.Run("nil service", func(t *testing.T) {
		handler := NewQUICServiceHandler(logging.DefaultLogger(), WithQUICDNSService(nil))
		assert.Nil(t, handler.dnsService)
	})
	t.Run("real service", func(t *testing.T) {
		mock := NewMockDNSService()
		handler := NewQUICServiceHandler(logging.DefaultLogger(), WithQUICDNSService(mock))
		assert.NotNil(t, handler.dnsService)
	})
}

// =============================================================================
// Daemon-native handlers (flat wire, no SDK QUIC client)
// =============================================================================

func TestDNSUpdateRecord_DaemonNative(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		mock := NewMockDNSService()
		handler := createDNSUnitTestHandler(mock)
		req := createDNSUnitTestRequest(t, quic.OpDNSUpdateRecord, &DNSUpdateRecordRequest{
			Zone: "example.com.", Name: "www", RecordType: "A", Value: "1.2.3.4", TTL: 300,
		})
		resp := handler.HandleRequest(ctx, req)
		require.Equal(t, quic.StatusOK, resp.Status, string(resp.Payload))

		var result DNSUpdateRecordResponse
		require.NoError(t, quic.DecodePayload(resp.Payload, &result))
		assert.True(t, result.Success)
		assert.Equal(t, 1, mock.CallCount("AddRecord"))
	})

	t.Run("missing zone", func(t *testing.T) {
		handler := createDNSUnitTestHandler(NewMockDNSService())
		req := createDNSUnitTestRequest(t, quic.OpDNSUpdateRecord, &DNSUpdateRecordRequest{Name: "www", RecordType: "A", Value: "1.2.3.4"})
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
	})
}

func TestDNSGetRecord_DaemonNative(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		handler := createDNSUnitTestHandler(NewMockDNSService())
		req := createDNSUnitTestRequest(t, quic.OpDNSGetRecord, &DNSGetRecordRequest{Zone: "example.com.", Name: "www", RecordType: "A"})
		resp := handler.HandleRequest(ctx, req)
		require.Equal(t, quic.StatusOK, resp.Status, string(resp.Payload))

		var result DNSGetRecordResponse
		require.NoError(t, quic.DecodePayload(resp.Payload, &result))
		require.NotNil(t, result.Record)
		assert.Equal(t, "A", result.Record.RecordType)
	})

	t.Run("missing name", func(t *testing.T) {
		handler := createDNSUnitTestHandler(NewMockDNSService())
		req := createDNSUnitTestRequest(t, quic.OpDNSGetRecord, &DNSGetRecordRequest{Zone: "example.com.", RecordType: "A"})
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
	})

	t.Run("not found", func(t *testing.T) {
		mock := NewMockDNSService()
		mock.GetRecordFunc = func(ctx context.Context, name, recordType string) (interface{}, error) {
			return nil, ErrDNSRecordNotFound{Name: name, RecordType: recordType}
		}
		handler := createDNSUnitTestHandler(mock)
		req := createDNSUnitTestRequest(t, quic.OpDNSGetRecord, &DNSGetRecordRequest{Zone: "example.com.", Name: "missing", RecordType: "A"})
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quic.StatusNotFound, resp.Status)
	})
}

func TestDNSGetZone_DaemonNative(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		handler := createDNSUnitTestHandler(NewMockDNSService())
		req := createDNSUnitTestRequest(t, quic.OpDNSGetZone, &DNSGetZoneRequest{Zone: "example.com."})
		resp := handler.HandleRequest(ctx, req)
		require.Equal(t, quic.StatusOK, resp.Status, string(resp.Payload))

		var result DNSGetZoneResponse
		require.NoError(t, quic.DecodePayload(resp.Payload, &result))
		require.NotNil(t, result.Zone)
		assert.Equal(t, "example.com.", result.Zone.Name)
	})

	t.Run("missing zone", func(t *testing.T) {
		handler := createDNSUnitTestHandler(NewMockDNSService())
		req := createDNSUnitTestRequest(t, quic.OpDNSGetZone, &DNSGetZoneRequest{})
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
	})

	t.Run("not found", func(t *testing.T) {
		mock := NewMockDNSService()
		mock.ZoneFunc = func(ctx context.Context, zoneName string) (*entities.Zone, error) {
			return nil, ErrDNSZoneNotFound{Zone: zoneName}
		}
		handler := createDNSUnitTestHandler(mock)
		req := createDNSUnitTestRequest(t, quic.OpDNSGetZone, &DNSGetZoneRequest{Zone: "missing."})
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quic.StatusNotFound, resp.Status)
	})
}

func TestDNSGetConfig_DaemonNative(t *testing.T) {
	handler := createDNSUnitTestHandler(NewMockDNSService())
	req := createDNSUnitTestRequest(t, quic.OpDNSGetConfig, &DNSGetConfigRequest{})
	resp := handler.HandleRequest(context.Background(), req)
	require.Equal(t, quic.StatusOK, resp.Status, string(resp.Payload))

	var result DNSGetConfigResponse
	require.NoError(t, quic.DecodePayload(resp.Payload, &result))
	require.NotNil(t, result.Config)
	assert.Equal(t, "internal.example.com.", result.Config.InternalDomain)
	assert.Equal(t, "example.com.", result.Config.PublicDomain)
}

func TestDNSGetMetrics_DaemonNative(t *testing.T) {
	handler := createDNSUnitTestHandler(NewMockDNSService())
	req := createDNSUnitTestRequest(t, quic.OpDNSGetMetrics, &DNSGetMetricsRequest{})
	resp := handler.HandleRequest(context.Background(), req)
	require.Equal(t, quic.StatusOK, resp.Status, string(resp.Payload))

	var result DNSGetMetricsResponse
	require.NoError(t, quic.DecodePayload(resp.Payload, &result))
	require.NotNil(t, result.Metrics)
	assert.Equal(t, 2, result.Metrics.ZoneCount)
}

func TestDNSUpdateConfig_DaemonNativeNotImplemented(t *testing.T) {
	handler := createDNSUnitTestHandler(NewMockDNSService())
	req := createDNSUnitTestRequest(t, quic.OpDNSUpdateConfig, &DNSUpdateConfigRequest{})
	resp := handler.HandleRequest(context.Background(), req)
	assert.Equal(t, quic.StatusNotImplemented, resp.Status)
}

func TestDNSFlushCache_DaemonNativeNotImplemented(t *testing.T) {
	handler := createDNSUnitTestHandler(NewMockDNSService())
	req := createDNSUnitTestRequest(t, quic.OpDNSFlushCache, &DNSFlushCacheRequest{Zone: "example.com."})
	resp := handler.HandleRequest(context.Background(), req)
	assert.Equal(t, quic.StatusNotImplemented, resp.Status)
}
