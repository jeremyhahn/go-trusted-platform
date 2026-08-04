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
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// The SDK-mapped DNS QUIC handlers decode the SAME platform.v1 message the SDK
// sends (or a field-name-identical mirror) and delegate to the shared
// *DNSServiceServer. These tests encode the raw pb request exactly as the SDK
// adapter does and assert the delegated behavior.

// partialDNSService implements only the narrow local DNSService interface (not
// the full dns.DNSService). SetDNSService therefore cannot build the gRPC
// delegate, and the SDK-mapped handlers must report the service as
// unavailable rather than panic.
type partialDNSService struct{}

func (partialDNSService) Zone(context.Context, string) (*entities.Zone, error) {
	return &entities.Zone{}, nil
}
func (partialDNSService) CreateZone(context.Context, string) error            { return nil }
func (partialDNSService) DeleteZone(context.Context, string) error            { return nil }
func (partialDNSService) ListZones(context.Context) ([]*entities.Zone, error) { return nil, nil }
func (partialDNSService) AddRecord(context.Context, string, string, string, int) error {
	return nil
}
func (partialDNSService) DeleteRecord(context.Context, string, string) error { return nil }
func (partialDNSService) GetRecord(context.Context, string, string) (interface{}, error) {
	return nil, nil
}
func (partialDNSService) ListRecords(context.Context, string) ([]interface{}, error) {
	return nil, nil
}
func (partialDNSService) Resolve(context.Context, string, string) ([]string, error) {
	return nil, nil
}
func (partialDNSService) InternalDomain() string { return "internal." }
func (partialDNSService) PublicDomain() string   { return "public." }
func (partialDNSService) IsDNSSECEnabled() bool  { return false }

var _ DNSService = partialDNSService{}

// pbAddARecord builds a pb AddRecordRequest carrying an A record, exactly as
// the SDK adapter would put it on the wire.
func pbAddARecord(zone, name, value string) *platformv1.AddRecordRequest {
	return &platformv1.AddRecordRequest{
		ZoneName: zone,
		Record: &platformv1.Record{
			Type:   platformv1.RecordType_RECORD_TYPE_A,
			Record: &platformv1.Record_A{A: &platformv1.ARecord{Name: name, Value: value, Ttl: 3600}},
		},
	}
}

// =============================================================================
// AddRecord (0x20) — mirror-decoded request, pb response
// =============================================================================

func TestDNSAddRecord_Delegated(t *testing.T) {
	ctx := context.Background()

	t.Run("success adds record and saves zone", func(t *testing.T) {
		mock := NewMockDNSService()
		handler := createDNSUnitTestHandler(mock)
		req := createDNSUnitTestRequest(t, quic.OpDNSAddRecord, pbAddARecord("example.com.", "www", "1.2.3.4"))
		resp := handler.HandleRequest(ctx, req)
		require.Equal(t, quic.StatusOK, resp.Status, string(resp.Payload))

		require.NotNil(t, mock.SavedZone, "delegated AddRecord must Save the mutated zone")
		// Mock Zone() seeds one A record ("test"); the delegate adds "www".
		assert.Len(t, mock.SavedZone.RecordSet.ARecords, 2)
	})

	t.Run("missing zone name", func(t *testing.T) {
		handler := createDNSUnitTestHandler(NewMockDNSService())
		req := createDNSUnitTestRequest(t, quic.OpDNSAddRecord, &platformv1.AddRecordRequest{
			Record: &platformv1.Record{Type: platformv1.RecordType_RECORD_TYPE_A, Record: &platformv1.Record_A{A: &platformv1.ARecord{Name: "www"}}},
		})
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
	})

	t.Run("missing record", func(t *testing.T) {
		handler := createDNSUnitTestHandler(NewMockDNSService())
		req := createDNSUnitTestRequest(t, quic.OpDNSAddRecord, &platformv1.AddRecordRequest{ZoneName: "example.com."})
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
	})

	t.Run("service unavailable when delegate missing", func(t *testing.T) {
		handler := createDNSUnitTestHandler(partialDNSService{})
		req := createDNSUnitTestRequest(t, quic.OpDNSAddRecord, pbAddARecord("example.com.", "www", "1.2.3.4"))
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quic.StatusUnavailable, resp.Status)
	})
}

// =============================================================================
// DeleteRecord (0x21) — pb request/response (codec safe)
// =============================================================================

func TestDNSDeleteRecord_Delegated(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		mock := NewMockDNSService()
		handler := createDNSUnitTestHandler(mock)
		req := createDNSUnitTestRequest(t, quic.OpDNSDeleteRecord, &platformv1.DeleteRecordRequest{
			ZoneName: "example.com.", Type: platformv1.RecordType_RECORD_TYPE_A, Name: "www",
		})
		resp := handler.HandleRequest(ctx, req)
		require.Equal(t, quic.StatusOK, resp.Status, string(resp.Payload))
		assert.GreaterOrEqual(t, mock.CallCount("Save"), 1)
	})

	t.Run("missing zone name", func(t *testing.T) {
		handler := createDNSUnitTestHandler(NewMockDNSService())
		req := createDNSUnitTestRequest(t, quic.OpDNSDeleteRecord, &platformv1.DeleteRecordRequest{Name: "www"})
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
	})

	t.Run("missing name", func(t *testing.T) {
		handler := createDNSUnitTestHandler(NewMockDNSService())
		req := createDNSUnitTestRequest(t, quic.OpDNSDeleteRecord, &platformv1.DeleteRecordRequest{ZoneName: "example.com."})
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
	})
}

// =============================================================================
// ListRecords (0x24) — pb request, mirror response (oneof)
// =============================================================================

func TestDNSListRecords_Delegated(t *testing.T) {
	ctx := context.Background()

	t.Run("success returns oneof-safe records", func(t *testing.T) {
		handler := createDNSUnitTestHandler(NewMockDNSService())
		req := createDNSUnitTestRequest(t, quic.OpDNSListRecords, &platformv1.ListRecordsRequest{ZoneName: "example.com."})
		resp := handler.HandleRequest(ctx, req)
		require.Equal(t, quic.StatusOK, resp.Status, string(resp.Payload))

		var result dnsListRecordsResponseWire
		require.NoError(t, quic.DecodePayload(resp.Payload, &result))
		// Mock Zone() seeds a single A record.
		require.Len(t, result.Records, 1)
		rec := result.Records[0].toProto()
		assert.Equal(t, platformv1.RecordType_RECORD_TYPE_A, rec.GetType())
		assert.Equal(t, "test", rec.GetA().GetName())
	})

	t.Run("missing zone name", func(t *testing.T) {
		handler := createDNSUnitTestHandler(NewMockDNSService())
		req := createDNSUnitTestRequest(t, quic.OpDNSListRecords, &platformv1.ListRecordsRequest{})
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
	})
}

// =============================================================================
// CreateZone / AddZone (0x25) — pb request/response
// =============================================================================

func TestDNSAddZone_Delegated(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		mock := NewMockDNSService()
		handler := createDNSUnitTestHandler(mock)
		req := createDNSUnitTestRequest(t, quic.OpDNSAddZone, &platformv1.CreateZoneRequest{Name: "example.com.", Ttl: 3600})
		resp := handler.HandleRequest(ctx, req)
		require.Equal(t, quic.StatusOK, resp.Status, string(resp.Payload))
		assert.GreaterOrEqual(t, mock.CallCount("Save"), 1)
	})

	t.Run("missing name", func(t *testing.T) {
		handler := createDNSUnitTestHandler(NewMockDNSService())
		req := createDNSUnitTestRequest(t, quic.OpDNSAddZone, &platformv1.CreateZoneRequest{Ttl: 3600})
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
	})
}

// =============================================================================
// DeleteZone (0x26) — pb request/response
// =============================================================================

func TestDNSDeleteZone_Delegated(t *testing.T) {
	ctx := context.Background()

	t.Run("success", func(t *testing.T) {
		mock := NewMockDNSService()
		handler := createDNSUnitTestHandler(mock)
		req := createDNSUnitTestRequest(t, quic.OpDNSDeleteZone, &platformv1.DeleteZoneRequest{Name: "example.com."})
		resp := handler.HandleRequest(ctx, req)
		require.Equal(t, quic.StatusOK, resp.Status, string(resp.Payload))
		assert.GreaterOrEqual(t, mock.CallCount("Delete"), 1)
	})

	t.Run("missing name", func(t *testing.T) {
		handler := createDNSUnitTestHandler(NewMockDNSService())
		req := createDNSUnitTestRequest(t, quic.OpDNSDeleteZone, &platformv1.DeleteZoneRequest{})
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
	})
}

// =============================================================================
// ListZones (0x28) — pb request/response
// =============================================================================

func TestDNSListZones_Delegated(t *testing.T) {
	ctx := context.Background()

	t.Run("success returns all zones", func(t *testing.T) {
		handler := createDNSUnitTestHandler(NewMockDNSService())
		req := createDNSUnitTestRequest(t, quic.OpDNSListZones, &platformv1.ListZonesRequest{})
		resp := handler.HandleRequest(ctx, req)
		require.Equal(t, quic.StatusOK, resp.Status, string(resp.Payload))

		var result platformv1.ListZonesResponse
		require.NoError(t, quic.DecodePayload(resp.Payload, &result))
		assert.Len(t, result.GetZones(), 2)
	})

	t.Run("internal-only filter", func(t *testing.T) {
		handler := createDNSUnitTestHandler(NewMockDNSService())
		req := createDNSUnitTestRequest(t, quic.OpDNSListZones, &platformv1.ListZonesRequest{InternalOnly: true})
		resp := handler.HandleRequest(ctx, req)
		require.Equal(t, quic.StatusOK, resp.Status, string(resp.Payload))

		var result platformv1.ListZonesResponse
		require.NoError(t, quic.DecodePayload(resp.Payload, &result))
		assert.Len(t, result.GetZones(), 1)
	})
}

// =============================================================================
// Resolve (0x29) — pb request, mirror response (oneof)
// =============================================================================

func TestDNSResolve_Delegated(t *testing.T) {
	ctx := context.Background()

	t.Run("success returns authoritative records", func(t *testing.T) {
		handler := createDNSUnitTestHandler(NewMockDNSService())
		req := createDNSUnitTestRequest(t, quic.OpDNSResolve, &platformv1.ResolveRequest{Fqdn: "example.com.", Type: platformv1.RecordType_RECORD_TYPE_A})
		resp := handler.HandleRequest(ctx, req)
		require.Equal(t, quic.StatusOK, resp.Status, string(resp.Payload))

		var result dnsResolveResponseWire
		require.NoError(t, quic.DecodePayload(resp.Payload, &result))
		assert.True(t, result.Authoritative)
		require.Len(t, result.Records, 1)
		assert.Equal(t, platformv1.RecordType_RECORD_TYPE_A, result.Records[0].toProto().GetType())
	})

	t.Run("missing fqdn", func(t *testing.T) {
		handler := createDNSUnitTestHandler(NewMockDNSService())
		req := createDNSUnitTestRequest(t, quic.OpDNSResolve, &platformv1.ResolveRequest{})
		resp := handler.HandleRequest(ctx, req)
		assert.Equal(t, quic.StatusInvalidArgument, resp.Status)
	})
}
