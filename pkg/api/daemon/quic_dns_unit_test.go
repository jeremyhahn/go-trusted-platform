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
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns"
	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// skipIfNoCodec skips the test if the QUIC codec is not available.
// Codec requires building with -tags codec_msgpack.
func skipIfNoCodec(t *testing.T) {
	t.Helper()
	if _, err := quic.EncodePayload(struct{}{}); err != nil {
		t.Skip("Skipping test - no codec available (build with -tags codec_msgpack)")
	}
}

// createDNSUnitTestHandler creates a QUICServiceHandler with the given mock DNS service.
func createDNSUnitTestHandler(mockDNS DNSService) *QUICServiceHandler {
	logger := logging.DefaultLogger()
	handler := NewQUICServiceHandler(logger)
	handler.SetDNSService(mockDNS)
	return handler
}

// createDNSUnitTestRequest creates a QUIC request with the given opcode and payload.
// It will skip the test if no codec is available.
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
	return &quic.Request{
		Opcode:  opcode,
		Payload: data,
	}
}

// =============================================================================
// Test handleDNSAddRecord
// =============================================================================

func TestDNSAddRecord_Success(t *testing.T) {
	mock := NewMockDNSService()
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSAddRecord, &DNSAddRecordRequest{
		Zone:       "example.com.",
		Name:       "www",
		RecordType: "A",
		Value:      "192.168.1.100",
		TTL:        3600,
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusOK {
		t.Errorf("expected status OK, got %s: %s", quic.StatusToString(resp.Status), string(resp.Payload))
	}

	var result DNSAddRecordResponse
	if err := quic.DecodePayload(resp.Payload, &result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !result.Success {
		t.Error("expected success=true")
	}
	if result.Zone != "example.com." {
		t.Errorf("expected zone 'example.com.', got '%s'", result.Zone)
	}
	if result.Name != "www" {
		t.Errorf("expected name 'www', got '%s'", result.Name)
	}
	if mock.CallCount("AddRecord") != 1 {
		t.Errorf("expected AddRecord to be called once, got %d", mock.CallCount("AddRecord"))
	}
}

func TestDNSAddRecord_MissingZone(t *testing.T) {
	mock := NewMockDNSService()
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSAddRecord, &DNSAddRecordRequest{
		Name:       "www",
		RecordType: "A",
		Value:      "192.168.1.100",
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected StatusInvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestDNSAddRecord_MissingName(t *testing.T) {
	mock := NewMockDNSService()
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSAddRecord, &DNSAddRecordRequest{
		Zone:       "example.com.",
		RecordType: "A",
		Value:      "192.168.1.100",
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected StatusInvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestDNSAddRecord_MissingRecordType(t *testing.T) {
	mock := NewMockDNSService()
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSAddRecord, &DNSAddRecordRequest{
		Zone:  "example.com.",
		Name:  "www",
		Value: "192.168.1.100",
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected StatusInvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestDNSAddRecord_MissingValue(t *testing.T) {
	mock := NewMockDNSService()
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSAddRecord, &DNSAddRecordRequest{
		Zone:       "example.com.",
		Name:       "www",
		RecordType: "A",
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected StatusInvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestDNSAddRecord_ServiceError(t *testing.T) {
	mock := NewMockDNSService()
	mock.AddRecordFunc = func(ctx context.Context, name, recordType, value string, ttl int) error {
		return errors.New("database error")
	}
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSAddRecord, &DNSAddRecordRequest{
		Zone:       "example.com.",
		Name:       "www",
		RecordType: "A",
		Value:      "192.168.1.100",
		TTL:        3600,
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusInternalError {
		t.Errorf("expected StatusInternalError, got %s", quic.StatusToString(resp.Status))
	}
}

func TestDNSAddRecord_DefaultTTL(t *testing.T) {
	mock := NewMockDNSService()
	var capturedTTL int
	mock.AddRecordFunc = func(ctx context.Context, name, recordType, value string, ttl int) error {
		capturedTTL = ttl
		return nil
	}
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSAddRecord, &DNSAddRecordRequest{
		Zone:       "example.com.",
		Name:       "www",
		RecordType: "A",
		Value:      "192.168.1.100",
		TTL:        0, // Should default to 3600
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusOK {
		t.Errorf("expected status OK, got %s", quic.StatusToString(resp.Status))
	}
	if capturedTTL != 3600 {
		t.Errorf("expected default TTL 3600, got %d", capturedTTL)
	}
}

// =============================================================================
// Test handleDNSDeleteRecord
// =============================================================================

func TestDNSDeleteRecord_Success(t *testing.T) {
	mock := NewMockDNSService()
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSDeleteRecord, &DNSDeleteRecordRequest{
		Zone:       "example.com.",
		Name:       "www",
		RecordType: "A",
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusOK {
		t.Errorf("expected status OK, got %s: %s", quic.StatusToString(resp.Status), string(resp.Payload))
	}

	var result DNSDeleteRecordResponse
	if err := quic.DecodePayload(resp.Payload, &result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !result.Success {
		t.Error("expected success=true")
	}
	if mock.CallCount("DeleteRecord") != 1 {
		t.Errorf("expected DeleteRecord to be called once, got %d", mock.CallCount("DeleteRecord"))
	}
}

func TestDNSDeleteRecord_MissingZone(t *testing.T) {
	mock := NewMockDNSService()
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSDeleteRecord, &DNSDeleteRecordRequest{
		Name:       "www",
		RecordType: "A",
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected StatusInvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestDNSDeleteRecord_MissingName(t *testing.T) {
	mock := NewMockDNSService()
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSDeleteRecord, &DNSDeleteRecordRequest{
		Zone:       "example.com.",
		RecordType: "A",
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected StatusInvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestDNSDeleteRecord_MissingRecordType(t *testing.T) {
	mock := NewMockDNSService()
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSDeleteRecord, &DNSDeleteRecordRequest{
		Zone: "example.com.",
		Name: "www",
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected StatusInvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestDNSDeleteRecord_ServiceError(t *testing.T) {
	mock := NewMockDNSService()
	mock.DeleteRecordFunc = func(ctx context.Context, name, recordType string) error {
		return errors.New("record not found")
	}
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSDeleteRecord, &DNSDeleteRecordRequest{
		Zone:       "example.com.",
		Name:       "www",
		RecordType: "A",
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusInternalError {
		t.Errorf("expected StatusInternalError, got %s", quic.StatusToString(resp.Status))
	}
}

// =============================================================================
// Test handleDNSUpdateRecord
// =============================================================================

func TestDNSUpdateRecord_Success(t *testing.T) {
	mock := NewMockDNSService()
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSUpdateRecord, &DNSUpdateRecordRequest{
		Zone:       "example.com.",
		Name:       "www",
		RecordType: "A",
		Value:      "192.168.1.200",
		TTL:        7200,
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusOK {
		t.Errorf("expected status OK, got %s: %s", quic.StatusToString(resp.Status), string(resp.Payload))
	}

	var result DNSUpdateRecordResponse
	if err := quic.DecodePayload(resp.Payload, &result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !result.Success {
		t.Error("expected success=true")
	}
	// Update is delete + add
	if mock.CallCount("DeleteRecord") != 1 {
		t.Errorf("expected DeleteRecord to be called once, got %d", mock.CallCount("DeleteRecord"))
	}
	if mock.CallCount("AddRecord") != 1 {
		t.Errorf("expected AddRecord to be called once, got %d", mock.CallCount("AddRecord"))
	}
}

func TestDNSUpdateRecord_MissingZone(t *testing.T) {
	mock := NewMockDNSService()
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSUpdateRecord, &DNSUpdateRecordRequest{
		Name:       "www",
		RecordType: "A",
		Value:      "192.168.1.200",
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected StatusInvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestDNSUpdateRecord_MissingName(t *testing.T) {
	mock := NewMockDNSService()
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSUpdateRecord, &DNSUpdateRecordRequest{
		Zone:       "example.com.",
		RecordType: "A",
		Value:      "192.168.1.200",
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected StatusInvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestDNSUpdateRecord_MissingRecordType(t *testing.T) {
	mock := NewMockDNSService()
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSUpdateRecord, &DNSUpdateRecordRequest{
		Zone:  "example.com.",
		Name:  "www",
		Value: "192.168.1.200",
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected StatusInvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestDNSUpdateRecord_MissingValue(t *testing.T) {
	mock := NewMockDNSService()
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSUpdateRecord, &DNSUpdateRecordRequest{
		Zone:       "example.com.",
		Name:       "www",
		RecordType: "A",
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected StatusInvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestDNSUpdateRecord_AddError(t *testing.T) {
	mock := NewMockDNSService()
	mock.AddRecordFunc = func(ctx context.Context, name, recordType, value string, ttl int) error {
		return errors.New("add failed")
	}
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSUpdateRecord, &DNSUpdateRecordRequest{
		Zone:       "example.com.",
		Name:       "www",
		RecordType: "A",
		Value:      "192.168.1.200",
		TTL:        7200,
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusInternalError {
		t.Errorf("expected StatusInternalError, got %s", quic.StatusToString(resp.Status))
	}
}

// =============================================================================
// Test handleDNSGetRecord
// =============================================================================

func TestDNSGetRecord_Success(t *testing.T) {
	mock := NewMockDNSService()
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSGetRecord, &DNSGetRecordRequest{
		Zone:       "example.com.",
		Name:       "www",
		RecordType: "A",
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusOK {
		t.Errorf("expected status OK, got %s: %s", quic.StatusToString(resp.Status), string(resp.Payload))
	}

	var result DNSGetRecordResponse
	if err := quic.DecodePayload(resp.Payload, &result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result.Record == nil {
		t.Fatal("expected record to be non-nil")
	}
	if result.Record.RecordType != "A" {
		t.Errorf("expected record type 'A', got '%s'", result.Record.RecordType)
	}
	if mock.CallCount("GetRecord") != 1 {
		t.Errorf("expected GetRecord to be called once, got %d", mock.CallCount("GetRecord"))
	}
}

func TestDNSGetRecord_MissingZone(t *testing.T) {
	mock := NewMockDNSService()
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSGetRecord, &DNSGetRecordRequest{
		Name:       "www",
		RecordType: "A",
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected StatusInvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestDNSGetRecord_MissingName(t *testing.T) {
	mock := NewMockDNSService()
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSGetRecord, &DNSGetRecordRequest{
		Zone:       "example.com.",
		RecordType: "A",
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected StatusInvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestDNSGetRecord_MissingRecordType(t *testing.T) {
	mock := NewMockDNSService()
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSGetRecord, &DNSGetRecordRequest{
		Zone: "example.com.",
		Name: "www",
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected StatusInvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestDNSGetRecord_NotFound(t *testing.T) {
	mock := NewMockDNSService()
	mock.GetRecordFunc = func(ctx context.Context, name, recordType string) (interface{}, error) {
		return nil, errors.New("record not found")
	}
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSGetRecord, &DNSGetRecordRequest{
		Zone:       "example.com.",
		Name:       "nonexistent",
		RecordType: "A",
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusNotFound {
		t.Errorf("expected StatusNotFound, got %s", quic.StatusToString(resp.Status))
	}
}

func TestDNSGetRecord_AllRecordTypes(t *testing.T) {
	testCases := []struct {
		recordType string
	}{
		{"A"},
		{"AAAA"},
		{"CNAME"},
		{"TXT"},
		{"MX"},
		{"NS"},
	}

	for _, tc := range testCases {
		t.Run(tc.recordType, func(t *testing.T) {
			mock := NewMockDNSService()
			handler := createDNSUnitTestHandler(mock)
			ctx := context.Background()

			req := createDNSUnitTestRequest(t, quic.OpDNSGetRecord, &DNSGetRecordRequest{
				Zone:       "example.com.",
				Name:       "test",
				RecordType: tc.recordType,
			})

			resp := handler.HandleRequest(ctx, req)

			if resp.Status != quic.StatusOK {
				t.Errorf("expected status OK for %s, got %s", tc.recordType, quic.StatusToString(resp.Status))
			}
		})
	}
}

// =============================================================================
// Test handleDNSListRecords
// =============================================================================

func TestDNSListRecords_Success(t *testing.T) {
	mock := NewMockDNSService()
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSListRecords, &DNSListRecordsRequest{
		Zone: "example.com.",
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusOK {
		t.Errorf("expected status OK, got %s: %s", quic.StatusToString(resp.Status), string(resp.Payload))
	}

	var result DNSListRecordsResponse
	if err := quic.DecodePayload(resp.Payload, &result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result.Total == 0 {
		t.Error("expected non-zero total records")
	}
	if len(result.Records) == 0 {
		t.Error("expected non-empty records list")
	}
	if mock.CallCount("ListRecords") != 1 {
		t.Errorf("expected ListRecords to be called once, got %d", mock.CallCount("ListRecords"))
	}
}

func TestDNSListRecords_MissingZone(t *testing.T) {
	mock := NewMockDNSService()
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSListRecords, &DNSListRecordsRequest{})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected StatusInvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestDNSListRecords_WithTypeFilter(t *testing.T) {
	mock := NewMockDNSService()
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSListRecords, &DNSListRecordsRequest{
		Zone:       "example.com.",
		RecordType: "A",
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusOK {
		t.Errorf("expected status OK, got %s", quic.StatusToString(resp.Status))
	}

	var result DNSListRecordsResponse
	if err := quic.DecodePayload(resp.Payload, &result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// All returned records should be type A
	for _, rec := range result.Records {
		if rec.RecordType != "A" {
			t.Errorf("expected all records to be type A, got %s", rec.RecordType)
		}
	}
}

func TestDNSListRecords_ServiceError(t *testing.T) {
	mock := NewMockDNSService()
	mock.ListRecordsFunc = func(ctx context.Context, zoneName string) ([]interface{}, error) {
		return nil, errors.New("database error")
	}
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSListRecords, &DNSListRecordsRequest{
		Zone: "example.com.",
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusInternalError {
		t.Errorf("expected StatusInternalError, got %s", quic.StatusToString(resp.Status))
	}
}

// =============================================================================
// Test handleDNSAddZone
// =============================================================================

func TestDNSAddZone_Success(t *testing.T) {
	mock := NewMockDNSService()
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSAddZone, &DNSAddZoneRequest{
		Name:        "newzone.example.com.",
		Description: "Test zone",
		TTL:         3600,
		Internal:    true,
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusOK {
		t.Errorf("expected status OK, got %s: %s", quic.StatusToString(resp.Status), string(resp.Payload))
	}

	var result DNSAddZoneResponse
	if err := quic.DecodePayload(resp.Payload, &result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !result.Success {
		t.Error("expected success=true")
	}
	if result.Zone != "newzone.example.com." {
		t.Errorf("expected zone 'newzone.example.com.', got '%s'", result.Zone)
	}
	if mock.CallCount("CreateZone") != 1 {
		t.Errorf("expected CreateZone to be called once, got %d", mock.CallCount("CreateZone"))
	}
}

func TestDNSAddZone_MissingName(t *testing.T) {
	mock := NewMockDNSService()
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSAddZone, &DNSAddZoneRequest{
		Description: "Test zone",
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected StatusInvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestDNSAddZone_AlreadyExists(t *testing.T) {
	mock := NewMockDNSService()
	mock.CreateZoneFunc = func(ctx context.Context, zoneName string) error {
		return dns.ErrZoneAlreadyExists
	}
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSAddZone, &DNSAddZoneRequest{
		Name: "existing.example.com.",
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusAlreadyExists {
		t.Errorf("expected StatusAlreadyExists, got %s", quic.StatusToString(resp.Status))
	}
}

func TestDNSAddZone_ServiceError(t *testing.T) {
	mock := NewMockDNSService()
	mock.CreateZoneFunc = func(ctx context.Context, zoneName string) error {
		return errors.New("database error")
	}
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSAddZone, &DNSAddZoneRequest{
		Name: "newzone.example.com.",
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusInternalError {
		t.Errorf("expected StatusInternalError, got %s", quic.StatusToString(resp.Status))
	}
}

// =============================================================================
// Test handleDNSDeleteZone
// =============================================================================

func TestDNSDeleteZone_Success(t *testing.T) {
	mock := NewMockDNSService()
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSDeleteZone, &DNSDeleteZoneRequest{
		Zone: "delete.example.com.",
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusOK {
		t.Errorf("expected status OK, got %s: %s", quic.StatusToString(resp.Status), string(resp.Payload))
	}

	var result DNSDeleteZoneResponse
	if err := quic.DecodePayload(resp.Payload, &result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if !result.Success {
		t.Error("expected success=true")
	}
	if mock.CallCount("DeleteZone") != 1 {
		t.Errorf("expected DeleteZone to be called once, got %d", mock.CallCount("DeleteZone"))
	}
}

func TestDNSDeleteZone_MissingZone(t *testing.T) {
	mock := NewMockDNSService()
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSDeleteZone, &DNSDeleteZoneRequest{})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected StatusInvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestDNSDeleteZone_NotFound(t *testing.T) {
	mock := NewMockDNSService()
	mock.DeleteZoneFunc = func(ctx context.Context, zoneName string) error {
		return dns.ErrZoneNotFound
	}
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSDeleteZone, &DNSDeleteZoneRequest{
		Zone: "nonexistent.example.com.",
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusNotFound {
		t.Errorf("expected StatusNotFound, got %s", quic.StatusToString(resp.Status))
	}
}

func TestDNSDeleteZone_ServiceError(t *testing.T) {
	mock := NewMockDNSService()
	mock.DeleteZoneFunc = func(ctx context.Context, zoneName string) error {
		return errors.New("database error")
	}
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSDeleteZone, &DNSDeleteZoneRequest{
		Zone: "delete.example.com.",
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusInternalError {
		t.Errorf("expected StatusInternalError, got %s", quic.StatusToString(resp.Status))
	}
}

// =============================================================================
// Test handleDNSGetZone
// =============================================================================

func TestDNSGetZone_Success(t *testing.T) {
	mock := NewMockDNSService()
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSGetZone, &DNSGetZoneRequest{
		Zone: "example.com.",
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusOK {
		t.Errorf("expected status OK, got %s: %s", quic.StatusToString(resp.Status), string(resp.Payload))
	}

	var result DNSGetZoneResponse
	if err := quic.DecodePayload(resp.Payload, &result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result.Zone == nil {
		t.Fatal("expected zone to be non-nil")
	}
	if result.Zone.Name != "example.com." {
		t.Errorf("expected zone name 'example.com.', got '%s'", result.Zone.Name)
	}
	if mock.CallCount("Zone") != 1 {
		t.Errorf("expected Zone to be called once, got %d", mock.CallCount("Zone"))
	}
}

func TestDNSGetZone_MissingZone(t *testing.T) {
	mock := NewMockDNSService()
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSGetZone, &DNSGetZoneRequest{})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected StatusInvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestDNSGetZone_NotFound(t *testing.T) {
	mock := NewMockDNSService()
	mock.ZoneFunc = func(ctx context.Context, zoneName string) (*entities.Zone, error) {
		return nil, errors.New("zone not found")
	}
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSGetZone, &DNSGetZoneRequest{
		Zone: "nonexistent.example.com.",
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusNotFound {
		t.Errorf("expected StatusNotFound, got %s", quic.StatusToString(resp.Status))
	}
}

// =============================================================================
// Test handleDNSListZones
// =============================================================================

func TestDNSListZones_Success(t *testing.T) {
	mock := NewMockDNSService()
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSListZones, &DNSListZonesRequest{})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusOK {
		t.Errorf("expected status OK, got %s: %s", quic.StatusToString(resp.Status), string(resp.Payload))
	}

	var result DNSListZonesResponse
	if err := quic.DecodePayload(resp.Payload, &result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result.Total == 0 {
		t.Error("expected non-zero total zones")
	}
	if len(result.Zones) == 0 {
		t.Error("expected non-empty zones list")
	}
	if mock.CallCount("ListZones") != 1 {
		t.Errorf("expected ListZones to be called once, got %d", mock.CallCount("ListZones"))
	}
}

func TestDNSListZones_WithInternalFilter(t *testing.T) {
	mock := NewMockDNSService()
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	internal := true
	req := createDNSUnitTestRequest(t, quic.OpDNSListZones, &DNSListZonesRequest{
		Internal: &internal,
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusOK {
		t.Errorf("expected status OK, got %s", quic.StatusToString(resp.Status))
	}

	var result DNSListZonesResponse
	if err := quic.DecodePayload(resp.Payload, &result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// All returned zones should be internal
	for _, zone := range result.Zones {
		if !zone.Internal {
			t.Error("expected all zones to be internal")
		}
	}
}

func TestDNSListZones_ServiceError(t *testing.T) {
	mock := NewMockDNSService()
	mock.ListZonesFunc = func(ctx context.Context) ([]*entities.Zone, error) {
		return nil, errors.New("database error")
	}
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSListZones, &DNSListZonesRequest{})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusInternalError {
		t.Errorf("expected StatusInternalError, got %s", quic.StatusToString(resp.Status))
	}
}

func TestDNSListZones_EmptyPayload(t *testing.T) {
	mock := NewMockDNSService()
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	// Test with empty/nil payload
	req := &quic.Request{
		Opcode:  quic.OpDNSListZones,
		Payload: nil,
	}

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusOK {
		t.Errorf("expected status OK, got %s", quic.StatusToString(resp.Status))
	}
}

// =============================================================================
// Test handleDNSResolve
// =============================================================================

func TestDNSResolve_Success(t *testing.T) {
	mock := NewMockDNSService()
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSResolve, &DNSResolveRequest{
		Name:       "www.example.com",
		RecordType: "A",
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusOK {
		t.Errorf("expected status OK, got %s: %s", quic.StatusToString(resp.Status), string(resp.Payload))
	}

	var result DNSResolveResponse
	if err := quic.DecodePayload(resp.Payload, &result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if len(result.Values) == 0 {
		t.Error("expected non-empty values")
	}
	if result.Name != "www.example.com" {
		t.Errorf("expected name 'www.example.com', got '%s'", result.Name)
	}
	if result.Type != "A" {
		t.Errorf("expected type 'A', got '%s'", result.Type)
	}
	if mock.CallCount("Resolve") != 1 {
		t.Errorf("expected Resolve to be called once, got %d", mock.CallCount("Resolve"))
	}
}

func TestDNSResolve_MissingName(t *testing.T) {
	mock := NewMockDNSService()
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSResolve, &DNSResolveRequest{
		RecordType: "A",
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusInvalidArgument {
		t.Errorf("expected StatusInvalidArgument, got %s", quic.StatusToString(resp.Status))
	}
}

func TestDNSResolve_DefaultRecordType(t *testing.T) {
	mock := NewMockDNSService()
	var capturedType string
	mock.ResolveFunc = func(ctx context.Context, name, recordType string) ([]string, error) {
		capturedType = recordType
		return []string{"192.168.1.1"}, nil
	}
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSResolve, &DNSResolveRequest{
		Name: "www.example.com",
		// RecordType not set, should default to "A"
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusOK {
		t.Errorf("expected status OK, got %s", quic.StatusToString(resp.Status))
	}
	if capturedType != "A" {
		t.Errorf("expected default record type 'A', got '%s'", capturedType)
	}
}

func TestDNSResolve_NotFound(t *testing.T) {
	mock := NewMockDNSService()
	mock.ResolveFunc = func(ctx context.Context, name, recordType string) ([]string, error) {
		return nil, errors.New("no records found")
	}
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSResolve, &DNSResolveRequest{
		Name:       "nonexistent.example.com",
		RecordType: "A",
	})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusNotFound {
		t.Errorf("expected StatusNotFound, got %s", quic.StatusToString(resp.Status))
	}
}

// =============================================================================
// Test handleDNSGetConfig
// =============================================================================

func TestDNSGetConfig_Success(t *testing.T) {
	mock := NewMockDNSService()
	mock.InternalDomainValue = "internal.example.com."
	mock.PublicDomainValue = "example.com."
	mock.DNSSECEnabledValue = true
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSGetConfig, &DNSGetConfigRequest{})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusOK {
		t.Errorf("expected status OK, got %s: %s", quic.StatusToString(resp.Status), string(resp.Payload))
	}

	var result DNSGetConfigResponse
	if err := quic.DecodePayload(resp.Payload, &result); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if result.Config == nil {
		t.Fatal("expected config to be non-nil")
	}
	if result.Config.InternalDomain != "internal.example.com." {
		t.Errorf("expected internal domain 'internal.example.com.', got '%s'", result.Config.InternalDomain)
	}
	if result.Config.PublicDomain != "example.com." {
		t.Errorf("expected public domain 'example.com.', got '%s'", result.Config.PublicDomain)
	}
	if !result.Config.DNSSECEnabled {
		t.Error("expected DNSSEC to be enabled")
	}
}

func TestDNSGetConfig_EmptyPayload(t *testing.T) {
	mock := NewMockDNSService()
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := &quic.Request{
		Opcode:  quic.OpDNSGetConfig,
		Payload: nil,
	}

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusOK {
		t.Errorf("expected status OK, got %s", quic.StatusToString(resp.Status))
	}
}

// =============================================================================
// Test handleDNSUpdateConfig
// =============================================================================

func TestDNSUpdateConfig_NotImplemented(t *testing.T) {
	mock := NewMockDNSService()
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSUpdateConfig, &DNSUpdateConfigRequest{})

	resp := handler.HandleRequest(ctx, req)

	// UpdateConfig is not implemented and should return NotImplemented
	if resp.Status != quic.StatusNotImplemented {
		t.Errorf("expected StatusNotImplemented, got %s", quic.StatusToString(resp.Status))
	}
}

// =============================================================================
// Test handleDNSGetMetrics
// =============================================================================

func TestDNSGetMetrics_Success(t *testing.T) {
	mock := NewMockDNSService()
	mock.ListZonesFunc = func(ctx context.Context) ([]*entities.Zone, error) {
		return []*entities.Zone{
			{
				ID:   1,
				Name: "example.com.",
				RecordSet: entities.RecordSet{
					ARecords: []*entities.ARecord{
						{Name: "www", Value: "1.2.3.4", TTL: 3600},
						{Name: "api", Value: "1.2.3.5", TTL: 3600},
					},
					TXTRecords: []*entities.TXTRecord{
						{Name: "_dmarc", Value: "v=DMARC1", TTL: 3600},
					},
				},
			},
			{
				ID:   2,
				Name: "internal.example.com.",
				RecordSet: entities.RecordSet{
					ARecords: []*entities.ARecord{
						{Name: "server1", Value: "192.168.1.1", TTL: 3600},
					},
				},
			},
		}, nil
	}
	handler := createDNSUnitTestHandler(mock)
	ctx := context.Background()

	req := createDNSUnitTestRequest(t, quic.OpDNSGetMetrics, &DNSGetMetricsRequest{})

	resp := handler.HandleRequest(ctx, req)

	if resp.Status != quic.StatusOK {
		t.Errorf("expected status OK, got %s", quic.StatusToString(resp.Status))
	}

	var metricsResp DNSGetMetricsResponse
	if err := quic.DecodePayload(resp.Payload, &metricsResp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	// Verify metrics: 2 zones, 4 records total (3 A + 1 TXT)
	if metricsResp.Metrics.ZoneCount != 2 {
		t.Errorf("expected 2 zones, got %d", metricsResp.Metrics.ZoneCount)
	}
	if metricsResp.Metrics.TotalRecords != 4 {
		t.Errorf("expected 4 records, got %d", metricsResp.Metrics.TotalRecords)
	}
}
