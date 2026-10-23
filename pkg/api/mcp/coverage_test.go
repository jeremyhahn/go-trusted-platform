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

package mcp

import (
	"context"
	"encoding/json"
	"math"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// =============================================================================
// Client Coverage Tests
// =============================================================================

func TestMarshalResultSlice(t *testing.T) {
	input := []string{"a", "b", "c"}

	result, err := marshalResult(input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	arr, ok := result.([]interface{})
	if !ok {
		t.Fatalf("expected []interface{}, got %T", result)
	}
	if len(arr) != 3 {
		t.Errorf("expected 3 items, got %d", len(arr))
	}
}

func TestGetStringMapCoverage(t *testing.T) {
	tests := []struct {
		name     string
		args     map[string]interface{}
		key      string
		expected map[string]string
	}{
		{
			name: "valid string map",
			args: map[string]interface{}{
				"labels": map[string]interface{}{
					"env":  "prod",
					"team": "platform",
				},
			},
			key:      "labels",
			expected: map[string]string{"env": "prod", "team": "platform"},
		},
		{
			name: "missing key",
			args: map[string]interface{}{
				"other": "value",
			},
			key:      "labels",
			expected: nil,
		},
		{
			name: "wrong type",
			args: map[string]interface{}{
				"labels": "not a map",
			},
			key:      "labels",
			expected: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := getStringMap(tt.args, tt.key)
			if tt.expected == nil && result != nil {
				t.Errorf("expected nil, got %v", result)
			} else if tt.expected != nil {
				for k, v := range tt.expected {
					if result[k] != v {
						t.Errorf("expected %s=%s, got %s=%s", k, v, k, result[k])
					}
				}
			}
		})
	}
}

// =============================================================================
// Additional Server Coverage Tests
// =============================================================================

func TestServer_SetOAuthMetadataCoverage(t *testing.T) {
	mockSvc := newMockServiceProvider()
	config := DefaultConfig()
	server := NewServer(mockSvc, config, newTestLogger())

	server.SetOAuthMetadata("https://example.com/api", []string{"https://auth.example.com"})

	handler := server.GetOAuthMetadataHandler()
	if handler == nil {
		t.Fatal("expected non-nil OAuth metadata handler")
	}
}

func TestServer_StartAlreadyRunning(t *testing.T) {
	mockSvc := newMockServiceProvider()
	config := &Config{
		ServerName:    "Test Server",
		ServerVersion: "1.0.0",
		Transport:     "http",
		HTTPAddr:      "127.0.0.1:0",
		TLSConfig:     newTestTLSConfig(t),
	}
	server := NewServer(mockSvc, config, newTestLogger())

	err := server.Start()
	if err != nil {
		t.Fatalf("failed to start server: %v", err)
	}
	defer server.Stop()

	err = server.Start()
	if err == nil {
		t.Error("expected error when starting already running server")
	}
}

func TestServer_StopNotRunning(t *testing.T) {
	mockSvc := newMockServiceProvider()
	config := DefaultConfig()
	server := NewServer(mockSvc, config, newTestLogger())

	// Stop without starting should return error
	err := server.Stop()
	if err == nil {
		t.Error("expected error when stopping server that is not running")
	}
}

// =============================================================================
// CA Error Coverage Tests
// =============================================================================

func TestCAError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *CAError
		expected string
	}{
		{
			name:     "basic error",
			err:      &CAError{Code: "CA_TEST", Message: "test message"},
			expected: "CA_TEST: test message",
		},
		{
			name:     "ErrCAServiceUnavailable",
			err:      ErrCAServiceUnavailable,
			expected: "CA_SERVICE_UNAVAILABLE: certificate authority service is not available",
		},
		{
			name:     "ErrCANotInitialized",
			err:      ErrCANotInitialized,
			expected: "CA_NOT_INITIALIZED: certificate authority is not initialized",
		},
		{
			name:     "ErrCACommonNameRequired",
			err:      ErrCACommonNameRequired,
			expected: "CA_COMMON_NAME_REQUIRED: common name is required for certificate issuance",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.err.Error() != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, tt.err.Error())
			}
		})
	}
}

// =============================================================================
// MarshalResult Error Path Coverage
// =============================================================================

func TestMarshalResult_Error(t *testing.T) {
	// Test with a value that cannot be marshaled to JSON
	// math.Inf causes json.Marshal to fail
	_, err := marshalResult(math.Inf(1))
	if err == nil {
		t.Error("expected error when marshaling infinity")
	}

	// Test with complex number (also cannot be marshaled)
	type unmarshalable struct {
		Ch chan int
	}
	_, err = marshalResult(unmarshalable{Ch: make(chan int)})
	if err == nil {
		t.Error("expected error when marshaling channel")
	}
}

// =============================================================================
// vTPM Service Error Coverage Tests
// =============================================================================

func TestExecuteVTPMQuote_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.vtpmQuoteFunc = func(ctx context.Context, name string, nonce []byte, pcrs []int) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"name":  "test-vtpm",
		"nonce": "bm9uY2UxMjM=", // "nonce123" base64 encoded
		"pcrs":  []interface{}{float64(0), float64(1), float64(7)},
	}

	_, err := registry.ExecuteTool(ctx, "vtpm_quote", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteVTPMUnseal_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.vtpmUnsealFunc = func(ctx context.Context, name string, sealed []byte, authValue string) ([]byte, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"name":   "test-vtpm",
		"sealed": "c2VhbGVkLWRhdGE=", // "sealed-data" base64 encoded
	}

	_, err := registry.ExecuteTool(ctx, "vtpm_unseal", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteVTPMExtendPCR_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.vtpmExtendPCRFunc = func(ctx context.Context, name string, pcr int, data []byte) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"name": "test-vtpm",
		"pcr":  float64(7),
		"data": "ZXh0ZW5kLWRhdGE=", // "extend-data" base64 encoded
	}

	_, err := registry.ExecuteTool(ctx, "vtpm_extend_pcr", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteVTPMReadPCR_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.vtpmReadPCRFunc = func(ctx context.Context, name string, pcr int) ([]byte, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"name": "test-vtpm",
		"pcr":  float64(7),
	}

	_, err := registry.ExecuteTool(ctx, "vtpm_read_pcr", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

// =============================================================================
// ExecuteTool Context Timeout Coverage
// =============================================================================

func TestExecuteTool_WithExistingDeadline(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, newTestLogger())

	result, err := registry.ExecuteTool(ctx, "vtpm_list", map[string]interface{}{})
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result == nil {
		t.Error("expected non-nil result")
	}
}

func TestExecuteTool_UnknownTool(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.ExecuteTool(ctx, "nonexistent_tool", map[string]interface{}{})
	if err == nil {
		t.Error("expected error for unknown tool")
	}
	if err.Error() != "unknown tool: nonexistent_tool" {
		t.Errorf("unexpected error message: %v", err)
	}
}

// =============================================================================
// Additional Service Error Coverage Tests
// =============================================================================

func TestExecuteVTPMCreate_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.vtpmCreateFunc = func(ctx context.Context, name, algorithm string, secureBoot bool, labels map[string]string) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"name":      "test-vtpm",
		"algorithm": "rsa",
	}

	_, err := registry.ExecuteTool(ctx, "vtpm_create", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteVTPMDelete_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.vtpmDeleteFunc = func(ctx context.Context, name string) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"name": "test-vtpm",
	}

	_, err := registry.ExecuteTool(ctx, "vtpm_delete", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteVTPMStart_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.vtpmStartFunc = func(ctx context.Context, name string) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"name": "test-vtpm",
	}

	_, err := registry.ExecuteTool(ctx, "vtpm_start", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteVTPMStop_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.vtpmStopFunc = func(ctx context.Context, name string) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"name": "test-vtpm",
	}

	_, err := registry.ExecuteTool(ctx, "vtpm_stop", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteVTPMList_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.vtpmListFunc = func(ctx context.Context, opts *vtpm.ListOptions) ([]interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.ExecuteTool(ctx, "vtpm_list", map[string]interface{}{})
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteVTPMSeal_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.vtpmSealFunc = func(ctx context.Context, name string, data []byte, pcrs []int, authValue string) ([]byte, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"name": "test-vtpm",
		"data": "dGVzdC1kYXRh", // "test-data" base64 encoded
		"pcrs": []interface{}{float64(0), float64(7)},
	}

	_, err := registry.ExecuteTool(ctx, "vtpm_seal", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

// =============================================================================
// DNS Service Error Coverage Tests
// =============================================================================

func TestExecuteDNSAddRecord_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.dnsAddRecordFunc = func(ctx context.Context, name, recordType, value string, ttl int) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"name":        "test.example.com",
		"record_type": "A",
		"value":       "192.168.1.1",
		"ttl":         float64(300),
	}

	_, err := registry.ExecuteTool(ctx, "dns_add_record", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteDNSDeleteRecord_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.dnsDeleteRecordFunc = func(ctx context.Context, name, recordType string) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"name":        "test.example.com",
		"record_type": "A",
	}

	_, err := registry.ExecuteTool(ctx, "dns_delete_record", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteDNSGetRecord_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.dnsGetRecordFunc = func(ctx context.Context, name, recordType string) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"name":        "test.example.com",
		"record_type": "A",
	}

	_, err := registry.ExecuteTool(ctx, "dns_get_record", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteDNSListRecords_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.dnsListRecordsFunc = func(ctx context.Context, zone string) ([]interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"zone": "example.com",
	}

	_, err := registry.ExecuteTool(ctx, "dns_list_records", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteDNSResolve_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.dnsResolveFunc = func(ctx context.Context, name, recordType string) ([]string, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"name":        "test.example.com",
		"record_type": "A",
	}

	_, err := registry.ExecuteTool(ctx, "dns_resolve", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteDNSCreateZone_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.dnsCreateZoneFunc = func(ctx context.Context, zone string) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"zone": "example.com",
	}

	_, err := registry.ExecuteTool(ctx, "dns_create_zone", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteDNSDeleteZone_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.dnsDeleteZoneFunc = func(ctx context.Context, zone string) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"zone": "example.com",
	}

	_, err := registry.ExecuteTool(ctx, "dns_delete_zone", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteDNSListZones_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.dnsListZonesFunc = func(ctx context.Context) ([]string, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.ExecuteTool(ctx, "dns_list_zones", map[string]interface{}{})
	if err == nil {
		t.Error("expected error from service")
	}
}

// =============================================================================
// Device Service Error Coverage Tests
// =============================================================================

func TestExecuteDeviceGet_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.deviceGetFunc = func(ctx context.Context, deviceID string) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"device_id": "device-123",
	}

	_, err := registry.ExecuteTool(ctx, "device_get", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteDeviceList_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.deviceListFunc = func(ctx context.Context, filter map[string]string) ([]interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.ExecuteTool(ctx, "device_list", map[string]interface{}{})
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteDeviceDelete_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.deviceDeleteFunc = func(ctx context.Context, deviceID string) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"device_id": "device-123",
	}

	_, err := registry.ExecuteTool(ctx, "device_delete", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

// =============================================================================
// SDN Service Error Coverage Tests
// =============================================================================

func TestExecuteSDNListBridges_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.sdnListBridgesFunc = func(ctx context.Context) ([]interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.ExecuteTool(ctx, "sdn_list_bridges", map[string]interface{}{})
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteSDNCreateBridge_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.sdnCreateBridgeFunc = func(ctx context.Context, bridgeName string) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"bridge_name": "br0",
	}

	_, err := registry.ExecuteTool(ctx, "sdn_create_bridge", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteSDNDeleteBridge_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.sdnDeleteBridgeFunc = func(ctx context.Context, bridgeName string) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"bridge_name": "br0",
	}

	_, err := registry.ExecuteTool(ctx, "sdn_delete_bridge", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteSDNAddPort_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.sdnAddPortFunc = func(ctx context.Context, bridgeName, portName, portType string) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"bridge_name": "br0",
		"port_name":   "eth0",
		"port_type":   "internal",
	}

	_, err := registry.ExecuteTool(ctx, "sdn_add_port", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

// =============================================================================
// Health Service Error Coverage Tests
// =============================================================================

func TestExecuteHealth_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.healthFunc = func(ctx context.Context) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.ExecuteTool(ctx, "health_check", map[string]interface{}{})
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteLiveness_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.livenessFunc = func(ctx context.Context) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.ExecuteTool(ctx, "health_liveness", map[string]interface{}{})
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteReadiness_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.readinessFunc = func(ctx context.Context) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.ExecuteTool(ctx, "health_readiness", map[string]interface{}{})
	if err == nil {
		t.Error("expected error from service")
	}
}

// =============================================================================
// CA Service Error Coverage Tests
// =============================================================================

func TestExecuteCAInfo_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.caInfoFunc = func(ctx context.Context) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.ExecuteTool(ctx, "ca_info", map[string]interface{}{})
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteCAIssue_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.caIssueFunc = func(ctx context.Context, req *CAIssueRequest) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"common_name": "test.example.com",
	}

	_, err := registry.ExecuteTool(ctx, "ca_issue", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

// A key request gets the default algorithm, store and validity.
func TestExecuteCAIssue_KeyDefaults(t *testing.T) {
	var got *CAIssueRequest
	svc := newMockServiceProvider()
	svc.caIssueFunc = func(ctx context.Context, req *CAIssueRequest) (interface{}, error) {
		got = req
		return map[string]string{}, nil
	}
	registry := NewToolRegistry(svc, newTestLogger())
	if _, err := registry.ExecuteTool(context.Background(), "ca_issue", map[string]interface{}{"common_name": "a"}); err != nil {
		t.Fatalf("ca_issue: %v", err)
	}
	if got.Algorithm != "ECDSA" || got.StoreType != "software" || got.ValidDays != 365 {
		t.Errorf("request = %+v", got)
	}
}

// ca_sign_csr is its own tool: the CSR goes to CASignCSR, never CAIssue.
func TestExecuteCASignCSR(t *testing.T) {
	cases := []struct {
		name string
		args map[string]interface{}
		days int
	}{
		{"unset validity is left to the CA default", map[string]interface{}{"csr_pem": "PEM"}, 0},
		{"explicit validity", map[string]interface{}{"csr_pem": "PEM", "valid_days": 30}, 30},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var got *CASignCSRRequest
			svc := newMockServiceProvider()
			svc.caSignCSRFunc = func(ctx context.Context, req *CASignCSRRequest) (interface{}, error) {
				got = req
				return map[string]string{}, nil
			}
			svc.caIssueFunc = func(ctx context.Context, req *CAIssueRequest) (interface{}, error) {
				t.Error("ca_sign_csr reached CAIssue")
				return nil, nil
			}
			registry := NewToolRegistry(svc, newTestLogger())
			if _, err := registry.ExecuteTool(context.Background(), "ca_sign_csr", tc.args); err != nil {
				t.Fatalf("ca_sign_csr: %v", err)
			}
			if got.CSRPEM != "PEM" || got.ValidDays != tc.days {
				t.Errorf("request = %+v", got)
			}
		})
	}
}

func TestExecuteCASignCSR_ServiceError(t *testing.T) {
	svc := newMockServiceProvider()
	svc.caSignCSRFunc = func(ctx context.Context, req *CASignCSRRequest) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	if _, err := registry.ExecuteTool(context.Background(), "ca_sign_csr", map[string]interface{}{"csr_pem": "PEM"}); err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteCAGet_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.caGetFunc = func(ctx context.Context, serial string, includePEM, includeDER bool) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"serial": "1234567890",
	}

	_, err := registry.ExecuteTool(ctx, "ca_get", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteCAList_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.caListFunc = func(ctx context.Context, limit int, cursor string, status string) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.ExecuteTool(ctx, "ca_list", map[string]interface{}{})
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteCARevoke_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.caRevokeFunc = func(ctx context.Context, serial string, reason int, deleteKeys bool) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"serial": "1234567890",
		"reason": float64(1),
	}

	_, err := registry.ExecuteTool(ctx, "ca_revoke", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteCARenew_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.caRenewFunc = func(ctx context.Context, serial string, extendDays int, preserveAttrs bool) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"serial": "1234567890",
	}

	_, err := registry.ExecuteTool(ctx, "ca_renew", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteCAVerify_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.caVerifyFunc = func(ctx context.Context, certificatePEM string, certificateDER []byte, checkRevoked bool) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"certificate_pem": "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----",
	}

	_, err := registry.ExecuteTool(ctx, "ca_verify", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteCACRL_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.caCRLFunc = func(ctx context.Context) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.ExecuteTool(ctx, "ca_crl", map[string]interface{}{})
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteCABundle_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.caBundleFunc = func(ctx context.Context, storeType string, algorithm string) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.ExecuteTool(ctx, "ca_bundle", map[string]interface{}{})
	if err == nil {
		t.Error("expected error from service")
	}
}

// =============================================================================
// IAM User Service Error Coverage Tests
// =============================================================================

func TestExecuteIAMCreateUser_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamCreateUserFunc = func(ctx context.Context, req *IAMCreateUserRequest) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id": "tenant-123",
		"username":  "testuser",
		"email":     "test@example.com",
	}

	_, err := registry.ExecuteTool(ctx, "iam_create_user", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMDeleteUser_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamDeleteUserFunc = func(ctx context.Context, tenantID, userID string) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id": "tenant-123",
		"user_id":   "user-456",
	}

	_, err := registry.ExecuteTool(ctx, "iam_delete_user", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMGetUser_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamGetUserFunc = func(ctx context.Context, tenantID, userID string) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id": "tenant-123",
		"user_id":   "user-456",
	}

	_, err := registry.ExecuteTool(ctx, "iam_get_user", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMListUsers_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamListUsersFunc = func(ctx context.Context, req *IAMListUsersRequest) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id": "tenant-123",
	}

	_, err := registry.ExecuteTool(ctx, "iam_list_users", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

// =============================================================================
// IAM Role Service Error Coverage Tests
// =============================================================================

func TestExecuteIAMCreateRole_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamCreateRoleFunc = func(ctx context.Context, req *IAMCreateRoleRequest) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id":   "tenant-123",
		"id":          "role-456",
		"name":        "test-role",
		"permissions": []interface{}{"read", "write"},
	}

	_, err := registry.ExecuteTool(ctx, "iam_create_role", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMDeleteRole_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamDeleteRoleFunc = func(ctx context.Context, tenantID, roleID string) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id": "tenant-123",
		"role_id":   "role-456",
	}

	_, err := registry.ExecuteTool(ctx, "iam_delete_role", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMGetRole_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamGetRoleFunc = func(ctx context.Context, tenantID, roleID string) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id": "tenant-123",
		"role_id":   "role-456",
	}

	_, err := registry.ExecuteTool(ctx, "iam_get_role", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMListRoles_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamListRolesFunc = func(ctx context.Context, tenantID string, page IAMPagination) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id": "tenant-123",
	}

	_, err := registry.ExecuteTool(ctx, "iam_list_roles", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMAssignRole_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamAssignRoleFunc = func(ctx context.Context, tenantID, userID, roleID string) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id": "tenant-123",
		"user_id":   "user-456",
		"role_id":   "admin",
	}

	_, err := registry.ExecuteTool(ctx, "iam_assign_role", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMRevokeRole_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamRevokeRoleFunc = func(ctx context.Context, tenantID, userID, roleID string) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id": "tenant-123",
		"user_id":   "user-456",
		"role_id":   "admin",
	}

	_, err := registry.ExecuteTool(ctx, "iam_revoke_role", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMCheckPermission_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamCheckPermissionFunc = func(ctx context.Context, req *IAMCheckPermissionRequest) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id":  "tenant-123",
		"subject_id": "user-456",
		"resource":   "containers",
		"action":     "create",
	}

	_, err := registry.ExecuteTool(ctx, "iam_check_permission", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMAuthenticate_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamAuthenticateFunc = func(ctx context.Context, req *IAMAuthenticateRequest) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id": "tenant-123",
		"username":  "testuser",
		"password":  "testpass",
	}

	_, err := registry.ExecuteTool(ctx, "iam_authenticate", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

// =============================================================================
// KMS Service Error Coverage Tests
// =============================================================================

func TestExecuteKMSCreateKey_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.kmsCreateKeyFunc = func(ctx context.Context, req *KMSCreateKeyRequest) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"name":      "test-key",
		"algorithm": "aes-256-gcm",
		"usage":     []interface{}{"encrypt", "decrypt"},
	}

	_, err := registry.ExecuteTool(ctx, "kms_generate_key", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteKMSDeleteKey_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.kmsDeleteKeyFunc = func(ctx context.Context, keyID string) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"key_id": "key-123",
	}

	_, err := registry.ExecuteTool(ctx, "kms_delete_key", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteKMSGetKey_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.kmsGetKeyFunc = func(ctx context.Context, keyID string, version uint64) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"key_id": "key-123",
	}

	_, err := registry.ExecuteTool(ctx, "kms_get_key", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteKMSListKeys_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.kmsListKeysFunc = func(ctx context.Context, limit, offset int) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.ExecuteTool(ctx, "kms_list_keys", map[string]interface{}{})
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteKMSRotateKey_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.kmsRotateKeyFunc = func(ctx context.Context, keyID string) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"key_id": "key-123",
	}

	_, err := registry.ExecuteTool(ctx, "kms_rotate_key", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteKMSEncrypt_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.kmsEncryptFunc = func(ctx context.Context, req *KMSEncryptRequest) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"key_id":    "key-123",
		"plaintext": "dGVzdC1kYXRh", // "test-data" base64 encoded
	}

	_, err := registry.ExecuteTool(ctx, "kms_encrypt", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteKMSDecrypt_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.kmsDecryptFunc = func(ctx context.Context, req *KMSDecryptRequest) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"key_id":     "key-123",
		"ciphertext": "Y2lwaGVydGV4dA==", // "ciphertext" base64 encoded
	}

	_, err := registry.ExecuteTool(ctx, "kms_decrypt", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteKMSSign_PreHashedAndHashCoercion(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	var captured *KMSSignRequest
	svc.kmsSignFunc = func(ctx context.Context, req *KMSSignRequest) (interface{}, error) {
		captured = req
		return map[string]interface{}{"signature": "c2ln"}, nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	// Numeric hash_algorithm mirrors the SDK MCP transport adapter, which
	// JSON-encodes the platform.v1 proto SignRequest (SHA256 = 2).
	args := map[string]interface{}{
		"key_id":         "key-123",
		"message":        "3q2+7w==", // 0xdeadbeef base64 encoded
		"hash_algorithm": float64(2),
		"pre_hashed":     true,
	}

	if _, err := registry.ExecuteTool(ctx, "kms_sign", args); err != nil {
		t.Fatalf("ExecuteTool: %v", err)
	}
	if captured == nil {
		t.Fatal("provider KMSSign was not called")
	}
	if !captured.PreHashed {
		t.Error("PreHashed = false, want true")
	}
	if captured.HashAlgorithm != "SHA256" {
		t.Errorf("HashAlgorithm = %q, want SHA256", captured.HashAlgorithm)
	}
	if len(captured.Message) != 4 {
		t.Errorf("Message = %x, want the 4 decoded digest bytes", captured.Message)
	}
}

func TestExecuteKMSSign_InvalidInputs(t *testing.T) {
	ctx := context.Background()
	registry := NewToolRegistry(newMockServiceProvider(), newTestLogger())

	if _, err := registry.ExecuteTool(ctx, "kms_sign", map[string]interface{}{
		"key_id": "key-123",
	}); err == nil {
		t.Error("expected error for missing message")
	}
	if _, err := registry.ExecuteTool(ctx, "kms_sign", map[string]interface{}{
		"key_id":  "key-123",
		"message": "not-base64!!!",
	}); err == nil {
		t.Error("expected error for invalid base64 message")
	}
	if _, err := registry.ExecuteTool(ctx, "kms_sign", map[string]interface{}{
		"message": "bWVzc2FnZQ==",
	}); err == nil {
		t.Error("expected error for missing key_id")
	}
}

func TestExecuteKMSSign_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.kmsSignFunc = func(ctx context.Context, req *KMSSignRequest) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"key_id":  "key-123",
		"message": "bWVzc2FnZQ==", // "message" base64 encoded
	}

	_, err := registry.ExecuteTool(ctx, "kms_sign", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteKMSVerify_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.kmsVerifyFunc = func(ctx context.Context, req *KMSVerifyRequest) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"key_id":    "key-123",
		"message":   "bWVzc2FnZQ==", // "message" base64 encoded
		"signature": "c2lnbmF0dXJl", // "signature" base64 encoded
	}

	_, err := registry.ExecuteTool(ctx, "kms_verify", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteKMSGenerateRandom_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.kmsGenerateRandomFunc = func(ctx context.Context, numBytes int) ([]byte, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"num_bytes": float64(32),
	}

	_, err := registry.ExecuteTool(ctx, "kms_random", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

// =============================================================================
// IAM Group Service Error Coverage Tests
// =============================================================================

func TestExecuteIAMCreateGroup_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamCreateGroupFunc = func(ctx context.Context, req *IAMCreateGroupRequest) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id":   "tenant-123",
		"id":          "group-456",
		"name":        "test-group",
		"description": "Test group description",
	}

	_, err := registry.ExecuteTool(ctx, "iam_create_group", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMDeleteGroup_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamDeleteGroupFunc = func(ctx context.Context, tenantID, groupID string) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id": "tenant-123",
		"group_id":  "group-456",
	}

	_, err := registry.ExecuteTool(ctx, "iam_delete_group", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMGetGroup_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamGetGroupFunc = func(ctx context.Context, tenantID, groupID string) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id": "tenant-123",
		"group_id":  "group-456",
	}

	_, err := registry.ExecuteTool(ctx, "iam_get_group", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMListGroups_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamListGroupsFunc = func(ctx context.Context, tenantID string, page IAMPagination) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id": "tenant-123",
	}

	_, err := registry.ExecuteTool(ctx, "iam_list_groups", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMAddGroupMember_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamAddGroupMemberFunc = func(ctx context.Context, tenantID, groupID, userID string) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id": "tenant-123",
		"group_id":  "group-456",
		"user_id":   "user-789",
	}

	_, err := registry.ExecuteTool(ctx, "iam_add_group_member", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMRemoveGroupMember_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamRemoveGroupMemberFunc = func(ctx context.Context, tenantID, groupID, userID string) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id": "tenant-123",
		"group_id":  "group-456",
		"user_id":   "user-789",
	}

	_, err := registry.ExecuteTool(ctx, "iam_remove_group_member", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

// =============================================================================
// IAM Tenant Service Error Coverage Tests
// =============================================================================

func TestExecuteIAMCreateTenant_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamCreateTenantFunc = func(ctx context.Context, req *IAMCreateTenantRequest) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"id":   "tenant-new",
		"name": "New Tenant",
	}

	_, err := registry.ExecuteTool(ctx, "iam_create_tenant", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMDeleteTenant_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamDeleteTenantFunc = func(ctx context.Context, tenantID string) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id": "tenant-123",
	}

	_, err := registry.ExecuteTool(ctx, "iam_delete_tenant", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMGetTenant_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamGetTenantFunc = func(ctx context.Context, tenantID string) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id": "tenant-123",
	}

	_, err := registry.ExecuteTool(ctx, "iam_get_tenant", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMListTenants_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamListTenantsFunc = func(ctx context.Context, page IAMPagination) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.ExecuteTool(ctx, "iam_list_tenants", map[string]interface{}{})
	if err == nil {
		t.Error("expected error from service")
	}
}

// =============================================================================
// IAM Token Service Error Coverage Tests
// =============================================================================

func TestExecuteIAMCreateToken_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamCreateTokenFunc = func(ctx context.Context, req *IAMCreateTokenRequest) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"tenant_id": "tenant-123",
		"user_id":   "user-456",
		"scopes":    []interface{}{"read", "write"},
	}

	_, err := registry.ExecuteTool(ctx, "iam_create_token", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMRevokeToken_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamRevokeTokenFunc = func(ctx context.Context, tokenID string) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"token_id": "token-123",
	}

	_, err := registry.ExecuteTool(ctx, "iam_revoke_token", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteIAMVerifyToken_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iamVerifyTokenFunc = func(ctx context.Context, token string) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"token": "test-token-string",
	}

	_, err := registry.ExecuteTool(ctx, "iam_verify_token", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

// =============================================================================
// KMS Data Key Service Error Coverage Tests
// =============================================================================

func TestExecuteKMSGenerateDataKey_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.kmsGenerateDataKeyFunc = func(ctx context.Context, req *KMSGenerateDataKeyRequest) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"key_id":    "kek-123",
		"algorithm": "aes-256-gcm",
	}

	_, err := registry.ExecuteTool(ctx, "kms_generate_data_key", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteKMSGenerateWrappedDataKey_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.kmsGenerateWrappedDataKeyFunc = func(ctx context.Context, req *KMSGenerateWrappedDataKeyRequest) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"key_id":    "kek-123",
		"algorithm": "aes-256-gcm",
	}

	_, err := registry.ExecuteTool(ctx, "kms_generate_wrapped_data_key", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteKMSGenerateWrappedDataKey_MissingKeyID(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"algorithm": "aes-256-gcm",
	}

	_, err := registry.ExecuteTool(ctx, "kms_generate_wrapped_data_key", args)
	if err == nil {
		t.Error("expected error for missing key_id")
	}
}

// =============================================================================
// Container Service Error Coverage Tests
// =============================================================================

func TestExecuteContainerCreate_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.containerCreateFunc = func(ctx context.Context, name string, image string, config map[string]interface{}) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"name":  "test-container",
		"image": "alpine:latest",
	}

	_, err := registry.ExecuteTool(ctx, "container_create", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteContainerStart_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.containerStartFunc = func(ctx context.Context, id string) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"id": "container-123",
	}

	_, err := registry.ExecuteTool(ctx, "container_start", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteContainerStop_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.containerStopFunc = func(ctx context.Context, id string, timeout int) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"id": "container-123",
	}

	_, err := registry.ExecuteTool(ctx, "container_stop", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteContainerRemove_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.containerRemoveFunc = func(ctx context.Context, id string, force bool) error {
		return ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"id": "container-123",
	}

	_, err := registry.ExecuteTool(ctx, "container_remove", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteContainerGet_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.containerGetFunc = func(ctx context.Context, id string) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"id": "container-123",
	}

	_, err := registry.ExecuteTool(ctx, "container_get", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteContainerList_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.containerListFunc = func(ctx context.Context, all bool, filters map[string][]string, limit int) ([]interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.ExecuteTool(ctx, "container_list", map[string]interface{}{})
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteContainerLogs_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.containerLogsFunc = func(ctx context.Context, id string, follow bool, stdout bool, stderr bool, tail string, timestamps bool) (string, error) {
		return "", ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"id": "container-123",
	}

	_, err := registry.ExecuteTool(ctx, "container_logs", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

func TestExecuteContainerAttest_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.containerAttestFunc = func(ctx context.Context, id string) (interface{}, error) {
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"id": "container-123",
	}

	_, err := registry.ExecuteTool(ctx, "container_attest", args)
	if err == nil {
		t.Error("expected error from service")
	}
}

// =============================================================================
// Additional Coverage Tests for 90%+ Target
// =============================================================================

// TestClaimsMapToResult_AllFieldTypes tests claimsMapToResult with different field types
func TestClaimsMapToResult_AllFieldTypes(t *testing.T) {
	adapter := &QuicBaaSAuthAdapter{}

	tests := []struct {
		name   string
		claims map[string]interface{}
		check  func(*testing.T, *TokenValidationResult)
	}{
		{
			name:   "empty claims returns valid result",
			claims: map[string]interface{}{},
			check: func(t *testing.T, r *TokenValidationResult) {
				if !r.Valid {
					t.Error("expected valid result")
				}
			},
		},
		{
			name: "all fields populated",
			claims: map[string]interface{}{
				"sub":       "user-123",
				"tenant_id": "tenant-456",
				"exp":       int64(1234567890),
				"roles":     []string{"admin", "user"},
				"groups":    []string{"group1", "group2"},
				"scope":     "read write",
			},
			check: func(t *testing.T, r *TokenValidationResult) {
				if r.UserID != "user-123" {
					t.Errorf("expected user-123, got %s", r.UserID)
				}
				if r.TenantID != "tenant-456" {
					t.Errorf("expected tenant-456, got %s", r.TenantID)
				}
				if r.ExpiresAt != 1234567890 {
					t.Errorf("expected 1234567890, got %d", r.ExpiresAt)
				}
				if len(r.Roles) != 2 {
					t.Errorf("expected 2 roles, got %d", len(r.Roles))
				}
				if len(r.Groups) != 2 {
					t.Errorf("expected 2 groups, got %d", len(r.Groups))
				}
				if r.Scope != "read write" {
					t.Errorf("expected 'read write', got %s", r.Scope)
				}
			},
		},
		{
			name: "wrong types ignored",
			claims: map[string]interface{}{
				"sub":       123,        // not string
				"tenant_id": true,       // not string
				"exp":       "not-int",  // not int64
				"roles":     "not-list", // not []string
				"groups":    123,        // not []string
				"scope":     456,        // not string
			},
			check: func(t *testing.T, r *TokenValidationResult) {
				if r.UserID != "" {
					t.Error("expected empty UserID")
				}
				if r.TenantID != "" {
					t.Error("expected empty TenantID")
				}
				if r.ExpiresAt != 0 {
					t.Error("expected zero ExpiresAt")
				}
				if len(r.Roles) != 0 {
					t.Error("expected empty Roles")
				}
				if len(r.Groups) != 0 {
					t.Error("expected empty Groups")
				}
				if r.Scope != "" {
					t.Error("expected empty Scope")
				}
			},
		},
		{
			name: "nil values",
			claims: map[string]interface{}{
				"sub":       nil,
				"tenant_id": nil,
				"exp":       nil,
				"roles":     nil,
				"groups":    nil,
				"scope":     nil,
			},
			check: func(t *testing.T, r *TokenValidationResult) {
				if !r.Valid {
					t.Error("expected valid result even with nil values")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := adapter.claimsMapToResult(tt.claims)
			tt.check(t, result)
		})
	}
}

// TestMarshalResultEdgeCases tests marshalResult with various edge cases
func TestMarshalResultEdgeCases(t *testing.T) {
	tests := []struct {
		name    string
		data    interface{}
		wantErr bool
	}{
		{
			name:    "nil data",
			data:    nil,
			wantErr: false,
		},
		{
			name:    "simple string",
			data:    "test",
			wantErr: false,
		},
		{
			name:    "nested struct",
			data:    struct{ Name string }{Name: "test"},
			wantErr: false,
		},
		{
			name:    "slice",
			data:    []string{"a", "b", "c"},
			wantErr: false,
		},
		{
			name:    "map",
			data:    map[string]int{"a": 1, "b": 2},
			wantErr: false,
		},
		{
			name:    "channel cannot be marshaled",
			data:    make(chan int),
			wantErr: true,
		},
		{
			name:    "func cannot be marshaled",
			data:    func() {},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := marshalResult(tt.data)
			if (err != nil) != tt.wantErr {
				t.Errorf("marshalResult() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestServerStartWithSSE tests server with SSE transport
func TestServerStartWithSSE(t *testing.T) {
	server := &Server{
		config: &Config{
			Transport: "sse",
			HTTPAddr:  "127.0.0.1:0",
		},
		shutdown: make(chan struct{}),
	}

	err := server.Start()
	if err == nil {
		server.Stop()
	}
}

// TestAuthzCheckerEdgeCases tests authorization checker edge cases
func TestAuthzCheckerEdgeCases(t *testing.T) {
	// Test with no auth service configured - use a known protected tool
	checker := &AuthorizationChecker{
		toolPermissions: map[string]string{
			"protected_tool": "read:resource",
		},
	}

	ctx := context.Background()

	// A protected tool with no auth backend is refused (#440): nothing can
	// grant the permission it requires, so there is no "open mode".
	err := checker.CheckToolAuthorization(ctx, "protected_tool", "")
	if err == nil || err.Type != AuthErrorMissingToken {
		t.Errorf("expected AuthErrorMissingToken for a protected tool without a backend, got %v", err)
	}

	// An unmapped tool is refused as unclassified (#300), backend or not.
	err = checker.CheckToolAuthorization(ctx, "unknown_tool", "")
	if err == nil || err.Type != AuthErrorToolNotClassified {
		t.Errorf("expected AuthErrorToolNotClassified for an unmapped tool, got %v", err)
	}
}

// TestServerStartStdioTransportNotSupported tests stdio transport path
func TestServerStartStdioTransportNotSupported(t *testing.T) {
	// Stdio transport can't be easily tested in unit tests
	// but we can exercise the code path that checks for it
	server := &Server{
		config: &Config{
			Transport: "stdio",
		},
		shutdown: make(chan struct{}),
	}

	// Start will try to use stdio which will fail
	err := server.Start()
	if err != nil {
		// Expected - stdio doesn't work in tests
		t.Logf("stdio transport error (expected): %v", err)
	}
}

// TestServerStartUnknownTransport tests unknown transport handling
func TestServerStartUnknownTransport(t *testing.T) {
	server := &Server{
		config: &Config{
			Transport: "unknown-transport",
		},
		shutdown: make(chan struct{}),
	}

	err := server.Start()
	if err == nil {
		server.Stop()
		t.Error("expected error for unknown transport")
	}
}

// TestServerStopNotRunning tests stopping a server that's not running
func TestServerStopNotRunning(t *testing.T) {
	server := &Server{
		config:   &Config{},
		shutdown: make(chan struct{}),
	}

	// Should not panic or error
	server.Stop()
}

// TestServerHandleHTTPRequestInvalidJSON tests HTTP handler with invalid JSON
func TestServerHandleHTTPRequestInvalidJSON(t *testing.T) {
	server := &Server{
		config: &Config{
			Transport: "http",
			HTTPAddr:  "127.0.0.1:0",
		},
		shutdown: make(chan struct{}),
	}

	req := httptest.NewRequest("POST", "/mcp/v1", strings.NewReader("invalid-json{"))
	w := httptest.NewRecorder()

	server.handleHTTPRequest(w, req)

	// JSON-RPC returns 200 OK with error in response body (per spec)
	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	// Verify error response
	var resp mcpwire.JSONRPCResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Error == nil {
		t.Error("expected error response for invalid JSON")
	}
	if resp.Error != nil && resp.Error.Code != mcpwire.ParseError {
		t.Errorf("expected parse error code %d, got %d", mcpwire.ParseError, resp.Error.Code)
	}
}

// TestServerHandleHTTPRequestMethodNotAllowed tests HTTP handler with wrong method
func TestServerHandleHTTPRequestMethodNotAllowed(t *testing.T) {
	server := &Server{
		config: &Config{
			Transport: "http",
			HTTPAddr:  "127.0.0.1:0",
		},
		shutdown: make(chan struct{}),
	}

	req := httptest.NewRequest("GET", "/mcp/v1", nil)
	w := httptest.NewRecorder()

	server.handleHTTPRequest(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}
}

// TestHandleHTTPRequestValidRequest tests handleHTTPRequest with valid request
func TestHandleHTTPRequestValidRequest(t *testing.T) {
	server := &Server{
		config: &Config{
			Transport:     "http",
			HTTPAddr:      "127.0.0.1:0",
			ServerName:    "test",
			ServerVersion: "1.0",
		},
		shutdown: make(chan struct{}),
	}
	server.running.Store(true)

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}`
	req := httptest.NewRequest("POST", "/mcp/v1", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.handleHTTPRequest(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}
}

// TestServerStopWhileRunning tests stopping a running server
func TestServerStopWhileRunning(t *testing.T) {
	server := &Server{
		config: &Config{
			Transport: "http",
			HTTPAddr:  "127.0.0.1:0",
		},
		shutdown: make(chan struct{}),
	}
	server.running.Store(true)

	// Stop should work
	server.Stop()

	if server.running.Load() {
		t.Error("server should be stopped")
	}
}

// TestCheckToolAuthorizationMissingToken tests auth with missing token
func TestCheckToolAuthorizationMissingToken(t *testing.T) {
	checker := &AuthorizationChecker{
		toolPermissions: map[string]string{
			"protected_tool": "read:resource",
		},
	}

	ctx := context.Background()

	// Initialize with some mock auth service
	checker.authService = &mockAuthService{
		validateFunc: func(ctx context.Context, token string) (*TokenValidationResult, error) {
			return &TokenValidationResult{Valid: true}, nil
		},
	}

	// Should fail due to missing token
	err := checker.CheckToolAuthorization(ctx, "protected_tool", "")
	if err == nil {
		t.Error("expected error for missing token")
	}
	if err != nil && err.Type != AuthErrorMissingToken {
		t.Errorf("expected AuthErrorMissingToken, got %v", err.Type)
	}
}

// mockAuthService for auth testing
type mockAuthService struct {
	validateFunc  func(ctx context.Context, token string) (*TokenValidationResult, error)
	checkPermFunc func(ctx context.Context, subject, resource, action string) (bool, error)
}

func (m *mockAuthService) ValidateToken(ctx context.Context, token string) (*TokenValidationResult, error) {
	if m.validateFunc != nil {
		return m.validateFunc(ctx, token)
	}
	return nil, nil
}

func (m *mockAuthService) CheckPermission(ctx context.Context, subject, resource, action string) (bool, error) {
	if m.checkPermFunc != nil {
		return m.checkPermFunc(ctx, subject, resource, action)
	}
	return true, nil
}

// TestServerInitializeTools tests initialize returning tools
func TestServerInitializeTools(t *testing.T) {
	server := &Server{
		config: &Config{
			ServerName:    "test-server",
			ServerVersion: "1.0.0",
		},
		shutdown: make(chan struct{}),
	}
	server.running.Store(true)

	body := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`
	req := httptest.NewRequest("POST", "/mcp/v1", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.handleHTTPRequest(w, req)

	var resp mcpwire.JSONRPCResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Error != nil {
		t.Errorf("unexpected error: %v", resp.Error.Message)
	}
}

// TestServerHandleRequestVersionMismatch tests handleRequest with wrong version
func TestServerHandleRequestVersionMismatch(t *testing.T) {
	server := &Server{
		config: &Config{
			ServerName:    "test",
			ServerVersion: "1.0",
		},
		shutdown: make(chan struct{}),
	}
	server.running.Store(true)

	// Send request with wrong JSON-RPC version
	body := `{"jsonrpc":"1.0","id":1,"method":"initialize"}`
	req := httptest.NewRequest("POST", "/mcp/v1", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.handleHTTPRequest(w, req)

	var resp mcpwire.JSONRPCResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Error == nil {
		t.Error("expected error for version mismatch")
	}
}

// TestServerHandleRequestUnknownMethod tests handleRequest with unknown method
func TestServerHandleRequestUnknownMethod(t *testing.T) {
	server := &Server{
		config: &Config{
			ServerName:    "test",
			ServerVersion: "1.0",
		},
		shutdown: make(chan struct{}),
	}
	server.running.Store(true)

	body := `{"jsonrpc":"2.0","id":1,"method":"unknown_method"}`
	req := httptest.NewRequest("POST", "/mcp/v1", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	server.handleHTTPRequest(w, req)

	var resp mcpwire.JSONRPCResponse
	if err := json.NewDecoder(w.Body).Decode(&resp); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}

	if resp.Error == nil {
		t.Error("expected error for unknown method")
	}
}

// TestMakeErrorResponse tests makeErrorResponse function
func TestMakeErrorResponse(t *testing.T) {
	server := &Server{
		config: &Config{},
	}

	resp := server.makeErrorResponse(1, mcpwire.InvalidRequest, "test message", "test data")

	if resp.Error == nil {
		t.Error("expected error in response")
	}
	if resp.Error.Code != mcpwire.InvalidRequest {
		t.Errorf("expected code %d, got %d", mcpwire.InvalidRequest, resp.Error.Code)
	}
	if resp.Error.Message != "test message" {
		t.Errorf("expected message 'test message', got '%s'", resp.Error.Message)
	}
}

// TestOAuthMetadataServeHTTP tests OAuth metadata handler
func TestOAuthMetadataServeHTTP(t *testing.T) {
	config := &OAuthMetadataConfig{
		ResourceURL:             "https://example.com:8443",
		AuthorizationServerURLs: []string{"https://auth.example.com"},
		DocumentationURL:        "https://docs.example.com",
	}
	handler := NewOAuthMetadataHandler(config)

	req := httptest.NewRequest("GET", "/.well-known/oauth-protected-resource", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var metadata map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&metadata); err != nil {
		t.Fatalf("failed to decode metadata: %v", err)
	}

	if metadata["resource"] != "https://example.com:8443" {
		t.Errorf("expected resource 'https://example.com:8443', got '%v'", metadata["resource"])
	}
}

// TestOAuthMetadataDefaultConfig tests OAuth metadata handler with default config
func TestOAuthMetadataDefaultConfig(t *testing.T) {
	handler := NewOAuthMetadataHandler(nil)

	req := httptest.NewRequest("GET", "/.well-known/oauth-protected-resource", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	var metadata map[string]interface{}
	if err := json.NewDecoder(w.Body).Decode(&metadata); err != nil {
		t.Fatalf("failed to decode metadata: %v", err)
	}

	// Should have default resource URL
	if _, exists := metadata["resource"]; !exists {
		t.Error("expected 'resource' field in metadata")
	}
}

// TestExecuteToolWithExistingDeadline tests ExecuteTool when context already has deadline
func TestExecuteToolWithExistingDeadline(t *testing.T) {
	logger := newTestLogger()
	registry := NewToolRegistry(nil, logger)

	// Create context with existing deadline
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Second)
	defer cancel()

	// Execute an unknown tool with existing deadline
	_, err := registry.ExecuteTool(ctx, "unknown_tool", map[string]interface{}{})
	if err == nil {
		t.Error("expected error for unknown tool")
	}
}

// TestAuthorizationCheckerNoService tests auth checker when service is nil
func TestAuthorizationCheckerNoService(t *testing.T) {
	checker := NewAuthorizationChecker(nil, nil)

	if checker == nil {
		t.Fatal("expected non-nil checker")
	}
}

// TestReadResourceEmptyURI tests ReadResource with empty URI
func TestReadResourceEmptyURI(t *testing.T) {
	logger := newTestLogger()
	rr := NewResourceRegistry(nil, logger)

	_, err := rr.ReadResource(context.Background(), "")
	if err == nil {
		t.Error("expected error for empty URI")
	}
}

// TestReadResourceInvalidURI tests ReadResource with non-existent URI
func TestReadResourceInvalidURI(t *testing.T) {
	logger := newTestLogger()
	rr := NewResourceRegistry(nil, logger)

	_, err := rr.ReadResource(context.Background(), "nonexistent://resource")
	if err == nil {
		t.Error("expected error for non-existent resource")
	}
}

// TestReadResourceEmptyPath tests ReadResource with platform:// but no path
func TestReadResourceEmptyPath(t *testing.T) {
	logger := newTestLogger()
	rr := NewResourceRegistry(nil, logger)

	_, err := rr.ReadResource(context.Background(), "platform://")
	if err == nil {
		t.Error("expected error for empty resource path")
	}
}

// TestReadResourceUnknownType tests ReadResource with unknown resource type
func TestReadResourceUnknownType(t *testing.T) {
	logger := newTestLogger()
	rr := NewResourceRegistry(nil, logger)

	_, err := rr.ReadResource(context.Background(), "platform://unknowntype/resource")
	if err == nil {
		t.Error("expected error for unknown resource type")
	}
}

// TestOAuthDefaultOAuthMetadataConfigCreation tests default OAuth config creation
func TestOAuthDefaultOAuthMetadataConfigCreation(t *testing.T) {
	config := DefaultOAuthMetadataConfig()
	if config == nil {
		t.Fatal("expected non-nil config")
	}
	// Default config should have empty ResourceURL (to be set later)
	if config.ResourceURL != "" {
		t.Error("expected empty default ResourceURL")
	}
}

// TestOAuthMetadataMethodNotAllowed tests OAuth metadata with non-GET/HEAD methods
func TestOAuthMetadataMethodNotAllowed(t *testing.T) {
	config := &OAuthMetadataConfig{
		ResourceURL: "https://example.com:8443",
	}
	handler := NewOAuthMetadataHandler(config)

	req := httptest.NewRequest("POST", "/.well-known/oauth-protected-resource", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("expected status 405, got %d", w.Code)
	}
}

// TestOAuthMetadataHeadRequest tests OAuth metadata with HEAD request
func TestOAuthMetadataHeadRequest(t *testing.T) {
	config := &OAuthMetadataConfig{
		ResourceURL: "https://example.com:8443",
	}
	handler := NewOAuthMetadataHandler(config)

	req := httptest.NewRequest("HEAD", "/.well-known/oauth-protected-resource", nil)
	w := httptest.NewRecorder()

	handler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("expected status 200, got %d", w.Code)
	}

	// HEAD should return headers but no body
	if w.Body.Len() != 0 {
		t.Errorf("expected empty body for HEAD request, got %d bytes", w.Body.Len())
	}

	// Should still have Content-Type header
	if w.Header().Get("Content-Type") != "application/json" {
		t.Error("expected Content-Type header")
	}
}

// TestOAuthMetadataSetters tests OAuth metadata setter methods
func TestOAuthMetadataSetters(t *testing.T) {
	config := &OAuthMetadataConfig{
		ResourceURL: "https://old.example.com",
	}
	handler := NewOAuthMetadataHandler(config)

	// Test SetResourceURL
	handler.SetResourceURL("https://new.example.com")
	if handler.GetMetadata().Resource != "https://new.example.com" {
		t.Error("SetResourceURL did not update metadata")
	}

	// Test SetAuthorizationServers
	handler.SetAuthorizationServers([]string{"https://auth1.example.com", "https://auth2.example.com"})
	if len(handler.GetMetadata().AuthorizationServers) != 2 {
		t.Error("SetAuthorizationServers did not update metadata")
	}
}
