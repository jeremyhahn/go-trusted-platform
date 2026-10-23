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
	"encoding/base64"
	"encoding/json"
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
)

func TestVTPMToolExecution(t *testing.T) {
	ctx := context.Background()
	log := newTestLogger()

	t.Run("executeVTPMQuote success", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.vtpmQuoteFunc = func(ctx context.Context, name string, nonce []byte, pcrs []int) (interface{}, error) {
			if name != "test-vtpm" {
				t.Errorf("name = %s, want test-vtpm", name)
			}
			if string(nonce) != "nonce123" {
				t.Errorf("nonce = %s, want nonce123", string(nonce))
			}
			return map[string]interface{}{"quote": "data"}, nil
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"name":  "test-vtpm",
			"nonce": base64.StdEncoding.EncodeToString([]byte("nonce123")),
			"pcrs":  []interface{}{float64(0), float64(1), float64(2)},
		}

		result, err := registry.ExecuteTool(ctx, "vtpm_quote", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("executeVTPMQuote with invalid nonce encoding", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"name":  "test-vtpm",
			"nonce": "not-valid-base64!!!",
			"pcrs":  []interface{}{float64(0)},
		}

		_, err := registry.ExecuteTool(ctx, "vtpm_quote", args)
		if err == nil {
			t.Error("expected error for invalid base64")
		}
	})

	t.Run("executeVTPMSeal success", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.vtpmSealFunc = func(ctx context.Context, name string, data []byte, pcrs []int, authValue string) ([]byte, error) {
			if name != "test-vtpm" {
				t.Errorf("name = %s, want test-vtpm", name)
			}
			if string(data) != "secret-data" {
				t.Errorf("data = %s, want secret-data", string(data))
			}
			return []byte("sealed"), nil
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"name": "test-vtpm",
			"data": base64.StdEncoding.EncodeToString([]byte("secret-data")),
			"pcrs": []interface{}{float64(0), float64(1)},
		}

		result, err := registry.ExecuteTool(ctx, "vtpm_seal", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if _, ok := resultMap["sealed_data"]; !ok {
			t.Error("expected 'sealed_data' key in result")
		}
	})

	t.Run("executeVTPMSeal with invalid data encoding", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"name": "test-vtpm",
			"data": "not-valid!!!",
			"pcrs": []interface{}{float64(0)},
		}

		_, err := registry.ExecuteTool(ctx, "vtpm_seal", args)
		if err == nil {
			t.Error("expected error for invalid base64")
		}
	})

	t.Run("executeVTPMSeal error from service", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.vtpmSealFunc = func(ctx context.Context, name string, data []byte, pcrs []int, authValue string) ([]byte, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"name": "test-vtpm",
			"data": base64.StdEncoding.EncodeToString([]byte("data")),
			"pcrs": []interface{}{float64(0)},
		}

		_, err := registry.ExecuteTool(ctx, "vtpm_seal", args)
		if err == nil {
			t.Error("expected error from service")
		}
	})

	t.Run("executeVTPMUnseal success", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.vtpmUnsealFunc = func(ctx context.Context, name string, sealed []byte, authValue string) ([]byte, error) {
			return []byte("unsealed-data"), nil
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"name":   "test-vtpm",
			"sealed": base64.StdEncoding.EncodeToString([]byte("sealed-data")),
		}

		result, err := registry.ExecuteTool(ctx, "vtpm_unseal", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if _, ok := resultMap["data"]; !ok {
			t.Error("expected 'data' key in result")
		}
	})

	t.Run("executeVTPMUnseal with invalid sealed encoding", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"name":   "test-vtpm",
			"sealed": "not-valid!!!",
		}

		_, err := registry.ExecuteTool(ctx, "vtpm_unseal", args)
		if err == nil {
			t.Error("expected error for invalid base64")
		}
	})

	t.Run("executeVTPMExtendPCR success", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.vtpmExtendPCRFunc = func(ctx context.Context, name string, pcr int, data []byte) error {
			if name != "test-vtpm" {
				t.Errorf("name = %s, want test-vtpm", name)
			}
			if pcr != 7 {
				t.Errorf("pcr = %d, want 7", pcr)
			}
			return nil
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"name": "test-vtpm",
			"pcr":  float64(7),
			"data": base64.StdEncoding.EncodeToString([]byte("measurement")),
		}

		result, err := registry.ExecuteTool(ctx, "vtpm_extend_pcr", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if success, ok := resultMap["success"].(bool); !ok || !success {
			t.Error("expected success: true")
		}
	})

	t.Run("executeVTPMExtendPCR with invalid data encoding", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"name": "test-vtpm",
			"pcr":  float64(0),
			"data": "not-valid!!!",
		}

		_, err := registry.ExecuteTool(ctx, "vtpm_extend_pcr", args)
		if err == nil {
			t.Error("expected error for invalid base64")
		}
	})

	t.Run("executeVTPMReadPCR success", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.vtpmReadPCRFunc = func(ctx context.Context, name string, pcr int) ([]byte, error) {
			return []byte("pcr-value-here"), nil
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"name": "test-vtpm",
			"pcr":  float64(0),
		}

		result, err := registry.ExecuteTool(ctx, "vtpm_read_pcr", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if _, ok := resultMap["value"]; !ok {
			t.Error("expected 'value' key in result")
		}
	})

	t.Run("executeVTPMDelete error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.vtpmDeleteFunc = func(ctx context.Context, name string) error {
			return ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "vtpm_delete", map[string]interface{}{"name": "test"})
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeVTPMList error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.vtpmListFunc = func(ctx context.Context, opts *vtpm.ListOptions) ([]interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "vtpm_list", nil)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeVTPMStart error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.vtpmStartFunc = func(ctx context.Context, name string) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "vtpm_start", map[string]interface{}{"name": "test"})
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeVTPMStop error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.vtpmStopFunc = func(ctx context.Context, name string) error {
			return ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "vtpm_stop", map[string]interface{}{"name": "test"})
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("runtime replies name the bundle with the gRPC reply fields", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.vtpmQuoteFunc = func(ctx context.Context, name string, nonce []byte, pcrs []int) (interface{}, error) {
			return &vtpm.QuoteResult{Quote: []byte("q"), Signature: []byte("s"), HashAlgorithm: "SHA256"}, nil
		}
		svc.vtpmSealFunc = func(ctx context.Context, name string, data []byte, pcrs []int, authValue string) ([]byte, error) {
			return []byte("sealed"), nil
		}
		svc.vtpmUnsealFunc = func(ctx context.Context, name string, sealed []byte, authValue string) ([]byte, error) {
			return []byte("plain"), nil
		}
		svc.vtpmReadPCRFunc = func(ctx context.Context, name string, pcr int) ([]byte, error) {
			return []byte("pcr"), nil
		}
		registry := NewToolRegistry(svc, log)
		b64 := base64.StdEncoding.EncodeToString([]byte("x"))

		cases := []struct {
			tool string
			args map[string]interface{}
			want map[string]interface{}
		}{
			{"vtpm_stop", map[string]interface{}{"name": "test-vtpm"},
				map[string]interface{}{"bundle_id": "test-vtpm", "stopped": true}},
			{"vtpm_quote", map[string]interface{}{"name": "test-vtpm", "nonce": b64},
				map[string]interface{}{"bundle_id": "test-vtpm", "hash_algorithm": "SHA256"}},
			{"vtpm_seal", map[string]interface{}{"name": "test-vtpm", "data": b64},
				map[string]interface{}{"bundle_id": "test-vtpm", "sealed_data": base64.StdEncoding.EncodeToString([]byte("sealed"))}},
			{"vtpm_unseal", map[string]interface{}{"name": "test-vtpm", "sealed": b64},
				map[string]interface{}{"bundle_id": "test-vtpm", "data": base64.StdEncoding.EncodeToString([]byte("plain"))}},
			{"vtpm_extend_pcr", map[string]interface{}{"name": "test-vtpm", "pcr": float64(16), "data": b64},
				map[string]interface{}{"bundle_id": "test-vtpm", "pcr_index": 16, "extended": true}},
			{"vtpm_read_pcr", map[string]interface{}{"name": "test-vtpm", "pcr": float64(7)},
				map[string]interface{}{"bundle_id": "test-vtpm", "pcr_index": 7, "value": base64.StdEncoding.EncodeToString([]byte("pcr"))}},
		}
		for _, tc := range cases {
			result, err := registry.ExecuteTool(ctx, tc.tool, tc.args)
			require.NoError(t, err, tc.tool)
			resultMap, ok := result.(map[string]interface{})
			require.True(t, ok, "%s: result is not a map", tc.tool)
			for key, want := range tc.want {
				assert.EqualValues(t, want, resultMap[key], "%s: %s", tc.tool, key)
			}
		}
	})

	t.Run("executeVTPMStart returns the service's start reply", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.vtpmStartFunc = func(ctx context.Context, name string) (interface{}, error) {
			return map[string]interface{}{"bundle_id": name, "running": true, "socket_path": "/run/" + name + ".sock"}, nil
		}
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "vtpm_start", map[string]interface{}{"name": "test-vtpm"})
		require.NoError(t, err)
		resultMap, ok := result.(map[string]interface{})
		require.True(t, ok, "result is not a map")
		assert.Equal(t, "test-vtpm", resultMap["bundle_id"])
		assert.Equal(t, true, resultMap["running"])
		assert.Equal(t, "/run/test-vtpm.sock", resultMap["socket_path"])
	})
}

func TestDNSToolExecution(t *testing.T) {
	ctx := context.Background()
	log := newTestLogger()

	t.Run("executeDNSAddRecord error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.dnsAddRecordFunc = func(ctx context.Context, name, recordType, value string, ttl int) error {
			return ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"name":        "test.example.com",
			"record_type": "A",
			"value":       "192.168.1.1",
		}

		_, err := registry.ExecuteTool(ctx, "dns_add_record", args)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeDNSDeleteRecord error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.dnsDeleteRecordFunc = func(ctx context.Context, name, recordType string) error {
			return ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"name":        "test.example.com",
			"record_type": "A",
		}

		_, err := registry.ExecuteTool(ctx, "dns_delete_record", args)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeDNSGetRecord error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.dnsGetRecordFunc = func(ctx context.Context, name, recordType string) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"name":        "test.example.com",
			"record_type": "A",
		}

		_, err := registry.ExecuteTool(ctx, "dns_get_record", args)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeDNSListRecords error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.dnsListRecordsFunc = func(ctx context.Context, zone string) ([]interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "dns_list_records", map[string]interface{}{"zone": "example.com"})
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeDNSResolve error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.dnsResolveFunc = func(ctx context.Context, name, recordType string) ([]string, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "dns_resolve", map[string]interface{}{"name": "test.example.com"})
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeDNSCreateZone error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.dnsCreateZoneFunc = func(ctx context.Context, zone string) error {
			return ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "dns_create_zone", map[string]interface{}{"zone": "example.com"})
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeDNSDeleteZone error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.dnsDeleteZoneFunc = func(ctx context.Context, zone string) error {
			return ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "dns_delete_zone", map[string]interface{}{"zone": "example.com"})
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeDNSListZones error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.dnsListZonesFunc = func(ctx context.Context) ([]string, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "dns_list_zones", nil)
		if err == nil {
			t.Error("expected error")
		}
	})
}

func TestDeviceToolExecution(t *testing.T) {
	ctx := context.Background()
	log := newTestLogger()

	t.Run("executeDeviceRegister error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.deviceRegisterFunc = func(ctx context.Context, req *DeviceRegisterRequest) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{"serial": "SN-1"}

		_, err := registry.ExecuteTool(ctx, "device_register", args)
		if !errors.Is(err, ErrMockServiceError) {
			t.Errorf("err = %v, want ErrMockServiceError", err)
		}
	})

	t.Run("executeDeviceGet error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.deviceGetFunc = func(ctx context.Context, deviceID string) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "device_get", map[string]interface{}{"device_id": "dev-1"})
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeDeviceList error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.deviceListFunc = func(ctx context.Context, filter map[string]string) ([]interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "device_list", nil)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeDeviceDelete error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.deviceDeleteFunc = func(ctx context.Context, deviceID string) error {
			return ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "device_delete", map[string]interface{}{"device_id": "dev-1"})
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeDeviceUpdate error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.deviceUpdateFunc = func(ctx context.Context, deviceID string, updates map[string]interface{}) error {
			return ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"device_id": "dev-1",
			"model":     "model-updated",
		}

		_, err := registry.ExecuteTool(ctx, "device_update", args)
		if !errors.Is(err, ErrMockServiceError) {
			t.Errorf("err = %v, want ErrMockServiceError", err)
		}
	})

	t.Run("executeDeviceAttest error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.deviceAttestFunc = func(ctx context.Context, deviceID string, evidence []byte) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"device_id": "dev-1",
			"evidence":  base64.StdEncoding.EncodeToString([]byte("evidence")),
		}

		_, err := registry.ExecuteTool(ctx, "device_attest", args)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeDeviceProvision error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.deviceProvisionFunc = func(ctx context.Context, deviceID, profile string) error {
			return ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"device_id": "dev-1",
			"profile":   "default",
		}

		_, err := registry.ExecuteTool(ctx, "device_provision", args)
		if err == nil {
			t.Error("expected error")
		}
	})
}

func TestSDNToolExecution(t *testing.T) {
	ctx := context.Background()
	log := newTestLogger()

	t.Run("executeSDNGetPortState error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.sdnGetPortStateFunc = func(ctx context.Context, bridgeName, portName string) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"bridge_name": "br0",
			"port_name":   "eth0",
		}

		_, err := registry.ExecuteTool(ctx, "sdn_get_port_state", args)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeSDNSetPortState error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.sdnSetPortStateFunc = func(ctx context.Context, bridgeName, portName, state string, rates PortRates) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"bridge_name": "br0",
			"port_name":   "eth0",
			"state":       "up",
		}

		_, err := registry.ExecuteTool(ctx, "sdn_set_port_state", args)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeSDNListBridges error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.sdnListBridgesFunc = func(ctx context.Context) ([]interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "sdn_list_bridges", nil)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeSDNCreateBridge error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.sdnCreateBridgeFunc = func(ctx context.Context, bridgeName string) error {
			return ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "sdn_create_bridge", map[string]interface{}{"bridge_name": "br0"})
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeSDNDeleteBridge error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.sdnDeleteBridgeFunc = func(ctx context.Context, bridgeName string) error {
			return ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "sdn_delete_bridge", map[string]interface{}{"bridge_name": "br0"})
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeSDNAddPort error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.sdnAddPortFunc = func(ctx context.Context, bridgeName, portName, portType string) error {
			return ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"bridge_name": "br0",
			"port_name":   "eth0",
		}

		_, err := registry.ExecuteTool(ctx, "sdn_add_port", args)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeSDNDeletePort error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.sdnDeletePortFunc = func(ctx context.Context, bridgeName, portName string) error {
			return ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"bridge_name": "br0",
			"port_name":   "eth0",
		}

		_, err := registry.ExecuteTool(ctx, "sdn_delete_port", args)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeSDNApplyPolicy error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.sdnApplyPolicyFunc = func(ctx context.Context, policy json.RawMessage) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{"name": "web-acl", "type": "acl"}

		_, err := registry.ExecuteTool(ctx, "sdn_apply_policy", args)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeSDNApplyPolicy forwards the policy document", func(t *testing.T) {
		svc := newMockServiceProvider()
		var got map[string]interface{}
		svc.sdnApplyPolicyFunc = func(ctx context.Context, policy json.RawMessage) (interface{}, error) {
			if err := json.Unmarshal(policy, &got); err != nil {
				return nil, err
			}
			return got, nil
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{"name": "web-acl", "type": "acl", "priority": float64(10)}
		if _, err := registry.ExecuteTool(ctx, "sdn_apply_policy", args); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got["name"] != "web-acl" || got["type"] != "acl" || got["priority"] != float64(10) {
			t.Errorf("forwarded document = %v", got)
		}
	})

	t.Run("executeSDNApplyPolicy rejects arguments that are not JSON", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{"name": "web-acl", "schedule": make(chan int)}
		_, err := registry.ExecuteTool(ctx, "sdn_apply_policy", args)
		var invalid ErrInvalidArgument
		if !errors.As(err, &invalid) {
			t.Errorf("expected ErrInvalidArgument, got %T: %v", err, err)
		}
	})

	t.Run("executeSDNGetPolicy error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.sdnGetPolicyFunc = func(ctx context.Context, policyID string) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "sdn_get_policy", map[string]interface{}{"policy_id": "policy-1"})
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeSDNListPolicies error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.sdnListPoliciesFunc = func(ctx context.Context, policyType, targetID string) ([]interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "sdn_list_policies", nil)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeSDNListPolicies passes the filters", func(t *testing.T) {
		svc := newMockServiceProvider()
		var gotType, gotTarget string
		svc.sdnListPoliciesFunc = func(ctx context.Context, policyType, targetID string) ([]interface{}, error) {
			gotType, gotTarget = policyType, targetID
			return []interface{}{}, nil
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{"type": "acl", "target_id": "eth0"}
		if _, err := registry.ExecuteTool(ctx, "sdn_list_policies", args); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if gotType != "acl" || gotTarget != "eth0" {
			t.Errorf("filters = (%q, %q), want (acl, eth0)", gotType, gotTarget)
		}
	})

	t.Run("executeSDNDeletePolicy deletes the named policy", func(t *testing.T) {
		svc := newMockServiceProvider()
		var deleted string
		svc.sdnDeletePolicyFunc = func(ctx context.Context, policyID string) error {
			deleted = policyID
			return nil
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{"policy_id": "policy-1"}
		if _, err := registry.ExecuteTool(ctx, "sdn_delete_policy", args); err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if deleted != "policy-1" {
			t.Errorf("deleted %q, want policy-1", deleted)
		}
	})

	t.Run("executeSDNDeletePolicy error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.sdnDeletePolicyFunc = func(ctx context.Context, policyID string) error {
			return ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{"policy_id": "policy-1"}
		if _, err := registry.ExecuteTool(ctx, "sdn_delete_policy", args); !errors.Is(err, ErrMockServiceError) {
			t.Errorf("expected ErrMockServiceError, got %v", err)
		}
	})
}

func TestSDNFlowToolExecution(t *testing.T) {
	ctx := context.Background()
	log := newTestLogger()

	t.Run("executeSDNAddFlow error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.sdnAddFlowFunc = func(ctx context.Context, bridgeName string, flow map[string]interface{}) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "sdn_add_flow", map[string]interface{}{"bridge_name": "br0"})
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeSDNDeleteFlow error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.sdnDeleteFlowFunc = func(ctx context.Context, bridgeName, flowID string) error {
			return ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"bridge_name": "br0",
			"flow_id":     "flow-1",
		}

		_, err := registry.ExecuteTool(ctx, "sdn_delete_flow", args)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeSDNListFlows error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.sdnListFlowsFunc = func(ctx context.Context, bridgeName string) ([]interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "sdn_list_flows", map[string]interface{}{"bridge_name": "br0"})
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeSDNFlushFlows error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.sdnFlushFlowsFunc = func(ctx context.Context, bridgeName string) (uint32, error) {
			return 0, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "sdn_flush_flows", map[string]interface{}{"bridge_name": "br0"})
		if err == nil {
			t.Error("expected error")
		}
	})
}

func TestSDNVLANToolExecution(t *testing.T) {
	ctx := context.Background()
	log := newTestLogger()

	t.Run("executeSDNCreateVLAN error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.sdnCreateVLANFunc = func(ctx context.Context, bridgeName string, vlanID int, name string) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"bridge_name": "br0",
			"vlan_id":     float64(100),
		}

		_, err := registry.ExecuteTool(ctx, "sdn_create_vlan", args)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeSDNDeleteVLAN error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.sdnDeleteVLANFunc = func(ctx context.Context, bridgeName string, vlanID int) error {
			return ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"bridge_name": "br0",
			"vlan_id":     float64(100),
		}

		_, err := registry.ExecuteTool(ctx, "sdn_delete_vlan", args)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeSDNListVLANs error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.sdnListVLANsFunc = func(ctx context.Context, bridgeName string) ([]interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "sdn_list_vlans", map[string]interface{}{"bridge_name": "br0"})
		if err == nil {
			t.Error("expected error")
		}
	})
}

func TestSDNStatsToolExecution(t *testing.T) {
	ctx := context.Background()
	log := newTestLogger()

	t.Run("executeSDNGetPortStats error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.sdnGetPortStatsFunc = func(ctx context.Context, bridgeName, portName string) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"bridge_name": "br0",
			"port_name":   "eth0",
		}

		_, err := registry.ExecuteTool(ctx, "sdn_get_port_stats", args)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeSDNGetFlowStats error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.sdnGetFlowStatsFunc = func(ctx context.Context, bridgeName, flowID string) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "sdn_get_flow_stats", map[string]interface{}{"bridge_name": "br0"})
		if err == nil {
			t.Error("expected error")
		}
	})
}

func TestHealthToolExecution(t *testing.T) {
	ctx := context.Background()
	log := newTestLogger()

	t.Run("executeHealth error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.healthFunc = func(ctx context.Context) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "platform_health", nil)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeLiveness error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.livenessFunc = func(ctx context.Context) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "platform_liveness", nil)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeReadiness error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.readinessFunc = func(ctx context.Context) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "platform_readiness", nil)
		if err == nil {
			t.Error("expected error")
		}
	})
}

func TestCAToolExecution(t *testing.T) {
	ctx := context.Background()
	log := newTestLogger()

	t.Run("executeCAInfo success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "ca_info", nil)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("executeCAInfo error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.caInfoFunc = func(ctx context.Context) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "ca_info", nil)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeCAIssue success", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.caIssueFunc = func(ctx context.Context, req *CAIssueRequest) (interface{}, error) {
			if req.CommonName != "test.example.com" {
				t.Errorf("common_name = %s, want test.example.com", req.CommonName)
			}
			if req.ValidDays != 365 {
				t.Errorf("valid_days = %d, want 365 (default)", req.ValidDays)
			}
			return map[string]interface{}{"serial": "abc123"}, nil
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"common_name":  "test.example.com",
			"organization": "Test Org",
			"dns_names":    []interface{}{"test.example.com", "www.example.com"},
		}

		result, err := registry.ExecuteTool(ctx, "ca_issue", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("executeCAIssue error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.caIssueFunc = func(ctx context.Context, req *CAIssueRequest) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"common_name": "test.example.com",
		}

		_, err := registry.ExecuteTool(ctx, "ca_issue", args)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeCAGet success", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.caGetFunc = func(ctx context.Context, serial string, includePEM, includeDER bool) (interface{}, error) {
			if serial != "abc123" {
				t.Errorf("serial = %s, want abc123", serial)
			}
			if !includePEM {
				t.Error("includePEM should be true")
			}
			if !includeDER {
				t.Error("includeDER should be true")
			}
			return map[string]interface{}{"serial": serial}, nil
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"serial":      "abc123",
			"include_pem": true,
			"include_der": true,
		}

		result, err := registry.ExecuteTool(ctx, "ca_get", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("executeCAGet error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.caGetFunc = func(ctx context.Context, serial string, includePEM, includeDER bool) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "ca_get", map[string]interface{}{"serial": "abc123"})
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeCAList success", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.caListFunc = func(ctx context.Context, limit int, cursor string, status string) (interface{}, error) {
			if limit != 50 {
				t.Errorf("limit = %d, want 50 (default)", limit)
			}
			return map[string]interface{}{"certificates": []interface{}{}}, nil
		}
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "ca_list", nil)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("executeCAList error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.caListFunc = func(ctx context.Context, limit int, cursor string, status string) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "ca_list", nil)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeCARevoke success", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.caRevokeFunc = func(ctx context.Context, serial string, reason int, deleteKeys bool) (interface{}, error) {
			if serial != "abc123" {
				t.Errorf("serial = %s, want abc123", serial)
			}
			return map[string]interface{}{"status": "REVOKED"}, nil
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"serial":      "abc123",
			"reason":      float64(1),
			"delete_keys": true,
		}

		result, err := registry.ExecuteTool(ctx, "ca_revoke", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("executeCARevoke error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.caRevokeFunc = func(ctx context.Context, serial string, reason int, deleteKeys bool) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "ca_revoke", map[string]interface{}{"serial": "abc123"})
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeCARenew success", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.caRenewFunc = func(ctx context.Context, serial string, extendDays int, preserveAttrs bool) (interface{}, error) {
			if extendDays != 365 {
				t.Errorf("extendDays = %d, want 365 (default)", extendDays)
			}
			if !preserveAttrs {
				t.Error("preserveAttrs should be true by default")
			}
			return map[string]interface{}{"serial": "new123"}, nil
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"serial": "abc123",
		}

		result, err := registry.ExecuteTool(ctx, "ca_renew", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("executeCARenew error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.caRenewFunc = func(ctx context.Context, serial string, extendDays int, preserveAttrs bool) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "ca_renew", map[string]interface{}{"serial": "abc123"})
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeCAVerify success with PEM", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.caVerifyFunc = func(ctx context.Context, certificatePEM string, certificateDER []byte, checkRevoked bool) (interface{}, error) {
			if certificatePEM == "" {
				t.Error("certificatePEM should not be empty")
			}
			if !checkRevoked {
				t.Error("checkRevoked should be true by default")
			}
			return map[string]interface{}{"valid": true}, nil
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"certificate_pem": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
		}

		result, err := registry.ExecuteTool(ctx, "ca_verify", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("executeCAVerify success with DER", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.caVerifyFunc = func(ctx context.Context, certificatePEM string, certificateDER []byte, checkRevoked bool) (interface{}, error) {
			if len(certificateDER) == 0 {
				t.Error("certificateDER should not be empty")
			}
			return map[string]interface{}{"valid": true}, nil
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"certificate_der": base64.StdEncoding.EncodeToString([]byte("der-data")),
		}

		result, err := registry.ExecuteTool(ctx, "ca_verify", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("executeCAVerify with invalid DER encoding", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"certificate_der": "not-valid-base64!!!",
		}

		_, err := registry.ExecuteTool(ctx, "ca_verify", args)
		if err == nil {
			t.Error("expected error for invalid base64")
		}
	})

	t.Run("executeCAVerify error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.caVerifyFunc = func(ctx context.Context, certificatePEM string, certificateDER []byte, checkRevoked bool) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"certificate_pem": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
		}

		_, err := registry.ExecuteTool(ctx, "ca_verify", args)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeCACRL success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "ca_crl", nil)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("executeCACRL error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.caCRLFunc = func(ctx context.Context) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "ca_crl", nil)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeCABundle success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"store_type": "software",
			"algorithm":  "ECDSA",
		}

		result, err := registry.ExecuteTool(ctx, "ca_bundle", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("executeCABundle error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.caBundleFunc = func(ctx context.Context, storeType string, algorithm string) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "ca_bundle", nil)
		if err == nil {
			t.Error("expected error")
		}
	})
}

func TestIAMToolExecution(t *testing.T) {
	ctx := context.Background()
	log := newTestLogger()

	t.Run("executeIAMCreateUser success", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.iamCreateUserFunc = func(ctx context.Context, req *IAMCreateUserRequest) (interface{}, error) {
			if req.Email != "user@example.com" {
				t.Errorf("email = %s, want user@example.com", req.Email)
			}
			return map[string]interface{}{"id": "user-123"}, nil
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"tenant_id": "tenant-1",
			"email":     "user@example.com",
			"name":      "Test User",
			"roles":     []interface{}{"admin", "user"},
			"groups":    []interface{}{"group1"},
		}

		result, err := registry.ExecuteTool(ctx, "iam_create_user", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("executeIAMCreateUser error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.iamCreateUserFunc = func(ctx context.Context, req *IAMCreateUserRequest) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"tenant_id": "tenant-1",
			"email":     "user@example.com",
		}

		_, err := registry.ExecuteTool(ctx, "iam_create_user", args)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeIAMDeleteUser success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"tenant_id": "tenant-1",
			"user_id":   "user-123",
		}

		result, err := registry.ExecuteTool(ctx, "iam_delete_user", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if success, ok := resultMap["success"].(bool); !ok || !success {
			t.Error("expected success: true")
		}
	})

	t.Run("executeIAMDeleteUser error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.iamDeleteUserFunc = func(ctx context.Context, tenantID, userID string) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"tenant_id": "tenant-1",
			"user_id":   "user-123",
		}

		_, err := registry.ExecuteTool(ctx, "iam_delete_user", args)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeIAMGetUser success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"tenant_id": "tenant-1",
			"user_id":   "user-123",
		}

		result, err := registry.ExecuteTool(ctx, "iam_get_user", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("executeIAMGetUser error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.iamGetUserFunc = func(ctx context.Context, tenantID, userID string) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"tenant_id": "tenant-1",
			"user_id":   "user-123",
		}

		_, err := registry.ExecuteTool(ctx, "iam_get_user", args)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeIAMListUsers success", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.iamListUsersFunc = func(ctx context.Context, req *IAMListUsersRequest) (interface{}, error) {
			want := IAMListUsersRequest{
				TenantID:    "tenant-1",
				Pagination:  IAMPagination{Page: 2, PageSize: 25},
				EmailFilter: "@example.com",
				RoleFilter:  "admin",
				GroupFilter: "ops",
			}
			if *req != want {
				t.Errorf("request = %+v, want %+v", *req, want)
			}
			return map[string]interface{}{"users": []interface{}{}}, nil
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"tenant_id":    "tenant-1",
			"pagination":   map[string]interface{}{"page": 2, "page_size": 25},
			"email_filter": "@example.com",
			"role_filter":  "admin",
			"group_filter": "ops",
		}

		result, err := registry.ExecuteTool(ctx, "iam_list_users", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("executeIAMListUsers negative pagination reads as unset", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.iamListUsersFunc = func(ctx context.Context, req *IAMListUsersRequest) (interface{}, error) {
			if req.Pagination != (IAMPagination{}) {
				t.Errorf("pagination = %+v, want zero so the service applies its defaults", req.Pagination)
			}
			return map[string]interface{}{"users": []interface{}{}}, nil
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"tenant_id":  "tenant-1",
			"pagination": map[string]interface{}{"page": -1, "page_size": -5},
		}
		if _, err := registry.ExecuteTool(ctx, "iam_list_users", args); err != nil {
			t.Errorf("unexpected error: %v", err)
		}
	})

	t.Run("executeIAMListUsers error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.iamListUsersFunc = func(ctx context.Context, req *IAMListUsersRequest) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"tenant_id": "tenant-1",
		}

		_, err := registry.ExecuteTool(ctx, "iam_list_users", args)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeIAMCreateRole success", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.iamCreateRoleFunc = func(ctx context.Context, req *IAMCreateRoleRequest) (interface{}, error) {
			if req.Name != "Admin" {
				t.Errorf("name = %s, want Admin", req.Name)
			}
			return map[string]interface{}{"id": "role-123"}, nil
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"tenant_id":   "tenant-1",
			"id":          "admin",
			"name":        "Admin",
			"description": "Administrator role",
			"permissions": []interface{}{"read", "write", "delete"},
		}

		result, err := registry.ExecuteTool(ctx, "iam_create_role", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("executeIAMCreateRole error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.iamCreateRoleFunc = func(ctx context.Context, req *IAMCreateRoleRequest) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"tenant_id": "tenant-1",
			"name":      "Admin",
		}

		_, err := registry.ExecuteTool(ctx, "iam_create_role", args)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeIAMDeleteRole success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"tenant_id": "tenant-1",
			"role_id":   "role-123",
		}

		result, err := registry.ExecuteTool(ctx, "iam_delete_role", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if success, ok := resultMap["success"].(bool); !ok || !success {
			t.Error("expected success: true")
		}
	})

	t.Run("executeIAMDeleteRole error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.iamDeleteRoleFunc = func(ctx context.Context, tenantID, roleID string) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"tenant_id": "tenant-1",
			"role_id":   "role-123",
		}

		_, err := registry.ExecuteTool(ctx, "iam_delete_role", args)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeIAMGetRole success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"tenant_id": "tenant-1",
			"role_id":   "role-123",
		}

		result, err := registry.ExecuteTool(ctx, "iam_get_role", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("executeIAMGetRole error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.iamGetRoleFunc = func(ctx context.Context, tenantID, roleID string) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"tenant_id": "tenant-1",
			"role_id":   "role-123",
		}

		_, err := registry.ExecuteTool(ctx, "iam_get_role", args)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeIAMListRoles success", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.iamListRolesFunc = func(ctx context.Context, tenantID string, page IAMPagination) (interface{}, error) {
			if page != (IAMPagination{Page: 3, PageSize: 10}) {
				t.Errorf("pagination = %+v, want page 3 of size 10", page)
			}
			return map[string]interface{}{"roles": []interface{}{}}, nil
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"tenant_id":  "tenant-1",
			"pagination": map[string]interface{}{"page": float64(3), "page_size": float64(10)},
		}

		result, err := registry.ExecuteTool(ctx, "iam_list_roles", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("executeIAMListRoles error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.iamListRolesFunc = func(ctx context.Context, tenantID string, page IAMPagination) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"tenant_id": "tenant-1",
		}

		_, err := registry.ExecuteTool(ctx, "iam_list_roles", args)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeIAMAssignRole success", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.iamAssignRoleFunc = func(ctx context.Context, tenantID, userID, roleID string) (interface{}, error) {
			if tenantID != "tenant-1" || userID != "user-123" || roleID != "admin" {
				t.Errorf("assign(%q, %q, %q), want (tenant-1, user-123, admin)", tenantID, userID, roleID)
			}
			return mockIAMSuccess(), nil
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"tenant_id": "tenant-1",
			"user_id":   "user-123",
			"role_id":   "admin",
		}

		result, err := registry.ExecuteTool(ctx, "iam_assign_role", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if success, ok := resultMap["success"].(bool); !ok || !success {
			t.Error("expected success: true")
		}
	})

	t.Run("executeIAMAssignRole error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.iamAssignRoleFunc = func(ctx context.Context, tenantID, userID, roleID string) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"tenant_id": "tenant-1",
			"user_id":   "user-123",
			"role_id":   "admin",
		}

		_, err := registry.ExecuteTool(ctx, "iam_assign_role", args)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeIAMRevokeRole success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"tenant_id": "tenant-1",
			"user_id":   "user-123",
			"role_id":   "admin",
		}

		result, err := registry.ExecuteTool(ctx, "iam_revoke_role", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if success, ok := resultMap["success"].(bool); !ok || !success {
			t.Error("expected success: true")
		}
	})

	t.Run("executeIAMRevokeRole error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.iamRevokeRoleFunc = func(ctx context.Context, tenantID, userID, roleID string) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"tenant_id": "tenant-1",
			"user_id":   "user-123",
			"role_id":   "admin",
		}

		_, err := registry.ExecuteTool(ctx, "iam_revoke_role", args)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeIAMCheckPermission success", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.iamCheckPermissionFunc = func(ctx context.Context, req *IAMCheckPermissionRequest) (interface{}, error) {
			if req.TenantID != "tenant-1" || req.SubjectID != "user-123" ||
				req.Resource != "documents" || req.Action != "read" {
				t.Errorf("request = %+v, want tenant-1/user-123 read documents", *req)
			}
			if len(req.Roles) != 1 || req.Roles[0] != "viewer" || len(req.Groups) != 1 || req.Groups[0] != "ops" {
				t.Errorf("roles/groups = %v/%v, want [viewer]/[ops]", req.Roles, req.Groups)
			}
			if req.Context["ip"] != "10.0.0.1" || req.Attributes["dept"] != "eng" {
				t.Errorf("context/attributes = %v/%v, want ip and dept carried", req.Context, req.Attributes)
			}
			return map[string]interface{}{"allowed": true}, nil
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"tenant_id":  "tenant-1",
			"subject_id": "user-123",
			"roles":      []interface{}{"viewer"},
			"groups":     []interface{}{"ops"},
			"resource":   "documents",
			"action":     "read",
			"context":    map[string]interface{}{"ip": "10.0.0.1"},
			"attributes": map[string]interface{}{"dept": "eng"},
		}

		result, err := registry.ExecuteTool(ctx, "iam_check_permission", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if allowed, ok := resultMap["allowed"].(bool); !ok || !allowed {
			t.Error("expected allowed: true")
		}
	})

	t.Run("executeIAMCheckPermission error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.iamCheckPermissionFunc = func(ctx context.Context, req *IAMCheckPermissionRequest) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"tenant_id":  "tenant-1",
			"subject_id": "user-123",
			"resource":   "documents",
			"action":     "read",
		}

		_, err := registry.ExecuteTool(ctx, "iam_check_permission", args)
		if err == nil {
			t.Error("expected error")
		}
	})

	t.Run("executeIAMAuthenticate success", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.iamAuthenticateFunc = func(ctx context.Context, req *IAMAuthenticateRequest) (interface{}, error) {
			if req.Email != "user@example.com" {
				t.Errorf("email = %s, want user@example.com", req.Email)
			}
			return map[string]interface{}{"authenticated": true}, nil
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"tenant_id": "tenant-1",
			"email":     "user@example.com",
			"password":  "secret123",
		}

		result, err := registry.ExecuteTool(ctx, "iam_authenticate", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("executeIAMAuthenticate error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.iamAuthenticateFunc = func(ctx context.Context, req *IAMAuthenticateRequest) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"tenant_id": "tenant-1",
			"email":     "user@example.com",
			"password":  "wrong",
		}

		_, err := registry.ExecuteTool(ctx, "iam_authenticate", args)
		if err == nil {
			t.Error("expected error")
		}
	})
}

func TestIAMGroupToolExecution(t *testing.T) {
	ctx := context.Background()
	log := newTestLogger()

	t.Run("executeIAMCreateGroup success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"tenant_id":   "tenant-1",
			"id":          "group-123",
			"name":        "Administrators",
			"description": "Admin group",
		}

		result, err := registry.ExecuteTool(ctx, "iam_create_group", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("executeIAMDeleteGroup success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"tenant_id": "tenant-1",
			"group_id":  "group-123",
		}

		result, err := registry.ExecuteTool(ctx, "iam_delete_group", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if success, ok := resultMap["success"].(bool); !ok || !success {
			t.Error("expected success: true")
		}
	})

	t.Run("executeIAMGetGroup success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"tenant_id": "tenant-1",
			"group_id":  "group-123",
		}

		result, err := registry.ExecuteTool(ctx, "iam_get_group", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("executeIAMListGroups success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"tenant_id": "tenant-1",
		}

		result, err := registry.ExecuteTool(ctx, "iam_list_groups", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("executeIAMListGroups with pagination", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.iamListGroupsFunc = func(ctx context.Context, tenantID string, page IAMPagination) (interface{}, error) {
			if tenantID != "tenant-1" || page != (IAMPagination{Page: 4, PageSize: 100}) {
				t.Errorf("list(%q, %+v), want tenant-1 page 4 of size 100", tenantID, page)
			}
			return map[string]interface{}{"groups": []interface{}{}}, nil
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"tenant_id":  "tenant-1",
			"pagination": map[string]interface{}{"page": float64(4), "page_size": float64(100)},
		}

		result, err := registry.ExecuteTool(ctx, "iam_list_groups", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("executeIAMAddGroupMember success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"tenant_id": "tenant-1",
			"group_id":  "group-123",
			"user_id":   "user-456",
		}

		result, err := registry.ExecuteTool(ctx, "iam_add_group_member", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if success, ok := resultMap["success"].(bool); !ok || !success {
			t.Error("expected success: true")
		}
	})

	t.Run("executeIAMRemoveGroupMember success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"tenant_id": "tenant-1",
			"group_id":  "group-123",
			"user_id":   "user-456",
		}

		result, err := registry.ExecuteTool(ctx, "iam_remove_group_member", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if success, ok := resultMap["success"].(bool); !ok || !success {
			t.Error("expected success: true")
		}
	})
}

func TestIAMTenantToolExecution(t *testing.T) {
	ctx := context.Background()
	log := newTestLogger()

	t.Run("executeIAMCreateTenant success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"id":   "tenant-123",
			"name": "Test Tenant",
		}

		result, err := registry.ExecuteTool(ctx, "iam_create_tenant", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("executeIAMCreateTenant with settings", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.iamCreateTenantFunc = func(ctx context.Context, req *IAMCreateTenantRequest) (interface{}, error) {
			if req.Settings == nil || req.Settings.MaxUsers != 100 || !req.Settings.MFARequired {
				t.Errorf("settings = %+v, want max_users 100 and mfa_required", req.Settings)
			}
			return map[string]interface{}{"id": req.ID}, nil
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"id":       "tenant-123",
			"name":     "Test Tenant",
			"settings": map[string]interface{}{"max_users": float64(100), "mfa_required": true},
		}

		result, err := registry.ExecuteTool(ctx, "iam_create_tenant", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("executeIAMDeleteTenant success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"tenant_id": "tenant-123",
		}

		result, err := registry.ExecuteTool(ctx, "iam_delete_tenant", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result is not a map")
		}
		if success, ok := resultMap["success"].(bool); !ok || !success {
			t.Error("expected success: true")
		}
	})

	t.Run("executeIAMGetTenant success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"tenant_id": "tenant-123",
		}

		result, err := registry.ExecuteTool(ctx, "iam_get_tenant", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("executeIAMListTenants success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "iam_list_tenants", nil)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("executeIAMListTenants with pagination", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.iamListTenantsFunc = func(ctx context.Context, page IAMPagination) (interface{}, error) {
			if page != (IAMPagination{Page: 5, PageSize: 25}) {
				t.Errorf("pagination = %+v, want page 5 of size 25", page)
			}
			return map[string]interface{}{"tenants": []interface{}{}}, nil
		}
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"pagination": map[string]interface{}{"page": float64(5), "page_size": float64(25)},
		}

		result, err := registry.ExecuteTool(ctx, "iam_list_tenants", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})
}

func TestIAMTokenToolExecution(t *testing.T) {
	ctx := context.Background()
	log := newTestLogger()

	// The token tools refuse issuance and revocation on every transport; the
	// tool must surface that refusal, never a token or a "success".
	refusals := []struct {
		name string
		tool string
		args map[string]interface{}
	}{
		{
			name: "executeIAMCreateToken refuses",
			tool: "iam_create_token",
			args: map[string]interface{}{
				"tenant_id":   "tenant-1",
				"user_id":     "user-123",
				"scopes":      []interface{}{"read", "write"},
				"description": "API access token",
			},
		},
		{
			name: "executeIAMCreateToken with expires_in refuses",
			tool: "iam_create_token",
			args: map[string]interface{}{
				"tenant_id":  "tenant-1",
				"user_id":    "user-123",
				"scopes":     []interface{}{"read"},
				"expires_in": float64(7200),
			},
		},
		{
			name: "executeIAMRevokeToken refuses",
			tool: "iam_revoke_token",
			args: map[string]interface{}{"token_id": "token-123"},
		},
	}
	for _, tc := range refusals {
		t.Run(tc.name, func(t *testing.T) {
			registry := NewToolRegistry(newMockServiceProvider(), log)

			result, err := registry.ExecuteTool(ctx, tc.tool, tc.args)
			var refused errMockTokenRefused
			if !errors.As(err, &refused) {
				t.Fatalf("expected the token refusal, got %v", err)
			}
			if result != nil {
				t.Errorf("a refused %s must return no result, got %v", tc.tool, result)
			}
		})
	}

	t.Run("executeIAMVerifyToken passes a rejection through", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.iamVerifyTokenFunc = func(ctx context.Context, token string) (interface{}, error) {
			if token != "header.payload.signature" {
				t.Errorf("tool passed token %q, want the caller's token", token)
			}
			return map[string]interface{}{"valid": false, "reason": "expired"}, nil
		}
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "iam_verify_token",
			map[string]interface{}{"token": "header.payload.signature"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatalf("result is %T, want a map", result)
		}
		if valid, ok := resultMap["valid"].(bool); !ok || valid {
			t.Errorf("valid = %v, want an explicit false", resultMap["valid"])
		}
		if resultMap["reason"] != "expired" {
			t.Errorf("reason = %v, want expired", resultMap["reason"])
		}
	})

	t.Run("executeIAMVerifyToken passes valid claims through", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.iamVerifyTokenFunc = func(ctx context.Context, token string) (interface{}, error) {
			return map[string]interface{}{
				"valid":      true,
				"user_id":    "user-123",
				"tenant_id":  "tenant-1",
				"scopes":     []string{"iam:read"},
				"expires_at": int64(1767225600),
			}, nil
		}
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "iam_verify_token",
			map[string]interface{}{"token": "header.payload.signature"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatalf("result is %T, want a map", result)
		}
		if resultMap["valid"] != true {
			t.Errorf("valid = %v, want true", resultMap["valid"])
		}
		if resultMap["user_id"] != "user-123" || resultMap["tenant_id"] != "tenant-1" {
			t.Errorf("claims = %v, want user-123 in tenant-1", resultMap)
		}
		if resultMap["expires_at"] != float64(1767225600) {
			t.Errorf("expires_at = %v, want 1767225600", resultMap["expires_at"])
		}
		if _, echoed := resultMap["token"]; echoed {
			t.Error("the result must never echo the token")
		}
	})
}

func TestKMSToolExecution(t *testing.T) {
	ctx := context.Background()
	log := newTestLogger()

	t.Run("executeKMSGenerateDataKey success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"key_id":    "kek-123",
			"algorithm": "aes-256-gcm",
			"context":   "encryption-context",
		}

		result, err := registry.ExecuteTool(ctx, "kms_generate_data_key", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("executeKMSGenerateDataKey missing key_id", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"algorithm": "aes-256-gcm",
		}

		_, err := registry.ExecuteTool(ctx, "kms_generate_data_key", args)
		if err == nil {
			t.Error("expected error for missing key_id")
		}
	})

	t.Run("executeKMSGenerateWrappedDataKey success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"key_id":    "kek-123",
			"algorithm": "aes-256-gcm",
		}

		result, err := registry.ExecuteTool(ctx, "kms_generate_wrapped_data_key", args)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		if result == nil {
			t.Error("result should not be nil")
		}
	})

	t.Run("executeKMSGenerateWrappedDataKey missing key_id", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		args := map[string]interface{}{
			"algorithm": "aes-256-gcm",
		}

		_, err := registry.ExecuteTool(ctx, "kms_generate_wrapped_data_key", args)
		if err == nil {
			t.Error("expected error for missing key_id")
		}
	})
}

func TestAdditionalHelperFunctions(t *testing.T) {
	t.Run("getStringSlice with valid slice", func(t *testing.T) {
		args := map[string]interface{}{
			"items": []interface{}{"a", "b", "c"},
		}
		result := getStringSlice(args, "items")
		if len(result) != 3 {
			t.Errorf("len(result) = %d, want 3", len(result))
		}
		if result[0] != "a" || result[1] != "b" || result[2] != "c" {
			t.Errorf("result = %v, want [a b c]", result)
		}
	})

	t.Run("getStringSlice with mixed types", func(t *testing.T) {
		args := map[string]interface{}{
			"items": []interface{}{"a", 123, "c"},
		}
		result := getStringSlice(args, "items")
		// Only strings should be included
		if len(result) != 2 {
			t.Errorf("len(result) = %d, want 2", len(result))
		}
	})

	t.Run("getStringSlice with missing key", func(t *testing.T) {
		args := map[string]interface{}{}
		result := getStringSlice(args, "items")
		if result != nil {
			t.Errorf("result = %v, want nil", result)
		}
	})

	t.Run("getStringSlice with wrong type", func(t *testing.T) {
		args := map[string]interface{}{
			"items": "not-a-slice",
		}
		result := getStringSlice(args, "items")
		if result != nil {
			t.Errorf("result = %v, want nil", result)
		}
	})

	t.Run("getBool with true", func(t *testing.T) {
		args := map[string]interface{}{
			"flag": true,
		}
		result := getBool(args, "flag")
		if !result {
			t.Error("result should be true")
		}
	})

	t.Run("getBool with false", func(t *testing.T) {
		args := map[string]interface{}{
			"flag": false,
		}
		result := getBool(args, "flag")
		if result {
			t.Error("result should be false")
		}
	})

	t.Run("getBool with missing key", func(t *testing.T) {
		args := map[string]interface{}{}
		result := getBool(args, "flag")
		if result {
			t.Error("result should be false for missing key")
		}
	})

	t.Run("getBool with wrong type", func(t *testing.T) {
		args := map[string]interface{}{
			"flag": "true",
		}
		result := getBool(args, "flag")
		if result {
			t.Error("result should be false for wrong type")
		}
	})

	t.Run("getInt64 with float64", func(t *testing.T) {
		args := map[string]interface{}{
			"value": float64(12345),
		}
		result := getInt64(args, "value")
		if result != 12345 {
			t.Errorf("result = %d, want 12345", result)
		}
	})

	t.Run("getInt64 with int", func(t *testing.T) {
		args := map[string]interface{}{
			"value": int(54321),
		}
		result := getInt64(args, "value")
		if result != 54321 {
			t.Errorf("result = %d, want 54321", result)
		}
	})

	t.Run("getInt64 with int64", func(t *testing.T) {
		args := map[string]interface{}{
			"value": int64(9876543210),
		}
		result := getInt64(args, "value")
		if result != 9876543210 {
			t.Errorf("result = %d, want 9876543210", result)
		}
	})

	t.Run("getInt64 with missing key", func(t *testing.T) {
		args := map[string]interface{}{}
		result := getInt64(args, "value")
		if result != 0 {
			t.Errorf("result = %d, want 0", result)
		}
	})

	t.Run("getInt64 with wrong type", func(t *testing.T) {
		args := map[string]interface{}{
			"value": "not-a-number",
		}
		result := getInt64(args, "value")
		if result != 0 {
			t.Errorf("result = %d, want 0", result)
		}
	})

	t.Run("getIntSlice with int64 values", func(t *testing.T) {
		args := map[string]interface{}{
			"values": []interface{}{int64(1), int64(2), int64(3)},
		}
		result := getIntSlice(args, "values")
		if len(result) != 3 {
			t.Errorf("len(result) = %d, want 3", len(result))
		}
		if result[0] != 1 || result[1] != 2 || result[2] != 3 {
			t.Errorf("result = %v, want [1 2 3]", result)
		}
	})

	t.Run("getIntSlice with int values", func(t *testing.T) {
		args := map[string]interface{}{
			"values": []interface{}{int(4), int(5), int(6)},
		}
		result := getIntSlice(args, "values")
		if len(result) != 3 {
			t.Errorf("len(result) = %d, want 3", len(result))
		}
		if result[0] != 4 || result[1] != 5 || result[2] != 6 {
			t.Errorf("result = %v, want [4 5 6]", result)
		}
	})
}
