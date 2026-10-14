// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.
package mcp

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// TestExecuteDeviceRegister_MapsArgumentsByName is the #533 regression for
// the argument mapping: device_register once read name and device_type and
// stored them as the model and the serial, so the serial a caller sent was
// dropped. Every argument must reach the request under its own name.
func TestExecuteDeviceRegister_MapsArgumentsByName(t *testing.T) {
	mock := newMockServiceProvider()
	var got *DeviceRegisterRequest
	mock.deviceRegisterFunc = func(ctx context.Context, req *DeviceRegisterRequest) (interface{}, error) {
		got = req
		return map[string]interface{}{"id": "7", "serial": req.Serial}, nil
	}
	registry := NewToolRegistry(mock, logging.DefaultLogger())

	_, err := registry.ExecuteTool(context.Background(), "device_register", map[string]interface{}{
		"serial":       "SN-533",
		"model":        "model-533",
		"ek_cert":      "ek-pem",
		"attest_pub":   "ak-pub",
		"attest_cert":  "ak-cert",
		"signing_pub":  "signing-pub",
		"hash_algo_id": float64(11),
	})
	if err != nil {
		t.Fatalf("device_register: %v", err)
	}

	want := DeviceRegisterRequest{
		Serial:     "SN-533",
		Model:      "model-533",
		EKCert:     "ek-pem",
		AttestPub:  "ak-pub",
		AttestCert: "ak-cert",
		SigningPub: "signing-pub",
		HashAlgoID: 11,
	}
	if got == nil || *got != want {
		t.Fatalf("request = %+v, want %+v", got, want)
	}
}

func TestExecuteDeviceRegister_HashAlgoOutOfRange(t *testing.T) {
	mock := newMockServiceProvider()
	mock.deviceRegisterFunc = func(ctx context.Context, req *DeviceRegisterRequest) (interface{}, error) {
		t.Fatal("an out-of-range hash_algo_id reached the service")
		return nil, nil
	}
	registry := NewToolRegistry(mock, logging.DefaultLogger())

	for _, value := range []float64{-1, math.MaxUint32 + 1} {
		t.Run(fmt.Sprint(value), func(t *testing.T) {
			_, err := registry.ExecuteTool(context.Background(), "device_register", map[string]interface{}{
				"serial":       "SN-533",
				"hash_algo_id": value,
			})
			if !errors.Is(err, ErrDeviceHashAlgoInvalid) {
				t.Fatalf("error = %v, want ErrDeviceHashAlgoInvalid", err)
			}
		})
	}
}

func TestExecuteDeviceFindBySerial_ReturnsDevice(t *testing.T) {
	mock := newMockServiceProvider()
	mock.deviceFindBySerialFunc = func(ctx context.Context, serial string) (interface{}, error) {
		return map[string]interface{}{"id": "7", "serial": serial}, nil
	}
	registry := NewToolRegistry(mock, logging.DefaultLogger())

	result, err := registry.ExecuteTool(context.Background(), "device_find_by_serial", map[string]interface{}{
		"serial": "SN-533",
	})
	if err != nil {
		t.Fatalf("device_find_by_serial: %v", err)
	}
	device, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("result is %T, want a map", result)
	}
	if device["serial"] != "SN-533" {
		t.Errorf("serial = %v, want SN-533", device["serial"])
	}
}

func TestExecuteDeviceFindBySerial_Errors(t *testing.T) {
	t.Run("missing serial", func(t *testing.T) {
		registry := NewToolRegistry(newMockServiceProvider(), logging.DefaultLogger())
		_, err := registry.ExecuteTool(context.Background(), "device_find_by_serial", map[string]interface{}{})
		if !errors.Is(err, ErrDeviceSerialRequired) {
			t.Fatalf("error = %v, want ErrDeviceSerialRequired", err)
		}
	})

	t.Run("service error", func(t *testing.T) {
		mock := newMockServiceProvider()
		mock.deviceFindBySerialFunc = func(ctx context.Context, serial string) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(mock, logging.DefaultLogger())
		_, err := registry.ExecuteTool(context.Background(), "device_find_by_serial", map[string]interface{}{
			"serial": "SN-533",
		})
		if !errors.Is(err, ErrMockServiceError) {
			t.Fatalf("error = %v, want ErrMockServiceError", err)
		}
	})
}

// TestExecuteDeviceUpdate_ForwardsFieldsAndReturnsDevice pins the update
// contract the device suite relies on: only the caller-owned model and
// serial are forwarded, and the reply is the stored device, not an
// acknowledgement.
func TestExecuteDeviceUpdate_ForwardsFieldsAndReturnsDevice(t *testing.T) {
	mock := newMockServiceProvider()
	var updates map[string]interface{}
	mock.deviceUpdateFunc = func(ctx context.Context, deviceID string, u map[string]interface{}) error {
		updates = u
		return nil
	}
	mock.deviceGetFunc = func(ctx context.Context, deviceID string) (interface{}, error) {
		return map[string]interface{}{"id": deviceID, "model": "model-new"}, nil
	}
	registry := NewToolRegistry(mock, logging.DefaultLogger())

	result, err := registry.ExecuteTool(context.Background(), "device_update", map[string]interface{}{
		"device_id":  "7",
		"model":      "model-new",
		"attest_pub": "ignored-server-owned",
	})
	if err != nil {
		t.Fatalf("device_update: %v", err)
	}
	if len(updates) != 1 || updates["model"] != "model-new" {
		t.Errorf("updates = %v, want only model", updates)
	}
	device, ok := result.(map[string]interface{})
	if !ok {
		t.Fatalf("result is %T, want a map", result)
	}
	if device["id"] != "7" || device["model"] != "model-new" {
		t.Errorf("result = %v, want the stored device 7", device)
	}
}

func TestExecuteDeviceUpdate_Errors(t *testing.T) {
	t.Run("missing device_id", func(t *testing.T) {
		registry := NewToolRegistry(newMockServiceProvider(), logging.DefaultLogger())
		_, err := registry.ExecuteTool(context.Background(), "device_update", map[string]interface{}{
			"model": "model-new",
		})
		if !errors.Is(err, ErrDeviceIDRequired) {
			t.Fatalf("error = %v, want ErrDeviceIDRequired", err)
		}
	})

	t.Run("read-back error", func(t *testing.T) {
		mock := newMockServiceProvider()
		mock.deviceGetFunc = func(ctx context.Context, deviceID string) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(mock, logging.DefaultLogger())
		_, err := registry.ExecuteTool(context.Background(), "device_update", map[string]interface{}{
			"device_id": "7",
			"model":     "model-new",
		})
		if !errors.Is(err, ErrMockServiceError) {
			t.Fatalf("error = %v, want ErrMockServiceError", err)
		}
	})
}

// knownUndispatched lists tools advertised in tools/list that no executor
// serves yet; each answers "unknown tool". Like knownUnclassified, the list
// may only shrink: a new advertised tool must ship with its executor, and a
// tool that gains one must leave the list.
var knownUndispatched = []string{
	"attestation_attest_workload",
	"attestation_create_policy",
	"attestation_create_report",
	"attestation_delete_policy",
	"attestation_evaluate_policy",
	"attestation_get_policy",
	"attestation_get_report",
	"attestation_list_policies",
	"attestation_list_reports",
	"attestation_verify_workload",
	"dns_reverse_lookup",
	"vm_create",
	"vm_delete",
	"vm_get",
	"vm_list",
	"vm_reboot",
	"vm_resume",
	"vm_start",
	"vm_stop",
	"vm_suspend",
	"vm_update",
	"vtpm_bundle_create",
	"vtpm_bundle_delete",
	"vtpm_bundle_get",
	"vtpm_bundle_list",
	"vtpm_bundle_pcr_extend",
	"vtpm_bundle_pcr_read",
	"vtpm_bundle_quote",
	"vtpm_bundle_seal",
	"vtpm_bundle_unseal",
}

// TestExecuteTool_EveryAdvertisedToolDispatches is the #533 regression for
// tools advertised in tools/list with no executor behind them: seven
// device_* tools answered "unknown tool". Any advertised tool may refuse
// empty arguments, but none outside knownUndispatched may be unknown to its
// own registry.
func TestExecuteTool_EveryAdvertisedToolDispatches(t *testing.T) {
	registry := NewToolRegistry(newMockServiceProvider(), logging.DefaultLogger())

	pending := make(map[string]bool, len(knownUndispatched))
	for _, name := range knownUndispatched {
		pending[name] = true
	}

	for _, tool := range registry.ListTools() {
		err := executeRecovering(registry, tool.Name)
		unknown := err != nil && strings.Contains(err.Error(), "unknown tool: "+tool.Name)
		switch {
		case unknown && !pending[tool.Name]:
			t.Errorf("%s is advertised but has no executor", tool.Name)
		case !unknown && pending[tool.Name]:
			t.Errorf("%s now dispatches; remove it from knownUndispatched", tool.Name)
		}
		delete(pending, tool.Name)
	}
	for name := range pending {
		t.Errorf("%s is no longer advertised; remove it from knownUndispatched", name)
	}
}

func TestExecuteTool_UnadvertisedToolIsUnknown(t *testing.T) {
	registry := NewToolRegistry(newMockServiceProvider(), logging.DefaultLogger())

	err := executeRecovering(registry, "device_create")
	if err == nil || !strings.Contains(err.Error(), "unknown tool: device_create") {
		t.Fatalf("error = %v, want unknown tool: device_create", err)
	}
}

// executeRecovering calls a tool with empty arguments. An executor that
// panics on them has still been dispatched, so the panic counts as reached.
func executeRecovering(registry *ToolRegistry, name string) (err error) {
	defer func() {
		if recover() != nil {
			err = nil
		}
	}()
	_, err = registry.ExecuteTool(context.Background(), name, map[string]interface{}{})
	return err
}
