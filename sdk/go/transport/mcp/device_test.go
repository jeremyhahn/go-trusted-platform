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
	"errors"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestDeviceMCP_DeleteDevice_SendsDeviceIDString pins DeleteDevice to the
// registered device_delete tool with the device as a decimal "device_id".
func TestDeviceMCP_DeleteDevice_SendsDeviceIDString(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"device_delete": map[string]interface{}{"success": true},
	}, &calls)

	err := a.Connection().Invoke(context.Background(),
		platformv1.DeviceService_DeleteDevice_FullMethodName,
		&platformv1.DeleteDeviceRequest{Id: 18446744073709551615},
		&platformv1.DeleteDeviceResponse{})
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if len(calls) != 1 || calls[0].Name != "device_delete" {
		t.Fatalf("calls = %+v, want one device_delete call", calls)
	}
	if got := calls[0].Arguments["device_id"]; got != "18446744073709551615" {
		t.Errorf("device_id = %v, want the uint64 as a decimal string", got)
	}
	if _, has := calls[0].Arguments["id"]; has {
		t.Errorf("args = %v, carry the pb id key the tool ignores", calls[0].Arguments)
	}
}

// TestDeviceMCP_GetDevice_SendsDeviceIDString pins GetDevice's arguments to
// the device_get tool's "device_id".
func TestDeviceMCP_GetDevice_SendsDeviceIDString(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"device_get": map[string]interface{}{},
	}, &calls)

	err := a.Connection().Invoke(context.Background(),
		platformv1.DeviceService_GetDevice_FullMethodName,
		&platformv1.GetDeviceRequest{Id: 9},
		&platformv1.GetDeviceResponse{})
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if len(calls) != 1 || calls[0].Name != "device_get" || calls[0].Arguments["device_id"] != "9" {
		t.Fatalf("calls = %+v, want device_get with device_id 9", calls)
	}
}

// TestDeviceMCP_Lifecycle_CallsTheTransitionTools proves DisableDevice and
// EnableDevice reach the device_disable and device_enable tools with the
// argument names the server reads, and that the reply decodes.
func TestDeviceMCP_Lifecycle_CallsTheTransitionTools(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		// The server returns the pb response, so device_id is a JSON number.
		"device_disable": map[string]interface{}{"device_id": 42, "state": "suspended"},
		"device_enable":  map[string]interface{}{"device_id": 42, "state": "quarantined", "reattestation_requested": true},
	}, &calls)

	disabled := &platformv1.DeviceLifecycleResponse{}
	err := a.Connection().Invoke(context.Background(),
		platformv1.DeviceService_DisableDevice_FullMethodName,
		&platformv1.DisableDeviceRequest{DeviceId: "42", Reason: "rma pending"},
		disabled)
	if err != nil {
		t.Fatalf("Invoke disable: %v", err)
	}
	enabled := &platformv1.DeviceLifecycleResponse{}
	err = a.Connection().Invoke(context.Background(),
		platformv1.DeviceService_EnableDevice_FullMethodName,
		&platformv1.EnableDeviceRequest{DeviceId: "42"},
		enabled)
	if err != nil {
		t.Fatalf("Invoke enable: %v", err)
	}

	if len(calls) != 2 || calls[0].Name != "device_disable" || calls[1].Name != "device_enable" {
		t.Fatalf("calls = %+v, want device_disable then device_enable", calls)
	}
	if calls[0].Arguments["device_id"] != "42" || calls[0].Arguments["reason"] != "rma pending" {
		t.Errorf("disable args = %v, want device_id 42 and the reason", calls[0].Arguments)
	}
	if calls[1].Arguments["device_id"] != "42" {
		t.Errorf("enable args = %v, want device_id 42", calls[1].Arguments)
	}
	if disabled.GetState() != "suspended" || enabled.GetState() != "quarantined" || !enabled.GetReattestationRequested() {
		t.Errorf("replies = %+v / %+v, want suspended then quarantined with re-attestation", disabled, enabled)
	}
}

func TestDeviceMCP_ArgBuilders_RejectWrongRequestType(t *testing.T) {
	builders := map[string]mcpArgBuilder{
		platformv1.DeviceService_GetDevice_FullMethodName:    buildDeviceGetArgs,
		platformv1.DeviceService_DeleteDevice_FullMethodName: buildDeviceDeleteArgs,
	}
	for method, build := range builders {
		_, err := build(&platformv1.ListDevicesRequest{})
		var wrongType ErrUnexpectedArgsType
		if !errors.As(err, &wrongType) || wrongType.Method != method {
			t.Errorf("%s: err = %v, want ErrUnexpectedArgsType for the method", method, err)
		}
	}
}
