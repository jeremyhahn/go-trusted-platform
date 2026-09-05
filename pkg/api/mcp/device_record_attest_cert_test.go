// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

func TestExecuteDeviceRecordAttestCert(t *testing.T) {
	ctx := context.Background()
	log := logging.DefaultLogger()

	t.Run("passes device_id and reissue through and returns the provider result", func(t *testing.T) {
		svc := newMockServiceProvider()
		var gotID string
		var gotReissue bool
		svc.deviceRecordAttestCertFunc = func(_ context.Context, deviceID string, reissue bool) (interface{}, error) {
			gotID, gotReissue = deviceID, reissue
			return map[string]interface{}{"device_id": deviceID, "changed": true, "source": "ca"}, nil
		}
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "device_record_attest_cert", map[string]interface{}{
			"device_id": "42",
			"reissue":   true,
		})
		if err != nil {
			t.Fatalf("ExecuteTool: %v", err)
		}
		if gotID != "42" || !gotReissue {
			t.Fatalf("provider got (%q, %t), want (\"42\", true)", gotID, gotReissue)
		}
		out, ok := result.(map[string]interface{})
		if !ok || out["source"] != "ca" || out["changed"] != true {
			t.Fatalf("unexpected result %#v", result)
		}
	})

	t.Run("reissue defaults to false", func(t *testing.T) {
		svc := newMockServiceProvider()
		gotReissue := true
		svc.deviceRecordAttestCertFunc = func(_ context.Context, _ string, reissue bool) (interface{}, error) {
			gotReissue = reissue
			return map[string]interface{}{}, nil
		}
		registry := NewToolRegistry(svc, log)
		if _, err := registry.ExecuteTool(ctx, "device_record_attest_cert", map[string]interface{}{"device_id": "42"}); err != nil {
			t.Fatalf("ExecuteTool: %v", err)
		}
		if gotReissue {
			t.Fatal("reissue must default to false: re-issuance asks the CA to sign")
		}
	})

	t.Run("missing device_id is refused before the provider", func(t *testing.T) {
		svc := newMockServiceProvider()
		called := false
		svc.deviceRecordAttestCertFunc = func(context.Context, string, bool) (interface{}, error) {
			called = true
			return nil, nil
		}
		registry := NewToolRegistry(svc, log)
		_, err := registry.ExecuteTool(ctx, "device_record_attest_cert", map[string]interface{}{"reissue": true})
		if !errors.Is(err, ErrDeviceIDRequired) {
			t.Fatalf("want ErrDeviceIDRequired, got %v", err)
		}
		if called {
			t.Fatal("the provider must not be called without a device id")
		}
	})

	t.Run("provider refusal is returned as-is", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.deviceRecordAttestCertFunc = func(context.Context, string, bool) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)
		_, err := registry.ExecuteTool(ctx, "device_record_attest_cert", map[string]interface{}{"device_id": "42"})
		if !errors.Is(err, ErrMockServiceError) {
			t.Fatalf("want the provider error, got %v", err)
		}
	})
}

func TestDeviceRecordAttestCertTool_IsRegisteredAsAWrite(t *testing.T) {
	registry := NewToolRegistry(newMockServiceProvider(), logging.DefaultLogger())
	var def *ToolDefinition
	for _, tool := range registry.ListTools() {
		if tool.Name == "device_record_attest_cert" {
			d := tool
			def = &d
		}
	}
	if def == nil {
		t.Fatal("device_record_attest_cert is not registered")
	}
	props, _ := def.InputSchema["properties"].(map[string]interface{})
	if _, ok := props["device_id"]; !ok {
		t.Fatal("device_id is missing from the schema")
	}
	if _, ok := props["reissue"]; !ok {
		t.Fatal("reissue is missing from the schema")
	}

	authz := NewAuthorizationChecker(nil, nil)
	if perm := authz.toolPermissions["device_record_attest_cert"]; perm != "device:write" {
		t.Fatalf("permission = %q, want device:write: recording rewrites the device's trust anchor", perm)
	}
}
