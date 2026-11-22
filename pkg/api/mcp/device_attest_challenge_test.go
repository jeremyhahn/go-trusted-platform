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
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

func TestExecuteDeviceAttestChallenge(t *testing.T) {
	ctx := context.Background()
	log := logging.DefaultLogger()

	t.Run("passes device_id through and returns the provider result", func(t *testing.T) {
		svc := newMockServiceProvider()
		var gotID string
		svc.deviceAttestChallengeFunc = func(_ context.Context, deviceID string) (interface{}, error) {
			gotID = deviceID
			return map[string]interface{}{"challenge_id": "c-1", "nonce": "bm9uY2U="}, nil
		}
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "device_attest_challenge", map[string]interface{}{"device_id": "42"})
		if err != nil {
			t.Fatalf("ExecuteTool: %v", err)
		}
		if gotID != "42" {
			t.Fatalf("provider got %q, want \"42\"", gotID)
		}
		out, ok := result.(map[string]interface{})
		if !ok || out["challenge_id"] != "c-1" || out["nonce"] != "bm9uY2U=" {
			t.Fatalf("unexpected result %#v", result)
		}
	})

	t.Run("a missing device_id is ErrDeviceIDRequired and the provider is not called", func(t *testing.T) {
		svc := newMockServiceProvider()
		called := false
		svc.deviceAttestChallengeFunc = func(context.Context, string) (interface{}, error) {
			called = true
			return nil, nil
		}
		registry := NewToolRegistry(svc, log)
		_, err := registry.ExecuteTool(ctx, "device_attest_challenge", map[string]interface{}{})
		if !errors.Is(err, ErrDeviceIDRequired) {
			t.Fatalf("want ErrDeviceIDRequired, got %v", err)
		}
		if called {
			t.Fatal("the provider must not be called without a device id")
		}
	})

	t.Run("a provider error is returned", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.deviceAttestChallengeFunc = func(context.Context, string) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)
		_, err := registry.ExecuteTool(ctx, "device_attest_challenge", map[string]interface{}{"device_id": "42"})
		if !errors.Is(err, ErrMockServiceError) {
			t.Fatalf("want the provider error, got %v", err)
		}
	})
}

func TestDeviceAttestChallengeTool_IsRegisteredAsAWrite(t *testing.T) {
	registry := NewToolRegistry(newMockServiceProvider(), logging.DefaultLogger())
	var def *mcpwire.ToolDefinition
	for _, tool := range registry.ListTools() {
		if tool.Name == "device_attest_challenge" {
			d := tool
			def = &d
		}
	}
	if def == nil {
		t.Fatal("device_attest_challenge is not registered")
	}
	props, _ := def.InputSchema["properties"].(map[string]interface{})
	if _, ok := props["device_id"]; !ok {
		t.Fatal("device_id is missing from the schema")
	}
	required := false
	switch req := def.InputSchema["required"].(type) {
	case []string:
		for _, name := range req {
			required = required || name == "device_id"
		}
	case []interface{}:
		for _, name := range req {
			required = required || name == "device_id"
		}
	}
	if !required {
		t.Fatalf("device_id must be required, schema required = %#v", def.InputSchema["required"])
	}

	authz := NewAuthorizationChecker(nil, nil)
	if perm := authz.toolPermissions["device_attest_challenge"]; perm != "device:write" {
		t.Fatalf("permission = %q, want device:write: issuing a challenge stores server state for the device", perm)
	}
}
