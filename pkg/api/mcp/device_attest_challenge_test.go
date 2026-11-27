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
	"encoding/base64"
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

func TestExecuteDeviceAttest_PassesTheChallengeID(t *testing.T) {
	ctx := context.Background()
	log := logging.DefaultLogger()
	evidence := []byte(`{"quote":"x"}`)

	run := func(t *testing.T, args map[string]interface{}) (string, []byte, string) {
		t.Helper()
		svc := newMockServiceProvider()
		var gotID, gotChallenge string
		var gotEvidence []byte
		svc.deviceAttestFunc = func(_ context.Context, deviceID string, ev []byte, challengeID string) (interface{}, error) {
			gotID, gotEvidence, gotChallenge = deviceID, ev, challengeID
			return map[string]interface{}{"verified": true}, nil
		}
		registry := NewToolRegistry(svc, log)
		if _, err := registry.ExecuteTool(ctx, "device_attest", args); err != nil {
			t.Fatalf("ExecuteTool: %v", err)
		}
		return gotID, gotEvidence, gotChallenge
	}

	t.Run("challenge_id reaches the provider with the device id and the decoded evidence", func(t *testing.T) {
		id, ev, challenge := run(t, map[string]interface{}{
			"device_id":    "42",
			"evidence":     base64.StdEncoding.EncodeToString(evidence),
			"challenge_id": "c-1",
		})
		if id != "42" || string(ev) != string(evidence) || challenge != "c-1" {
			t.Fatalf("provider got (%q, %q, %q), want (\"42\", %q, \"c-1\")", id, ev, challenge, evidence)
		}
	})

	t.Run("without challenge_id the provider receives an empty challenge id", func(t *testing.T) {
		_, _, challenge := run(t, map[string]interface{}{
			"device_id": "42",
			"evidence":  base64.StdEncoding.EncodeToString(evidence),
		})
		if challenge != "" {
			t.Fatalf("challenge id = %q, want empty", challenge)
		}
	})
}

func TestDeviceAttestTool_TakesAnOptionalChallengeID(t *testing.T) {
	registry := NewToolRegistry(newMockServiceProvider(), logging.DefaultLogger())
	var def *mcpwire.ToolDefinition
	for _, tool := range registry.ListTools() {
		if tool.Name == "device_attest" {
			d := tool
			def = &d
		}
	}
	if def == nil {
		t.Fatal("device_attest is not registered")
	}
	props, _ := def.InputSchema["properties"].(map[string]interface{})
	if _, ok := props["challenge_id"]; !ok {
		t.Fatal("challenge_id is missing from the device_attest schema")
	}
	var required []string
	switch req := def.InputSchema["required"].(type) {
	case []string:
		required = req
	case []interface{}:
		for _, name := range req {
			s, _ := name.(string)
			required = append(required, s)
		}
	}
	if len(required) != 2 || !attestRequiredHas(required, "device_id") || !attestRequiredHas(required, "evidence") {
		t.Fatalf("required = %#v, want only device_id and evidence: challenge_id stays optional", required)
	}
}

func attestRequiredHas(list []string, want string) bool {
	for _, s := range list {
		if s == want {
			return true
		}
	}
	return false
}
