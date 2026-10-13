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

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

type lifecycleReply struct {
	DeviceID string `json:"device_id"`
	State    string `json:"state"`
}

func TestExecuteDeviceDisable(t *testing.T) {
	svc := newMockServiceProvider()
	var gotID, gotReason string
	svc.deviceDisableFunc = func(_ context.Context, deviceID, reason string) (interface{}, error) {
		gotID, gotReason = deviceID, reason
		return lifecycleReply{DeviceID: deviceID, State: "suspended"}, nil
	}
	registry := NewToolRegistry(svc, logging.DefaultLogger())

	result, err := registry.ExecuteTool(context.Background(), "device_disable",
		map[string]interface{}{"device_id": "42", "reason": "rma pending"})
	require.NoError(t, err)

	assert.Equal(t, "42", gotID)
	assert.Equal(t, "rma pending", gotReason)
	reply, ok := result.(map[string]interface{})
	require.True(t, ok, "the reply is the JSON object form: %T", result)
	assert.Equal(t, "suspended", reply["state"])
}

func TestExecuteDeviceEnable(t *testing.T) {
	svc := newMockServiceProvider()
	var gotID string
	svc.deviceEnableFunc = func(_ context.Context, deviceID string) (interface{}, error) {
		gotID = deviceID
		return lifecycleReply{DeviceID: deviceID, State: "quarantined"}, nil
	}
	registry := NewToolRegistry(svc, logging.DefaultLogger())

	result, err := registry.ExecuteTool(context.Background(), "device_enable",
		map[string]interface{}{"device_id": "42"})
	require.NoError(t, err)

	assert.Equal(t, "42", gotID)
	reply, ok := result.(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "quarantined", reply["state"])
}

func TestExecuteDeviceLifecycle_Errors(t *testing.T) {
	svc := newMockServiceProvider()
	called := false
	svc.deviceDisableFunc = func(context.Context, string, string) (interface{}, error) {
		called = true
		return nil, ErrMockServiceError
	}
	svc.deviceEnableFunc = func(context.Context, string) (interface{}, error) {
		called = true
		return nil, ErrMockServiceError
	}
	registry := NewToolRegistry(svc, logging.DefaultLogger())
	ctx := context.Background()

	for _, tool := range []string{"device_disable", "device_enable"} {
		called = false
		_, err := registry.ExecuteTool(ctx, tool, map[string]interface{}{})
		assert.True(t, errors.Is(err, ErrDeviceIDRequired), "%s without device_id: %v", tool, err)
		assert.False(t, called, "%s: a missing id never reaches the service", tool)

		_, err = registry.ExecuteTool(ctx, tool, map[string]interface{}{"device_id": "42"})
		assert.True(t, errors.Is(err, ErrMockServiceError), "%s propagates the service refusal: %v", tool, err)
	}
}
