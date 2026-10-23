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
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	restdevice "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/device"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

func TestExecuteDeviceBootCertificate(t *testing.T) {
	svc := newMockServiceProvider()
	var gotIdentity string
	var gotSignature []byte
	svc.deviceBootCertificateFunc = func(_ context.Context, identity string, signature []byte) (interface{}, error) {
		gotIdentity, gotSignature = identity, signature
		return map[string]interface{}{"identity": identity}, nil
	}
	registry := NewToolRegistry(svc, logging.DefaultLogger())

	result, err := registry.ExecuteTool(context.Background(), "device_boot_certificate", map[string]interface{}{
		"identity":  "node-1.example",
		"signature": base64.StdEncoding.EncodeToString([]byte("sig")),
	})

	require.NoError(t, err)
	assert.Equal(t, "node-1.example", gotIdentity)
	assert.Equal(t, []byte("sig"), gotSignature)
	assert.NotNil(t, result)
}

func TestExecuteDeviceBootCertificate_RejectsMalformedSignature(t *testing.T) {
	svc := newMockServiceProvider()
	called := false
	svc.deviceBootCertificateFunc = func(context.Context, string, []byte) (interface{}, error) {
		called = true
		return nil, nil
	}
	registry := NewToolRegistry(svc, logging.DefaultLogger())

	_, err := registry.ExecuteTool(context.Background(), "device_boot_certificate", map[string]interface{}{
		"identity":  "node-1.example",
		"signature": "!!not base64!!",
	})

	var invalid ErrInvalidArgument
	require.ErrorAs(t, err, &invalid)
	assert.Equal(t, mcpwire.InvalidParams, toolErrorCode(err))
	assert.False(t, called, "the provider must not see an undecodable proof")
}

func TestExecuteDeviceBootDelivery(t *testing.T) {
	svc := newMockServiceProvider()
	var gotEvidence []byte
	svc.deviceBootDeliveryFunc = func(_ context.Context, evidence []byte) (interface{}, error) {
		gotEvidence = evidence
		return map[string]interface{}{"serial": "SN-1"}, nil
	}
	registry := NewToolRegistry(svc, logging.DefaultLogger())

	result, err := registry.ExecuteTool(context.Background(), "device_boot_delivery", map[string]interface{}{
		"evidence": base64.StdEncoding.EncodeToString([]byte("evidence")),
	})

	require.NoError(t, err)
	assert.Equal(t, []byte("evidence"), gotEvidence)
	assert.NotNil(t, result)
}

func TestExecuteDeviceBootDelivery_RejectsMalformedEvidence(t *testing.T) {
	registry := NewToolRegistry(newMockServiceProvider(), logging.DefaultLogger())

	_, err := registry.ExecuteTool(context.Background(), "device_boot_delivery", map[string]interface{}{
		"evidence": "!!not base64!!",
	})

	var invalid ErrInvalidArgument
	require.ErrorAs(t, err, &invalid)
	assert.Equal(t, mcpwire.InvalidParams, toolErrorCode(err))
}

// Both MCP service providers refuse a boot request with ErrBootChannelRequired
// (MCP carries no TLS connection); the tool answers it as FailedPrecondition,
// the class gRPC answers it with, not as an unclassified failure.
func TestExecuteDeviceBoot_ChannelRefusalIsFailedPrecondition(t *testing.T) {
	_, refusal := restdevice.BootChannel(nil, "MCP")
	require.Error(t, refusal)
	svc := newMockServiceProvider()
	svc.deviceBootCertificateFunc = func(context.Context, string, []byte) (interface{}, error) {
		return nil, refusal
	}
	svc.deviceBootDeliveryFunc = func(context.Context, []byte) (interface{}, error) {
		return nil, refusal
	}
	registry := NewToolRegistry(svc, logging.DefaultLogger())
	encoded := base64.StdEncoding.EncodeToString([]byte("proof"))

	for tool, args := range map[string]map[string]interface{}{
		"device_boot_certificate": {"identity": "node-1.example", "signature": encoded},
		"device_boot_delivery":    {"evidence": encoded},
	} {
		t.Run(tool, func(t *testing.T) {
			_, err := registry.ExecuteTool(context.Background(), tool, args)

			require.ErrorIs(t, err, refusal)
			assert.Equal(t, mcpwire.FailedPrecondition, toolErrorCode(err))
		})
	}
}

// A diskless node holds no token, so the two boot tools are explicitly open;
// every other device tool still demands one.
func TestAuthorizeTool_BootToolsAreOpenAndNothingElseIs(t *testing.T) {
	checker := NewAuthorizationChecker(nil, nil)

	for _, tool := range []string{"device_boot_certificate", "device_boot_delivery"} {
		_, authErr := checker.AuthorizeTool(context.Background(), tool, "")
		assert.Nil(t, authErr, tool)
	}

	_, authErr := checker.AuthorizeTool(context.Background(), "device_record_attest_cert", "")
	assert.NotNil(t, authErr)
}
