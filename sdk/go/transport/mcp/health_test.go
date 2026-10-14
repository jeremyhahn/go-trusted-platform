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
	"errors"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestHealthProbeTools(t *testing.T) {
	for method, tool := range map[string]string{
		platformv1.PlatformDaemon_GetHealth_FullMethodName: "platform_health",
		platformv1.PlatformDaemon_Liveness_FullMethodName:  "platform_liveness",
		platformv1.PlatformDaemon_Readiness_FullMethodName: "platform_readiness",
	} {
		assert.Equal(t, tool, MethodTools()[method], method)
		assert.Contains(t, mcpReplyDecoders, method)
	}
}

// The probe tools answer in the protojson platformd's REST probes send; the
// decoded tool result arrives as a JSON map.
func TestHealthProbeReplies_DecodeAsTheRPCMessage(t *testing.T) {
	stamp := "2026-10-14T01:02:03Z"

	var ready platformv1.ReadinessResponse
	err := mcpReplyDecoders[platformv1.PlatformDaemon_Readiness_FullMethodName](
		map[string]interface{}{"ready": false, "status": "HEALTH_STATUS_UNHEALTHY", "timestamp": stamp}, &ready)
	require.NoError(t, err)
	assert.False(t, ready.GetReady())
	assert.Equal(t, platformv1.HealthStatus_HEALTH_STATUS_UNHEALTHY, ready.GetStatus())
	assert.Equal(t, int64(1791939723), ready.GetTimestamp().GetSeconds())

	var live platformv1.LivenessResponse
	err = mcpReplyDecoders[platformv1.PlatformDaemon_Liveness_FullMethodName](
		map[string]interface{}{"alive": true, "timestamp": stamp}, &live)
	require.NoError(t, err)
	assert.True(t, live.GetAlive())

	var summary platformv1.GetHealthResponse
	err = mcpReplyDecoders[platformv1.PlatformDaemon_GetHealth_FullMethodName](
		map[string]interface{}{"status": "HEALTH_STATUS_DEGRADED", "components": []interface{}{}, "timestamp": stamp}, &summary)
	require.NoError(t, err)
	assert.Equal(t, platformv1.HealthStatus_HEALTH_STATUS_DEGRADED, summary.GetStatus())
	assert.Empty(t, summary.GetComponents())
}

// A probe answer that is not the rpc's message is refused, not half-read.
func TestHealthProbeReplies_RefuseAMalformedAnswer(t *testing.T) {
	var live platformv1.LivenessResponse
	err := mcpReplyDecoders[platformv1.PlatformDaemon_Liveness_FullMethodName](
		map[string]interface{}{"alive": true, "timestamp": "yesterday"}, &live)

	var unmarshal ErrUnmarshalFailed
	assert.True(t, errors.As(err, &unmarshal), "error = %v", err)
}
