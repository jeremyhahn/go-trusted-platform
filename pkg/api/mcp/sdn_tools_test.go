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

//go:build iam && codec_msgpack && codec_cbor && codec_json

package mcp

import (
	"testing"
)

// =============================================================================
// SDN Sentinel Error Tests
// =============================================================================

func TestSDNSentinelErrors(t *testing.T) {
	tests := []struct {
		name     string
		err      *SDNError
		expected string
	}{
		{
			name:     "ErrSDNServiceUnavailable",
			err:      ErrSDNServiceUnavailable,
			expected: "SDN_SERVICE_UNAVAILABLE: SDN service is not available",
		},
		{
			name:     "ErrSDNBridgeNameRequired",
			err:      ErrSDNBridgeNameRequired,
			expected: "SDN_BRIDGE_NAME_REQUIRED: bridge name is required",
		},
		{
			name:     "ErrSDNPortNameRequired",
			err:      ErrSDNPortNameRequired,
			expected: "SDN_PORT_NAME_REQUIRED: port name is required",
		},
		{
			name:     "ErrSDNFlowMatchRequired",
			err:      ErrSDNFlowMatchRequired,
			expected: "SDN_FLOW_MATCH_REQUIRED: flow match criteria is required",
		},
		{
			name:     "ErrSDNFlowActionsRequired",
			err:      ErrSDNFlowActionsRequired,
			expected: "SDN_FLOW_ACTIONS_REQUIRED: flow actions are required",
		},
		{
			name:     "ErrSDNFlowIDRequired",
			err:      ErrSDNFlowIDRequired,
			expected: "SDN_FLOW_ID_REQUIRED: flow ID is required",
		},
		{
			name:     "ErrSDNPolicyNameRequired",
			err:      ErrSDNPolicyNameRequired,
			expected: "SDN_POLICY_NAME_REQUIRED: policy name is required",
		},
		{
			name:     "ErrSDNPolicyIDRequired",
			err:      ErrSDNPolicyIDRequired,
			expected: "SDN_POLICY_ID_REQUIRED: policy ID is required",
		},
		{
			name:     "ErrSDNPolicyRulesRequired",
			err:      ErrSDNPolicyRulesRequired,
			expected: "SDN_POLICY_RULES_REQUIRED: policy rules are required",
		},
		{
			name:     "ErrSDNBridgeNotFound",
			err:      ErrSDNBridgeNotFound,
			expected: "SDN_BRIDGE_NOT_FOUND: bridge not found",
		},
		{
			name:     "ErrSDNPortNotFound",
			err:      ErrSDNPortNotFound,
			expected: "SDN_PORT_NOT_FOUND: port not found",
		},
		{
			name:     "ErrSDNFlowNotFound",
			err:      ErrSDNFlowNotFound,
			expected: "SDN_FLOW_NOT_FOUND: flow not found",
		},
		{
			name:     "ErrSDNPolicyNotFound",
			err:      ErrSDNPolicyNotFound,
			expected: "SDN_POLICY_NOT_FOUND: policy not found",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.expected {
				t.Errorf("Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}
