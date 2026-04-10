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
	"fmt"
)

// =============================================================================
// SDN Error Types
// =============================================================================

// SDNError represents an SDN operation error.
type SDNError struct {
	Code    string
	Message string
}

func (e *SDNError) Error() string {
	return fmt.Sprintf("%s: %s", e.Code, e.Message)
}

// ErrSDNServiceUnavailable indicates the SDN service is not available.
var ErrSDNServiceUnavailable = &SDNError{
	Code:    "SDN_SERVICE_UNAVAILABLE",
	Message: "SDN service is not available",
}

// ErrSDNBridgeNameRequired indicates a bridge name is required.
var ErrSDNBridgeNameRequired = &SDNError{
	Code:    "SDN_BRIDGE_NAME_REQUIRED",
	Message: "bridge name is required",
}

// ErrSDNPortNameRequired indicates a port name is required.
var ErrSDNPortNameRequired = &SDNError{
	Code:    "SDN_PORT_NAME_REQUIRED",
	Message: "port name is required",
}

// ErrSDNFlowMatchRequired indicates a flow match is required.
var ErrSDNFlowMatchRequired = &SDNError{
	Code:    "SDN_FLOW_MATCH_REQUIRED",
	Message: "flow match criteria is required",
}

// ErrSDNFlowActionsRequired indicates flow actions are required.
var ErrSDNFlowActionsRequired = &SDNError{
	Code:    "SDN_FLOW_ACTIONS_REQUIRED",
	Message: "flow actions are required",
}

// ErrSDNFlowIDRequired indicates a flow ID is required.
var ErrSDNFlowIDRequired = &SDNError{
	Code:    "SDN_FLOW_ID_REQUIRED",
	Message: "flow ID is required",
}

// ErrSDNPolicyNameRequired indicates a policy name is required.
var ErrSDNPolicyNameRequired = &SDNError{
	Code:    "SDN_POLICY_NAME_REQUIRED",
	Message: "policy name is required",
}

// ErrSDNPolicyIDRequired indicates a policy ID is required.
var ErrSDNPolicyIDRequired = &SDNError{
	Code:    "SDN_POLICY_ID_REQUIRED",
	Message: "policy ID is required",
}

// ErrSDNPolicyRulesRequired indicates policy rules are required.
var ErrSDNPolicyRulesRequired = &SDNError{
	Code:    "SDN_POLICY_RULES_REQUIRED",
	Message: "policy rules are required",
}

// ErrSDNBridgeNotFound indicates a bridge was not found.
var ErrSDNBridgeNotFound = &SDNError{
	Code:    "SDN_BRIDGE_NOT_FOUND",
	Message: "bridge not found",
}

// ErrSDNPortNotFound indicates a port was not found.
var ErrSDNPortNotFound = &SDNError{
	Code:    "SDN_PORT_NOT_FOUND",
	Message: "port not found",
}

// ErrSDNFlowNotFound indicates a flow was not found.
var ErrSDNFlowNotFound = &SDNError{
	Code:    "SDN_FLOW_NOT_FOUND",
	Message: "flow not found",
}

// ErrSDNPolicyNotFound indicates a policy was not found.
var ErrSDNPolicyNotFound = &SDNError{
	Code:    "SDN_POLICY_NOT_FOUND",
	Message: "policy not found",
}
