//go:build integration

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

// Package sdn provides integration test helpers for SDN services.
// These helpers provide reusable functions for creating test bridges,
// generating test data, and performing assertions in integration tests.
package sdn

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"
)

// =============================================================================
// Environment Variable Constants
// =============================================================================

const (
	// EnvIntegrationTest is the environment variable that must be set to run
	// integration tests. Set INTEGRATION_TEST=1 to enable.
	EnvIntegrationTest = "INTEGRATION_TEST"

	// EnvPlatformdGRPCEndpoint is the environment variable for platformd gRPC endpoint.
	// Default: 127.0.0.1:10443
	EnvPlatformdGRPCEndpoint = "PLATFORMD_GRPC_ENDPOINT"

	// EnvPlatformAPIEndpoint is the environment variable for the platformd REST endpoint.
	// Default: 127.0.0.1:8443
	EnvPlatformAPIEndpoint = "PLATFORM_API_ENDPOINT"

	// EnvPlatformQUICEndpoint is the environment variable for platform QUIC endpoint.
	// Default: 127.0.0.1:9444
	EnvPlatformQUICEndpoint = "PLATFORM_QUIC_ENDPOINT"

	// EnvPlatformMCPEndpoint is the environment variable for platform MCP endpoint.
	// Default: 127.0.0.1:9445
	EnvPlatformMCPEndpoint = "PLATFORM_MCP_ENDPOINT"

	// EnvPlatformdSocket is the environment variable for platformd Unix socket.
	// Default: /run/platformd.sock
	EnvPlatformdSocket = "PLATFORMD_SOCKET"

	// EnvSDNOVSUnavailable is set when OVS is not available during test setup.
	EnvSDNOVSUnavailable = "SDN_OVS_UNAVAILABLE"

	// EnvSDNServiceUnavailable is set when SDN service creation failed.
	EnvSDNServiceUnavailable = "SDN_SERVICE_UNAVAILABLE"

	// EnvSDNOVSConnectionFailed is set when OVS connection failed.
	EnvSDNOVSConnectionFailed = "SDN_OVS_CONNECTION_FAILED"

	// EnvSDNOVSSocket is set to the OVS socket path when OVS is available.
	EnvSDNOVSSocket = "SDN_OVS_SOCKET"
)

// =============================================================================
// Default Endpoints
// =============================================================================

const (
	// DefaultPlatformdGRPCEndpoint is the default platformd gRPC endpoint.
	DefaultPlatformdGRPCEndpoint = "127.0.0.1:10443"

	// DefaultPlatformAPIEndpoint is the default platformd REST endpoint.
	DefaultPlatformAPIEndpoint = "http://127.0.0.1:8443"

	// DefaultPlatformQUICEndpoint is the default platform QUIC endpoint.
	DefaultPlatformQUICEndpoint = "127.0.0.1:9444"

	// DefaultPlatformMCPEndpoint is the default platform MCP endpoint.
	DefaultPlatformMCPEndpoint = "127.0.0.1:9445"

	// DefaultPlatformdSocket is the default platformd Unix socket.
	DefaultPlatformdSocket = "/run/platformd.sock"
)

// =============================================================================
// Skip Helpers
// =============================================================================

// SkipIfNotIntegration skips the test if the INTEGRATION_TEST environment
// variable is not set. This ensures integration tests only run when explicitly
// requested, preventing accidental execution during normal unit testing.
// This is an exported version for use by other test packages.
func SkipIfNotIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv(EnvIntegrationTest) == "" {
		t.Skip("Skipping integration test. Set INTEGRATION_TEST=1 to run.")
	}
}

// SkipIfSDNUnavailable skips the test if the SDN service is not available.
// This checks the environment variables set by setup_test.go to determine
// if SDN tests can run.
func SkipIfSDNUnavailable(t *testing.T) {
	t.Helper()

	if os.Getenv(EnvSDNOVSUnavailable) == "1" {
		t.Skip("Skipping SDN test: OVS not available. Ensure OVS is running in the devcontainer.")
	}

	if os.Getenv(EnvSDNServiceUnavailable) == "1" {
		t.Skip("Skipping SDN test: SDN service creation failed. Check OVS configuration.")
	}

	if os.Getenv(EnvSDNOVSConnectionFailed) == "1" {
		t.Skip("Skipping SDN test: OVS connection failed. Ensure OVS daemon is running.")
	}
}

// IsSDNAvailable returns true if the SDN service is available for testing.
func IsSDNAvailable() bool {
	if os.Getenv(EnvSDNOVSUnavailable) == "1" {
		return false
	}
	if os.Getenv(EnvSDNServiceUnavailable) == "1" {
		return false
	}
	if os.Getenv(EnvSDNOVSConnectionFailed) == "1" {
		return false
	}
	return true
}

// GetOVSSocketPath returns the OVS socket path if available, empty string otherwise.
func GetOVSSocketPath() string {
	return os.Getenv(EnvSDNOVSSocket)
}

// =============================================================================
// Endpoint Configuration
// =============================================================================

// ServiceEndpoints contains all configured service endpoints.
type ServiceEndpoints struct {
	PlatformdGRPC string
	PlatformAPI   string
	PlatformQUIC  string
	PlatformMCP   string
	PlatformdSock string
}

// GetServiceEndpoints returns service endpoints from environment
// variables with sensible defaults.
func GetServiceEndpoints() ServiceEndpoints {
	return ServiceEndpoints{
		PlatformdGRPC: getEnvOrDefault(EnvPlatformdGRPCEndpoint, DefaultPlatformdGRPCEndpoint),
		PlatformAPI:   getEnvOrDefault(EnvPlatformAPIEndpoint, DefaultPlatformAPIEndpoint),
		PlatformQUIC:  getEnvOrDefault(EnvPlatformQUICEndpoint, DefaultPlatformQUICEndpoint),
		PlatformMCP:   getEnvOrDefault(EnvPlatformMCPEndpoint, DefaultPlatformMCPEndpoint),
		PlatformdSock: getEnvOrDefault(EnvPlatformdSocket, DefaultPlatformdSocket),
	}
}

// getEnvOrDefault returns the environment variable value or the default if not set.
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// =============================================================================
// Test Data Generators
// =============================================================================

// GenerateUniqueBridgeName generates a unique bridge name with the given prefix.
// The name includes a timestamp to ensure uniqueness across test runs.
// Format: prefix-YYYYMMDDHHMMSS-nanoseconds
func GenerateUniqueBridgeName(prefix string) string {
	now := time.Now()
	return fmt.Sprintf("%s-%s-%09d", prefix, now.Format("20060102150405"), now.Nanosecond())
}

// GenerateUniqueVLANID generates a unique VLAN ID for testing.
// Uses timestamp-based approach to avoid conflicts.
func GenerateUniqueVLANID() int32 {
	now := time.Now()
	// Use last 12 bits of nanoseconds modulo 4000 + 100 to get VLAN in range 100-4095
	return int32((now.Nanosecond() % 4000) + 100)
}

// GenerateTestMAC generates a deterministic test MAC address.
func GenerateTestMAC(index int) string {
	return fmt.Sprintf("02:00:00:00:00:%02x", index%256)
}

// GenerateTestIP generates a deterministic test IP address.
func GenerateTestIP(index int) string {
	return fmt.Sprintf("10.%d.%d.%d", (index/65536)%256, (index/256)%256, index%256)
}

// =============================================================================
// Test Context Helpers
// =============================================================================

// DefaultTestContext returns a context with a reasonable timeout for integration tests.
func DefaultTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 60*time.Second)
}

// bridgeTypeToString converts a protobuf BridgeType (int or string) to a
// human-readable string matching the test adapter convention.
func parseBridgeTypeFromJSON(v interface{}) string {
	switch t := v.(type) {
	case string:
		switch t {
		case "BRIDGE_TYPE_OVS", "ovs":
			return "ovs"
		case "BRIDGE_TYPE_LINUX", "linux":
			return "linux"
		default:
			return t
		}
	case float64:
		switch int(t) {
		case 1:
			return "ovs"
		case 2:
			return "linux"
		default:
			return fmt.Sprintf("%v", t)
		}
	default:
		return fmt.Sprintf("%v", v)
	}
}

// parsePortTypeFromJSON converts a protobuf PortType enum value
// (integer or string) from CLI JSON output to a friendly type string.
func parsePortTypeFromJSON(v interface{}) string {
	switch t := v.(type) {
	case string:
		switch t {
		case "PORT_TYPE_INTERNAL", "internal":
			return "internal"
		case "PORT_TYPE_PHYSICAL", "physical":
			return "physical"
		case "PORT_TYPE_TAP", "tap":
			return "tap"
		case "PORT_TYPE_VETH", "veth":
			return "veth"
		case "PORT_TYPE_VXLAN", "vxlan":
			return "vxlan"
		case "PORT_TYPE_GRE", "gre":
			return "gre"
		default:
			return t
		}
	case float64:
		switch int(t) {
		case 1:
			return "internal"
		case 2:
			return "physical"
		case 3:
			return "tap"
		case 4:
			return "veth"
		case 5:
			return "vxlan"
		case 6:
			return "gre"
		default:
			return fmt.Sprintf("%v", t)
		}
	default:
		return fmt.Sprintf("%v", v)
	}
}

// parsePortStatusFromJSON converts a protobuf PortStatus enum value
// (integer or string) from CLI JSON output to a friendly status string.
func parsePortStatusFromJSON(v interface{}) string {
	switch t := v.(type) {
	case string:
		switch t {
		case "PORT_STATUS_UP":
			return "up"
		case "PORT_STATUS_DOWN":
			return "down"
		case "PORT_STATUS_BLOCKED":
			return "blocked"
		case "PORT_STATUS_LEARNING":
			return "learning"
		case "PORT_STATUS_FORWARDING":
			return "forwarding"
		default:
			return t
		}
	case float64:
		switch int(t) {
		case 1:
			return "up"
		case 2:
			return "down"
		case 3:
			return "blocked"
		case 4:
			return "learning"
		case 5:
			return "forwarding"
		default:
			return fmt.Sprintf("%v", t)
		}
	default:
		return fmt.Sprintf("%v", v)
	}
}

// parsePortStatusToAdminState derives the admin state from a port status value.
// When the server does not explicitly store admin_state in port options,
// the port status enum is used to infer it.
func parsePortStatusToAdminState(v interface{}) string {
	status := parsePortStatusFromJSON(v)
	switch status {
	case "up", "forwarding", "learning":
		return "up"
	case "down", "blocked":
		return "down"
	default:
		if status != "" && status != "0" {
			return "up"
		}
		return "up"
	}
}

// parseFlowTableFromJSON converts a protobuf FlowTable enum value
// (integer or string) from CLI JSON output to a table number.
func parseFlowTableFromJSON(v interface{}) int32 {
	switch t := v.(type) {
	case string:
		switch t {
		case "FLOW_TABLE_0":
			return 0
		case "FLOW_TABLE_1":
			return 1
		case "FLOW_TABLE_2":
			return 2
		case "FLOW_TABLE_3":
			return 3
		case "FLOW_TABLE_DROP":
			return 255
		default:
			return 0
		}
	case float64:
		// Protobuf enum values: 1=TABLE_0, 2=TABLE_1, etc.
		switch int(t) {
		case 1:
			return 0
		case 2:
			return 1
		case 3:
			return 2
		case 4:
			return 3
		case 255:
			return 255
		default:
			return int32(t)
		}
	default:
		return 0
	}
}

// parsePolicyStatusFromJSON converts a protobuf PolicyStatus enum value
// (integer or string) from CLI JSON output to a friendly status string.
func parsePolicyStatusFromJSON(v interface{}) string {
	switch t := v.(type) {
	case string:
		switch t {
		case "POLICY_STATUS_ACTIVE":
			return "active"
		case "POLICY_STATUS_INACTIVE":
			return "inactive"
		case "POLICY_STATUS_ERROR":
			return "error"
		case "POLICY_STATUS_PENDING":
			return "pending"
		default:
			return t
		}
	case float64:
		switch int(t) {
		case 1:
			return "active"
		case 2:
			return "inactive"
		case 3:
			return "error"
		case 4:
			return "pending"
		default:
			return fmt.Sprintf("%v", t)
		}
	default:
		return fmt.Sprintf("%v", v)
	}
}

// parsePolicyTypeFromJSON converts a protobuf PolicyType enum value
// (integer or string) from CLI JSON output to a friendly type string.
func parsePolicyTypeFromJSON(v interface{}) string {
	switch t := v.(type) {
	case string:
		switch t {
		case "POLICY_TYPE_ACL", "acl":
			return "acl"
		case "POLICY_TYPE_QOS", "qos":
			return "qos"
		case "POLICY_TYPE_NAT", "nat":
			return "nat"
		case "POLICY_TYPE_FIREWALL", "firewall":
			return "firewall"
		case "POLICY_TYPE_ROUTING", "routing":
			return "routing"
		default:
			return t
		}
	case float64:
		switch int(t) {
		case 1:
			return "acl"
		case 2:
			return "qos"
		case 3:
			return "nat"
		case 4:
			return "firewall"
		case 5:
			return "routing"
		default:
			return fmt.Sprintf("%v", t)
		}
	default:
		return fmt.Sprintf("%v", v)
	}
}

// parseFlowActionTypeFromJSON converts a protobuf FlowActionType enum value
// (integer or string) from CLI JSON output to a friendly action type string.
func parseFlowActionTypeFromJSON(v interface{}) string {
	switch t := v.(type) {
	case string:
		switch t {
		case "FLOW_ACTION_OUTPUT", "output", "normal", "flood":
			return "output"
		case "FLOW_ACTION_DROP", "drop":
			return "drop"
		case "FLOW_ACTION_SET_VLAN", "set_vlan":
			return "set_vlan"
		case "FLOW_ACTION_STRIP_VLAN", "strip_vlan":
			return "strip_vlan"
		case "FLOW_ACTION_SET_FIELD", "set_field":
			return "set_field"
		case "FLOW_ACTION_GOTO_TABLE", "goto_table":
			return "goto_table"
		case "FLOW_ACTION_CONTROLLER", "controller":
			return "controller"
		default:
			return t
		}
	case float64:
		switch int(t) {
		case 1:
			return "output"
		case 2:
			return "drop"
		case 3:
			return "set_vlan"
		case 4:
			return "strip_vlan"
		case 5:
			return "set_field"
		case 6:
			return "goto_table"
		case 7:
			return "controller"
		default:
			return fmt.Sprintf("%v", t)
		}
	default:
		return fmt.Sprintf("%v", v)
	}
}

// parseTimestamp converts a CLI JSON timestamp to time.Time.
// CLI JSON output uses protobuf timestamp format: either an RFC3339 string
// or a {"seconds": N, "nanos": N} object. Returns zero time on failure.
func parseTimestamp(v interface{}) time.Time {
	if v == nil {
		return time.Time{}
	}
	switch t := v.(type) {
	case string:
		parsed, _ := time.Parse(time.RFC3339, t)
		return parsed
	case map[string]interface{}:
		var seconds int64
		var nanos int64
		if s, ok := t["seconds"]; ok {
			switch sv := s.(type) {
			case float64:
				seconds = int64(sv)
			case json.Number:
				seconds, _ = sv.Int64()
			}
		}
		if n, ok := t["nanos"]; ok {
			switch nv := n.(type) {
			case float64:
				nanos = int64(nv)
			case json.Number:
				nanos, _ = nv.Int64()
			}
		}
		if seconds > 0 {
			return time.Unix(seconds, nanos)
		}
		return time.Time{}
	default:
		return time.Time{}
	}
}

// LongRunningTestContext returns a context with a longer timeout for tests
// that may take more time (e.g., bridge creation, policy application).
func LongRunningTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Minute)
}

// ShortTestContext returns a context with a short timeout for quick operations.
func ShortTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

// =============================================================================
// Test Bridge Helpers
// =============================================================================

// DefaultBridgeOptions returns default options for creating a test bridge.
func DefaultBridgeOptions(prefix string) BridgeCreateOptions {
	uniqueID := GenerateUniqueBridgeName(prefix)
	return BridgeCreateOptions{
		BridgeID:    uniqueID,
		Name:        uniqueID,
		Description: "Integration test bridge",
		Type:        "ovs",
		FailMode:    "secure",
		STP:         false,
		RSTP:        false,
		MTU:         1500,
		Tags:        map[string]string{"test": "true"},
	}
}

// DefaultPortOptions returns default options for adding a test port.
func DefaultPortOptions(bridgeID, portID string) PortAddOptions {
	return PortAddOptions{
		BridgeID:   bridgeID,
		PortID:     portID,
		Name:       portID,
		Type:       "internal",
		AdminState: "up",
		MTU:        1500,
	}
}

// DefaultFlowOptions returns default options for adding a test flow.
func DefaultFlowOptions(bridgeID, flowID string) FlowAddOptions {
	return FlowAddOptions{
		BridgeID: bridgeID,
		FlowID:   flowID,
		Table:    0,
		Priority: 100,
		Match: FlowMatch{
			DlType: 0x0800, // IPv4
		},
		Actions: []FlowAction{
			{Type: "drop"},
		},
		IdleTimeout: 0,
		HardTimeout: 0,
	}
}

// DefaultVLANOptions returns default options for creating a test VLAN.
// bridgeID specifies the bridge the VLAN is associated with, which is
// required by the SDN service for VLAN creation.
func DefaultVLANOptions(vlanID int32, bridgeID string) VLANCreateOptions {
	opts := VLANCreateOptions{
		VLANID:      vlanID,
		Name:        fmt.Sprintf("vlan-%d", vlanID),
		Description: "Integration test VLAN",
	}
	if bridgeID != "" {
		opts.BridgeIDs = []string{bridgeID}
	}
	return opts
}

// DefaultPolicyOptions returns default options for applying a test policy.
// bridgeID specifies the bridge the policy is applied to, which is required
// by the SDN service when the policy is translated to flow rules.
func DefaultPolicyOptions(policyID, bridgeID string) PolicyApplyOptions {
	return PolicyApplyOptions{
		PolicyID:    policyID,
		Name:        "Test Policy " + policyID,
		Description: "Integration test policy",
		Type:        "acl",
		BridgeID:    bridgeID,
		Priority:    100,
		Enabled:     true,
		Rules: []PolicyRule{
			{
				RuleID:   "rule-1",
				Priority: 100,
				Match: PolicyMatch{
					Protocol:  "tcp",
					Direction: "ingress",
				},
				Action: "allow",
			},
		},
	}
}
