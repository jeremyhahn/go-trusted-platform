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

//go:build integration

package iam

import (
	"os"
	"testing"
)

// SkipIfNotIntegration skips the test if not running in integration mode
func SkipIfNotIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("INTEGRATION_TEST") == "" {
		t.Skip("Skipping integration test. Set INTEGRATION_TEST=1 to run.")
	}
}

// DefaultTenantID returns the default tenant ID for tests
func DefaultTenantID() string {
	if id := os.Getenv("IAM_TENANT_ID"); id != "" {
		return id
	}
	return "test-tenant"
}

// GetRESTEndpoint returns the REST API endpoint
func GetRESTEndpoint() string {
	if endpoint := os.Getenv("IAM_REST_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return "https://localhost:8443"
}

// GetGRPCEndpoint returns the gRPC API endpoint
func GetGRPCEndpoint() string {
	if endpoint := os.Getenv("IAM_GRPC_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return "localhost:10443"
}

// GetQUICEndpoint returns the QUIC API endpoint
func GetQUICEndpoint() string {
	if endpoint := os.Getenv("IAM_QUIC_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return "localhost:9444"
}

// GetMCPEndpoint returns the MCP API endpoint
func GetMCPEndpoint() string {
	if endpoint := os.Getenv("IAM_MCP_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return "http://localhost:9445"
}

// GetSocketPath returns the Unix socket path
func GetSocketPath() string {
	if path := os.Getenv("IAM_SOCKET_PATH"); path != "" {
		return path
	}
	return "/run/platformd.sock"
}

// GetCLIPath returns the path to the platformctl CLI
func GetCLIPath() string {
	if path := os.Getenv("PLATFORMCTL_PATH"); path != "" {
		return path
	}
	return "platformctl"
}

// GenerateTestUserID generates a unique user ID for testing
func GenerateTestUserID(testID string) string {
	return "test-user-" + testID
}

// GenerateTestEmail generates a unique email for testing
func GenerateTestEmail(testID string) string {
	return "test-" + testID + "@example.com"
}

// GenerateTestRoleName generates a unique role name for testing
func GenerateTestRoleName(testID string) string {
	return "test-role-" + testID
}

// GenerateTestRoleID generates a unique role ID for testing
func GenerateTestRoleID(testID string) string {
	return "test-role-" + testID
}

// GenerateTestGroupName generates a unique group name for testing
func GenerateTestGroupName(testID string) string {
	return "test-group-" + testID
}

// GenerateTestGroupID generates a unique group ID for testing
func GenerateTestGroupID(testID string) string {
	return "test-group-" + testID
}

// GenerateTestPolicyName generates a unique policy name for testing
func GenerateTestPolicyName(testID string) string {
	return "test-policy-" + testID
}

// GenerateTestPermissionName generates a unique permission name for testing
func GenerateTestPermissionName(testID string) string {
	return "test-permission-" + testID
}

// GenerateTestServiceAccountName generates a unique service account name for testing
func GenerateTestServiceAccountName(testID string) string {
	return "test-sa-" + testID
}

// GenerateTestUsername generates a unique username for testing
func GenerateTestUsername(testID string) string {
	return "testuser" + testID
}

// GetTestPassword returns a test password for integration tests
func GetTestPassword() string {
	if password := os.Getenv("IAM_TEST_PASSWORD"); password != "" {
		return password
	}
	return "TestPassword123!"
}

// GetAdminToken returns an admin token for authenticated API calls
func GetAdminToken() string {
	return os.Getenv("IAM_ADMIN_TOKEN")
}

// GetTestToken returns a test user token for authenticated API calls
func GetTestToken() string {
	return os.Getenv("IAM_TEST_TOKEN")
}
