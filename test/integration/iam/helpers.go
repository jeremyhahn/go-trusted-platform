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

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

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
	return helpers.GetRESTEndpoint()
}

// GetGRPCEndpoint returns the gRPC API endpoint
func GetGRPCEndpoint() string {
	if endpoint := os.Getenv("IAM_GRPC_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return helpers.GetGRPCEndpoint()
}

// GetQUICEndpoint returns the QUIC API endpoint
func GetQUICEndpoint() string {
	if endpoint := os.Getenv("IAM_QUIC_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return helpers.GetQUICEndpoint()
}

// GetMCPEndpoint returns the MCP API endpoint
func GetMCPEndpoint() string {
	if endpoint := os.Getenv("IAM_MCP_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return helpers.GetMCPEndpoint()
}

// GetSocketPath returns the Unix socket path
func GetSocketPath() string {
	if path := os.Getenv("IAM_SOCKET_PATH"); path != "" {
		return path
	}
	return helpers.GetSocketPath()
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
