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

// Package invitation provides integration test adapters for Invitation services.
// This file provides helper functions for invitation integration tests.
package invitation

import (
	"os"
	"testing"
	"time"

	"github.com/google/uuid"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
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
	if id := os.Getenv("INVITATION_TENANT_ID"); id != "" {
		return id
	}
	return "test-tenant"
}

// DefaultOwnerUserID returns the default owner user ID for tests
func DefaultOwnerUserID() uint64 {
	return 1 // Default owner user ID
}

// AlternateTenantID returns an alternate tenant ID for cross-tenant tests
func AlternateTenantID() string {
	if id := os.Getenv("INVITATION_ALTERNATE_TENANT_ID"); id != "" {
		return id
	}
	return "test-tenant-2"
}

// GenerateTestEmail generates a unique email for testing
func GenerateTestEmail(prefix string) string {
	return "test-" + prefix + "-" + uuid.New().String()[:8] + "@example.com"
}

// GenerateTestName generates a unique name for testing
func GenerateTestName(prefix string) string {
	return "Test User " + prefix + " " + uuid.New().String()[:4]
}

// GenerateTestPassword returns a test password
func GenerateTestPassword() string {
	if password := os.Getenv("INVITATION_TEST_PASSWORD"); password != "" {
		return password
	}
	return "TestPassword123!"
}

// GetRESTEndpoint returns the REST API endpoint
func GetRESTEndpoint() string {
	if endpoint := os.Getenv("INVITATION_REST_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return helpers.GetRESTEndpoint()
}

// GetGRPCEndpoint returns the gRPC API endpoint
func GetGRPCEndpoint() string {
	if endpoint := os.Getenv("INVITATION_GRPC_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return helpers.GetGRPCEndpoint()
}

// GetQUICEndpoint returns the QUIC API endpoint
func GetQUICEndpoint() string {
	if endpoint := os.Getenv("INVITATION_QUIC_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return helpers.GetQUICEndpoint()
}

// GetMCPEndpoint returns the MCP API endpoint
func GetMCPEndpoint() string {
	if endpoint := os.Getenv("INVITATION_MCP_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return helpers.GetMCPEndpoint()
}

// GetSocketPath returns the Unix socket path
func GetSocketPath() string {
	if path := os.Getenv("INVITATION_SOCKET_PATH"); path != "" {
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

// GetAdminToken returns an admin token for authenticated API calls
func GetAdminToken() string {
	return os.Getenv("INVITATION_ADMIN_TOKEN")
}

// GetOwnerToken returns a tenant owner token for authenticated API calls
func GetOwnerToken() string {
	return os.Getenv("INVITATION_OWNER_TOKEN")
}

// GetMemberToken returns a non-owner member token for authenticated API calls
func GetMemberToken() string {
	return os.Getenv("INVITATION_MEMBER_TOKEN")
}

// DefaultExpirationDuration returns the default expiration duration for invitations
func DefaultExpirationDuration() time.Duration {
	return 7 * 24 * time.Hour // 7 days
}

// ShortExpirationDuration returns a short expiration duration for testing expiration
func ShortExpirationDuration() time.Duration {
	return 1 * time.Second
}

// Endpoints contains all API endpoints for invitation operations
type Endpoints struct {
	REST   string
	GRPC   string
	QUIC   string
	MCP    string
	Socket string
	CLI    string
}

// GetEndpoints returns all configured endpoints
func GetEndpoints() *Endpoints {
	return &Endpoints{
		REST:   GetRESTEndpoint(),
		GRPC:   GetGRPCEndpoint(),
		QUIC:   GetQUICEndpoint(),
		MCP:    GetMCPEndpoint(),
		Socket: GetSocketPath(),
		CLI:    GetCLIPath(),
	}
}

// TestFixture contains common test data for invitation tests
type TestFixture struct {
	TenantID    string
	OwnerUserID uint64
	Email       string
	Role        string
}

// NewTestFixture creates a new test fixture with unique data
func NewTestFixture(prefix string) *TestFixture {
	return &TestFixture{
		TenantID:    DefaultTenantID(),
		OwnerUserID: DefaultOwnerUserID(),
		Email:       GenerateTestEmail(prefix),
		Role:        "member",
	}
}

// CreateInvitationOptionsFromFixture creates CreateInvitationOptions from a fixture
func (f *TestFixture) CreateInvitationOptionsFromFixture() CreateInvitationOptions {
	return CreateInvitationOptions{
		TenantID: f.TenantID,
		Email:    f.Email,
		Role:     f.Role,
		AsOwner:  true,
		UserID:   f.OwnerUserID,
	}
}
