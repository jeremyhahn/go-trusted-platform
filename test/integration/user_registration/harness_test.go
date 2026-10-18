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

// Package user_registration provides integration tests for user registration services.
// This file provides test harness and helper functions.
package user_registration

import (
	"time"

	"github.com/google/uuid"
)

// GenerateTestEmail generates a unique email address for testing
func GenerateTestEmail(prefix string) string {
	return prefix + "-" + uuid.New().String()[:8] + "@test.example.com"
}

// GenerateTestTenantName generates a unique tenant name for testing
func GenerateTestTenantName(prefix string) string {
	return "test-tenant-" + prefix + "-" + uuid.New().String()[:8]
}

// GenerateTestDisplayName generates a unique display name for testing
func GenerateTestDisplayName(prefix string) string {
	return "Test User " + prefix + " " + uuid.New().String()[:4]
}

// GenerateStrongPassword generates a strong password for testing
func GenerateStrongPassword() string {
	return "TestP@ssw0rd!" + uuid.New().String()[:8]
}

// DefaultRegisterOptions returns default registration options for tests
func DefaultRegisterOptions(prefix string) RegisterOptions {
	return RegisterOptions{
		Email:       GenerateTestEmail(prefix),
		Password:    GenerateStrongPassword(),
		FirstName:   "Test",
		LastName:    "User",
		DisplayName: GenerateTestDisplayName(prefix),
		TenantName:  GenerateTestTenantName(prefix),
	}
}

// DefaultInvitedRegisterOptions returns default invited registration options for tests
func DefaultInvitedRegisterOptions(prefix string, invitationToken string) RegisterInvitedOptions {
	return RegisterInvitedOptions{
		Email:           GenerateTestEmail(prefix),
		Password:        GenerateStrongPassword(),
		FirstName:       "Invited",
		LastName:        "User",
		DisplayName:     GenerateTestDisplayName(prefix),
		InvitationToken: invitationToken,
	}
}

// DefaultCreateInvitationOptions returns default invitation options for tests
func DefaultCreateInvitationOptions(tenantID, email, role string) CreateInvitationOptions {
	return CreateInvitationOptions{
		TenantID: tenantID,
		Email:    email,
		Role:     role,
	}
}

// DefaultCreateTenantOptions returns default tenant creation options for tests
func DefaultCreateTenantOptions(prefix string) CreateTenantOptions {
	return CreateTenantOptions{
		Name:        GenerateTestTenantName(prefix),
		DisplayName: "Test Tenant " + prefix,
	}
}

// Endpoints contains all API endpoints for registration operations
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

// TestContext holds test context information
type TestContext struct {
	Prefix    string
	StartTime time.Time
}

// NewTestContext creates a new test context
func NewTestContext(prefix string) *TestContext {
	return &TestContext{
		Prefix:    prefix,
		StartTime: time.Now(),
	}
}

// TestData holds test data created during setup
type TestData struct {
	// Owner user data
	OwnerUser     *UserData
	OwnerPassword string
	OwnerToken    *TokenData

	// Invited user data
	InvitedUser     *UserData
	InvitedPassword string
	InvitedToken    *TokenData

	// Tenant data
	Tenant *TenantData

	// Invitation data
	Invitation *InvitationData
}

// NewTestData creates a new test data holder
func NewTestData() *TestData {
	return &TestData{}
}

// TestRoles defines standard test roles
var TestRoles = struct {
	Admin  string
	Member string
	Viewer string
}{
	Admin:  "admin",
	Member: "member",
	Viewer: "viewer",
}

// TestUserStatus defines standard user status values
var TestUserStatus = struct {
	Active    string
	Pending   string
	Suspended string
}{
	Active:    "active",
	Pending:   "pending",
	Suspended: "suspended",
}

// TestInvitationStatus defines standard invitation status values
var TestInvitationStatus = struct {
	Pending  string
	Accepted string
	Expired  string
	Revoked  string
}{
	Pending:  "pending",
	Accepted: "accepted",
	Expired:  "expired",
	Revoked:  "revoked",
}
