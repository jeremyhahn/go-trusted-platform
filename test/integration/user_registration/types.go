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

// Package user_registration provides integration tests for user registration
// with tenant management across all protocols.
// These tests verify that user registration operations work consistently across
// all protocol adapters (CLI, REST, gRPC, QUIC, MCP, Unix) using a unified
// RegistrationCommands interface.
//
// Run tests via:
//
//	make integration-test-user-registration
//
// The multiprotocol pattern enables:
//   - Testing all protocols against the same test scenarios
//   - Ensuring API consistency across transport layers
//   - Easy addition of new protocol adapters
package user_registration

import (
	"context"
	"time"
)

// RegistrationCommands defines the interface for user registration operations across all protocols
type RegistrationCommands interface {
	// Setup prepares the adapter for testing
	Setup(ctx context.Context) error

	// Teardown cleans up after testing
	Teardown(ctx context.Context) error

	// Name returns the adapter name
	Name() string

	// Registration Operations

	// RegisterNewUser registers a new user (creates their own tenant)
	RegisterNewUser(ctx context.Context, opts RegisterOptions) (*RegisterResult, error)

	// RegisterInvitedUser registers a user who was invited to join an existing tenant
	RegisterInvitedUser(ctx context.Context, opts RegisterInvitedOptions) (*RegisterResult, error)

	// User Operations

	// GetUser retrieves a user by ID
	GetUser(ctx context.Context, opts GetUserOptions) (*GetUserResult, error)

	// GetUserByEmail retrieves a user by email
	GetUserByEmail(ctx context.Context, opts GetUserByEmailOptions) (*GetUserResult, error)

	// Token Operations

	// GetToken retrieves a JWT token for a user (login)
	GetToken(ctx context.Context, opts GetTokenOptions) (*GetTokenResult, error)

	// ValidateToken validates a JWT token and returns its claims
	ValidateToken(ctx context.Context, opts ValidateTokenOptions) (*ValidateTokenResult, error)

	// Invitation Operations

	// CreateInvitation creates an invitation for a user to join a tenant
	CreateInvitation(ctx context.Context, opts CreateInvitationOptions) (*CreateInvitationResult, error)

	// GetInvitation retrieves an invitation by token
	GetInvitation(ctx context.Context, opts GetInvitationOptions) (*GetInvitationResult, error)

	// Tenant Operations (for test setup/verification)

	// CreateTenant creates a tenant for test setup
	CreateTenant(ctx context.Context, opts CreateTenantOptions) (*CreateTenantResult, error)

	// GetTenant retrieves a tenant by ID
	GetTenant(ctx context.Context, opts GetTenantOptions) (*GetTenantResult, error)
}

// =============================================================================
// Registration Options and Results
// =============================================================================

// RegisterOptions contains options for registering a new user
type RegisterOptions struct {
	Email       string `json:"email"`
	Password    string `json:"password"`
	FirstName   string `json:"first_name,omitempty"`
	LastName    string `json:"last_name,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
	TenantName  string `json:"tenant_name,omitempty"` // Name for the new tenant
}

// RegisterInvitedOptions contains options for registering an invited user
type RegisterInvitedOptions struct {
	Email           string `json:"email"`
	Password        string `json:"password"`
	FirstName       string `json:"first_name,omitempty"`
	LastName        string `json:"last_name,omitempty"`
	DisplayName     string `json:"display_name,omitempty"`
	InvitationToken string `json:"invitation_token"`
}

// RegisterResult contains the result of user registration
type RegisterResult struct {
	User  *UserData  `json:"user"`
	Token *TokenData `json:"token,omitempty"`
}

// UserData represents user data in results
type UserData struct {
	ID            string    `json:"id"`
	Email         string    `json:"email"`
	FirstName     string    `json:"first_name,omitempty"`
	LastName      string    `json:"last_name,omitempty"`
	DisplayName   string    `json:"display_name,omitempty"`
	TenantID      string    `json:"tenant_id"`
	IsTenantOwner bool      `json:"is_tenant_owner"`
	Role          string    `json:"role,omitempty"`
	Status        string    `json:"status,omitempty"`
	CreatedAt     time.Time `json:"created_at"`
	UpdatedAt     time.Time `json:"updated_at"`
}

// TokenData represents JWT token data in results
type TokenData struct {
	AccessToken  string    `json:"access_token"`
	RefreshToken string    `json:"refresh_token,omitempty"`
	TokenType    string    `json:"token_type"`
	ExpiresAt    time.Time `json:"expires_at"`
}

// =============================================================================
// User Options and Results
// =============================================================================

// GetUserOptions contains options for getting a user
type GetUserOptions struct {
	UserID string `json:"user_id"`
}

// GetUserByEmailOptions contains options for getting a user by email
type GetUserByEmailOptions struct {
	Email string `json:"email"`
}

// GetUserResult contains the result of getting a user
type GetUserResult struct {
	User *UserData `json:"user"`
}

// =============================================================================
// Token Options and Results
// =============================================================================

// GetTokenOptions contains options for getting a token (login)
type GetTokenOptions struct {
	Email    string `json:"email"`
	Password string `json:"password"`
}

// GetTokenResult contains the result of getting a token
type GetTokenResult struct {
	Token *TokenData `json:"token"`
}

// ValidateTokenOptions contains options for validating a token
type ValidateTokenOptions struct {
	Token string `json:"token"`
}

// ValidateTokenResult contains the result of validating a token
type ValidateTokenResult struct {
	Valid   bool         `json:"valid"`
	Claims  *TokenClaims `json:"claims,omitempty"`
	Message string       `json:"message,omitempty"`
}

// TokenClaims represents JWT token claims
type TokenClaims struct {
	Subject       string `json:"sub"`
	Email         string `json:"email,omitempty"`
	TenantID      string `json:"tenant_id"`
	IsTenantOwner bool   `json:"is_tenant_owner"`
	Role          string `json:"role,omitempty"`
	ExpiresAt     int64  `json:"exp"`
	IssuedAt      int64  `json:"iat"`
}

// =============================================================================
// Invitation Options and Results
// =============================================================================

// CreateInvitationOptions contains options for creating an invitation
type CreateInvitationOptions struct {
	TenantID string `json:"tenant_id"`
	Email    string `json:"email"`
	Role     string `json:"role,omitempty"`
}

// CreateInvitationResult contains the result of creating an invitation
type CreateInvitationResult struct {
	Invitation *InvitationData `json:"invitation"`
}

// InvitationData represents invitation data in results
type InvitationData struct {
	ID        string    `json:"id"`
	TenantID  string    `json:"tenant_id"`
	Email     string    `json:"email"`
	Role      string    `json:"role,omitempty"`
	Token     string    `json:"token"`
	Status    string    `json:"status"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// GetInvitationOptions contains options for getting an invitation
type GetInvitationOptions struct {
	Token string `json:"token"`
}

// GetInvitationResult contains the result of getting an invitation
type GetInvitationResult struct {
	Invitation *InvitationData `json:"invitation"`
}

// =============================================================================
// Tenant Options and Results
// =============================================================================

// CreateTenantOptions contains options for creating a tenant
type CreateTenantOptions struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
}

// CreateTenantResult contains the result of tenant creation
type CreateTenantResult struct {
	Tenant *TenantData `json:"tenant"`
}

// TenantData represents tenant data in results
type TenantData struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	DisplayName string    `json:"display_name,omitempty"`
	OwnerID     string    `json:"owner_id,omitempty"`
	State       string    `json:"state,omitempty"`
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
}

// GetTenantOptions contains options for getting a tenant
type GetTenantOptions struct {
	TenantID string `json:"tenant_id"`
}

// GetTenantResult contains the result of getting a tenant
type GetTenantResult struct {
	Tenant *TenantData `json:"tenant"`
}
