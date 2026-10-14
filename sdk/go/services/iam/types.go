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

package iam

import "time"

// User represents an IAM user.
type User struct {
	ID          string            `json:"id" yaml:"id"`
	TenantID    string            `json:"tenant_id" yaml:"tenant_id"`
	Email       string            `json:"email" yaml:"email"`
	Name        string            `json:"name,omitempty" yaml:"name,omitempty"`
	Roles       []string          `json:"roles,omitempty" yaml:"roles,omitempty"`
	Attributes  map[string]string `json:"attributes,omitempty" yaml:"attributes,omitempty"`
	MfaVerified bool              `json:"mfa_verified" yaml:"mfa_verified"`
	CreatedAt   time.Time         `json:"created_at" yaml:"created_at"`
	UpdatedAt   *time.Time        `json:"updated_at,omitempty" yaml:"updated_at,omitempty"`
	LastAuth    *time.Time        `json:"last_auth,omitempty" yaml:"last_auth,omitempty"`
}

// Role represents an IAM role.
type Role struct {
	ID          string     `json:"id" yaml:"id"`
	TenantID    string     `json:"tenant_id" yaml:"tenant_id"`
	Name        string     `json:"name,omitempty" yaml:"name,omitempty"`
	Description string     `json:"description,omitempty" yaml:"description,omitempty"`
	Permissions []string   `json:"permissions,omitempty" yaml:"permissions,omitempty"`
	CreatedAt   time.Time  `json:"created_at" yaml:"created_at"`
	UpdatedAt   *time.Time `json:"updated_at,omitempty" yaml:"updated_at,omitempty"`
}

// Policy represents an IAM policy.
type Policy struct {
	Name        string            `json:"name" yaml:"name"`
	TenantID    string            `json:"tenant_id" yaml:"tenant_id"`
	Description string            `json:"description,omitempty" yaml:"description,omitempty"`
	Priority    int32             `json:"priority" yaml:"priority"`
	SpecYAML    []byte            `json:"spec_yaml,omitempty" yaml:"spec_yaml,omitempty"`
	Labels      map[string]string `json:"labels,omitempty" yaml:"labels,omitempty"`
	CreatedAt   time.Time         `json:"created_at" yaml:"created_at"`
	UpdatedAt   *time.Time        `json:"updated_at,omitempty" yaml:"updated_at,omitempty"`
}

// Tenant represents an IAM tenant.
type Tenant struct {
	ID        string          `json:"id" yaml:"id"`
	Name      string          `json:"name" yaml:"name"`
	Settings  *TenantSettings `json:"settings,omitempty" yaml:"settings,omitempty"`
	CreatedAt time.Time       `json:"created_at" yaml:"created_at"`
	UpdatedAt *time.Time      `json:"updated_at,omitempty" yaml:"updated_at,omitempty"`
}

// TenantSettings contains tenant configuration settings.
type TenantSettings struct {
	MaxUsers    int32 `json:"max_users" yaml:"max_users"`
	MfaRequired bool  `json:"mfa_required" yaml:"mfa_required"`
}

// App represents an OAuth application.
type App struct {
	ClientID       string     `json:"client_id" yaml:"client_id"`
	ClientSecret   string     `json:"client_secret,omitempty" yaml:"client_secret,omitempty"`
	Name           string     `json:"name" yaml:"name"`
	TenantID       string     `json:"tenant_id" yaml:"tenant_id"`
	RedirectURIs   []string   `json:"redirect_uris,omitempty" yaml:"redirect_uris,omitempty"`
	GrantTypes     []string   `json:"grant_types,omitempty" yaml:"grant_types,omitempty"`
	ResponseTypes  []string   `json:"response_types,omitempty" yaml:"response_types,omitempty"`
	ResourcePrefix string     `json:"resource_prefix,omitempty" yaml:"resource_prefix,omitempty"`
	CreatedAt      time.Time  `json:"created_at" yaml:"created_at"`
	UpdatedAt      *time.Time `json:"updated_at,omitempty" yaml:"updated_at,omitempty"`
}

// OperationStatus represents the result of a mutating operation.
type OperationStatus struct {
	Success bool   `json:"success" yaml:"success"`
	Message string `json:"message,omitempty" yaml:"message,omitempty"`
}

// ValidatePolicyResult contains the result of policy validation.
type ValidatePolicyResult struct {
	Valid  bool     `json:"valid" yaml:"valid"`
	Errors []string `json:"errors,omitempty" yaml:"errors,omitempty"`
}

// TestPolicyResult contains the result of a policy test.
type TestPolicyResult struct {
	Allowed          bool   `json:"allowed" yaml:"allowed"`
	MatchedPolicy    string `json:"matched_policy,omitempty" yaml:"matched_policy,omitempty"`
	MatchedRule      string `json:"matched_rule,omitempty" yaml:"matched_rule,omitempty"`
	EvaluationTimeNs int64  `json:"evaluation_time_ns" yaml:"evaluation_time_ns"`
}

// RotateSecretResult contains the result of rotating an app secret.
type RotateSecretResult struct {
	ClientID     string `json:"client_id" yaml:"client_id"`
	Name         string `json:"name" yaml:"name"`
	ClientSecret string `json:"client_secret,omitempty" yaml:"client_secret,omitempty"`
}

// ListUsersResult contains the result of listing users.
type ListUsersResult struct {
	Users []*User `json:"users" yaml:"users"`
	Total uint64  `json:"total" yaml:"total"`
}

// ListRolesResult contains the result of listing roles.
type ListRolesResult struct {
	Roles []*Role `json:"roles" yaml:"roles"`
	Total uint64  `json:"total" yaml:"total"`
}

// ListPoliciesResult contains the result of listing policies.
type ListPoliciesResult struct {
	Policies []*Policy `json:"policies" yaml:"policies"`
	Total    uint64    `json:"total" yaml:"total"`
}

// ListTenantsResult contains the result of listing tenants.
type ListTenantsResult struct {
	Tenants []*Tenant `json:"tenants" yaml:"tenants"`
	Total   uint64    `json:"total" yaml:"total"`
}

// ListAppsResult contains the result of listing apps.
type ListAppsResult struct {
	Apps  []*App `json:"apps" yaml:"apps"`
	Total uint64 `json:"total" yaml:"total"`
}
