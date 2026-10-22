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

import "fmt"

// ErrMissingTenantID is returned when tenant ID is required but not provided
type ErrMissingTenantID struct{}

func (e ErrMissingTenantID) Error() string {
	return "tenant ID is required"
}

// ErrMissingUserID is returned when user ID is required but not provided
type ErrMissingUserID struct{}

func (e ErrMissingUserID) Error() string {
	return "user ID is required"
}

// ErrMissingGroupID is returned when group ID is required but not provided
type ErrMissingGroupID struct{}

func (e ErrMissingGroupID) Error() string {
	return "group ID is required"
}

// ErrMissingRoleID is returned when role ID is required but not provided
type ErrMissingRoleID struct{}

func (e ErrMissingRoleID) Error() string {
	return "role ID is required"
}

// ErrMissingPolicyID is returned when policy ID is required but not provided
type ErrMissingPolicyID struct{}

func (e ErrMissingPolicyID) Error() string {
	return "policy ID is required"
}

// ErrMissingAppID is returned when app ID is required but not provided
type ErrMissingAppID struct{}

func (e ErrMissingAppID) Error() string {
	return "app ID is required"
}

// ErrInvalidRequestBody is returned when the request body cannot be parsed
type ErrInvalidRequestBody struct {
	Reason string
}

func (e ErrInvalidRequestBody) Error() string {
	return fmt.Sprintf("invalid request body: %s", e.Reason)
}

// ErrInvalidPaginationParams is returned when pagination parameters are invalid
type ErrInvalidPaginationParams struct {
	Reason string
}

func (e ErrInvalidPaginationParams) Error() string {
	return fmt.Sprintf("invalid pagination parameters: %s", e.Reason)
}

// ErrUserNotFound is returned when a user is not found
type ErrUserNotFound struct {
	TenantID string
	UserID   string
}

func (e ErrUserNotFound) Error() string {
	return fmt.Sprintf("user not found: tenant=%s, user=%s", e.TenantID, e.UserID)
}

// ErrGroupNotFound is returned when a group is not found
type ErrGroupNotFound struct {
	TenantID string
	GroupID  string
}

func (e ErrGroupNotFound) Error() string {
	return fmt.Sprintf("group not found: tenant=%s, group=%s", e.TenantID, e.GroupID)
}

// ErrRoleNotFound is returned when a role is not found
type ErrRoleNotFound struct {
	TenantID string
	RoleID   string
}

func (e ErrRoleNotFound) Error() string {
	return fmt.Sprintf("role not found: tenant=%s, role=%s", e.TenantID, e.RoleID)
}

// ErrTenantNotFound is returned when a tenant is not found
type ErrTenantNotFound struct {
	TenantID string
}

func (e ErrTenantNotFound) Error() string {
	return fmt.Sprintf("tenant not found: %s", e.TenantID)
}

// ErrPolicyNotFound is returned when a policy is not found
type ErrPolicyNotFound struct {
	TenantID string
	PolicyID string
}

func (e ErrPolicyNotFound) Error() string {
	return fmt.Sprintf("policy not found: tenant=%s, policy=%s", e.TenantID, e.PolicyID)
}

// ErrAppNotFound is returned when an application is not found
type ErrAppNotFound struct {
	TenantID string
	AppID    string
}

func (e ErrAppNotFound) Error() string {
	return fmt.Sprintf("application not found: tenant=%s, app=%s", e.TenantID, e.AppID)
}

// ErrInvalidPolicySpec is returned when policy spec is invalid
type ErrInvalidPolicySpec struct {
	Reason string
}

func (e ErrInvalidPolicySpec) Error() string {
	return fmt.Sprintf("invalid policy spec: %s", e.Reason)
}

// ErrMissingRole is returned when role name is required but not provided
type ErrMissingRole struct{}

func (e ErrMissingRole) Error() string {
	return "role is required"
}

// ErrMissingMember is returned when member ID is required but not provided
type ErrMissingMember struct{}

func (e ErrMissingMember) Error() string {
	return "member ID is required"
}

// ErrAuthorizationRequired is returned when NewIAMRouter is called without
// a complete Authorization. The IAM surface is administration-only, so a
// missing guard aborts construction instead of publishing it unguarded.
type ErrAuthorizationRequired struct {
	Guard string
}

func (e ErrAuthorizationRequired) Error() string {
	return fmt.Sprintf("rest/iam: authorization guard is required: %s", e.Guard)
}

// ErrMirrorClientMissing is returned when the user mirror is asked to read the
// IAM tenant without an IAM client to read it through.
type ErrMirrorClientMissing struct{}

func (e ErrMirrorClientMissing) Error() string {
	return "rest/iam: user mirror has no IAM client"
}

// ErrRoleResolverClientMissing is returned when a workspace role resolver is
// built without an IAM client to read the workspace's users through.
type ErrRoleResolverClientMissing struct{}

func (e ErrRoleResolverClientMissing) Error() string {
	return "rest/iam: workspace role resolver has no IAM client"
}

// ErrForeignBodyTenant is returned when a request body names a tenant other
// than the one the route acts on: the path's {tenant}, otherwise the
// session's. It is refused with 403, as the own-tenant guard refuses the same
// tenant named in the path or the tenant_id query (#401).
type ErrForeignBodyTenant struct {
	Tenant string
}

func (e ErrForeignBodyTenant) Error() string {
	return fmt.Sprintf("rest/iam: request body names a tenant other than %q", e.Tenant)
}

// ErrConflictingQueryTenant is returned when a tenant-scoped route's
// tenant_id query names a tenant other than the path's {tenant}. The request
// is ambiguous, so it is refused with 403 rather than served from the path's
// tenant (#401).
type ErrConflictingQueryTenant struct {
	Path  string
	Query string
}

func (e ErrConflictingQueryTenant) Error() string {
	return fmt.Sprintf("rest/iam: tenant_id query %q conflicts with path tenant %q", e.Query, e.Path)
}

// ErrPEPClientMissing is returned when a permission check reaches a router
// built without the policy enforcement point the check is evaluated by: the
// daemon wired no IAM PEP, so the route answers 503 rather than a verdict.
type ErrPEPClientMissing struct{}

func (e ErrPEPClientMissing) Error() string {
	return "rest/iam: no policy enforcement point is wired to check permissions"
}

// ErrRoleClientMissing is returned when role references are resolved without
// an IAM role client to read the tenant's roles through.
type ErrRoleClientMissing struct{}

func (e ErrRoleClientMissing) Error() string {
	return "rest/iam: no IAM role client to resolve role references"
}

// ErrRoleListFailed is returned when the tenant's roles could not be read to
// resolve role references. Err is the IAM client's error.
type ErrRoleListFailed struct {
	TenantID string
	Err      error
}

func (e ErrRoleListFailed) Error() string {
	return fmt.Sprintf("rest/iam: listing the roles of tenant %s: %v", e.TenantID, e.Err)
}

func (e ErrRoleListFailed) Unwrap() error {
	return e.Err
}
