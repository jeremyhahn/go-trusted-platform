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

// ErrMissingEmail is returned when email is required but not provided
type ErrMissingEmail struct{}

func (e ErrMissingEmail) Error() string {
	return "email is required"
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

// ErrMissingRole is returned when role name is required but not provided
type ErrMissingRole struct{}

func (e ErrMissingRole) Error() string {
	return "role is required"
}

// ErrMissingPolicyName is returned when policy name is required but not provided
type ErrMissingPolicyName struct{}

func (e ErrMissingPolicyName) Error() string {
	return "policy name is required"
}

// ErrMissingClientID is returned when client ID is required but not provided
type ErrMissingClientID struct{}

func (e ErrMissingClientID) Error() string {
	return "client ID is required"
}

// ErrMissingAppName is returned when application name is required but not provided
type ErrMissingAppName struct{}

func (e ErrMissingAppName) Error() string {
	return "application name is required"
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
	TenantID   string
	PolicyName string
}

func (e ErrPolicyNotFound) Error() string {
	return fmt.Sprintf("policy not found: tenant=%s, policy=%s", e.TenantID, e.PolicyName)
}

// ErrAppNotFound is returned when an application is not found
type ErrAppNotFound struct {
	TenantID string
	ClientID string
}

func (e ErrAppNotFound) Error() string {
	return fmt.Sprintf("application not found: tenant=%s, client=%s", e.TenantID, e.ClientID)
}

// ErrInvalidPolicySpec is returned when policy spec YAML is invalid
type ErrInvalidPolicySpec struct {
	Reason string
}

func (e ErrInvalidPolicySpec) Error() string {
	return fmt.Sprintf("invalid policy spec: %s", e.Reason)
}

// MessageError is a typed error carrying a fully formatted message with no
// underlying cause. It replaces inline formatted-error constructions that do not wrap
// another error.
type MessageError struct {
	Msg string
}

// Error implements the error interface.
func (e *MessageError) Error() string {
	return e.Msg
}

// WrappedError wraps an underlying cause with a contextual message while
// preserving errors.Is / errors.As matching through Unwrap. It replaces
// inline formatted-error constructions that wrap another error.
type WrappedError struct {
	Msg string
	Err error
}

// Error implements the error interface.
func (e *WrappedError) Error() string {
	return e.Msg + ": " + e.Err.Error()
}

// Unwrap returns the wrapped cause.
func (e *WrappedError) Unwrap() error {
	return e.Err
}
