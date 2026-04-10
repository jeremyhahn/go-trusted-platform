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

package tenant

import "fmt"

// ErrMissingAuthorizationHeader indicates no authorization header was provided.
type ErrMissingAuthorizationHeader struct{}

func (e ErrMissingAuthorizationHeader) Error() string {
	return "tenant: missing authorization header"
}

// ErrInvalidAuthorizationFormat indicates the authorization header format is invalid.
type ErrInvalidAuthorizationFormat struct {
	Reason string
}

func (e ErrInvalidAuthorizationFormat) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("tenant: invalid authorization format: %s", e.Reason)
	}
	return "tenant: invalid authorization format"
}

// ErrInvalidToken indicates the JWT token is invalid.
type ErrInvalidToken struct {
	Reason string
}

func (e ErrInvalidToken) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("tenant: invalid token: %s", e.Reason)
	}
	return "tenant: invalid token"
}

// ErrTokenExpired indicates the JWT token has expired.
type ErrTokenExpired struct{}

func (e ErrTokenExpired) Error() string {
	return "tenant: token has expired"
}

// ErrMissingTenantClaim indicates the JWT token is missing the tenant_id claim.
type ErrMissingTenantClaim struct{}

func (e ErrMissingTenantClaim) Error() string {
	return "tenant: token missing tenant_id claim"
}

// ErrMissingUserClaim indicates the JWT token is missing the user_id claim.
type ErrMissingUserClaim struct{}

func (e ErrMissingUserClaim) Error() string {
	return "tenant: token missing user_id claim"
}

// ErrInvalidConfig indicates an invalid middleware configuration.
type ErrInvalidConfig struct {
	Field  string
	Reason string
}

func (e ErrInvalidConfig) Error() string {
	if e.Reason != "" {
		return fmt.Sprintf("tenant: invalid configuration for %s: %s", e.Field, e.Reason)
	}
	return fmt.Sprintf("tenant: invalid configuration for %s", e.Field)
}
