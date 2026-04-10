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

package auth

import (
	"context"
	"crypto/tls"
)

// AuthType represents the type of authentication.
type AuthType string

const (
	// AuthTypeNone indicates no authentication.
	AuthTypeNone AuthType = "none"

	// AuthTypeToken indicates token-based authentication (JWT or API token).
	AuthTypeToken AuthType = "token"

	// AuthTypeMTLS indicates mutual TLS authentication.
	AuthTypeMTLS AuthType = "mtls"
)

// String returns the string representation of the auth type.
func (t AuthType) String() string {
	return string(t)
}

// Provider defines the authentication interface for the platform SDK.
// All implementations must be safe for concurrent use.
type Provider interface {
	// GetToken returns an authentication token for requests.
	// Returns ErrNoToken if no token is available for this provider type.
	GetToken(ctx context.Context) (string, error)

	// GetTLSConfig returns TLS configuration for mTLS.
	// Returns nil if this provider does not use TLS client certificates.
	GetTLSConfig() *tls.Config

	// Refresh refreshes authentication credentials.
	// For token providers, this obtains a new token.
	// For mTLS providers, this reloads certificates.
	// Returns ErrNoRefreshCallback if refresh is not supported.
	Refresh(ctx context.Context) error

	// IsExpired checks if credentials are expired.
	// For token providers, this checks the JWT exp claim.
	// For mTLS providers, this checks certificate validity.
	// Returns false for providers without expiration (e.g., API tokens).
	IsExpired() bool

	// Type returns the authentication type.
	Type() AuthType
}

// RefreshCallback is a function type for token refresh operations.
// It receives a context and returns a new token or an error.
type RefreshCallback func(ctx context.Context) (string, error)
