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

// Package auth provides authentication providers for the platform SDK.
//
// This package defines a Provider interface and concrete implementations for
// different authentication mechanisms:
//
//   - TokenProvider: JWT or API token-based authentication with automatic refresh
//   - MTLSProvider: Mutual TLS authentication using client certificates
//   - NoneProvider: No authentication (for testing or local Unix socket)
//
// # Usage
//
// Create a token provider with automatic refresh:
//
//	provider := auth.NewTokenProvider(
//	    auth.WithToken("your-jwt-token"),
//	    auth.WithRefreshCallback(func(ctx context.Context) (string, error) {
//	        // Refresh logic here
//	        return newToken, nil
//	    }),
//	)
//
// Create an mTLS provider:
//
//	provider, err := auth.NewMTLSProvider(
//	    auth.WithCertFile("/path/to/client.crt"),
//	    auth.WithKeyFile("/path/to/client.key"),
//	    auth.WithCAFile("/path/to/ca.crt"),
//	)
//
// Use the provider with a platform client:
//
//	client, err := platform.NewClient(ctx,
//	    platform.WithAuthProvider(provider),
//	)
//
// # Thread Safety
//
// All providers are safe for concurrent use. Token operations use atomic
// operations to ensure thread safety without locks.
package auth
