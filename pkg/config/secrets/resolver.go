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

// Package secrets provides secret resolution for configuration values that
// reference encrypted or externally stored secrets. It supports multiple
// resolution schemes including encrypted values, environment variables,
// and external secret stores.
package secrets

import (
	"context"
	"time"
)

// SecretValue represents a resolved secret with metadata.
type SecretValue struct {
	// Value is the decrypted/resolved secret value.
	Value []byte

	// ExpiresAt indicates when this secret value expires and should be re-resolved.
	// Zero time means no expiration.
	ExpiresAt time.Time

	// Source indicates where the secret was resolved from (e.g., "idevid", "env", "vault").
	Source string

	// Version is an optional version identifier for the secret.
	Version string
}

// SecretResolver resolves configuration values that reference secrets.
// Implementations handle specific URI schemes (e.g., "idevid:", "env:", "vault:").
type SecretResolver interface {
	// Scheme returns the URI scheme this resolver handles (e.g., "idevid").
	Scheme() string

	// CanResolve returns true if this resolver can handle the given raw value.
	// This allows resolvers to use pattern matching beyond simple scheme prefix.
	CanResolve(raw string) bool

	// Resolve decrypts or retrieves the secret value from the raw configuration string.
	// The context allows for cancellation and timeout handling.
	Resolve(ctx context.Context, raw string) (*SecretValue, error)
}

// Clear securely zeros out the secret value from memory.
// This should be called when the secret is no longer needed.
func (sv *SecretValue) Clear() {
	if sv == nil || sv.Value == nil {
		return
	}
	for i := range sv.Value {
		sv.Value[i] = 0
	}
	sv.Value = nil
}

// IsExpired returns true if the secret value has expired.
func (sv *SecretValue) IsExpired() bool {
	if sv == nil || sv.ExpiresAt.IsZero() {
		return false
	}
	return time.Now().After(sv.ExpiresAt)
}

// String returns the secret value as a string.
// Note: This creates a copy - the caller should zero it when done.
func (sv *SecretValue) String() string {
	if sv == nil || sv.Value == nil {
		return ""
	}
	return string(sv.Value)
}
