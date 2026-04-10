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

package attestation

import (
	"context"
	"sync"
	"time"
)

// Guard verifies attestation requirements for DNS operations.
type Guard struct {
	// defaultConfig is the default attestation configuration
	defaultConfig *ZoneAttestationConfig

	// zoneConfigs maps zone names to their attestation configurations
	zoneConfigs sync.Map
}

// NewGuard creates a new attestation guard.
func NewGuard(defaultConfig *ZoneAttestationConfig) *Guard {
	if defaultConfig == nil {
		defaultConfig = DefaultZoneAttestationConfig()
	}
	return &Guard{
		defaultConfig: defaultConfig,
	}
}

// SetZoneConfig sets the attestation configuration for a specific zone.
func (g *Guard) SetZoneConfig(zoneName string, config *ZoneAttestationConfig) {
	if config == nil {
		g.zoneConfigs.Delete(zoneName)
		return
	}
	g.zoneConfigs.Store(zoneName, config)
}

// GetZoneConfig returns the attestation configuration for a zone.
func (g *Guard) GetZoneConfig(zoneName string) *ZoneAttestationConfig {
	if config, ok := g.zoneConfigs.Load(zoneName); ok {
		return config.(*ZoneAttestationConfig)
	}
	return g.defaultConfig
}

// RemoveZoneConfig removes the attestation configuration for a specific zone.
func (g *Guard) RemoveZoneConfig(zoneName string) {
	g.zoneConfigs.Delete(zoneName)
}

// DefaultConfig returns the default attestation configuration.
func (g *Guard) DefaultConfig() *ZoneAttestationConfig {
	return g.defaultConfig
}

// GuardResult contains the result of attestation verification.
type GuardResult struct {
	Allowed bool
	Token   *AttestationToken
	Error   error
	Message string
}

// VerifyForUpdate verifies attestation requirements for a DNS update operation.
func (g *Guard) VerifyForUpdate(
	ctx context.Context,
	zoneName string,
	recordType string,
	token *AttestationToken,
) *GuardResult {
	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return &GuardResult{
			Allowed: false,
			Error:   ErrServiceUnavailable{Reason: "context canceled", Err: err},
			Message: "context canceled",
		}
	}

	config := g.GetZoneConfig(zoneName)

	// If attestation not required, allow
	if !config.Required {
		return &GuardResult{Allowed: true, Message: "attestation not required"}
	}

	// Attestation required but no token provided
	if token == nil {
		return &GuardResult{
			Allowed: false,
			Error:   ErrAttestationRequired{Zone: zoneName},
			Message: "attestation token required for zone updates",
		}
	}

	// Check token expiration
	if token.IsExpired() {
		return &GuardResult{
			Allowed: false,
			Token:   token,
			Error:   ErrAttestationExpired{DeviceID: token.DeviceID, ExpiredAt: token.Expires.Format(time.RFC3339)},
			Message: "attestation token has expired, please re-attest",
		}
	}

	// Check max age
	age := time.Since(token.Issued)
	if age > config.MaxAge {
		return &GuardResult{
			Allowed: false,
			Token:   token,
			Error:   ErrAttestationTooOld{Age: age.String(), MaxAge: config.MaxAge.String()},
			Message: "attestation evidence is too old",
		}
	}

	// Check if operation is allowed
	if !g.isOperationAllowed(token, recordType) {
		return &GuardResult{
			Allowed: false,
			Token:   token,
			Error:   ErrOperationNotAllowed{Operation: recordType, AllowedOperations: token.AllowedOperations},
			Message: "operation not permitted by attestation token",
		}
	}

	// Check if zone is allowed
	if !g.isZoneAllowed(token, zoneName) {
		return &GuardResult{
			Allowed: false,
			Token:   token,
			Error:   ErrZoneNotAllowed{Zone: zoneName, AllowedZones: token.AllowedZones},
			Message: "zone not permitted by attestation token",
		}
	}

	return &GuardResult{
		Allowed: true,
		Token:   token,
		Message: "attestation verified",
	}
}

// isOperationAllowed checks if the given operation is allowed by the token.
func (g *Guard) isOperationAllowed(token *AttestationToken, operation string) bool {
	for _, op := range token.AllowedOperations {
		if op == operation || op == "*" {
			return true
		}
	}
	return false
}

// isZoneAllowed checks if the given zone is allowed by the token.
func (g *Guard) isZoneAllowed(token *AttestationToken, zone string) bool {
	for _, z := range token.AllowedZones {
		if z == zone || z == "*" {
			return true
		}
	}
	return false
}

// VerifyForQuery verifies attestation requirements for a DNS query operation.
// This is typically less restrictive than update verification.
func (g *Guard) VerifyForQuery(
	ctx context.Context,
	zoneName string,
	recordType string,
	token *AttestationToken,
) *GuardResult {
	// Check context cancellation
	if err := ctx.Err(); err != nil {
		return &GuardResult{
			Allowed: false,
			Error:   ErrServiceUnavailable{Reason: "context canceled", Err: err},
			Message: "context canceled",
		}
	}

	config := g.GetZoneConfig(zoneName)

	// If attestation not required, allow queries without token
	if !config.Required {
		return &GuardResult{Allowed: true, Message: "attestation not required for queries"}
	}

	// For queries, we may allow without token if configured
	if token == nil {
		// Queries typically don't require attestation, but log for audit
		return &GuardResult{Allowed: true, Message: "query allowed without attestation"}
	}

	// If token is provided, validate it
	if token.IsExpired() {
		// For queries, we might still allow with expired token but warn
		return &GuardResult{
			Allowed: true,
			Token:   token,
			Message: "query allowed with expired attestation token",
		}
	}

	return &GuardResult{
		Allowed: true,
		Token:   token,
		Message: "query with valid attestation",
	}
}

// ZoneCount returns the number of zone-specific configurations.
func (g *Guard) ZoneCount() int {
	count := 0
	g.zoneConfigs.Range(func(_, _ any) bool {
		count++
		return true
	})
	return count
}
