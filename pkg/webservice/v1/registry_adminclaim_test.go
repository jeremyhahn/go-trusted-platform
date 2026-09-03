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

package v1

import (
	"bytes"
	"log/slog"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// capturingRegistry builds a HandlerRegistry whose logger writes into the
// returned buffer, so a test can tell WHICH guard refused the handler
// rather than only that the result was nil.
func capturingRegistry(t *testing.T, cfg *Config) (*HandlerRegistry, *bytes.Buffer) {
	t.Helper()

	var captured bytes.Buffer
	return &HandlerRegistry{
		params: RegistryParams{
			Logger:           logging.NewLogger(slog.LevelDebug, &captured),
			WebServiceConfig: cfg,
			TenantID:         "system",
		},
	}, &captured
}

// TestAdminClaimRestHandler_RefusedWhenTheSeamIsTheBrokerValidator pins the
// fail-closed gate: the claim ceremony completes by minting a platform-local
// JWT, and when JWT.PlatformToken.Enabled makes the broker validator the
// inbound seam, that JWT is rejected by every protected route. Handing the
// operator a session the same server refuses is worse than not offering the
// flow, so the routes stay unregistered.
//
// Converging the two token types is #202 (owner ruling 2026-09-02), not
// this gate.
func TestAdminClaimRestHandler_RefusedWhenTheSeamIsTheBrokerValidator(t *testing.T) {
	cfg := &Config{}
	cfg.JWT.PlatformToken.Enabled = true
	cfg.JWT.PlatformToken.Issuer = "https://broker.example.com"
	cfg.JWT.PlatformToken.JWKSURL = "https://broker.example.com/.well-known/jwks.json"

	registry, captured := capturingRegistry(t, cfg)

	assert.Nil(t, registry.AdminClaimRestHandler())
	require.Contains(t, captured.String(), "admin-claim routes not registered",
		"the refusal must be reported")
	assert.Contains(t, captured.String(), "PlatformToken",
		"the seam, not a missing dependency, must be the reported reason")
	assert.Contains(t, captured.String(), "#202",
		"the reason must point at the issue that resolves it")
}

// TestAdminClaimRestHandler_SeamGateDoesNotFireOnTheDefaultConfig is the
// positive control: with the default seam the gate must not be what stops
// the handler. Registration still fails here — nothing else is wired — but
// it fails for the SDK clients, further down the function, which proves the
// seam gate let execution through.
func TestAdminClaimRestHandler_SeamGateDoesNotFireOnTheDefaultConfig(t *testing.T) {
	registry, captured := capturingRegistry(t, &Config{})

	assert.Nil(t, registry.AdminClaimRestHandler())
	assert.Contains(t, captured.String(), "SDK auth clients are not wired",
		"execution must reach the dependency checks past the seam gate")
	assert.NotContains(t, captured.String(), "#202",
		"the seam gate must not fire when the default seam is in use")
}

// TestAdminClaimRestHandler_SeamGateIsSkippedWithoutAWebServiceConfig
// covers the nil-config path: no config means no broker validator, so the
// gate is not what refuses.
func TestAdminClaimRestHandler_SeamGateIsSkippedWithoutAWebServiceConfig(t *testing.T) {
	registry, captured := capturingRegistry(t, nil)

	assert.Nil(t, registry.AdminClaimRestHandler())
	assert.NotContains(t, captured.String(), "#202")
}
