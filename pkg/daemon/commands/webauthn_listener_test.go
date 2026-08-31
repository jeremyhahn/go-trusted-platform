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

package commands

import (
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	v1 "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestListenerWebAuthnConfig_MatchingRPRegisters proves a listener whose
// RP ID matches the SDK's single relying party gets its handler config.
func TestListenerWebAuthnConfig_MatchingRPRegisters(t *testing.T) {
	ws := &v1.Config{WebAuthn: &v1.WebAuthn{
		RPID:          "cp.trusted-platform.io",
		RPDisplayName: "Trusted Platform",
		RPOrigins:     []string{"https://cp.trusted-platform.io:8443"},
	}}
	cfg := listenerWebAuthnConfig(ws, "cp.trusted-platform.io", logging.DefaultLogger())
	require.NotNil(t, cfg)
	assert.Equal(t, "cp.trusted-platform.io", cfg.RPID)
	assert.Equal(t, []string{"https://cp.trusted-platform.io:8443"}, cfg.RPOrigins)
}

// TestListenerWebAuthnConfig_DivergentRPDisabled proves a listener whose
// RP ID differs from the SDK's single relying party has its WebAuthn
// routes explicitly disabled (nil config): every ceremony on it would fail
// in the browser, so a visible deterministic disable replaces a
// user-discovered failure.
func TestListenerWebAuthnConfig_DivergentRPDisabled(t *testing.T) {
	ws := &v1.Config{WebAuthn: &v1.WebAuthn{
		RPID:      "cp.trusted-platform.internal",
		RPOrigins: []string{"https://cp.trusted-platform.internal"},
	}}
	assert.Nil(t, listenerWebAuthnConfig(ws, "cp.trusted-platform.io", logging.DefaultLogger()))
}

// TestListenerWebAuthnConfig_NoWebAuthnOrNilConfig proves listeners
// without WebAuthn (and a nil listener) yield nil without error, and that
// an empty SDK RP (no mirror ran — e.g. lean builds) leaves the listener's
// own config in force.
func TestListenerWebAuthnConfig_NoWebAuthnOrNilConfig(t *testing.T) {
	assert.Nil(t, listenerWebAuthnConfig(nil, "cp.trusted-platform.io", logging.DefaultLogger()))
	assert.Nil(t, listenerWebAuthnConfig(&v1.Config{}, "cp.trusted-platform.io", logging.DefaultLogger()))

	ws := &v1.Config{WebAuthn: &v1.WebAuthn{RPID: "cp.trusted-platform.io"}}
	cfg := listenerWebAuthnConfig(ws, "", logging.DefaultLogger())
	require.NotNil(t, cfg, "an empty SDK RP must not disable listeners")
	assert.Equal(t, "cp.trusted-platform.io", cfg.RPID)
}
