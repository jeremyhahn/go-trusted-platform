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

package app

import (
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestApp_ParsePINs_DefaultPasswordWithoutDebugSecrets covers the branch where
// DebugSecretsFlag=false with default password — the PINs are regenerated but
// the debug logging branch is skipped.
func TestApp_ParsePINs_DefaultPasswordWithoutDebugSecrets(t *testing.T) {
	logger := logging.DefaultLogger()
	app := &App{DebugFlag: true, DebugSecretsFlag: false, Logger: logger}

	soPIN, userPIN, err := app.ParsePINs(
		[]byte(xkmssdk.DEFAULT_PASSWORD), []byte(xkmssdk.DEFAULT_PASSWORD))
	require.NoError(t, err)

	// PINs should be regenerated
	assert.NotEqual(t, []byte(xkmssdk.DEFAULT_PASSWORD), soPIN.Bytes())
	assert.NotEqual(t, []byte(xkmssdk.DEFAULT_PASSWORD), userPIN.Bytes())
	assert.NotEmpty(t, soPIN.Bytes())
	assert.NotEmpty(t, userPIN.Bytes())
}

// TestApp_ParsePINs_EmptyBytes verifies behavior with empty byte slices (not nil, not default).
func TestApp_ParsePINs_EmptyBytes(t *testing.T) {
	logger := logging.DefaultLogger()
	app := &App{DebugFlag: true, Logger: logger}

	soPIN, userPIN, err := app.ParsePINs([]byte{}, []byte{})
	require.NoError(t, err)
	// Empty bytes are not the default password, so they pass through unchanged
	assert.Empty(t, soPIN.Bytes())
	assert.Empty(t, userPIN.Bytes())
}
