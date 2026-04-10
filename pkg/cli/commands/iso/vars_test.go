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

package iso

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestVars_InitialValues(t *testing.T) {
	// Test that package-level variables have expected initial values
	// These should be nil/empty when the package is first loaded
	assert.Nil(t, App, "App should be nil initially")
	assert.Nil(t, InitParams, "InitParams should be nil initially")
	assert.Empty(t, configFile, "configFile should be empty initially")
	assert.Empty(t, workDir, "workDir should be empty initially")
	assert.False(t, debug, "debug should be false initially")
	assert.False(t, verbose, "verbose should be false initially")
}

func TestVars_CanBeSet(t *testing.T) {
	// Test that package-level variables can be modified
	// Save original values
	origConfigFile := configFile
	origWorkDir := workDir
	origDebug := debug
	origVerbose := verbose

	// Modify values
	configFile = "/test/config.yaml"
	workDir = "/test/work"
	debug = true
	verbose = true

	// Verify modifications
	assert.Equal(t, "/test/config.yaml", configFile)
	assert.Equal(t, "/test/work", workDir)
	assert.True(t, debug)
	assert.True(t, verbose)

	// Restore original values
	configFile = origConfigFile
	workDir = origWorkDir
	debug = origDebug
	verbose = origVerbose
}
