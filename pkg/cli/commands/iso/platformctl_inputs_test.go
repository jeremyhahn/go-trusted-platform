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
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	pkgiso "github.com/jeremyhahn/go-trusted-platform/pkg/iso"
)

func TestNamePlatformctlBinaries_DefaultsToThisPlatformctl(t *testing.T) {
	config := pkgiso.DefaultISOBuildConfig()
	config.PlatformdBinary = filepath.Join(t.TempDir(), "platformd")

	require.NoError(t, namePlatformctlBinaries(config, "", ""))

	self, err := os.Executable()
	require.NoError(t, err)
	self, err = filepath.EvalSymlinks(self)
	require.NoError(t, err)
	assert.Equal(t, self, config.PlatformctlBinary, "the running platformctl, not one beside platformd")
	assert.Empty(t, config.PlatformctlStaticBinary, "unset: not installed, and not inferred")
}

func TestNamePlatformctlBinaries_FlagsWin(t *testing.T) {
	config := pkgiso.DefaultISOBuildConfig()
	config.PlatformctlBinary = "/from/config/platformctl"

	require.NoError(t, namePlatformctlBinaries(config, "/flag/platformctl", "/flag/platformctl-static"))
	assert.Equal(t, "/flag/platformctl", config.PlatformctlBinary)
	assert.Equal(t, "/flag/platformctl-static", config.PlatformctlStaticBinary)
}

func TestNamePlatformctlBinaries_KeepsConfigFileValues(t *testing.T) {
	config := pkgiso.DefaultISOBuildConfig()
	config.PlatformctlBinary = "/from/config/platformctl"
	config.PlatformctlStaticBinary = "/from/config/platformctl-static"

	require.NoError(t, namePlatformctlBinaries(config, "", ""))
	assert.Equal(t, "/from/config/platformctl", config.PlatformctlBinary)
	assert.Equal(t, "/from/config/platformctl-static", config.PlatformctlStaticBinary)
}
