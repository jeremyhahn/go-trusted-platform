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
)

// placeSiblingPlatformd writes a platformd beside the running test binary,
// where iso create looks for it, and removes it when the test ends.
func placeSiblingPlatformd(t *testing.T) string {
	t.Helper()
	self, err := selfBinary()
	require.NoError(t, err)
	path := filepath.Join(filepath.Dir(self), "platformd")
	require.NoError(t, os.WriteFile(path, []byte("platformd"), 0o600))
	t.Cleanup(func() { require.NoError(t, os.Remove(path)) })
	return path
}

// configPlatformd writes a platformd outside the test binary's directory, for
// a --config file to name.
func configPlatformd(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "platformd")
	require.NoError(t, os.WriteFile(path, []byte("platformd"), 0o600))
	return path
}

func TestBuildISOBuildConfig_ConfigFileWithoutPlatformdUsesSibling(t *testing.T) {
	sibling := placeSiblingPlatformd(t)
	flags := &createFlags{configFile: writeConfigFile(t, "{}\n")}

	config, err := buildISOBuildConfig(flags)
	require.NoError(t, err)
	assert.Equal(t, sibling, config.PlatformdBinary, "a config file without the field still gets the platformd beside platformctl")
}

func TestBuildISOBuildConfig_ConfigFilePlatformdWins(t *testing.T) {
	placeSiblingPlatformd(t)
	fromConfig := configPlatformd(t)
	flags := &createFlags{configFile: writeConfigFile(t, "platformd-binary: "+fromConfig+"\n")}

	config, err := buildISOBuildConfig(flags)
	require.NoError(t, err)
	assert.Equal(t, fromConfig, config.PlatformdBinary)
}

func TestBuildISOBuildConfig_ConfigFilePlatformdNeedsNoSibling(t *testing.T) {
	fromConfig := configPlatformd(t)
	flags := &createFlags{configFile: writeConfigFile(t, "platformd-binary: "+fromConfig+"\n")}

	config, err := buildISOBuildConfig(flags)
	require.NoError(t, err)
	assert.Equal(t, fromConfig, config.PlatformdBinary)
}

func TestBuildISOBuildConfig_NoPlatformdAnywhere(t *testing.T) {
	flags := &createFlags{configFile: writeConfigFile(t, "{}\n")}

	_, err := buildISOBuildConfig(flags)
	var missing *MessageError
	require.ErrorAs(t, err, &missing)
}
