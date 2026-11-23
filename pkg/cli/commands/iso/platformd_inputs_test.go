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

	"github.com/jeremyhahn/go-trusted-platform/pkg/cli"
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

func TestBuildISOBuildConfig_DefaultTemplateFromPlatformConfigDir(t *testing.T) {
	placeSiblingPlatformd(t)
	dir := t.TempDir()
	tmpl := filepath.Join(dir, "templates", "single-node", "default.yaml")
	require.NoError(t, os.MkdirAll(filepath.Dir(tmpl), 0o750))
	require.NoError(t, os.WriteFile(tmpl, []byte("{}\n"), 0o600))
	t.Setenv("PLATFORM_CONFIG_DIR", dir)
	flags := &createFlags{configFile: writeConfigFile(t, "{}\n"), platformType: "server"}

	config, err := buildISOBuildConfig(flags)
	require.NoError(t, err)
	assert.Equal(t, tmpl, config.PlatformConfigFile)
}

func TestBuildISOBuildConfig_PlatformConfigDirWithoutTemplateFails(t *testing.T) {
	placeSiblingPlatformd(t)
	t.Setenv("PLATFORM_CONFIG_DIR", t.TempDir())
	flags := &createFlags{configFile: writeConfigFile(t, "{}\n"), platformType: "server"}

	_, err := buildISOBuildConfig(flags)
	var missing *cli.ErrPlatformTemplateMissing
	require.ErrorAs(t, err, &missing)
}

// A build file that sets only config-server-url is a dynamic-only build
// (docs/installer/iso-building.md, Config Delivery Modes, mode 3): the
// PLATFORM_CONFIG_DIR default must not turn it into a hybrid build.
func TestBuildISOBuildConfig_ConfigFileDynamicOnlyKeepsEmptyTemplate(t *testing.T) {
	placeSiblingPlatformd(t)
	dir := t.TempDir()
	tmpl := filepath.Join(dir, "templates", "single-node", "default.yaml")
	require.NoError(t, os.MkdirAll(filepath.Dir(tmpl), 0o750))
	require.NoError(t, os.WriteFile(tmpl, []byte("{}\n"), 0o600))
	t.Setenv("PLATFORM_CONFIG_DIR", dir)
	flags := &createFlags{
		configFile:   writeConfigFile(t, "config-server-url: https://config.example\n"),
		platformType: "server",
	}

	config, err := buildISOBuildConfig(flags)
	require.NoError(t, err)
	assert.Equal(t, "", config.PlatformConfigFile, "a dynamic-only build file keeps an empty template")
	assert.True(t, config.IsDynamicConfigMode())
}

// A dynamic-only build bakes no template, so a PLATFORM_CONFIG_DIR without
// the default template is no reason to refuse it.
func TestBuildISOBuildConfig_ConfigFileDynamicOnlyNeedsNoDefault(t *testing.T) {
	placeSiblingPlatformd(t)
	t.Setenv("PLATFORM_CONFIG_DIR", t.TempDir())
	flags := &createFlags{
		configFile:   writeConfigFile(t, "config-server-url: https://config.example\n"),
		platformType: "server",
	}

	config, err := buildISOBuildConfig(flags)
	require.NoError(t, err)
	assert.Equal(t, "", config.PlatformConfigFile)
}

// A build file that names its own template needs no default template.
func TestBuildISOBuildConfig_ConfigFileTemplateNeedsNoDefault(t *testing.T) {
	placeSiblingPlatformd(t)
	t.Setenv("PLATFORM_CONFIG_DIR", t.TempDir())
	flags := &createFlags{
		configFile:   writeConfigFile(t, "platform-config-file: /cfg/own.yaml\n"),
		platformType: "server",
	}

	config, err := buildISOBuildConfig(flags)
	require.NoError(t, err)
	assert.Equal(t, "/cfg/own.yaml", config.PlatformConfigFile)
}

// An explicit --platform-config fills a build file that names no template,
// and needs no default template.
func TestBuildISOBuildConfig_ExplicitTemplateFillsConfigFileGap(t *testing.T) {
	placeSiblingPlatformd(t)
	t.Setenv("PLATFORM_CONFIG_DIR", t.TempDir())
	flags := &createFlags{
		configFile:     writeConfigFile(t, "{}\n"),
		platformConfig: "/cfg/flag.yaml",
		platformType:   "server",
	}

	config, err := buildISOBuildConfig(flags)
	require.NoError(t, err)
	assert.Equal(t, "/cfg/flag.yaml", config.PlatformConfigFile)
}
