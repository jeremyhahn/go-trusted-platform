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
	"context"
	"debug/elf"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/diskimage/diskimagetest"
	pkgiso "github.com/jeremyhahn/go-trusted-platform/pkg/iso"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
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

// writeConfigFile writes an iso create --config file and returns its path.
func writeConfigFile(t *testing.T, content string) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "iso.yaml")
	require.NoError(t, os.WriteFile(path, []byte(content), 0o600))
	return path
}

func TestMergeConfigFile_DefaultsToThisPlatformctl(t *testing.T) {
	placeSiblingPlatformd(t)
	flags := &createFlags{configFile: writeConfigFile(t, "{}\n")}

	config, err := mergeConfigFile(pkgiso.DefaultISOBuildConfig(), flags)
	require.NoError(t, err)

	self, err := os.Executable()
	require.NoError(t, err)
	self, err = filepath.EvalSymlinks(self)
	require.NoError(t, err)
	assert.Equal(t, self, config.PlatformctlBinary, "a config file without the field still gets the running platformctl")
}

func TestMergeConfigFile_KeepsConfigFileValues(t *testing.T) {
	placeSiblingPlatformd(t)
	flags := &createFlags{configFile: writeConfigFile(t,
		"platformctl-binary: /from/config/platformctl\nplatformctl-static-binary: /from/config/platformctl-static\n")}

	config, err := mergeConfigFile(pkgiso.DefaultISOBuildConfig(), flags)
	require.NoError(t, err)
	assert.Equal(t, "/from/config/platformctl", config.PlatformctlBinary)
	assert.Equal(t, "/from/config/platformctl-static", config.PlatformctlStaticBinary)
}

func TestMergeConfigFile_FlagsWin(t *testing.T) {
	placeSiblingPlatformd(t)
	flags := &createFlags{
		configFile: writeConfigFile(t,
			"platformctl-binary: /from/config/platformctl\nplatformctl-static-binary: /from/config/platformctl-static\n"),
		platformctlPath:       "/flag/platformctl",
		platformctlStaticPath: "/flag/platformctl-static",
	}

	config, err := mergeConfigFile(pkgiso.DefaultISOBuildConfig(), flags)
	require.NoError(t, err)
	assert.Equal(t, "/flag/platformctl", config.PlatformctlBinary)
	assert.Equal(t, "/flag/platformctl-static", config.PlatformctlStaticBinary)
}

func TestMergeConfigFile_MissingFile(t *testing.T) {
	flags := &createFlags{configFile: filepath.Join(t.TempDir(), "absent.yaml")}

	_, err := mergeConfigFile(pkgiso.DefaultISOBuildConfig(), flags)
	var wrapped *WrappedError
	require.ErrorAs(t, err, &wrapped)
}

// cliStageBuild is the build `iso create --config` merges for staging: the
// config file names platformd; platformctl and platformctl-static come from
// the flags.
func cliStageBuild(t *testing.T, flags *createFlags) (*pkgiso.ISOBuildConfig, error) {
	t.Helper()
	flags.configFile = stagingConfigFile(t)
	config := pkgiso.DefaultISOBuildConfig()
	config.SecureBoot = false
	return mergeConfigFile(config, flags)
}

// stagingConfigFile writes a build config naming a static platformd and a
// platform config, everything StageInstallMedia needs besides platformctl.
func stagingConfigFile(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	platformd := filepath.Join(dir, "platformd")
	diskimagetest.WriteELF(t, platformd, elf.EM_X86_64)
	platformConfig := filepath.Join(dir, "platform.yaml")
	require.NoError(t, os.WriteFile(platformConfig, []byte("os:\n  hostname: node\nseal-pcrs: [0, 7, 9]\nsecure-boot:\n  enabled: false\n"), 0o600))
	return writeConfigFile(t, "architecture: x86_64\n"+
		"work-dir: "+t.TempDir()+"\n"+
		"platform-version: 1.0.0-test\n"+
		"platform-config-file: "+platformConfig+"\n"+
		"platformd-binary: "+platformd+"\n"+
		"pre-fetch: false\n")
}

// platformctlStagers resolve the build config the way each verb does from
// its --platformctl-binary and --platformctl-static-binary flags.
var platformctlStagers = map[string]func(t *testing.T, platformctl, static string) (*pkgiso.ISOBuildConfig, error){
	"create": func(t *testing.T, platformctl, static string) (*pkgiso.ISOBuildConfig, error) {
		return cliStageBuild(t, &createFlags{platformctlPath: platformctl, platformctlStaticPath: static})
	},
	"customize": func(t *testing.T, platformctl, static string) (*pkgiso.ISOBuildConfig, error) {
		return customizeBuildConfig(&customizeFlags{
			configFile:            stagingConfigFile(t),
			platformctlPath:       platformctl,
			platformctlStaticPath: static,
		})
	},
}

// TestStaging_NoStaticRejectsDynamicPlatformctl drives the iso create and
// iso customize inputs into staging with a dynamically linked platformctl (a
// desktop glibc build) and no static installer: the build fails rather than
// ship an installer Alpine cannot run (#1152).
func TestStaging_NoStaticRejectsDynamicPlatformctl(t *testing.T) {
	for verb, stage := range platformctlStagers {
		t.Run(verb, func(t *testing.T) {
			platformctl := filepath.Join(t.TempDir(), "platformctl")
			diskimagetest.WriteDynamicELF(t, platformctl, elf.EM_X86_64)
			config, err := stage(t, platformctl, "")
			require.NoError(t, err)
			require.Empty(t, config.PlatformctlStaticBinary)

			_, err = pkgiso.StageInstallMedia(context.Background(), config, "media", pkgiso.InstallerOverrides{}, nil, logging.DefaultLogger())
			var dynamic *pkgiso.DynamicBinaryError
			require.ErrorAs(t, err, &dynamic)
			assert.Equal(t, platformctl, dynamic.Path)
		})
	}
}

// TestStaging_StaticFlagAcceptsDynamicPlatformctl supplies a static installer
// beside the dynamic platformctl through --platformctl-static-binary, as the
// iso integration suite does for iso customize (Codex 8120): the media
// carries both.
func TestStaging_StaticFlagAcceptsDynamicPlatformctl(t *testing.T) {
	for verb, stage := range platformctlStagers {
		t.Run(verb, func(t *testing.T) {
			bins := t.TempDir()
			platformctl := filepath.Join(bins, "platformctl")
			diskimagetest.WriteDynamicELF(t, platformctl, elf.EM_X86_64)
			static := filepath.Join(bins, "platformctl-static")
			diskimagetest.WriteELF(t, static, elf.EM_X86_64)
			config, err := stage(t, platformctl, static)
			require.NoError(t, err)
			assert.Equal(t, static, config.PlatformctlStaticBinary)

			media, err := pkgiso.StageInstallMedia(context.Background(), config, "media", pkgiso.InstallerOverrides{}, nil, logging.DefaultLogger())
			require.NoError(t, err)
			assert.FileExists(t, filepath.Join(media.Dir, "platformd-bin", "platformctl"))
			assert.FileExists(t, filepath.Join(media.Dir, "platformd-bin", "platformctl-static"))
		})
	}
}

// builderStage maps cfg through the shared ISO builder (`iso test
// client-server`) and stages the install media from the result.
func builderStage(t *testing.T, cfg *ISOBuilderConfig) (*pkgiso.InstallMedia, error) {
	t.Helper()
	dir := t.TempDir()
	platformd := filepath.Join(dir, "platformd")
	diskimagetest.WriteELF(t, platformd, elf.EM_X86_64)
	platformConfig := filepath.Join(dir, "platform.yaml")
	require.NoError(t, os.WriteFile(platformConfig, []byte("os:\n  hostname: node\nseal-pcrs: [0, 7, 9]\nsecure-boot:\n  enabled: false\n"), 0o600))
	cfg.WorkDir = t.TempDir()

	config, err := newBuilderISOBuildConfig(cfg, platformd)
	require.NoError(t, err)
	config.Architecture = "x86_64"
	config.PlatformVersion = "1.0.0-test"
	config.PlatformConfigFile = platformConfig
	return pkgiso.StageInstallMedia(context.Background(), config, "media", pkgiso.InstallerOverrides{}, nil, logging.DefaultLogger())
}

// A dynamically linked platformctl is accepted by the shared builder when a
// static installer is supplied beside it (Codex review on #1152).
func TestBuilderStaging_StaticInstallerAcceptsDynamicPlatformctl(t *testing.T) {
	bins := t.TempDir()
	platformctl := filepath.Join(bins, "platformctl")
	diskimagetest.WriteDynamicELF(t, platformctl, elf.EM_X86_64)
	static := filepath.Join(bins, "platformctl-static")
	diskimagetest.WriteELF(t, static, elf.EM_X86_64)

	media, err := builderStage(t, &ISOBuilderConfig{PlatformctlBinary: platformctl, PlatformctlStaticBinary: static})
	require.NoError(t, err)
	assert.FileExists(t, filepath.Join(media.Dir, "platformd-bin", "platformctl"))
	assert.FileExists(t, filepath.Join(media.Dir, "platformd-bin", "platformctl-static"))
}

func TestBuilderStaging_NoStaticRejectsDynamicPlatformctl(t *testing.T) {
	platformctl := filepath.Join(t.TempDir(), "platformctl")
	diskimagetest.WriteDynamicELF(t, platformctl, elf.EM_X86_64)

	_, err := builderStage(t, &ISOBuilderConfig{PlatformctlBinary: platformctl})
	var dynamic *pkgiso.DynamicBinaryError
	require.ErrorAs(t, err, &dynamic)
	assert.Equal(t, platformctl, dynamic.Path)
}
