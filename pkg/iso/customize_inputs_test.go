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
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// customizeInputs are the optional customize inputs (#351): unset means not
// installed, named and present is copied, named and missing fails the build.
var customizeInputs = []struct {
	name string
	dest string
	copy func(c *Customizer, path string) error
}{
	{"platformctl", "platformctl", func(c *Customizer, path string) error {
		return c.CopyPlatformctlBinary(context.Background(), path)
	}},
	{"platformctl-static", "platformctl-static", func(c *Customizer, path string) error {
		return c.CopyPlatformctlStaticBinary(context.Background(), path)
	}},
}

func inputCustomizer(t *testing.T) *Customizer {
	t.Helper()
	work := t.TempDir()
	return NewCustomizer(&PlatformISOConfig{
		Directories: DirectoryConfig{ISO: filepath.Join(work, "iso"), Overlay: filepath.Join(work, "overlay")},
	}, logging.DefaultLogger())
}

func TestCustomizeInput_UnsetIsNotInstalled(t *testing.T) {
	for _, in := range customizeInputs {
		t.Run(in.name, func(t *testing.T) {
			c := inputCustomizer(t)
			require.NoError(t, in.copy(c, ""))
			assert.NoFileExists(t, filepath.Join(c.config.Directories.ISO, "platformd-bin", in.dest))
		})
	}
}

// TestCustomizeInput_UnsetRemovesStaleCopy customizes a tree that already
// holds an input from an earlier run: an input now unset is removed, so the
// media never carries a previous build's binary (#1152).
func TestCustomizeInput_UnsetRemovesStaleCopy(t *testing.T) {
	for _, in := range customizeInputs {
		t.Run(in.name, func(t *testing.T) {
			c := inputCustomizer(t)
			src := filepath.Join(t.TempDir(), in.name)
			diskimagetest.WriteELF(t, src, elf.EM_X86_64)
			require.NoError(t, in.copy(c, src))
			dest := filepath.Join(c.config.Directories.ISO, "platformd-bin", in.dest)
			require.FileExists(t, dest)

			require.NoError(t, in.copy(c, ""))
			assert.NoFileExists(t, dest)
		})
	}
}

func TestCustomizeInput_StaticRejectsDynamicBinary(t *testing.T) {
	c := inputCustomizer(t)
	src := filepath.Join(t.TempDir(), "platformctl")
	diskimagetest.WriteDynamicELF(t, src, elf.EM_X86_64)

	err := c.CopyPlatformctlStaticBinary(context.Background(), src)
	var dynamic *DynamicBinaryError
	require.ErrorAs(t, err, &dynamic)
	assert.Equal(t, src, dynamic.Path)
	assert.Equal(t, "/lib64/ld-linux-x86-64.so.2", dynamic.Interpreter)
	assert.NoFileExists(t, filepath.Join(c.config.Directories.ISO, "platformd-bin", "platformctl-static"))
}

func TestCustomizeInput_NamedAndPresentIsCopied(t *testing.T) {
	for _, in := range customizeInputs {
		t.Run(in.name, func(t *testing.T) {
			c := inputCustomizer(t)
			src := filepath.Join(t.TempDir(), in.name)
			diskimagetest.WriteELF(t, src, elf.EM_X86_64)

			require.NoError(t, in.copy(c, src))
			dest := filepath.Join(c.config.Directories.ISO, "platformd-bin", in.dest)
			want, err := os.ReadFile(src)
			require.NoError(t, err)
			got, err := os.ReadFile(dest)
			require.NoError(t, err)
			assert.Equal(t, want, got)
		})
	}
}

func TestCustomizeInput_NamedAndMissingFails(t *testing.T) {
	for _, in := range customizeInputs {
		t.Run(in.name, func(t *testing.T) {
			c := inputCustomizer(t)
			missing := filepath.Join(t.TempDir(), "absent", in.name)

			err := in.copy(c, missing)
			var missingErr *MissingInputError
			require.ErrorAs(t, err, &missingErr)
			assert.Equal(t, missing, missingErr.Path)
			assert.ErrorIs(t, err, os.ErrNotExist)
			assert.Contains(t, err.Error(), missing)
		})
	}
}

func TestCustomizeInput_InvalidBinaryFails(t *testing.T) {
	for _, in := range customizeInputs {
		t.Run(in.name, func(t *testing.T) {
			c := inputCustomizer(t)
			src := filepath.Join(t.TempDir(), in.name)
			require.NoError(t, os.WriteFile(src, []byte("not a binary"), 0o755))

			err := in.copy(c, src)
			require.Error(t, err)
			var missingErr *MissingInputError
			assert.NotErrorAs(t, err, &missingErr, "the file exists; it is not a missing input")
		})
	}
}

// TestStageInstallMedia_PlatformctlNotInferred pins the removed inference:
// platformctl and platformctl-static beside platformd are not installed
// unless the build names them.
func TestStageInstallMedia_PlatformctlNotInferred(t *testing.T) {
	build := stageBuild(t, elf.EM_X86_64)
	build.PlatformctlBinary = ""
	build.PlatformctlStaticBinary = ""

	media, err := StageInstallMedia(context.Background(), build, "media", InstallerOverrides{}, nil, logging.DefaultLogger())
	require.NoError(t, err)
	assert.FileExists(t, filepath.Join(media.Dir, "platformd-bin", "platformd"))
	assert.NoFileExists(t, filepath.Join(media.Dir, "platformd-bin", "platformctl"))
	assert.NoFileExists(t, filepath.Join(media.Dir, "platformd-bin", "platformctl-static"))
}

func TestUseBinariesDir_NamesAllThree(t *testing.T) {
	build := &ISOBuildConfig{}
	build.UseBinariesDir("/out/aarch64")
	assert.Equal(t, "/out/aarch64/platformd", build.PlatformdBinary)
	assert.Equal(t, "/out/aarch64/platformctl", build.PlatformctlBinary)
	assert.Equal(t, "/out/aarch64/platformctl", build.PlatformctlStaticBinary,
		"with no platformctl-static in the directory, platformctl is the static installer")
}

func TestUseBinariesDir_NamesASuppliedStatic(t *testing.T) {
	bins := t.TempDir()
	diskimagetest.WriteELF(t, filepath.Join(bins, "platformctl-static"), elf.EM_AARCH64)
	build := &ISOBuildConfig{}
	build.UseBinariesDir(bins)
	assert.Equal(t, filepath.Join(bins, "platformctl"), build.PlatformctlBinary)
	assert.Equal(t, filepath.Join(bins, "platformctl-static"), build.PlatformctlStaticBinary)
}

func TestUseBinariesDir_ReachesTheCustomizer(t *testing.T) {
	build := &ISOBuildConfig{}
	build.UseBinariesDir("/out")
	platform := NewPlatformISOConfig(build, t.TempDir()).Platform
	assert.Equal(t, "/out/platformctl", platform.PlatformctlBinary)
	assert.Equal(t, "/out/platformctl", platform.PlatformctlStaticBinary)
}

// TestStageInstallMedia_NativeBuildLayout stages from a directory holding
// exactly what the native `make build` writes to bin/ (Makefile `build`):
// no platformctl-static, only the CGO_ENABLED=0 platformctl. The x86_64
// netboot set stages from that directory (#1152).
func TestStageInstallMedia_NativeBuildLayout(t *testing.T) {
	bins := t.TempDir()
	for _, name := range []string{"platformd", "platformctl", "gatewayd", "deployer-pin"} {
		diskimagetest.WriteELF(t, filepath.Join(bins, name), elf.EM_X86_64)
	}
	build := stageBuild(t, elf.EM_X86_64)
	build.UseBinariesDir(bins)

	media, err := StageInstallMedia(context.Background(), build, "media", InstallerOverrides{}, nil, logging.DefaultLogger())
	require.NoError(t, err)

	want, err := os.ReadFile(filepath.Join(bins, "platformctl"))
	require.NoError(t, err)
	got, err := os.ReadFile(filepath.Join(media.Dir, "platformd-bin", "platformctl-static"))
	require.NoError(t, err)
	assert.Equal(t, want, got, "the media's static installer is the build's static platformctl")
}

func TestStageInstallMedia_NamedPlatformctlMissingFails(t *testing.T) {
	for _, field := range []string{"platformctl", "platformctl-static"} {
		t.Run(field, func(t *testing.T) {
			build := stageBuild(t, elf.EM_X86_64)
			missing := filepath.Join(t.TempDir(), field)
			if field == "platformctl" {
				build.PlatformctlBinary = missing
			} else {
				build.PlatformctlStaticBinary = missing
			}

			_, err := StageInstallMedia(context.Background(), build, "media", InstallerOverrides{}, nil, logging.DefaultLogger())
			var missingErr *MissingInputError
			require.ErrorAs(t, err, &missingErr)
			assert.Equal(t, missing, missingErr.Path)
		})
	}
}

// TestStageInstallMedia_RestageDropsStaleStatic stages the same tree twice:
// first with a platformctl-static, then with a new platformctl and no
// static input. The autoinstall script prefers platformctl-static, so a
// stale copy would run the previous installer (#1152).
func TestStageInstallMedia_RestageDropsStaleStatic(t *testing.T) {
	build := stageBuild(t, elf.EM_X86_64)
	_, err := StageInstallMedia(context.Background(), build, "media", InstallerOverrides{}, nil, logging.DefaultLogger())
	require.NoError(t, err)

	build.PlatformctlBinary = filepath.Join(t.TempDir(), "platformctl")
	diskimagetest.WriteELF(t, build.PlatformctlBinary, elf.EM_X86_64)
	build.PlatformctlStaticBinary = ""
	media, err := StageInstallMedia(context.Background(), build, "media", InstallerOverrides{}, nil, logging.DefaultLogger())
	require.NoError(t, err)
	assert.FileExists(t, filepath.Join(media.Dir, "platformd-bin", "platformctl"))
	assert.NoFileExists(t, filepath.Join(media.Dir, "platformd-bin", "platformctl-static"))
}

// TestStageInstallMedia_BinariesDirPrefersStatic stages from a directory
// holding a CGO-enabled platformctl (build-no-web, build-desktop) beside a
// static platformctl-static: the media's static installer is the static one.
func TestStageInstallMedia_BinariesDirPrefersStatic(t *testing.T) {
	bins := t.TempDir()
	for _, name := range []string{"platformd", "platformctl-static", "gatewayd"} {
		diskimagetest.WriteELF(t, filepath.Join(bins, name), elf.EM_X86_64)
	}
	diskimagetest.WriteDynamicELF(t, filepath.Join(bins, "platformctl"), elf.EM_X86_64)
	build := stageBuild(t, elf.EM_X86_64)
	build.UseBinariesDir(bins)

	media, err := StageInstallMedia(context.Background(), build, "media", InstallerOverrides{}, nil, logging.DefaultLogger())
	require.NoError(t, err)

	want, err := os.ReadFile(filepath.Join(bins, "platformctl-static"))
	require.NoError(t, err)
	got, err := os.ReadFile(filepath.Join(media.Dir, "platformd-bin", "platformctl-static"))
	require.NoError(t, err)
	assert.Equal(t, want, got, "the supplied static installer wins over a dynamic platformctl")
}

// TestStageInstallMedia_BinariesDirDynamicPlatformctlFails stages from a
// directory with no platformctl-static and a CGO-enabled platformctl: that
// platformctl cannot serve as the Alpine installer, so staging fails.
func TestStageInstallMedia_BinariesDirDynamicPlatformctlFails(t *testing.T) {
	bins := t.TempDir()
	diskimagetest.WriteELF(t, filepath.Join(bins, "platformd"), elf.EM_X86_64)
	diskimagetest.WriteDynamicELF(t, filepath.Join(bins, "platformctl"), elf.EM_X86_64)
	build := stageBuild(t, elf.EM_X86_64)
	build.UseBinariesDir(bins)

	_, err := StageInstallMedia(context.Background(), build, "media", InstallerOverrides{}, nil, logging.DefaultLogger())
	var dynamic *DynamicBinaryError
	require.ErrorAs(t, err, &dynamic)
	assert.Equal(t, filepath.Join(bins, "platformctl"), dynamic.Path)
}

// TestStageInstallMedia_NoStaticRejectsDynamicPlatformctl names a dynamically
// linked platformctl and no platformctl-static: the autoinstall script would
// run that glibc binary on Alpine, so staging fails and leaves no copy
// behind (#1152).
func TestStageInstallMedia_NoStaticRejectsDynamicPlatformctl(t *testing.T) {
	build := stageBuild(t, elf.EM_X86_64)
	build.PlatformctlBinary = filepath.Join(t.TempDir(), "platformctl")
	diskimagetest.WriteDynamicELF(t, build.PlatformctlBinary, elf.EM_X86_64)
	build.PlatformctlStaticBinary = ""

	_, err := StageInstallMedia(context.Background(), build, "media", InstallerOverrides{}, nil, logging.DefaultLogger())
	var dynamic *DynamicBinaryError
	require.ErrorAs(t, err, &dynamic)
	assert.Equal(t, build.PlatformctlBinary, dynamic.Path)
	assert.NoFileExists(t, filepath.Join(build.WorkDir, "media", "platformd-bin", "platformctl"))
}

// TestStageInstallMedia_StaticCoversDynamicPlatformctl pairs a dynamic
// platformctl with a supplied static one: the static one is the Alpine
// installer, so the dynamic platformctl is still installed.
func TestStageInstallMedia_StaticCoversDynamicPlatformctl(t *testing.T) {
	build := stageBuild(t, elf.EM_X86_64)
	diskimagetest.WriteDynamicELF(t, build.PlatformctlBinary, elf.EM_X86_64)

	media, err := StageInstallMedia(context.Background(), build, "media", InstallerOverrides{}, nil, logging.DefaultLogger())
	require.NoError(t, err)
	assert.FileExists(t, filepath.Join(media.Dir, "platformd-bin", "platformctl"))
	assert.FileExists(t, filepath.Join(media.Dir, "platformd-bin", "platformctl-static"))
}
