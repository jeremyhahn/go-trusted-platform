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
	assert.Equal(t, "/out/aarch64/platformctl-static", build.PlatformctlStaticBinary)
}

func TestUseBinariesDir_ReachesTheCustomizer(t *testing.T) {
	build := &ISOBuildConfig{}
	build.UseBinariesDir("/out")
	platform := NewPlatformISOConfig(build, t.TempDir()).Platform
	assert.Equal(t, "/out/platformctl", platform.PlatformctlBinary)
	assert.Equal(t, "/out/platformctl-static", platform.PlatformctlStaticBinary)
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
