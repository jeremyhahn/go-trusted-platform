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
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// mockXorrisoRunner is a mock implementation for testing
type mockXorrisoRunner struct {
	runFunc      func(ctx context.Context, args []string, stdout, stderr io.Writer) error
	versionFunc  func(ctx context.Context) (string, error)
	capturedArgs []string
}

func (m *mockXorrisoRunner) Run(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	m.capturedArgs = args
	if m.runFunc != nil {
		return m.runFunc(ctx, args, stdout, stderr)
	}
	// Simulate successful run
	stdout.Write([]byte("xorriso 1.5.4 : RockRidge filesystem manipulator\n"))
	return nil
}

func (m *mockXorrisoRunner) Version(ctx context.Context) (string, error) {
	if m.versionFunc != nil {
		return m.versionFunc(ctx)
	}
	return "xorriso 1.5.4", nil
}

func createTestISODirectory(t *testing.T) string {
	tmpDir := t.TempDir()
	isoDir := filepath.Join(tmpDir, "iso")

	// Create required boot directories (UEFI only)
	bootGrub := filepath.Join(isoDir, "boot", "grub")
	require.NoError(t, os.MkdirAll(bootGrub, 0755))

	// Create dummy UEFI boot file
	require.NoError(t, os.WriteFile(filepath.Join(bootGrub, "efi.img"), []byte("dummy"), 0644))

	return tmpDir
}

func TestNewBuilder(t *testing.T) {
	logger := logging.DefaultLogger()
	builder := NewBuilder(logger)

	assert.NotNil(t, builder)
	assert.NotNil(t, builder.logger)
	assert.NotNil(t, builder.runner)
}

func TestNewBuilderWithNilLogger(t *testing.T) {
	builder := NewBuilder(nil)

	assert.NotNil(t, builder)
	assert.NotNil(t, builder.logger)
}

func TestValidateConfig_Success(t *testing.T) {
	tmpDir := createTestISODirectory(t)
	isoDir := filepath.Join(tmpDir, "iso")

	builder := NewBuilder(nil)
	config := &ISOConfig{
		ISODir:    isoDir,
		OutputISO: filepath.Join(tmpDir, "test.iso"),
		VolumeID:  "TEST_ISO",
	}

	err := builder.validateConfig(config)
	assert.NoError(t, err)
	assert.Equal(t, "TEST_ISO", config.VolumeID)
}

func TestValidateConfig_DefaultVolumeID(t *testing.T) {
	tmpDir := createTestISODirectory(t)
	isoDir := filepath.Join(tmpDir, "iso")

	builder := NewBuilder(nil)
	config := &ISOConfig{
		ISODir:    isoDir,
		OutputISO: filepath.Join(tmpDir, "test.iso"),
	}

	err := builder.validateConfig(config)
	assert.NoError(t, err)
	assert.Equal(t, "ALPINE_BOOT", config.VolumeID)
}

func TestValidateConfig_VolumeIDTruncation(t *testing.T) {
	tmpDir := createTestISODirectory(t)
	isoDir := filepath.Join(tmpDir, "iso")

	builder := NewBuilder(nil)
	config := &ISOConfig{
		ISODir:    isoDir,
		OutputISO: filepath.Join(tmpDir, "test.iso"),
		VolumeID:  "THIS_IS_A_VERY_LONG_VOLUME_ID_THAT_EXCEEDS_32_CHARACTERS",
	}

	err := builder.validateConfig(config)
	assert.NoError(t, err)
	assert.LessOrEqual(t, len(config.VolumeID), 32)
}

func TestValidateConfig_NilConfig(t *testing.T) {
	builder := NewBuilder(nil)
	err := builder.validateConfig(nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "configuration is required")
}

func TestBuildISO_Success(t *testing.T) {
	tmpDir := createTestISODirectory(t)
	isoDir := filepath.Join(tmpDir, "iso")
	outputISO := filepath.Join(tmpDir, "test.iso")

	// Create mock runner that creates the output file
	mockRunner := &mockXorrisoRunner{
		runFunc: func(ctx context.Context, args []string, stdout, stderr io.Writer) error {
			// Create the output ISO file to simulate success
			for i, arg := range args {
				if arg == "-o" && i+1 < len(args) {
					return os.WriteFile(args[i+1], []byte("dummy iso content"), 0644)
				}
			}
			return nil
		},
	}

	builder := NewBuilder(nil)
	builder.runner = mockRunner

	config := &ISOConfig{
		ISODir:    isoDir,
		OutputISO: outputISO,
		VolumeID:  "TEST_ISO",
	}

	ctx := context.Background()
	err := builder.BuildISO(ctx, config)

	assert.NoError(t, err)
	assert.FileExists(t, outputISO)

	// Verify xorriso was called with correct arguments
	assert.Contains(t, mockRunner.capturedArgs, "-as")
	assert.Contains(t, mockRunner.capturedArgs, "mkisofs")
	assert.Contains(t, mockRunner.capturedArgs, "-V")
	assert.Contains(t, mockRunner.capturedArgs, "TEST_ISO")
	assert.Contains(t, mockRunner.capturedArgs, "-o")
}

func TestBuildISO_WithDebug(t *testing.T) {
	tmpDir := createTestISODirectory(t)
	isoDir := filepath.Join(tmpDir, "iso")
	outputISO := filepath.Join(tmpDir, "test.iso")

	mockRunner := &mockXorrisoRunner{
		runFunc: func(ctx context.Context, args []string, stdout, stderr io.Writer) error {
			stdout.Write([]byte("NOTE: This is a note\nCreating ISO...\nDone\n"))
			for i, arg := range args {
				if arg == "-o" && i+1 < len(args) {
					return os.WriteFile(args[i+1], []byte("dummy iso content"), 0644)
				}
			}
			return nil
		},
	}

	builder := NewBuilder(nil)
	builder.runner = mockRunner

	config := &ISOConfig{
		ISODir:    isoDir,
		OutputISO: outputISO,
		Debug:     true,
	}

	ctx := context.Background()
	err := builder.BuildISO(ctx, config)

	assert.NoError(t, err)
}

func TestBuildISO_WithSecureBootKeys(t *testing.T) {
	tmpDir := createTestISODirectory(t)
	isoDir := filepath.Join(tmpDir, "iso")
	outputISO := filepath.Join(tmpDir, "test.iso")
	keysDir := filepath.Join(tmpDir, "keys")

	// Create test keys directory
	require.NoError(t, os.MkdirAll(keysDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(keysDir, "DB.key"), []byte("key"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(keysDir, "DB.crt"), []byte("cert"), 0644))

	mockRunner := &mockXorrisoRunner{
		runFunc: func(ctx context.Context, args []string, stdout, stderr io.Writer) error {
			for i, arg := range args {
				if arg == "-o" && i+1 < len(args) {
					return os.WriteFile(args[i+1], []byte("dummy iso content"), 0644)
				}
			}
			return nil
		},
	}

	builder := NewBuilder(nil)
	builder.runner = mockRunner

	config := &ISOConfig{
		ISODir:    isoDir,
		OutputISO: outputISO,
		KeysDir:   keysDir,
	}

	ctx := context.Background()
	err := builder.BuildISO(ctx, config)

	assert.NoError(t, err)

	// Verify keys were copied
	copiedKeyDir := filepath.Join(isoDir, "keys")
	assert.DirExists(t, copiedKeyDir)
	assert.FileExists(t, filepath.Join(copiedKeyDir, "DB.key"))
	assert.FileExists(t, filepath.Join(copiedKeyDir, "DB.crt"))
}

func TestBuildISO_WithFIPSKernel(t *testing.T) {
	tmpDir := createTestISODirectory(t)
	workDir := tmpDir
	isoDir := filepath.Join(tmpDir, "iso")
	outputISO := filepath.Join(tmpDir, "test.iso")
	fipsKernelDir := filepath.Join(workDir, "fips-kernel")

	// Create FIPS kernel
	require.NoError(t, os.MkdirAll(fipsKernelDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(fipsKernelDir, "vmlinuz-fips"), []byte("kernel"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(fipsKernelDir, "config-fips"), []byte("config"), 0644))

	mockRunner := &mockXorrisoRunner{
		runFunc: func(ctx context.Context, args []string, stdout, stderr io.Writer) error {
			for i, arg := range args {
				if arg == "-o" && i+1 < len(args) {
					return os.WriteFile(args[i+1], []byte("dummy iso content"), 0644)
				}
			}
			return nil
		},
	}

	builder := NewBuilder(nil)
	builder.runner = mockRunner

	config := &ISOConfig{
		WorkDir:   workDir,
		ISODir:    isoDir,
		OutputISO: outputISO,
	}

	ctx := context.Background()
	err := builder.BuildISO(ctx, config)

	assert.NoError(t, err)

	// Verify FIPS kernel was copied
	fipsDestDir := filepath.Join(isoDir, ".fips-data")
	assert.DirExists(t, fipsDestDir)
	assert.FileExists(t, filepath.Join(fipsDestDir, "vmlinuz-fips"))
	assert.FileExists(t, filepath.Join(fipsDestDir, "config-fips"))
}

func TestBuildISO_WithPreSignedUKI(t *testing.T) {
	tmpDir := createTestISODirectory(t)
	workDir := tmpDir
	isoDir := filepath.Join(tmpDir, "iso")
	outputISO := filepath.Join(tmpDir, "test.iso")
	hostUKIDir := filepath.Join(workDir, "host-uki")

	// Create pre-signed UKI
	require.NoError(t, os.MkdirAll(hostUKIDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(hostUKIDir, "BOOTX64.EFI"), []byte("uki"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(hostUKIDir, "manifest.txt"), []byte("manifest"), 0644))

	mockRunner := &mockXorrisoRunner{
		runFunc: func(ctx context.Context, args []string, stdout, stderr io.Writer) error {
			for i, arg := range args {
				if arg == "-o" && i+1 < len(args) {
					return os.WriteFile(args[i+1], []byte("dummy iso content"), 0644)
				}
			}
			return nil
		},
	}

	builder := NewBuilder(nil)
	builder.runner = mockRunner

	config := &ISOConfig{
		WorkDir:   workDir,
		ISODir:    isoDir,
		OutputISO: outputISO,
	}

	ctx := context.Background()
	err := builder.BuildISO(ctx, config)

	assert.NoError(t, err)

	// Verify UKI was copied
	ukiDestDir := filepath.Join(isoDir, ".signed-uki")
	assert.DirExists(t, ukiDestDir)
	assert.FileExists(t, filepath.Join(ukiDestDir, "BOOTX64.EFI"))
}

func TestBuildISO_XorrisoFailure(t *testing.T) {
	tmpDir := createTestISODirectory(t)
	isoDir := filepath.Join(tmpDir, "iso")
	outputISO := filepath.Join(tmpDir, "test.iso")

	mockRunner := &mockXorrisoRunner{
		runFunc: func(ctx context.Context, args []string, stdout, stderr io.Writer) error {
			stderr.Write([]byte("xorriso: FAILURE"))
			return assert.AnError
		},
	}

	builder := NewBuilder(nil)
	builder.runner = mockRunner

	config := &ISOConfig{
		ISODir:    isoDir,
		OutputISO: outputISO,
	}

	ctx := context.Background()
	err := builder.BuildISO(ctx, config)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "xorriso failed")
}

func TestValidateISO_Success(t *testing.T) {
	tmpDir := t.TempDir()
	isoPath := filepath.Join(tmpDir, "test.iso")

	// Create test ISO
	require.NoError(t, os.WriteFile(isoPath, []byte("dummy iso content"), 0644))

	builder := NewBuilder(nil)
	err := builder.ValidateISO(context.Background(), isoPath)

	assert.NoError(t, err)
}

func TestValidateISO_FileNotFound(t *testing.T) {
	tmpDir := t.TempDir()
	isoPath := filepath.Join(tmpDir, "nonexistent.iso")

	builder := NewBuilder(nil)
	err := builder.ValidateISO(context.Background(), isoPath)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ISO file not found")
}

func TestValidateISO_EmptyFile(t *testing.T) {
	tmpDir := t.TempDir()
	isoPath := filepath.Join(tmpDir, "empty.iso")

	// Create empty ISO
	require.NoError(t, os.WriteFile(isoPath, []byte{}, 0644))

	builder := NewBuilder(nil)
	err := builder.ValidateISO(context.Background(), isoPath)

	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ISO file is empty")
}

func TestXorrisoArguments(t *testing.T) {
	tmpDir := createTestISODirectory(t)
	isoDir := filepath.Join(tmpDir, "iso")
	outputISO := filepath.Join(tmpDir, "test.iso")

	mockRunner := &mockXorrisoRunner{
		runFunc: func(ctx context.Context, args []string, stdout, stderr io.Writer) error {
			for i, arg := range args {
				if arg == "-o" && i+1 < len(args) {
					return os.WriteFile(args[i+1], []byte("dummy iso content"), 0644)
				}
			}
			return nil
		},
	}

	builder := NewBuilder(nil)
	builder.runner = mockRunner

	config := &ISOConfig{
		ISODir:        isoDir,
		OutputISO:     outputISO,
		VolumeID:      "TEST_VOL",
		ApplicationID: "TEST_APP",
		PublisherID:   "TEST_PUB",
	}

	ctx := context.Background()
	err := builder.BuildISO(ctx, config)

	assert.NoError(t, err)

	// Verify all required xorriso arguments — UEFI-only boot
	args := mockRunner.capturedArgs
	argsStr := strings.Join(args, " ")

	// UEFI boot entries that MUST be present
	assert.Contains(t, argsStr, "-as mkisofs")
	assert.Contains(t, argsStr, "-r")
	assert.Contains(t, argsStr, "-J")
	assert.Contains(t, argsStr, "-e boot/grub/efi.img")
	assert.Contains(t, argsStr, "-no-emul-boot")
	assert.Contains(t, argsStr, "-isohybrid-gpt-basdat")
	assert.Contains(t, argsStr, "-V TEST_VOL")
	assert.Contains(t, argsStr, "-A TEST_APP")
	assert.Contains(t, argsStr, "-publisher TEST_PUB")

	// Legacy BIOS/syslinux entries that MUST NOT be present
	assert.NotContains(t, argsStr, "-b boot/syslinux/isolinux.bin")
	assert.NotContains(t, argsStr, "-c boot/syslinux/boot.cat")
	assert.NotContains(t, argsStr, "-boot-load-size")
	assert.NotContains(t, argsStr, "-boot-info-table")
	assert.NotContains(t, argsStr, "-eltorito-alt-boot")
}

func TestHelperFunctions(t *testing.T) {
	tmpDir := t.TempDir()

	t.Run("isDir", func(t *testing.T) {
		dir := filepath.Join(tmpDir, "testdir")
		require.NoError(t, os.MkdirAll(dir, 0755))

		assert.True(t, isDir(dir))
		assert.False(t, isDir(filepath.Join(tmpDir, "nonexistent")))

		file := filepath.Join(tmpDir, "file.txt")
		require.NoError(t, os.WriteFile(file, []byte("content"), 0644))
		assert.False(t, isDir(file))
	})

	t.Run("fileExists", func(t *testing.T) {
		file := filepath.Join(tmpDir, "test.txt")
		assert.False(t, fileExists(file))

		require.NoError(t, os.WriteFile(file, []byte("content"), 0644))
		assert.True(t, fileExists(file))
	})

	t.Run("copyFile", func(t *testing.T) {
		src := filepath.Join(tmpDir, "source.txt")
		dst := filepath.Join(tmpDir, "dest.txt")

		require.NoError(t, os.WriteFile(src, []byte("test content"), 0644))
		require.NoError(t, copyFile(src, dst))

		content, err := os.ReadFile(dst)
		require.NoError(t, err)
		assert.Equal(t, "test content", string(content))
	})

	t.Run("copyDir", func(t *testing.T) {
		srcDir := filepath.Join(tmpDir, "srcdir")
		dstDir := filepath.Join(tmpDir, "dstdir")

		require.NoError(t, os.MkdirAll(filepath.Join(srcDir, "subdir"), 0755))
		require.NoError(t, os.WriteFile(filepath.Join(srcDir, "file1.txt"), []byte("content1"), 0644))
		require.NoError(t, os.WriteFile(filepath.Join(srcDir, "subdir", "file2.txt"), []byte("content2"), 0644))

		require.NoError(t, copyDir(srcDir, dstDir))

		assert.DirExists(t, dstDir)
		assert.DirExists(t, filepath.Join(dstDir, "subdir"))
		assert.FileExists(t, filepath.Join(dstDir, "file1.txt"))
		assert.FileExists(t, filepath.Join(dstDir, "subdir", "file2.txt"))
	})
}
