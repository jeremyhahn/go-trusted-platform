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
	"bytes"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCopyFile_Success(t *testing.T) {
	tempDir := t.TempDir()

	srcFile := filepath.Join(tempDir, "source.txt")
	dstFile := filepath.Join(tempDir, "dest.txt")

	testData := []byte("test content")
	require.NoError(t, os.WriteFile(srcFile, testData, 0644))

	err := copyFile(srcFile, dstFile)
	require.NoError(t, err)

	// Verify content
	data, err := os.ReadFile(dstFile)
	require.NoError(t, err)
	assert.Equal(t, testData, data)
}

func TestCopyFile_SourceNotFound(t *testing.T) {
	tempDir := t.TempDir()

	srcFile := "/nonexistent/source.txt"
	dstFile := filepath.Join(tempDir, "dest.txt")

	err := copyFile(srcFile, dstFile)
	assert.Error(t, err)
}

func TestCopyFile_DestinationError(t *testing.T) {
	tempDir := t.TempDir()

	srcFile := filepath.Join(tempDir, "source.txt")
	require.NoError(t, os.WriteFile(srcFile, []byte("test"), 0644))

	// Try to write to invalid destination
	dstFile := "/invalid/path/dest.txt"

	err := copyFile(srcFile, dstFile)
	assert.Error(t, err)
}

func TestCopyDir_Success(t *testing.T) {
	tempDir := t.TempDir()

	srcDir := filepath.Join(tempDir, "source")
	dstDir := filepath.Join(tempDir, "dest")

	// Create source directory structure
	require.NoError(t, os.MkdirAll(filepath.Join(srcDir, "subdir"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "file1.txt"), []byte("content1"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(srcDir, "subdir", "file2.txt"), []byte("content2"), 0644))

	err := copyDir(srcDir, dstDir)
	require.NoError(t, err)

	// Verify files were copied
	data1, err := os.ReadFile(filepath.Join(dstDir, "file1.txt"))
	require.NoError(t, err)
	assert.Equal(t, []byte("content1"), data1)

	data2, err := os.ReadFile(filepath.Join(dstDir, "subdir", "file2.txt"))
	require.NoError(t, err)
	assert.Equal(t, []byte("content2"), data2)
}

func TestCopyDir_SourceNotFound(t *testing.T) {
	tempDir := t.TempDir()

	srcDir := "/nonexistent/source"
	dstDir := filepath.Join(tempDir, "dest")

	err := copyDir(srcDir, dstDir)
	assert.Error(t, err)
}

func TestCopyDir_NestedDirectories(t *testing.T) {
	tempDir := t.TempDir()

	srcDir := filepath.Join(tempDir, "source")
	dstDir := filepath.Join(tempDir, "dest")

	// Create deeply nested structure
	deepDir := filepath.Join(srcDir, "level1", "level2", "level3")
	require.NoError(t, os.MkdirAll(deepDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(deepDir, "deep.txt"), []byte("deep content"), 0644))

	err := copyDir(srcDir, dstDir)
	require.NoError(t, err)

	// Verify deep file exists
	data, err := os.ReadFile(filepath.Join(dstDir, "level1", "level2", "level3", "deep.txt"))
	require.NoError(t, err)
	assert.Equal(t, []byte("deep content"), data)
}

func TestCopyDir_EmptyDirectory(t *testing.T) {
	tempDir := t.TempDir()

	srcDir := filepath.Join(tempDir, "empty_source")
	dstDir := filepath.Join(tempDir, "empty_dest")

	require.NoError(t, os.MkdirAll(srcDir, 0755))

	err := copyDir(srcDir, dstDir)
	require.NoError(t, err)

	// Verify destination exists
	info, err := os.Stat(dstDir)
	require.NoError(t, err)
	assert.True(t, info.IsDir())
}

func TestFileExists_True(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "exists.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("test"), 0644))

	assert.True(t, fileExists(testFile))
}

func TestFileExists_False(t *testing.T) {
	assert.False(t, fileExists("/nonexistent/file.txt"))
}

func TestIsDir_True(t *testing.T) {
	tempDir := t.TempDir()
	assert.True(t, isDir(tempDir))
}

func TestIsDir_False_File(t *testing.T) {
	tempDir := t.TempDir()
	testFile := filepath.Join(tempDir, "file.txt")
	require.NoError(t, os.WriteFile(testFile, []byte("test"), 0644))

	assert.False(t, isDir(testFile))
}

func TestIsDir_False_NotExist(t *testing.T) {
	assert.False(t, isDir("/nonexistent/directory"))
}

func TestBuildISO_ValidateConfigError(t *testing.T) {
	builder := NewBuilder(nil)

	// Invalid config - nil
	err := builder.BuildISO(context.Background(), nil)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "configuration is required")
}

func TestBuildISO_ISODirNotFound(t *testing.T) {
	builder := NewBuilder(nil)

	config := &ISOConfig{
		ISODir:    "/nonexistent/iso/dir",
		OutputISO: "/tmp/output.iso",
		VolumeID:  "TEST",
	}

	err := builder.BuildISO(context.Background(), config)
	assert.Error(t, err)
}

func TestBuildISO_PrepareISOContentsWithFIPSKernel(t *testing.T) {
	tempDir := t.TempDir()
	isoDir := filepath.Join(tempDir, "iso")
	require.NoError(t, os.MkdirAll(isoDir, 0755))

	// Create a fake FIPS kernel directory
	fipsKernelDir := filepath.Join(tempDir, "work", "fips-kernel")
	require.NoError(t, os.MkdirAll(fipsKernelDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(fipsKernelDir, "vmlinuz-fips"), []byte("fake kernel"), 0644))

	builder := NewBuilder(nil)
	config := &ISOConfig{
		ISODir:    isoDir,
		OutputISO: filepath.Join(tempDir, "output.iso"),
		VolumeID:  "TEST",
		WorkDir:   filepath.Join(tempDir, "work"),
	}

	// This will fail at xorriso step, but we're testing the FIPS kernel copy
	err := builder.BuildISO(context.Background(), config)
	assert.Error(t, err) // Expected to fail at xorriso

	// Verify FIPS data directory was created
	fipsDataDir := filepath.Join(isoDir, ".fips-data")
	assert.True(t, isDir(fipsDataDir))
}

func TestBuildISO_PrepareISOContentsWithUKI(t *testing.T) {
	tempDir := t.TempDir()
	isoDir := filepath.Join(tempDir, "iso")
	require.NoError(t, os.MkdirAll(isoDir, 0755))

	// Create a fake UKI directory
	ukiDir := filepath.Join(tempDir, "work", "host-uki")
	require.NoError(t, os.MkdirAll(ukiDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(ukiDir, "BOOTX64.EFI"), []byte("fake uki"), 0644))

	builder := NewBuilder(nil)
	config := &ISOConfig{
		ISODir:    isoDir,
		OutputISO: filepath.Join(tempDir, "output.iso"),
		VolumeID:  "TEST",
		WorkDir:   filepath.Join(tempDir, "work"),
	}

	// This will fail at xorriso step, but we're testing the UKI copy
	err := builder.BuildISO(context.Background(), config)
	assert.Error(t, err) // Expected to fail at xorriso

	// Verify UKI data directory was created
	ukiDataDir := filepath.Join(isoDir, ".signed-uki")
	assert.True(t, isDir(ukiDataDir))
}

func TestCopySecureBootKeys_Success(t *testing.T) {
	tempDir := t.TempDir()

	// Create source keys directory
	keysDir := filepath.Join(tempDir, "keys")
	require.NoError(t, os.MkdirAll(keysDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(keysDir, "PK.auth"), []byte("pk"), 0644))
	require.NoError(t, os.WriteFile(filepath.Join(keysDir, "KEK.auth"), []byte("kek"), 0644))

	// Create ISO directory
	isoDir := filepath.Join(tempDir, "iso")
	require.NoError(t, os.MkdirAll(isoDir, 0755))

	builder := NewBuilder(nil)
	config := &ISOConfig{
		ISODir:  isoDir,
		KeysDir: keysDir,
	}

	err := builder.copySecureBootKeys(config)
	require.NoError(t, err)

	// Verify keys were copied
	dstKeys := filepath.Join(isoDir, "keys")
	assert.True(t, fileExists(filepath.Join(dstKeys, "PK.auth")))
	assert.True(t, fileExists(filepath.Join(dstKeys, "KEK.auth")))
}

func TestCopySecureBootKeys_SourceNotFound(t *testing.T) {
	tempDir := t.TempDir()
	isoDir := filepath.Join(tempDir, "iso")
	require.NoError(t, os.MkdirAll(isoDir, 0755))

	builder := NewBuilder(nil)
	config := &ISOConfig{
		ISODir:  isoDir,
		KeysDir: "/nonexistent/keys",
	}

	err := builder.copySecureBootKeys(config)
	assert.Error(t, err)
}

// TestBuilderCopySecureBootKeys_PrivateKeyStagedOwnerOnly holds the legacy
// builder path to the same staging rule as the customize path (#62): a
// private key lands owner-only on the ISO tree, a public certificate stays
// world-readable.
func TestBuilderCopySecureBootKeys_PrivateKeyStagedOwnerOnly(t *testing.T) {
	tempDir := t.TempDir()
	isoDir := filepath.Join(tempDir, "iso")
	keysDir := filepath.Join(tempDir, "keys")
	require.NoError(t, os.MkdirAll(isoDir, 0755))
	require.NoError(t, os.MkdirAll(keysDir, 0755))

	keyPEM, certPEM := genTestSigningPairPEM(t)
	require.NoError(t, os.WriteFile(filepath.Join(keysDir, "DB.key"), keyPEM, 0600))
	require.NoError(t, os.WriteFile(filepath.Join(keysDir, "DB.crt"), certPEM, 0644))

	builder := NewBuilder(nil)
	require.NoError(t, builder.copySecureBootKeys(&ISOConfig{ISODir: isoDir, KeysDir: keysDir}))

	stagedKey := filepath.Join(isoDir, "keys", "DB.key")
	info, err := os.Stat(stagedKey)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm(), "staged DB.key must be owner-only")
	got, err := os.ReadFile(stagedKey)
	require.NoError(t, err)
	assert.Equal(t, keyPEM, got)

	info, err = os.Stat(filepath.Join(isoDir, "keys", "DB.crt"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0644), info.Mode().Perm(), "staged DB.crt stays world-readable")
}

// TestBuilderCopySecureBootKeys_OverwritesStaleWorldReadableKey: the legacy
// builder merges into an existing ISO tree, so a DB.key left 0644 by an
// earlier build must come out owner-only, and a DB.crt left 0600 must come
// out 0644 (#62).
func TestBuilderCopySecureBootKeys_OverwritesStaleWorldReadableKey(t *testing.T) {
	tempDir := t.TempDir()
	isoDir := filepath.Join(tempDir, "iso")
	keysDir := filepath.Join(tempDir, "keys")
	stagedDir := filepath.Join(isoDir, "keys")
	require.NoError(t, os.MkdirAll(stagedDir, 0755))
	require.NoError(t, os.MkdirAll(keysDir, 0755))

	keyPEM, certPEM := genTestSigningPairPEM(t)
	require.NoError(t, os.WriteFile(filepath.Join(keysDir, "DB.key"), keyPEM, 0600))
	require.NoError(t, os.WriteFile(filepath.Join(keysDir, "DB.crt"), certPEM, 0644))

	stagedKey := filepath.Join(stagedDir, "DB.key")
	stagedCrt := filepath.Join(stagedDir, "DB.crt")
	require.NoError(t, os.WriteFile(stagedKey, []byte("stale"), 0644))
	require.NoError(t, os.Chmod(stagedKey, 0644))
	require.NoError(t, os.WriteFile(stagedCrt, []byte("stale"), 0600))

	require.NoError(t, NewBuilder(nil).copySecureBootKeys(&ISOConfig{ISODir: isoDir, KeysDir: keysDir}))

	info, err := os.Stat(stagedKey)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm(), "stale 0644 DB.key must be re-staged owner-only")
	got, err := os.ReadFile(stagedKey)
	require.NoError(t, err)
	assert.Equal(t, keyPEM, got)

	info, err = os.Stat(stagedCrt)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0644), info.Mode().Perm(), "stale 0600 DB.crt must be re-staged 0644")
	got, err = os.ReadFile(stagedCrt)
	require.NoError(t, err)
	assert.Equal(t, certPEM, got)
}

// TestBuilderCopySecureBootKeys_DoesNotWriteThroughSymlink: a symlink at the
// staged DB.key path is replaced by a regular owner-only file; the link target
// is left untouched (#62).
func TestBuilderCopySecureBootKeys_DoesNotWriteThroughSymlink(t *testing.T) {
	tempDir := t.TempDir()
	isoDir := filepath.Join(tempDir, "iso")
	keysDir := filepath.Join(tempDir, "keys")
	stagedDir := filepath.Join(isoDir, "keys")
	require.NoError(t, os.MkdirAll(stagedDir, 0755))
	require.NoError(t, os.MkdirAll(keysDir, 0755))

	keyPEM, certPEM := genTestSigningPairPEM(t)
	require.NoError(t, os.WriteFile(filepath.Join(keysDir, "DB.key"), keyPEM, 0600))
	require.NoError(t, os.WriteFile(filepath.Join(keysDir, "DB.crt"), certPEM, 0644))

	outside := filepath.Join(tempDir, "outside.txt")
	require.NoError(t, os.WriteFile(outside, []byte("outside"), 0644))
	stagedKey := filepath.Join(stagedDir, "DB.key")
	require.NoError(t, os.Symlink(outside, stagedKey))

	require.NoError(t, NewBuilder(nil).copySecureBootKeys(&ISOConfig{ISODir: isoDir, KeysDir: keysDir}))

	got, err := os.ReadFile(outside)
	require.NoError(t, err)
	assert.Equal(t, []byte("outside"), got, "symlink target must not be written through")

	info, err := os.Lstat(stagedKey)
	require.NoError(t, err)
	assert.True(t, info.Mode().IsRegular(), "staged DB.key must be a regular file, not a symlink")
	assert.Equal(t, os.FileMode(0600), info.Mode().Perm(), "staged DB.key must be owner-only")
	got, err = os.ReadFile(stagedKey)
	require.NoError(t, err)
	assert.Equal(t, keyPEM, got)
}

// writeTestDBPair writes a DB signing pair into dir and returns the key PEM.
func writeTestDBPair(t *testing.T, dir string) []byte {
	t.Helper()
	require.NoError(t, os.MkdirAll(dir, 0755))
	keyPEM, certPEM := genTestSigningPairPEM(t)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "DB.key"), keyPEM, 0600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "DB.crt"), certPEM, 0644))
	return keyPEM
}

// fakeXorrisoBuilder returns a Builder whose xorriso writes output (or
// fails with runErr) after calling onRun with the tree it was asked to pack.
func fakeXorrisoBuilder(output string, runErr error, onRun func()) *Builder {
	builder := NewBuilder(nil)
	builder.runner = &mockXorrisoRunner{
		runFunc: func(ctx context.Context, args []string, stdout, stderr io.Writer) error {
			if onRun != nil {
				onRun()
			}
			if runErr != nil {
				return runErr
			}
			return os.WriteFile(output, []byte("iso"), 0644)
		},
	}
	return builder
}

func TestBuildISO_WipesStagedSecureBootPrivateKeyAfterPacking(t *testing.T) {
	tempDir := t.TempDir()
	isoDir := filepath.Join(tempDir, "iso")
	keysDir := filepath.Join(tempDir, "secure-boot-keys")
	require.NoError(t, os.MkdirAll(isoDir, 0755))
	keyPEM := writeTestDBPair(t, keysDir)

	stagedKey := filepath.Join(isoDir, "secure-boot-keys", "DB.key")
	held := filepath.Join(tempDir, "held.key")
	packed := false
	output := filepath.Join(tempDir, "out.iso")
	builder := fakeXorrisoBuilder(output, nil, func() {
		got, err := os.ReadFile(stagedKey)
		packed = err == nil && bytes.Equal(got, keyPEM)
		// A second link to the staged inode shows what the wipe left in it.
		require.NoError(t, os.Link(stagedKey, held))
	})

	require.NoError(t, builder.BuildISO(context.Background(),
		&ISOConfig{ISODir: isoDir, KeysDir: keysDir, OutputISO: output}))

	assert.True(t, packed, "xorriso must pack the staged DB.key")
	assert.NoFileExists(t, stagedKey, "the staged DB.key copy must be removed after packing")
	assert.FileExists(t, filepath.Join(isoDir, "secure-boot-keys", "DB.crt"), "public DB.crt stays staged")
	left, err := os.ReadFile(held)
	require.NoError(t, err)
	assert.Equal(t, make([]byte, len(keyPEM)), left, "the staged DB.key bytes must be zeroed before removal")
	src, err := os.ReadFile(filepath.Join(keysDir, "DB.key"))
	require.NoError(t, err)
	assert.Equal(t, keyPEM, src, "the source DB.key is untouched")
}

// TestBuildISO_KeysDirCopyDoesNotOwnStaleHardLinkedEntry checks that copying
// KeysDir into an ISO keys dir that already holds a stale hard link to an
// external signing key (an entry absent from KeysDir) does not make the wipe
// treat that link as the build's own: the external key keeps its bytes and
// only the stale link is detached (#2363).
func TestBuildISO_KeysDirCopyDoesNotOwnStaleHardLinkedEntry(t *testing.T) {
	tempDir := t.TempDir()
	isoDir := filepath.Join(tempDir, "iso")
	keysDir := filepath.Join(tempDir, "keys")
	writeTestDBPair(t, keysDir)

	external := filepath.Join(tempDir, "external.key")
	externalBytes := []byte("external signing key material\n")
	require.NoError(t, os.WriteFile(external, externalBytes, 0600))
	stagedDir := filepath.Join(isoDir, "keys")
	require.NoError(t, os.MkdirAll(stagedDir, 0755))
	stale := filepath.Join(stagedDir, "retired.key")
	require.NoError(t, os.Link(external, stale))

	output := filepath.Join(tempDir, "out.iso")
	builder := fakeXorrisoBuilder(output, nil, nil)
	require.NoError(t, builder.BuildISO(context.Background(),
		&ISOConfig{ISODir: isoDir, KeysDir: keysDir, OutputISO: output}))

	got, err := os.ReadFile(external)
	require.NoError(t, err)
	assert.Equal(t, externalBytes, got, "the external key behind a stale staged link must keep its bytes")
	assert.NoFileExists(t, stale, "the stale hard link is detached from the staged keys dir")
	assert.NoFileExists(t, filepath.Join(stagedDir, "DB.key"), "the staged DB.key copy is removed after packing")
}

func TestBuildISO_WipesStagedSecureBootPrivateKeyWhenXorrisoFails(t *testing.T) {
	tempDir := t.TempDir()
	isoDir := filepath.Join(tempDir, "iso")
	keysDir := filepath.Join(tempDir, "keys")
	require.NoError(t, os.MkdirAll(isoDir, 0755))
	writeTestDBPair(t, keysDir)

	builder := fakeXorrisoBuilder(filepath.Join(tempDir, "out.iso"), assert.AnError, nil)
	err := builder.BuildISO(context.Background(),
		&ISOConfig{ISODir: isoDir, KeysDir: keysDir, OutputISO: filepath.Join(tempDir, "out.iso")})

	require.Error(t, err)
	assert.NoFileExists(t, filepath.Join(isoDir, "keys", "DB.key"), "a failed build must not leave the staged DB.key")
	assert.FileExists(t, filepath.Join(isoDir, "keys", "DB.crt"))
}

func TestBuildISO_WipesCustomizeStagedSecureBootPrivateKey(t *testing.T) {
	tempDir := t.TempDir()
	isoDir := filepath.Join(tempDir, "iso")
	require.NoError(t, os.MkdirAll(isoDir, 0755))
	// Customize stages the keypair at the ISO root without a builder KeysDir.
	writeTestDBPair(t, filepath.Join(isoDir, SecureBootKeysISODirName))

	output := filepath.Join(tempDir, "out.iso")
	builder := fakeXorrisoBuilder(output, nil, nil)
	require.NoError(t, builder.BuildISO(context.Background(), &ISOConfig{ISODir: isoDir, OutputISO: output}))

	assert.NoFileExists(t, filepath.Join(isoDir, SecureBootKeysISODirName, "DB.key"))
	assert.FileExists(t, filepath.Join(isoDir, SecureBootKeysISODirName, "DB.crt"))
}

func TestBuildISO_KeepsKeysDirThatIsTheISOTreeItself(t *testing.T) {
	isoDir := t.TempDir()
	keysDir := filepath.Join(isoDir, SecureBootKeysISODirName)
	keyPEM := writeTestDBPair(t, keysDir)

	output := filepath.Join(t.TempDir(), "out.iso")
	builder := fakeXorrisoBuilder(output, nil, nil)
	require.NoError(t, builder.BuildISO(context.Background(),
		&ISOConfig{ISODir: isoDir, KeysDir: keysDir, OutputISO: output}))

	got, err := os.ReadFile(filepath.Join(keysDir, "DB.key"))
	require.NoError(t, err, "the key source must never be wiped")
	assert.Equal(t, keyPEM, got)
}

func TestBuildISO_KeepsKeysDirNestedInStagingTree(t *testing.T) {
	tempDir := t.TempDir()
	isoDir := filepath.Join(tempDir, "iso")
	keysDir := filepath.Join(isoDir, SecureBootKeysISODirName, "source")
	keyPEM := writeTestDBPair(t, keysDir)

	output := filepath.Join(tempDir, "out.iso")
	builder := fakeXorrisoBuilder(output, nil, nil)
	require.NoError(t, builder.BuildISO(context.Background(),
		&ISOConfig{ISODir: isoDir, KeysDir: keysDir, OutputISO: output}))

	got, err := os.ReadFile(filepath.Join(keysDir, "DB.key"))
	require.NoError(t, err, "a key source nested in the staging tree must never be wiped")
	assert.Equal(t, keyPEM, got)
	assert.FileExists(t, filepath.Join(keysDir, "DB.crt"))
	assert.NoFileExists(t, filepath.Join(isoDir, "source", "DB.key"),
		"the builder's staged DB.key copy must be removed")
}

func TestBuildISO_DoesNotWipeThroughSymlinkedStagingRoot(t *testing.T) {
	tempDir := t.TempDir()
	isoDir := filepath.Join(tempDir, "iso")
	outside := filepath.Join(tempDir, "outside")
	require.NoError(t, os.MkdirAll(isoDir, 0755))
	keyPEM := writeTestDBPair(t, outside)
	require.NoError(t, os.Symlink(outside, filepath.Join(isoDir, SecureBootKeysISODirName)))

	output := filepath.Join(tempDir, "out.iso")
	builder := fakeXorrisoBuilder(output, nil, nil)
	err := builder.BuildISO(context.Background(), &ISOConfig{ISODir: isoDir, OutputISO: output})
	require.Error(t, err, "a symlinked staging root must be refused")

	got, err := os.ReadFile(filepath.Join(outside, "DB.key"))
	require.NoError(t, err, "a key outside the ISO tree must never be wiped")
	assert.Equal(t, keyPEM, got)
}

func TestRunXorriso_ContextCancellation(t *testing.T) {
	tempDir := t.TempDir()
	isoDir := filepath.Join(tempDir, "iso")
	require.NoError(t, os.MkdirAll(isoDir, 0755))

	config := &ISOConfig{
		ISODir:    isoDir,
		OutputISO: filepath.Join(tempDir, "output.iso"),
		VolumeID:  "TEST",
	}

	// Create cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	builder := NewBuilder(nil)
	err := builder.runXorriso(ctx, config)
	assert.Error(t, err)
}

func TestPrepareISOContents_NoWorkDir(t *testing.T) {
	tempDir := t.TempDir()
	isoDir := filepath.Join(tempDir, "iso")
	require.NoError(t, os.MkdirAll(isoDir, 0755))

	config := &ISOConfig{
		ISODir:    isoDir,
		OutputISO: filepath.Join(tempDir, "output.iso"),
		VolumeID:  "TEST",
		WorkDir:   "", // No work directory
	}

	builder := NewBuilder(nil)
	err := builder.prepareISOContents(config)
	require.NoError(t, err) // Should succeed with no-op
}

func TestValidateConfig_LongVolumeID(t *testing.T) {
	tempDir := t.TempDir()
	isoDir := filepath.Join(tempDir, "iso")
	require.NoError(t, os.MkdirAll(isoDir, 0755))

	builder := NewBuilder(nil)

	config := &ISOConfig{
		ISODir:    isoDir,
		OutputISO: filepath.Join(tempDir, "output.iso"),
		VolumeID:  "THIS_VOLUME_ID_IS_WAY_TOO_LONG_AND_EXCEEDS_32_CHARACTERS",
	}

	err := builder.validateConfig(config)
	require.NoError(t, err)

	// Volume ID should be truncated to 32 characters
	assert.Len(t, config.VolumeID, 32)
}

func TestValidateConfig_EmptyVolumeID(t *testing.T) {
	tempDir := t.TempDir()
	isoDir := filepath.Join(tempDir, "iso")
	require.NoError(t, os.MkdirAll(isoDir, 0755))

	builder := NewBuilder(nil)

	config := &ISOConfig{
		ISODir:    isoDir,
		OutputISO: filepath.Join(tempDir, "output.iso"),
		VolumeID:  "",
	}

	err := builder.validateConfig(config)
	require.NoError(t, err)

	// Should have default label
	assert.Equal(t, "ALPINE_BOOT", config.VolumeID)
}

func TestValidateConfig_MissingISODir(t *testing.T) {
	builder := NewBuilder(nil)

	config := &ISOConfig{
		OutputISO: "/tmp/output.iso",
		VolumeID:  "TEST",
	}

	err := builder.validateConfig(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ISO directory is required")
}

func TestValidateConfig_MissingOutputISO(t *testing.T) {
	tempDir := t.TempDir()
	isoDir := filepath.Join(tempDir, "iso")
	require.NoError(t, os.MkdirAll(isoDir, 0755))

	builder := NewBuilder(nil)

	config := &ISOConfig{
		ISODir:   isoDir,
		VolumeID: "TEST",
	}

	err := builder.validateConfig(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "output ISO path is required")
}

func TestValidateConfig_ISODirNotFound(t *testing.T) {
	builder := NewBuilder(nil)

	config := &ISOConfig{
		ISODir:    "/nonexistent/iso",
		OutputISO: "/tmp/output.iso",
		VolumeID:  "TEST",
	}

	err := builder.validateConfig(config)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "ISO directory not found")
}

func TestPrepareISOContents_FIPSKernelCopyError(t *testing.T) {
	tempDir := t.TempDir()
	isoDir := filepath.Join(tempDir, "iso")
	require.NoError(t, os.MkdirAll(isoDir, 0755))

	// Create FIPS kernel dir with a file we can't copy (read-only directory for destination)
	fipsKernelDir := filepath.Join(tempDir, "work", "fips-kernel")
	require.NoError(t, os.MkdirAll(fipsKernelDir, 0755))
	require.NoError(t, os.WriteFile(filepath.Join(fipsKernelDir, "vmlinuz-fips"), []byte("kernel"), 0644))

	// Make ISO dir read-only to cause copy failure
	fipsDataDir := filepath.Join(isoDir, ".fips-data")
	require.NoError(t, os.MkdirAll(fipsDataDir, 0444)) // Read-only

	builder := NewBuilder(nil)
	config := &ISOConfig{
		ISODir:  isoDir,
		WorkDir: filepath.Join(tempDir, "work"),
	}

	// Should not fail, just log warnings
	err := builder.prepareISOContents(config)
	assert.NoError(t, err)

	// Restore permissions for cleanup
	os.Chmod(fipsDataDir, 0755)
}

// Benchmark tests
func BenchmarkCopyFile(b *testing.B) {
	tempDir := b.TempDir()
	srcFile := filepath.Join(tempDir, "source.txt")
	testData := make([]byte, 1024*1024) // 1MB
	os.WriteFile(srcFile, testData, 0644)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dstFile := filepath.Join(tempDir, "dest_"+string(rune(i))+".txt")
		copyFile(srcFile, dstFile)
	}
}

func BenchmarkCopyDir(b *testing.B) {
	tempDir := b.TempDir()
	srcDir := filepath.Join(tempDir, "source")
	os.MkdirAll(srcDir, 0755)

	// Create some files
	for i := 0; i < 10; i++ {
		filePath := filepath.Join(srcDir, "file_"+string(rune(i))+".txt")
		os.WriteFile(filePath, []byte("content"), 0644)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dstDir := filepath.Join(tempDir, "dest_"+string(rune(i)))
		copyDir(srcDir, dstDir)
	}
}
