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

package authenticode

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/authenticode/authenticodetest"
)

// Signing a file onto itself signs it in place; before the fix the output
// was created (truncating the input) before the input was read.
func TestSignFileInPlace(t *testing.T) {
	signer := newTestSigner(t, "")
	dir := t.TempDir()
	path := filepath.Join(dir, "bootx64.efi")
	unsigned := authenticodetest.MinimalPE(authenticodetest.MachineAMD64)
	require.NoError(t, os.WriteFile(path, unsigned, 0o644))

	require.NoError(t, signer.SignFile(path, path))

	signed, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Greater(t, len(signed), len(unsigned))
	require.NoError(t, signer.VerifyFile(path))
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 1, "no temporary file is left beside the output")
}

// A failed signing leaves an existing output file as it was and removes the
// temporary file.
func TestSignFileFailureKeepsExistingOutput(t *testing.T) {
	signer := newTestSigner(t, "")
	dir := t.TempDir()
	input := filepath.Join(dir, "not-a-pe.efi")
	output := filepath.Join(dir, "signed.efi")
	require.NoError(t, os.WriteFile(input, []byte("not a PE image"), 0o644))
	previous := []byte("previously signed image")
	require.NoError(t, os.WriteFile(output, previous, 0o755))

	require.Error(t, signer.SignFile(input, output))

	kept, err := os.ReadFile(output)
	require.NoError(t, err)
	require.Equal(t, previous, kept)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	require.Len(t, entries, 2, "no temporary file is left beside the output")
}
