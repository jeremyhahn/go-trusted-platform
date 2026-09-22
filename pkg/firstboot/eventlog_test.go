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

package firstboot

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestTPMEventLogAvailable pins that availability is decided by reading,
// never by size: securityfs' binary_bios_measurements is a seq_file whose
// stat size is always zero, and the old size check reported every
// populated log as empty.
func TestTPMEventLogAvailable(t *testing.T) {
	dir := t.TempDir()

	t.Run("a populated log reads its first bytes", func(t *testing.T) {
		path := filepath.Join(dir, "populated")
		require.NoError(t, os.WriteFile(path, bytes.Repeat([]byte{0xAB}, 300), 0o644))

		n, err := tpmEventLogAvailable(path)

		require.NoError(t, err)
		assert.Equal(t, 300, n)
	})

	t.Run("a log larger than the probe is reported by the probe size", func(t *testing.T) {
		path := filepath.Join(dir, "large")
		require.NoError(t, os.WriteFile(path, bytes.Repeat([]byte{1}, tpmEventLogProbeSize*3), 0o644))

		n, err := tpmEventLogAvailable(path)

		require.NoError(t, err)
		assert.Equal(t, tpmEventLogProbeSize, n, "the probe is bounded; it proves content, it does not copy the log")
	})

	t.Run("an empty file is present but not available", func(t *testing.T) {
		path := filepath.Join(dir, "empty")
		require.NoError(t, os.WriteFile(path, nil, 0o644))

		n, err := tpmEventLogAvailable(path)

		require.NoError(t, err, "existence is not an error; the caller keeps polling")
		assert.Zero(t, n)
	})

	t.Run("a missing file is the no-log case", func(t *testing.T) {
		n, err := tpmEventLogAvailable(filepath.Join(dir, "absent"))

		assert.Error(t, err)
		assert.Zero(t, n)
	})
}
