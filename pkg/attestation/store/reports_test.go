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

package store

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/reporting"
)

func TestFileStore_ReportsRoundTrip(t *testing.T) {
	s, err := NewFileStore(t.TempDir())
	require.NoError(t, err)

	empty, err := s.Reports()
	require.NoError(t, err)
	assert.Empty(t, empty)

	at := time.Unix(1_700_000_000, 0).UTC()
	require.NoError(t, s.PutReport(&reporting.Report{DeviceID: "42", Verified: true, Status: "verified", CollectedAt: at, PCRBaselineSource: "tofu"}))
	require.NoError(t, s.PutReport(&reporting.Report{DeviceID: "7", Verified: false, Status: "failed", Message: "nonce", CollectedAt: at, Cryptographic: true}))
	// Replacing keeps one file per device.
	require.NoError(t, s.PutReport(&reporting.Report{DeviceID: "42", Verified: false, Status: "failed", CollectedAt: at.Add(time.Minute)}))

	got, err := s.Reports()
	require.NoError(t, err)
	require.Len(t, got, 2)
	assert.Equal(t, "42", got[0].DeviceID)
	assert.Equal(t, "7", got[1].DeviceID)
	assert.False(t, got[0].Verified)
	assert.Equal(t, at.Add(time.Minute), got[0].CollectedAt)
	assert.True(t, got[1].Cryptographic)
}

func TestFileStore_PutReportRejectsBadKeys(t *testing.T) {
	s, err := NewFileStore(t.TempDir())
	require.NoError(t, err)
	require.Error(t, s.PutReport(nil))
	for _, id := range []string{"", "../x", "a/b", ".hidden", `a\b`} {
		err := s.PutReport(&reporting.Report{DeviceID: id})
		var bad ErrInvalidReportDeviceID
		require.ErrorAs(t, err, &bad, id)
		assert.Contains(t, bad.Error(), "report key")
	}
}

func TestFileStore_ReportsSkipsCorruptFiles(t *testing.T) {
	root := t.TempDir()
	s, err := NewFileStore(root)
	require.NoError(t, err)
	require.NoError(t, s.PutReport(&reporting.Report{DeviceID: "1", CollectedAt: time.Now()}))
	dir := filepath.Join(root, reportsDir)
	require.NoError(t, os.WriteFile(filepath.Join(dir, "2.json"), []byte("{not json"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "3.json"), []byte(`{"DeviceID":""}`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "notes.txt"), []byte("x"), 0o600))
	require.NoError(t, os.Mkdir(filepath.Join(dir, "sub.json"), 0o700))

	got, err := s.Reports()
	require.NoError(t, err)
	require.Len(t, got, 1)
	assert.Equal(t, "1", got[0].DeviceID)
}

func TestFileStore_ReportsDirectoryUnreadable(t *testing.T) {
	root := t.TempDir()
	s, err := NewFileStore(root)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(root, reportsDir), []byte("file, not dir"), 0o600))
	_, err = s.Reports()
	require.Error(t, err)
	err = s.PutReport(&reporting.Report{DeviceID: "1"})
	require.Error(t, err)
}
