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

package gateway

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
)

func TestRevocationJournal_RoundTrip(t *testing.T) {
	journal := tempRevocationJournal(t)
	empty, err := journal.load()
	require.NoError(t, err, "a journal never written holds nothing")
	assert.Empty(t, empty)

	want := map[vpn.LeaseID]string{"lease-1": "tenant-a", "lease-2": "tenant-b"}
	require.NoError(t, journal.save(want))

	got, err := NewRevocationJournal(journal.path).load()
	require.NoError(t, err)
	assert.Equal(t, want, got, "another process reads what this one wrote")
	file, err := os.Stat(journal.path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), file.Mode().Perm())
	dir, err := os.Stat(filepath.Dir(journal.path))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), dir.Mode().Perm())

	require.NoError(t, journal.save(map[vpn.LeaseID]string{}))
	got, err = journal.load()
	require.NoError(t, err)
	assert.Empty(t, got, "a save replaces the whole journal")
	assertOnlyTheJournal(t, journal)
}

func TestRevocationJournal_Failures(t *testing.T) {
	journalError := func(t *testing.T, err error) *ErrRevocationJournal {
		t.Helper()
		var broken *ErrRevocationJournal
		require.True(t, errors.As(err, &broken), "got %v", err)
		return broken
	}

	t.Run("unparseable", func(t *testing.T) {
		journal := tempRevocationJournal(t)
		require.NoError(t, os.MkdirAll(filepath.Dir(journal.path), 0o700))
		require.NoError(t, os.WriteFile(journal.path, []byte("[1,2"), 0o600))
		_, err := journal.load()
		broken := journalError(t, err)
		assert.Equal(t, "parse", broken.Op)
		assert.Equal(t, journal.path, broken.Path)
	})
	t.Run("unreadable", func(t *testing.T) {
		journal := tempRevocationJournal(t)
		require.NoError(t, os.MkdirAll(journal.path, 0o700))
		_, err := journal.load()
		assert.Equal(t, "read", journalError(t, err).Op)
	})
	t.Run("no directory can be made", func(t *testing.T) {
		blocker := filepath.Join(t.TempDir(), "file")
		require.NoError(t, os.WriteFile(blocker, nil, 0o600))
		err := NewRevocationJournal(filepath.Join(blocker, "vpn", "pending-revocations.json")).save(nil)
		assert.Equal(t, "write", journalError(t, err).Op)
	})
	t.Run("the rename fails and leaves no temporary file", func(t *testing.T) {
		journal := tempRevocationJournal(t)
		require.NoError(t, os.MkdirAll(journal.path, 0o700))
		require.NoError(t, os.WriteFile(filepath.Join(journal.path, "entry"), nil, 0o600))
		err := journal.save(map[vpn.LeaseID]string{"lease-1": "tenant-a"})
		assert.Equal(t, "write", journalError(t, err).Op)
		assertOnlyTheJournal(t, journal)
	})
}

// assertOnlyTheJournal requires the journal's directory to hold the journal
// alone: no temporary file is left behind.
func assertOnlyTheJournal(t *testing.T, journal *RevocationJournal) {
	t.Helper()
	entries, err := os.ReadDir(filepath.Dir(journal.path))
	require.NoError(t, err)
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	assert.Equal(t, []string{filepath.Base(journal.path)}, names)
}
