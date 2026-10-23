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

package agent

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	gwvpn "github.com/jeremyhahn/go-trusted-platform/pkg/sdn/gateway/services/vpn"
)

func testState() *State {
	return &State{
		Gateway: "gw.example:4433",
		Lease: gwvpn.LeaseWire{
			ID: "l-1", DeviceID: "laptop-1", TenantID: "acme", Address: "10.8.0.2/32",
			DataPlane: gwvpn.DataPlaneMASQUE, ExpiresAtUnix: 1760328800, RenewAtUnix: 1760325200,
		},
		Session:     Session{Interface: "vpn0"},
		ConnectedAt: time.Unix(1760300000, 0).UTC(),
	}
}

func TestFileStateStore_SavesPrivatelyAndLoadsBack(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "platformctl")
	store := NewFileStateStore(filepath.Join(dir, "vpn.json"))

	require.NoError(t, store.Save(testState()))
	got, err := store.Load()
	require.NoError(t, err)
	assert.Equal(t, testState(), got)

	info, err := os.Stat(store.Path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	dirInfo, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), dirInfo.Mode().Perm())
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 1, "no temporary file is left behind")
}

func TestFileStateStore_DefaultsToTheRunPath(t *testing.T) {
	assert.Equal(t, DefaultStatePath, NewFileStateStore("").Path)
}

func TestFileStateStore_LoadWithoutAFileIsNotConnected(t *testing.T) {
	_, err := NewFileStateStore(filepath.Join(t.TempDir(), "vpn.json")).Load()
	var notConnected *ErrNotConnected
	assert.ErrorAs(t, err, &notConnected)
}

func TestFileStateStore_LoadRejectsACorruptFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vpn.json")
	require.NoError(t, os.WriteFile(path, []byte("{not json"), 0o600))

	_, err := NewFileStateStore(path).Load()
	var storeErr *ErrStateStore
	require.ErrorAs(t, err, &storeErr)
	assert.Equal(t, "decode", storeErr.Op)
}

func TestFileStateStore_LoadReportsAnUnreadableFile(t *testing.T) {
	_, err := NewFileStateStore(t.TempDir()).Load()
	var storeErr *ErrStateStore
	require.ErrorAs(t, err, &storeErr, "a directory in place of the file is not 'not connected'")
	assert.Equal(t, "read", storeErr.Op)
}

func TestFileStateStore_SaveFailsWhenTheDirectoryCannotExist(t *testing.T) {
	blocker := filepath.Join(t.TempDir(), "file")
	require.NoError(t, os.WriteFile(blocker, nil, 0o600))

	err := NewFileStateStore(filepath.Join(blocker, "vpn.json")).Save(testState())
	var storeErr *ErrStateStore
	require.ErrorAs(t, err, &storeErr)
	assert.Equal(t, "create directory", storeErr.Op)
}

func TestFileStateStore_SaveFailsWhenTheRenameCannotReplace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vpn.json")
	require.NoError(t, os.MkdirAll(filepath.Join(path, "occupied"), 0o700))

	err := NewFileStateStore(path).Save(testState())
	var storeErr *ErrStateStore
	require.ErrorAs(t, err, &storeErr)
	assert.Equal(t, "rename", storeErr.Op)
	entries, err := os.ReadDir(dir)
	require.NoError(t, err)
	assert.Len(t, entries, 1, "the temporary file is discarded")
}

func TestFileStateStore_RemoveIsIdempotent(t *testing.T) {
	store := NewFileStateStore(filepath.Join(t.TempDir(), "vpn.json"))
	require.NoError(t, store.Save(testState()))

	require.NoError(t, store.Remove())
	require.NoError(t, store.Remove(), "removing what is gone is not an error")
	_, err := store.Load()
	var notConnected *ErrNotConnected
	assert.ErrorAs(t, err, &notConnected)
}

func TestFileStateStore_RemoveReportsAFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "vpn.json")
	require.NoError(t, os.MkdirAll(filepath.Join(path, "occupied"), 0o700))

	err := NewFileStateStore(path).Remove()
	var storeErr *ErrStateStore
	require.ErrorAs(t, err, &storeErr)
	assert.Equal(t, "remove", storeErr.Op)
}
