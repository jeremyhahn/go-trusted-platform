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

package secureboot

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestNewXKMSManager_RemoteForcesNoExport verifies ResignModeRemote keeps the
// private key server-side: ExportKeys is forced false and GenerateAll never
// writes a DB.key PEM to disk, even when ExportKeys was requested true.
func TestNewXKMSManager_RemoteForcesNoExport(t *testing.T) {
	keysDir := t.TempDir()
	km, err := NewXKMSManager(&XKMSConfig{
		KeysDir:    keysDir,
		Backend:    BackendSoftware,
		CommonName: "Remote Resign Test",
		ExportKeys: true, // requested, but remote mode must override to false
		ResignMode: ResignModeRemote,
	}, nil)
	require.NoError(t, err)
	defer km.Close()

	assert.False(t, km.config.ExportKeys, "remote resign-mode must force ExportKeys false")

	require.NoError(t, km.GenerateAll(context.Background()))

	// No private key PEM may be exported in remote mode.
	_, err = os.Stat(km.GetKeyPaths().DBKey)
	assert.True(t, os.IsNotExist(err), "DB.key must NOT be exported in remote resign-mode")
}

// TestNewXKMSManager_LocalExportsKeys verifies the local mode still exports the
// keypair when ExportKeys is set, so offline UKI signing keeps working.
func TestNewXKMSManager_LocalExportsKeys(t *testing.T) {
	keysDir := t.TempDir()
	km, err := NewXKMSManager(&XKMSConfig{
		KeysDir:    keysDir,
		Backend:    BackendSoftware,
		CommonName: "Local Resign Test",
		ExportKeys: true,
		ResignMode: ResignModeLocal,
	}, nil)
	require.NoError(t, err)
	defer km.Close()

	assert.True(t, km.config.ExportKeys, "local resign-mode must preserve ExportKeys")

	require.NoError(t, km.GenerateAll(context.Background()))

	_, err = os.Stat(km.GetKeyPaths().DBKey)
	require.NoError(t, err, "DB.key must be exported in local resign-mode")
}
