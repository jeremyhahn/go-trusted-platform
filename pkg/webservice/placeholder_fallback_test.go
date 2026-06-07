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

package webservice

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestFindPlaceholderFallbackFS_FindsDirectChild verifies the helper
// resolves a single-level dynamic route (e.g. `/devices/<id>` ->
// `devices/__placeholder__/index.html`). This is the exact case the
// deployed CP hits when a user clicks View Details on a device row.
func TestFindPlaceholderFallbackFS_FindsDirectChild(t *testing.T) {
	root := t.TempDir()
	placeholderDir := filepath.Join(root, "devices", "__placeholder__")
	require.NoError(t, os.MkdirAll(placeholderDir, 0755))
	indexPath := filepath.Join(placeholderDir, "index.html")
	require.NoError(t, os.WriteFile(indexPath, []byte("<html>placeholder</html>"), 0644))

	got := findPlaceholderFallbackFS(root, "devices/5168606593679365", "index.html")
	assert.Equal(t, indexPath, got)
}

// TestFindPlaceholderFallbackFS_NoPlaceholder ensures the helper
// returns "" when no `__placeholder__` directory exists in the tree.
// Without this guarantee a missing placeholder would still trigger
// a serve attempt and leak random file content.
func TestFindPlaceholderFallbackFS_NoPlaceholder(t *testing.T) {
	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "devices"), 0755))
	require.NoError(t, os.WriteFile(filepath.Join(root, "devices", "index.html"), []byte("list"), 0644))

	assert.Empty(t, findPlaceholderFallbackFS(root, "devices/anything", "index.html"))
}

// TestFindPlaceholderFallbackFS_WalksUp covers a nested dynamic
// route — e.g. `/devices/<id>/sub` — where only the parent placeholder
// directory exists. The walk-up loop must find the sibling placeholder
// at the `<id>` level even when the deepest segment can't be matched.
func TestFindPlaceholderFallbackFS_WalksUp(t *testing.T) {
	root := t.TempDir()
	// Only the device-level placeholder exists; no sub-route is defined.
	placeholderDir := filepath.Join(root, "devices", "__placeholder__")
	require.NoError(t, os.MkdirAll(placeholderDir, 0755))
	indexPath := filepath.Join(placeholderDir, "index.html")
	require.NoError(t, os.WriteFile(indexPath, []byte("ph"), 0644))

	got := findPlaceholderFallbackFS(root, "devices/123/sub", "index.html")
	assert.Equal(t, indexPath, got)
}

// TestFindPlaceholderFallbackFS_EmptyPath defends against the
// degenerate empty-path call — common when the request is for `/`
// itself and the SPA index fallback path drops through.
func TestFindPlaceholderFallbackFS_EmptyPath(t *testing.T) {
	root := t.TempDir()
	assert.Empty(t, findPlaceholderFallbackFS(root, "", "index.html"))
}

// TestFindPlaceholderFallbackFS_IgnoresDirectoryMatches makes sure
// the helper rejects matches where the candidate is a directory
// rather than a real file. Without the `!info.IsDir()` guard a
// `__placeholder__` *directory* without an `index.html` inside it
// would be returned as a valid path and trigger a misleading serve.
func TestFindPlaceholderFallbackFS_IgnoresDirectoryMatches(t *testing.T) {
	root := t.TempDir()
	// Create the directory but NOT the index file.
	require.NoError(t, os.MkdirAll(filepath.Join(root, "devices", "__placeholder__"), 0755))
	assert.Empty(t, findPlaceholderFallbackFS(root, "devices/123", "index.html"))
}
