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

//go:build platform_web

package embed

import (
	"io/fs"
	"testing"
	"testing/fstest"

	"github.com/stretchr/testify/assert"
)

func TestHasConsole(t *testing.T) {
	t.Run("console present", func(t *testing.T) {
		fsys := fstest.MapFS{
			".gitkeep":   {},
			"index.html": {Data: []byte("<html></html>")},
		}
		assert.True(t, hasConsole(fsys))
	})

	t.Run("placeholder only", func(t *testing.T) {
		fsys := fstest.MapFS{".gitkeep": {}}
		assert.False(t, hasConsole(fsys))
	})

	t.Run("empty", func(t *testing.T) {
		assert.False(t, hasConsole(fstest.MapFS{}))
	})

	t.Run("nil filesystem", func(t *testing.T) {
		assert.False(t, hasConsole(nil))
	})

	t.Run("unreadable root", func(t *testing.T) {
		assert.False(t, hasConsole(failingFS{}))
	})
}

// A placeholder-only dist, as produced by `go build -tags platform_web`
// without _web-embed-prepare, must not report a console (#323).
func TestIsEmbedded_PlaceholderOnlyDist(t *testing.T) {
	entries, err := fs.ReadDir(WebFS, ".")
	assert.NoError(t, err)
	onlyPlaceholder := true
	for _, e := range entries {
		if e.Name() != placeholderName {
			onlyPlaceholder = false
		}
	}
	// A developer who ran WITH_WEB=1 has a populated dist; the invariant
	// holds either way: IsEmbedded is false exactly when only the placeholder exists.
	assert.Equal(t, !onlyPlaceholder, IsEmbedded())
}

// failingFS fails every open, standing in for an unreadable embedded root.
type failingFS struct{}

func (failingFS) Open(string) (fs.File, error) { return nil, fs.ErrPermission }
