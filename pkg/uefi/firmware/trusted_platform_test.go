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

package firmware

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSetTrustedPlatform(t *testing.T) {
	root, _ := useEfiVars(t)

	require.NoError(t, SetTrustedPlatform())

	raw, err := os.ReadFile(filepath.Join(root, variableFilename(TrustedPlatformVariableName, TrustedPlatformGUID)))
	require.NoError(t, err)
	assert.Equal(t, []byte{byte(TrustedPlatformAttributes), 0, 0, 0, 't', 'r', 'u', 'e'}, raw)

	result, err := GetTrustedPlatform()
	require.NoError(t, err)
	assert.True(t, result)
	assert.True(t, IsTrustedPlatform())
}

func TestGetTrustedPlatform(t *testing.T) {
	t.Run("not set", func(t *testing.T) {
		useEfiVars(t)
		result, err := GetTrustedPlatform()
		assert.ErrorIs(t, err, ErrNotTrustedPlatform)
		assert.False(t, result)
		assert.False(t, IsTrustedPlatform())
	})

	t.Run("set to another value", func(t *testing.T) {
		root, _ := useEfiVars(t)
		writeRawVariable(t, root, TrustedPlatformVariableName, TrustedPlatformGUID, []byte{0x07, 0, 0, 0, 'n', 'o'})

		result, err := GetTrustedPlatform()
		require.NoError(t, err)
		assert.False(t, result)
		assert.False(t, IsTrustedPlatform())
	})

	t.Run("invalid data", func(t *testing.T) {
		root, _ := useEfiVars(t)
		writeRawVariable(t, root, TrustedPlatformVariableName, TrustedPlatformGUID, []byte{0x07})

		result, err := GetTrustedPlatform()
		assert.ErrorIs(t, err, ErrInvalidData)
		assert.False(t, result)
	})
}

func TestClearTrustedPlatform(t *testing.T) {
	t.Run("set", func(t *testing.T) {
		root, _ := useEfiVars(t)
		path := writeRawVariable(t, root, TrustedPlatformVariableName, TrustedPlatformGUID, []byte{0x07, 0, 0, 0, 't', 'r', 'u', 'e'})

		require.NoError(t, ClearTrustedPlatform())
		assert.NoFileExists(t, path)
		assert.False(t, IsTrustedPlatform())
	})

	t.Run("not set", func(t *testing.T) {
		useEfiVars(t)
		assert.NoError(t, ClearTrustedPlatform())
	})

	t.Run("remove immutable fails", func(t *testing.T) {
		root, chattr := useEfiVars(t)
		chattr.fail = "-i"
		path := writeRawVariable(t, root, TrustedPlatformVariableName, TrustedPlatformGUID, []byte{0x07, 0, 0, 0, 't', 'r', 'u', 'e'})

		err := ClearTrustedPlatform()
		assert.ErrorIs(t, err, errFakeChattr)
		assert.FileExists(t, path)
	})
}
