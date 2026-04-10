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

package installer

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewFIDO2Unlock(t *testing.T) {
	t.Run("create unlock handler", func(t *testing.T) {
		unlock := NewFIDO2Unlock("/dev/vda2", true)
		assert.NotNil(t, unlock)
		assert.Equal(t, "/dev/vda2", unlock.luksDevice)
		assert.True(t, unlock.debug)
	})

	t.Run("create without debug", func(t *testing.T) {
		unlock := NewFIDO2Unlock("/dev/sda2", false)
		assert.NotNil(t, unlock)
		assert.Equal(t, "/dev/sda2", unlock.luksDevice)
		assert.False(t, unlock.debug)
	})
}

func TestFIDO2Unlock_GetTokenInfo(t *testing.T) {
	t.Run("no FIDO2 token in device", func(t *testing.T) {
		unlock := NewFIDO2Unlock("/dev/null", false)
		token, err := unlock.GetTokenInfo()
		// Should fail because /dev/null is not a LUKS device
		assert.Error(t, err)
		assert.Nil(t, token)
	})

	t.Run("invalid LUKS device", func(t *testing.T) {
		unlock := NewFIDO2Unlock("/nonexistent/device", false)
		token, err := unlock.GetTokenInfo()
		// Should fail because device doesn't exist
		assert.Error(t, err)
		assert.Nil(t, token)
		assert.Contains(t, err.Error(), "failed to read LUKS header")
	})
}
