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

package eab

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEABCredential_EntityID(t *testing.T) {
	t.Run("returns ID", func(t *testing.T) {
		entity := &EABCredential{ID: 12345}
		assert.Equal(t, uint64(12345), entity.EntityID())
	})

	t.Run("returns zero when not set", func(t *testing.T) {
		entity := &EABCredential{}
		assert.Equal(t, uint64(0), entity.EntityID())
	})
}

func TestEABCredential_SetEntityID(t *testing.T) {
	t.Run("sets ID", func(t *testing.T) {
		entity := &EABCredential{}
		entity.SetEntityID(67890)
		assert.Equal(t, uint64(67890), entity.ID)
	})

	t.Run("overwrites existing ID", func(t *testing.T) {
		entity := &EABCredential{ID: 111}
		entity.SetEntityID(222)
		assert.Equal(t, uint64(222), entity.ID)
	})
}

func TestEABCredential_FullStruct(t *testing.T) {
	entity := &EABCredential{
		ID:        1,
		KeyID:     "test-key-id",
		HMACKey:   []byte("test-hmac-key"),
		ProfileID: 100,
		TenantID:  "tenant-abc",
		ExpiresAt: 1704067200,
		Status:    uint8(StatusActive),
		CreatedAt: 1704000000,
		UsedAt:    0,
	}

	assert.Equal(t, uint64(1), entity.ID)
	assert.Equal(t, "test-key-id", entity.KeyID)
	assert.Equal(t, []byte("test-hmac-key"), entity.HMACKey)
	assert.Equal(t, uint64(100), entity.ProfileID)
	assert.Equal(t, "tenant-abc", entity.TenantID)
	assert.Equal(t, int64(1704067200), entity.ExpiresAt)
	assert.Equal(t, uint8(StatusActive), entity.Status)
	assert.Equal(t, int64(1704000000), entity.CreatedAt)
	assert.Equal(t, int64(0), entity.UsedAt)
}
