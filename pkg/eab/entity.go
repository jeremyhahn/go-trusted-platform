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
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

// Ensure EABCredential implements KeyValueEntity.
var _ entities.KeyValueEntity = (*EABCredential)(nil)

// EABCredential is the storage entity for EAB credentials.
// It implements entities.KeyValueEntity for QuicBaaS storage.
type EABCredential struct {
	ID        uint64 `yaml:"id" json:"id"`
	KeyID     string `yaml:"key_id" json:"key_id"`
	HMACKey   []byte `yaml:"hmac_key" json:"hmac_key"`
	ProfileID uint64 `yaml:"profile_id" json:"profile_id"`
	TenantID  string `yaml:"tenant_id" json:"tenant_id"`
	ExpiresAt int64  `yaml:"expires_at" json:"expires_at"`
	Status    uint8  `yaml:"status" json:"status"`
	CreatedAt int64  `yaml:"created_at" json:"created_at"`
	UsedAt    int64  `yaml:"used_at,omitempty" json:"used_at,omitempty"`

	entities.KeyValueEntity `yaml:"-" json:"-"`
}

// EntityID returns the entity's unique identifier.
func (e *EABCredential) EntityID() uint64 {
	return e.ID
}

// SetEntityID sets the entity's unique identifier.
func (e *EABCredential) SetEntityID(id uint64) {
	e.ID = id
}
