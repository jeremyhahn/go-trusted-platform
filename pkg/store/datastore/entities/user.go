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

package entities

import (
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
)

// User is the platform-local identity record. WebAuthn credentials are
// authoritative in the quicbaas IAM tenant — the platform no longer
// caches them here. The platform User retains tenant ownership, roles,
// and the foreign-key handles consumed by the rest of the system.
type User struct {
	ID               uint64    `yaml:"id" json:"id"`
	TenantID         string    `yaml:"tenant-id" json:"tenant_id"`
	IsTenantOwner    bool      `yaml:"is-tenant-owner" json:"is_tenant_owner"`
	DisplayName      string    `yaml:"display" json:"display"`
	Email            string    `yaml:"email" json:"email"`
	OrganizationRefs []uint64  `yaml:"orgs" json:"orgs"`
	Password         string    `yaml:"password" json:"password" secret:"true"`
	Roles            []*Role   `yaml:"roles" json:"roles"`
	ServiceRefs      []uint64  `yaml:"services" json:"services"`
	CreatedAt        time.Time `yaml:"created-at" json:"created_at"`
	UpdatedAt        time.Time `yaml:"updated-at" json:"updated_at"`
	KeyValueEntity   `yaml:"-" json:"-"`
}

// NewUser constructs a User with the email-derived ID and zero-valued
// secondary fields. Callers populate DisplayName/Roles/TenantID after.
func NewUser(email string) *User {
	now := time.Now().UTC()
	return &User{
		ID:        util.NewID([]byte(email)),
		Email:     email,
		Roles:     make([]*Role, 0),
		CreatedAt: now,
		UpdatedAt: now,
	}
}

// SetEntityID implements KeyValueEntity.
func (user *User) SetEntityID(id uint64) {
	user.ID = id
}

// EntityID implements KeyValueEntity.
func (user *User) EntityID() uint64 {
	return user.ID
}

// AddRole appends a role to the user.
func (user *User) AddRole(role *Role) {
	user.Roles = append(user.Roles, role)
}

// HasRole reports whether the named role is present on the user.
func (user *User) HasRole(name string) bool {
	for _, role := range user.Roles {
		if role.Name == name {
			return true
		}
	}
	return false
}
