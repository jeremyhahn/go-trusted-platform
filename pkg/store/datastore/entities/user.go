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
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
)

type User struct {
	ID               uint64                `yaml:"id" json:"id"`
	TenantID         string                `yaml:"tenant-id" json:"tenant_id"`
	IsTenantOwner    bool                  `yaml:"is-tenant-owner" json:"is_tenant_owner"`
	Credentials      []webauthn.Credential `yaml:"credentials" json:"credentials"`
	DisplayName      string                `yaml:"display" json:"display"`
	Email            string                `yaml:"email" json:"email"`
	OrganizationRefs []uint64              `yaml:"orgs" json:"orgs"`
	Password         string                `yaml:"password" json:"password" secret:"true"`
	Roles            []*Role               `yaml:"roles" json:"roles"`
	ServiceRefs      []uint64              `yaml:"services" json:"services"`
	SessionData      []byte                `yaml:"session" json:"session"`
	CreatedAt        time.Time             `yaml:"created-at" json:"created_at"`
	UpdatedAt        time.Time             `yaml:"updated-at" json:"updated_at"`
	KeyValueEntity   `yaml:"-" json:"-"`
	webauthn.User    `yaml:"-" json:"-"`
}

func NewUser(email string) *User {
	now := time.Now().UTC()
	return &User{
		Credentials: make([]webauthn.Credential, 0),
		ID:          util.NewID([]byte(email)),
		Email:       email,
		Roles:       make([]*Role, 0),
		CreatedAt:   now,
		UpdatedAt:   now,
	}
}

// Specification: §5.4.3. User Account Parameters for Credential Generation
// https://w3c.github.io/webauthn/#dom-publickeycredentialuserentity-id
func (user *User) WebAuthnID() []byte {
	return []byte(fmt.Sprintf("%d", user.ID))
}

// Specification: §5.4.3. User Account Parameters for Credential Generation
// https://w3c.github.io/webauthn/#dictdef-publickeycredentialuserentity
func (user *User) WebAuthnName() string {
	return user.Email
}

// Specification: §5.4.3. User Account Parameters for Credential Generation
// https://www.w3.org/TR/webauthn/#dom-publickeycredentialuserentity-displayname
func (user *User) WebAuthnDisplayName() string {
	if user.DisplayName != "" {
		return user.DisplayName
	}
	return user.Email
}

// WebAuthnCredentials provides the list of Credential objects owned by the user.
func (user *User) WebAuthnCredentials() []webauthn.Credential {
	return user.Credentials
}

// Adds a new WebAuthn credential
func (user *User) AddCredential(credential *webauthn.Credential) {
	user.Credentials = append(user.Credentials, *credential)
}

func (user *User) UpdateCredential(credential *webauthn.Credential) {
	for i, c := range user.Credentials {
		if string(c.ID) == string(credential.ID) {
			user.Credentials[i] = *credential
		}
	}
}

func (user *User) SetEntityID(id uint64) {
	user.ID = id
}

func (user *User) EntityID() uint64 {
	return user.ID
}

func (user *User) AddRole(role *Role) {
	user.Roles = append(user.Roles, role)
}

func (user *User) HasRole(name string) bool {
	for _, role := range user.Roles {
		if role.Name == name {
			return true
		}
	}
	return false
}
