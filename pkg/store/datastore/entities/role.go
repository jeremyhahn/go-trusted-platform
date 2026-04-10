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

import "github.com/jeremyhahn/go-trusted-platform/pkg/util"

type Role struct {
	ID             uint64 `json:"id"`
	Name           string `json:"name"`
	KeyValueEntity `yaml:"-" json:"-"`
}

func NewRole(name string) *Role {
	return &Role{
		ID:   util.NewID([]byte(name)),
		Name: name,
	}
}

func (role *Role) SetEntityID(id uint64) {
	role.ID = id
}

func (role *Role) EntityID() uint64 {
	return role.ID
}
