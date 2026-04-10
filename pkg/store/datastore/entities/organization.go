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

type Organization struct {
	ID             uint64 `yaml:"id" json:"id"`
	Name           string `yaml:"name" json:"name"`
	KeyValueEntity `yaml:"-" json:"-"`
}

func NewOrganization(name string) *Organization {
	return &Organization{
		ID:   util.NewID([]byte(name)),
		Name: name,
	}
}

func (organization *Organization) SetEntityID(id uint64) {
	organization.ID = id
}

func (organization *Organization) EntityID() uint64 {
	return organization.ID
}
