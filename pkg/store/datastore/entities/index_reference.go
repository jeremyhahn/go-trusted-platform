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

type Reference struct {
	ID          uint64 `yaml:"id" json:"id"`
	ReferenceID uint64 `yaml:"ref-id" json:"ref_id"`
	name        string `yaml:"-" json:"-"`
	Index       `yaml:"-" json:"-"`
}

func NewReference(name string, referenceID uint64, referencedValue []byte) Index {
	return &Reference{
		ID:          util.NewID(referencedValue),
		ReferenceID: referenceID,
		name:        name,
	}
}

func (ref *Reference) SetEntityID(id uint64) {
	ref.ID = id
}

func (ref *Reference) EntityID() uint64 {
	return ref.ID
}

func (ref *Reference) Name() string {
	return ref.name
}

func (ref *Reference) RefID() uint64 {
	return ref.ReferenceID
}
