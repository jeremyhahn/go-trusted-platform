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

type Registration struct {
	ID              uint64 `yaml:"id" json:"id"`
	Email           string `yaml:"email" json:"email"`
	Password        string `yaml:"password" json:"password" secret:"true"`
	OrgID           uint64 `yaml:"org-id" json:"org_id"`
	OrgName         string `yaml:"org-name" json:"org_name"`
	SessionData     []byte `yaml:"session-data" json:"session_data"`
	InvitationToken string `yaml:"invitation-token,omitempty" json:"invitation_token,omitempty" secret:"true"`
	KeyValueEntity  `yaml:"-" json:"-"`
}

func NewRegistration(email string) *Registration {
	return &Registration{
		ID:    util.NewID([]byte(email)),
		Email: email,
	}
}

func (r *Registration) EntityID() uint64 {
	return r.ID
}

func (r *Registration) SetEntityID(id uint64) {
	r.ID = id
}
