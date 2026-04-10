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
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	xkmssdk "github.com/jeremyhahn/go-xkms/sdk/go"
)

type Service struct {
	ID            uint64
	Name          string
	KeyAttributes *xkmssdk.KeyAttributes
}

func NewService(name string) *Service {
	return &Service{
		ID:   util.NewID([]byte(name)),
		Name: name,
	}
}

func (service *Service) SetEntityID(id uint64) {
	service.ID = id
}

func (service *Service) EntityID() uint64 {
	return service.ID
}
