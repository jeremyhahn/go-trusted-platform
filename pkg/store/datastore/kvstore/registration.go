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

package kvstore

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

const entityTypeRegistration = "Registration"

// RegistrationDAO provides a key-value store backed implementation of datastore.RegistrationDAO.
type RegistrationDAO struct {
	*GenericDAO[*entities.Registration]
}

// NewRegistrationDAO creates a new RegistrationDAO.
func NewRegistrationDAO(storage Storage, logger *logging.Logger, opts ...DAOOption) *RegistrationDAO {
	return &RegistrationDAO{
		GenericDAO: NewGenericDAO[*entities.Registration](
			storage,
			entityTypeRegistration,
			func() *entities.Registration { return &entities.Registration{} },
			logger,
			opts...,
		),
	}
}
