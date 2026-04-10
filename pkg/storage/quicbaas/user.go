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

package quicbaas

import (
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

const entityTypeUser = "User"

// UserDAO provides a QuicBaaS-backed implementation of datastore.UserDAO.
type UserDAO struct {
	*GenericDAO[*entities.User]
}

// NewUserDAO creates a new UserDAO.
func NewUserDAO(storage Storage, logger *logging.Logger, opts ...DAOOption) *UserDAO {
	return &UserDAO{
		GenericDAO: NewGenericDAO[*entities.User](
			storage,
			entityTypeUser,
			func() *entities.User { return entities.NewUser("") },
			logger,
			opts...,
		),
	}
}
