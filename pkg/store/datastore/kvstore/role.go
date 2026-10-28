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
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

const entityTypeRole = "Role"

// RoleDAO provides a key-value store backed implementation of datastore.RoleDAO.
type RoleDAO struct {
	*GenericDAO[*entities.Role]
}

// NewRoleDAO creates a new RoleDAO.
func NewRoleDAO(storage Storage, logger *logging.Logger, opts ...DAOOption) *RoleDAO {
	return &RoleDAO{
		GenericDAO: NewGenericDAO[*entities.Role](
			storage,
			entityTypeRole,
			func() *entities.Role { return &entities.Role{} },
			logger,
			opts...,
		),
	}
}

// GetByName retrieves a role by its name using a secondary index query.
// If no secondary index exists, falls back to scanning all roles.
func (d *RoleDAO) GetByName(ctx context.Context, name string) (*entities.Role, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	results, err := d.storage.Query(ctx, entityTypeRole, "Name", []byte(name), d.shardID)
	if err != nil {
		return d.getRoleByScan(ctx, name)
	}

	if len(results) == 0 {
		return d.getRoleByScan(ctx, name)
	}

	var role entities.Role
	if err := datastore.DecodeEntity(results[0].Data, &role); err != nil {
		return nil, ErrDeserializationFailed{EntityType: entityTypeRole, Cause: err}
	}

	return &role, nil
}

// getRoleByScan scans all roles and finds one by name.
// This is a fallback when secondary index query is not available.
func (d *RoleDAO) getRoleByScan(ctx context.Context, name string) (*entities.Role, error) {
	pageToken := ""

	for {
		svcEntities, nextToken, err := d.storage.List(ctx, entityTypeRole, 1000, pageToken, d.shardID)
		if err != nil {
			return nil, err
		}

		for _, entity := range svcEntities {
			var role entities.Role
			if err := datastore.DecodeEntity(entity.Data, &role); err != nil {
				d.logger.Warn("Failed to deserialize role", "id", entity.ID, "error", err)
				continue
			}

			if role.Name == name {
				return &role, nil
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return nil, ErrNotFoundByIndex{EntityType: entityTypeRole, IndexField: "Name", Value: name}
}
