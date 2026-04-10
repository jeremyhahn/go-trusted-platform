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
	"context"
	"encoding/json"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore/entities"
)

const entityTypeOrganization = "Organization"

// OrganizationDAO provides a QuicBaaS-backed implementation of datastore.OrganizationDAO.
type OrganizationDAO struct {
	*GenericDAO[*entities.Organization]
	userEntityType string
}

// NewOrganizationDAO creates a new OrganizationDAO.
func NewOrganizationDAO(storage Storage, logger *logging.Logger, opts ...DAOOption) *OrganizationDAO {
	return &OrganizationDAO{
		GenericDAO: NewGenericDAO[*entities.Organization](
			storage,
			entityTypeOrganization,
			func() *entities.Organization { return &entities.Organization{} },
			logger,
			opts...,
		),
		userEntityType: "User",
	}
}

// GetUsers returns all users belonging to an organization.
// This scans users and filters by organization ID in their OrganizationRefs field.
// Note: QuicBaaS doesn't support element-in-array queries, so we use scan.
func (d *OrganizationDAO) GetUsers(ctx context.Context, id uint64) ([]*entities.User, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	// Use scan since OrganizationRefs is a slice field and QuicBaaS
	// doesn't support element-in-array queries on secondary indexes
	return d.getUsersByScan(ctx, id)
}

// getUsersByScan scans all users and filters by organization ID.
// This is a fallback when secondary index query is not available.
func (d *OrganizationDAO) getUsersByScan(ctx context.Context, orgID uint64) ([]*entities.User, error) {
	var users []*entities.User
	pageToken := ""

	for {
		svcEntities, nextToken, err := d.storage.List(ctx, d.userEntityType, 100, pageToken, d.shardID)
		if err != nil {
			return nil, err
		}

		for _, entity := range svcEntities {
			var user entities.User
			if err := json.Unmarshal(entity.Data, &user); err != nil {
				d.logger.Warn("Failed to deserialize user", "id", entity.ID, "error", err)
				continue
			}

			// Check if user belongs to the organization
			for _, ref := range user.OrganizationRefs {
				if ref == orgID {
					users = append(users, &user)
					break
				}
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return users, nil
}
