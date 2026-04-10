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

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

const entityTypeDeviceTemplate = "DeviceTemplate"

// DeviceTemplateDAO provides a QuicBaaS-backed implementation for device template storage.
type DeviceTemplateDAO struct {
	*GenericDAO[*entities.DeviceTemplate]
}

// NewDeviceTemplateDAO creates a new DeviceTemplateDAO.
func NewDeviceTemplateDAO(storage Storage, logger *logging.Logger, opts ...DAOOption) *DeviceTemplateDAO {
	return &DeviceTemplateDAO{
		GenericDAO: NewGenericDAO[*entities.DeviceTemplate](
			storage,
			entityTypeDeviceTemplate,
			func() *entities.DeviceTemplate { return &entities.DeviceTemplate{} },
			logger,
			opts...,
		),
	}
}

// FindByName finds a template by its name within a tenant.
// Scans all templates and matches on both name and tenantID.
func (d *DeviceTemplateDAO) FindByName(ctx context.Context, tenantID, name string) (*entities.DeviceTemplate, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	pageToken := ""

	for {
		svcEntities, nextToken, err := d.storage.List(ctx, entityTypeDeviceTemplate, 1000, pageToken, d.shardID)
		if err != nil {
			return nil, err
		}

		for _, entity := range svcEntities {
			var template entities.DeviceTemplate
			if err := json.Unmarshal(entity.Data, &template); err != nil {
				d.logger.Warn("Failed to deserialize device template", "id", entity.ID, "error", err)
				continue
			}

			if template.Name == name && template.TenantID == tenantID {
				return &template, nil
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return nil, ErrNotFoundByIndex{EntityType: entityTypeDeviceTemplate, IndexField: "Name", Value: name}
}
