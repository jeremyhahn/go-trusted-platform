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

	"github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

const entityTypeZone = "Zone"

// ZoneDAO provides a QuicBaaS-backed implementation for DNS zone storage.
type ZoneDAO struct {
	*GenericDAO[*entities.Zone]
}

// NewZoneDAO creates a new ZoneDAO.
func NewZoneDAO(storage Storage, logger *logging.Logger, opts ...DAOOption) *ZoneDAO {
	return &ZoneDAO{
		GenericDAO: NewGenericDAO[*entities.Zone](
			storage,
			entityTypeZone,
			func() *entities.Zone { return &entities.Zone{} },
			logger,
			opts...,
		),
	}
}

// GetByName retrieves a zone by its name using a secondary index query.
// If no secondary index exists, falls back to scanning all zones.
func (d *ZoneDAO) GetByName(ctx context.Context, name string) (*entities.Zone, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	// Try secondary index query first
	results, err := d.storage.Query(ctx, entityTypeZone, "Name", []byte(name), d.shardID)
	if err != nil {
		// Fall back to scanning all zones
		return d.getZoneByScan(ctx, name)
	}

	// If Query returns empty results, fall back to scan
	// This happens when QuicBaaS doesn't have a secondary index on the Name field
	if len(results) == 0 {
		return d.getZoneByScan(ctx, name)
	}

	var zone entities.Zone
	if err := json.Unmarshal(results[0].Data, &zone); err != nil {
		return nil, ErrDeserializationFailed{EntityType: entityTypeZone, Cause: err}
	}

	return &zone, nil
}

// getZoneByScan scans all zones and finds one by name.
// This is a fallback when secondary index query is not available.
func (d *ZoneDAO) getZoneByScan(ctx context.Context, name string) (*entities.Zone, error) {
	pageToken := ""

	for {
		svcEntities, nextToken, err := d.storage.List(ctx, entityTypeZone, 1000, pageToken, d.shardID)
		if err != nil {
			return nil, err
		}

		for _, entity := range svcEntities {
			var zone entities.Zone
			if err := json.Unmarshal(entity.Data, &zone); err != nil {
				d.logger.Warn("Failed to deserialize zone", "id", entity.ID, "error", err)
				continue
			}

			if zone.Name == name {
				return &zone, nil
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return nil, ErrNotFoundByIndex{EntityType: entityTypeZone, IndexField: "Name", Value: name}
}
