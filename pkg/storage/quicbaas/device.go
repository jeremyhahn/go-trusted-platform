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

const entityTypeDevice = "Device"

// DeviceDAO provides a QuicBaaS-backed implementation for device storage.
type DeviceDAO struct {
	*GenericDAO[*entities.Device]
}

// NewDeviceDAO creates a new DeviceDAO.
func NewDeviceDAO(storage Storage, logger *logging.Logger, opts ...DAOOption) *DeviceDAO {
	return &DeviceDAO{
		GenericDAO: NewGenericDAO[*entities.Device](
			storage,
			entityTypeDevice,
			func() *entities.Device { return &entities.Device{} },
			logger,
			opts...,
		),
	}
}

// FindBySerial finds a device by its serial number.
// Falls back to scanning if secondary index is not available.
func (d *DeviceDAO) FindBySerial(ctx context.Context, serial string) (*entities.Device, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	// Try secondary index query first
	results, err := d.storage.Query(ctx, entityTypeDevice, "Serial", []byte(serial), d.shardID)
	if err != nil {
		// Fall back to scanning all devices
		return d.getDeviceByScan(ctx, "Serial", serial)
	}

	if len(results) == 0 {
		return d.getDeviceByScan(ctx, "Serial", serial)
	}

	var device entities.Device
	if err := json.Unmarshal(results[0].Data, &device); err != nil {
		return nil, ErrDeserializationFailed{EntityType: entityTypeDevice, Cause: err}
	}

	return &device, nil
}


// FindByHostname finds a device by its IDevID hostname (CN).
// Falls back to scanning all devices when the secondary index is unavailable.
func (d *DeviceDAO) FindByHostname(ctx context.Context, hostname string) (*entities.Device, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	// Try secondary index query first.
	results, err := d.storage.Query(ctx, entityTypeDevice, "Hostname", []byte(hostname), d.shardID)
	if err != nil {
		return d.getDeviceByScan(ctx, "Hostname", hostname)
	}

	if len(results) == 0 {
		return d.getDeviceByScan(ctx, "Hostname", hostname)
	}

	var device entities.Device
	if err := json.Unmarshal(results[0].Data, &device); err != nil {
		return nil, ErrDeserializationFailed{EntityType: entityTypeDevice, Cause: err}
	}

	return &device, nil
}
// GetByModel retrieves all devices matching a specific model.
func (d *DeviceDAO) GetByModel(ctx context.Context, model string) ([]*entities.Device, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	var devices []*entities.Device
	pageToken := ""

	for {
		svcEntities, nextToken, err := d.storage.List(ctx, entityTypeDevice, 1000, pageToken, d.shardID)
		if err != nil {
			return nil, err
		}

		for _, entity := range svcEntities {
			var device entities.Device
			if err := json.Unmarshal(entity.Data, &device); err != nil {
				d.logger.Warn("Failed to deserialize device", "id", entity.ID, "error", err)
				continue
			}

			if device.Model == model {
				devices = append(devices, &device)
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return devices, nil
}

// getDeviceByScan scans all devices and finds one by a field value.
func (d *DeviceDAO) getDeviceByScan(ctx context.Context, field, value string) (*entities.Device, error) {
	pageToken := ""

	for {
		svcEntities, nextToken, err := d.storage.List(ctx, entityTypeDevice, 1000, pageToken, d.shardID)
		if err != nil {
			return nil, err
		}

		for _, entity := range svcEntities {
			var device entities.Device
			if err := json.Unmarshal(entity.Data, &device); err != nil {
				d.logger.Warn("Failed to deserialize device", "id", entity.ID, "error", err)
				continue
			}

			switch field {
			case "Serial":
				if device.Serial == value {
					return &device, nil
				}
			case "Model":
				if device.Model == value {
					return &device, nil
				}
			case "Hostname":
				if device.Hostname == value {
					return &device, nil
				}
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return nil, ErrNotFoundByIndex{EntityType: entityTypeDevice, IndexField: field, Value: value}
}
