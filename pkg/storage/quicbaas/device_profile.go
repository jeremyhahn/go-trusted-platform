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
	"strings"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

const entityTypeDeviceProfile = "DeviceProfile"

// DeviceProfileDAO provides a QuicBaaS-backed implementation for device profile storage.
type DeviceProfileDAO struct {
	*GenericDAO[*entities.DeviceProfile]
}

// NewDeviceProfileDAO creates a new DeviceProfileDAO.
func NewDeviceProfileDAO(storage Storage, logger *logging.Logger, opts ...DAOOption) *DeviceProfileDAO {
	return &DeviceProfileDAO{
		GenericDAO: NewGenericDAO[*entities.DeviceProfile](
			storage,
			entityTypeDeviceProfile,
			func() *entities.DeviceProfile { return &entities.DeviceProfile{} },
			logger,
			opts...,
		),
	}
}

// GetByModel retrieves a device profile by its model name.
// Falls back to scanning if secondary index is not available.
func (d *DeviceProfileDAO) GetByModel(ctx context.Context, model string) (*entities.DeviceProfile, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	// Try secondary index query first
	results, err := d.storage.Query(ctx, entityTypeDeviceProfile, "Model", []byte(model), d.shardID)
	if err != nil {
		// Fall back to scanning all profiles
		return d.getProfileByScan(ctx, model)
	}

	if len(results) == 0 {
		return d.getProfileByScan(ctx, model)
	}

	var profile entities.DeviceProfile
	if err := json.Unmarshal(results[0].Data, &profile); err != nil {
		return nil, ErrDeserializationFailed{EntityType: entityTypeDeviceProfile, Cause: err}
	}

	return &profile, nil
}

// getProfileByScan scans all profiles and finds one by model.
func (d *DeviceProfileDAO) getProfileByScan(ctx context.Context, model string) (*entities.DeviceProfile, error) {
	pageToken := ""

	for {
		svcEntities, nextToken, err := d.storage.List(ctx, entityTypeDeviceProfile, 1000, pageToken, d.shardID)
		if err != nil {
			return nil, err
		}

		for _, entity := range svcEntities {
			var profile entities.DeviceProfile
			if err := json.Unmarshal(entity.Data, &profile); err != nil {
				d.logger.Warn("Failed to deserialize device profile", "id", entity.ID, "error", err)
				continue
			}

			if profile.Model == model {
				return &profile, nil
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return nil, ErrNotFoundByIndex{EntityType: entityTypeDeviceProfile, IndexField: "Model", Value: model}
}

// FindByMACPrefix finds a profile where the profile's MACPrefix matches as a prefix of the given macAddr.
func (d *DeviceProfileDAO) FindByMACPrefix(ctx context.Context, macAddr string) (*entities.DeviceProfile, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	if macAddr == "" {
		return nil, ErrNotFoundByIndex{EntityType: entityTypeDeviceProfile, IndexField: "MACPrefix", Value: macAddr}
	}

	// Normalize MAC address to lowercase for consistent comparison
	macAddr = strings.ToLower(macAddr)

	pageToken := ""

	for {
		svcEntities, nextToken, err := d.storage.List(ctx, entityTypeDeviceProfile, 1000, pageToken, d.shardID)
		if err != nil {
			return nil, err
		}

		for _, entity := range svcEntities {
			var profile entities.DeviceProfile
			if err := json.Unmarshal(entity.Data, &profile); err != nil {
				d.logger.Warn("Failed to deserialize device profile", "id", entity.ID, "error", err)
				continue
			}

			if profile.MatchRules != nil && profile.MatchRules.MACPrefix != "" {
				prefix := strings.ToLower(profile.MatchRules.MACPrefix)
				if len(macAddr) >= len(prefix) && macAddr[:len(prefix)] == prefix {
					return &profile, nil
				}
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return nil, ErrNotFoundByIndex{EntityType: entityTypeDeviceProfile, IndexField: "MACPrefix", Value: macAddr}
}

// FindBySerialPrefix finds a profile where the profile's SerialPrefix matches as a prefix of the given serial.
func (d *DeviceProfileDAO) FindBySerialPrefix(ctx context.Context, serial string) (*entities.DeviceProfile, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	if serial == "" {
		return nil, ErrNotFoundByIndex{EntityType: entityTypeDeviceProfile, IndexField: "SerialPrefix", Value: serial}
	}

	// Normalize serial to uppercase for consistent comparison
	serial = strings.ToUpper(serial)

	pageToken := ""

	for {
		svcEntities, nextToken, err := d.storage.List(ctx, entityTypeDeviceProfile, 1000, pageToken, d.shardID)
		if err != nil {
			return nil, err
		}

		for _, entity := range svcEntities {
			var profile entities.DeviceProfile
			if err := json.Unmarshal(entity.Data, &profile); err != nil {
				d.logger.Warn("Failed to deserialize device profile", "id", entity.ID, "error", err)
				continue
			}

			if profile.MatchRules != nil && profile.MatchRules.SerialPrefix != "" {
				prefix := strings.ToUpper(profile.MatchRules.SerialPrefix)
				if len(serial) >= len(prefix) && serial[:len(prefix)] == prefix {
					return &profile, nil
				}
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return nil, ErrNotFoundByIndex{EntityType: entityTypeDeviceProfile, IndexField: "SerialPrefix", Value: serial}
}

// FindMatchingProfile returns the first stored profile whose match rules fit
// the MAC prefix, the serial prefix or the model: any one non-empty rule is
// enough (ProfileMatchRules.Matches). There is no priority between the fields
// or between profiles; the scan returns the first hit in storage-iteration
// order, which is not specified, so overlapping rules make the result
// arbitrary (docs/device/architecture.md §7).
func (d *DeviceProfileDAO) FindMatchingProfile(ctx context.Context, macAddr, serial, model string) (*entities.DeviceProfile, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	// Normalize inputs for consistent comparison
	macAddr = strings.ToLower(macAddr)
	serial = strings.ToUpper(serial)

	pageToken := ""

	for {
		svcEntities, nextToken, err := d.storage.List(ctx, entityTypeDeviceProfile, 1000, pageToken, d.shardID)
		if err != nil {
			return nil, err
		}

		for _, entity := range svcEntities {
			var profile entities.DeviceProfile
			if err := json.Unmarshal(entity.Data, &profile); err != nil {
				d.logger.Warn("Failed to deserialize device profile", "id", entity.ID, "error", err)
				continue
			}

			if profile.MatchRules != nil && normalizedMatchRules(profile.MatchRules).Matches(macAddr, serial, model) {
				return &profile, nil
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return nil, ErrNotFoundByIndex{EntityType: entityTypeDeviceProfile, IndexField: "MatchRules", Value: "no match"}
}

// normalizedMatchRules returns a copy of rules with its prefixes in the case
// FindMatchingProfile compares them in: the MAC prefix lowercase, the serial
// prefixes uppercase. A stored prefix then matches whatever case it was
// written in, as it does in FindByMACPrefix and FindBySerialPrefix.
func normalizedMatchRules(rules *entities.ProfileMatchRules) *entities.ProfileMatchRules {
	normalized := *rules
	normalized.MACPrefix = strings.ToLower(rules.MACPrefix)
	normalized.SerialPrefix = strings.ToUpper(rules.SerialPrefix)
	normalized.SerialPattern = strings.ToUpper(rules.SerialPattern)
	return &normalized
}

// FindByEKSerial finds a profile by exact TPM EK certificate serial number.
// The comparison is case-insensitive.
func (d *DeviceProfileDAO) FindByEKSerial(ctx context.Context, ekSerial string) (*entities.DeviceProfile, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	if ekSerial == "" {
		return nil, ErrNotFoundByIndex{EntityType: entityTypeDeviceProfile, IndexField: "EKSerial", Value: ekSerial}
	}

	pageToken := ""

	for {
		svcEntities, nextToken, err := d.storage.List(ctx, entityTypeDeviceProfile, 1000, pageToken, d.shardID)
		if err != nil {
			return nil, err
		}

		for _, entity := range svcEntities {
			var profile entities.DeviceProfile
			if err := json.Unmarshal(entity.Data, &profile); err != nil {
				d.logger.Warn("Failed to deserialize device profile", "id", entity.ID, "error", err)
				continue
			}

			if strings.EqualFold(profile.EKSerial, ekSerial) {
				return &profile, nil
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return nil, ErrNotFoundByIndex{EntityType: entityTypeDeviceProfile, IndexField: "EKSerial", Value: ekSerial}
}

// FindByExactMAC finds a profile by exact MAC address.
// The comparison is case-insensitive.
func (d *DeviceProfileDAO) FindByExactMAC(ctx context.Context, mac string) (*entities.DeviceProfile, error) {
	ctx, cancel := context.WithTimeout(ctx, d.requestTimeout)
	defer cancel()

	if mac == "" {
		return nil, ErrNotFoundByIndex{EntityType: entityTypeDeviceProfile, IndexField: "MACAddress", Value: mac}
	}

	pageToken := ""

	for {
		svcEntities, nextToken, err := d.storage.List(ctx, entityTypeDeviceProfile, 1000, pageToken, d.shardID)
		if err != nil {
			return nil, err
		}

		for _, entity := range svcEntities {
			var profile entities.DeviceProfile
			if err := json.Unmarshal(entity.Data, &profile); err != nil {
				d.logger.Warn("Failed to deserialize device profile", "id", entity.ID, "error", err)
				continue
			}

			if strings.EqualFold(profile.MACAddress, mac) {
				return &profile, nil
			}
		}

		if nextToken == "" {
			break
		}
		pageToken = nextToken
	}

	return nil, ErrNotFoundByIndex{EntityType: entityTypeDeviceProfile, IndexField: "MACAddress", Value: mac}
}

// FindConfigForDevice finds a profile for a device using resolution priority:
// 1. Exact EK serial match
// 2. Exact MAC address match
// 3. Prefix match rules (MAC prefix, serial prefix, model)
// Returns ErrNotFoundByIndex if no matching profile is found.
func (d *DeviceProfileDAO) FindConfigForDevice(ctx context.Context, ekSerial, mac string) (*entities.DeviceProfile, error) {
	// Try exact EK serial match first
	if ekSerial != "" {
		profile, err := d.FindByEKSerial(ctx, ekSerial)
		if err == nil {
			return profile, nil
		}
	}

	// Try exact MAC address match
	if mac != "" {
		profile, err := d.FindByExactMAC(ctx, mac)
		if err == nil {
			return profile, nil
		}
	}

	// Fall back to prefix match rules using MAC
	if mac != "" {
		profile, err := d.FindMatchingProfile(ctx, mac, "", "")
		if err == nil {
			return profile, nil
		}
	}

	return nil, ErrNotFoundByIndex{EntityType: entityTypeDeviceProfile, IndexField: "ConfigForDevice", Value: "no match"}
}
