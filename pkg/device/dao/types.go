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

package dao

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

// DeviceProfileDAO provides data access operations for device profiles.
type DeviceProfileDAO interface {
	datastore.GenericDAO[*entities.DeviceProfile]

	// FindByMACPrefix finds a profile matching the given MAC address prefix
	FindByMACPrefix(ctx context.Context, macAddr string) (*entities.DeviceProfile, error)

	// FindBySerialPrefix finds a profile matching the given serial number prefix
	FindBySerialPrefix(ctx context.Context, serial string) (*entities.DeviceProfile, error)

	// FindMatchingProfile finds a profile that matches the given device characteristics
	FindMatchingProfile(ctx context.Context, macAddr, serial, model string) (*entities.DeviceProfile, error)

	// FindByEKSerial finds a profile by exact TPM EK certificate serial number.
	FindByEKSerial(ctx context.Context, ekSerial string) (*entities.DeviceProfile, error)

	// FindByDICEDeviceID finds a profile by exact (case-insensitive) DICE
	// device id.
	FindByDICEDeviceID(ctx context.Context, diceDeviceID string) (*entities.DeviceProfile, error)

	// FindByExactMAC finds a profile by exact MAC address.
	FindByExactMAC(ctx context.Context, mac string) (*entities.DeviceProfile, error)

	// FindConfigForDevice finds a profile for a device using resolution priority:
	// 1. Exact EK serial match (across all tenants)
	// 2. Exact MAC address match (across all tenants)
	// 3. Prefix match rules (MAC prefix, serial prefix, model)
	// Returns the first matching profile. Searches all tenants since
	// the device doesn't know its tenant at boot time.
	FindConfigForDevice(ctx context.Context, ekSerial, mac string) (*entities.DeviceProfile, error)
}

// DeviceDAO provides data access operations for devices.
type DeviceDAO interface {
	datastore.GenericDAO[*entities.Device]

	// FindBySerial finds a device by its serial number.
	FindBySerial(ctx context.Context, serial string) (*entities.Device, error)

	// FindByHostname finds a device by its IDevID hostname (CN). Returns
	// ErrNotFoundByIndex when no matching record exists.
	FindByHostname(ctx context.Context, hostname string) (*entities.Device, error)
}

// DeviceTemplateDAO provides data access operations for device templates.
type DeviceTemplateDAO interface {
	datastore.GenericDAO[*entities.DeviceTemplate]

	// FindByName finds a template by its name within a tenant.
	FindByName(ctx context.Context, tenantID, name string) (*entities.DeviceTemplate, error)
}
