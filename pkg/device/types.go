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

package device

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

// DeviceService provides device management operations.
// This interface abstracts the concrete Service implementation for
// dependency injection and testing purposes.
type DeviceService interface {
	// Save persists a device. The device must have a non-zero ID.
	Save(ctx context.Context, device *entities.Device) error

	// Get retrieves a device by its ID.
	Get(ctx context.Context, id uint64) (*entities.Device, error)

	// Delete removes a device from storage.
	Delete(ctx context.Context, device *entities.Device) error

	// Update modifies an existing device. The device must exist.
	Update(ctx context.Context, device *entities.Device) error

	// Count returns the total number of devices.
	Count(ctx context.Context) (int, error)

	// Page retrieves a paginated list of devices.
	Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*entities.Device], error)

	// FindBySerial finds a device by its serial number.
	FindBySerial(ctx context.Context, serial string) (*entities.Device, error)
}

// DeviceProfileService provides device profile management operations.
// This interface abstracts the concrete ProfileService implementation for
// dependency injection and testing purposes.
type DeviceProfileService interface {
	// Save persists a device profile. The profile must have a non-zero ID.
	Save(ctx context.Context, profile *entities.DeviceProfile) error

	// Get retrieves a device profile by its ID.
	Get(ctx context.Context, id uint64) (*entities.DeviceProfile, error)

	// Delete removes a device profile from storage.
	Delete(ctx context.Context, profile *entities.DeviceProfile) error

	// Update modifies an existing device profile. The profile must exist.
	Update(ctx context.Context, profile *entities.DeviceProfile) error

	// Count returns the total number of device profiles.
	Count(ctx context.Context) (int, error)

	// Page retrieves a paginated list of device profiles.
	Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*entities.DeviceProfile], error)

	// FindByMACAddress finds a profile matching the given MAC address.
	FindByMACAddress(ctx context.Context, macAddr string) (*entities.DeviceProfile, error)

	// FindBySerial finds a profile matching the given serial number.
	FindBySerial(ctx context.Context, serial string) (*entities.DeviceProfile, error)

	// FindMatchingProfile finds a profile that matches the given device characteristics.
	FindMatchingProfile(ctx context.Context, macAddr, serial, model string) (*entities.DeviceProfile, error)
}

// DeviceTemplateService provides device template management operations.
// This interface abstracts the concrete TemplateService implementation for
// dependency injection and testing purposes.
type DeviceTemplateService interface {
	// Save persists a device template. The template must have a non-zero ID.
	Save(ctx context.Context, template *entities.DeviceTemplate) error

	// Get retrieves a device template by its ID.
	Get(ctx context.Context, id uint64) (*entities.DeviceTemplate, error)

	// Delete removes a device template from storage.
	Delete(ctx context.Context, template *entities.DeviceTemplate) error

	// Update modifies an existing device template. The template must exist.
	Update(ctx context.Context, template *entities.DeviceTemplate) error

	// Count returns the total number of device templates.
	Count(ctx context.Context) (int, error)

	// Page retrieves a paginated list of device templates.
	Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*entities.DeviceTemplate], error)

	// FindByName finds a template by its name within a tenant.
	FindByName(ctx context.Context, tenantID, name string) (*entities.DeviceTemplate, error)

	// ToProfile deep-copies the template config into a new DeviceProfile with optional overrides.
	ToProfile(ctx context.Context, templateID uint64, overrides *entities.DeviceProfile) (*entities.DeviceProfile, error)
}
