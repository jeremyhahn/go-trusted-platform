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
	"errors"
	"fmt"
	"strings"

	devicepkg "github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

// isNotFoundError checks if the error indicates a record was not found.
// This handles both datastore.ErrRecordNotFound and QuicBaaS's error types.
func isNotFoundError(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, datastore.ErrRecordNotFound) {
		return true
	}
	// Check for QuicBaaS error types by checking error message
	errMsg := err.Error()
	return strings.Contains(errMsg, "not found")
}

// DeviceServiceInterface defines the interface for device operations
type DeviceServiceInterface interface {
	Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*entities.Device], error)
}

// DeviceProfileServiceInterface defines the interface for device profile operations
type DeviceProfileServiceInterface interface {
	FindMatchingProfile(ctx context.Context, macAddr, serial, model string) (*entities.DeviceProfile, error)
}

// ProfileServiceAdapter adapts the device package's ProfileService to the
// webservice's ProfileService interface.
type ProfileServiceAdapter struct {
	deviceService  DeviceServiceInterface
	profileService DeviceProfileServiceInterface
}

// NewProfileServiceAdapter creates a new adapter for the device profile service.
func NewProfileServiceAdapter(
	deviceService *devicepkg.Service,
	profileService *devicepkg.ProfileService,
) ProfileService {
	return &ProfileServiceAdapter{
		deviceService:  deviceService,
		profileService: profileService,
	}
}

// NewProfileServiceAdapterWithInterfaces creates an adapter using interface types for testing.
func NewProfileServiceAdapterWithInterfaces(
	deviceService DeviceServiceInterface,
	profileService DeviceProfileServiceInterface,
) ProfileService {
	return &ProfileServiceAdapter{
		deviceService:  deviceService,
		profileService: profileService,
	}
}

// GetBySerial retrieves a device profile by serial number.
// It first attempts to find a device by serial number, then looks up the associated profile.
func (a *ProfileServiceAdapter) GetBySerial(ctx context.Context, serial string) (*ProfileResponse, error) {
	if serial == "" {
		return nil, ErrProfileNotFoundBySerial
	}

	// Try to find device by serial number
	device, err := a.findDeviceBySerial(ctx, serial)
	if err != nil {
		return nil, fmt.Errorf("failed to find device by serial: %w", err)
	}

	// Get the device's profile using FindMatchingProfile
	profile, err := a.profileService.FindMatchingProfile(ctx, "", serial, device.Model)
	if err != nil {
		if isNotFoundError(err) {
			return nil, ErrProfileNotFoundBySerial
		}
		return nil, fmt.Errorf("failed to find matching profile: %w", err)
	}

	// Convert DeviceProfile to ProfileResponse
	return ProfileFromDeviceProfile(profile, serial), nil
}

// findDeviceBySerial searches for a device by its serial number.
// This performs a page query through all devices to find a match.
func (a *ProfileServiceAdapter) findDeviceBySerial(ctx context.Context, serial string) (*entities.Device, error) {
	pageSize := 100
	page := 1

	for {
		query := datastore.PageQuery{
			Page:      page,
			PageSize:  pageSize,
			SortOrder: datastore.SORT_ASCENDING,
		}

		result, err := a.deviceService.Page(ctx, query)
		if err != nil {
			return nil, fmt.Errorf("failed to page devices: %w", err)
		}

		// Search for device with matching serial
		for _, device := range result.Entities {
			if device.Serial == serial {
				return device, nil
			}
		}

		// Check if we've reached the end
		if len(result.Entities) < pageSize {
			break
		}

		page++
	}

	return nil, datastore.ErrRecordNotFound
}
