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

package daemon

import (
	"context"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	deviceentities "github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

// Compile-time check: the MCP service provider satisfies the optional
// device profile provider interface that unlocks the profile_* MCP tools.
var _ mcp.DeviceProfileProvider = (*MCPServiceProvider)(nil)

// DeviceProfileCreate persists a new device profile via the platform
// device profile service, generating an ID when the caller supplied none
// (matching the REST and gRPC create paths so profile creation has parity
// across transports).
func (p *MCPServiceProvider) DeviceProfileCreate(ctx context.Context, profile *deviceentities.DeviceProfile) (*deviceentities.DeviceProfile, error) {
	if p.deviceProfileService == nil {
		return nil, ErrServiceNotAvailable{Service: "device_profile"}
	}
	if profile.ID == 0 {
		profile.ID = device.NewID()
	}
	if err := p.deviceProfileService.Save(ctx, profile); err != nil {
		return nil, err
	}
	return profile, nil
}

// DeviceProfileGet retrieves a device profile by ID.
func (p *MCPServiceProvider) DeviceProfileGet(ctx context.Context, id uint64) (*deviceentities.DeviceProfile, error) {
	if p.deviceProfileService == nil {
		return nil, ErrServiceNotAvailable{Service: "device_profile"}
	}
	return p.deviceProfileService.Get(ctx, id)
}

// DeviceProfileList returns a page of device profiles and the total count.
func (p *MCPServiceProvider) DeviceProfileList(ctx context.Context, page, pageSize int) ([]*deviceentities.DeviceProfile, int, error) {
	if p.deviceProfileService == nil {
		return nil, 0, ErrServiceNotAvailable{Service: "device_profile"}
	}
	result, err := p.deviceProfileService.Page(ctx, datastore.PageQuery{
		Page:      page,
		PageSize:  pageSize,
		SortOrder: datastore.SortAscending,
	})
	if err != nil {
		return nil, 0, err
	}
	return result.Entities, result.Total, nil
}

// DeviceProfileUpdate replaces an existing device profile.
func (p *MCPServiceProvider) DeviceProfileUpdate(ctx context.Context, profile *deviceentities.DeviceProfile) (*deviceentities.DeviceProfile, error) {
	if p.deviceProfileService == nil {
		return nil, ErrServiceNotAvailable{Service: "device_profile"}
	}
	if err := p.deviceProfileService.Update(ctx, profile); err != nil {
		return nil, err
	}
	return profile, nil
}

// DeviceProfileDelete removes a device profile by ID.
func (p *MCPServiceProvider) DeviceProfileDelete(ctx context.Context, id uint64) error {
	if p.deviceProfileService == nil {
		return ErrServiceNotAvailable{Service: "device_profile"}
	}
	profile, err := p.deviceProfileService.Get(ctx, id)
	if err != nil {
		return err
	}
	return p.deviceProfileService.Delete(ctx, profile)
}

// DeviceProfileAssign binds a profile to a device identity (EK serial
// and/or MAC address), optionally prestaging the device's PEM-encoded EK
// certificate, and returns the updated profile. Argument validation
// (profile ID, device identity, EK certificate PEM) happens at the MCP
// tool boundary; this bridge delegates straight to the platform device
// profile service so the MCP and gRPC transports share one code path.
func (p *MCPServiceProvider) DeviceProfileAssign(ctx context.Context, profileID uint64, ekSerial, macAddress, ekCertPEM string) (*deviceentities.DeviceProfile, error) {
	if p.deviceProfileService == nil {
		return nil, ErrServiceNotAvailable{Service: "device_profile"}
	}
	if err := p.deviceProfileService.AssignToDeviceWithEK(ctx, profileID, ekSerial, macAddress, ekCertPEM); err != nil {
		return nil, err
	}
	return p.deviceProfileService.Get(ctx, profileID)
}

// DeviceProfileUnassign clears a profile's device binding and returns the
// updated profile.
func (p *MCPServiceProvider) DeviceProfileUnassign(ctx context.Context, profileID uint64) (*deviceentities.DeviceProfile, error) {
	if p.deviceProfileService == nil {
		return nil, ErrServiceNotAvailable{Service: "device_profile"}
	}
	if err := p.deviceProfileService.UnassignFromDevice(ctx, profileID); err != nil {
		return nil, err
	}
	return p.deviceProfileService.Get(ctx, profileID)
}
