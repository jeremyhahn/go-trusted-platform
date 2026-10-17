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

// DeviceProfileGet retrieves a device profile by ID. A missing profile is
// NotFound, as on gRPC.
func (p *MCPServiceProvider) DeviceProfileGet(ctx context.Context, id uint64) (*deviceentities.DeviceProfile, error) {
	if p.deviceProfileService == nil {
		return nil, ErrServiceNotAvailable{Service: "device_profile"}
	}
	profile, err := p.deviceProfileService.Get(ctx, id)
	if err != nil {
		return nil, deviceStatusError(err)
	}
	return profile, nil
}

// DeviceProfileMatch returns the profile whose match rules fit the device
// attributes. No match is NotFound, as on gRPC.
func (p *MCPServiceProvider) DeviceProfileMatch(ctx context.Context, macAddr, serial, model string) (*deviceentities.DeviceProfile, error) {
	if p.deviceProfileService == nil {
		return nil, ErrServiceNotAvailable{Service: "device_profile"}
	}
	profile, err := p.deviceProfileService.FindMatchingProfile(ctx, macAddr, serial, model)
	if err != nil {
		return nil, deviceStatusError(err)
	}
	return profile, nil
}

// DeviceProfileFindByMAC returns the profile whose MAC prefix rule fits the
// device MAC address. No match is NotFound, as on gRPC.
func (p *MCPServiceProvider) DeviceProfileFindByMAC(ctx context.Context, macAddr string) (*deviceentities.DeviceProfile, error) {
	if p.deviceProfileService == nil {
		return nil, ErrServiceNotAvailable{Service: "device_profile"}
	}
	profile, err := p.deviceProfileService.FindByMACAddress(ctx, macAddr)
	if err != nil {
		return nil, deviceStatusError(err)
	}
	return profile, nil
}

// DeviceProfileFindConfig resolves a booting machine's configuration profile
// from its EK serial or MAC address through the same finder gRPC
// FindConfigForDevice uses; a profile service that cannot resolve configs is
// ErrDeviceConfigFinderUnavailable, as on gRPC.
func (p *MCPServiceProvider) DeviceProfileFindConfig(ctx context.Context, ekSerial, macAddr string) (*deviceentities.DeviceProfile, error) {
	if p.deviceProfileService == nil {
		return nil, ErrServiceNotAvailable{Service: "device_profile"}
	}
	finder, ok := p.deviceProfileService.(device.ConfigForDeviceFinder)
	if !ok {
		return nil, ErrDeviceConfigFinderUnavailable{}
	}
	profile, err := finder.FindConfigForDevice(ctx, ekSerial, macAddr)
	if err != nil {
		return nil, deviceStatusError(err)
	}
	return profile, nil
}

// DeviceProfileFindBySerial returns the profile whose serial prefix rule fits
// the device serial number. No match is NotFound, as on gRPC.
func (p *MCPServiceProvider) DeviceProfileFindBySerial(ctx context.Context, serial string) (*deviceentities.DeviceProfile, error) {
	if p.deviceProfileService == nil {
		return nil, ErrServiceNotAvailable{Service: "device_profile"}
	}
	profile, err := p.deviceProfileService.FindBySerial(ctx, serial)
	if err != nil {
		return nil, deviceStatusError(err)
	}
	return profile, nil
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
func (p *MCPServiceProvider) DeviceProfileUpdate(ctx context.Context, profile *deviceentities.DeviceProfile, opts ...device.ProfileUpdateOption) (*deviceentities.DeviceProfile, error) {
	if p.deviceProfileService == nil {
		return nil, ErrServiceNotAvailable{Service: "device_profile"}
	}
	if err := p.deviceProfileService.Update(ctx, profile, opts...); err != nil {
		return nil, err
	}
	return profile, nil
}

// DeviceProfileDelete removes a device profile by ID. A missing profile is
// NotFound, as on gRPC.
func (p *MCPServiceProvider) DeviceProfileDelete(ctx context.Context, id uint64) error {
	if p.deviceProfileService == nil {
		return ErrServiceNotAvailable{Service: "device_profile"}
	}
	profile, err := p.deviceProfileService.Get(ctx, id)
	if err != nil {
		return deviceStatusError(err)
	}
	return deviceStatusError(p.deviceProfileService.Delete(ctx, profile))
}

// DeviceProfileAssign binds a profile to a device identity (EK serial
// and/or MAC address), optionally prestaging the device's PEM-encoded EK
// certificate, and returns the updated profile. Argument validation
// (profile ID, device identity, EK certificate PEM) happens at the MCP
// tool boundary; this bridge delegates straight to the platform device
// profile service so the MCP and gRPC transports share one code path.
func (p *MCPServiceProvider) DeviceProfileAssign(ctx context.Context, profileID, deviceID uint64, ekSerial, macAddress, ekCertPEM string) (*deviceentities.DeviceProfile, error) {
	if p.deviceProfileService == nil {
		return nil, ErrServiceNotAvailable{Service: "device_profile"}
	}
	binding := device.DeviceBinding{EKSerial: ekSerial, MAC: macAddress, EKCert: ekCertPEM}
	if deviceID != 0 {
		if p.deviceService == nil {
			return nil, ErrServiceNotAvailable{Service: "device"}
		}
		dev, err := p.deviceService.Get(ctx, deviceID)
		if err != nil {
			return nil, err
		}
		binding, err = device.BindingFromDevice(dev, binding.EKSerial, binding.MAC, binding.EKCert)
		if err != nil {
			return nil, err
		}
	}
	if err := p.deviceProfileService.AssignToDeviceWithEK(ctx, profileID, binding.EKSerial, binding.MAC, binding.EKCert); err != nil {
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

// DeviceTemplateCreate stores a device template through the template
// service the REST template handlers use, assigning an ID when absent.
func (p *MCPServiceProvider) DeviceTemplateCreate(ctx context.Context, template *deviceentities.DeviceTemplate) (*deviceentities.DeviceTemplate, error) {
	if p.deviceTemplateService == nil {
		return nil, ErrServiceNotAvailable{Service: "device_template"}
	}
	if template.ID == 0 {
		template.ID = device.NewID()
	}
	if err := p.deviceTemplateService.Save(ctx, template); err != nil {
		return nil, err
	}
	return template, nil
}

// DeviceTemplateGet returns the stored device template with the given ID.
func (p *MCPServiceProvider) DeviceTemplateGet(ctx context.Context, id uint64) (*deviceentities.DeviceTemplate, error) {
	if p.deviceTemplateService == nil {
		return nil, ErrServiceNotAvailable{Service: "device_template"}
	}
	template, err := p.deviceTemplateService.Get(ctx, id)
	if err != nil {
		return nil, deviceStatusError(err)
	}
	return template, nil
}

// DeviceTemplateList returns one page of device templates and the total
// number of stored templates.
func (p *MCPServiceProvider) DeviceTemplateList(ctx context.Context, page, pageSize int) ([]*deviceentities.DeviceTemplate, int, error) {
	if p.deviceTemplateService == nil {
		return nil, 0, ErrServiceNotAvailable{Service: "device_template"}
	}
	result, err := p.deviceTemplateService.Page(ctx, datastore.PageQuery{
		Page:      page,
		PageSize:  pageSize,
		SortOrder: datastore.SortAscending,
	})
	if err != nil {
		return nil, 0, deviceStatusError(err)
	}
	return result.Entities, result.Total, nil
}

// DeviceTemplateUpdate replaces the stored device template whose ID the
// template carries.
func (p *MCPServiceProvider) DeviceTemplateUpdate(ctx context.Context, template *deviceentities.DeviceTemplate) (*deviceentities.DeviceTemplate, error) {
	if p.deviceTemplateService == nil {
		return nil, ErrServiceNotAvailable{Service: "device_template"}
	}
	if err := p.deviceTemplateService.Update(ctx, template); err != nil {
		return nil, deviceStatusError(err)
	}
	return template, nil
}

// DeviceTemplateDelete removes the stored device template with the given ID.
func (p *MCPServiceProvider) DeviceTemplateDelete(ctx context.Context, id uint64) error {
	if p.deviceTemplateService == nil {
		return ErrServiceNotAvailable{Service: "device_template"}
	}
	template, err := p.deviceTemplateService.Get(ctx, id)
	if err != nil {
		return deviceStatusError(err)
	}
	return deviceStatusError(p.deviceTemplateService.Delete(ctx, template))
}

// DeviceProfileFromTemplate builds a profile from a stored template plus
// the overrides and saves it, assigning a profile ID when absent.
func (p *MCPServiceProvider) DeviceProfileFromTemplate(ctx context.Context, templateID uint64, overrides *deviceentities.DeviceProfile) (*deviceentities.DeviceProfile, error) {
	if p.deviceTemplateService == nil {
		return nil, ErrServiceNotAvailable{Service: "device_template"}
	}
	if p.deviceProfileService == nil {
		return nil, ErrServiceNotAvailable{Service: "device_profile"}
	}
	profile, err := p.deviceTemplateService.ToProfile(ctx, templateID, overrides)
	if err != nil {
		return nil, err
	}
	if profile.ID == 0 {
		profile.ID = device.NewID()
	}
	if err := p.deviceProfileService.Save(ctx, profile); err != nil {
		return nil, err
	}
	return profile, nil
}
