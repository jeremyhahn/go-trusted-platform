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

package main

import (
	"log/slog"
	"strings"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// DeviceBinding exposes device service methods to the Wails frontend.
type DeviceBinding struct {
	logger *slog.Logger
	conn   *ConnectionBinding
}

// NewDeviceBinding creates a new DeviceBinding.
func NewDeviceBinding(logger *slog.Logger, conn *ConnectionBinding) *DeviceBinding {
	return &DeviceBinding{logger: logger, conn: conn}
}

// getClient returns the current platform client or an error.
func (b *DeviceBinding) getClient() (platform.Client, error) {
	cl, err := b.conn.loadClient()
	if err != nil {
		return nil, err
	}
	return *cl, nil
}

// CreateDevice creates a new device.
func (b *DeviceBinding) CreateDevice(attestPub, attestCert, ekCert string, eventLog []byte,
	hashAlgoID uint32, model, serial, signingPub string) (map[string]interface{}, error) {

	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Device().CreateDevice(b.conn.ctx, &platformv1.CreateDeviceRequest{
		Device: &platformv1.Device{
			AttestPub:  attestPub,
			AttestCert: attestCert,
			EkCert:     ekCert,
			EventLog:   eventLog,
			HashAlgoId: hashAlgoID,
			Model:      model,
			Serial:     serial,
			SigningPub: signingPub,
		},
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// GetDevice retrieves a device by ID.
func (b *DeviceBinding) GetDevice(id uint64) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Device().GetDevice(b.conn.ctx, &platformv1.GetDeviceRequest{
		Id: id,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// UpdateDevice updates an existing device.
func (b *DeviceBinding) UpdateDevice(id uint64, attestPub, attestCert, ekCert string,
	eventLog []byte, hashAlgoID uint32, model, serial,
	signingPub string) (map[string]interface{}, error) {

	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Device().UpdateDevice(b.conn.ctx, &platformv1.UpdateDeviceRequest{
		Device: &platformv1.Device{
			Id:         id,
			AttestPub:  attestPub,
			AttestCert: attestCert,
			EkCert:     ekCert,
			EventLog:   eventLog,
			HashAlgoId: hashAlgoID,
			Model:      model,
			Serial:     serial,
			SigningPub: signingPub,
		},
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// DeleteDevice deletes a device by ID.
func (b *DeviceBinding) DeleteDevice(id uint64) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Device().DeleteDevice(b.conn.ctx, &platformv1.DeleteDeviceRequest{
		Id: id,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// ListDevices lists devices with optional pagination.
func (b *DeviceBinding) ListDevices(page, pageSize uint32,
	sortBy string, ascending bool) (map[string]interface{}, error) {

	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Device().ListDevices(b.conn.ctx, &platformv1.ListDevicesRequest{
		Pagination: &platformv1.PaginationRequest{
			Page:      page,
			PageSize:  pageSize,
			SortBy:    sortBy,
			Ascending: ascending,
		},
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// FindDeviceBySerial looks up a device by its serial number.
func (b *DeviceBinding) FindDeviceBySerial(serial string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Device().FindDeviceBySerial(b.conn.ctx, &platformv1.FindDeviceBySerialRequest{
		Serial: serial,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// CountDevices returns the total number of registered devices.
func (b *DeviceBinding) CountDevices() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Device().CountDevices(b.conn.ctx, &platformv1.CountDevicesRequest{})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// CreateProfile creates a new device profile.
func (b *DeviceBinding) CreateProfile(name, model string,
	role string) (map[string]interface{}, error) {

	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	deviceRole, err := parseDeviceRole(role)
	if err != nil {
		return nil, err
	}
	resp, err := cl.Device().CreateProfile(b.conn.ctx, &platformv1.CreateProfileRequest{
		Profile: &platformv1.DeviceProfile{
			Name:  name,
			Model: model,
			Role:  deviceRole,
		},
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// GetProfile retrieves a device profile by ID.
func (b *DeviceBinding) GetProfile(id uint64) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Device().GetProfile(b.conn.ctx, &platformv1.GetProfileRequest{
		Id: id,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// UpdateProfile updates an existing device profile.
func (b *DeviceBinding) UpdateProfile(id uint64, name, model,
	role string) (map[string]interface{}, error) {

	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	deviceRole, err := parseDeviceRole(role)
	if err != nil {
		return nil, err
	}
	resp, err := cl.Device().UpdateProfile(b.conn.ctx, &platformv1.UpdateProfileRequest{
		Profile: &platformv1.DeviceProfile{
			Id:    id,
			Name:  name,
			Model: model,
			Role:  deviceRole,
		},
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// DeleteProfile deletes a device profile by ID.
func (b *DeviceBinding) DeleteProfile(id uint64) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Device().DeleteProfile(b.conn.ctx, &platformv1.DeleteProfileRequest{
		Id: id,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// ListProfiles lists device profiles with optional pagination.
func (b *DeviceBinding) ListProfiles(page, pageSize uint32,
	sortBy string, ascending bool) (map[string]interface{}, error) {

	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Device().ListProfiles(b.conn.ctx, &platformv1.ListProfilesRequest{
		Pagination: &platformv1.PaginationRequest{
			Page:      page,
			PageSize:  pageSize,
			SortBy:    sortBy,
			Ascending: ascending,
		},
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// FindProfileByMACAddress looks up a device profile by MAC address.
func (b *DeviceBinding) FindProfileByMACAddress(macAddress string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Device().FindProfileByMACAddress(b.conn.ctx,
		&platformv1.FindProfileByMACAddressRequest{
			MacAddress: macAddress,
		})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// FindProfileBySerial looks up a device profile by serial number.
func (b *DeviceBinding) FindProfileBySerial(serial string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Device().FindProfileBySerial(b.conn.ctx,
		&platformv1.FindProfileBySerialRequest{
			Serial: serial,
		})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// FindMatchingProfile finds a device profile matching the given criteria.
func (b *DeviceBinding) FindMatchingProfile(macAddress, serial,
	model string) (map[string]interface{}, error) {

	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Device().FindMatchingProfile(b.conn.ctx,
		&platformv1.FindMatchingProfileRequest{
			MacAddress: macAddress,
			Serial:     serial,
			Model:      model,
		})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// CountProfiles returns the total number of device profiles.
func (b *DeviceBinding) CountProfiles() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Device().CountProfiles(b.conn.ctx, &platformv1.CountProfilesRequest{})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// ActivateDevice activates a device by serial and MAC address.
func (b *DeviceBinding) ActivateDevice(serial, macAddress string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Device().ActivateDevice(b.conn.ctx, &platformv1.ActivateDeviceRequest{
		Serial:     serial,
		MacAddress: macAddress,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// parseDeviceRole converts a device role string to the protobuf enum.
// It accepts both short names (e.g., "server") and full enum names
// (e.g., "DEVICE_ROLE_SERVER").
func parseDeviceRole(input string) (platformv1.DeviceRole, error) {
	if input == "" {
		return platformv1.DeviceRole_DEVICE_ROLE_UNSPECIFIED, nil
	}

	upper := strings.ToUpper(input)

	if val, ok := platformv1.DeviceRole_value[upper]; ok {
		return platformv1.DeviceRole(val), nil
	}

	prefixed := "DEVICE_ROLE_" + upper
	if val, ok := platformv1.DeviceRole_value[prefixed]; ok {
		return platformv1.DeviceRole(val), nil
	}

	return platformv1.DeviceRole_DEVICE_ROLE_UNSPECIFIED,
		&InvalidDeviceRoleError{Input: input}
}

// AssignProfileToDevice binds a profile to a specific device identity by
// EK serial and/or MAC address, optionally prestaging the device's
// PEM-encoded EK certificate (source-agnostic: swtpm-backed vTPM or
// physical hardware TPM).
func (b *DeviceBinding) AssignProfileToDevice(profileID uint64, ekSerial, macAddress,
	ekCert string) (map[string]interface{}, error) {

	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Device().AssignProfileToDevice(b.conn.ctx, &platformv1.AssignProfileToDeviceRequest{
		ProfileId:  profileID,
		EkSerial:   ekSerial,
		MacAddress: macAddress,
		EkCert:     ekCert,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}

// UnassignProfileFromDevice clears a profile's device binding: the EK
// serial, MAC address, prestaged EK certificate, and assignment state are
// all reset.
func (b *DeviceBinding) UnassignProfileFromDevice(profileID uint64) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}
	resp, err := cl.Device().UnassignProfileFromDevice(b.conn.ctx, &platformv1.UnassignProfileFromDeviceRequest{
		ProfileId: profileID,
	})
	if err != nil {
		return nil, err
	}
	return protoToMap(resp)
}
