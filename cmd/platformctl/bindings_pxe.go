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

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// PXEBinding exposes PXE provisioning service methods to the Wails frontend.
type PXEBinding struct {
	logger *slog.Logger
	conn   *ConnectionBinding
}

// NewPXEBinding creates a new PXEBinding.
func NewPXEBinding(logger *slog.Logger, conn *ConnectionBinding) *PXEBinding {
	return &PXEBinding{logger: logger, conn: conn}
}

// getClient returns the current platform client or an error.
func (b *PXEBinding) getClient() (platform.Client, error) {
	cl, err := b.conn.loadClient()
	if err != nil {
		return nil, err
	}
	return *cl, nil
}

// RegisterDevice registers a new PXE device by MAC address and port ID.
func (b *PXEBinding) RegisterDevice(macAddress string, portID string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.PXE().RegisterDevice(b.conn.ctx, &platformv1.RegisterPXEDeviceRequest{
		MacAddress: macAddress,
		PortId:     portID,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// GetDevice retrieves a PXE device by ID.
func (b *PXEBinding) GetDevice(deviceID string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.PXE().GetDevice(b.conn.ctx, &platformv1.GetPXEDeviceRequest{
		DeviceId: deviceID,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// ListDevices returns all registered PXE devices.
func (b *PXEBinding) ListDevices() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.PXE().ListDevices(b.conn.ctx, &platformv1.ListPXEDevicesRequest{})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// RemoveDevice removes a PXE device by ID.
func (b *PXEBinding) RemoveDevice(deviceID string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.PXE().RemoveDevice(b.conn.ctx, &platformv1.RemovePXEDeviceRequest{
		DeviceId: deviceID,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// UpdateState updates the provisioning state of a PXE device.
func (b *PXEBinding) UpdateState(deviceID string, state int32, reason string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.PXE().UpdateState(b.conn.ctx, &platformv1.UpdatePXEStateRequest{
		DeviceId: deviceID,
		State:    platformv1.ProvisioningState(state),
		Reason:   reason,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// Authorize authorizes a PXE device for network access.
func (b *PXEBinding) Authorize(deviceID string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.PXE().Authorize(b.conn.ctx, &platformv1.AuthorizePXEDeviceRequest{
		DeviceId: deviceID,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// Quarantine quarantines a PXE device.
func (b *PXEBinding) Quarantine(deviceID string, reason string) (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.PXE().Quarantine(b.conn.ctx, &platformv1.QuarantinePXEDeviceRequest{
		DeviceId: deviceID,
		Reason:   reason,
	})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// GetStatus returns the current status of the PXE service.
func (b *PXEBinding) GetStatus() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.PXE().GetStatus(b.conn.ctx, &platformv1.GetPXEStatusRequest{})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// StartService starts the PXE service.
func (b *PXEBinding) StartService() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.PXE().StartService(b.conn.ctx, &platformv1.StartPXEServiceRequest{})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}

// StopService stops the PXE service.
func (b *PXEBinding) StopService() (map[string]interface{}, error) {
	cl, err := b.getClient()
	if err != nil {
		return nil, err
	}

	resp, err := cl.PXE().StopService(b.conn.ctx, &platformv1.StopPXEServiceRequest{})
	if err != nil {
		return nil, err
	}

	return protoToMap(resp)
}
