// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

// This file implements the BMCCommands interface through the platform SDK.

//go:build integration

package bmc_integration

import (
	"context"

	platform "github.com/jeremyhahn/go-trusted-platform/sdk/go"
	bmcsvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/bmc"

	// Register the sdk/go transports the SDK adapters select by protocol.
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/mcp"
	_ "github.com/jeremyhahn/go-trusted-platform/sdk/go/transport/quic"
)

// SDKAdapter drives BMCCommands through the platform SDK over one selected
// transport, exercising the exact adapter tables (QUIC category/sub-opcode
// map, MCP tool map) the production clients use.
type SDKAdapter struct {
	name     string
	endpoint string
	options  func() *platform.Options
	client   platform.Client
	bmc      *bmcsvc.Client
}

// Name returns the protocol adapter identifier.
func (a *SDKAdapter) Name() string { return a.name }

// Setup connects the platform SDK client over the selected transport.
func (a *SDKAdapter) Setup(ctx context.Context) error {
	client, err := platform.Connect(ctx, a.options())
	if err != nil {
		return ErrSDKConnectionFailed{Protocol: a.name, Endpoint: a.endpoint, Err: err}
	}
	a.client = client
	a.bmc = bmcsvc.NewClientFromGRPC(client.BMC())
	return nil
}

// Teardown closes the SDK client.
func (a *SDKAdapter) Teardown() error {
	if a.client != nil {
		return a.client.Close()
	}
	return nil
}

// callFailed wraps err with the transport and the BMCService method it failed.
func (a *SDKAdapter) callFailed(method string, err error) error {
	return ErrSDKCallFailed{Protocol: a.name, Method: method, Err: err}
}

// =============================================================================
// Power Operations
// =============================================================================

// PowerOn powers on a BMC-managed system.
func (a *SDKAdapter) PowerOn(ctx context.Context, profileID uint64) (*bmcsvc.PowerResponse, error) {
	resp, err := a.bmc.PowerOn(ctx, profileID)
	if err != nil {
		return nil, a.callFailed("PowerOn", err)
	}
	return resp, nil
}

// PowerOff powers off a BMC-managed system.
func (a *SDKAdapter) PowerOff(ctx context.Context, profileID uint64) (*bmcsvc.PowerResponse, error) {
	resp, err := a.bmc.PowerOff(ctx, profileID)
	if err != nil {
		return nil, a.callFailed("PowerOff", err)
	}
	return resp, nil
}

// PowerStatus queries the current power state.
func (a *SDKAdapter) PowerStatus(ctx context.Context, profileID uint64) (bmcsvc.PowerState, error) {
	state, err := a.bmc.PowerStatus(ctx, profileID)
	if err != nil {
		return bmcsvc.PowerStateUnspecified, a.callFailed("PowerStatus", err)
	}
	return state, nil
}

// =============================================================================
// Boot Device Operations
// =============================================================================

// SetBootDevice sets the boot device.
func (a *SDKAdapter) SetBootDevice(ctx context.Context, profileID uint64, device bmcsvc.BootDevice, persistent bool) error {
	if err := a.bmc.SetBootDevice(ctx, profileID, device, persistent); err != nil {
		return a.callFailed("SetBootDevice", err)
	}
	return nil
}

// GetBootDevice queries the current boot device.
func (a *SDKAdapter) GetBootDevice(ctx context.Context, profileID uint64) (bmcsvc.BootDevice, error) {
	device, err := a.bmc.GetBootDevice(ctx, profileID)
	if err != nil {
		return bmcsvc.BootDeviceUnspecified, a.callFailed("GetBootDevice", err)
	}
	return device, nil
}

// =============================================================================
// Virtual Media Operations
// =============================================================================

// MountISO mounts an ISO as virtual media.
func (a *SDKAdapter) MountISO(ctx context.Context, profileID uint64, isoURL string) error {
	if err := a.bmc.MountISO(ctx, profileID, isoURL); err != nil {
		return a.callFailed("MountISO", err)
	}
	return nil
}

// UnmountISO unmounts virtual media.
func (a *SDKAdapter) UnmountISO(ctx context.Context, profileID uint64) error {
	if err := a.bmc.UnmountISO(ctx, profileID); err != nil {
		return a.callFailed("UnmountISO", err)
	}
	return nil
}

// VirtualMediaStatus queries virtual media status.
func (a *SDKAdapter) VirtualMediaStatus(ctx context.Context, profileID uint64) (*bmcsvc.VirtualMediaInfo, error) {
	info, err := a.bmc.VirtualMediaStatus(ctx, profileID)
	if err != nil {
		return nil, a.callFailed("VirtualMediaStatus", err)
	}
	return info, nil
}

// =============================================================================
// Sensor, System Info, Certificate and User Operations
// =============================================================================

// GetSensors queries sensor readings.
func (a *SDKAdapter) GetSensors(ctx context.Context, profileID uint64) ([]bmcsvc.SensorReading, error) {
	sensors, err := a.bmc.GetSensors(ctx, profileID)
	if err != nil {
		return nil, a.callFailed("GetSensors", err)
	}
	return sensors, nil
}

// GetSystemInfo queries system information.
func (a *SDKAdapter) GetSystemInfo(ctx context.Context, profileID uint64) (*bmcsvc.SystemInfo, error) {
	info, err := a.bmc.GetSystemInfo(ctx, profileID)
	if err != nil {
		return nil, a.callFailed("GetSystemInfo", err)
	}
	return info, nil
}

// GetWebCertificate queries the BMC web certificate.
func (a *SDKAdapter) GetWebCertificate(ctx context.Context, profileID uint64) (*bmcsvc.CertificateInfo, error) {
	info, err := a.bmc.GetWebCertificate(ctx, profileID)
	if err != nil {
		return nil, a.callFailed("GetWebCertificate", err)
	}
	return info, nil
}

// ListUsers lists BMC users.
func (a *SDKAdapter) ListUsers(ctx context.Context, profileID uint64) ([]bmcsvc.User, error) {
	users, err := a.bmc.ListUsers(ctx, profileID)
	if err != nil {
		return nil, a.callFailed("ListUsers", err)
	}
	return users, nil
}

// =============================================================================
// Enrollment and Factory Certificate Restore Operations
// =============================================================================

// EnrollBMC runs the BMC enrollment ceremony (BMCService/EnrollBMC).
func (a *SDKAdapter) EnrollBMC(ctx context.Context, profileID uint64, opts *EnrollOptions) (*EnrollResult, error) {
	resp, err := a.bmc.EnrollBMC(ctx, profileID, enrollOptionsToSDK(opts))
	if err != nil {
		return nil, a.callFailed("EnrollBMC", err)
	}
	return sdkEnrollResultToDomain(resp), nil
}

// RestoreBMC runs the BMC factory-certificate restore ceremony
// (BMCService/RestoreFactoryCert).
func (a *SDKAdapter) RestoreBMC(ctx context.Context, profileID uint64) (*RestoreResult, error) {
	resp, err := a.bmc.RestoreFactoryCert(ctx, profileID)
	if err != nil {
		return nil, a.callFailed("RestoreFactoryCert", err)
	}
	return sdkRestoreResultToDomain(resp), nil
}

// Ensure SDKAdapter implements BMCCommands interface.
var _ BMCCommands = (*SDKAdapter)(nil)
