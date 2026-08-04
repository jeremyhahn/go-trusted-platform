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

package bmc

import (
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// powerAction defines the function signature for power management dispatch.
type powerAction func(ctx context.Context, in *platformv1.BMCPowerRequest) (*platformv1.BMCPowerResponse, error)

// Client provides access to BMC service operations.
type Client struct {
	grpc         platformv1.BMCServiceClient
	powerActions map[string]powerAction
}

// NewClient creates a new BMC service client.
func NewClient(conn transport.Adapter) (*Client, error) {
	if conn == nil {
		return nil, common.ErrNilConnection
	}
	grpcConn := conn.Connection()
	if grpcConn == nil {
		return nil, common.ErrNilConnection
	}
	return newClient(platformv1.NewBMCServiceClient(grpcConn)), nil
}

// NewClientFromGRPC creates a new BMC service client from a gRPC client.
// This is useful when you already have a gRPC client from the platform.Client.
func NewClientFromGRPC(grpcClient platformv1.BMCServiceClient) *Client {
	return newClient(grpcClient)
}

// newClient initializes the client with its power action dispatch map.
func newClient(grpcClient platformv1.BMCServiceClient) *Client {
	c := &Client{
		grpc: grpcClient,
	}
	c.powerActions = map[string]powerAction{
		"on": func(ctx context.Context, in *platformv1.BMCPowerRequest) (*platformv1.BMCPowerResponse, error) {
			return c.grpc.PowerOn(ctx, in)
		},
		"off": func(ctx context.Context, in *platformv1.BMCPowerRequest) (*platformv1.BMCPowerResponse, error) {
			return c.grpc.PowerOff(ctx, in)
		},
		"reset": func(ctx context.Context, in *platformv1.BMCPowerRequest) (*platformv1.BMCPowerResponse, error) {
			return c.grpc.PowerReset(ctx, in)
		},
		"cycle": func(ctx context.Context, in *platformv1.BMCPowerRequest) (*platformv1.BMCPowerResponse, error) {
			return c.grpc.PowerCycle(ctx, in)
		},
	}
	return c
}

// Power Management

// powerOp executes a power management operation using map-based dispatch.
func (c *Client) powerOp(ctx context.Context, profileID uint64, action string) (*PowerResponse, error) {
	handler, ok := c.powerActions[action]
	if !ok {
		return nil, &ErrPowerFailed{
			ProfileID: profileID,
			Action:    action,
			Cause:     common.ErrInvalidArgument,
		}
	}
	resp, err := handler(ctx, &platformv1.BMCPowerRequest{ProfileId: profileID})
	if err != nil {
		return nil, &ErrPowerFailed{ProfileID: profileID, Action: action, Cause: err}
	}
	return powerResponseFromProto(resp), nil
}

// PowerOn powers on the system identified by the given profile ID.
func (c *Client) PowerOn(ctx context.Context, profileID uint64) (*PowerResponse, error) {
	return c.powerOp(ctx, profileID, "on")
}

// PowerOff powers off the system identified by the given profile ID.
func (c *Client) PowerOff(ctx context.Context, profileID uint64) (*PowerResponse, error) {
	return c.powerOp(ctx, profileID, "off")
}

// PowerReset resets the system identified by the given profile ID.
func (c *Client) PowerReset(ctx context.Context, profileID uint64) (*PowerResponse, error) {
	return c.powerOp(ctx, profileID, "reset")
}

// PowerCycle power cycles the system identified by the given profile ID.
func (c *Client) PowerCycle(ctx context.Context, profileID uint64) (*PowerResponse, error) {
	return c.powerOp(ctx, profileID, "cycle")
}

// PowerStatus queries the current power state of the system identified by the given profile ID.
func (c *Client) PowerStatus(ctx context.Context, profileID uint64) (PowerState, error) {
	resp, err := c.grpc.PowerStatus(ctx, &platformv1.BMCPowerStatusRequest{ProfileId: profileID})
	if err != nil {
		return PowerStateUnspecified, &ErrPowerFailed{ProfileID: profileID, Action: "status", Cause: err}
	}
	return PowerStateFromProto(resp.State), nil
}

// Boot Device Control

// SetBootDevice sets the boot device for the system identified by the given profile ID.
func (c *Client) SetBootDevice(ctx context.Context, profileID uint64, device BootDevice, persistent bool) error {
	protoDevice := BootDeviceToProto(device)
	_, err := c.grpc.SetBootDevice(ctx, &platformv1.BMCSetBootDeviceRequest{
		ProfileId:  profileID,
		Device:     protoDevice,
		Persistent: persistent,
	})
	if err != nil {
		return &ErrBootDeviceFailed{ProfileID: profileID, Cause: err}
	}
	return nil
}

// GetBootDevice queries the current boot device for the system identified by the given profile ID.
func (c *Client) GetBootDevice(ctx context.Context, profileID uint64) (BootDevice, error) {
	resp, err := c.grpc.GetBootDevice(ctx, &platformv1.BMCGetBootDeviceRequest{ProfileId: profileID})
	if err != nil {
		return BootDeviceUnspecified, &ErrBootDeviceFailed{ProfileID: profileID, Cause: err}
	}
	return BootDeviceFromProto(resp.Device), nil
}

// Virtual Media

// MountISO mounts an ISO image via virtual media for the system identified by the given profile ID.
func (c *Client) MountISO(ctx context.Context, profileID uint64, isoURL string) error {
	_, err := c.grpc.MountISO(ctx, &platformv1.BMCMountISORequest{
		ProfileId: profileID,
		IsoUrl:    isoURL,
	})
	if err != nil {
		return &ErrVirtualMediaFailed{ProfileID: profileID, Action: "mount", Cause: err}
	}
	return nil
}

// UnmountISO unmounts virtual media from the system identified by the given profile ID.
func (c *Client) UnmountISO(ctx context.Context, profileID uint64) error {
	_, err := c.grpc.UnmountISO(ctx, &platformv1.BMCUnmountISORequest{ProfileId: profileID})
	if err != nil {
		return &ErrVirtualMediaFailed{ProfileID: profileID, Action: "unmount", Cause: err}
	}
	return nil
}

// VirtualMediaStatus queries the virtual media status for the system identified by the given profile ID.
func (c *Client) VirtualMediaStatus(ctx context.Context, profileID uint64) (*VirtualMediaInfo, error) {
	resp, err := c.grpc.VirtualMediaStatus(ctx, &platformv1.BMCVirtualMediaStatusRequest{ProfileId: profileID})
	if err != nil {
		return nil, &ErrVirtualMediaFailed{ProfileID: profileID, Action: "status", Cause: err}
	}
	return virtualMediaFromProto(resp), nil
}

// Monitoring

// GetSensors queries sensor readings for the system identified by the given profile ID.
func (c *Client) GetSensors(ctx context.Context, profileID uint64) ([]SensorReading, error) {
	resp, err := c.grpc.GetSensors(ctx, &platformv1.BMCGetSensorsRequest{ProfileId: profileID})
	if err != nil {
		return nil, &ErrSensorsFailed{ProfileID: profileID, Cause: err}
	}
	return sensorsFromProto(resp.Sensors), nil
}

// GetSystemInfo queries system information for the system identified by the given profile ID.
func (c *Client) GetSystemInfo(ctx context.Context, profileID uint64) (*SystemInfo, error) {
	resp, err := c.grpc.GetSystemInfo(ctx, &platformv1.BMCGetSystemInfoRequest{ProfileId: profileID})
	if err != nil {
		return nil, &ErrSystemInfoFailed{ProfileID: profileID, Cause: err}
	}
	return systemInfoFromProto(resp), nil
}

// Orchestrated Provisioning

// Provision initiates an orchestrated bare metal provisioning workflow for the system
// identified by the given profile ID.
func (c *Client) Provision(ctx context.Context, profileID uint64, isoURL string) (*ProvisionResult, error) {
	resp, err := c.grpc.Provision(ctx, &platformv1.BMCProvisionRequest{
		ProfileId: profileID,
		IsoUrl:    isoURL,
	})
	if err != nil {
		return nil, &ErrProvisionFailed{ProfileID: profileID, Cause: err}
	}
	return provisionResultFromProto(resp), nil
}

// ProvisionStatus queries the current provisioning status for the system identified by the given profile ID.
func (c *Client) ProvisionStatus(ctx context.Context, profileID uint64) (*ProvisioningStatus, error) {
	resp, err := c.grpc.ProvisionStatus(ctx, &platformv1.BMCProvisionStatusRequest{ProfileId: profileID})
	if err != nil {
		return nil, &ErrProvisionFailed{ProfileID: profileID, Cause: err}
	}
	return provisioningStatusFromProto(resp), nil
}

// Certificate Management

// GetWebCertificate queries the BMC web server certificate details for the system
// identified by the given profile ID.
func (c *Client) GetWebCertificate(ctx context.Context, profileID uint64) (*CertificateInfo, error) {
	resp, err := c.grpc.GetWebCertificate(ctx, &platformv1.BMCGetWebCertificateRequest{ProfileId: profileID})
	if err != nil {
		return nil, &ErrCertificateFailed{ProfileID: profileID, Action: "get", Cause: err}
	}
	return certificateInfoFromProto(resp), nil
}

// ReplaceWebCertificate replaces the BMC web server certificate for the system
// identified by the given profile ID. certPEM is the PEM-encoded certificate
// (leaf, optionally with chain) and keyPEM is the PEM-encoded private key.
func (c *Client) ReplaceWebCertificate(ctx context.Context, profileID uint64, certPEM, keyPEM []byte) (string, error) {
	resp, err := c.grpc.ReplaceWebCertificate(ctx, &platformv1.BMCReplaceWebCertificateRequest{
		ProfileId: profileID,
		CertPem:   certPEM,
		KeyPem:    keyPEM,
	})
	if err != nil {
		return "", &ErrCertificateFailed{ProfileID: profileID, Action: "replace", Cause: err}
	}
	return resp.Message, nil
}

// User Management

// ListUsers queries the BMC user accounts for the system identified by the given profile ID.
func (c *Client) ListUsers(ctx context.Context, profileID uint64) ([]User, error) {
	resp, err := c.grpc.ListUsers(ctx, &platformv1.BMCListUsersRequest{ProfileId: profileID})
	if err != nil {
		return nil, &ErrUserFailed{ProfileID: profileID, Action: "list", Cause: err}
	}
	return usersFromProto(resp.Users), nil
}

// CreateUser creates a new BMC user for the system identified by the given profile ID.
func (c *Client) CreateUser(ctx context.Context, profileID uint64, user *User, password string) (uint32, error) {
	resp, err := c.grpc.CreateUser(ctx, &platformv1.BMCCreateUserRequest{
		ProfileId: profileID,
		User:      userToProto(user),
		Password:  password,
	})
	if err != nil {
		return 0, &ErrUserFailed{ProfileID: profileID, Action: "create", Cause: err}
	}
	return resp.Slot, nil
}

// DeleteUser deletes a BMC user slot for the system identified by the given profile ID.
func (c *Client) DeleteUser(ctx context.Context, profileID uint64, slot uint32) error {
	_, err := c.grpc.DeleteUser(ctx, &platformv1.BMCDeleteUserRequest{
		ProfileId: profileID,
		Slot:      slot,
	})
	if err != nil {
		return &ErrUserFailed{ProfileID: profileID, Action: "delete", Cause: err}
	}
	return nil
}

// SetUserPassword updates the password for a BMC user slot.
func (c *Client) SetUserPassword(ctx context.Context, profileID uint64, slot uint32, password string) error {
	_, err := c.grpc.SetUserPassword(ctx, &platformv1.BMCSetUserPasswordRequest{
		ProfileId: profileID,
		Slot:      slot,
		Password:  password,
	})
	if err != nil {
		return &ErrUserFailed{ProfileID: profileID, Action: "set-password", Cause: err}
	}
	return nil
}

// SetUserPrivilege updates the privilege level for a BMC user slot.
func (c *Client) SetUserPrivilege(ctx context.Context, profileID uint64, slot, channel uint32, privilege Privilege) error {
	_, err := c.grpc.SetUserPrivilege(ctx, &platformv1.BMCSetUserPrivilegeRequest{
		ProfileId: profileID,
		Slot:      slot,
		Channel:   channel,
		Privilege: PrivilegeToProto(privilege),
	})
	if err != nil {
		return &ErrUserFailed{ProfileID: profileID, Action: "set-privilege", Cause: err}
	}
	return nil
}

// Enrollment Ceremony

// EnrollBMC performs the BMC enrollment ceremony for the device identified by
// profileID. opts may be nil; absent fields use the profile's stored enrollment
// config defaults. Returns the full ceremony result or an *ErrEnrollFailed
// wrapping the underlying gRPC error.
func (c *Client) EnrollBMC(ctx context.Context, profileID uint64, opts *EnrollOptions) (*EnrollResult, error) {
	req := enrollOptionsToProto(profileID, opts)
	resp, err := c.grpc.EnrollBMC(ctx, req)
	if err != nil {
		return nil, &ErrEnrollFailed{ProfileID: profileID, Cause: err}
	}
	return enrollResultFromProto(resp), nil
}

// Factory Certificate Restore

// RestoreFactoryCert performs the BMC factory-certificate restore ceremony for
// the device identified by profileID. It instructs the BMC to regenerate its
// default self-signed certificate and cleans up platform-side trust state
// (SPKI pin deletion, DANE TLSA record removal, Device entity update).
// Returns the full ceremony result or an *ErrRestoreFailed wrapping the
// underlying gRPC error.
func (c *Client) RestoreFactoryCert(ctx context.Context, profileID uint64) (*RestoreResult, error) {
	resp, err := c.grpc.RestoreFactoryCert(ctx, &platformv1.BMCRestoreRequest{ProfileId: profileID})
	if err != nil {
		return nil, &ErrRestoreFailed{ProfileID: profileID, Cause: err}
	}
	return restoreResultFromProto(resp), nil
}
