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

// Package pxe provides a client for PXE provisioning service operations.
package pxe

import (
	"context"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// Client provides access to PXE service operations.
type Client struct {
	grpc platformv1.PXEServiceClient
}

// NewClient creates a new PXE service client.
func NewClient(conn transport.Adapter) (*Client, error) {
	if conn == nil {
		return nil, common.ErrNilConnection
	}
	grpcConn := conn.Connection()
	if grpcConn == nil {
		return nil, common.ErrNilConnection
	}
	return &Client{
		grpc: platformv1.NewPXEServiceClient(grpcConn),
	}, nil
}

// Device Registration and Management

// RegisterDevice registers a new device for PXE provisioning.
func (c *Client) RegisterDevice(ctx context.Context, macAddress, portID string) (*platformv1.PXEDeviceInfo, error) {
	resp, err := c.grpc.RegisterDevice(ctx, &platformv1.RegisterPXEDeviceRequest{
		MacAddress: macAddress,
		PortId:     portID,
	})
	if err != nil {
		return nil, &ErrRegisterDeviceFailed{MACAddress: macAddress, Cause: err}
	}
	return resp.Device, nil
}

// GetDevice retrieves a PXE device by ID.
func (c *Client) GetDevice(ctx context.Context, deviceID string) (*platformv1.PXEDeviceInfo, error) {
	resp, err := c.grpc.GetDevice(ctx, &platformv1.GetPXEDeviceRequest{DeviceId: deviceID})
	if err != nil {
		return nil, &ErrGetDeviceFailed{ID: deviceID, Cause: err}
	}
	return resp.Device, nil
}

// GetDeviceByMAC retrieves a PXE device by MAC address.
func (c *Client) GetDeviceByMAC(ctx context.Context, macAddress string) (*platformv1.PXEDeviceInfo, error) {
	resp, err := c.grpc.GetDeviceByMAC(ctx, &platformv1.GetPXEDeviceByMACRequest{MacAddress: macAddress})
	if err != nil {
		return nil, &ErrGetDeviceByMACFailed{MACAddress: macAddress, Cause: err}
	}
	return resp.Device, nil
}

// ListDevices lists PXE devices with optional filtering.
func (c *Client) ListDevices(ctx context.Context, filter *platformv1.PXEDeviceFilter) ([]*platformv1.PXEDeviceInfo, int32, error) {
	resp, err := c.grpc.ListDevices(ctx, &platformv1.ListPXEDevicesRequest{Filter: filter})
	if err != nil {
		return nil, 0, &ErrListDevicesFailed{Cause: err}
	}
	return resp.Devices, resp.TotalCount, nil
}

// RemoveDevice removes a device from PXE tracking.
func (c *Client) RemoveDevice(ctx context.Context, deviceID string) error {
	_, err := c.grpc.RemoveDevice(ctx, &platformv1.RemovePXEDeviceRequest{DeviceId: deviceID})
	if err != nil {
		return &ErrRemoveDeviceFailed{ID: deviceID, Cause: err}
	}
	return nil
}

// State Transitions

// UpdateState updates the provisioning state of a device.
func (c *Client) UpdateState(ctx context.Context, deviceID string, state platformv1.ProvisioningState, reason string) (*platformv1.PXEDeviceInfo, error) {
	resp, err := c.grpc.UpdateState(ctx, &platformv1.UpdatePXEStateRequest{
		DeviceId: deviceID,
		State:    state,
		Reason:   reason,
	})
	if err != nil {
		return nil, &ErrUpdateStateFailed{ID: deviceID, Cause: err}
	}
	return resp.Device, nil
}

// SetDeviceInstalling moves a booting device to installing and binds the
// installer certificate its install-completion webhook will present:
// installCertificateSHA256 is the hex SHA-256 of that certificate's DER. The
// webhook refuses an installation entered without a binding, and the binding
// cannot be added once the device is installing.
func (c *Client) SetDeviceInstalling(ctx context.Context, deviceID, installCertificateSHA256, reason string) (*platformv1.PXEDeviceInfo, error) {
	// An empty fingerprint would make the request a plain state update: the
	// device would enter installing unbound, and the webhook could never end it.
	if installCertificateSHA256 == "" {
		return nil, &ErrInstallCertificateRequired{ID: deviceID}
	}
	resp, err := c.grpc.UpdateState(ctx, &platformv1.UpdatePXEStateRequest{
		DeviceId:                 deviceID,
		State:                    platformv1.ProvisioningState_PROVISIONING_STATE_INSTALLING,
		Reason:                   reason,
		InstallCertificateSha256: installCertificateSHA256,
	})
	if err != nil {
		return nil, &ErrSetInstallingFailed{ID: deviceID, Cause: err}
	}
	return resp.Device, nil
}

// SetDeviceEnrolled marks a device as enrolled with a certificate.
func (c *Client) SetDeviceEnrolled(ctx context.Context, deviceID, certificateSerial string) (*platformv1.PXEDeviceInfo, error) {
	resp, err := c.grpc.SetDeviceEnrolled(ctx, &platformv1.SetPXEDeviceEnrolledRequest{
		DeviceId:          deviceID,
		CertificateSerial: certificateSerial,
	})
	if err != nil {
		return nil, &ErrSetEnrolledFailed{ID: deviceID, Cause: err}
	}
	return resp.Device, nil
}

// Authorize authorizes a device for network access.
func (c *Client) Authorize(ctx context.Context, deviceID string, targetVLAN uint32) (*platformv1.PXEDeviceInfo, error) {
	resp, err := c.grpc.Authorize(ctx, &platformv1.AuthorizePXEDeviceRequest{
		DeviceId:   deviceID,
		TargetVlan: targetVLAN,
	})
	if err != nil {
		return nil, &ErrAuthorizeFailed{ID: deviceID, Cause: err}
	}
	return resp.Device, nil
}

// Quarantine quarantines a device.
func (c *Client) Quarantine(ctx context.Context, deviceID, reason string) (*platformv1.PXEDeviceInfo, error) {
	resp, err := c.grpc.Quarantine(ctx, &platformv1.QuarantinePXEDeviceRequest{
		DeviceId: deviceID,
		Reason:   reason,
	})
	if err != nil {
		return nil, &ErrQuarantineFailed{ID: deviceID, Cause: err}
	}
	return resp.Device, nil
}

// Retry retries provisioning for a failed device.
func (c *Client) Retry(ctx context.Context, deviceID string) (*platformv1.PXEDeviceInfo, error) {
	resp, err := c.grpc.Retry(ctx, &platformv1.RetryPXEDeviceRequest{DeviceId: deviceID})
	if err != nil {
		return nil, &ErrRetryFailed{ID: deviceID, Cause: err}
	}
	return resp.Device, nil
}

// Events

// GetEvents retrieves provisioning events for a device.
func (c *Client) GetEvents(ctx context.Context, deviceID string) ([]*platformv1.ProvisioningEvent, error) {
	resp, err := c.grpc.GetEvents(ctx, &platformv1.GetPXEEventsRequest{DeviceId: deviceID})
	if err != nil {
		return nil, &ErrGetEventsFailed{ID: deviceID, Cause: err}
	}
	return resp.Events, nil
}

// Service Lifecycle

// GetStatus returns the status of the PXE service.
func (c *Client) GetStatus(ctx context.Context) (*platformv1.PXEServiceStatus, error) {
	resp, err := c.grpc.GetStatus(ctx, &platformv1.GetPXEStatusRequest{})
	if err != nil {
		return nil, &ErrGetStatusFailed{Cause: err}
	}
	return resp.Status, nil
}

// StartService starts the PXE service.
func (c *Client) StartService(ctx context.Context) error {
	_, err := c.grpc.StartService(ctx, &platformv1.StartPXEServiceRequest{})
	if err != nil {
		return &ErrStartServiceFailed{Cause: err}
	}
	return nil
}

// StopService stops the PXE service.
func (c *Client) StopService(ctx context.Context) error {
	_, err := c.grpc.StopService(ctx, &platformv1.StopPXEServiceRequest{})
	if err != nil {
		return &ErrStopServiceFailed{Cause: err}
	}
	return nil
}

// Webhook

// WebhookComplete notifies completion of OS installation.
func (c *Client) WebhookComplete(ctx context.Context, macAddress, hostname string, success bool, message string) error {
	_, err := c.grpc.WebhookComplete(ctx, &platformv1.PXEWebhookCompleteRequest{
		MacAddress: macAddress,
		Hostname:   hostname,
		Success:    success,
		Message:    message,
	})
	if err != nil {
		return &ErrWebhookCompleteFailed{MACAddress: macAddress, Cause: err}
	}
	return nil
}
