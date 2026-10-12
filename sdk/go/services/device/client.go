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

// Package device provides a client for device service operations.
package device

import (
	"context"
	"strconv"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/common"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/transport"
)

// Client provides access to device service operations.
type Client struct {
	grpc platformv1.DeviceServiceClient
}

// NewClient creates a new device service client from a transport adapter.
func NewClient(conn transport.Adapter) (*Client, error) {
	if conn == nil {
		return nil, common.ErrNilConnection
	}
	grpcConn := conn.Connection()
	if grpcConn == nil {
		return nil, common.ErrNilConnection
	}
	return &Client{
		grpc: platformv1.NewDeviceServiceClient(grpcConn),
	}, nil
}

// NewClientFromGRPC creates a new device service client from a gRPC client.
// This is useful when you already have a gRPC client from the platform.Client.
func NewClientFromGRPC(grpcClient platformv1.DeviceServiceClient) *Client {
	return &Client{
		grpc: grpcClient,
	}
}

// Create creates a new device.
func (c *Client) Create(ctx context.Context, device *platformv1.Device) (*platformv1.Device, error) {
	resp, err := c.grpc.CreateDevice(ctx, &platformv1.CreateDeviceRequest{Device: device})
	if err != nil {
		return nil, &ErrCreateFailed{Cause: err}
	}
	return resp.Device, nil
}

// Get retrieves a device by ID.
func (c *Client) Get(ctx context.Context, id uint64) (*platformv1.Device, error) {
	resp, err := c.grpc.GetDevice(ctx, &platformv1.GetDeviceRequest{Id: id})
	if err != nil {
		return nil, &ErrGetFailed{ID: id, Cause: err}
	}
	return resp.Device, nil
}

// Update updates an existing device.
func (c *Client) Update(ctx context.Context, device *platformv1.Device) (*platformv1.Device, error) {
	resp, err := c.grpc.UpdateDevice(ctx, &platformv1.UpdateDeviceRequest{Device: device})
	if err != nil {
		return nil, &ErrUpdateFailed{ID: device.Id, Cause: err}
	}
	return resp.Device, nil
}

// Delete deletes a device by ID.
func (c *Client) Delete(ctx context.Context, id uint64) error {
	_, err := c.grpc.DeleteDevice(ctx, &platformv1.DeleteDeviceRequest{Id: id})
	if err != nil {
		return &ErrDeleteFailed{ID: id, Cause: err}
	}
	return nil
}

// List retrieves devices with optional pagination and label selector.
func (c *Client) List(ctx context.Context, opts *common.ListOptions) ([]*platformv1.Device, *common.PageResult, error) {
	req := &platformv1.ListDevicesRequest{}
	if opts != nil {
		if opts.Pagination != nil {
			req.Pagination = &platformv1.PaginationRequest{
				Page:      opts.Pagination.Page,
				PageSize:  opts.Pagination.PageSize,
				SortBy:    opts.Pagination.SortBy,
				Ascending: opts.Pagination.Asc,
			}
		}
		if opts.Labels != nil || opts.Expressions != nil {
			req.Selector = &platformv1.LabelSelector{
				MatchLabels:      opts.Labels,
				MatchExpressions: opts.Expressions,
			}
		}
	}
	resp, err := c.grpc.ListDevices(ctx, req)
	if err != nil {
		return nil, nil, &ErrListFailed{Cause: err}
	}
	var pageResult *common.PageResult
	if resp.Pagination != nil {
		pageResult = &common.PageResult{
			Page:       resp.Pagination.Page,
			PageSize:   resp.Pagination.PageSize,
			TotalPages: resp.Pagination.TotalPages,
			TotalItems: resp.Pagination.TotalItems,
		}
	}
	return resp.Devices, pageResult, nil
}

// FindBySerial finds a device by serial number.
func (c *Client) FindBySerial(ctx context.Context, serial string) (*platformv1.Device, error) {
	resp, err := c.grpc.FindDeviceBySerial(ctx, &platformv1.FindDeviceBySerialRequest{Serial: serial})
	if err != nil {
		return nil, &ErrFindBySerialFailed{Serial: serial, Cause: err}
	}
	return resp.Device, nil
}

// Count returns the total number of devices.
func (c *Client) Count(ctx context.Context) (int32, error) {
	resp, err := c.grpc.CountDevices(ctx, &platformv1.CountDevicesRequest{})
	if err != nil {
		return 0, &ErrCountFailed{Cause: err}
	}
	return resp.Count, nil
}

// CreateProfile creates a new device profile.
func (c *Client) CreateProfile(ctx context.Context, profile *platformv1.DeviceProfile) (*platformv1.DeviceProfile, error) {
	resp, err := c.grpc.CreateProfile(ctx, &platformv1.CreateProfileRequest{Profile: profile})
	if err != nil {
		return nil, &ErrCreateProfileFailed{Cause: err}
	}
	return resp.Profile, nil
}

// GetProfile retrieves a device profile by ID.
func (c *Client) GetProfile(ctx context.Context, id uint64) (*platformv1.DeviceProfile, error) {
	resp, err := c.grpc.GetProfile(ctx, &platformv1.GetProfileRequest{Id: id})
	if err != nil {
		return nil, &ErrGetProfileFailed{ID: id, Cause: err}
	}
	return resp.Profile, nil
}

// ProfileUpdateOption sets an UpdateProfile request field that the profile
// itself cannot carry.
type ProfileUpdateOption func(*platformv1.UpdateProfileRequest)

// WithClearTLSServerName blanks the profile's stored tls_server_name. proto3
// cannot tell an unset string from an empty one, so an empty
// profile.TlsServerName alone keeps the stored name (#462).
func WithClearTLSServerName() ProfileUpdateOption {
	return func(req *platformv1.UpdateProfileRequest) {
		req.ClearTlsServerName = true
	}
}

// UpdateProfile updates an existing device profile.
func (c *Client) UpdateProfile(ctx context.Context, profile *platformv1.DeviceProfile, opts ...ProfileUpdateOption) (*platformv1.DeviceProfile, error) {
	req := &platformv1.UpdateProfileRequest{Profile: profile}
	for _, opt := range opts {
		opt(req)
	}
	resp, err := c.grpc.UpdateProfile(ctx, req)
	if err != nil {
		return nil, &ErrUpdateProfileFailed{ID: profile.Id, Cause: err}
	}
	return resp.Profile, nil
}

// DeleteProfile deletes a device profile by ID.
func (c *Client) DeleteProfile(ctx context.Context, id uint64) error {
	_, err := c.grpc.DeleteProfile(ctx, &platformv1.DeleteProfileRequest{Id: id})
	if err != nil {
		return &ErrDeleteProfileFailed{ID: id, Cause: err}
	}
	return nil
}

// ListProfiles retrieves device profiles with optional pagination and label selector.
func (c *Client) ListProfiles(ctx context.Context, opts *common.ListOptions) ([]*platformv1.DeviceProfile, *common.PageResult, error) {
	req := &platformv1.ListProfilesRequest{}
	if opts != nil {
		if opts.Pagination != nil {
			req.Pagination = &platformv1.PaginationRequest{
				Page:      opts.Pagination.Page,
				PageSize:  opts.Pagination.PageSize,
				SortBy:    opts.Pagination.SortBy,
				Ascending: opts.Pagination.Asc,
			}
		}
		if opts.Labels != nil || opts.Expressions != nil {
			req.Selector = &platformv1.LabelSelector{
				MatchLabels:      opts.Labels,
				MatchExpressions: opts.Expressions,
			}
		}
	}
	resp, err := c.grpc.ListProfiles(ctx, req)
	if err != nil {
		return nil, nil, &ErrListProfilesFailed{Cause: err}
	}
	var pageResult *common.PageResult
	if resp.Pagination != nil {
		pageResult = &common.PageResult{
			Page:       resp.Pagination.Page,
			PageSize:   resp.Pagination.PageSize,
			TotalPages: resp.Pagination.TotalPages,
			TotalItems: resp.Pagination.TotalItems,
		}
	}
	return resp.Profiles, pageResult, nil
}

// FindProfileByMACAddress finds a device profile by MAC address.
func (c *Client) FindProfileByMACAddress(ctx context.Context, macAddress string) (*platformv1.DeviceProfile, error) {
	resp, err := c.grpc.FindProfileByMACAddress(ctx, &platformv1.FindProfileByMACAddressRequest{MacAddress: macAddress})
	if err != nil {
		return nil, &ErrFindProfileByMACFailed{MACAddress: macAddress, Cause: err}
	}
	return resp.Profile, nil
}

// FindProfileBySerial finds a device profile by serial number.
func (c *Client) FindProfileBySerial(ctx context.Context, serial string) (*platformv1.DeviceProfile, error) {
	resp, err := c.grpc.FindProfileBySerial(ctx, &platformv1.FindProfileBySerialRequest{Serial: serial})
	if err != nil {
		return nil, &ErrFindProfileBySerialFailed{Serial: serial, Cause: err}
	}
	return resp.Profile, nil
}

// FindMatchingProfile finds a device profile matching the specified criteria.
func (c *Client) FindMatchingProfile(ctx context.Context, macAddress, serial, model string) (*platformv1.DeviceProfile, error) {
	resp, err := c.grpc.FindMatchingProfile(ctx, &platformv1.FindMatchingProfileRequest{
		MacAddress: macAddress,
		Serial:     serial,
		Model:      model,
	})
	if err != nil {
		return nil, &ErrFindMatchingProfileFailed{Cause: err}
	}
	return resp.Profile, nil
}

// CountProfiles returns the total number of device profiles.
func (c *Client) CountProfiles(ctx context.Context) (int32, error) {
	resp, err := c.grpc.CountProfiles(ctx, &platformv1.CountProfilesRequest{})
	if err != nil {
		return 0, &ErrCountProfilesFailed{Cause: err}
	}
	return resp.Count, nil
}

// Activate activates a device.
func (c *Client) Activate(ctx context.Context, serial, macAddress string) (*platformv1.ActivateDeviceResponse, error) {
	resp, err := c.grpc.ActivateDevice(ctx, &platformv1.ActivateDeviceRequest{
		Serial:     serial,
		MacAddress: macAddress,
	})
	if err != nil {
		return nil, &ErrActivateFailed{Serial: serial, Cause: err}
	}
	return resp, nil
}

// RecordAttestCertOptions are the choices of RecordAttestationCertificate.
// Both default to false.
type RecordAttestCertOptions struct {
	// Reissue lets the CA issue a fresh certificate over the enrolled
	// attestation key when no stored one passes.
	Reissue bool
	// ClearOnRefusal clears the certificate on the device record when every
	// candidate is refused, so the device's next collection is an absence
	// (denied service) instead of a cryptographic failure (quarantine). The
	// clear is audited as its own event; the response reports Cleared and
	// the Refusal that caused it. It never clears a compliant certificate.
	ClearOnRefusal bool
}

// RecordAttestationCertificate records (or re-records) the device's
// attestation certificate on its platform record without re-enrolling the
// device. The control plane fails closed: the certificate must parse, chain
// to the platform CA, carry tcg-cap-verifiedTPMRestricted and certify the
// device's enrolled attestation key, or nothing is written and the call
// fails with FailedPrecondition naming every candidate refused. See
// RecordAttestCertOptions for the reissue and clear-on-refusal choices.
func (c *Client) RecordAttestationCertificate(ctx context.Context, id uint64, opts RecordAttestCertOptions) (*platformv1.RecordAttestationCertificateResponse, error) {
	resp, err := c.grpc.RecordAttestationCertificate(ctx, &platformv1.RecordAttestationCertificateRequest{
		DeviceId:       strconv.FormatUint(id, 10),
		Reissue:        opts.Reissue,
		ClearOnRefusal: opts.ClearOnRefusal,
	})
	if err != nil {
		return nil, &ErrRecordAttestCertFailed{ID: id, Cause: err}
	}
	return resp, nil
}

// AssignProfile binds a profile to a specific device identity by EK serial
// and/or MAC address, optionally prestaging the device's PEM-encoded EK
// certificate (source-agnostic: swtpm-backed vTPM or physical hardware
// TPM). At least one of ekSerial or macAddress must be non-empty. The
// updated profile is returned so callers can audit the resulting binding.
func (c *Client) AssignProfile(ctx context.Context, profileID uint64, ekSerial, macAddress, ekCertPEM string) (*platformv1.DeviceProfile, error) {
	resp, err := c.grpc.AssignProfileToDevice(ctx, &platformv1.AssignProfileToDeviceRequest{
		ProfileId:  profileID,
		EkSerial:   ekSerial,
		MacAddress: macAddress,
		EkCert:     ekCertPEM,
	})
	if err != nil {
		return nil, &ErrAssignProfileFailed{ProfileID: profileID, Cause: err}
	}
	return resp.Profile, nil
}

// AssignProfileToRegisteredDevice binds a profile to an already-registered
// device: the daemon derives the EK serial from the device's stored EK
// certificate and prestages that certificate (#463); explicit ekSerial,
// macAddress and ekCertPEM values override what is derived. deviceID may be
// zero when the caller supplies the identity explicitly.
func (c *Client) AssignProfileToRegisteredDevice(ctx context.Context, profileID, deviceID uint64, ekSerial, macAddress, ekCertPEM string) (*platformv1.DeviceProfile, error) {
	resp, err := c.grpc.AssignProfileToDevice(ctx, &platformv1.AssignProfileToDeviceRequest{
		ProfileId:  profileID,
		DeviceId:   deviceID,
		EkSerial:   ekSerial,
		MacAddress: macAddress,
		EkCert:     ekCertPEM,
	})
	if err != nil {
		return nil, &ErrAssignProfileFailed{ProfileID: profileID, Cause: err}
	}
	return resp.Profile, nil
}

// UnassignProfile clears a profile's device binding: the EK serial, MAC
// address, prestaged EK certificate, and assignment state are all reset.
// The updated profile is returned so callers can confirm the cleared
// binding.
func (c *Client) UnassignProfile(ctx context.Context, profileID uint64) (*platformv1.DeviceProfile, error) {
	resp, err := c.grpc.UnassignProfileFromDevice(ctx, &platformv1.UnassignProfileFromDeviceRequest{
		ProfileId: profileID,
	})
	if err != nil {
		return nil, &ErrUnassignProfileFailed{ProfileID: profileID, Cause: err}
	}
	return resp.Profile, nil
}
