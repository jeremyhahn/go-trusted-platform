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

// CreateTemplate stores a device template and returns it with its
// assigned ID.
func (c *Client) CreateTemplate(ctx context.Context, template *platformv1.DeviceTemplate) (*platformv1.DeviceTemplate, error) {
	resp, err := c.grpc.CreateTemplate(ctx, &platformv1.DeviceTemplateCreateRequest{Template: template})
	if err != nil {
		return nil, &ErrCreateTemplateFailed{Cause: err}
	}
	return resp.Template, nil
}

// GetTemplate returns the device template with the given ID.
func (c *Client) GetTemplate(ctx context.Context, id uint64) (*platformv1.DeviceTemplate, error) {
	resp, err := c.grpc.GetTemplate(ctx, &platformv1.DeviceTemplateGetRequest{Id: id})
	if err != nil {
		return nil, &ErrGetTemplateFailed{ID: id, Cause: err}
	}
	return resp.Template, nil
}

// ListTemplates returns one page of device templates. A nil opts lists the
// first page at the server's default page size.
func (c *Client) ListTemplates(ctx context.Context, opts *common.Pagination) ([]*platformv1.DeviceTemplate, *common.PageResult, error) {
	req := &platformv1.DeviceTemplateListRequest{}
	if opts != nil {
		req.Pagination = &platformv1.PaginationRequest{
			Page:      opts.Page,
			PageSize:  opts.PageSize,
			SortBy:    opts.SortBy,
			Ascending: opts.Asc,
		}
	}
	resp, err := c.grpc.ListTemplates(ctx, req)
	if err != nil {
		return nil, nil, &ErrListTemplatesFailed{Cause: err}
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
	return resp.Templates, pageResult, nil
}

// UpdateTemplate replaces the stored device template whose ID the template
// carries: every field is replaced, so a caller changing one field sends
// the template GetTemplate returned with that field edited. The server
// keeps the creation time.
func (c *Client) UpdateTemplate(ctx context.Context, template *platformv1.DeviceTemplate) (*platformv1.DeviceTemplate, error) {
	resp, err := c.grpc.UpdateTemplate(ctx, &platformv1.DeviceTemplateUpdateRequest{Template: template})
	if err != nil {
		return nil, &ErrUpdateTemplateFailed{ID: template.GetId(), Cause: err}
	}
	return resp.Template, nil
}

// DeleteTemplate deletes the device template with the given ID. Profiles
// already built from the template are not affected.
func (c *Client) DeleteTemplate(ctx context.Context, id uint64) error {
	_, err := c.grpc.DeleteTemplate(ctx, &platformv1.DeviceTemplateDeleteRequest{Id: id})
	if err != nil {
		return &ErrDeleteTemplateFailed{ID: id, Cause: err}
	}
	return nil
}

// CreateProfileFromTemplate derives a device profile from a template,
// applying the set fields of overrides on top of the template's values.
func (c *Client) CreateProfileFromTemplate(ctx context.Context, templateID uint64, overrides *platformv1.DeviceProfile) (*platformv1.DeviceProfile, error) {
	resp, err := c.grpc.CreateProfileFromTemplate(ctx, &platformv1.CreateProfileFromTemplateRequest{
		TemplateId: templateID,
		Overrides:  overrides,
	})
	if err != nil {
		return nil, &ErrCreateProfileFromTemplateFailed{TemplateID: templateID, Cause: err}
	}
	return resp.Profile, nil
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

// Disable is the operator Disable Device: the control plane blocks the
// device's switch port and records it suspended, reason as its state
// reason. An empty reason is recorded as "disabled".
func (c *Client) Disable(ctx context.Context, id uint64, reason string) (*platformv1.DeviceLifecycleResponse, error) {
	resp, err := c.grpc.DisableDevice(ctx, &platformv1.DisableDeviceRequest{
		DeviceId: strconv.FormatUint(id, 10),
		Reason:   reason,
	})
	if err != nil {
		return nil, &ErrDisableFailed{ID: id, Cause: err}
	}
	return resp, nil
}

// BootProofFunc computes a diskless node's boot proof over binding, the
// channel binding of the connection the call travels on
// (provisioning.BootChannelNonce of that TLS 1.3 connection). The SDK calls
// it after the connection exists, so a proof always matches the connection
// that carries it; one computed in advance for another connection never
// can.
type BootProofFunc func(ctx context.Context, binding []byte) ([]byte, error)

// BootCertificate asks the control plane for a diskless node's recorded
// IDevID chain. sign proves the node holds the chain's key: it receives the
// connection's channel binding and returns the signature
// provisioning.SignBootCertificateProof makes over the identity and that
// binding. The server refuses every unproven request alike, so the call
// cannot enumerate devices. It needs no token and no client certificate,
// and is refused with transport.ErrChannelBindingUnavailable on a transport
// with no TLS connection (Unix socket, MCP, embedded).
func (c *Client) BootCertificate(ctx context.Context, identity string, sign BootProofFunc) (*platformv1.BootCertificateResponse, error) {
	if sign == nil {
		return nil, &ErrBootCertificateFailed{Identity: identity, Cause: &ErrBootProofMissing{}}
	}
	req := &platformv1.BootCertificateRequest{Identity: identity}
	bind := transport.WithChannelBinding(func(ctx context.Context, binding []byte) error {
		signature, err := sign(ctx, binding)
		if err != nil {
			return err
		}
		req.Signature = signature
		return nil
	})
	resp, err := c.grpc.BootCertificate(ctx, req, bind)
	if err != nil {
		return nil, &ErrBootCertificateFailed{Identity: identity, Cause: err}
	}
	return resp, nil
}

// Enable is the operator Enable of a disabled device. The control plane
// re-admits it to the quarantine zone and requests a re-attestation; the
// response state is "quarantined" until a passing verdict restores it.
func (c *Client) Enable(ctx context.Context, id uint64) (*platformv1.DeviceLifecycleResponse, error) {
	resp, err := c.grpc.EnableDevice(ctx, &platformv1.EnableDeviceRequest{
		DeviceId: strconv.FormatUint(id, 10),
	})
	if err != nil {
		return nil, &ErrEnableFailed{ID: id, Cause: err}
	}
	return resp, nil
}

// BootDelivery presents a diskless node's attestation evidence and, once the
// control plane has verified it against the connection's client certificate
// and channel binding, returns the node's network profile and the CA bundle.
// quote receives the connection's channel binding and returns the evidence
// quoted over it. The node's identity is the client certificate, never a
// request field.
func (c *Client) BootDelivery(ctx context.Context, quote BootProofFunc) (*platformv1.BootDeliveryResponse, error) {
	if quote == nil {
		return nil, &ErrBootDeliveryFailed{Cause: &ErrBootProofMissing{}}
	}
	req := &platformv1.BootDeliveryRequest{}
	bind := transport.WithChannelBinding(func(ctx context.Context, binding []byte) error {
		evidence, err := quote(ctx, binding)
		if err != nil {
			return err
		}
		req.Evidence = evidence
		return nil
	})
	resp, err := c.grpc.BootDelivery(ctx, req, bind)
	if err != nil {
		return nil, &ErrBootDeliveryFailed{Cause: err}
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
