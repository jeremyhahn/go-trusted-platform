//go:build integration

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

// Package device provides integration test adapters for Device services.
// This file implements the DeviceCommands interface using gRPC protocol.
package device

import (
	"context"
	"fmt"
	"strconv"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	pb "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/surface"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// =============================================================================
// Error Types
// =============================================================================

// ErrGRPCConnectionFailed indicates a gRPC connection failure.
type ErrGRPCConnectionFailed struct {
	Endpoint string
	Err      error
}

func (e ErrGRPCConnectionFailed) Error() string {
	return fmt.Sprintf("gRPC connection failed to %s: %v", e.Endpoint, e.Err)
}

func (e ErrGRPCConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrGRPCCallFailed indicates a gRPC method call failure.
type ErrGRPCCallFailed struct {
	Method string
	Err    error
}

func (e ErrGRPCCallFailed) Error() string {
	return fmt.Sprintf("gRPC call %s failed: %v", e.Method, e.Err)
}

func (e ErrGRPCCallFailed) Unwrap() error {
	return e.Err
}

// =============================================================================
// gRPC Protocol Adapter
// =============================================================================

// GRPCAdapter implements DeviceCommands using gRPC API
type GRPCAdapter struct {
	endpoint string
	conn     *grpc.ClientConn
	client   pb.DeviceServiceClient
}

// NewGRPCAdapter creates a new gRPC adapter
func NewGRPCAdapter() *GRPCAdapter {
	return &GRPCAdapter{
		endpoint: GetGRPCEndpoint(),
	}
}

// Setup prepares the adapter for testing
func (a *GRPCAdapter) Setup(ctx context.Context) error {
	tlsConfig := helpers.TLSConfigOrInsecure()

	conn, err := grpc.DialContext(ctx, a.endpoint,
		grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig)),
	)
	if err != nil {
		return ErrGRPCConnectionFailed{
			Endpoint: a.endpoint,
			Err:      err,
		}
	}

	a.conn = conn
	a.client = pb.NewDeviceServiceClient(conn)
	return nil
}

// Teardown cleans up after testing
func (a *GRPCAdapter) Teardown(ctx context.Context) error {
	if a.conn != nil {
		return a.conn.Close()
	}
	return nil
}

// Name returns the adapter name
func (a *GRPCAdapter) Name() string {
	return "gRPC"
}

// =============================================================================
// Device CRUD Operations
// =============================================================================

// RegisterDevice registers a new device
func (a *GRPCAdapter) RegisterDevice(ctx context.Context, opts RegisterDeviceOptions) (*RegisterDeviceResult, error) {
	req := &pb.CreateDeviceRequest{
		Device: &pb.Device{
			Serial:     opts.Serial,
			Model:      opts.Model,
			EkCert:     opts.EKCert,
			AttestPub:  opts.AttestPub,
			AttestCert: opts.AttestCert,
			SigningPub: opts.SigningPub,
			HashAlgoId: opts.HashAlgoId,
		},
	}

	resp, err := a.client.CreateDevice(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "CreateDevice", Err: err}
	}

	return &RegisterDeviceResult{
		Device: protoToDevice(resp.GetDevice()),
	}, nil
}

// GetDevice retrieves a device by its key
func (a *GRPCAdapter) GetDevice(ctx context.Context, opts GetDeviceOptions) (*GetDeviceResult, error) {
	deviceID, err := strconv.ParseUint(opts.DeviceID, 10, 64)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetDevice", Err: fmt.Errorf("invalid device ID: %w", err)}
	}

	req := &pb.GetDeviceRequest{
		Id: deviceID,
	}

	resp, err := a.client.GetDevice(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetDevice", Err: err}
	}

	return &GetDeviceResult{
		Device: protoToDevice(resp.GetDevice()),
	}, nil
}

// UpdateDevice updates an existing device
func (a *GRPCAdapter) UpdateDevice(ctx context.Context, opts UpdateDeviceOptions) (*UpdateDeviceResult, error) {
	deviceID, err := strconv.ParseUint(opts.DeviceID, 10, 64)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "UpdateDevice", Err: fmt.Errorf("invalid device ID: %w", err)}
	}

	req := &pb.UpdateDeviceRequest{
		Device: &pb.Device{
			Id:         deviceID,
			Model:      opts.Model,
			EkCert:     opts.EKCert,
			AttestPub:  opts.AttestPub,
			AttestCert: opts.AttestCert,
			SigningPub: opts.SigningPub,
			HashAlgoId: opts.HashAlgoId,
		},
	}

	resp, err := a.client.UpdateDevice(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "UpdateDevice", Err: err}
	}

	return &UpdateDeviceResult{
		Device: protoToDevice(resp.GetDevice()),
	}, nil
}

// DeleteDevice removes a device
func (a *GRPCAdapter) DeleteDevice(ctx context.Context, opts DeleteDeviceOptions) (*DeleteDeviceResult, error) {
	deviceID, err := strconv.ParseUint(opts.DeviceID, 10, 64)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "DeleteDevice", Err: fmt.Errorf("invalid device ID: %w", err)}
	}

	req := &pb.DeleteDeviceRequest{
		Id: deviceID,
	}

	resp, err := a.client.DeleteDevice(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "DeleteDevice", Err: err}
	}

	return &DeleteDeviceResult{
		Success: resp.GetStatus().GetSuccess(),
	}, nil
}

// ListDevices lists all devices with optional filtering
func (a *GRPCAdapter) ListDevices(ctx context.Context, opts ListDevicesOptions) (*ListDevicesResult, error) {
	// Calculate page number from offset and limit
	page := uint32(1)
	if opts.Limit > 0 && opts.Offset > 0 {
		page = uint32(opts.Offset/opts.Limit) + 1
	}

	req := &pb.ListDevicesRequest{
		Pagination: &pb.PaginationRequest{
			PageSize: uint32(opts.Limit),
			Page:     page,
		},
	}

	resp, err := a.client.ListDevices(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "ListDevices", Err: err}
	}

	devices := make([]*entities.Device, 0, len(resp.GetDevices()))
	for _, d := range resp.GetDevices() {
		devices = append(devices, protoToDevice(d))
	}

	total := 0
	if resp.GetPagination() != nil {
		total = int(resp.GetPagination().GetTotalItems())
	}

	return &ListDevicesResult{
		Devices: devices,
		Total:   total,
	}, nil
}

// =============================================================================
// Device Lookups
// =============================================================================

// FindBySerial finds a device by its serial number
func (a *GRPCAdapter) FindBySerial(ctx context.Context, opts FindBySerialOptions) (*FindBySerialResult, error) {
	req := &pb.FindDeviceBySerialRequest{
		Serial: opts.Serial,
	}

	resp, err := a.client.FindDeviceBySerial(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "FindDeviceBySerial", Err: err}
	}

	return &FindBySerialResult{
		Device: protoToDevice(resp.GetDevice()),
	}, nil
}

// =============================================================================
// Profile CRUD Operations
// =============================================================================

// CreateProfile creates a new device profile
func (a *GRPCAdapter) CreateProfile(ctx context.Context, opts CreateProfileOptions) (*CreateProfileResult, error) {
	req := &pb.CreateProfileRequest{
		Profile: &pb.DeviceProfile{
			Name:  opts.Name,
			Model: opts.Model,
			Role:  grpcapi.EntityRoleToProto(opts.Role),
			MatchRules: &pb.ProfileMatchRules{
				MacPrefix:    opts.MACPrefix,
				SerialPrefix: opts.SerialPrefix,
			},
		},
	}

	if opts.MatchRules != nil {
		req.Profile.MatchRules = entityMatchRulesToProto(opts.MatchRules)
	}

	resp, err := a.client.CreateProfile(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "CreateProfile", Err: err}
	}

	return &CreateProfileResult{
		Profile: protoToProfile(resp.GetProfile()),
	}, nil
}

// GetProfile retrieves a profile by its key
func (a *GRPCAdapter) GetProfile(ctx context.Context, opts GetProfileOptions) (*GetProfileResult, error) {
	profileID, err := strconv.ParseUint(opts.ProfileID, 10, 64)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetProfile", Err: fmt.Errorf("invalid profile ID: %w", err)}
	}

	req := &pb.GetProfileRequest{
		Id: profileID,
	}

	resp, err := a.client.GetProfile(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "GetProfile", Err: err}
	}

	return &GetProfileResult{
		Profile: protoToProfile(resp.GetProfile()),
	}, nil
}

// UpdateProfile updates an existing profile
func (a *GRPCAdapter) UpdateProfile(ctx context.Context, opts UpdateProfileOptions) (*UpdateProfileResult, error) {
	profileID, err := strconv.ParseUint(opts.ProfileID, 10, 64)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "UpdateProfile", Err: fmt.Errorf("invalid profile ID: %w", err)}
	}

	req := &pb.UpdateProfileRequest{
		Profile: &pb.DeviceProfile{
			Id:    profileID,
			Name:  opts.Name,
			Model: opts.Model,
			Role:  grpcapi.EntityRoleToProto(opts.Role),
		},
	}

	if opts.MatchRules != nil {
		req.Profile.MatchRules = entityMatchRulesToProto(opts.MatchRules)
	}

	resp, err := a.client.UpdateProfile(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "UpdateProfile", Err: err}
	}

	return &UpdateProfileResult{
		Profile: protoToProfile(resp.GetProfile()),
	}, nil
}

// DeleteProfile removes a profile
func (a *GRPCAdapter) DeleteProfile(ctx context.Context, opts DeleteProfileOptions) (*DeleteProfileResult, error) {
	profileID, err := strconv.ParseUint(opts.ProfileID, 10, 64)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "DeleteProfile", Err: fmt.Errorf("invalid profile ID: %w", err)}
	}

	req := &pb.DeleteProfileRequest{
		Id: profileID,
	}

	resp, err := a.client.DeleteProfile(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "DeleteProfile", Err: err}
	}

	return &DeleteProfileResult{
		Success: resp.GetStatus().GetSuccess(),
	}, nil
}

// ListProfiles lists all profiles with optional filtering
func (a *GRPCAdapter) ListProfiles(ctx context.Context, opts ListProfilesOptions) (*ListProfilesResult, error) {
	// Calculate page number from offset and limit
	page := uint32(1)
	if opts.Limit > 0 && opts.Offset > 0 {
		page = uint32(opts.Offset/opts.Limit) + 1
	}

	req := &pb.ListProfilesRequest{
		Pagination: &pb.PaginationRequest{
			PageSize: uint32(opts.Limit),
			Page:     page,
		},
	}

	resp, err := a.client.ListProfiles(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "ListProfiles", Err: err}
	}

	profiles := make([]*entities.DeviceProfile, 0, len(resp.GetProfiles()))
	for _, p := range resp.GetProfiles() {
		profiles = append(profiles, protoToProfile(p))
	}

	total := 0
	if resp.GetPagination() != nil {
		total = int(resp.GetPagination().GetTotalItems())
	}

	return &ListProfilesResult{
		Profiles: profiles,
		Total:    total,
	}, nil
}

// =============================================================================
// Profile Lookups
// =============================================================================

// FindProfileByMACAddress finds a profile by MAC address prefix
func (a *GRPCAdapter) FindProfileByMACAddress(ctx context.Context, opts FindProfileByMACAddressOptions) (*FindProfileByMACAddressResult, error) {
	req := &pb.FindProfileByMACAddressRequest{
		MacAddress: opts.MACAddress,
	}

	resp, err := a.client.FindProfileByMACAddress(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "FindProfileByMACAddress", Err: err}
	}

	return &FindProfileByMACAddressResult{
		Profile: protoToProfile(resp.GetProfile()),
	}, nil
}

// FindProfileBySerial finds a profile by serial pattern
func (a *GRPCAdapter) FindProfileBySerial(ctx context.Context, opts FindProfileBySerialOptions) (*FindProfileBySerialResult, error) {
	req := &pb.FindProfileBySerialRequest{
		Serial: opts.Serial,
	}

	resp, err := a.client.FindProfileBySerial(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "FindProfileBySerial", Err: err}
	}

	return &FindProfileBySerialResult{
		Profile: protoToProfile(resp.GetProfile()),
	}, nil
}

// FindMatchingProfile finds a profile matching device attributes
func (a *GRPCAdapter) FindMatchingProfile(ctx context.Context, opts FindMatchingProfileOptions) (*FindMatchingProfileResult, error) {
	req := &pb.FindMatchingProfileRequest{
		MacAddress: opts.MACAddress,
		Serial:     opts.Serial,
		Model:      opts.Model,
	}

	resp, err := a.client.FindMatchingProfile(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "FindMatchingProfile", Err: err}
	}

	return &FindMatchingProfileResult{
		Profile: protoToProfile(resp.GetProfile()),
	}, nil
}

// =============================================================================
// Attestation
// =============================================================================

// AttestDevice submits quote evidence to the DeviceService AttestDevice RPC
// and returns the platform's verdict.
//
// This adapter previously called ActivateDevice and reported ITS success as
// an attestation verdict, so the suite reported attestation passing without
// a quote ever being verified (#403).
func (a *GRPCAdapter) AttestDevice(ctx context.Context, opts AttestDeviceOptions) (*AttestDeviceResult, error) {
	resp, err := a.client.AttestDevice(ctx, &pb.AttestDeviceRequest{
		DeviceId: opts.DeviceID,
		Evidence: opts.Evidence,
	})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "AttestDevice", Err: err}
	}

	return attestResultFromProto(opts.DeviceID, resp), nil
}

// attestResultFromProto maps the gRPC verdict onto the suite's result shape.
// Shared with the Unix adapter, which speaks the same service over UDS.
func attestResultFromProto(deviceID string, resp *pb.AttestDeviceResponse) *AttestDeviceResult {
	return &AttestDeviceResult{
		DeviceID:              deviceID,
		Serial:                resp.GetSerial(),
		Verified:              resp.GetVerified(),
		SignatureValid:        resp.GetSignatureValid(),
		NonceValid:            resp.GetNonceValid(),
		PCRsValid:             resp.GetPcrsValid(),
		AKCertificateVerified: resp.GetAkCertificateVerified(),
		AttestationStatus:     resp.GetAttestationStatus(),
		Message:               resp.GetMessage(),
	}
}

// RecordAttestCert records the device's attestation certificate via
// DeviceService.RecordAttestationCertificate.
func (a *GRPCAdapter) RecordAttestCert(ctx context.Context, opts RecordAttestCertOptions) (*RecordAttestCertResult, error) {
	resp, err := a.client.RecordAttestationCertificate(ctx, &pb.RecordAttestationCertificateRequest{
		DeviceId:       opts.DeviceID,
		Reissue:        opts.Reissue,
		ClearOnRefusal: opts.ClearOnRefusal,
	})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "RecordAttestationCertificate", Err: err}
	}
	return &RecordAttestCertResult{
		DeviceID:          strconv.FormatUint(resp.GetDeviceId(), 10),
		Serial:            resp.GetSerial(),
		Model:             resp.GetModel(),
		Changed:           resp.GetChanged(),
		Source:            resp.GetSource(),
		SourceDetail:      resp.GetSourceDetail(),
		Reissued:          resp.GetReissued(),
		Subject:           resp.GetSubject(),
		CertificateSerial: resp.GetCertificateSerial(),
		AttestCert:        resp.GetAttestCert(),
		Cleared:           resp.GetCleared(),
		Refusal:           resp.GetRefusal(),
	}, nil
}

// =============================================================================
// Template CRUD Operations (not yet available via gRPC)
// =============================================================================

// CreateTemplate creates a new device template via gRPC.
func (a *GRPCAdapter) CreateTemplate(ctx context.Context, opts CreateTemplateOptions) (*CreateTemplateResult, error) {
	resp, err := a.client.CreateTemplate(ctx, templateCreateRequest(opts))
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "CreateTemplate", Err: err}
	}
	if resp.GetTemplate() == nil {
		return nil, ErrGRPCCallFailed{Method: "CreateTemplate", Err: fmt.Errorf("daemon returned no template")}
	}
	return &CreateTemplateResult{Template: protoToTemplate(resp.GetTemplate())}, nil
}

// GetTemplate retrieves a template by ID via gRPC.
func (a *GRPCAdapter) GetTemplate(ctx context.Context, opts GetTemplateOptions) (*GetTemplateResult, error) {
	return nil, surface.ErrNoSurface{Transport: "gRPC", Operation: "GetTemplate"}
}

// UpdateTemplate updates an existing template via gRPC.
func (a *GRPCAdapter) UpdateTemplate(ctx context.Context, opts UpdateTemplateOptions) (*UpdateTemplateResult, error) {
	return nil, surface.ErrNoSurface{Transport: "gRPC", Operation: "UpdateTemplate"}
}

// DeleteTemplate removes a template via gRPC.
func (a *GRPCAdapter) DeleteTemplate(ctx context.Context, opts DeleteTemplateOptions) (*DeleteTemplateResult, error) {
	return nil, surface.ErrNoSurface{Transport: "gRPC", Operation: "DeleteTemplate"}
}

// ListTemplates lists all templates via gRPC.
func (a *GRPCAdapter) ListTemplates(ctx context.Context, opts ListTemplatesOptions) (*ListTemplatesResult, error) {
	return nil, surface.ErrNoSurface{Transport: "gRPC", Operation: "ListTemplates"}
}

// CreateProfileFromTemplate creates a profile from a template via gRPC.
func (a *GRPCAdapter) CreateProfileFromTemplate(ctx context.Context, opts CreateProfileFromTemplateOptions) (*CreateProfileResult, error) {
	templateID, err := strconv.ParseUint(opts.TemplateID, 10, 64)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "CreateProfileFromTemplate", Err: fmt.Errorf("invalid template ID: %w", err)}
	}

	// Name, EK serial and MAC ride as overrides on the template: the RPC takes
	// a DeviceProfile whose set fields replace the template's. Leaving them
	// empty means "inherit", which is what the shared subtest wants when it
	// only names the profile.
	req := &pb.CreateProfileFromTemplateRequest{
		TemplateId: templateID,
		Overrides: &pb.DeviceProfile{
			Name:       opts.Name,
			EkSerial:   opts.EKSerial,
			MacAddress: opts.MACAddress,
		},
	}

	resp, err := a.client.CreateProfileFromTemplate(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "CreateProfileFromTemplate", Err: err}
	}

	if resp.GetProfile() == nil {
		return nil, ErrGRPCCallFailed{
			Method: "CreateProfileFromTemplate",
			Err:    fmt.Errorf("daemon returned no profile for template %d", templateID),
		}
	}

	return &CreateProfileResult{
		Profile: protoToProfile(resp.GetProfile()),
	}, nil
}

// FindConfigForDevice finds the config for a device via gRPC.
func (a *GRPCAdapter) FindConfigForDevice(ctx context.Context, opts FindConfigForDeviceOptions) (*FindConfigForDeviceResult, error) {
	return nil, surface.ErrNoSurface{Transport: "gRPC", Operation: "FindConfigForDevice"}
}

// AssignProfileToDevice assigns a profile to a device via gRPC.
func (a *GRPCAdapter) AssignProfileToDevice(ctx context.Context, opts AssignProfileToDeviceOptions) (*AssignProfileToDeviceResult, error) {
	profileID, err := strconv.ParseUint(opts.ProfileID, 10, 64)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "AssignProfileToDevice", Err: fmt.Errorf("invalid profile ID: %w", err)}
	}

	req := &pb.AssignProfileToDeviceRequest{
		ProfileId: profileID,
		EkSerial:  opts.EKSerial,
	}

	resp, err := a.client.AssignProfileToDevice(ctx, req)
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "AssignProfileToDevice", Err: err}
	}

	// A nil profile means the daemon answered without assigning anything.
	// Returning it would let the caller's "Assigned" assertion nil-panic
	// rather than report which transport failed.
	if resp.GetProfile() == nil {
		return nil, ErrGRPCCallFailed{
			Method: "AssignProfileToDevice",
			Err:    fmt.Errorf("daemon returned no profile for id %d", profileID),
		}
	}

	return &AssignProfileToDeviceResult{
		Profile: protoToProfile(resp.GetProfile()),
	}, nil
}

// DisableDevice calls DeviceService.DisableDevice.
func (a *GRPCAdapter) DisableDevice(ctx context.Context, opts DisableDeviceOptions) (*DeviceLifecycleResult, error) {
	resp, err := a.client.DisableDevice(ctx, &pb.DisableDeviceRequest{DeviceId: opts.DeviceID, Reason: opts.Reason})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "DisableDevice", Err: err}
	}
	return lifecycleResultFromProto(resp), nil
}

// EnableDevice calls DeviceService.EnableDevice.
func (a *GRPCAdapter) EnableDevice(ctx context.Context, opts EnableDeviceOptions) (*DeviceLifecycleResult, error) {
	resp, err := a.client.EnableDevice(ctx, &pb.EnableDeviceRequest{DeviceId: opts.DeviceID})
	if err != nil {
		return nil, ErrGRPCCallFailed{Method: "EnableDevice", Err: err}
	}
	return lifecycleResultFromProto(resp), nil
}

// =============================================================================
// Proto Conversion Helpers
// =============================================================================

// protoToDevice converts a proto device to an entity device
func protoToDevice(d *pb.Device) *entities.Device {
	if d == nil {
		return nil
	}
	return &entities.Device{
		ID:         d.GetId(),
		Serial:     d.GetSerial(),
		Model:      d.GetModel(),
		EKCert:     d.GetEkCert(),
		AttestPub:  d.GetAttestPub(),
		AttestCert: d.GetAttestCert(),
		SigningPub: d.GetSigningPub(),
		HashAlgoId: d.GetHashAlgoId(),
		EventLog:   d.GetEventLog(),
	}
}

// protoToProfile converts a proto profile to an entity profile
func protoToProfile(p *pb.DeviceProfile) *entities.DeviceProfile {
	if p == nil {
		return nil
	}
	profile := &entities.DeviceProfile{
		ID:       p.GetId(),
		Name:     p.GetName(),
		Model:    p.GetModel(),
		Role:     grpcapi.ProtoRoleToEntity(p.GetRole()),
		EventLog: p.GetEventLog(),
	}

	if p.GetMatchRules() != nil {
		profile.MatchRules = protoMatchRulesToEntity(p.GetMatchRules())
	}

	// The current proto carries named network phases in a map plus the
	// enrollment / post-enrollment / failure phase name bindings instead
	// of the former fixed provisioning / production / quarantine fields.
	profile.Zone = p.GetZone()
	profile.TenantID = p.GetTenantId()
	profile.EnrollmentNetwork = p.GetEnrollmentNetwork()
	profile.PostEnrollmentNetwork = p.GetPostEnrollmentNetwork()
	profile.FailureNetwork = p.GetFailureNetwork()

	profile.Networks = make(map[string]*entities.NetworkPhaseConfig, len(p.GetNetworks()))
	for name, cfg := range p.GetNetworks() {
		profile.Networks[name] = protoNetworkConfigToEntity(cfg)
	}

	return profile
}

// templateCreateRequest is the DeviceService.CreateTemplate request every
// RPC-shaped adapter (gRPC, Unix, QUIC) sends for opts.
func templateCreateRequest(opts CreateTemplateOptions) *pb.DeviceTemplateCreateRequest {
	return &pb.DeviceTemplateCreateRequest{
		Template: &pb.DeviceTemplate{
			TenantId:    opts.TenantID,
			Name:        opts.Name,
			Description: opts.Description,
			Role:        grpcapi.EntityRoleToProto(opts.Role),
			Config:      opts.Config,
			MatchRules:  entityMatchRulesToProto(opts.MatchRules),
		},
	}
}

// protoToTemplate maps the template a CreateTemplate response carries
// onto the entity the shared subtests compare against.
func protoToTemplate(t *pb.DeviceTemplate) *entities.DeviceTemplate {
	if t == nil {
		return nil
	}
	return &entities.DeviceTemplate{
		ID:          t.GetId(),
		TenantID:    t.GetTenantId(),
		Name:        t.GetName(),
		Description: t.GetDescription(),
		Role:        grpcapi.ProtoRoleToEntity(t.GetRole()),
		Config:      t.GetConfig(),
		MatchRules:  protoMatchRulesToEntity(t.GetMatchRules()),
	}
}

// protoMatchRulesToEntity converts proto ProfileMatchRules to entity ProfileMatchRules
func protoMatchRulesToEntity(rules *pb.ProfileMatchRules) *entities.ProfileMatchRules {
	if rules == nil {
		return nil
	}
	return &entities.ProfileMatchRules{
		MACPrefix:         rules.GetMacPrefix(),
		SerialPrefix:      rules.GetSerialPrefix(),
		Model:             rules.GetModel(),
		ModelPattern:      rules.GetModelPattern(),
		SerialPattern:     rules.GetSerialPattern(),
		ManufacturerMatch: rules.GetManufacturerMatch(),
		TPMVendor:         rules.GetTpmVendor(),
		CustomAttributes:  rules.GetCustomAttributes(),
	}
}

// entityMatchRulesToProto converts entity ProfileMatchRules to proto ProfileMatchRules
func entityMatchRulesToProto(rules *entities.ProfileMatchRules) *pb.ProfileMatchRules {
	if rules == nil {
		return nil
	}
	return &pb.ProfileMatchRules{
		MacPrefix:         rules.MACPrefix,
		SerialPrefix:      rules.SerialPrefix,
		Model:             rules.Model,
		ModelPattern:      rules.ModelPattern,
		SerialPattern:     rules.SerialPattern,
		ManufacturerMatch: rules.ManufacturerMatch,
		TpmVendor:         rules.TPMVendor,
		CustomAttributes:  rules.CustomAttributes,
	}
}

// protoNetworkConfigToEntity converts proto NetworkPhaseConfig to entity NetworkPhaseConfig
func protoNetworkConfigToEntity(config *pb.NetworkPhaseConfig) *entities.NetworkPhaseConfig {
	if config == nil {
		return nil
	}

	result := &entities.NetworkPhaseConfig{
		VLAN:       uint16(config.GetVlan()),
		StaticIP:   config.GetStaticIp(),
		Gateway:    config.GetGateway(),
		DNS:        config.GetDns(),
		AuthMethod: protoAuthMethodToEntity(config.GetAuthMethod()),
		Subnet:     config.GetSubnet(),
		DNSServers: config.GetDnsServers(),
		DHCP:       config.GetDhcp(),
		Zone:       config.GetZone(),
	}

	if config.GetDhcpPool() != nil {
		result.DHCPPool = &entities.DHCPPoolConfig{
			Network:    config.GetDhcpPool().GetNetwork(),
			RangeStart: config.GetDhcpPool().GetRangeStart(),
			RangeEnd:   config.GetDhcpPool().GetRangeEnd(),
			LeaseTime:  int(config.GetDhcpPool().GetLeaseTime()),
		}
	}

	if config.GetAcls() != nil {
		result.ACLs = make([]entities.ACLConfig, 0, len(config.GetAcls()))
		for _, acl := range config.GetAcls() {
			result.ACLs = append(result.ACLs, entities.ACLConfig{
				Priority: int(acl.GetPriority()),
				Protocol: acl.GetProtocol(),
				SrcIP:    acl.GetSrcIp(),
				DstIP:    acl.GetDstIp(),
				SrcPort:  uint16(acl.GetSrcPort()),
				DstPort:  uint16(acl.GetDstPort()),
				Action:   acl.GetAction(),
			})
		}
	}

	return result
}

// protoAuthMethodToEntity converts proto AuthMethod to entity AuthMethod
func protoAuthMethodToEntity(method pb.AuthMethod) entities.AuthMethod {
	switch method {
	case pb.AuthMethod_AUTH_METHOD_802_1X:
		return entities.AuthMethod802_1X
	case pb.AuthMethod_AUTH_METHOD_NONE:
		return entities.AuthMethodNone
	default:
		return entities.AuthMethodNone
	}
}

// =============================================================================
// Compile-time Interface Verification
// =============================================================================

// Verify GRPCAdapter implements DeviceCommands
var _ DeviceCommands = (*GRPCAdapter)(nil)
