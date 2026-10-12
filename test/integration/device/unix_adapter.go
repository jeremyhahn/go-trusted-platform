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
// This file implements the DeviceCommands interface using gRPC over Unix socket.
package device

import (
	"context"
	"fmt"
	"net"
	"strconv"
	"strings"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	pb "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers/surface"
	"google.golang.org/grpc"
)

// =============================================================================
// Error Types
// =============================================================================

// ErrUnixConnectionFailed indicates a Unix socket connection failure.
type ErrUnixConnectionFailed struct {
	Path string
	Err  error
}

func (e ErrUnixConnectionFailed) Error() string {
	return fmt.Sprintf("Unix connection failed to %s: %v", e.Path, e.Err)
}

func (e ErrUnixConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrUnixRPCFailed indicates a gRPC call over Unix socket failed.
type ErrUnixRPCFailed struct {
	Method string
	Err    error
}

func (e ErrUnixRPCFailed) Error() string {
	return fmt.Sprintf("Unix RPC %s failed: %v", e.Method, e.Err)
}

func (e ErrUnixRPCFailed) Unwrap() error {
	return e.Err
}

// =============================================================================
// Unix Protocol Adapter
// =============================================================================

// UnixAdapter implements DeviceCommands using Unix domain socket
type UnixAdapter struct {
	socketPath string
	conn       *grpc.ClientConn
	client     pb.DeviceServiceClient
}

// NewUnixAdapter creates a new Unix socket adapter
func NewUnixAdapter() *UnixAdapter {
	return &UnixAdapter{
		socketPath: GetSocketPath(),
	}
}

// Setup prepares the adapter for testing
func (a *UnixAdapter) Setup(ctx context.Context) error {
	// Create gRPC connection using Unix socket dialer
	conn, err := grpc.DialContext(ctx, "unix://"+a.socketPath,
		helpers.GRPCUnixCredentials(),
		grpc.WithContextDialer(func(ctx context.Context, addr string) (net.Conn, error) {
			// Strip the unix:// prefix if present
			socketAddr := strings.TrimPrefix(addr, "unix://")
			var d net.Dialer
			return d.DialContext(ctx, "unix", socketAddr)
		}),
	)
	if err != nil {
		return ErrUnixConnectionFailed{
			Path: a.socketPath,
			Err:  err,
		}
	}

	a.conn = conn
	a.client = pb.NewDeviceServiceClient(conn)
	return nil
}

// Teardown cleans up after testing
func (a *UnixAdapter) Teardown(ctx context.Context) error {
	if a.conn != nil {
		return a.conn.Close()
	}
	return nil
}

// Name returns the adapter name
func (a *UnixAdapter) Name() string {
	return "Unix"
}

// =============================================================================
// Device CRUD Operations
// =============================================================================

// RegisterDevice registers a new device
func (a *UnixAdapter) RegisterDevice(ctx context.Context, opts RegisterDeviceOptions) (*RegisterDeviceResult, error) {
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
		return nil, ErrUnixRPCFailed{Method: "CreateDevice", Err: err}
	}

	return &RegisterDeviceResult{
		Device: unixProtoToDevice(resp.GetDevice()),
	}, nil
}

// GetDevice retrieves a device by its key
func (a *UnixAdapter) GetDevice(ctx context.Context, opts GetDeviceOptions) (*GetDeviceResult, error) {
	deviceID, err := strconv.ParseUint(opts.DeviceID, 10, 64)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetDevice", Err: fmt.Errorf("invalid device ID: %w", err)}
	}

	req := &pb.GetDeviceRequest{
		Id: deviceID,
	}

	resp, err := a.client.GetDevice(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetDevice", Err: err}
	}

	return &GetDeviceResult{
		Device: unixProtoToDevice(resp.GetDevice()),
	}, nil
}

// UpdateDevice updates an existing device
func (a *UnixAdapter) UpdateDevice(ctx context.Context, opts UpdateDeviceOptions) (*UpdateDeviceResult, error) {
	deviceID, err := strconv.ParseUint(opts.DeviceID, 10, 64)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "UpdateDevice", Err: fmt.Errorf("invalid device ID: %w", err)}
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
		return nil, ErrUnixRPCFailed{Method: "UpdateDevice", Err: err}
	}

	return &UpdateDeviceResult{
		Device: unixProtoToDevice(resp.GetDevice()),
	}, nil
}

// DeleteDevice removes a device
func (a *UnixAdapter) DeleteDevice(ctx context.Context, opts DeleteDeviceOptions) (*DeleteDeviceResult, error) {
	deviceID, err := strconv.ParseUint(opts.DeviceID, 10, 64)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "DeleteDevice", Err: fmt.Errorf("invalid device ID: %w", err)}
	}

	req := &pb.DeleteDeviceRequest{
		Id: deviceID,
	}

	resp, err := a.client.DeleteDevice(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "DeleteDevice", Err: err}
	}

	return &DeleteDeviceResult{
		Success: resp.GetStatus().GetSuccess(),
	}, nil
}

// ListDevices lists all devices with optional filtering
func (a *UnixAdapter) ListDevices(ctx context.Context, opts ListDevicesOptions) (*ListDevicesResult, error) {
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
		return nil, ErrUnixRPCFailed{Method: "ListDevices", Err: err}
	}

	devices := make([]*entities.Device, 0, len(resp.GetDevices()))
	for _, d := range resp.GetDevices() {
		devices = append(devices, unixProtoToDevice(d))
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
func (a *UnixAdapter) FindBySerial(ctx context.Context, opts FindBySerialOptions) (*FindBySerialResult, error) {
	req := &pb.FindDeviceBySerialRequest{
		Serial: opts.Serial,
	}

	resp, err := a.client.FindDeviceBySerial(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "FindDeviceBySerial", Err: err}
	}

	return &FindBySerialResult{
		Device: unixProtoToDevice(resp.GetDevice()),
	}, nil
}

// =============================================================================
// Profile CRUD Operations
// =============================================================================

// CreateProfile creates a new device profile
func (a *UnixAdapter) CreateProfile(ctx context.Context, opts CreateProfileOptions) (*CreateProfileResult, error) {
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
		req.Profile.MatchRules = unixEntityMatchRulesToProto(opts.MatchRules)
	}

	resp, err := a.client.CreateProfile(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "CreateProfile", Err: err}
	}

	return &CreateProfileResult{
		Profile: unixProtoToProfile(resp.GetProfile()),
	}, nil
}

// GetProfile retrieves a profile by its key
func (a *UnixAdapter) GetProfile(ctx context.Context, opts GetProfileOptions) (*GetProfileResult, error) {
	profileID, err := strconv.ParseUint(opts.ProfileID, 10, 64)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetProfile", Err: fmt.Errorf("invalid profile ID: %w", err)}
	}

	req := &pb.GetProfileRequest{
		Id: profileID,
	}

	resp, err := a.client.GetProfile(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "GetProfile", Err: err}
	}

	return &GetProfileResult{
		Profile: unixProtoToProfile(resp.GetProfile()),
	}, nil
}

// UpdateProfile updates an existing profile
func (a *UnixAdapter) UpdateProfile(ctx context.Context, opts UpdateProfileOptions) (*UpdateProfileResult, error) {
	profileID, err := strconv.ParseUint(opts.ProfileID, 10, 64)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "UpdateProfile", Err: fmt.Errorf("invalid profile ID: %w", err)}
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
		req.Profile.MatchRules = unixEntityMatchRulesToProto(opts.MatchRules)
	}

	resp, err := a.client.UpdateProfile(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "UpdateProfile", Err: err}
	}

	return &UpdateProfileResult{
		Profile: unixProtoToProfile(resp.GetProfile()),
	}, nil
}

// DeleteProfile removes a profile
func (a *UnixAdapter) DeleteProfile(ctx context.Context, opts DeleteProfileOptions) (*DeleteProfileResult, error) {
	profileID, err := strconv.ParseUint(opts.ProfileID, 10, 64)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "DeleteProfile", Err: fmt.Errorf("invalid profile ID: %w", err)}
	}

	req := &pb.DeleteProfileRequest{
		Id: profileID,
	}

	resp, err := a.client.DeleteProfile(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "DeleteProfile", Err: err}
	}

	return &DeleteProfileResult{
		Success: resp.GetStatus().GetSuccess(),
	}, nil
}

// ListProfiles lists all profiles with optional filtering
func (a *UnixAdapter) ListProfiles(ctx context.Context, opts ListProfilesOptions) (*ListProfilesResult, error) {
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
		return nil, ErrUnixRPCFailed{Method: "ListProfiles", Err: err}
	}

	profiles := make([]*entities.DeviceProfile, 0, len(resp.GetProfiles()))
	for _, p := range resp.GetProfiles() {
		profiles = append(profiles, unixProtoToProfile(p))
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
func (a *UnixAdapter) FindProfileByMACAddress(ctx context.Context, opts FindProfileByMACAddressOptions) (*FindProfileByMACAddressResult, error) {
	req := &pb.FindProfileByMACAddressRequest{
		MacAddress: opts.MACAddress,
	}

	resp, err := a.client.FindProfileByMACAddress(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "FindProfileByMACAddress", Err: err}
	}

	return &FindProfileByMACAddressResult{
		Profile: unixProtoToProfile(resp.GetProfile()),
	}, nil
}

// FindProfileBySerial finds a profile by serial pattern
func (a *UnixAdapter) FindProfileBySerial(ctx context.Context, opts FindProfileBySerialOptions) (*FindProfileBySerialResult, error) {
	req := &pb.FindProfileBySerialRequest{
		Serial: opts.Serial,
	}

	resp, err := a.client.FindProfileBySerial(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "FindProfileBySerial", Err: err}
	}

	return &FindProfileBySerialResult{
		Profile: unixProtoToProfile(resp.GetProfile()),
	}, nil
}

// FindMatchingProfile finds a profile matching device attributes
func (a *UnixAdapter) FindMatchingProfile(ctx context.Context, opts FindMatchingProfileOptions) (*FindMatchingProfileResult, error) {
	req := &pb.FindMatchingProfileRequest{
		MacAddress: opts.MACAddress,
		Serial:     opts.Serial,
		Model:      opts.Model,
	}

	resp, err := a.client.FindMatchingProfile(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "FindMatchingProfile", Err: err}
	}

	return &FindMatchingProfileResult{
		Profile: unixProtoToProfile(resp.GetProfile()),
	}, nil
}

// =============================================================================
// Attestation
// =============================================================================

// AttestDevice submits quote evidence to the DeviceService AttestDevice RPC
// over the Unix socket and returns the platform's verdict.
//
// This adapter previously called ActivateDevice and reported ITS success as
// an attestation verdict, so the suite reported attestation passing without
// a quote ever being verified (#403).
func (a *UnixAdapter) AttestDevice(ctx context.Context, opts AttestDeviceOptions) (*AttestDeviceResult, error) {
	resp, err := a.client.AttestDevice(ctx, &pb.AttestDeviceRequest{
		DeviceId: opts.DeviceID,
		Evidence: opts.Evidence,
	})
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "AttestDevice", Err: err}
	}

	return attestResultFromProto(opts.DeviceID, resp), nil
}

// RecordAttestCert records the device's attestation certificate via
// DeviceService.RecordAttestationCertificate.
func (a *UnixAdapter) RecordAttestCert(ctx context.Context, opts RecordAttestCertOptions) (*RecordAttestCertResult, error) {
	resp, err := a.client.RecordAttestationCertificate(ctx, &pb.RecordAttestationCertificateRequest{
		DeviceId:       opts.DeviceID,
		Reissue:        opts.Reissue,
		ClearOnRefusal: opts.ClearOnRefusal,
	})
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "RecordAttestationCertificate", Err: err}
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
// Template CRUD Operations (not yet available via Unix/gRPC)
// =============================================================================

// CreateTemplate creates a new device template via Unix socket.
func (a *UnixAdapter) CreateTemplate(ctx context.Context, opts CreateTemplateOptions) (*CreateTemplateResult, error) {
	return nil, surface.ErrNoSurface{Transport: "Unix", Operation: "CreateTemplate"}
}

// GetTemplate retrieves a template by ID via Unix socket.
func (a *UnixAdapter) GetTemplate(ctx context.Context, opts GetTemplateOptions) (*GetTemplateResult, error) {
	return nil, surface.ErrNoSurface{Transport: "Unix", Operation: "GetTemplate"}
}

// UpdateTemplate updates an existing template via Unix socket.
func (a *UnixAdapter) UpdateTemplate(ctx context.Context, opts UpdateTemplateOptions) (*UpdateTemplateResult, error) {
	return nil, surface.ErrNoSurface{Transport: "Unix", Operation: "UpdateTemplate"}
}

// DeleteTemplate removes a template via Unix socket.
func (a *UnixAdapter) DeleteTemplate(ctx context.Context, opts DeleteTemplateOptions) (*DeleteTemplateResult, error) {
	return nil, surface.ErrNoSurface{Transport: "Unix", Operation: "DeleteTemplate"}
}

// ListTemplates lists all templates via Unix socket.
func (a *UnixAdapter) ListTemplates(ctx context.Context, opts ListTemplatesOptions) (*ListTemplatesResult, error) {
	return nil, surface.ErrNoSurface{Transport: "Unix", Operation: "ListTemplates"}
}

// CreateProfileFromTemplate creates a profile from a template via Unix socket.
func (a *UnixAdapter) CreateProfileFromTemplate(ctx context.Context, opts CreateProfileFromTemplateOptions) (*CreateProfileResult, error) {
	templateID, err := strconv.ParseUint(opts.TemplateID, 10, 64)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "CreateProfileFromTemplate", Err: fmt.Errorf("invalid template ID: %w", err)}
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
		return nil, ErrUnixRPCFailed{Method: "CreateProfileFromTemplate", Err: err}
	}

	if resp.GetProfile() == nil {
		return nil, ErrUnixRPCFailed{
			Method: "CreateProfileFromTemplate",
			Err:    fmt.Errorf("daemon returned no profile for template %d", templateID),
		}
	}

	return &CreateProfileResult{
		Profile: unixProtoToProfile(resp.GetProfile()),
	}, nil
}

// FindConfigForDevice finds the config for a device via Unix socket.
func (a *UnixAdapter) FindConfigForDevice(ctx context.Context, opts FindConfigForDeviceOptions) (*FindConfigForDeviceResult, error) {
	return nil, surface.ErrNoSurface{Transport: "Unix", Operation: "FindConfigForDevice"}
}

// AssignProfileToDevice assigns a profile to a device via Unix socket.
func (a *UnixAdapter) AssignProfileToDevice(ctx context.Context, opts AssignProfileToDeviceOptions) (*AssignProfileToDeviceResult, error) {
	profileID, err := strconv.ParseUint(opts.ProfileID, 10, 64)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "AssignProfileToDevice", Err: fmt.Errorf("invalid profile ID: %w", err)}
	}

	req := &pb.AssignProfileToDeviceRequest{
		ProfileId: profileID,
		EkSerial:  opts.EKSerial,
	}

	resp, err := a.client.AssignProfileToDevice(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "AssignProfileToDevice", Err: err}
	}

	// A nil profile means the daemon answered without assigning anything;
	// surfacing it here names the transport instead of nil-panicking in the
	// shared subtest.
	if resp.GetProfile() == nil {
		return nil, ErrUnixRPCFailed{
			Method: "AssignProfileToDevice",
			Err:    fmt.Errorf("daemon returned no profile for id %d", profileID),
		}
	}

	return &AssignProfileToDeviceResult{
		Profile: unixProtoToProfile(resp.GetProfile()),
	}, nil
}

// =============================================================================
// Proto Conversion Helpers (Unix-specific to avoid name collisions)
// =============================================================================

// unixProtoToDevice converts a proto device to an entity device
func unixProtoToDevice(d *pb.Device) *entities.Device {
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

// unixProtoToProfile converts a proto profile to an entity profile
func unixProtoToProfile(p *pb.DeviceProfile) *entities.DeviceProfile {
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
		profile.MatchRules = unixProtoMatchRulesToEntity(p.GetMatchRules())
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
		profile.Networks[name] = unixProtoNetworkConfigToEntity(cfg)
	}

	return profile
}

// unixProtoMatchRulesToEntity converts proto ProfileMatchRules to entity ProfileMatchRules
func unixProtoMatchRulesToEntity(rules *pb.ProfileMatchRules) *entities.ProfileMatchRules {
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

// unixEntityMatchRulesToProto converts entity ProfileMatchRules to proto ProfileMatchRules
func unixEntityMatchRulesToProto(rules *entities.ProfileMatchRules) *pb.ProfileMatchRules {
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

// unixProtoNetworkConfigToEntity converts proto NetworkPhaseConfig to entity NetworkPhaseConfig
func unixProtoNetworkConfigToEntity(config *pb.NetworkPhaseConfig) *entities.NetworkPhaseConfig {
	if config == nil {
		return nil
	}

	result := &entities.NetworkPhaseConfig{
		VLAN:       uint16(config.GetVlan()),
		StaticIP:   config.GetStaticIp(),
		Gateway:    config.GetGateway(),
		DNS:        config.GetDns(),
		AuthMethod: unixProtoAuthMethodToEntity(config.GetAuthMethod()),
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

// unixProtoAuthMethodToEntity converts proto AuthMethod to entity AuthMethod
func unixProtoAuthMethodToEntity(method pb.AuthMethod) entities.AuthMethod {
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

// Verify UnixAdapter implements DeviceCommands
var _ DeviceCommands = (*UnixAdapter)(nil)
