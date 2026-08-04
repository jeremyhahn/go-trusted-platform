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

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	pb "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
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

// ErrUnixNotImplemented indicates a method is not yet implemented for Unix.
type ErrUnixNotImplemented struct {
	Method string
}

func (e ErrUnixNotImplemented) Error() string {
	return fmt.Sprintf("Unix method %s not implemented", e.Method)
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
		helpers.GRPCTransportCredentials(),
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
			Role:  unixEntityRoleToProto(opts.Role),
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
			Role:  unixEntityRoleToProto(opts.Role),
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

// AttestDevice performs device attestation
func (a *UnixAdapter) AttestDevice(ctx context.Context, opts AttestDeviceOptions) (*AttestDeviceResult, error) {
	// Note: AttestDevice is not part of the DeviceService proto but may be
	// available through a separate attestation service. For now, we use
	// ActivateDevice which is the closest equivalent in the current proto.
	req := &pb.ActivateDeviceRequest{
		Serial: opts.DeviceID,
	}

	resp, err := a.client.ActivateDevice(ctx, req)
	if err != nil {
		return nil, ErrUnixRPCFailed{Method: "ActivateDevice", Err: err}
	}

	attested := resp.GetStatus().GetSuccess()
	return &AttestDeviceResult{
		Attested: attested,
		DeviceID: opts.DeviceID,
		Message:  resp.GetActivationStatus(),
	}, nil
}

// =============================================================================
// Template CRUD Operations (not yet available via Unix/gRPC)
// =============================================================================

// CreateTemplate creates a new device template via Unix socket.
func (a *UnixAdapter) CreateTemplate(ctx context.Context, opts CreateTemplateOptions) (*CreateTemplateResult, error) {
	return nil, ErrUnixNotImplemented{Method: "CreateTemplate"}
}

// GetTemplate retrieves a template by ID via Unix socket.
func (a *UnixAdapter) GetTemplate(ctx context.Context, opts GetTemplateOptions) (*GetTemplateResult, error) {
	return nil, ErrUnixNotImplemented{Method: "GetTemplate"}
}

// UpdateTemplate updates an existing template via Unix socket.
func (a *UnixAdapter) UpdateTemplate(ctx context.Context, opts UpdateTemplateOptions) (*UpdateTemplateResult, error) {
	return nil, ErrUnixNotImplemented{Method: "UpdateTemplate"}
}

// DeleteTemplate removes a template via Unix socket.
func (a *UnixAdapter) DeleteTemplate(ctx context.Context, opts DeleteTemplateOptions) (*DeleteTemplateResult, error) {
	return nil, ErrUnixNotImplemented{Method: "DeleteTemplate"}
}

// ListTemplates lists all templates via Unix socket.
func (a *UnixAdapter) ListTemplates(ctx context.Context, opts ListTemplatesOptions) (*ListTemplatesResult, error) {
	return nil, ErrUnixNotImplemented{Method: "ListTemplates"}
}

// CreateProfileFromTemplate creates a profile from a template via Unix socket.
func (a *UnixAdapter) CreateProfileFromTemplate(ctx context.Context, opts CreateProfileFromTemplateOptions) (*CreateProfileResult, error) {
	return nil, ErrUnixNotImplemented{Method: "CreateProfileFromTemplate"}
}

// FindConfigForDevice finds the config for a device via Unix socket.
func (a *UnixAdapter) FindConfigForDevice(ctx context.Context, opts FindConfigForDeviceOptions) (*FindConfigForDeviceResult, error) {
	return nil, ErrUnixNotImplemented{Method: "FindConfigForDevice"}
}

// AssignProfileToDevice assigns a profile to a device via Unix socket.
func (a *UnixAdapter) AssignProfileToDevice(ctx context.Context, opts AssignProfileToDeviceOptions) (*AssignProfileToDeviceResult, error) {
	return nil, ErrUnixNotImplemented{Method: "AssignProfileToDevice"}
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
		Role:     unixProtoRoleToEntity(p.GetRole()),
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

// unixProtoRoleToEntity converts a proto DeviceRole to an entity DeviceRole
func unixProtoRoleToEntity(role pb.DeviceRole) entities.DeviceRole {
	switch role {
	case pb.DeviceRole_DEVICE_ROLE_SERVER:
		return entities.DeviceRoleServer
	case pb.DeviceRole_DEVICE_ROLE_CLIENT:
		return entities.DeviceRoleClient
	case pb.DeviceRole_DEVICE_ROLE_WORKSTATION:
		return entities.DeviceRoleWorkstation
	case pb.DeviceRole_DEVICE_ROLE_EDGE:
		return entities.DeviceRoleEdge
	case pb.DeviceRole_DEVICE_ROLE_IOT:
		return entities.DeviceRoleIoT
	case pb.DeviceRole_DEVICE_ROLE_GATEWAY:
		return entities.DeviceRoleGateway
	case pb.DeviceRole_DEVICE_ROLE_LOAD_BALANCER:
		return entities.DeviceRoleLoadBalancer
	default:
		return entities.DeviceRoleUnknown
	}
}

// unixEntityRoleToProto converts an entity DeviceRole to a proto DeviceRole
func unixEntityRoleToProto(role entities.DeviceRole) pb.DeviceRole {
	switch role {
	case entities.DeviceRoleServer:
		return pb.DeviceRole_DEVICE_ROLE_SERVER
	case entities.DeviceRoleClient:
		return pb.DeviceRole_DEVICE_ROLE_CLIENT
	case entities.DeviceRoleWorkstation:
		return pb.DeviceRole_DEVICE_ROLE_WORKSTATION
	case entities.DeviceRoleEdge:
		return pb.DeviceRole_DEVICE_ROLE_EDGE
	case entities.DeviceRoleIoT:
		return pb.DeviceRole_DEVICE_ROLE_IOT
	case entities.DeviceRoleGateway:
		return pb.DeviceRole_DEVICE_ROLE_GATEWAY
	case entities.DeviceRoleLoadBalancer:
		return pb.DeviceRole_DEVICE_ROLE_LOAD_BALANCER
	default:
		return pb.DeviceRole_DEVICE_ROLE_UNKNOWN
	}
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
