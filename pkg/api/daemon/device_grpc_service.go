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

package daemon

import (
	"context"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

// DeviceGRPCService implements the gRPC DeviceService.
// It delegates all operations to the service layer interfaces.
type DeviceGRPCService struct {
	platformv1.UnimplementedDeviceServiceServer

	deviceService  device.DeviceService
	profileService device.DeviceProfileService
	logger         *slog.Logger
}

// NewDeviceGRPCService creates a new DeviceGRPCService.
func NewDeviceGRPCService(
	deviceService device.DeviceService,
	profileService device.DeviceProfileService,
	logger *slog.Logger,
) *DeviceGRPCService {
	if logger == nil {
		logger = slog.Default()
	}
	return &DeviceGRPCService{
		deviceService:  deviceService,
		profileService: profileService,
		logger:         logger,
	}
}

// CreateDevice creates a new device via the service layer.
func (s *DeviceGRPCService) CreateDevice(
	ctx context.Context,
	req *platformv1.CreateDeviceRequest,
) (*platformv1.CreateDeviceResponse, error) {
	if req.GetDevice() == nil {
		return nil, status.Error(codes.InvalidArgument, "device is required")
	}

	device := s.pbToDevice(req.GetDevice())

	if err := s.deviceService.Save(ctx, device); err != nil {
		s.logger.Error("failed to create device", "error", err)
		return nil, s.toGRPCError(err)
	}

	s.logger.Info("device created", "id", device.ID, "serial", device.Serial)

	return &platformv1.CreateDeviceResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "device created successfully",
		},
		Device: s.deviceToPb(device),
	}, nil
}

// GetDevice retrieves a device by ID via the service layer.
func (s *DeviceGRPCService) GetDevice(
	ctx context.Context,
	req *platformv1.GetDeviceRequest,
) (*platformv1.GetDeviceResponse, error) {
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "device id is required")
	}

	device, err := s.deviceService.Get(ctx, req.GetId())
	if err != nil {
		return nil, s.toGRPCError(err)
	}

	return &platformv1.GetDeviceResponse{
		Device: s.deviceToPb(device),
	}, nil
}

// UpdateDevice updates an existing device via the service layer.
func (s *DeviceGRPCService) UpdateDevice(
	ctx context.Context,
	req *platformv1.UpdateDeviceRequest,
) (*platformv1.UpdateDeviceResponse, error) {
	if req.GetDevice() == nil {
		return nil, status.Error(codes.InvalidArgument, "device is required")
	}

	device := s.pbToDevice(req.GetDevice())

	if err := s.deviceService.Update(ctx, device); err != nil {
		s.logger.Error("failed to update device", "id", device.ID, "error", err)
		return nil, s.toGRPCError(err)
	}

	s.logger.Info("device updated", "id", device.ID)

	return &platformv1.UpdateDeviceResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "device updated successfully",
		},
		Device: s.deviceToPb(device),
	}, nil
}

// DeleteDevice removes a device via the service layer.
func (s *DeviceGRPCService) DeleteDevice(
	ctx context.Context,
	req *platformv1.DeleteDeviceRequest,
) (*platformv1.DeleteDeviceResponse, error) {
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "device id is required")
	}

	device, err := s.deviceService.Get(ctx, req.GetId())
	if err != nil {
		return nil, s.toGRPCError(err)
	}

	if err := s.deviceService.Delete(ctx, device); err != nil {
		s.logger.Error("failed to delete device", "id", req.GetId(), "error", err)
		return nil, s.toGRPCError(err)
	}

	s.logger.Info("device deleted", "id", req.GetId())

	return &platformv1.DeleteDeviceResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "device deleted successfully",
		},
	}, nil
}

// ListDevices retrieves a paginated list of devices via the service layer.
func (s *DeviceGRPCService) ListDevices(
	ctx context.Context,
	req *platformv1.ListDevicesRequest,
) (*platformv1.ListDevicesResponse, error) {
	query := s.paginationToQuery(req.GetPagination())

	result, err := s.deviceService.Page(ctx, query)
	if err != nil {
		s.logger.Error("failed to list devices", "error", err)
		return nil, s.toGRPCError(err)
	}

	devices := make([]*platformv1.Device, 0, len(result.Entities))
	for _, d := range result.Entities {
		devices = append(devices, s.deviceToPb(d))
	}

	return &platformv1.ListDevicesResponse{
		Devices: devices,
		Pagination: &platformv1.PaginationResponse{
			Page:       uint32(result.Page),
			PageSize:   uint32(result.PageSize),
			TotalPages: uint32(s.calculateTotalPages(result.Total, result.PageSize)),
			TotalItems: uint64(result.Total),
		},
	}, nil
}

// FindDeviceBySerial finds a device by serial number via the service layer.
func (s *DeviceGRPCService) FindDeviceBySerial(
	ctx context.Context,
	req *platformv1.FindDeviceBySerialRequest,
) (*platformv1.FindDeviceBySerialResponse, error) {
	if req.GetSerial() == "" {
		return nil, status.Error(codes.InvalidArgument, "serial is required")
	}

	device, err := s.deviceService.FindBySerial(ctx, req.GetSerial())
	if err != nil {
		return nil, s.toGRPCError(err)
	}

	return &platformv1.FindDeviceBySerialResponse{
		Device: s.deviceToPb(device),
	}, nil
}

// CountDevices returns the total number of devices via the service layer.
func (s *DeviceGRPCService) CountDevices(
	ctx context.Context,
	req *platformv1.CountDevicesRequest,
) (*platformv1.CountDevicesResponse, error) {
	count, err := s.deviceService.Count(ctx)
	if err != nil {
		s.logger.Error("failed to count devices", "error", err)
		return nil, s.toGRPCError(err)
	}

	return &platformv1.CountDevicesResponse{
		Count: int32(count),
	}, nil
}

// CreateProfile creates a new device profile via the service layer.
func (s *DeviceGRPCService) CreateProfile(
	ctx context.Context,
	req *platformv1.CreateProfileRequest,
) (*platformv1.CreateProfileResponse, error) {
	if req.GetProfile() == nil {
		return nil, status.Error(codes.InvalidArgument, "profile is required")
	}

	profile := s.pbToProfile(req.GetProfile())

	// Generate an ID when the client did not supply one, matching the REST
	// CreateProfile handler so profile creation has parity across transports.
	// ProfileService.Save itself requires a non-zero ID because it doubles as
	// the update primitive.
	if profile.ID == 0 {
		profile.ID = device.NewID()
	}

	if err := s.profileService.Save(ctx, profile); err != nil {
		s.logger.Error("failed to create profile", "error", err)
		return nil, s.toGRPCError(err)
	}

	s.logger.Info("profile created", "id", profile.ID, "name", profile.Name)

	return &platformv1.CreateProfileResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "profile created successfully",
		},
		Profile: s.profileToPb(profile),
	}, nil
}

// GetProfile retrieves a device profile by ID via the service layer.
func (s *DeviceGRPCService) GetProfile(
	ctx context.Context,
	req *platformv1.GetProfileRequest,
) (*platformv1.GetProfileResponse, error) {
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "profile id is required")
	}

	profile, err := s.profileService.Get(ctx, req.GetId())
	if err != nil {
		return nil, s.toGRPCError(err)
	}

	return &platformv1.GetProfileResponse{
		Profile: s.profileToPb(profile),
	}, nil
}

// UpdateProfile updates an existing device profile via the service layer.
func (s *DeviceGRPCService) UpdateProfile(
	ctx context.Context,
	req *platformv1.UpdateProfileRequest,
) (*platformv1.UpdateProfileResponse, error) {
	if req.GetProfile() == nil {
		return nil, status.Error(codes.InvalidArgument, "profile is required")
	}

	profile := s.pbToProfile(req.GetProfile())

	if err := s.profileService.Update(ctx, profile); err != nil {
		s.logger.Error("failed to update profile", "id", profile.ID, "error", err)
		return nil, s.toGRPCError(err)
	}

	s.logger.Info("profile updated", "id", profile.ID)

	return &platformv1.UpdateProfileResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "profile updated successfully",
		},
		Profile: s.profileToPb(profile),
	}, nil
}

// DeleteProfile removes a device profile via the service layer.
func (s *DeviceGRPCService) DeleteProfile(
	ctx context.Context,
	req *platformv1.DeleteProfileRequest,
) (*platformv1.DeleteProfileResponse, error) {
	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "profile id is required")
	}

	profile, err := s.profileService.Get(ctx, req.GetId())
	if err != nil {
		return nil, s.toGRPCError(err)
	}

	if err := s.profileService.Delete(ctx, profile); err != nil {
		s.logger.Error("failed to delete profile", "id", req.GetId(), "error", err)
		return nil, s.toGRPCError(err)
	}

	s.logger.Info("profile deleted", "id", req.GetId())

	return &platformv1.DeleteProfileResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "profile deleted successfully",
		},
	}, nil
}

// ListProfiles retrieves a paginated list of device profiles via the service layer.
func (s *DeviceGRPCService) ListProfiles(
	ctx context.Context,
	req *platformv1.ListProfilesRequest,
) (*platformv1.ListProfilesResponse, error) {
	query := s.paginationToQuery(req.GetPagination())

	result, err := s.profileService.Page(ctx, query)
	if err != nil {
		s.logger.Error("failed to list profiles", "error", err)
		return nil, s.toGRPCError(err)
	}

	profiles := make([]*platformv1.DeviceProfile, 0, len(result.Entities))
	for _, p := range result.Entities {
		profiles = append(profiles, s.profileToPb(p))
	}

	return &platformv1.ListProfilesResponse{
		Profiles: profiles,
		Pagination: &platformv1.PaginationResponse{
			Page:       uint32(result.Page),
			PageSize:   uint32(result.PageSize),
			TotalPages: uint32(s.calculateTotalPages(result.Total, result.PageSize)),
			TotalItems: uint64(result.Total),
		},
	}, nil
}

// FindProfileByMACAddress finds a profile by MAC address via the service layer.
func (s *DeviceGRPCService) FindProfileByMACAddress(
	ctx context.Context,
	req *platformv1.FindProfileByMACAddressRequest,
) (*platformv1.FindProfileByMACAddressResponse, error) {
	if req.GetMacAddress() == "" {
		return nil, status.Error(codes.InvalidArgument, "mac_address is required")
	}

	profile, err := s.profileService.FindByMACAddress(ctx, req.GetMacAddress())
	if err != nil {
		return nil, s.toGRPCError(err)
	}

	return &platformv1.FindProfileByMACAddressResponse{
		Profile: s.profileToPb(profile),
	}, nil
}

// FindProfileBySerial finds a profile by serial number via the service layer.
func (s *DeviceGRPCService) FindProfileBySerial(
	ctx context.Context,
	req *platformv1.FindProfileBySerialRequest,
) (*platformv1.FindProfileBySerialResponse, error) {
	if req.GetSerial() == "" {
		return nil, status.Error(codes.InvalidArgument, "serial is required")
	}

	profile, err := s.profileService.FindBySerial(ctx, req.GetSerial())
	if err != nil {
		return nil, s.toGRPCError(err)
	}

	return &platformv1.FindProfileBySerialResponse{
		Profile: s.profileToPb(profile),
	}, nil
}

// FindMatchingProfile finds a profile matching device characteristics via the service layer.
func (s *DeviceGRPCService) FindMatchingProfile(
	ctx context.Context,
	req *platformv1.FindMatchingProfileRequest,
) (*platformv1.FindMatchingProfileResponse, error) {
	profile, err := s.profileService.FindMatchingProfile(
		ctx,
		req.GetMacAddress(),
		req.GetSerial(),
		req.GetModel(),
	)
	if err != nil {
		return nil, s.toGRPCError(err)
	}

	return &platformv1.FindMatchingProfileResponse{
		Profile: s.profileToPb(profile),
	}, nil
}

// CountProfiles returns the total number of device profiles via the service layer.
func (s *DeviceGRPCService) CountProfiles(
	ctx context.Context,
	req *platformv1.CountProfilesRequest,
) (*platformv1.CountProfilesResponse, error) {
	count, err := s.profileService.Count(ctx)
	if err != nil {
		s.logger.Error("failed to count profiles", "error", err)
		return nil, s.toGRPCError(err)
	}

	return &platformv1.CountProfilesResponse{
		Count: int32(count),
	}, nil
}

// ActivateDevice activates a device and transitions it to production network.
func (s *DeviceGRPCService) ActivateDevice(
	ctx context.Context,
	req *platformv1.ActivateDeviceRequest,
) (*platformv1.ActivateDeviceResponse, error) {
	if req.GetSerial() == "" {
		return nil, status.Error(codes.InvalidArgument, "serial is required")
	}

	// Find the device
	device, err := s.deviceService.FindBySerial(ctx, req.GetSerial())
	if err != nil {
		return nil, s.toGRPCError(err)
	}

	// Find matching profile
	profile, err := s.profileService.FindMatchingProfile(
		ctx,
		req.GetMacAddress(),
		req.GetSerial(),
		device.Model,
	)
	if err != nil {
		return nil, s.toGRPCError(err)
	}

	// Get production VLAN from profile
	var vlan uint32
	if prodNet := profile.GetPostEnrollmentNetworkConfig(); prodNet != nil {
		vlan = uint32(prodNet.VLAN)
	}

	s.logger.Info("device activated",
		"serial", req.GetSerial(),
		"vlan", vlan,
	)

	return &platformv1.ActivateDeviceResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "device activated successfully",
		},
		ActivationStatus: "activated",
		Vlan:             vlan,
		TransitionedAt:   timestamppb.New(time.Now().UTC()),
	}, nil
}

// Conversion helpers

func (s *DeviceGRPCService) pbToDevice(pb *platformv1.Device) *entities.Device {
	if pb == nil {
		return nil
	}
	return &entities.Device{
		ID:            pb.GetId(),
		AttestPub:     pb.GetAttestPub(),
		EKCert:        pb.GetEkCert(),
		EventLog:      pb.GetEventLog(),
		HashAlgoId:    pb.GetHashAlgoId(),
		Model:         pb.GetModel(),
		Serial:        pb.GetSerial(),
		SigningPub:    pb.GetSigningPub(),
		NetworkPortID: pb.GetNetworkPortId(),
	}
}

func (s *DeviceGRPCService) deviceToPb(d *entities.Device) *platformv1.Device {
	if d == nil {
		return nil
	}
	return &platformv1.Device{
		Id:            d.ID,
		AttestPub:     d.AttestPub,
		EkCert:        d.EKCert,
		EventLog:      d.EventLog,
		HashAlgoId:    d.HashAlgoId,
		Model:         d.Model,
		Serial:        d.Serial,
		SigningPub:    d.SigningPub,
		NetworkPortId: d.NetworkPortID,
	}
}

func (s *DeviceGRPCService) pbToProfile(pb *platformv1.DeviceProfile) *entities.DeviceProfile {
	if pb == nil {
		return nil
	}
	profile := &entities.DeviceProfile{
		ID:                    pb.GetId(),
		TenantID:              pb.GetTenantId(),
		Name:                  pb.GetName(),
		Model:                 pb.GetModel(),
		Role:                  s.pbToDeviceRole(pb.GetRole()),
		EventLog:              pb.GetEventLog(),
		Zone:                  pb.GetZone(),
		EnrollmentNetwork:     pb.GetEnrollmentNetwork(),
		PostEnrollmentNetwork: pb.GetPostEnrollmentNetwork(),
		FailureNetwork:        pb.GetFailureNetwork(),
	}

	if pbNets := pb.GetNetworks(); len(pbNets) > 0 {
		profile.Networks = make(map[string]*entities.NetworkPhaseConfig, len(pbNets))
		for k, v := range pbNets {
			profile.Networks[k] = s.pbToNetworkPhaseConfig(v)
		}
	} else {
		profile.Networks = make(map[string]*entities.NetworkPhaseConfig)
	}
	if pb.GetPlatformdConfig() != nil {
		profile.PlatformdConfig = s.pbToPlatformdConfigRef(pb.GetPlatformdConfig())
	}
	if pb.GetMatchRules() != nil {
		profile.MatchRules = s.pbToProfileMatchRules(pb.GetMatchRules())
	}
	if pb.GetBmc() != nil {
		profile.BMC = s.pbToBMCConfig(pb.GetBmc())
	}

	return profile
}

// pbToBMCConfig maps a protobuf BMCConfig into the entity BMCConfig.
func (s *DeviceGRPCService) pbToBMCConfig(pb *platformv1.BMCConfig) *entities.BMCConfig {
	if pb == nil {
		return nil
	}
	return &entities.BMCConfig{
		Address:  pb.GetAddress(),
		Port:     int(pb.GetPort()),
		Username: pb.GetUsername(),
		Password: pb.GetPassword(),
		Protocol: entities.BMCProtocol(pb.GetProtocol()),
	}
}

// bmcConfigToPb maps an entity BMCConfig into its protobuf representation.
func (s *DeviceGRPCService) bmcConfigToPb(b *entities.BMCConfig) *platformv1.BMCConfig {
	if b == nil {
		return nil
	}
	return &platformv1.BMCConfig{
		Address:  b.Address,
		Port:     int32(b.Port),
		Username: b.Username,
		Password: b.Password,
		Protocol: string(b.Protocol),
	}
}

func (s *DeviceGRPCService) profileToPb(p *entities.DeviceProfile) *platformv1.DeviceProfile {
	if p == nil {
		return nil
	}
	profile := &platformv1.DeviceProfile{
		Id:                    p.ID,
		TenantId:              p.TenantID,
		Name:                  p.Name,
		Model:                 p.Model,
		Role:                  s.deviceRoleToPb(p.Role),
		EventLog:              p.EventLog,
		Zone:                  p.Zone,
		EnrollmentNetwork:     p.EnrollmentNetwork,
		PostEnrollmentNetwork: p.PostEnrollmentNetwork,
		FailureNetwork:        p.FailureNetwork,
	}

	if len(p.Networks) > 0 {
		profile.Networks = make(map[string]*platformv1.NetworkPhaseConfig, len(p.Networks))
		for k, v := range p.Networks {
			profile.Networks[k] = s.networkPhaseConfigToPb(v)
		}
	}
	if p.PlatformdConfig != nil {
		profile.PlatformdConfig = s.platformdConfigRefToPb(p.PlatformdConfig)
	}
	if p.MatchRules != nil {
		profile.MatchRules = s.profileMatchRulesToPb(p.MatchRules)
	}
	if p.BMC != nil {
		profile.Bmc = s.bmcConfigToPb(p.BMC)
	}

	return profile
}

func (s *DeviceGRPCService) pbToDeviceRole(role platformv1.DeviceRole) entities.DeviceRole {
	switch role {
	case platformv1.DeviceRole_DEVICE_ROLE_SERVER:
		return entities.DeviceRoleServer
	case platformv1.DeviceRole_DEVICE_ROLE_CLIENT:
		return entities.DeviceRoleClient
	case platformv1.DeviceRole_DEVICE_ROLE_WORKSTATION:
		return entities.DeviceRoleWorkstation
	case platformv1.DeviceRole_DEVICE_ROLE_EDGE:
		return entities.DeviceRoleEdge
	case platformv1.DeviceRole_DEVICE_ROLE_IOT:
		return entities.DeviceRoleIoT
	case platformv1.DeviceRole_DEVICE_ROLE_GATEWAY:
		return entities.DeviceRoleGateway
	case platformv1.DeviceRole_DEVICE_ROLE_LOAD_BALANCER:
		return entities.DeviceRoleLoadBalancer
	default:
		return entities.DeviceRoleUnknown
	}
}

func (s *DeviceGRPCService) deviceRoleToPb(role entities.DeviceRole) platformv1.DeviceRole {
	switch role {
	case entities.DeviceRoleServer:
		return platformv1.DeviceRole_DEVICE_ROLE_SERVER
	case entities.DeviceRoleClient:
		return platformv1.DeviceRole_DEVICE_ROLE_CLIENT
	case entities.DeviceRoleWorkstation:
		return platformv1.DeviceRole_DEVICE_ROLE_WORKSTATION
	case entities.DeviceRoleEdge:
		return platformv1.DeviceRole_DEVICE_ROLE_EDGE
	case entities.DeviceRoleIoT:
		return platformv1.DeviceRole_DEVICE_ROLE_IOT
	case entities.DeviceRoleGateway:
		return platformv1.DeviceRole_DEVICE_ROLE_GATEWAY
	case entities.DeviceRoleLoadBalancer:
		return platformv1.DeviceRole_DEVICE_ROLE_LOAD_BALANCER
	default:
		return platformv1.DeviceRole_DEVICE_ROLE_UNKNOWN
	}
}

func (s *DeviceGRPCService) pbToNetworkPhaseConfig(pb *platformv1.NetworkPhaseConfig) *entities.NetworkPhaseConfig {
	if pb == nil {
		return nil
	}
	config := &entities.NetworkPhaseConfig{
		VLAN:       uint16(pb.GetVlan()),
		StaticIP:   pb.GetStaticIp(),
		Gateway:    pb.GetGateway(),
		DNS:        pb.GetDns(),
		AuthMethod: s.pbToAuthMethod(pb.GetAuthMethod()),
		Subnet:     pb.GetSubnet(),
		DNSServers: pb.GetDnsServers(),
		DHCP:       pb.GetDhcp(),
		Zone:       pb.GetZone(),
	}

	if pb.GetDhcpPool() != nil {
		config.DHCPPool = &entities.DHCPPoolConfig{
			Network:    pb.GetDhcpPool().GetNetwork(),
			RangeStart: pb.GetDhcpPool().GetRangeStart(),
			RangeEnd:   pb.GetDhcpPool().GetRangeEnd(),
			LeaseTime:  int(pb.GetDhcpPool().GetLeaseTime()),
		}
	}

	for _, acl := range pb.GetAcls() {
		config.ACLs = append(config.ACLs, entities.ACLConfig{
			Priority: int(acl.GetPriority()),
			Protocol: acl.GetProtocol(),
			SrcIP:    acl.GetSrcIp(),
			DstIP:    acl.GetDstIp(),
			SrcPort:  uint16(acl.GetSrcPort()),
			DstPort:  uint16(acl.GetDstPort()),
			Action:   acl.GetAction(),
		})
	}

	return config
}

func (s *DeviceGRPCService) networkPhaseConfigToPb(c *entities.NetworkPhaseConfig) *platformv1.NetworkPhaseConfig {
	if c == nil {
		return nil
	}
	config := &platformv1.NetworkPhaseConfig{
		Vlan:       uint32(c.VLAN),
		StaticIp:   c.StaticIP,
		Gateway:    c.Gateway,
		Dns:        c.DNS,
		AuthMethod: s.authMethodToPb(c.AuthMethod),
		Subnet:     c.Subnet,
		DnsServers: c.DNSServers,
		Dhcp:       c.DHCP,
		Zone:       c.Zone,
	}

	if c.DHCPPool != nil {
		config.DhcpPool = &platformv1.DHCPPoolConfig{
			Network:    c.DHCPPool.Network,
			RangeStart: c.DHCPPool.RangeStart,
			RangeEnd:   c.DHCPPool.RangeEnd,
			LeaseTime:  int32(c.DHCPPool.LeaseTime),
		}
	}

	for _, acl := range c.ACLs {
		config.Acls = append(config.Acls, &platformv1.ACLConfig{
			Priority: int32(acl.Priority),
			Protocol: acl.Protocol,
			SrcIp:    acl.SrcIP,
			DstIp:    acl.DstIP,
			SrcPort:  uint32(acl.SrcPort),
			DstPort:  uint32(acl.DstPort),
			Action:   acl.Action,
		})
	}

	return config
}

func (s *DeviceGRPCService) pbToAuthMethod(method platformv1.AuthMethod) entities.AuthMethod {
	switch method {
	case platformv1.AuthMethod_AUTH_METHOD_802_1X:
		return entities.AuthMethod802_1X
	default:
		return entities.AuthMethodNone
	}
}

func (s *DeviceGRPCService) authMethodToPb(method entities.AuthMethod) platformv1.AuthMethod {
	switch method {
	case entities.AuthMethod802_1X:
		return platformv1.AuthMethod_AUTH_METHOD_802_1X
	default:
		return platformv1.AuthMethod_AUTH_METHOD_NONE
	}
}

func (s *DeviceGRPCService) pbToPlatformdConfigRef(pb *platformv1.PlatformdConfigRef) *entities.PlatformdConfigRef {
	if pb == nil {
		return nil
	}
	return &entities.PlatformdConfigRef{
		ConfigType: pb.GetConfigType(),
		Reference:  pb.GetReference(),
		ConfigName: pb.GetConfigName(),
		ConfigPath: pb.GetConfigPath(),
		Version:    pb.GetVersion(),
	}
}

func (s *DeviceGRPCService) platformdConfigRefToPb(c *entities.PlatformdConfigRef) *platformv1.PlatformdConfigRef {
	if c == nil {
		return nil
	}
	return &platformv1.PlatformdConfigRef{
		ConfigType: c.ConfigType,
		Reference:  c.Reference,
		ConfigName: c.ConfigName,
		ConfigPath: c.ConfigPath,
		Version:    c.Version,
	}
}

func (s *DeviceGRPCService) pbToProfileMatchRules(pb *platformv1.ProfileMatchRules) *entities.ProfileMatchRules {
	if pb == nil {
		return nil
	}
	return &entities.ProfileMatchRules{
		MACPrefix:         pb.GetMacPrefix(),
		SerialPrefix:      pb.GetSerialPrefix(),
		Model:             pb.GetModel(),
		ModelPattern:      pb.GetModelPattern(),
		SerialPattern:     pb.GetSerialPattern(),
		ManufacturerMatch: pb.GetManufacturerMatch(),
		TPMVendor:         pb.GetTpmVendor(),
		CustomAttributes:  pb.GetCustomAttributes(),
	}
}

func (s *DeviceGRPCService) profileMatchRulesToPb(r *entities.ProfileMatchRules) *platformv1.ProfileMatchRules {
	if r == nil {
		return nil
	}
	return &platformv1.ProfileMatchRules{
		MacPrefix:         r.MACPrefix,
		SerialPrefix:      r.SerialPrefix,
		Model:             r.Model,
		ModelPattern:      r.ModelPattern,
		SerialPattern:     r.SerialPattern,
		ManufacturerMatch: r.ManufacturerMatch,
		TpmVendor:         r.TPMVendor,
		CustomAttributes:  r.CustomAttributes,
	}
}

func (s *DeviceGRPCService) paginationToQuery(pagination *platformv1.PaginationRequest) datastore.PageQuery {
	query := datastore.NewPageQuery()

	if pagination != nil {
		if pagination.GetPage() > 0 {
			query.Page = int(pagination.GetPage())
		}
		if pagination.GetPageSize() > 0 {
			query.PageSize = int(pagination.GetPageSize())
		}
		if pagination.GetAscending() {
			query.SortOrder = datastore.SortAscending
		} else {
			query.SortOrder = datastore.SortDescending
		}
	}

	return query
}

func (s *DeviceGRPCService) calculateTotalPages(total, pageSize int) int {
	if pageSize <= 0 {
		return 0
	}
	pages := total / pageSize
	if total%pageSize > 0 {
		pages++
	}
	return pages
}

func (s *DeviceGRPCService) toGRPCError(err error) error {
	if err == nil {
		return nil
	}

	errStr := err.Error()

	// Check for common error patterns
	switch {
	case errStr == "invalid device ID" || errStr == "invalid profile ID":
		return status.Error(codes.InvalidArgument, errStr)
	case containsNotFound(errStr):
		return status.Error(codes.NotFound, errStr)
	case containsAlreadyExists(errStr):
		return status.Error(codes.AlreadyExists, errStr)
	default:
		return status.Error(codes.Internal, errStr)
	}
}

func containsNotFound(s string) bool {
	return contains(s, "not found") || contains(s, "failed to get")
}

func containsAlreadyExists(s string) bool {
	return contains(s, "already exists")
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || containsSubstring(s, substr))
}

func containsSubstring(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
