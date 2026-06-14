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

package grpc

import (
	"context"
	"fmt"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Device gRPC service error types.

// ErrNilDeviceService is returned when the device service is nil.
type ErrNilDeviceService struct{}

func (e ErrNilDeviceService) Error() string {
	return "device service is nil"
}

// ErrNilProfileService is returned when the profile service is nil.
type ErrNilProfileService struct{}

func (e ErrNilProfileService) Error() string {
	return "profile service is nil"
}

// ErrMissingDeviceID is returned when a device ID is required but not provided.
type ErrMissingDeviceID struct{}

func (e ErrMissingDeviceID) Error() string {
	return "device ID is required"
}

// ErrMissingProfileID is returned when a profile ID is required but not provided.
type ErrMissingProfileID struct{}

func (e ErrMissingProfileID) Error() string {
	return "profile ID is required"
}

// ErrMissingDevice is returned when device data is required but not provided.
type ErrMissingDevice struct{}

func (e ErrMissingDevice) Error() string {
	return "device data is required"
}

// ErrMissingProfile is returned when profile data is required but not provided.
type ErrMissingProfile struct{}

func (e ErrMissingProfile) Error() string {
	return "profile data is required"
}

// ErrMissingDeviceSerial is returned when device serial number is required but not provided.
type ErrMissingDeviceSerial struct{}

func (e ErrMissingDeviceSerial) Error() string {
	return "device serial number is required"
}

// ErrMissingDeviceMACAddress is returned when MAC address is required but not provided.
type ErrMissingDeviceMACAddress struct{}

func (e ErrMissingDeviceMACAddress) Error() string {
	return "MAC address is required"
}

// ErrDeviceOperationFailed is returned when a device operation fails.
type ErrDeviceOperationFailed struct {
	Operation string
	Reason    string
}

func (e ErrDeviceOperationFailed) Error() string {
	return fmt.Sprintf("device operation %s failed: %s", e.Operation, e.Reason)
}

// ErrProfileOperationFailed is returned when a profile operation fails.
type ErrProfileOperationFailed struct {
	Operation string
	Reason    string
}

func (e ErrProfileOperationFailed) Error() string {
	return fmt.Sprintf("profile operation %s failed: %s", e.Operation, e.Reason)
}

// ErrDeviceNotFound is returned when a device is not found.
type ErrDeviceNotFound struct {
	ID uint64
}

func (e ErrDeviceNotFound) Error() string {
	return fmt.Sprintf("device not found: %d", e.ID)
}

// ErrProfileNotFound is returned when a profile is not found.
type ErrProfileNotFound struct {
	ID uint64
}

func (e ErrProfileNotFound) Error() string {
	return fmt.Sprintf("profile not found: %d", e.ID)
}

// DeviceService defines the interface for device operations.
type DeviceService interface {
	Save(ctx context.Context, device *entities.Device) error
	Get(ctx context.Context, id uint64) (*entities.Device, error)
	Update(ctx context.Context, device *entities.Device) error
	Delete(ctx context.Context, device *entities.Device) error
	Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*entities.Device], error)
	FindBySerial(ctx context.Context, serial string) (*entities.Device, error)
	Count(ctx context.Context) (int, error)
}

// DeviceProfileService defines the interface for device profile operations.
type DeviceProfileService interface {
	Save(ctx context.Context, profile *entities.DeviceProfile) error
	Get(ctx context.Context, id uint64) (*entities.DeviceProfile, error)
	Update(ctx context.Context, profile *entities.DeviceProfile) error
	Delete(ctx context.Context, profile *entities.DeviceProfile) error
	Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*entities.DeviceProfile], error)
	FindByMACAddress(ctx context.Context, mac string) (*entities.DeviceProfile, error)
	FindBySerial(ctx context.Context, serial string) (*entities.DeviceProfile, error)
	FindMatchingProfile(ctx context.Context, mac, serial, model string) (*entities.DeviceProfile, error)
	Count(ctx context.Context) (int, error)
}

// DeviceGRPCService implements the gRPC DeviceService server interface.
// It wraps the DeviceService and DeviceProfileService interfaces to provide
// gRPC access to device and profile management operations.
type DeviceGRPCService struct {
	platformv1.UnimplementedDeviceServiceServer
	logger         *logging.Logger
	deviceService  DeviceService
	profileService DeviceProfileService
}

// NewDeviceGRPCService creates a new DeviceGRPCService instance.
func NewDeviceGRPCService(
	logger *logging.Logger,
	deviceService DeviceService,
	profileService DeviceProfileService,
) *DeviceGRPCService {
	return &DeviceGRPCService{
		logger:         logger,
		deviceService:  deviceService,
		profileService: profileService,
	}
}

// CreateDevice creates a new device.
func (s *DeviceGRPCService) CreateDevice(
	ctx context.Context,
	req *platformv1.CreateDeviceRequest,
) (*platformv1.CreateDeviceResponse, error) {

	if s.deviceService == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilDeviceService{}.Error())
	}

	if req.GetDevice() == nil {
		return nil, status.Error(codes.InvalidArgument, ErrMissingDevice{}.Error())
	}

	device := protoDeviceToEntity(req.GetDevice())

	if err := s.deviceService.Save(ctx, device); err != nil {
		return nil, s.mapDeviceError("CreateDevice", err)
	}

	return &platformv1.CreateDeviceResponse{
		Status: successStatus("device created successfully"),
		Device: entityDeviceToProto(device),
	}, nil
}

// GetDevice retrieves a device by ID.
func (s *DeviceGRPCService) GetDevice(
	ctx context.Context,
	req *platformv1.GetDeviceRequest,
) (*platformv1.GetDeviceResponse, error) {

	if s.deviceService == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilDeviceService{}.Error())
	}

	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrMissingDeviceID{}.Error())
	}

	device, err := s.deviceService.Get(ctx, req.GetId())
	if err != nil {
		return nil, s.mapDeviceError("GetDevice", err)
	}

	return &platformv1.GetDeviceResponse{
		Device: entityDeviceToProto(device),
	}, nil
}

// UpdateDevice updates an existing device.
func (s *DeviceGRPCService) UpdateDevice(
	ctx context.Context,
	req *platformv1.UpdateDeviceRequest,
) (*platformv1.UpdateDeviceResponse, error) {

	if s.deviceService == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilDeviceService{}.Error())
	}

	if req.GetDevice() == nil {
		return nil, status.Error(codes.InvalidArgument, ErrMissingDevice{}.Error())
	}

	if req.GetDevice().GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrMissingDeviceID{}.Error())
	}

	device := protoDeviceToEntity(req.GetDevice())

	if err := s.deviceService.Update(ctx, device); err != nil {
		return nil, s.mapDeviceError("UpdateDevice", err)
	}

	return &platformv1.UpdateDeviceResponse{
		Status: successStatus("device updated successfully"),
		Device: entityDeviceToProto(device),
	}, nil
}

// DeleteDevice deletes a device by ID.
func (s *DeviceGRPCService) DeleteDevice(
	ctx context.Context,
	req *platformv1.DeleteDeviceRequest,
) (*platformv1.DeleteDeviceResponse, error) {

	if s.deviceService == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilDeviceService{}.Error())
	}

	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrMissingDeviceID{}.Error())
	}

	// Retrieve device first to pass to delete
	device, err := s.deviceService.Get(ctx, req.GetId())
	if err != nil {
		return nil, s.mapDeviceError("DeleteDevice", err)
	}

	if err := s.deviceService.Delete(ctx, device); err != nil {
		return nil, s.mapDeviceError("DeleteDevice", err)
	}

	return &platformv1.DeleteDeviceResponse{
		Status: successStatus("device deleted successfully"),
	}, nil
}

// ListDevices returns a paginated list of devices.
func (s *DeviceGRPCService) ListDevices(
	ctx context.Context,
	req *platformv1.ListDevicesRequest,
) (*platformv1.ListDevicesResponse, error) {

	if s.deviceService == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilDeviceService{}.Error())
	}

	query := protoDevicePaginationToQuery(req.GetPagination())

	result, err := s.deviceService.Page(ctx, query)
	if err != nil {
		return nil, s.mapDeviceError("ListDevices", err)
	}

	devices := make([]*platformv1.Device, 0, len(result.Entities))
	for _, d := range result.Entities {
		devices = append(devices, entityDeviceToProto(d))
	}

	return &platformv1.ListDevicesResponse{
		Devices:    devices,
		Pagination: queryResultToDevicePagination(result),
	}, nil
}

// FindDeviceBySerial finds a device by its serial number.
func (s *DeviceGRPCService) FindDeviceBySerial(
	ctx context.Context,
	req *platformv1.FindDeviceBySerialRequest,
) (*platformv1.FindDeviceBySerialResponse, error) {

	if s.deviceService == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilDeviceService{}.Error())
	}

	if req.GetSerial() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingDeviceSerial{}.Error())
	}

	device, err := s.deviceService.FindBySerial(ctx, req.GetSerial())
	if err != nil {
		return nil, s.mapDeviceError("FindDeviceBySerial", err)
	}

	return &platformv1.FindDeviceBySerialResponse{
		Device: entityDeviceToProto(device),
	}, nil
}

// CountDevices returns the total number of devices.
func (s *DeviceGRPCService) CountDevices(
	ctx context.Context,
	req *platformv1.CountDevicesRequest,
) (*platformv1.CountDevicesResponse, error) {

	if s.deviceService == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilDeviceService{}.Error())
	}

	count, err := s.deviceService.Count(ctx)
	if err != nil {
		return nil, s.mapDeviceError("CountDevices", err)
	}

	return &platformv1.CountDevicesResponse{
		Count: int32(count),
	}, nil
}

// CreateProfile creates a new device profile.
func (s *DeviceGRPCService) CreateProfile(
	ctx context.Context,
	req *platformv1.CreateProfileRequest,
) (*platformv1.CreateProfileResponse, error) {

	if s.profileService == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilProfileService{}.Error())
	}

	if req.GetProfile() == nil {
		return nil, status.Error(codes.InvalidArgument, ErrMissingProfile{}.Error())
	}

	profile := protoProfileToEntity(req.GetProfile())

	if err := s.profileService.Save(ctx, profile); err != nil {
		return nil, s.mapProfileError("CreateProfile", err)
	}

	return &platformv1.CreateProfileResponse{
		Status:  successStatus("profile created successfully"),
		Profile: entityProfileToProto(profile),
	}, nil
}

// GetProfile retrieves a device profile by ID.
func (s *DeviceGRPCService) GetProfile(
	ctx context.Context,
	req *platformv1.GetProfileRequest,
) (*platformv1.GetProfileResponse, error) {

	if s.profileService == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilProfileService{}.Error())
	}

	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrMissingProfileID{}.Error())
	}

	profile, err := s.profileService.Get(ctx, req.GetId())
	if err != nil {
		return nil, s.mapProfileError("GetProfile", err)
	}

	return &platformv1.GetProfileResponse{
		Profile: entityProfileToProto(profile),
	}, nil
}

// UpdateProfile updates an existing device profile.
func (s *DeviceGRPCService) UpdateProfile(
	ctx context.Context,
	req *platformv1.UpdateProfileRequest,
) (*platformv1.UpdateProfileResponse, error) {

	if s.profileService == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilProfileService{}.Error())
	}

	if req.GetProfile() == nil {
		return nil, status.Error(codes.InvalidArgument, ErrMissingProfile{}.Error())
	}

	if req.GetProfile().GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrMissingProfileID{}.Error())
	}

	profile := protoProfileToEntity(req.GetProfile())

	if err := s.profileService.Update(ctx, profile); err != nil {
		return nil, s.mapProfileError("UpdateProfile", err)
	}

	return &platformv1.UpdateProfileResponse{
		Status:  successStatus("profile updated successfully"),
		Profile: entityProfileToProto(profile),
	}, nil
}

// DeleteProfile deletes a device profile by ID.
func (s *DeviceGRPCService) DeleteProfile(
	ctx context.Context,
	req *platformv1.DeleteProfileRequest,
) (*platformv1.DeleteProfileResponse, error) {

	if s.profileService == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilProfileService{}.Error())
	}

	if req.GetId() == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrMissingProfileID{}.Error())
	}

	// Retrieve profile first to pass to delete
	profile, err := s.profileService.Get(ctx, req.GetId())
	if err != nil {
		return nil, s.mapProfileError("DeleteProfile", err)
	}

	if err := s.profileService.Delete(ctx, profile); err != nil {
		return nil, s.mapProfileError("DeleteProfile", err)
	}

	return &platformv1.DeleteProfileResponse{
		Status: successStatus("profile deleted successfully"),
	}, nil
}

// ListProfiles returns a paginated list of device profiles.
func (s *DeviceGRPCService) ListProfiles(
	ctx context.Context,
	req *platformv1.ListProfilesRequest,
) (*platformv1.ListProfilesResponse, error) {

	if s.profileService == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilProfileService{}.Error())
	}

	query := protoDevicePaginationToQuery(req.GetPagination())

	result, err := s.profileService.Page(ctx, query)
	if err != nil {
		return nil, s.mapProfileError("ListProfiles", err)
	}

	profiles := make([]*platformv1.DeviceProfile, 0, len(result.Entities))
	for _, p := range result.Entities {
		profiles = append(profiles, entityProfileToProto(p))
	}

	return &platformv1.ListProfilesResponse{
		Profiles:   profiles,
		Pagination: queryResultToProfilePagination(result),
	}, nil
}

// FindProfileByMACAddress finds a profile by MAC address.
func (s *DeviceGRPCService) FindProfileByMACAddress(
	ctx context.Context,
	req *platformv1.FindProfileByMACAddressRequest,
) (*platformv1.FindProfileByMACAddressResponse, error) {

	if s.profileService == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilProfileService{}.Error())
	}

	if req.GetMacAddress() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingDeviceMACAddress{}.Error())
	}

	profile, err := s.profileService.FindByMACAddress(ctx, req.GetMacAddress())
	if err != nil {
		return nil, s.mapProfileError("FindProfileByMACAddress", err)
	}

	return &platformv1.FindProfileByMACAddressResponse{
		Profile: entityProfileToProto(profile),
	}, nil
}

// FindProfileBySerial finds a profile by serial number.
func (s *DeviceGRPCService) FindProfileBySerial(
	ctx context.Context,
	req *platformv1.FindProfileBySerialRequest,
) (*platformv1.FindProfileBySerialResponse, error) {

	if s.profileService == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilProfileService{}.Error())
	}

	if req.GetSerial() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingDeviceSerial{}.Error())
	}

	profile, err := s.profileService.FindBySerial(ctx, req.GetSerial())
	if err != nil {
		return nil, s.mapProfileError("FindProfileBySerial", err)
	}

	return &platformv1.FindProfileBySerialResponse{
		Profile: entityProfileToProto(profile),
	}, nil
}

// FindMatchingProfile finds a profile that matches device characteristics.
func (s *DeviceGRPCService) FindMatchingProfile(
	ctx context.Context,
	req *platformv1.FindMatchingProfileRequest,
) (*platformv1.FindMatchingProfileResponse, error) {

	if s.profileService == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilProfileService{}.Error())
	}

	profile, err := s.profileService.FindMatchingProfile(
		ctx,
		req.GetMacAddress(),
		req.GetSerial(),
		req.GetModel(),
	)
	if err != nil {
		return nil, s.mapProfileError("FindMatchingProfile", err)
	}

	return &platformv1.FindMatchingProfileResponse{
		Profile: entityProfileToProto(profile),
	}, nil
}

// CountProfiles returns the total number of device profiles.
func (s *DeviceGRPCService) CountProfiles(
	ctx context.Context,
	req *platformv1.CountProfilesRequest,
) (*platformv1.CountProfilesResponse, error) {

	if s.profileService == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilProfileService{}.Error())
	}

	count, err := s.profileService.Count(ctx)
	if err != nil {
		return nil, s.mapProfileError("CountProfiles", err)
	}

	return &platformv1.CountProfilesResponse{
		Count: int32(count),
	}, nil
}

// ActivateDevice activates a device and returns network transition information.
func (s *DeviceGRPCService) ActivateDevice(
	ctx context.Context,
	req *platformv1.ActivateDeviceRequest,
) (*platformv1.ActivateDeviceResponse, error) {

	if s.deviceService == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilDeviceService{}.Error())
	}

	if s.profileService == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrNilProfileService{}.Error())
	}

	if req.GetSerial() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingDeviceSerial{}.Error())
	}

	// Find the device by serial
	device, err := s.deviceService.FindBySerial(ctx, req.GetSerial())
	if err != nil {
		return nil, s.mapDeviceError("ActivateDevice", err)
	}

	// Find matching profile for network configuration
	profile, err := s.profileService.FindMatchingProfile(
		ctx,
		req.GetMacAddress(),
		req.GetSerial(),
		device.Model,
	)
	if err != nil {
		return nil, s.mapProfileError("ActivateDevice", err)
	}

	// Get the production VLAN from the profile
	var vlan uint32
	if postEnroll := profile.GetPostEnrollmentNetworkConfig(); postEnroll != nil {
		vlan = uint32(postEnroll.VLAN)
	}

	return &platformv1.ActivateDeviceResponse{
		Status:           successStatus("device activated successfully"),
		ActivationStatus: "activated",
		Vlan:             vlan,
		TransitionedAt:   timestamppb.New(time.Now().UTC()),
	}, nil
}

// Helper functions for conversion between proto and entity types.

func protoDeviceToEntity(d *platformv1.Device) *entities.Device {
	if d == nil {
		return nil
	}
	return &entities.Device{
		ID:            d.GetId(),
		AttestPub:     d.GetAttestPub(),
		EKCert:        d.GetEkCert(),
		EventLog:      d.GetEventLog(),
		HashAlgoId:    d.GetHashAlgoId(),
		Model:         d.GetModel(),
		Serial:        d.GetSerial(),
		SigningPub:    d.GetSigningPub(),
		NetworkPortID: d.GetNetworkPortId(),
	}
}

func entityDeviceToProto(d *entities.Device) *platformv1.Device {
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

func protoProfileToEntity(p *platformv1.DeviceProfile) *entities.DeviceProfile {
	if p == nil {
		return nil
	}
	profile := &entities.DeviceProfile{
		ID:                    p.GetId(),
		TenantID:              p.GetTenantId(),
		Name:                  p.GetName(),
		Model:                 p.GetModel(),
		Role:                  protoRoleToEntity(p.GetRole()),
		EventLog:              p.GetEventLog(),
		Zone:                  p.GetZone(),
		EnrollmentNetwork:     p.GetEnrollmentNetwork(),
		PostEnrollmentNetwork: p.GetPostEnrollmentNetwork(),
		FailureNetwork:        p.GetFailureNetwork(),
	}

	if pbNets := p.GetNetworks(); len(pbNets) > 0 {
		profile.Networks = make(map[string]*entities.NetworkPhaseConfig, len(pbNets))
		for k, v := range pbNets {
			profile.Networks[k] = protoNetworkConfigToEntity(v)
		}
	} else {
		profile.Networks = make(map[string]*entities.NetworkPhaseConfig)
	}
	if p.GetPlatformdConfig() != nil {
		profile.PlatformdConfig = protoPlatformdConfigToEntity(p.GetPlatformdConfig())
	}
	if p.GetMatchRules() != nil {
		profile.MatchRules = protoMatchRulesToEntity(p.GetMatchRules())
	}

	return profile
}

func entityProfileToProto(p *entities.DeviceProfile) *platformv1.DeviceProfile {
	if p == nil {
		return nil
	}
	profile := &platformv1.DeviceProfile{
		Id:                    p.ID,
		TenantId:              p.TenantID,
		Name:                  p.Name,
		Model:                 p.Model,
		Role:                  entityRoleToProto(p.Role),
		EventLog:              p.EventLog,
		Zone:                  p.Zone,
		EnrollmentNetwork:     p.EnrollmentNetwork,
		PostEnrollmentNetwork: p.PostEnrollmentNetwork,
		FailureNetwork:        p.FailureNetwork,
	}

	if len(p.Networks) > 0 {
		profile.Networks = make(map[string]*platformv1.NetworkPhaseConfig, len(p.Networks))
		for k, v := range p.Networks {
			profile.Networks[k] = entityNetworkConfigToProto(v)
		}
	}
	if p.PlatformdConfig != nil {
		profile.PlatformdConfig = entityPlatformdConfigToProto(p.PlatformdConfig)
	}
	if p.MatchRules != nil {
		profile.MatchRules = entityMatchRulesToProto(p.MatchRules)
	}

	return profile
}

func protoRoleToEntity(r platformv1.DeviceRole) entities.DeviceRole {
	switch r {
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

func entityRoleToProto(r entities.DeviceRole) platformv1.DeviceRole {
	switch r {
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

func protoNetworkConfigToEntity(n *platformv1.NetworkPhaseConfig) *entities.NetworkPhaseConfig {
	if n == nil {
		return nil
	}
	config := &entities.NetworkPhaseConfig{
		VLAN:       uint16(n.GetVlan()),
		StaticIP:   n.GetStaticIp(),
		Gateway:    n.GetGateway(),
		DNS:        n.GetDns(),
		AuthMethod: protoAuthMethodToEntity(n.GetAuthMethod()),
		Subnet:     n.GetSubnet(),
		DNSServers: n.GetDnsServers(),
		DHCP:       n.GetDhcp(),
		Zone:       n.GetZone(),
	}

	if n.GetDhcpPool() != nil {
		config.DHCPPool = &entities.DHCPPoolConfig{
			Network:    n.GetDhcpPool().GetNetwork(),
			RangeStart: n.GetDhcpPool().GetRangeStart(),
			RangeEnd:   n.GetDhcpPool().GetRangeEnd(),
			LeaseTime:  int(n.GetDhcpPool().GetLeaseTime()),
		}
	}

	acls := make([]entities.ACLConfig, 0, len(n.GetAcls()))
	for _, acl := range n.GetAcls() {
		acls = append(acls, entities.ACLConfig{
			Priority: int(acl.GetPriority()),
			Protocol: acl.GetProtocol(),
			SrcIP:    acl.GetSrcIp(),
			DstIP:    acl.GetDstIp(),
			SrcPort:  uint16(acl.GetSrcPort()),
			DstPort:  uint16(acl.GetDstPort()),
			Action:   acl.GetAction(),
		})
	}
	config.ACLs = acls

	return config
}

func entityNetworkConfigToProto(n *entities.NetworkPhaseConfig) *platformv1.NetworkPhaseConfig {
	if n == nil {
		return nil
	}
	config := &platformv1.NetworkPhaseConfig{
		Vlan:       uint32(n.VLAN),
		StaticIp:   n.StaticIP,
		Gateway:    n.Gateway,
		Dns:        n.DNS,
		AuthMethod: entityAuthMethodToProto(n.AuthMethod),
		Subnet:     n.Subnet,
		DnsServers: n.DNSServers,
		Dhcp:       n.DHCP,
		Zone:       n.Zone,
	}

	if n.DHCPPool != nil {
		config.DhcpPool = &platformv1.DHCPPoolConfig{
			Network:    n.DHCPPool.Network,
			RangeStart: n.DHCPPool.RangeStart,
			RangeEnd:   n.DHCPPool.RangeEnd,
			LeaseTime:  int32(n.DHCPPool.LeaseTime),
		}
	}

	acls := make([]*platformv1.ACLConfig, 0, len(n.ACLs))
	for _, acl := range n.ACLs {
		acls = append(acls, &platformv1.ACLConfig{
			Priority: int32(acl.Priority),
			Protocol: acl.Protocol,
			SrcIp:    acl.SrcIP,
			DstIp:    acl.DstIP,
			SrcPort:  uint32(acl.SrcPort),
			DstPort:  uint32(acl.DstPort),
			Action:   acl.Action,
		})
	}
	config.Acls = acls

	return config
}

func protoAuthMethodToEntity(a platformv1.AuthMethod) entities.AuthMethod {
	switch a {
	case platformv1.AuthMethod_AUTH_METHOD_802_1X:
		return entities.AuthMethod802_1X
	default:
		return entities.AuthMethodNone
	}
}

func entityAuthMethodToProto(a entities.AuthMethod) platformv1.AuthMethod {
	switch a {
	case entities.AuthMethod802_1X:
		return platformv1.AuthMethod_AUTH_METHOD_802_1X
	default:
		return platformv1.AuthMethod_AUTH_METHOD_NONE
	}
}

func protoPlatformdConfigToEntity(p *platformv1.PlatformdConfigRef) *entities.PlatformdConfigRef {
	if p == nil {
		return nil
	}
	return &entities.PlatformdConfigRef{
		ConfigType: p.GetConfigType(),
		Reference:  p.GetReference(),
		ConfigName: p.GetConfigName(),
		ConfigPath: p.GetConfigPath(),
		Version:    p.GetVersion(),
	}
}

func entityPlatformdConfigToProto(p *entities.PlatformdConfigRef) *platformv1.PlatformdConfigRef {
	if p == nil {
		return nil
	}
	return &platformv1.PlatformdConfigRef{
		ConfigType: p.ConfigType,
		Reference:  p.Reference,
		ConfigName: p.ConfigName,
		ConfigPath: p.ConfigPath,
		Version:    p.Version,
	}
}

func protoMatchRulesToEntity(m *platformv1.ProfileMatchRules) *entities.ProfileMatchRules {
	if m == nil {
		return nil
	}
	return &entities.ProfileMatchRules{
		MACPrefix:         m.GetMacPrefix(),
		SerialPrefix:      m.GetSerialPrefix(),
		Model:             m.GetModel(),
		ModelPattern:      m.GetModelPattern(),
		SerialPattern:     m.GetSerialPattern(),
		ManufacturerMatch: m.GetManufacturerMatch(),
		TPMVendor:         m.GetTpmVendor(),
		CustomAttributes:  m.GetCustomAttributes(),
	}
}

func entityMatchRulesToProto(m *entities.ProfileMatchRules) *platformv1.ProfileMatchRules {
	if m == nil {
		return nil
	}
	return &platformv1.ProfileMatchRules{
		MacPrefix:         m.MACPrefix,
		SerialPrefix:      m.SerialPrefix,
		Model:             m.Model,
		ModelPattern:      m.ModelPattern,
		SerialPattern:     m.SerialPattern,
		ManufacturerMatch: m.ManufacturerMatch,
		TpmVendor:         m.TPMVendor,
		CustomAttributes:  m.CustomAttributes,
	}
}

func protoDevicePaginationToQuery(p *platformv1.PaginationRequest) datastore.PageQuery {
	query := datastore.NewPageQuery()
	if p == nil {
		return query
	}
	if p.GetPage() > 0 {
		query.Page = int(p.GetPage())
	}
	if p.GetPageSize() > 0 {
		query.PageSize = int(p.GetPageSize())
	}
	if !p.GetAscending() {
		query.SortOrder = datastore.SortDescending
	}
	return query
}

func queryResultToDevicePagination(r datastore.PageResult[*entities.Device]) *platformv1.PaginationResponse {
	totalPages := uint32(0)
	if r.PageSize > 0 {
		totalPages = uint32(r.Total / r.PageSize)
		if r.Total%r.PageSize > 0 {
			totalPages++
		}
	}
	return &platformv1.PaginationResponse{
		Page:       uint32(r.Page),
		PageSize:   uint32(r.PageSize),
		TotalPages: totalPages,
		TotalItems: uint64(r.Total),
	}
}

func queryResultToProfilePagination(r datastore.PageResult[*entities.DeviceProfile]) *platformv1.PaginationResponse {
	totalPages := uint32(0)
	if r.PageSize > 0 {
		totalPages = uint32(r.Total / r.PageSize)
		if r.Total%r.PageSize > 0 {
			totalPages++
		}
	}
	return &platformv1.PaginationResponse{
		Page:       uint32(r.Page),
		PageSize:   uint32(r.PageSize),
		TotalPages: totalPages,
		TotalItems: uint64(r.Total),
	}
}

// mapDeviceError maps device errors to appropriate gRPC status codes.
func (s *DeviceGRPCService) mapDeviceError(operation string, err error) error {
	if err == nil {
		return nil
	}

	s.logger.Error(err, "device operation failed", "operation", operation)

	// Check for specific device error types
	switch e := err.(type) {
	case ErrDeviceOperationFailed:
		return status.Errorf(codes.Internal, "device operation %s failed: %s", e.Operation, e.Reason)
	case ErrDeviceNotFound:
		return status.Errorf(codes.NotFound, "device not found: %d", e.ID)
	}

	// Check for datastore not found error
	if err == datastore.ErrRecordNotFound {
		return status.Error(codes.NotFound, "device not found")
	}

	// Default to internal error
	return status.Error(codes.Internal, err.Error())
}

// mapProfileError maps profile errors to appropriate gRPC status codes.
func (s *DeviceGRPCService) mapProfileError(operation string, err error) error {
	if err == nil {
		return nil
	}

	s.logger.Error(err, "profile operation failed", "operation", operation)

	// Check for specific profile error types
	switch e := err.(type) {
	case ErrProfileOperationFailed:
		return status.Errorf(codes.Internal, "profile operation %s failed: %s", e.Operation, e.Reason)
	case ErrProfileNotFound:
		return status.Errorf(codes.NotFound, "profile not found: %d", e.ID)
	}

	// Check for datastore not found error
	if err == datastore.ErrRecordNotFound {
		return status.Error(codes.NotFound, "profile not found")
	}

	// Default to internal error
	return status.Error(codes.Internal, err.Error())
}

// Ensure DeviceGRPCService implements the DeviceServiceServer interface.
var _ platformv1.DeviceServiceServer = (*DeviceGRPCService)(nil)
