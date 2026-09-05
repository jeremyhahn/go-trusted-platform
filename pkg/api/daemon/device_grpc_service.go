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
	"encoding/json"
	"errors"
	"log/slog"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	grpcapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/attestation/verdict"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// DeviceGRPCService implements the gRPC DeviceService.
// It delegates all operations to the service layer interfaces.
type DeviceGRPCService struct {
	platformv1.UnimplementedDeviceServiceServer

	deviceService  device.DeviceService
	profileService device.DeviceProfileService
	akTrust        AKTrustAnchor
	verdictSink    verdict.Sink
	verifier       *DeviceQuoteVerifier
	// attestCertRecorder backs RecordAttestationCertificate; nil answers
	// Unavailable.
	attestCertRecorder AttestCertRecorder
	logger             *slog.Logger
}

// DeviceGRPCOption configures optional dependencies of a DeviceGRPCService.
type DeviceGRPCOption func(*DeviceGRPCService)

// WithDeviceAKTrust supplies the platform CA used to chain device
// attestation certificates. Without it every device quote fails closed.
func WithDeviceAKTrust(trust AKTrustAnchor) DeviceGRPCOption {
	return func(s *DeviceGRPCService) { s.akTrust = trust }
}

// WithDeviceVerdictSink supplies the sink that receives device quote
// verdicts: the attestation event log and the SDN quarantine observers.
func WithDeviceVerdictSink(sink verdict.Sink) DeviceGRPCOption {
	return func(s *DeviceGRPCService) { s.verdictSink = sink }
}

// NewDeviceGRPCService creates a new DeviceGRPCService.
func NewDeviceGRPCService(
	deviceService device.DeviceService,
	profileService device.DeviceProfileService,
	logger *slog.Logger,
	opts ...DeviceGRPCOption,
) *DeviceGRPCService {
	if logger == nil {
		logger = slog.Default()
	}
	s := &DeviceGRPCService{
		deviceService:  deviceService,
		profileService: profileService,
		logger:         logger,
	}
	for _, opt := range opts {
		opt(s)
	}
	s.verifier = NewDeviceQuoteVerifier(deviceService, profileService, s.akTrust, s.verdictSink, logger)
	return s
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

	profile, convErr := s.pbToProfile(req.GetProfile())
	if convErr != nil {
		return nil, status.Error(codes.InvalidArgument, convErr.Error())
	}

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

	profile, convErr := s.pbToProfile(req.GetProfile())
	if convErr != nil {
		return nil, status.Error(codes.InvalidArgument, convErr.Error())
	}

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

// AssignProfileToDevice binds a profile to a specific device identity by
// EK serial and/or MAC address, optionally prestaging the device's
// PEM-encoded EK certificate, and marks the profile assigned. The EK
// certificate is source-agnostic: it may come from a swtpm-backed vTPM or
// a physical hardware TPM, so it is validated only as a generic PEM-encoded
// X.509 certificate. The updated profile is returned so callers can audit
// the resulting binding.
func (s *DeviceGRPCService) AssignProfileToDevice(
	ctx context.Context,
	req *platformv1.AssignProfileToDeviceRequest,
) (*platformv1.AssignProfileToDeviceResponse, error) {
	if req.GetProfileId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "profile_id is required")
	}
	if req.GetDeviceId() == 0 && req.GetEkSerial() == "" && req.GetMacAddress() == "" {
		return nil, status.Error(codes.InvalidArgument, "device_id, ek_serial or mac_address is required")
	}
	// A prestaged EK certificate binds config delivery and remote UKI
	// signing to the hardware EK; an unparseable value can never match a
	// presented certificate, so reject it at the boundary.
	if err := entities.ValidateEKCertPEM(req.GetEkCert()); err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}

	binding := device.DeviceBinding{EKSerial: req.GetEkSerial(), MAC: req.GetMacAddress(), EKCert: req.GetEkCert()}
	if req.GetDeviceId() != 0 {
		// Bind to a registered device: the EK serial and the prestaged
		// certificate derive from the device's stored EK certificate on the
		// server; explicit request values win (#463).
		dev, err := s.deviceService.Get(ctx, req.GetDeviceId())
		if err != nil {
			return nil, s.toGRPCError(err)
		}
		binding, err = device.BindingFromDevice(dev, binding.EKSerial, binding.MAC, binding.EKCert)
		if err != nil {
			return nil, status.Error(codes.FailedPrecondition, err.Error())
		}
	}

	if err := s.profileService.AssignToDeviceWithEK(
		ctx, req.GetProfileId(), binding.EKSerial, binding.MAC, binding.EKCert,
	); err != nil {
		s.logger.Error("failed to assign profile to device",
			"profile_id", req.GetProfileId(), "error", err)
		return nil, s.toGRPCError(err)
	}

	profile, err := s.profileService.Get(ctx, req.GetProfileId())
	if err != nil {
		return nil, s.toGRPCError(err)
	}

	s.logger.Info("profile assigned to device",
		"profile_id", req.GetProfileId(),
		"device_id", req.GetDeviceId(),
		"ek_serial", binding.EKSerial,
		"mac_address", binding.MAC,
		"ek_cert_prestaged", binding.EKCert != "",
	)

	return &platformv1.AssignProfileToDeviceResponse{
		Profile: s.profileToPb(profile),
	}, nil
}

// UnassignProfileFromDevice clears a profile's device binding: the EK
// serial, MAC address, prestaged EK certificate, and assignment state are
// all reset so the profile returns to the unassigned pool. The updated
// profile is returned so callers can confirm the cleared binding.
func (s *DeviceGRPCService) UnassignProfileFromDevice(
	ctx context.Context,
	req *platformv1.UnassignProfileFromDeviceRequest,
) (*platformv1.UnassignProfileFromDeviceResponse, error) {
	if req.GetProfileId() == 0 {
		return nil, status.Error(codes.InvalidArgument, "profile_id is required")
	}

	if err := s.profileService.UnassignFromDevice(ctx, req.GetProfileId()); err != nil {
		s.logger.Error("failed to unassign profile from device",
			"profile_id", req.GetProfileId(), "error", err)
		return nil, s.toGRPCError(err)
	}

	profile, err := s.profileService.Get(ctx, req.GetProfileId())
	if err != nil {
		return nil, s.toGRPCError(err)
	}

	s.logger.Info("profile unassigned from device", "profile_id", req.GetProfileId())

	return &platformv1.UnassignProfileFromDeviceResponse{
		Profile: s.profileToPb(profile),
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
		AttestCert:    pb.GetAttestCert(),
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
		AttestCert:    d.AttestCert,
		EkCert:        d.EKCert,
		EventLog:      d.EventLog,
		HashAlgoId:    d.HashAlgoId,
		Model:         d.Model,
		Serial:        d.Serial,
		SigningPub:    d.SigningPub,
		NetworkPortId: d.NetworkPortID,
	}
}

// pbToProfile maps a protobuf DeviceProfile onto its entity representation,
// mirroring profileToPb so a profile round-trips through the gRPC surface
// without data loss: the device-identity fields (ek_serial, mac_address),
// the prestaged EK certificate (ek_cert), the assignment state, and the
// full device config (carried as its JSON encoding in the pb config bytes
// field) are all preserved. Config bytes that are not valid JSON are
// rejected with a typed ErrProfileConfigInvalid, and a non-empty ek_cert
// that does not parse as a PEM-encoded X.509 certificate is rejected with
// the typed entities EK-cert error, so callers can map either failure to
// an invalid-argument status. The domain-only WorkloadPCR field has no pb
// counterpart and is never populated here.
func (s *DeviceGRPCService) pbToProfile(pb *platformv1.DeviceProfile) (*entities.DeviceProfile, error) {
	if pb == nil {
		return nil, nil
	}
	profile := &entities.DeviceProfile{
		ID:                    pb.GetId(),
		TenantID:              pb.GetTenantId(),
		Name:                  pb.GetName(),
		Model:                 pb.GetModel(),
		Role:                  grpcapi.ProtoRoleToEntity(pb.GetRole()),
		EventLog:              pb.GetEventLog(),
		Zone:                  pb.GetZone(),
		EnrollmentNetwork:     pb.GetEnrollmentNetwork(),
		PostEnrollmentNetwork: pb.GetPostEnrollmentNetwork(),
		FailureNetwork:        pb.GetFailureNetwork(),
		EKSerial:              pb.GetEkSerial(),
		MACAddress:            pb.GetMacAddress(),
		TLSServerName:         pb.GetTlsServerName(),
		Assigned:              pb.GetAssigned(),
		// PCRBaseline is deliberately NOT mapped: the baseline is read-only
		// on every transport (#373, #448). A caller-supplied expected state
		// never reaches the entity; ProfileService.Update restores the
		// stored one when the incoming entity carries none (#446).
	}

	// A prestaged EK certificate binds config delivery and remote UKI
	// signing to the hardware EK, so a value that cannot possibly match a
	// presented certificate (unparseable PEM) is rejected at the boundary.
	if ekCert := pb.GetEkCert(); ekCert != "" {
		if err := entities.ValidateEKCertPEM(ekCert); err != nil {
			return nil, err
		}
		profile.EKCert = ekCert
	}

	if ts := pb.GetAssignedAt(); ts != nil {
		profile.AssignedAt = ts.AsTime()
	}
	if configJSON := pb.GetConfig(); len(configJSON) > 0 {
		var config any
		if err := json.Unmarshal(configJSON, &config); err != nil {
			return nil, ErrProfileConfigInvalid{Cause: err}
		}
		profile.Config = config
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

	return profile, nil
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

// profileToPb maps an entity DeviceProfile onto its protobuf representation,
// populating every pb field that has a domain counterpart. The pb created_at
// and updated_at fields stay unset because the domain entity carries no such
// timestamps; the domain-only WorkloadPCR field has no pb counterpart. The
// full device config (an arbitrary JSON-shaped value) is carried as its
// JSON encoding in the pb config bytes field. The prestaged EK certificate
// is echoed back on reads deliberately: an EK certificate is public key
// material (an X.509 certificate carrying no secrets), so exposing it lets
// operators audit which certificate is prestaged without leaking anything.
// The PCR baseline is read-only wire state: it travels out here and is
// ignored on the way in by pbToProfile (#448).
func (s *DeviceGRPCService) profileToPb(p *entities.DeviceProfile) *platformv1.DeviceProfile {
	if p == nil {
		return nil
	}
	profile := &platformv1.DeviceProfile{
		Id:                    p.ID,
		TenantId:              p.TenantID,
		Name:                  p.Name,
		Model:                 p.Model,
		Role:                  grpcapi.EntityRoleToProto(p.Role),
		EventLog:              p.EventLog,
		Zone:                  p.Zone,
		EnrollmentNetwork:     p.EnrollmentNetwork,
		PostEnrollmentNetwork: p.PostEnrollmentNetwork,
		FailureNetwork:        p.FailureNetwork,
		EkSerial:              p.EKSerial,
		EkCert:                p.EKCert,
		MacAddress:            p.MACAddress,
		TlsServerName:         p.TLSServerName,
		Assigned:              p.Assigned,
		PcrBaseline:           grpcapi.EntityPCRBaselineToProto(p.PCRBaseline),
	}

	if !p.AssignedAt.IsZero() {
		profile.AssignedAt = timestamppb.New(p.AssignedAt)
	}
	if p.Config != nil {
		configJSON, err := json.Marshal(p.Config)
		if err != nil {
			// The config is an arbitrary value; a non-serializable config
			// must not fail the whole profile conversion. Log and omit.
			s.logger.Error("device profile config serialization failed",
				"profile_id", p.ID, "error", err)
		} else {
			profile.Config = configJSON
		}
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

	// Typed validation failures from the service layer are client errors.
	var vlans device.ErrProfileVLANsNotDistinct
	if errors.As(err, &vlans) {
		return status.Error(codes.InvalidArgument, errStr)
	}

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

// AttestDevice verifies a TPM quote submitted for a device.
//
// It delegates to verifyDeviceQuote — the same implementation
// PlatformServiceProvider.DeviceAttest uses, which is what QUIC and the MCP
// device_attest tool reach. Adding a transport must not add a second
// verifier: two implementations of "did this device attest" is how two
// transports come to disagree about a security verdict.
//
// One RPC serves two transports here: the device service is registered on
// both the TCP gRPC server and the Unix-domain-socket server
// (pkg/api/daemon/daemon.go), so gRPC and Unix share this method.
//
// A verification that FAILS is not a gRPC error. It is a successful call
// reporting a negative verdict, so a caller can read which check failed
// rather than parsing a status message. Errors are reserved for calls that
// could not be evaluated at all — an unknown device, unusable evidence, a
// device with no trustworthy attestation key.
func (s *DeviceGRPCService) AttestDevice(
	ctx context.Context,
	req *platformv1.AttestDeviceRequest,
) (*platformv1.AttestDeviceResponse, error) {
	if req.GetDeviceId() == "" {
		return nil, status.Error(codes.InvalidArgument, "device_id is required")
	}
	if len(req.GetEvidence()) == 0 {
		return nil, status.Error(codes.InvalidArgument, "evidence is required")
	}

	result, err := s.verifier.Verify(ctx, req.GetDeviceId(), req.GetEvidence())
	if err != nil {
		return nil, s.toGRPCError(err)
	}

	s.logger.Info("device attestation completed",
		"device_id", result.DeviceID,
		"serial", result.Serial,
		"verified", result.Verified,
		"transport", "grpc",
	)

	return &platformv1.AttestDeviceResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "device attestation evaluated",
		},
		DeviceId:              result.DeviceID,
		Serial:                result.Serial,
		Model:                 result.Model,
		Verified:              result.Verified,
		SignatureValid:        result.SignatureValid,
		NonceValid:            result.NonceValid,
		PcrsValid:             result.PCRsValid,
		AttestationStatus:     result.Status,
		Message:               result.Message,
		AttestedAt:            timestamppb.New(result.AttestedAt),
		AkCertificateVerified: result.AKCertificateVerified,
		PcrBaselineSource:     result.PCRBaselineSource,
		PcrBaselineRecordedAt: baselineTimestamp(result.PCRBaselineRecordedAt),
		PcrBaselineCaptured:   result.PCRBaselineCaptured,
	}, nil
}

// baselineTimestamp encodes an optional baseline time; a zero time is
// carried as nil so the wire says "no baseline" rather than year 1.
func baselineTimestamp(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}
