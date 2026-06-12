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
	"errors"
	"log/slog"
	"math"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc/gen"
	"github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning/baremetal"
)

// =============================================================================
// Errors
// =============================================================================

// ErrBMCServiceNotConfigured indicates no BMC service is wired into the daemon.
type ErrBMCServiceNotConfigured struct{}

func (ErrBMCServiceNotConfigured) Error() string {
	return "bmc service not configured"
}

// ErrBaremetalServiceNotConfigured indicates no baremetal provisioning
// service is wired into the daemon.
type ErrBaremetalServiceNotConfigured struct{}

func (ErrBaremetalServiceNotConfigured) Error() string {
	return "baremetal provisioning service not configured"
}

// ErrInvalidProfileID indicates a profile ID of 0 was supplied.
type ErrInvalidProfileID struct{}

func (ErrInvalidProfileID) Error() string {
	return "profile id must be non-zero"
}

// ErrMissingISOURL indicates a required ISO URL was not supplied.
type ErrMissingISOURL struct{}

func (ErrMissingISOURL) Error() string {
	return "iso url is required"
}

// ErrInvalidBootDevice indicates an unrecognized boot device value.
type ErrInvalidBootDevice struct {
	Device platformv1.BMCBootDevice
}

func (e ErrInvalidBootDevice) Error() string {
	return "invalid boot device: " + e.Device.String()
}

// ErrInvalidPrivilege indicates an unrecognized privilege value.
type ErrInvalidPrivilege struct {
	Privilege platformv1.BMCUserPrivilege
}

func (e ErrInvalidPrivilege) Error() string {
	return "invalid user privilege: " + e.Privilege.String()
}

// ErrMissingUser indicates the BMCCreateUserRequest.User field was nil.
type ErrMissingUser struct{}

func (ErrMissingUser) Error() string {
	return "user is required"
}

// ErrMissingCertPEM indicates the cert PEM bytes were empty.
type ErrMissingCertPEM struct{}

func (ErrMissingCertPEM) Error() string {
	return "cert_pem is required"
}

// ErrMissingKeyPEM indicates the key PEM bytes were empty.
type ErrMissingKeyPEM struct{}

func (ErrMissingKeyPEM) Error() string {
	return "key_pem is required"
}

// ErrInvalidSlot indicates a slot value that does not fit in a uint8.
type ErrInvalidSlot struct {
	Slot uint32
}

func (ErrInvalidSlot) Error() string {
	return "slot value out of range (must be 0-255)"
}

// ErrInvalidChannel indicates a channel value that does not fit in a uint8.
type ErrInvalidChannel struct {
	Channel uint32
}

func (ErrInvalidChannel) Error() string {
	return "channel value out of range (must be 0-255)"
}

// =============================================================================
// Service interfaces
// =============================================================================

// BMCServicer defines the BMC service operations the gRPC server delegates
// to. The interface mirrors *bmc.Service so production wiring passes the
// concrete service while tests can supply fakes.
type BMCServicer interface {
	PowerOn(ctx context.Context, profileID uint64) error
	PowerOff(ctx context.Context, profileID uint64) error
	PowerReset(ctx context.Context, profileID uint64) error
	PowerCycle(ctx context.Context, profileID uint64) error
	PowerStatus(ctx context.Context, profileID uint64) (bmc.PowerState, error)

	SetBootDevice(ctx context.Context, profileID uint64, device bmc.BootDevice, persistent bool) error
	GetBootDevice(ctx context.Context, profileID uint64) (bmc.BootDevice, error)

	MountISO(ctx context.Context, profileID uint64, isoURL string) error
	UnmountISO(ctx context.Context, profileID uint64) error
	VirtualMediaStatus(ctx context.Context, profileID uint64) (*bmc.VirtualMediaInfo, error)

	GetSensors(ctx context.Context, profileID uint64) ([]bmc.SensorReading, error)
	GetSystemInfo(ctx context.Context, profileID uint64) (*bmc.SystemInfo, error)

	GetWebCertificate(ctx context.Context, profileID uint64) (*bmc.CertificateInfo, error)
	ReplaceWebCertificate(ctx context.Context, profileID uint64, certPEM, keyPEM []byte) error

	ListUsers(ctx context.Context, profileID uint64) ([]bmc.User, error)
	CreateUser(ctx context.Context, profileID uint64, user bmc.User, password string) error
	DeleteUser(ctx context.Context, profileID uint64, slot uint8) error
	SetUserPassword(ctx context.Context, profileID uint64, slot uint8, password string) error
	SetUserPrivilege(ctx context.Context, profileID uint64, slot, channel uint8, privilege bmc.Privilege) error
}

// BaremetalServicer defines the bare metal provisioning operations the
// gRPC server delegates to. Implementations track provision workflows
// keyed by profile ID and return the most recent ProvisionResult.
type BaremetalServicer interface {
	// Provision initiates a new provisioning workflow for the given
	// profile and ISO URL. Returns the ProvisionResult containing the
	// generated provision ID and initial status.
	Provision(ctx context.Context, req *baremetal.ProvisionRequest) (*baremetal.ProvisionResult, error)

	// StatusForProfile returns the most recent ProvisionResult for the
	// given profile ID. Returns ErrProvisionNotFound if no provisioning
	// workflow has been started for that profile.
	StatusForProfile(ctx context.Context, profileID uint64) (*baremetal.ProvisionResult, error)
}

// =============================================================================
// Enum dispatch maps
// =============================================================================

// powerActionFunc is the function signature for power dispatch.
type powerActionFunc func(ctx context.Context, profileID uint64) error

// bootDeviceFromProto translates a proto BMCBootDevice into a domain
// bmc.BootDevice. Returns false on unknown values.
var bootDeviceFromProto = map[platformv1.BMCBootDevice]bmc.BootDevice{
	platformv1.BMCBootDevice_BMC_BOOT_DEVICE_PXE:           bmc.BootDevicePXE,
	platformv1.BMCBootDevice_BMC_BOOT_DEVICE_DISK:          bmc.BootDeviceDisk,
	platformv1.BMCBootDevice_BMC_BOOT_DEVICE_CDROM:         bmc.BootDeviceCDROM,
	platformv1.BMCBootDevice_BMC_BOOT_DEVICE_VIRTUAL_MEDIA: bmc.BootDeviceVirtualMedia,
	platformv1.BMCBootDevice_BMC_BOOT_DEVICE_NONE:          bmc.BootDeviceNone,
}

// bootDeviceToProto translates a domain bmc.BootDevice into a proto
// BMCBootDevice. Returns BMC_BOOT_DEVICE_UNSPECIFIED for unknown values.
var bootDeviceToProto = map[bmc.BootDevice]platformv1.BMCBootDevice{
	bmc.BootDevicePXE:          platformv1.BMCBootDevice_BMC_BOOT_DEVICE_PXE,
	bmc.BootDeviceDisk:         platformv1.BMCBootDevice_BMC_BOOT_DEVICE_DISK,
	bmc.BootDeviceCDROM:        platformv1.BMCBootDevice_BMC_BOOT_DEVICE_CDROM,
	bmc.BootDeviceVirtualMedia: platformv1.BMCBootDevice_BMC_BOOT_DEVICE_VIRTUAL_MEDIA,
	bmc.BootDeviceNone:         platformv1.BMCBootDevice_BMC_BOOT_DEVICE_NONE,
}

// powerStateToProto translates a domain bmc.PowerState into a proto
// BMCPowerState. Returns BMC_POWER_STATE_UNSPECIFIED for unknown values.
var powerStateToProto = map[bmc.PowerState]platformv1.BMCPowerState{
	bmc.PowerStateOn:      platformv1.BMCPowerState_BMC_POWER_STATE_ON,
	bmc.PowerStateOff:     platformv1.BMCPowerState_BMC_POWER_STATE_OFF,
	bmc.PowerStateUnknown: platformv1.BMCPowerState_BMC_POWER_STATE_UNKNOWN,
}

// privilegeFromProto translates a proto BMCUserPrivilege into a domain
// bmc.Privilege. Returns false on unknown values.
var privilegeFromProto = map[platformv1.BMCUserPrivilege]bmc.Privilege{
	platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_CALLBACK:      bmc.PrivilegeCallback,
	platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_USER:          bmc.PrivilegeUser,
	platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_OPERATOR:      bmc.PrivilegeOperator,
	platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_ADMINISTRATOR: bmc.PrivilegeAdministrator,
	platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_NO_ACCESS:     bmc.PrivilegeNoAccess,
}

// privilegeToProto translates a domain bmc.Privilege into a proto
// BMCUserPrivilege. Returns BMC_USER_PRIVILEGE_UNSPECIFIED for unknown.
var privilegeToProto = map[bmc.Privilege]platformv1.BMCUserPrivilege{
	bmc.PrivilegeCallback:      platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_CALLBACK,
	bmc.PrivilegeUser:          platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_USER,
	bmc.PrivilegeOperator:      platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_OPERATOR,
	bmc.PrivilegeAdministrator: platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_ADMINISTRATOR,
	bmc.PrivilegeNoAccess:      platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_NO_ACCESS,
}

// provisioningStatusToProto translates a domain baremetal.ProvisioningStatus
// into a proto BMCProvisioningStatus.
var provisioningStatusToProto = map[baremetal.ProvisioningStatus]platformv1.BMCProvisioningStatus{
	baremetal.StatusPending:     platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_PENDING,
	baremetal.StatusConnecting:  platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_CONNECTING,
	baremetal.StatusSettingBoot: platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_SETTING_BOOT,
	baremetal.StatusMountingISO: platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_MOUNTING_ISO,
	baremetal.StatusPoweringOn:  platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_POWERING_ON,
	baremetal.StatusInstalling:  platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_INSTALLING,
	baremetal.StatusFinalizing:  platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_FINALIZING,
	baremetal.StatusComplete:    platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_COMPLETE,
	baremetal.StatusFailed:      platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_FAILED,
}

// =============================================================================
// BMCGRPCService
// =============================================================================

// BMCGRPCService implements platformv1.BMCServiceServer by delegating to
// the domain bmc.Service for power, boot, vmedia, sensor, system info,
// certificate and user operations, and to baremetal.Service for the
// orchestrated Provision workflow.
type BMCGRPCService struct {
	platformv1.UnimplementedBMCServiceServer

	service      BMCServicer
	baremetal    BaremetalServicer
	logger       *slog.Logger
	powerActions map[string]powerActionFunc
	// enroller and profileSvc are wired via SetEnroller for the EnrollBMC RPC.
	enroller   BMCEnroller
	profileSvc device.DeviceProfileService
	// restorer is wired via SetRestorer for the RestoreFactoryCert RPC.
	restorer BMCRestorer
}

// Compile-time interface check.
var _ platformv1.BMCServiceServer = (*BMCGRPCService)(nil)

// NewBMCGRPCService constructs a BMC gRPC service. service is required;
// baremetal may be nil, in which case Provision and ProvisionStatus
// return codes.FailedPrecondition.
func NewBMCGRPCService(service BMCServicer, baremetal BaremetalServicer, logger *slog.Logger) *BMCGRPCService {
	if logger == nil {
		logger = slog.Default()
	}
	s := &BMCGRPCService{
		service:   service,
		baremetal: baremetal,
		logger:    logger,
	}
	if service != nil {
		// Map-based dispatch for the four power actions (O(1) lookup).
		s.powerActions = map[string]powerActionFunc{
			"on":    service.PowerOn,
			"off":   service.PowerOff,
			"reset": service.PowerReset,
			"cycle": service.PowerCycle,
		}
	}
	return s
}

// SetBaremetalService injects a BaremetalServicer after construction.
// Used by daemon wiring when the baremetal service becomes available
// after the gRPC service has been registered.
func (s *BMCGRPCService) SetBaremetalService(b BaremetalServicer) {
	s.baremetal = b
}

// =============================================================================
// Power management
// =============================================================================

// powerOp executes a power action via map-based dispatch and converts
// the resulting error into a gRPC status. The previous and current
// power states are queried before and after the action so the caller
// receives a meaningful BMCPowerResponse.
func (s *BMCGRPCService) powerOp(ctx context.Context, profileID uint64, action string) (*platformv1.BMCPowerResponse, error) {
	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBMCServiceNotConfigured{}.Error())
	}
	if profileID == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrInvalidProfileID{}.Error())
	}
	fn, ok := s.powerActions[action]
	if !ok {
		return nil, status.Error(codes.InvalidArgument, "invalid power action: "+action)
	}

	previous, prevErr := s.service.PowerStatus(ctx, profileID)
	if prevErr != nil {
		return nil, s.toGRPCError(action, prevErr)
	}

	if err := fn(ctx, profileID); err != nil {
		return nil, s.toGRPCError(action, err)
	}

	current, curErr := s.service.PowerStatus(ctx, profileID)
	if curErr != nil {
		// The action succeeded but the post-status check failed; log a
		// warning and return PowerStateUnknown for current. The action
		// itself was successful so the RPC reports success.
		s.logger.Warn("bmc grpc: power status check after action failed",
			slog.String("action", action),
			slog.Uint64("profile_id", profileID),
			slog.String("error", curErr.Error()))
		current = bmc.PowerStateUnknown
	}

	return &platformv1.BMCPowerResponse{
		PreviousState: powerStateProto(previous),
		CurrentState:  powerStateProto(current),
	}, nil
}

// PowerOn powers on the system identified by the profile.
func (s *BMCGRPCService) PowerOn(ctx context.Context, req *platformv1.BMCPowerRequest) (*platformv1.BMCPowerResponse, error) {
	return s.powerOp(ctx, req.GetProfileId(), "on")
}

// PowerOff powers off the system identified by the profile.
func (s *BMCGRPCService) PowerOff(ctx context.Context, req *platformv1.BMCPowerRequest) (*platformv1.BMCPowerResponse, error) {
	return s.powerOp(ctx, req.GetProfileId(), "off")
}

// PowerReset performs a hard reset of the system identified by the profile.
func (s *BMCGRPCService) PowerReset(ctx context.Context, req *platformv1.BMCPowerRequest) (*platformv1.BMCPowerResponse, error) {
	return s.powerOp(ctx, req.GetProfileId(), "reset")
}

// PowerCycle power-cycles the system identified by the profile.
func (s *BMCGRPCService) PowerCycle(ctx context.Context, req *platformv1.BMCPowerRequest) (*platformv1.BMCPowerResponse, error) {
	return s.powerOp(ctx, req.GetProfileId(), "cycle")
}

// PowerStatus returns the current power state of the system.
func (s *BMCGRPCService) PowerStatus(ctx context.Context, req *platformv1.BMCPowerStatusRequest) (*platformv1.BMCPowerStatusResponse, error) {
	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBMCServiceNotConfigured{}.Error())
	}
	if req.GetProfileId() == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrInvalidProfileID{}.Error())
	}
	state, err := s.service.PowerStatus(ctx, req.GetProfileId())
	if err != nil {
		return nil, s.toGRPCError("power_status", err)
	}
	return &platformv1.BMCPowerStatusResponse{
		State: powerStateProto(state),
	}, nil
}

// =============================================================================
// Boot device control
// =============================================================================

// SetBootDevice sets the next boot device for the system.
func (s *BMCGRPCService) SetBootDevice(ctx context.Context, req *platformv1.BMCSetBootDeviceRequest) (*platformv1.BMCSetBootDeviceResponse, error) {
	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBMCServiceNotConfigured{}.Error())
	}
	if req.GetProfileId() == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrInvalidProfileID{}.Error())
	}
	device, ok := bootDeviceFromProto[req.GetDevice()]
	if !ok {
		return nil, status.Error(codes.InvalidArgument, ErrInvalidBootDevice{Device: req.GetDevice()}.Error())
	}
	if err := s.service.SetBootDevice(ctx, req.GetProfileId(), device, req.GetPersistent()); err != nil {
		return nil, s.toGRPCError("set_boot_device", err)
	}
	return &platformv1.BMCSetBootDeviceResponse{
		Device: req.GetDevice(),
	}, nil
}

// GetBootDevice returns the current boot device override.
func (s *BMCGRPCService) GetBootDevice(ctx context.Context, req *platformv1.BMCGetBootDeviceRequest) (*platformv1.BMCGetBootDeviceResponse, error) {
	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBMCServiceNotConfigured{}.Error())
	}
	if req.GetProfileId() == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrInvalidProfileID{}.Error())
	}
	device, err := s.service.GetBootDevice(ctx, req.GetProfileId())
	if err != nil {
		return nil, s.toGRPCError("get_boot_device", err)
	}
	return &platformv1.BMCGetBootDeviceResponse{
		Device: bootDeviceProto(device),
	}, nil
}

// =============================================================================
// Virtual media
// =============================================================================

// MountISO mounts an ISO image via virtual media.
func (s *BMCGRPCService) MountISO(ctx context.Context, req *platformv1.BMCMountISORequest) (*platformv1.BMCMountISOResponse, error) {
	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBMCServiceNotConfigured{}.Error())
	}
	if req.GetProfileId() == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrInvalidProfileID{}.Error())
	}
	if req.GetIsoUrl() == "" {
		return nil, status.Error(codes.InvalidArgument, ErrMissingISOURL{}.Error())
	}
	if err := s.service.MountISO(ctx, req.GetProfileId(), req.GetIsoUrl()); err != nil {
		return nil, s.toGRPCError("mount_iso", err)
	}
	return &platformv1.BMCMountISOResponse{Mounted: true}, nil
}

// UnmountISO unmounts the currently mounted ISO virtual media.
func (s *BMCGRPCService) UnmountISO(ctx context.Context, req *platformv1.BMCUnmountISORequest) (*platformv1.BMCUnmountISOResponse, error) {
	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBMCServiceNotConfigured{}.Error())
	}
	if req.GetProfileId() == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrInvalidProfileID{}.Error())
	}
	if err := s.service.UnmountISO(ctx, req.GetProfileId()); err != nil {
		return nil, s.toGRPCError("unmount_iso", err)
	}
	return &platformv1.BMCUnmountISOResponse{}, nil
}

// VirtualMediaStatus returns the current virtual media state.
func (s *BMCGRPCService) VirtualMediaStatus(ctx context.Context, req *platformv1.BMCVirtualMediaStatusRequest) (*platformv1.BMCVirtualMediaStatusResponse, error) {
	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBMCServiceNotConfigured{}.Error())
	}
	if req.GetProfileId() == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrInvalidProfileID{}.Error())
	}
	info, err := s.service.VirtualMediaStatus(ctx, req.GetProfileId())
	if err != nil {
		return nil, s.toGRPCError("virtual_media_status", err)
	}
	if info == nil {
		return &platformv1.BMCVirtualMediaStatusResponse{}, nil
	}
	return &platformv1.BMCVirtualMediaStatusResponse{
		Mounted:   info.Mounted,
		ImageUrl:  info.ImageURL,
		MediaType: info.MediaType,
	}, nil
}

// =============================================================================
// Monitoring
// =============================================================================

// GetSensors returns sensor readings from the BMC.
func (s *BMCGRPCService) GetSensors(ctx context.Context, req *platformv1.BMCGetSensorsRequest) (*platformv1.BMCGetSensorsResponse, error) {
	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBMCServiceNotConfigured{}.Error())
	}
	if req.GetProfileId() == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrInvalidProfileID{}.Error())
	}
	sensors, err := s.service.GetSensors(ctx, req.GetProfileId())
	if err != nil {
		return nil, s.toGRPCError("get_sensors", err)
	}
	out := make([]*platformv1.BMCSensorReading, len(sensors))
	for i, sensor := range sensors {
		out[i] = &platformv1.BMCSensorReading{
			Name:   sensor.Name,
			Value:  sensor.Value,
			Units:  sensor.Units,
			Status: sensor.Status,
		}
	}
	return &platformv1.BMCGetSensorsResponse{Sensors: out}, nil
}

// GetSystemInfo returns system identification information.
func (s *BMCGRPCService) GetSystemInfo(ctx context.Context, req *platformv1.BMCGetSystemInfoRequest) (*platformv1.BMCGetSystemInfoResponse, error) {
	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBMCServiceNotConfigured{}.Error())
	}
	if req.GetProfileId() == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrInvalidProfileID{}.Error())
	}
	info, err := s.service.GetSystemInfo(ctx, req.GetProfileId())
	if err != nil {
		return nil, s.toGRPCError("get_system_info", err)
	}
	if info == nil {
		return &platformv1.BMCGetSystemInfoResponse{}, nil
	}
	return &platformv1.BMCGetSystemInfoResponse{
		Manufacturer:    info.Manufacturer,
		Product:         info.Product,
		SerialNumber:    info.SerialNumber,
		FirmwareVersion: info.FirmwareVersion,
		BiosVersion:     info.BIOSVersion,
		PowerState:      powerStateProto(info.PowerState),
	}, nil
}

// =============================================================================
// Provisioning
// =============================================================================

// Provision initiates an orchestrated bare metal provisioning workflow.
func (s *BMCGRPCService) Provision(ctx context.Context, req *platformv1.BMCProvisionRequest) (*platformv1.BMCProvisionResponse, error) {
	if s.baremetal == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBaremetalServiceNotConfigured{}.Error())
	}
	if req.GetProfileId() == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrInvalidProfileID{}.Error())
	}
	result, err := s.baremetal.Provision(ctx, &baremetal.ProvisionRequest{
		ProfileID: req.GetProfileId(),
		ISOURL:    req.GetIsoUrl(),
	})
	if err != nil {
		return nil, s.toGRPCError("provision", err)
	}
	return &platformv1.BMCProvisionResponse{
		ProvisionId: result.ProvisionID,
		Status:      provisioningStatusProto(result.Status),
	}, nil
}

// ProvisionStatus returns the current provisioning workflow status for
// the given profile.
func (s *BMCGRPCService) ProvisionStatus(ctx context.Context, req *platformv1.BMCProvisionStatusRequest) (*platformv1.BMCProvisionStatusResponse, error) {
	if s.baremetal == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBaremetalServiceNotConfigured{}.Error())
	}
	if req.GetProfileId() == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrInvalidProfileID{}.Error())
	}
	result, err := s.baremetal.StatusForProfile(ctx, req.GetProfileId())
	if err != nil {
		return nil, s.toGRPCError("provision_status", err)
	}
	return &platformv1.BMCProvisionStatusResponse{
		Status:    provisioningStatusProto(result.Status),
		Message:   result.Message,
		StartedAt: timeToProto(result.StartedAt),
		UpdatedAt: timeToProto(result.UpdatedAt),
	}, nil
}

// =============================================================================
// Certificate management
// =============================================================================

// GetWebCertificate returns the BMC's HTTPS certificate metadata.
func (s *BMCGRPCService) GetWebCertificate(ctx context.Context, req *platformv1.BMCGetWebCertificateRequest) (*platformv1.BMCGetWebCertificateResponse, error) {
	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBMCServiceNotConfigured{}.Error())
	}
	if req.GetProfileId() == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrInvalidProfileID{}.Error())
	}
	info, err := s.service.GetWebCertificate(ctx, req.GetProfileId())
	if err != nil {
		return nil, s.toGRPCError("get_web_certificate", err)
	}
	return certInfoToProto(info), nil
}

// ReplaceWebCertificate uploads a new certificate and key to the BMC's
// HTTPS server.
func (s *BMCGRPCService) ReplaceWebCertificate(ctx context.Context, req *platformv1.BMCReplaceWebCertificateRequest) (*platformv1.BMCReplaceWebCertificateResponse, error) {
	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBMCServiceNotConfigured{}.Error())
	}
	if req.GetProfileId() == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrInvalidProfileID{}.Error())
	}
	if len(req.GetCertPem()) == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrMissingCertPEM{}.Error())
	}
	if len(req.GetKeyPem()) == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrMissingKeyPEM{}.Error())
	}
	if err := s.service.ReplaceWebCertificate(ctx, req.GetProfileId(), req.GetCertPem(), req.GetKeyPem()); err != nil {
		return nil, s.toGRPCError("replace_web_certificate", err)
	}
	return &platformv1.BMCReplaceWebCertificateResponse{
		Message: "certificate replaced successfully; BMC web server restarted",
	}, nil
}

// =============================================================================
// User management
// =============================================================================

// ListUsers returns all populated BMC user slots.
func (s *BMCGRPCService) ListUsers(ctx context.Context, req *platformv1.BMCListUsersRequest) (*platformv1.BMCListUsersResponse, error) {
	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBMCServiceNotConfigured{}.Error())
	}
	if req.GetProfileId() == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrInvalidProfileID{}.Error())
	}
	users, err := s.service.ListUsers(ctx, req.GetProfileId())
	if err != nil {
		return nil, s.toGRPCError("list_users", err)
	}
	out := make([]*platformv1.BMCUser, len(users))
	for i, u := range users {
		out[i] = userToProto(u)
	}
	return &platformv1.BMCListUsersResponse{Users: out}, nil
}

// CreateUser creates a new BMC user account in the requested slot.
func (s *BMCGRPCService) CreateUser(ctx context.Context, req *platformv1.BMCCreateUserRequest) (*platformv1.BMCCreateUserResponse, error) {
	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBMCServiceNotConfigured{}.Error())
	}
	if req.GetProfileId() == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrInvalidProfileID{}.Error())
	}
	pUser := req.GetUser()
	if pUser == nil {
		return nil, status.Error(codes.InvalidArgument, ErrMissingUser{}.Error())
	}
	domainUser, err := userFromProto(pUser)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := s.service.CreateUser(ctx, req.GetProfileId(), domainUser, req.GetPassword()); err != nil {
		return nil, s.toGRPCError("create_user", err)
	}
	return &platformv1.BMCCreateUserResponse{Slot: uint32(domainUser.Slot)}, nil
}

// DeleteUser removes a BMC user slot.
func (s *BMCGRPCService) DeleteUser(ctx context.Context, req *platformv1.BMCDeleteUserRequest) (*platformv1.BMCDeleteUserResponse, error) {
	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBMCServiceNotConfigured{}.Error())
	}
	if req.GetProfileId() == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrInvalidProfileID{}.Error())
	}
	slot, err := slotFromProto(req.GetSlot())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := s.service.DeleteUser(ctx, req.GetProfileId(), slot); err != nil {
		return nil, s.toGRPCError("delete_user", err)
	}
	return &platformv1.BMCDeleteUserResponse{}, nil
}

// SetUserPassword updates the password for the BMC user in the given slot.
func (s *BMCGRPCService) SetUserPassword(ctx context.Context, req *platformv1.BMCSetUserPasswordRequest) (*platformv1.BMCSetUserPasswordResponse, error) {
	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBMCServiceNotConfigured{}.Error())
	}
	if req.GetProfileId() == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrInvalidProfileID{}.Error())
	}
	slot, err := slotFromProto(req.GetSlot())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	if err := s.service.SetUserPassword(ctx, req.GetProfileId(), slot, req.GetPassword()); err != nil {
		return nil, s.toGRPCError("set_user_password", err)
	}
	return &platformv1.BMCSetUserPasswordResponse{}, nil
}

// SetUserPrivilege updates the channel privilege for the BMC user.
func (s *BMCGRPCService) SetUserPrivilege(ctx context.Context, req *platformv1.BMCSetUserPrivilegeRequest) (*platformv1.BMCSetUserPrivilegeResponse, error) {
	if s.service == nil {
		return nil, status.Error(codes.FailedPrecondition, ErrBMCServiceNotConfigured{}.Error())
	}
	if req.GetProfileId() == 0 {
		return nil, status.Error(codes.InvalidArgument, ErrInvalidProfileID{}.Error())
	}
	slot, err := slotFromProto(req.GetSlot())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	channel, err := channelFromProto(req.GetChannel())
	if err != nil {
		return nil, status.Error(codes.InvalidArgument, err.Error())
	}
	priv, ok := privilegeFromProto[req.GetPrivilege()]
	if !ok {
		return nil, status.Error(codes.InvalidArgument, ErrInvalidPrivilege{Privilege: req.GetPrivilege()}.Error())
	}
	if err := s.service.SetUserPrivilege(ctx, req.GetProfileId(), slot, channel, priv); err != nil {
		return nil, s.toGRPCError("set_user_privilege", err)
	}
	return &platformv1.BMCSetUserPrivilegeResponse{}, nil
}

// =============================================================================
// Helpers
// =============================================================================

// powerStateProto returns the proto power state for a domain value, or
// BMC_POWER_STATE_UNSPECIFIED for unknown values.
func powerStateProto(state bmc.PowerState) platformv1.BMCPowerState {
	if p, ok := powerStateToProto[state]; ok {
		return p
	}
	return platformv1.BMCPowerState_BMC_POWER_STATE_UNSPECIFIED
}

// bootDeviceProto returns the proto boot device for a domain value, or
// BMC_BOOT_DEVICE_UNSPECIFIED for unknown values.
func bootDeviceProto(device bmc.BootDevice) platformv1.BMCBootDevice {
	if p, ok := bootDeviceToProto[device]; ok {
		return p
	}
	return platformv1.BMCBootDevice_BMC_BOOT_DEVICE_UNSPECIFIED
}

// provisioningStatusProto returns the proto provisioning status for a
// domain value, or BMC_PROVISIONING_STATUS_UNSPECIFIED for unknown values.
func provisioningStatusProto(s baremetal.ProvisioningStatus) platformv1.BMCProvisioningStatus {
	if p, ok := provisioningStatusToProto[s]; ok {
		return p
	}
	return platformv1.BMCProvisioningStatus_BMC_PROVISIONING_STATUS_UNSPECIFIED
}

// userFromProto converts a proto BMCUser into a domain bmc.User.
func userFromProto(p *platformv1.BMCUser) (bmc.User, error) {
	slot, err := slotFromProto(p.GetSlot())
	if err != nil {
		return bmc.User{}, err
	}
	channel, err := channelFromProto(p.GetChannel())
	if err != nil {
		return bmc.User{}, err
	}
	priv, ok := privilegeFromProto[p.GetPrivilege()]
	if !ok && p.GetPrivilege() != platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_UNSPECIFIED {
		return bmc.User{}, ErrInvalidPrivilege{Privilege: p.GetPrivilege()}
	}
	return bmc.User{
		Slot:      slot,
		Username:  p.GetUsername(),
		Enabled:   p.GetEnabled(),
		Privilege: priv,
		Channel:   channel,
	}, nil
}

// userToProto converts a domain bmc.User into a proto BMCUser.
func userToProto(u bmc.User) *platformv1.BMCUser {
	priv, ok := privilegeToProto[u.Privilege]
	if !ok {
		priv = platformv1.BMCUserPrivilege_BMC_USER_PRIVILEGE_UNSPECIFIED
	}
	return &platformv1.BMCUser{
		Slot:      uint32(u.Slot),
		Username:  u.Username,
		Enabled:   u.Enabled,
		Privilege: priv,
		Channel:   uint32(u.Channel),
	}
}

// slotFromProto narrows a proto uint32 slot value into the uint8 the
// IPMI user APIs require. Returns an error for values that overflow.
func slotFromProto(slot uint32) (uint8, error) {
	if slot > math.MaxUint8 {
		return 0, ErrInvalidSlot{Slot: slot}
	}
	return uint8(slot), nil
}

// channelFromProto narrows a proto uint32 channel value into the uint8
// the IPMI user APIs require. Returns an error for values that overflow.
func channelFromProto(channel uint32) (uint8, error) {
	if channel > math.MaxUint8 {
		return 0, ErrInvalidChannel{Channel: channel}
	}
	return uint8(channel), nil
}

// timeToProto converts a time.Time to a protobuf timestamp. Returns nil
// for the zero time so the encoded proto omits the field.
func timeToProto(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t)
}

// certInfoToProto serializes a *bmc.CertificateInfo into the proto
// cert info shape. Returns an empty response for a nil info.
func certInfoToProto(info *bmc.CertificateInfo) *platformv1.BMCGetWebCertificateResponse {
	if info == nil {
		return &platformv1.BMCGetWebCertificateResponse{}
	}
	return &platformv1.BMCGetWebCertificateResponse{
		Subject:                 info.Subject,
		Issuer:                  info.Issuer,
		SerialNumber:            info.SerialNumber,
		NotBefore:               timeToProto(info.NotBefore),
		NotAfter:                timeToProto(info.NotAfter),
		DaysRemaining:           info.DaysRemaining,
		SubjectAlternativeNames: info.SubjectAlternativeNames,
		Fingerprint:             info.Fingerprint,
	}
}

// toGRPCError converts a domain BMC error into a gRPC status error.
func (s *BMCGRPCService) toGRPCError(operation string, err error) error {
	if err == nil {
		return nil
	}
	var profileNotFound bmc.ErrProfileNotFound
	if errors.As(err, &profileNotFound) {
		return status.Error(codes.NotFound, profileNotFound.Error())
	}
	var nilConfig bmc.ErrNilConfig
	if errors.As(err, &nilConfig) {
		return status.Error(codes.InvalidArgument, nilConfig.Error())
	}
	var invalidConfig bmc.ErrInvalidConfig
	if errors.As(err, &invalidConfig) {
		return status.Error(codes.InvalidArgument, invalidConfig.Error())
	}
	var unsupported bmc.ErrUnsupportedOperation
	if errors.As(err, &unsupported) {
		return status.Error(codes.Unimplemented, unsupported.Error())
	}
	var connFailed bmc.ErrConnectionFailed
	if errors.As(err, &connFailed) {
		return status.Error(codes.Unavailable, connFailed.Error())
	}
	var provNotFound baremetal.ErrProvisionNotFound
	if errors.As(err, &provNotFound) {
		return status.Error(codes.NotFound, provNotFound.Error())
	}
	var provInProgress baremetal.ErrProvisionInProgress
	if errors.As(err, &provInProgress) {
		return status.Error(codes.AlreadyExists, provInProgress.Error())
	}
	var invalidProvReq baremetal.ErrInvalidProvisionRequest
	if errors.As(err, &invalidProvReq) {
		return status.Error(codes.InvalidArgument, invalidProvReq.Error())
	}
	var profileNoBMC baremetal.ErrProfileNoBMC
	if errors.As(err, &profileNoBMC) {
		return status.Error(codes.FailedPrecondition, profileNoBMC.Error())
	}

	s.logger.Error("bmc grpc: operation failed",
		slog.String("operation", operation),
		slog.String("error", err.Error()))
	return status.Error(codes.Internal, err.Error())
}
