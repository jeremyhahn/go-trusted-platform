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
	"bytes"
	"context"
	"net"

	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/pxe"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/tlspeer"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// PXEGRPCService implements the PXE gRPC service for device provisioning operations.
// It provides PXE boot provisioning management including device registration,
// state transitions, and network authorization during the provisioning workflow.
type PXEGRPCService struct {
	platformv1.UnimplementedPXEServiceServer

	logger     *logging.Logger
	pxeService pxe.Service
}

// NewPXEGRPCService creates a new PXE gRPC service instance.
func NewPXEGRPCService(logger *logging.Logger, pxeService pxe.Service) *PXEGRPCService {
	return &PXEGRPCService{
		logger:     logger,
		pxeService: pxeService,
	}
}

// SetPXEService sets the PXE service for provisioning operations.
func (s *PXEGRPCService) SetPXEService(svc pxe.Service) {
	s.pxeService = svc
}

// requireService returns the canonical not-configured error when this
// node has no PXE backend. PXE is served by the GATEWAY role, so on a
// control plane an absent backend is the expected topology, not an
// operator error: the answer is codes.Unavailable (REST 503) carrying
// the SERVICE_NOT_CONFIGURED discriminator, so a client can render the
// role state instead of an alarm.
//
// It was previously codes.FailedPrecondition, which REST maps to 409 —
// a conflict with the resource's state, impossible to tell apart from a
// genuine precondition failure without reading the prose.
func (s *PXEGRPCService) requireService() error {
	if s.pxeService == nil {
		return serviceNotConfigured("pxe", "PXE service is not configured on this node")
	}
	return nil
}

// =============================================================================
// Device Registration and Management
// =============================================================================

// RegisterDevice registers a new device for PXE provisioning.
func (s *PXEGRPCService) RegisterDevice(ctx context.Context, req *platformv1.RegisterPXEDeviceRequest) (*platformv1.RegisterPXEDeviceResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}

	macAddress := req.GetMacAddress()
	if macAddress == "" {
		return nil, status.Error(codes.InvalidArgument, "MAC address is required")
	}

	portID := req.GetPortId()
	if portID == "" {
		return nil, status.Error(codes.InvalidArgument, "port ID is required")
	}

	device, err := s.pxeService.RegisterDevice(ctx, macAddress, portID)
	if err != nil {
		s.logger.Error(err, "Failed to register device", "mac_address", macAddress, "port_id", portID)
		return nil, s.mapPXEError(err, "register device")
	}

	s.logger.Info("Device registered via gRPC", "device_id", device.ID, "mac_address", macAddress)

	return &platformv1.RegisterPXEDeviceResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "device registered successfully",
		},
		Device: s.deviceToProto(device),
	}, nil
}

// GetDevice retrieves a device by its ID.
func (s *PXEGRPCService) GetDevice(ctx context.Context, req *platformv1.GetPXEDeviceRequest) (*platformv1.GetPXEDeviceResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}

	deviceID := req.GetDeviceId()
	if deviceID == "" {
		return nil, status.Error(codes.InvalidArgument, "device ID is required")
	}

	device, err := s.pxeService.GetDevice(ctx, deviceID)
	if err != nil {
		return nil, s.mapPXEError(err, "get device")
	}

	return &platformv1.GetPXEDeviceResponse{
		Device: s.deviceToProto(device),
	}, nil
}

// GetDeviceByMAC retrieves a device by its MAC address.
func (s *PXEGRPCService) GetDeviceByMAC(ctx context.Context, req *platformv1.GetPXEDeviceByMACRequest) (*platformv1.GetPXEDeviceByMACResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}

	macAddress := req.GetMacAddress()
	if macAddress == "" {
		return nil, status.Error(codes.InvalidArgument, "MAC address is required")
	}

	device, err := s.pxeService.GetDeviceByMAC(ctx, macAddress)
	if err != nil {
		return nil, s.mapPXEError(err, "get device by MAC")
	}

	return &platformv1.GetPXEDeviceByMACResponse{
		Device: s.deviceToProto(device),
	}, nil
}

// ListDevices returns all devices matching the provided filter. When
// this node has no PXE backend the call answers the not-configured
// status rather than an empty list, so a dashboard renders the
// gateway-role state instead of an indistinguishable "no devices".
func (s *PXEGRPCService) ListDevices(ctx context.Context, req *platformv1.ListPXEDevicesRequest) (*platformv1.ListPXEDevicesResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}

	filter := s.filterFromProto(req.GetFilter())

	devices, err := s.pxeService.ListDevices(ctx, filter)
	if err != nil {
		s.logger.Error(err, "Failed to list devices")
		return nil, s.mapPXEError(err, "list devices")
	}

	protoDevices := make([]*platformv1.PXEDeviceInfo, len(devices))
	for i, device := range devices {
		protoDevices[i] = s.deviceToProto(device)
	}

	return &platformv1.ListPXEDevicesResponse{
		Devices:    protoDevices,
		TotalCount: int32(len(devices)),
	}, nil
}

// RemoveDevice removes a device from the PXE service.
func (s *PXEGRPCService) RemoveDevice(ctx context.Context, req *platformv1.RemovePXEDeviceRequest) (*platformv1.RemovePXEDeviceResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}

	deviceID := req.GetDeviceId()
	if deviceID == "" {
		return nil, status.Error(codes.InvalidArgument, "device ID is required")
	}

	if err := s.pxeService.RemoveDevice(ctx, deviceID); err != nil {
		s.logger.Error(err, "Failed to remove device", "device_id", deviceID)
		return nil, s.mapPXEError(err, "remove device")
	}

	s.logger.Info("Device removed via gRPC", "device_id", deviceID)

	return &platformv1.RemovePXEDeviceResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "device removed successfully",
		},
	}, nil
}

// =============================================================================
// State Transitions
// =============================================================================

// UpdateState transitions a device to a new provisioning state.
func (s *PXEGRPCService) UpdateState(ctx context.Context, req *platformv1.UpdatePXEStateRequest) (*platformv1.UpdatePXEStateResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}

	deviceID := req.GetDeviceId()
	if deviceID == "" {
		return nil, status.Error(codes.InvalidArgument, "device ID is required")
	}

	state := s.stateFromProto(req.GetState())
	reason := req.GetReason()

	var err error
	if installCert := req.GetInstallCertificateSha256(); installCert != "" {
		if state != pxe.StateInstalling {
			return nil, status.Error(codes.InvalidArgument,
				ErrPXEInstallCertificateState{State: string(state)}.Error())
		}
		err = s.pxeService.SetDeviceInstalling(ctx, deviceID, installCert, reason)
	} else {
		err = s.pxeService.UpdateDeviceState(ctx, deviceID, state, reason)
	}
	if err != nil {
		s.logger.Error(err, "Failed to update device state", "device_id", deviceID, "state", state)
		return nil, s.mapPXEError(err, "update state")
	}

	device, err := s.pxeService.GetDevice(ctx, deviceID)
	if err != nil {
		return nil, s.mapPXEError(err, "get device after state update")
	}

	s.logger.Info("Device state updated via gRPC", "device_id", deviceID, "state", state)

	return &platformv1.UpdatePXEStateResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "state updated successfully",
		},
		Device: s.deviceToProto(device),
	}, nil
}

// SetDeviceEnrolled marks a device as enrolled with the provided certificate serial.
func (s *PXEGRPCService) SetDeviceEnrolled(ctx context.Context, req *platformv1.SetPXEDeviceEnrolledRequest) (*platformv1.SetPXEDeviceEnrolledResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}

	deviceID := req.GetDeviceId()
	if deviceID == "" {
		return nil, status.Error(codes.InvalidArgument, "device ID is required")
	}

	certSerial := req.GetCertificateSerial()
	if certSerial == "" {
		return nil, status.Error(codes.InvalidArgument, "certificate serial is required")
	}

	if err := s.pxeService.SetDeviceEnrolled(ctx, deviceID, certSerial); err != nil {
		s.logger.Error(err, "Failed to set device enrolled", "device_id", deviceID)
		return nil, s.mapPXEError(err, "set device enrolled")
	}

	device, err := s.pxeService.GetDevice(ctx, deviceID)
	if err != nil {
		return nil, s.mapPXEError(err, "get device after enrollment")
	}

	s.logger.Info("Device marked enrolled via gRPC", "device_id", deviceID, "cert_serial", certSerial)

	return &platformv1.SetPXEDeviceEnrolledResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "device enrolled successfully",
		},
		Device: s.deviceToProto(device),
	}, nil
}

// Authorize authorizes a device for production network access.
func (s *PXEGRPCService) Authorize(ctx context.Context, req *platformv1.AuthorizePXEDeviceRequest) (*platformv1.AuthorizePXEDeviceResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}

	deviceID := req.GetDeviceId()
	if deviceID == "" {
		return nil, status.Error(codes.InvalidArgument, "device ID is required")
	}

	targetVLAN := uint16(req.GetTargetVlan())
	if targetVLAN == 0 {
		return nil, status.Error(codes.InvalidArgument, "target VLAN is required")
	}

	if err := s.pxeService.AuthorizeDevice(ctx, deviceID, targetVLAN); err != nil {
		s.logger.Error(err, "Failed to authorize device", "device_id", deviceID, "target_vlan", targetVLAN)
		return nil, s.mapPXEError(err, "authorize device")
	}

	device, err := s.pxeService.GetDevice(ctx, deviceID)
	if err != nil {
		return nil, s.mapPXEError(err, "get device after authorization")
	}

	s.logger.Info("Device authorized via gRPC", "device_id", deviceID, "target_vlan", targetVLAN)

	return &platformv1.AuthorizePXEDeviceResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "device authorized successfully",
		},
		Device: s.deviceToProto(device),
	}, nil
}

// Quarantine moves a device to quarantine state.
func (s *PXEGRPCService) Quarantine(ctx context.Context, req *platformv1.QuarantinePXEDeviceRequest) (*platformv1.QuarantinePXEDeviceResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}

	deviceID := req.GetDeviceId()
	if deviceID == "" {
		return nil, status.Error(codes.InvalidArgument, "device ID is required")
	}

	reason := req.GetReason()
	if reason == "" {
		return nil, status.Error(codes.InvalidArgument, "reason is required")
	}

	if err := s.pxeService.QuarantineDevice(ctx, deviceID, reason); err != nil {
		s.logger.Error(err, "Failed to quarantine device", "device_id", deviceID, "reason", reason)
		return nil, s.mapPXEError(err, "quarantine device")
	}

	device, err := s.pxeService.GetDevice(ctx, deviceID)
	if err != nil {
		return nil, s.mapPXEError(err, "get device after quarantine")
	}

	s.logger.Warn("Device quarantined via gRPC", "device_id", deviceID, "reason", reason)

	return &platformv1.QuarantinePXEDeviceResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "device quarantined successfully",
		},
		Device: s.deviceToProto(device),
	}, nil
}

// Retry resets a device to discovered state for retry.
func (s *PXEGRPCService) Retry(ctx context.Context, req *platformv1.RetryPXEDeviceRequest) (*platformv1.RetryPXEDeviceResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}

	deviceID := req.GetDeviceId()
	if deviceID == "" {
		return nil, status.Error(codes.InvalidArgument, "device ID is required")
	}

	if err := s.pxeService.RetryDevice(ctx, deviceID); err != nil {
		s.logger.Error(err, "Failed to retry device", "device_id", deviceID)
		return nil, s.mapPXEError(err, "retry device")
	}

	device, err := s.pxeService.GetDevice(ctx, deviceID)
	if err != nil {
		return nil, s.mapPXEError(err, "get device after retry")
	}

	s.logger.Info("Device retry initiated via gRPC", "device_id", deviceID)

	return &platformv1.RetryPXEDeviceResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "device retry initiated successfully",
		},
		Device: s.deviceToProto(device),
	}, nil
}

// =============================================================================
// Events
// =============================================================================

// GetEvents retrieves all events for a device.
func (s *PXEGRPCService) GetEvents(ctx context.Context, req *platformv1.GetPXEEventsRequest) (*platformv1.GetPXEEventsResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}

	deviceID := req.GetDeviceId()
	if deviceID == "" {
		return nil, status.Error(codes.InvalidArgument, "device ID is required")
	}

	events, err := s.pxeService.GetEvents(ctx, deviceID)
	if err != nil {
		return nil, s.mapPXEError(err, "get events")
	}

	protoEvents := make([]*platformv1.ProvisioningEvent, len(events))
	for i, event := range events {
		protoEvents[i] = s.eventToProto(event)
	}

	return &platformv1.GetPXEEventsResponse{
		Events: protoEvents,
	}, nil
}

// =============================================================================
// Service Lifecycle
// =============================================================================

// GetStatus returns the current status of the PXE provisioning service.
// When this node has no PXE backend the call answers the not-configured
// status; a synthetic "stopped" would be a lie, since stopped means a
// configured service an operator can start here.
func (s *PXEGRPCService) GetStatus(ctx context.Context, req *platformv1.GetPXEStatusRequest) (*platformv1.GetPXEStatusResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}

	svcStatus := s.pxeService.Status()

	return &platformv1.GetPXEStatusResponse{
		Status: s.statusToProto(svcStatus),
	}, nil
}

// StartService starts the PXE provisioning service.
func (s *PXEGRPCService) StartService(ctx context.Context, req *platformv1.StartPXEServiceRequest) (*platformv1.StartPXEServiceResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}

	if err := s.pxeService.Start(ctx); err != nil {
		s.logger.Error(err, "Failed to start PXE service")
		return nil, s.mapPXEError(err, "start service")
	}

	s.logger.Info("PXE service started via gRPC")

	return &platformv1.StartPXEServiceResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "PXE service started successfully",
		},
	}, nil
}

// StopService stops the PXE provisioning service.
func (s *PXEGRPCService) StopService(ctx context.Context, req *platformv1.StopPXEServiceRequest) (*platformv1.StopPXEServiceResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}

	if err := s.pxeService.Stop(ctx); err != nil {
		s.logger.Error(err, "Failed to stop PXE service")
		return nil, s.mapPXEError(err, "stop service")
	}

	s.logger.Info("PXE service stopped via gRPC")

	return &platformv1.StopPXEServiceResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "PXE service stopped successfully",
		},
	}, nil
}

// =============================================================================
// Webhook
// =============================================================================

// WebhookComplete handles the callback when OS installation completes.
func (s *PXEGRPCService) WebhookComplete(ctx context.Context, req *platformv1.PXEWebhookCompleteRequest) (*platformv1.PXEWebhookCompleteResponse, error) {
	if err := s.requireService(); err != nil {
		return nil, err
	}

	device, err := s.webhookDevice(ctx, req.GetMacAddress())
	if err != nil {
		s.logger.Error(err, "Refused PXE webhook", "mac_address", req.GetMacAddress())
		return nil, err
	}

	var newState pxe.ProvisioningState
	var reason string

	if req.GetSuccess() {
		newState = pxe.StateInstallComplete
		reason = "OS installation completed successfully"
		if req.GetMessage() != "" {
			reason = reason + ": " + req.GetMessage()
		}
	} else {
		newState = pxe.StateFailed
		reason = "OS installation failed"
		if req.GetMessage() != "" {
			reason = reason + ": " + req.GetMessage()
		}
	}

	if err := s.pxeService.UpdateDeviceState(ctx, device.ID, newState, reason); err != nil {
		s.logger.Error(err, "Failed to update device state from webhook", "device_id", device.ID)
		return nil, s.mapPXEError(err, "update state from webhook")
	}

	s.logger.Info("Webhook processed",
		"device_id", device.ID,
		"mac_address", device.MACAddress.String(),
		"hostname", req.GetHostname(),
		"success", req.GetSuccess(),
	)

	return &platformv1.PXEWebhookCompleteResponse{
		Status: &platformv1.Status{
			Success: true,
			Message: "webhook processed successfully",
		},
	}, nil
}

// webhookDevice returns the device the install-completion webhook is from.
// The identity is the verified client certificate of the connection (#238),
// resolved the same way on every transport by requestChannel; the device is
// the one whose installer certificate fingerprint, bound by UpdateState as the
// device entered installing, is the SHA-256 of the leaf's DER. Enrollment
// follows install_complete, so the enrolled certificate cannot serve here. The
// body MAC is never an identity: when present it must be that device's MAC. A
// connection without a verified certificate is Unauthenticated; an unbound
// certificate or a mismatched MAC is
// PermissionDenied. Every refusal happens before any state is written.
func (s *PXEGRPCService) webhookDevice(ctx context.Context, bodyMAC string) (*pxe.DeviceInfo, error) {
	state, transport := requestChannel(ctx)
	leaf, err := tlspeer.VerifiedLeaf(state)
	if err != nil {
		return nil, status.Error(codes.Unauthenticated,
			ErrPXEWebhookIdentityRequired{Transport: transport, Reason: err.Error()}.Error())
	}
	if len(leaf.Raw) == 0 {
		return nil, status.Error(codes.Unauthenticated,
			ErrPXEWebhookIdentityRequired{Transport: transport, Reason: "the verified certificate has no DER encoding"}.Error())
	}

	// The whole certificate is the identity: a serial is unique only within
	// one issuer, and the listener admits more than one.
	fingerprint := pxe.CertificateSHA256(leaf.Raw)
	devices, err := s.pxeService.ListDevices(ctx, &pxe.DeviceFilter{InstallCertificateSHA256: fingerprint})
	if err != nil {
		return nil, s.mapPXEError(err, "find device for webhook")
	}
	if len(devices) != 1 {
		return nil, status.Error(codes.PermissionDenied,
			ErrPXEWebhookUnknownIdentity{CertificateSHA256: fingerprint, Matches: len(devices)}.Error())
	}
	device := devices[0]

	if bodyMAC == "" {
		return device, nil
	}
	mac, err := net.ParseMAC(bodyMAC)
	if err != nil {
		return nil, status.Error(codes.InvalidArgument,
			pxe.ErrInvalidMACAddress{MACAddress: bodyMAC, Reason: err.Error()}.Error())
	}
	if !bytes.Equal(mac, device.MACAddress) {
		return nil, status.Error(codes.PermissionDenied,
			ErrPXEWebhookIdentityMismatch{CertificateSHA256: fingerprint, MACAddress: bodyMAC}.Error())
	}
	return device, nil
}

// =============================================================================
// Helper Functions - Type Conversions
// =============================================================================

// deviceToProto converts a pxe.DeviceInfo to a proto message.
func (s *PXEGRPCService) deviceToProto(device *pxe.DeviceInfo) *platformv1.PXEDeviceInfo {
	if device == nil {
		return nil
	}

	info := &platformv1.PXEDeviceInfo{
		Id:                       device.ID,
		MacAddress:               device.MACAddress.String(),
		PortId:                   device.PortID,
		State:                    s.stateToProto(device.State),
		StateReason:              device.StateReason,
		CertificateSerial:        device.CertificateSerial,
		InstallCertificateSha256: device.InstallCertificateSHA256,
		CurrentVlan:              uint32(device.CurrentVLAN),
		TargetVlan:               uint32(device.TargetVLAN),
		CreatedAt:                timestamppb.New(device.CreatedAt),
		UpdatedAt:                timestamppb.New(device.UpdatedAt),
		StateChangedAt:           timestamppb.New(device.StateChangedAt),
		RetryCount:               int32(device.RetryCount),
	}

	if device.Events != nil {
		info.Events = make([]*platformv1.ProvisioningEvent, len(device.Events))
		for i, event := range device.Events {
			info.Events[i] = s.eventToProto(event)
		}
	}

	return info
}

// eventToProto converts a pxe.ProvisioningEvent to a proto message.
func (s *PXEGRPCService) eventToProto(event *pxe.ProvisioningEvent) *platformv1.ProvisioningEvent {
	if event == nil {
		return nil
	}

	return &platformv1.ProvisioningEvent{
		Id:        event.ID,
		DeviceId:  event.DeviceID,
		Timestamp: timestamppb.New(event.Timestamp),
		EventType: s.eventTypeToProto(event.EventType),
		FromState: s.stateToProto(event.FromState),
		ToState:   s.stateToProto(event.ToState),
		Details:   event.Details,
		Error:     event.Error,
	}
}

// statusToProto converts a pxe.ServiceStatus to a proto message.
func (s *PXEGRPCService) statusToProto(svcStatus *pxe.ServiceStatus) *platformv1.PXEServiceStatus {
	if svcStatus == nil {
		return nil
	}

	return &platformv1.PXEServiceStatus{
		Running:          svcStatus.Running,
		DeviceCount:      int32(svcStatus.DeviceCount),
		StartTime:        timestamppb.New(svcStatus.StartTime),
		IpxeServerAddr:   svcStatus.IPXEServerAddr,
		QuarantineVlan:   uint32(svcStatus.QuarantineVLAN),
		ProvisioningVlan: uint32(svcStatus.ProvisioningVLAN),
	}
}

// stateToProto converts a pxe.ProvisioningState to a proto enum.
func (s *PXEGRPCService) stateToProto(state pxe.ProvisioningState) platformv1.ProvisioningState {
	switch state {
	case pxe.StateUnknown:
		return platformv1.ProvisioningState_PROVISIONING_STATE_UNKNOWN
	case pxe.StateDiscovered:
		return platformv1.ProvisioningState_PROVISIONING_STATE_DISCOVERED
	case pxe.StateBooting:
		return platformv1.ProvisioningState_PROVISIONING_STATE_BOOTING
	case pxe.StateInstalling:
		return platformv1.ProvisioningState_PROVISIONING_STATE_INSTALLING
	case pxe.StateInstallComplete:
		return platformv1.ProvisioningState_PROVISIONING_STATE_INSTALL_COMPLETE
	case pxe.StateEnrolling:
		return platformv1.ProvisioningState_PROVISIONING_STATE_ENROLLING
	case pxe.StateEnrolled:
		return platformv1.ProvisioningState_PROVISIONING_STATE_ENROLLED
	case pxe.StateAuthorizing:
		return platformv1.ProvisioningState_PROVISIONING_STATE_AUTHORIZING
	case pxe.StateAuthorized:
		return platformv1.ProvisioningState_PROVISIONING_STATE_AUTHORIZED
	case pxe.StateFailed:
		return platformv1.ProvisioningState_PROVISIONING_STATE_FAILED
	case pxe.StateQuarantined:
		return platformv1.ProvisioningState_PROVISIONING_STATE_QUARANTINED
	default:
		return platformv1.ProvisioningState_PROVISIONING_STATE_UNSPECIFIED
	}
}

// stateFromProto converts a proto enum to a pxe.ProvisioningState.
func (s *PXEGRPCService) stateFromProto(state platformv1.ProvisioningState) pxe.ProvisioningState {
	switch state {
	case platformv1.ProvisioningState_PROVISIONING_STATE_UNKNOWN:
		return pxe.StateUnknown
	case platformv1.ProvisioningState_PROVISIONING_STATE_DISCOVERED:
		return pxe.StateDiscovered
	case platformv1.ProvisioningState_PROVISIONING_STATE_BOOTING:
		return pxe.StateBooting
	case platformv1.ProvisioningState_PROVISIONING_STATE_INSTALLING:
		return pxe.StateInstalling
	case platformv1.ProvisioningState_PROVISIONING_STATE_INSTALL_COMPLETE:
		return pxe.StateInstallComplete
	case platformv1.ProvisioningState_PROVISIONING_STATE_ENROLLING:
		return pxe.StateEnrolling
	case platformv1.ProvisioningState_PROVISIONING_STATE_ENROLLED:
		return pxe.StateEnrolled
	case platformv1.ProvisioningState_PROVISIONING_STATE_AUTHORIZING:
		return pxe.StateAuthorizing
	case platformv1.ProvisioningState_PROVISIONING_STATE_AUTHORIZED:
		return pxe.StateAuthorized
	case platformv1.ProvisioningState_PROVISIONING_STATE_FAILED:
		return pxe.StateFailed
	case platformv1.ProvisioningState_PROVISIONING_STATE_QUARANTINED:
		return pxe.StateQuarantined
	default:
		return pxe.StateUnknown
	}
}

// eventTypeToProto converts a pxe.ProvisioningEventType to a proto enum.
func (s *PXEGRPCService) eventTypeToProto(eventType pxe.ProvisioningEventType) platformv1.ProvisioningEventType {
	switch eventType {
	case pxe.EventDeviceDiscovered:
		return platformv1.ProvisioningEventType_PROVISIONING_EVENT_TYPE_DEVICE_DISCOVERED
	case pxe.EventPXEBootStarted:
		return platformv1.ProvisioningEventType_PROVISIONING_EVENT_TYPE_PXE_BOOT_STARTED
	case pxe.EventInstallStarted:
		return platformv1.ProvisioningEventType_PROVISIONING_EVENT_TYPE_INSTALL_STARTED
	case pxe.EventInstallCompleted:
		return platformv1.ProvisioningEventType_PROVISIONING_EVENT_TYPE_INSTALL_COMPLETED
	case pxe.EventEnrollmentStarted:
		return platformv1.ProvisioningEventType_PROVISIONING_EVENT_TYPE_ENROLLMENT_STARTED
	case pxe.EventEnrollmentCompleted:
		return platformv1.ProvisioningEventType_PROVISIONING_EVENT_TYPE_ENROLLMENT_COMPLETED
	case pxe.EventAuthorizationStarted:
		return platformv1.ProvisioningEventType_PROVISIONING_EVENT_TYPE_AUTHORIZATION_STARTED
	case pxe.EventAuthorizationCompleted:
		return platformv1.ProvisioningEventType_PROVISIONING_EVENT_TYPE_AUTHORIZATION_COMPLETED
	case pxe.EventQuarantined:
		return platformv1.ProvisioningEventType_PROVISIONING_EVENT_TYPE_QUARANTINED
	case pxe.EventFailed:
		return platformv1.ProvisioningEventType_PROVISIONING_EVENT_TYPE_FAILED
	case pxe.EventRetry:
		return platformv1.ProvisioningEventType_PROVISIONING_EVENT_TYPE_RETRY
	default:
		return platformv1.ProvisioningEventType_PROVISIONING_EVENT_TYPE_UNSPECIFIED
	}
}

// filterFromProto converts a proto filter to a pxe.DeviceFilter.
func (s *PXEGRPCService) filterFromProto(filter *platformv1.PXEDeviceFilter) *pxe.DeviceFilter {
	if filter == nil {
		return nil
	}

	// An unset state means "any state". stateFromProto answers
	// StateUnknown for it, which would narrow a VLAN- or MAC-only
	// filter to devices in the "unknown" state and return none (#975).
	var state pxe.ProvisioningState
	if filter.GetState() != platformv1.ProvisioningState_PROVISIONING_STATE_UNSPECIFIED {
		state = s.stateFromProto(filter.GetState())
	}

	return &pxe.DeviceFilter{
		State:      state,
		MACAddress: filter.GetMacAddress(),
		VLAN:       uint16(filter.GetVlan()),
		Limit:      int(filter.GetLimit()),
		Offset:     int(filter.GetOffset()),
	}
}

// =============================================================================
// Error Mapping
// =============================================================================

// mapPXEError maps PXE service errors to gRPC status errors.
func (s *PXEGRPCService) mapPXEError(err error, operation string) error {
	if err == nil {
		return nil
	}

	// Check for typed errors from the PXE package
	switch e := err.(type) {
	case pxe.ErrDeviceNotFound:
		return status.Errorf(codes.NotFound, "device not found: %s", e.DeviceID)
	case pxe.ErrDeviceAlreadyExists:
		return status.Errorf(codes.AlreadyExists, "device already exists: %s", e.MACAddress)
	case pxe.ErrInvalidMACAddress:
		return status.Errorf(codes.InvalidArgument, "invalid MAC address: %s", e.MACAddress)
	case pxe.ErrInvalidState:
		return status.Errorf(codes.InvalidArgument, "invalid state: %s", e.Reason)
	case pxe.ErrInvalidCertificateFingerprint:
		return status.Error(codes.InvalidArgument, e.Error())
	case pxe.ErrInvalidStateTransition:
		return status.Errorf(codes.FailedPrecondition, "invalid state transition from %s to %s: %s",
			e.FromState, e.ToState, e.Reason)
	case pxe.ErrServiceNotInitialized:
		return status.Error(codes.FailedPrecondition, "PXE service not initialized")
	case pxe.ErrServiceAlreadyRunning:
		return status.Error(codes.FailedPrecondition, "PXE service already running")
	case pxe.ErrServiceNotRunning:
		return status.Error(codes.FailedPrecondition, "PXE service not running")
	case pxe.ErrMaxRetriesExceeded:
		return status.Errorf(codes.ResourceExhausted, "max retries exceeded: %s", e.Reason)
	case pxe.ErrVLANTransitionFailed:
		return status.Errorf(codes.Internal, "VLAN transition failed: %s", e.Reason)
	case pxe.ErrProvisioningFailed:
		return status.Errorf(codes.Internal, "provisioning failed: %s", e.Reason)
	case pxe.ErrInvalidConfiguration:
		return status.Errorf(codes.InvalidArgument, "invalid configuration: %s", e.Reason)
	default:
		return status.Errorf(codes.Internal, "failed to %s: %s", operation, err.Error())
	}
}
