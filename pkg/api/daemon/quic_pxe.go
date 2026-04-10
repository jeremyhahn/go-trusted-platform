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
	"strconv"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/compute/pxe"
)

// PXE QUIC opcodes - aliased from quic.protocol for convenience
// Primary PXE Operations (0xEC-0xEF)
const (
	OpPXEListDevices    = quic.OpPXEListDevices    // 0xEC
	OpPXEGetDevice      = quic.OpPXEGetDevice      // 0xED
	OpPXERegisterDevice = quic.OpPXERegisterDevice // 0xEE
	OpPXEUpdateState    = quic.OpPXEUpdateState    // 0xEF
)

// Extended PXE Operations (0xFC-0xFF)
const (
	OpPXEAuthorize    = quic.OpPXEAuthorize    // 0xFC
	OpPXEQuarantine   = quic.OpPXEQuarantine   // 0xFD
	OpPXERetry        = quic.OpPXERetry        // 0xFE
	OpPXERemoveDevice = quic.OpPXERemoveDevice // 0xFF
)

// Extended PXE Operations (using extended opcode space)
const (
	OpPXEStatus            = quic.OpPXEStatus            // 0x00 (extended)
	OpPXEStart             = quic.OpPXEStart             // 0x01 (extended)
	OpPXEStop              = quic.OpPXEStop              // 0x02 (extended)
	OpPXEWebhookComplete   = quic.OpPXEWebhookComplete   // 0x03 (extended)
	OpPXEGetDeviceByMAC    = quic.OpPXEGetDeviceByMAC    // 0x04 (extended)
	OpPXESetDeviceEnrolled = quic.OpPXESetDeviceEnrolled // 0x05 (extended)
	OpPXEGetEvents         = quic.OpPXEGetEvents         // 0x06 (extended)
)

// =============================================================================
// Request/Response Types
// =============================================================================

// PXEListDevicesRequest represents a request to list PXE provisioning devices
type PXEListDevicesRequest struct {
	State      string `codec:"state,omitempty"`
	MACAddress string `codec:"mac_address,omitempty"`
	VLAN       uint16 `codec:"vlan,omitempty"`
	Limit      int    `codec:"limit,omitempty"`
	Offset     int    `codec:"offset,omitempty"`
}

// PXEDevice represents a device in the PXE provisioning workflow for QUIC responses
type PXEDevice struct {
	ID                string            `codec:"id"`
	MACAddress        string            `codec:"mac_address"`
	PortID            string            `codec:"port_id"`
	State             string            `codec:"state"`
	StateReason       string            `codec:"state_reason,omitempty"`
	CertificateSerial string            `codec:"certificate_serial,omitempty"`
	CurrentVLAN       uint16            `codec:"current_vlan"`
	TargetVLAN        uint16            `codec:"target_vlan"`
	CreatedAt         int64             `codec:"created_at"`
	UpdatedAt         int64             `codec:"updated_at"`
	StateChangedAt    int64             `codec:"state_changed_at"`
	RetryCount        int               `codec:"retry_count"`
	ProfileID         string            `codec:"profile_id,omitempty"`
	ProfileName       string            `codec:"profile_name,omitempty"`
	Metadata          map[string]string `codec:"metadata,omitempty"`
}

// PXEListDevicesResponse represents a response containing PXE devices
type PXEListDevicesResponse struct {
	Devices   []*PXEDevice `codec:"devices"`
	Total     int          `codec:"total"`
	Timestamp int64        `codec:"timestamp"`
}

// PXEGetDeviceRequest represents a request to get a specific device
type PXEGetDeviceRequest struct {
	DeviceID   string `codec:"device_id,omitempty"`
	MACAddress string `codec:"mac_address,omitempty"`
}

// PXEGetDeviceResponse represents a response containing a single device
type PXEGetDeviceResponse struct {
	Device    *PXEDevice `codec:"device"`
	Timestamp int64      `codec:"timestamp"`
}

// PXEGetDeviceByMACRequest represents a request to get a device by MAC address
type PXEGetDeviceByMACRequest struct {
	MACAddress string `codec:"mac_address"`
}

// PXEGetDeviceByMACResponse represents a response containing a device looked up by MAC
type PXEGetDeviceByMACResponse struct {
	Device    *PXEDevice `codec:"device"`
	Timestamp int64      `codec:"timestamp"`
}

// PXERegisterDeviceRequest represents a request to register a new device
type PXERegisterDeviceRequest struct {
	MACAddress string `codec:"mac_address"`
	PortID     string `codec:"port_id"`
}

// PXERegisterDeviceResponse represents a response after registering a device
type PXERegisterDeviceResponse struct {
	Device    *PXEDevice `codec:"device"`
	Timestamp int64      `codec:"timestamp"`
}

// PXEUpdateStateRequest represents a request to update device provisioning state
type PXEUpdateStateRequest struct {
	DeviceID string `codec:"device_id"`
	State    string `codec:"state"`
	Reason   string `codec:"reason,omitempty"`
}

// PXEUpdateStateResponse represents a response after updating device state
type PXEUpdateStateResponse struct {
	DeviceID  string `codec:"device_id"`
	OldState  string `codec:"old_state"`
	NewState  string `codec:"new_state"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// PXESetDeviceEnrolledRequest represents a request to mark a device as enrolled
type PXESetDeviceEnrolledRequest struct {
	DeviceID          string `codec:"device_id"`
	CertificateSerial string `codec:"certificate_serial"`
}

// PXESetDeviceEnrolledResponse represents a response after setting device enrolled
type PXESetDeviceEnrolledResponse struct {
	Device    *PXEDevice `codec:"device"`
	Success   bool       `codec:"success"`
	Timestamp int64      `codec:"timestamp"`
}

// PXEAuthorizeRequest represents a request to authorize a device
type PXEAuthorizeRequest struct {
	DeviceID   string `codec:"device_id"`
	TargetVLAN uint16 `codec:"target_vlan"`
}

// PXEAuthorizeResponse represents a response after authorizing a device
type PXEAuthorizeResponse struct {
	DeviceID   string `codec:"device_id"`
	TargetVLAN uint16 `codec:"target_vlan"`
	Success    bool   `codec:"success"`
	Timestamp  int64  `codec:"timestamp"`
}

// PXEQuarantineRequest represents a request to quarantine a device
type PXEQuarantineRequest struct {
	DeviceID string `codec:"device_id"`
	Reason   string `codec:"reason"`
}

// PXEQuarantineResponse represents a response after quarantining a device
type PXEQuarantineResponse struct {
	DeviceID  string `codec:"device_id"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// PXERetryRequest represents a request to retry provisioning for a device
type PXERetryRequest struct {
	DeviceID string `codec:"device_id"`
}

// PXERetryResponse represents a response after initiating a retry
type PXERetryResponse struct {
	DeviceID   string `codec:"device_id"`
	RetryCount int    `codec:"retry_count"`
	Success    bool   `codec:"success"`
	Timestamp  int64  `codec:"timestamp"`
}

// PXEGetEventsRequest represents a request to get events for a device
type PXEGetEventsRequest struct {
	DeviceID string `codec:"device_id"`
}

// PXEEvent represents a provisioning event for QUIC responses
type PXEEvent struct {
	ID        string            `codec:"id"`
	DeviceID  string            `codec:"device_id"`
	Timestamp int64             `codec:"timestamp"`
	EventType string            `codec:"event_type"`
	FromState string            `codec:"from_state"`
	ToState   string            `codec:"to_state"`
	Details   map[string]string `codec:"details,omitempty"`
	Error     string            `codec:"error,omitempty"`
}

// PXEGetEventsResponse represents a response containing device events
type PXEGetEventsResponse struct {
	Events    []*PXEEvent `codec:"events"`
	Timestamp int64       `codec:"timestamp"`
}

// PXERemoveDeviceRequest represents a request to remove a device
type PXERemoveDeviceRequest struct {
	DeviceID string `codec:"device_id"`
}

// PXERemoveDeviceResponse represents a response after removing a device
type PXERemoveDeviceResponse struct {
	DeviceID  string `codec:"device_id"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// PXEStatusRequest represents a request to get PXE service status
type PXEStatusRequest struct{}

// PXEStatusResponse represents a response containing PXE service status
type PXEStatusResponse struct {
	Running          bool   `codec:"running"`
	DeviceCount      int    `codec:"device_count"`
	StartTime        int64  `codec:"start_time"`
	IPXEServerAddr   string `codec:"ipxe_server_addr"`
	QuarantineVLAN   uint16 `codec:"quarantine_vlan"`
	ProvisioningVLAN uint16 `codec:"provisioning_vlan"`
	Timestamp        int64  `codec:"timestamp"`
}

// PXEStartRequest represents a request to start the PXE service
type PXEStartRequest struct{}

// PXEStartResponse represents a response after starting the PXE service
type PXEStartResponse struct {
	Success   bool   `codec:"success"`
	Message   string `codec:"message,omitempty"`
	Timestamp int64  `codec:"timestamp"`
}

// PXEStopRequest represents a request to stop the PXE service
type PXEStopRequest struct{}

// PXEStopResponse represents a response after stopping the PXE service
type PXEStopResponse struct {
	Success   bool   `codec:"success"`
	Message   string `codec:"message,omitempty"`
	Timestamp int64  `codec:"timestamp"`
}

// PXEWebhookCompleteRequest represents a webhook completion notification
type PXEWebhookCompleteRequest struct {
	MACAddress string `codec:"mac_address"`
	Hostname   string `codec:"hostname"`
	Success    bool   `codec:"success"`
	Message    string `codec:"message,omitempty"`
}

// PXEWebhookCompleteResponse represents a response after processing webhook
type PXEWebhookCompleteResponse struct {
	DeviceID  string `codec:"device_id"`
	NewState  string `codec:"new_state"`
	Success   bool   `codec:"success"`
	Timestamp int64  `codec:"timestamp"`
}

// =============================================================================
// Service Handler Extension
// =============================================================================

// WithQUICPXEService sets the PXE service for the QUIC handler
func WithQUICPXEService(svc pxe.Service) QUICServiceHandlerOption {
	return func(h *QUICServiceHandler) {
		h.pxeService = svc
	}
}

// SetPXEService sets the PXE service after construction
func (h *QUICServiceHandler) SetPXEService(svc pxe.Service) {
	h.pxeService = svc
}

// =============================================================================
// Handler Implementation
// =============================================================================

// handlePXEOperation routes PXE operations to their handlers
func (h *QUICServiceHandler) handlePXEOperation(ctx context.Context, req *quic.Request) *quic.Response {
	if h.pxeService == nil {
		return h.errorResponse(quic.StatusUnavailable, ErrQUICServiceUnavailable{Service: "pxe"})
	}

	switch req.Opcode {
	// Primary operations (0xEC-0xEF)
	case OpPXEListDevices:
		return h.handlePXEListDevices(ctx, req)
	case OpPXEGetDevice:
		return h.handlePXEGetDevice(ctx, req)
	case OpPXERegisterDevice:
		return h.handlePXERegisterDevice(ctx, req)
	case OpPXEUpdateState:
		return h.handlePXEUpdateState(ctx, req)
	// Extended operations (0xFC-0xFF)
	case OpPXEAuthorize:
		return h.handlePXEAuthorize(ctx, req)
	case OpPXEQuarantine:
		return h.handlePXEQuarantine(ctx, req)
	case OpPXERetry:
		return h.handlePXERetry(ctx, req)
	case OpPXERemoveDevice:
		return h.handlePXERemoveDevice(ctx, req)
	default:
		return h.errorResponse(quic.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: req.Opcode})
	}
}

// handlePXEListDevices handles the list devices operation
func (h *QUICServiceHandler) handlePXEListDevices(ctx context.Context, req *quic.Request) *quic.Response {
	var listReq PXEListDevicesRequest
	if len(req.Payload) > 0 {
		if err := quic.DecodePayload(req.Payload, &listReq); err != nil {
			return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
		}
	}

	filter := &pxe.DeviceFilter{
		State:      pxe.ProvisioningState(listReq.State),
		MACAddress: listReq.MACAddress,
		VLAN:       listReq.VLAN,
		Limit:      listReq.Limit,
		Offset:     listReq.Offset,
	}

	devices, err := h.pxeService.ListDevices(ctx, filter)
	if err != nil {
		h.logger.Error(err, "failed to list PXE devices")
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{Op: "PXEListDevices", Cause: err})
	}

	pxeDevices := make([]*PXEDevice, 0, len(devices))
	for _, device := range devices {
		pxeDevices = append(pxeDevices, convertDeviceInfoToPXEDevice(device))
	}

	resp := &PXEListDevicesResponse{
		Devices:   pxeDevices,
		Total:     len(pxeDevices),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handlePXEGetDevice handles the get device by ID operation
func (h *QUICServiceHandler) handlePXEGetDevice(ctx context.Context, req *quic.Request) *quic.Response {
	var getReq PXEGetDeviceRequest
	if err := quic.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if getReq.DeviceID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "device_id"})
	}

	device, err := h.pxeService.GetDevice(ctx, getReq.DeviceID)
	if err != nil {
		h.logger.Error(err, "failed to get PXE device", "device_id", getReq.DeviceID)
		return h.errorResponse(quic.StatusNotFound, ErrPXEDeviceNotFound{DeviceID: getReq.DeviceID})
	}

	resp := &PXEGetDeviceResponse{
		Device:    convertDeviceInfoToPXEDevice(device),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handlePXERegisterDevice handles the register device operation
func (h *QUICServiceHandler) handlePXERegisterDevice(ctx context.Context, req *quic.Request) *quic.Response {
	var regReq PXERegisterDeviceRequest
	if err := quic.DecodePayload(req.Payload, &regReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if regReq.MACAddress == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "mac_address"})
	}
	if regReq.PortID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "port_id"})
	}

	device, err := h.pxeService.RegisterDevice(ctx, regReq.MACAddress, regReq.PortID)
	if err != nil {
		h.logger.Error(err, "failed to register PXE device",
			"mac_address", regReq.MACAddress,
			"port_id", regReq.PortID)
		return h.errorResponse(quic.StatusInternalError, ErrPXERegistrationFailed{
			MACAddress: regReq.MACAddress,
			Cause:      err,
		})
	}

	resp := &PXERegisterDeviceResponse{
		Device:    convertDeviceInfoToPXEDevice(device),
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("registered PXE device",
		"device_id", device.ID,
		"mac_address", regReq.MACAddress,
		"port_id", regReq.PortID)

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handlePXEUpdateState handles the update state operation
func (h *QUICServiceHandler) handlePXEUpdateState(ctx context.Context, req *quic.Request) *quic.Response {
	var updateReq PXEUpdateStateRequest
	if err := quic.DecodePayload(req.Payload, &updateReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if updateReq.DeviceID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "device_id"})
	}
	if updateReq.State == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "state"})
	}

	newState := pxe.ProvisioningState(updateReq.State)
	if !newState.IsValid() {
		return h.errorResponse(quic.StatusInvalidArgument, ErrPXEInvalidState{State: updateReq.State})
	}

	// Get current device to track old state
	device, err := h.pxeService.GetDevice(ctx, updateReq.DeviceID)
	if err != nil {
		return h.errorResponse(quic.StatusNotFound, ErrPXEDeviceNotFound{DeviceID: updateReq.DeviceID})
	}
	oldState := device.State

	if err := h.pxeService.UpdateDeviceState(ctx, updateReq.DeviceID, newState, updateReq.Reason); err != nil {
		h.logger.Error(err, "failed to update PXE device state",
			"device_id", updateReq.DeviceID,
			"state", updateReq.State)
		return h.errorResponse(quic.StatusInternalError, ErrPXEStateTransitionFailed{
			DeviceID:  updateReq.DeviceID,
			FromState: string(oldState),
			ToState:   updateReq.State,
			Cause:     err,
		})
	}

	resp := &PXEUpdateStateResponse{
		DeviceID:  updateReq.DeviceID,
		OldState:  string(oldState),
		NewState:  updateReq.State,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("updated PXE device state",
		"device_id", updateReq.DeviceID,
		"old_state", oldState,
		"new_state", updateReq.State)

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handlePXEAuthorize handles the authorize device operation
func (h *QUICServiceHandler) handlePXEAuthorize(ctx context.Context, req *quic.Request) *quic.Response {
	var authReq PXEAuthorizeRequest
	if err := quic.DecodePayload(req.Payload, &authReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if authReq.DeviceID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "device_id"})
	}
	if authReq.TargetVLAN == 0 {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "target_vlan"})
	}

	if err := h.pxeService.AuthorizeDevice(ctx, authReq.DeviceID, authReq.TargetVLAN); err != nil {
		h.logger.Error(err, "failed to authorize PXE device",
			"device_id", authReq.DeviceID,
			"target_vlan", authReq.TargetVLAN)
		return h.errorResponse(quic.StatusInternalError, ErrPXEAuthorizationFailed{
			DeviceID: authReq.DeviceID,
			Cause:    err,
		})
	}

	resp := &PXEAuthorizeResponse{
		DeviceID:   authReq.DeviceID,
		TargetVLAN: authReq.TargetVLAN,
		Success:    true,
		Timestamp:  time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("authorized PXE device",
		"device_id", authReq.DeviceID,
		"target_vlan", authReq.TargetVLAN)

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handlePXEQuarantine handles the quarantine device operation
func (h *QUICServiceHandler) handlePXEQuarantine(ctx context.Context, req *quic.Request) *quic.Response {
	var quarReq PXEQuarantineRequest
	if err := quic.DecodePayload(req.Payload, &quarReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if quarReq.DeviceID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "device_id"})
	}
	if quarReq.Reason == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "reason"})
	}

	if err := h.pxeService.QuarantineDevice(ctx, quarReq.DeviceID, quarReq.Reason); err != nil {
		h.logger.Error(err, "failed to quarantine PXE device",
			"device_id", quarReq.DeviceID,
			"reason", quarReq.Reason)
		return h.errorResponse(quic.StatusInternalError, ErrPXEQuarantineFailed{
			DeviceID: quarReq.DeviceID,
			Cause:    err,
		})
	}

	resp := &PXEQuarantineResponse{
		DeviceID:  quarReq.DeviceID,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Warn("quarantined PXE device",
		"device_id", quarReq.DeviceID,
		"reason", quarReq.Reason)

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handlePXERetry handles the retry device operation
func (h *QUICServiceHandler) handlePXERetry(ctx context.Context, req *quic.Request) *quic.Response {
	var retryReq PXERetryRequest
	if err := quic.DecodePayload(req.Payload, &retryReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if retryReq.DeviceID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "device_id"})
	}

	if err := h.pxeService.RetryDevice(ctx, retryReq.DeviceID); err != nil {
		h.logger.Error(err, "failed to retry PXE device",
			"device_id", retryReq.DeviceID)
		return h.errorResponse(quic.StatusInternalError, ErrPXERetryFailed{
			DeviceID: retryReq.DeviceID,
			Cause:    err,
		})
	}

	// Get updated device to return retry count
	device, _ := h.pxeService.GetDevice(ctx, retryReq.DeviceID)
	retryCount := 0
	if device != nil {
		retryCount = device.RetryCount
	}

	resp := &PXERetryResponse{
		DeviceID:   retryReq.DeviceID,
		RetryCount: retryCount,
		Success:    true,
		Timestamp:  time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("initiated PXE device retry",
		"device_id", retryReq.DeviceID,
		"retry_count", retryCount)

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// handlePXERemoveDevice handles the remove device operation
func (h *QUICServiceHandler) handlePXERemoveDevice(ctx context.Context, req *quic.Request) *quic.Response {
	var removeReq PXERemoveDeviceRequest
	if err := quic.DecodePayload(req.Payload, &removeReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if removeReq.DeviceID == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "device_id"})
	}

	if err := h.pxeService.RemoveDevice(ctx, removeReq.DeviceID); err != nil {
		h.logger.Error(err, "failed to remove PXE device",
			"device_id", removeReq.DeviceID)
		return h.errorResponse(quic.StatusInternalError, ErrQUICOperationFailed{
			Op:    "PXERemoveDevice",
			Cause: err,
		})
	}

	resp := &PXERemoveDeviceResponse{
		DeviceID:  removeReq.DeviceID,
		Success:   true,
		Timestamp: time.Now().Unix(),
	}

	payload, err := quic.EncodePayload(resp)
	if err != nil {
		return h.errorResponse(quic.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}

	h.logger.Info("removed PXE device",
		"device_id", removeReq.DeviceID)

	return &quic.Response{
		Status:  quic.StatusOK,
		Payload: payload,
	}
}

// =============================================================================
// Conversion Helpers
// =============================================================================

// convertDeviceInfoToPXEDevice converts a pxe.DeviceInfo to a PXEDevice
func convertDeviceInfoToPXEDevice(device *pxe.DeviceInfo) *PXEDevice {
	if device == nil {
		return nil
	}

	pxeDevice := &PXEDevice{
		ID:                device.ID,
		MACAddress:        device.MACAddress.String(),
		PortID:            device.PortID,
		State:             string(device.State),
		StateReason:       device.StateReason,
		CertificateSerial: device.CertificateSerial,
		CurrentVLAN:       device.CurrentVLAN,
		TargetVLAN:        device.TargetVLAN,
		CreatedAt:         device.CreatedAt.Unix(),
		UpdatedAt:         device.UpdatedAt.Unix(),
		StateChangedAt:    device.StateChangedAt.Unix(),
		RetryCount:        device.RetryCount,
	}

	if device.Profile != nil {
		pxeDevice.ProfileID = strconv.FormatUint(device.Profile.ID, 10)
		pxeDevice.ProfileName = device.Profile.Name
	}

	return pxeDevice
}

// =============================================================================
// PXE-specific Error Types
// =============================================================================

// ErrPXEDeviceNotFound is returned when a PXE device is not found
type ErrPXEDeviceNotFound struct {
	DeviceID   string
	MACAddress string
}

func (e ErrPXEDeviceNotFound) Error() string {
	if e.DeviceID != "" {
		return "PXE device not found: " + e.DeviceID
	}
	return "PXE device not found with MAC: " + e.MACAddress
}

// ErrPXERegistrationFailed is returned when device registration fails
type ErrPXERegistrationFailed struct {
	MACAddress string
	Cause      error
}

func (e ErrPXERegistrationFailed) Error() string {
	return "PXE device registration failed for " + e.MACAddress + ": " + e.Cause.Error()
}

func (e ErrPXERegistrationFailed) Unwrap() error {
	return e.Cause
}

// ErrPXEInvalidState is returned when an invalid provisioning state is specified
type ErrPXEInvalidState struct {
	State string
}

func (e ErrPXEInvalidState) Error() string {
	return "invalid PXE provisioning state: " + e.State
}

// ErrPXEStateTransitionFailed is returned when a state transition fails
type ErrPXEStateTransitionFailed struct {
	DeviceID  string
	FromState string
	ToState   string
	Cause     error
}

func (e ErrPXEStateTransitionFailed) Error() string {
	return "PXE state transition failed for " + e.DeviceID + " from " + e.FromState + " to " + e.ToState + ": " + e.Cause.Error()
}

func (e ErrPXEStateTransitionFailed) Unwrap() error {
	return e.Cause
}

// ErrPXEEnrollmentFailed is returned when device enrollment fails
type ErrPXEEnrollmentFailed struct {
	DeviceID string
	Cause    error
}

func (e ErrPXEEnrollmentFailed) Error() string {
	return "PXE device enrollment failed for " + e.DeviceID + ": " + e.Cause.Error()
}

func (e ErrPXEEnrollmentFailed) Unwrap() error {
	return e.Cause
}

// ErrPXEAuthorizationFailed is returned when device authorization fails
type ErrPXEAuthorizationFailed struct {
	DeviceID string
	Cause    error
}

func (e ErrPXEAuthorizationFailed) Error() string {
	return "PXE device authorization failed for " + e.DeviceID + ": " + e.Cause.Error()
}

func (e ErrPXEAuthorizationFailed) Unwrap() error {
	return e.Cause
}

// ErrPXEQuarantineFailed is returned when device quarantine fails
type ErrPXEQuarantineFailed struct {
	DeviceID string
	Cause    error
}

func (e ErrPXEQuarantineFailed) Error() string {
	return "PXE device quarantine failed for " + e.DeviceID + ": " + e.Cause.Error()
}

func (e ErrPXEQuarantineFailed) Unwrap() error {
	return e.Cause
}

// ErrPXERetryFailed is returned when device retry fails
type ErrPXERetryFailed struct {
	DeviceID string
	Cause    error
}

func (e ErrPXERetryFailed) Error() string {
	return "PXE device retry failed for " + e.DeviceID + ": " + e.Cause.Error()
}

func (e ErrPXERetryFailed) Unwrap() error {
	return e.Cause
}

// ErrPXEServiceStartFailed is returned when the PXE service fails to start
type ErrPXEServiceStartFailed struct {
	Cause error
}

func (e ErrPXEServiceStartFailed) Error() string {
	return "PXE service failed to start: " + e.Cause.Error()
}

func (e ErrPXEServiceStartFailed) Unwrap() error {
	return e.Cause
}

// ErrPXEServiceStopFailed is returned when the PXE service fails to stop
type ErrPXEServiceStopFailed struct {
	Cause error
}

func (e ErrPXEServiceStopFailed) Error() string {
	return "PXE service failed to stop: " + e.Cause.Error()
}

func (e ErrPXEServiceStopFailed) Unwrap() error {
	return e.Cause
}
