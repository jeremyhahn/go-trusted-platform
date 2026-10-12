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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// =============================================================================
// Device QUIC wire contract
// =============================================================================
//
// The canonical QUIC wire contract for the device surface is the
// platform.v1 protobuf request/response messages themselves: the SDK QUIC
// transport adapter (sdk/go/transport/quic) encodes the platformv1 request
// structs directly and decodes daemon replies directly into the platformv1
// response structs. The payload codec (msgpack) keys on exact Go field
// names, so decoding the payload into the same platformv1 message types on
// the daemon side guarantees SDK<->daemon shape parity by construction and
// gives the QUIC transport identical semantics to gRPC: every handler
// below delegates to the shared DeviceGRPCService.
//
// Two opcodes are unions because the SDK maps two RPCs onto one wire byte:
//
//   - OpDeviceGet serves GetDevice (Id) and FindDeviceBySerial (Serial);
//     both responses carry the device under the same Device field.
//   - OpDeviceList / OpDeviceListProfiles serve List* and Count*; the SDK
//     derives Count* responses from the list response pagination totals.
//
// Profile assignment (AssignProfileToDevice / UnassignProfileFromDevice)
// travels as sub-opcodes under quicwire.OpProvisioningCategory because the
// single-byte opcode space is fully allocated (same precedent as the EAB
// sub-range); see handleDeviceProfileCategorySub.

// deviceGetWireRequest is the union decode shape for OpDeviceGet, which
// serves both platform.v1 GetDeviceRequest (Id) and
// FindDeviceBySerialRequest (Serial). Field names mirror the platformv1
// Go field names exactly (the codec keys on Go field names).
type deviceGetWireRequest struct {
	Id     uint64
	Serial string
}

// DeviceStateResponse is the daemon-native QUIC wire shape for
// OpDeviceGetState. Device state is a domain-only field with no
// platform.v1 counterpart, so this is the one device response that is not
// a protobuf message. Field names follow the platformv1 Go naming style.
type DeviceStateResponse struct {
	Id     uint64
	Serial string
	Model  string
	State  string
}

// deviceGRPCCodeToQUICStatus maps the gRPC status codes produced by the
// shared DeviceGRPCService onto QUIC status bytes. FailedPrecondition
// maps to StatusInvalidRequest since the QUIC status set has no
// precondition code. Aborted (a compare-and-clear that lost a race) maps to
// StatusAlreadyExists, the QUIC conflict status, as it does for NTP. Unknown
// codes map to StatusInternalError.
var deviceGRPCCodeToQUICStatus = map[codes.Code]byte{
	codes.Aborted:            quicwire.StatusAlreadyExists,
	codes.InvalidArgument:    quicwire.StatusInvalidArgument,
	codes.NotFound:           quicwire.StatusNotFound,
	codes.AlreadyExists:      quicwire.StatusAlreadyExists,
	codes.PermissionDenied:   quicwire.StatusPermissionDenied,
	codes.Unauthenticated:    quicwire.StatusUnauthorized,
	codes.FailedPrecondition: quicwire.StatusInvalidRequest,
	codes.Unavailable:        quicwire.StatusUnavailable,
	codes.Internal:           quicwire.StatusInternalError,
}

// deviceGRPCErrorToQUIC converts a gRPC status error from the shared
// DeviceGRPCService into a QUIC error response, preserving the
// status-code semantics of the gRPC transport.
func (h *QUICServiceHandler) deviceGRPCErrorToQUIC(op string, err error) *quicwire.Response {
	quicStatus := quicwire.StatusInternalError
	if mapped, ok := deviceGRPCCodeToQUICStatus[status.Code(err)]; ok {
		quicStatus = mapped
	}
	return h.errorResponse(quicStatus, ErrQUICOperationFailed{Op: op, Cause: err})
}

// encodeDeviceQUICResponse encodes v as a StatusOK QUIC response.
func (h *QUICServiceHandler) encodeDeviceQUICResponse(v interface{}) *quicwire.Response {
	payload, err := quicwire.EncodePayload(v)
	if err != nil {
		return h.errorResponse(quicwire.StatusInternalError, ErrQUICEncodingFailed{Cause: err})
	}
	return &quicwire.Response{
		Status:  quicwire.StatusOK,
		Payload: payload,
	}
}

// rebuildDeviceGRPC (re)constructs the shared DeviceGRPCService the QUIC
// device handlers delegate to. It is invoked from the device service
// setters so the delegate always reflects the currently configured
// services; construction happens during single-threaded daemon setup.
func (h *QUICServiceHandler) rebuildDeviceGRPC() {
	h.deviceGRPC = NewDeviceGRPCService(
		h.deviceService,
		h.profileService,
		h.logger.Slog(),
		WithDeviceAKTrust(h.akTrust),
		WithDeviceVerdictSink(h.deviceVerdicts),
		WithDeviceAttestCertRecorder(h.attestCertRecorder),
	)
}

// handleDeviceOperation routes device opcodes to their respective handlers.
func (h *QUICServiceHandler) handleDeviceOperation(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	switch req.Opcode {
	case quicwire.OpDeviceRegister:
		return h.handleDeviceRegister(ctx, req)
	case quicwire.OpDeviceUnregister:
		return h.handleDeviceUnregister(ctx, req)
	case quicwire.OpDeviceGet:
		return h.handleDeviceGet(ctx, req)
	case quicwire.OpDeviceList:
		return h.handleDeviceList(ctx, req)
	case quicwire.OpDeviceUpdate:
		return h.handleDeviceUpdate(ctx, req)
	case quicwire.OpDeviceGetProfile:
		return h.handleDeviceGetProfile(ctx, req)
	case quicwire.OpDeviceSetProfile:
		return h.handleDeviceSetProfile(ctx, req)
	case quicwire.OpDeviceListProfiles:
		return h.handleDeviceListProfiles(ctx, req)
	case quicwire.OpDeviceCreateProfile:
		return h.handleDeviceCreateProfile(ctx, req)
	case quicwire.OpDeviceDeleteProfile:
		return h.handleDeviceDeleteProfile(ctx, req)
	case quicwire.OpDeviceActivate:
		return h.handleDeviceActivate(ctx, req)
	case quicwire.OpDeviceGetState:
		return h.handleDeviceGetState(ctx, req)
	case quicwire.OpDeviceAttest:
		return h.handleDeviceAttest(ctx, req)
	case quicwire.OpDeviceDeactivate:
		return h.errorResponse(quicwire.StatusNotImplemented, ErrDeviceOperationNotImplemented{Operation: "deactivate"})
	case quicwire.OpDeviceGetMetrics:
		return h.errorResponse(quicwire.StatusNotImplemented, ErrDeviceOperationNotImplemented{Operation: "get_metrics"})
	case quicwire.OpDeviceAttributes:
		return h.errorResponse(quicwire.StatusNotImplemented, ErrDeviceOperationNotImplemented{Operation: "attributes"})
	default:
		return h.errorResponse(quicwire.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: req.Opcode})
	}
}

// handleDeviceRegister creates a device via the shared gRPC service.
func (h *QUICServiceHandler) handleDeviceRegister(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var createReq platformv1.CreateDeviceRequest
	if err := quicwire.DecodePayload(req.Payload, &createReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.deviceGRPC.CreateDevice(ctx, &createReq)
	if err != nil {
		return h.deviceGRPCErrorToQUIC("DeviceRegister", err)
	}
	return h.encodeDeviceQUICResponse(resp)
}

// handleDeviceUnregister deletes a device via the shared gRPC service.
func (h *QUICServiceHandler) handleDeviceUnregister(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var deleteReq platformv1.DeleteDeviceRequest
	if err := quicwire.DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.deviceGRPC.DeleteDevice(ctx, &deleteReq)
	if err != nil {
		return h.deviceGRPCErrorToQUIC("DeviceUnregister", err)
	}
	return h.encodeDeviceQUICResponse(resp)
}

// handleDeviceGet serves both GetDevice (Id) and FindDeviceBySerial
// (Serial); both response messages carry the device under the same
// Device field, so either reply type decodes the response.
func (h *QUICServiceHandler) handleDeviceGet(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var getReq deviceGetWireRequest
	if err := quicwire.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if getReq.Id != 0 {
		resp, err := h.deviceGRPC.GetDevice(ctx, &platformv1.GetDeviceRequest{Id: getReq.Id})
		if err != nil {
			return h.deviceGRPCErrorToQUIC("DeviceGet", err)
		}
		return h.encodeDeviceQUICResponse(resp)
	}

	resp, err := h.deviceGRPC.FindDeviceBySerial(ctx, &platformv1.FindDeviceBySerialRequest{Serial: getReq.Serial})
	if err != nil {
		return h.deviceGRPCErrorToQUIC("DeviceGet", err)
	}
	return h.encodeDeviceQUICResponse(resp)
}

// handleDeviceList serves ListDevices and CountDevices. The response
// pagination carries the total device count so the SDK can derive
// CountDevicesResponse from the list reply.
func (h *QUICServiceHandler) handleDeviceList(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var listReq platformv1.ListDevicesRequest
	if err := quicwire.DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.deviceGRPC.ListDevices(ctx, &listReq)
	if err != nil {
		return h.deviceGRPCErrorToQUIC("DeviceList", err)
	}
	return h.encodeDeviceQUICResponse(resp)
}

// handleDeviceUpdate updates a device via the shared gRPC service.
func (h *QUICServiceHandler) handleDeviceUpdate(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var updateReq platformv1.UpdateDeviceRequest
	if err := quicwire.DecodePayload(req.Payload, &updateReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.deviceGRPC.UpdateDevice(ctx, &updateReq)
	if err != nil {
		return h.deviceGRPCErrorToQUIC("DeviceUpdate", err)
	}
	return h.encodeDeviceQUICResponse(resp)
}

// handleDeviceActivate activates a device via the shared gRPC service,
// transitioning it to its post-enrollment production network.
func (h *QUICServiceHandler) handleDeviceActivate(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.profileService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrDeviceProfileServiceNotAvailable{})
	}

	var activateReq platformv1.ActivateDeviceRequest
	if err := quicwire.DecodePayload(req.Payload, &activateReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.deviceGRPC.ActivateDevice(ctx, &activateReq)
	if err != nil {
		return h.deviceGRPCErrorToQUIC("DeviceActivate", err)
	}
	return h.encodeDeviceQUICResponse(resp)
}

// handleDeviceAttest verifies TPM quote evidence submitted for a device.
//
// This opcode previously answered StatusNotImplemented on the live QUIC
// dispatcher while a complete handler sat in pkg/api/quic, which has no
// non-test caller (#291). So the operation looked implemented in one package
// and was a stub in the one actually served — CLAUDE.md is explicit that a
// "wire this up later" stub on a multi-protocol service is a bug, not a
// transitional state.
//
// Like every other device opcode here it delegates to the shared
// DeviceService gRPC implementation, so QUIC cannot form its own opinion
// about whether a device attested.
func (h *QUICServiceHandler) handleDeviceAttest(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var attestReq platformv1.AttestDeviceRequest
	if err := quicwire.DecodePayload(req.Payload, &attestReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.deviceGRPC.AttestDevice(ctx, &attestReq)
	if err != nil {
		return h.deviceGRPCErrorToQUIC("DeviceAttest", err)
	}
	return h.encodeDeviceQUICResponse(resp)
}

// handleDeviceGetState retrieves the domain-only device state. This is
// the one daemon-native device response with no platform.v1 counterpart.
func (h *QUICServiceHandler) handleDeviceGetState(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	var getReq deviceGetWireRequest
	if err := quicwire.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if getReq.Id == 0 {
		return h.errorResponse(quicwire.StatusInvalidArgument, ErrQUICMissingField{Field: "id"})
	}

	device, err := h.deviceService.Get(ctx, getReq.Id)
	if err != nil {
		return h.errorResponse(quicwire.StatusNotFound, ErrDeviceOperationFailed{Operation: "get_state", Cause: err})
	}

	return h.encodeDeviceQUICResponse(&DeviceStateResponse{
		Id:     device.ID,
		Serial: device.Serial,
		Model:  device.Model,
		State:  string(device.State),
	})
}

// =============================================================================
// Device profile handlers
// =============================================================================

// handleDeviceGetProfile retrieves a device profile by ID.
func (h *QUICServiceHandler) handleDeviceGetProfile(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.profileService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrDeviceProfileServiceNotAvailable{})
	}

	var getReq platformv1.GetProfileRequest
	if err := quicwire.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.deviceGRPC.GetProfile(ctx, &getReq)
	if err != nil {
		return h.deviceGRPCErrorToQUIC("DeviceGetProfile", err)
	}
	return h.encodeDeviceQUICResponse(resp)
}

// handleDeviceListProfiles serves ListProfiles and CountProfiles. The
// response pagination carries the total profile count so the SDK can
// derive CountProfilesResponse from the list reply.
func (h *QUICServiceHandler) handleDeviceListProfiles(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.profileService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrDeviceProfileServiceNotAvailable{})
	}

	var listReq platformv1.ListProfilesRequest
	if err := quicwire.DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.deviceGRPC.ListProfiles(ctx, &listReq)
	if err != nil {
		return h.deviceGRPCErrorToQUIC("DeviceListProfiles", err)
	}
	return h.encodeDeviceQUICResponse(resp)
}

// handleDeviceCreateProfile creates a new device profile. The shared
// gRPC service validates the prestaged EK certificate and the config
// bytes, and generates an ID when the client supplied none.
func (h *QUICServiceHandler) handleDeviceCreateProfile(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.profileService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrDeviceProfileServiceNotAvailable{})
	}

	var createReq platformv1.CreateProfileRequest
	if err := quicwire.DecodePayload(req.Payload, &createReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.deviceGRPC.CreateProfile(ctx, &createReq)
	if err != nil {
		return h.deviceGRPCErrorToQUIC("DeviceCreateProfile", err)
	}
	return h.encodeDeviceQUICResponse(resp)
}

// handleDeviceSetProfile replaces an existing device profile with the
// full profile carried in the request, exactly like the gRPC
// UpdateProfile RPC it delegates to.
func (h *QUICServiceHandler) handleDeviceSetProfile(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.profileService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrDeviceProfileServiceNotAvailable{})
	}

	var updateReq platformv1.UpdateProfileRequest
	if err := quicwire.DecodePayload(req.Payload, &updateReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.deviceGRPC.UpdateProfile(ctx, &updateReq)
	if err != nil {
		return h.deviceGRPCErrorToQUIC("DeviceSetProfile", err)
	}
	return h.encodeDeviceQUICResponse(resp)
}

// handleDeviceDeleteProfile deletes a device profile by ID.
func (h *QUICServiceHandler) handleDeviceDeleteProfile(ctx context.Context, req *quicwire.Request) *quicwire.Response {
	if h.profileService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrDeviceProfileServiceNotAvailable{})
	}

	var deleteReq platformv1.DeleteProfileRequest
	if err := quicwire.DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.deviceGRPC.DeleteProfile(ctx, &deleteReq)
	if err != nil {
		return h.deviceGRPCErrorToQUIC("DeviceDeleteProfile", err)
	}
	return h.encodeDeviceQUICResponse(resp)
}

// =============================================================================
// Profile assignment sub-opcodes (under OpProvisioningCategory)
// =============================================================================

// handleDeviceProfileCategorySub routes a device profile assignment
// sub-opcode when payload[0] belongs to the device profile sub-range
// under quicwire.OpProvisioningCategory. It reports handled=false for
// anything else so the caller can fall through to the config delivery
// dispatcher (same multiplexing precedent as the EAB sub-range: the
// single-byte opcode space is fully allocated).
func (h *QUICServiceHandler) handleDeviceProfileCategorySub(ctx context.Context, req *quicwire.Request) (*quicwire.Response, bool) {
	if len(req.Payload) == 0 {
		return nil, false
	}

	switch req.Payload[0] {
	case quicwire.DeviceProfileSubAssign:
		return h.handleDeviceProfileAssign(ctx, req.Payload[1:]), true
	case quicwire.DeviceProfileSubUnassign:
		return h.handleDeviceProfileUnassign(ctx, req.Payload[1:]), true
	case quicwire.DeviceSubRecordAttestCert:
		return h.handleDeviceRecordAttestCert(ctx, req.Payload[1:]), true
	default:
		return nil, false
	}
}

// handleDeviceRecordAttestCert records a device's attestation certificate
// via the shared gRPC service, so QUIC answers exactly what gRPC, Unix,
// REST and MCP answer: the same fail-closed preflight, the same refusal.
func (h *QUICServiceHandler) handleDeviceRecordAttestCert(ctx context.Context, payload []byte) *quicwire.Response {
	if h.deviceService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrServiceNotAvailable{Service: "device"})
	}

	var recordReq platformv1.RecordAttestationCertificateRequest
	if err := quicwire.DecodePayload(payload, &recordReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.deviceGRPC.RecordAttestationCertificate(ctx, &recordReq)
	if err != nil {
		return h.deviceGRPCErrorToQUIC("DeviceRecordAttestCert", err)
	}
	return h.encodeDeviceQUICResponse(resp)
}

// handleDeviceProfileAssign binds a profile to a device identity (EK
// serial and/or MAC address), optionally prestaging the device's EK
// certificate, via the shared gRPC service.
func (h *QUICServiceHandler) handleDeviceProfileAssign(ctx context.Context, payload []byte) *quicwire.Response {
	if h.profileService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrDeviceProfileServiceNotAvailable{})
	}

	var assignReq platformv1.AssignProfileToDeviceRequest
	if err := quicwire.DecodePayload(payload, &assignReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.deviceGRPC.AssignProfileToDevice(ctx, &assignReq)
	if err != nil {
		return h.deviceGRPCErrorToQUIC("DeviceProfileAssign", err)
	}
	return h.encodeDeviceQUICResponse(resp)
}

// handleDeviceProfileUnassign clears a profile's device binding via the
// shared gRPC service.
func (h *QUICServiceHandler) handleDeviceProfileUnassign(ctx context.Context, payload []byte) *quicwire.Response {
	if h.profileService == nil {
		return h.errorResponse(quicwire.StatusUnavailable, ErrDeviceProfileServiceNotAvailable{})
	}

	var unassignReq platformv1.UnassignProfileFromDeviceRequest
	if err := quicwire.DecodePayload(payload, &unassignReq); err != nil {
		return h.errorResponse(quicwire.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	resp, err := h.deviceGRPC.UnassignProfileFromDevice(ctx, &unassignReq)
	if err != nil {
		return h.deviceGRPCErrorToQUIC("DeviceProfileUnassign", err)
	}
	return h.encodeDeviceQUICResponse(resp)
}
