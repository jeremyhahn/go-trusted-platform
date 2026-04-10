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
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

// handleDeviceOperation routes device opcodes to their respective handlers.
func (h *QUICServiceHandler) handleDeviceOperation(ctx context.Context, req *quic.Request) *quic.Response {
	switch req.Opcode {
	case quic.OpDeviceRegister:
		return h.handleDeviceRegister(ctx, req)
	case quic.OpDeviceUnregister:
		return h.handleDeviceUnregister(ctx, req)
	case quic.OpDeviceGet:
		return h.handleDeviceGet(ctx, req)
	case quic.OpDeviceList:
		return h.handleDeviceList(ctx, req)
	case quic.OpDeviceUpdate:
		return h.handleDeviceUpdate(ctx, req)
	case quic.OpDeviceGetProfile:
		return h.handleDeviceGetProfile(ctx, req)
	case quic.OpDeviceSetProfile:
		return h.errorResponse(quic.StatusNotImplemented, ErrDeviceOperationNotImplemented{Operation: "set_profile"})
	case quic.OpDeviceListProfiles:
		return h.handleDeviceListProfiles(ctx, req)
	case quic.OpDeviceCreateProfile:
		return h.handleDeviceCreateProfile(ctx, req)
	case quic.OpDeviceDeleteProfile:
		return h.handleDeviceDeleteProfile(ctx, req)
	case quic.OpDeviceAttest:
		return h.errorResponse(quic.StatusNotImplemented, ErrDeviceOperationNotImplemented{Operation: "attest"})
	case quic.OpDeviceActivate:
		return h.errorResponse(quic.StatusNotImplemented, ErrDeviceOperationNotImplemented{Operation: "activate"})
	case quic.OpDeviceDeactivate:
		return h.errorResponse(quic.StatusNotImplemented, ErrDeviceOperationNotImplemented{Operation: "deactivate"})
	case quic.OpDeviceGetState:
		return h.handleDeviceGetState(ctx, req)
	case quic.OpDeviceGetMetrics:
		return h.errorResponse(quic.StatusNotImplemented, ErrDeviceOperationNotImplemented{Operation: "get_metrics"})
	case quic.OpDeviceAttributes:
		return h.errorResponse(quic.StatusNotImplemented, ErrDeviceOperationNotImplemented{Operation: "attributes"})
	default:
		return h.errorResponse(quic.StatusNotImplemented, ErrQUICUnknownOpcode{Opcode: req.Opcode})
	}
}

// handleDeviceRegister registers a new device via the device service.
func (h *QUICServiceHandler) handleDeviceRegister(ctx context.Context, req *quic.Request) *quic.Response {
	var registerReq DeviceRegisterRequest
	if err := quic.DecodePayload(req.Payload, &registerReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if registerReq.Serial == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "serial"})
	}

	device := &entities.Device{
		ID:         registerReq.ID,
		Serial:     registerReq.Serial,
		Model:      registerReq.Model,
		AttestPub:  registerReq.AttestPub,
		SigningPub: registerReq.SigningPub,
		EKCert:     registerReq.EKCert,
		HashAlgoId: uint32(registerReq.HashAlgoID),
		State:      entities.DeviceStateRegistered,
		CreatedAt:  time.Now(),
		UpdatedAt:  time.Now(),
	}

	if err := h.deviceService.Save(ctx, device); err != nil {
		h.logger.Error(err, "failed to register device", "serial", registerReq.Serial)
		return h.errorResponse(quic.StatusInternalError, ErrDeviceOperationFailed{Operation: "register", Cause: err})
	}

	resp := &DeviceRegisterResponse{
		ID:        device.ID,
		Serial:    device.Serial,
		Model:     device.Model,
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

// handleDeviceUnregister removes a device via the device service.
func (h *QUICServiceHandler) handleDeviceUnregister(ctx context.Context, req *quic.Request) *quic.Response {
	var unregisterReq DeviceUnregisterRequest
	if err := quic.DecodePayload(req.Payload, &unregisterReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if unregisterReq.ID == 0 {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "id"})
	}

	device, err := h.deviceService.Get(ctx, unregisterReq.ID)
	if err != nil {
		h.logger.Error(err, "failed to get device for unregister", "id", unregisterReq.ID)
		return h.errorResponse(quic.StatusNotFound, ErrDeviceNotFound{DeviceID: strconv.FormatUint(unregisterReq.ID, 10)})
	}

	if err := h.deviceService.Delete(ctx, device); err != nil {
		h.logger.Error(err, "failed to unregister device", "id", unregisterReq.ID)
		return h.errorResponse(quic.StatusInternalError, ErrDeviceOperationFailed{Operation: "unregister", Cause: err})
	}

	resp := &DeviceUnregisterResponse{
		ID:        unregisterReq.ID,
		Deleted:   true,
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

// handleDeviceGet retrieves a device by ID.
func (h *QUICServiceHandler) handleDeviceGet(ctx context.Context, req *quic.Request) *quic.Response {
	var getReq DeviceGetRequest
	if err := quic.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if getReq.ID == 0 {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "id"})
	}

	device, err := h.deviceService.Get(ctx, getReq.ID)
	if err != nil {
		h.logger.Error(err, "failed to get device", "id", getReq.ID)
		return h.errorResponse(quic.StatusNotFound, ErrDeviceNotFound{DeviceID: strconv.FormatUint(getReq.ID, 10)})
	}

	resp := &DeviceGetResponse{
		ID:        device.ID,
		Serial:    device.Serial,
		Model:     device.Model,
		State:     string(device.State),
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

// handleDeviceList retrieves a paginated list of devices.
func (h *QUICServiceHandler) handleDeviceList(ctx context.Context, req *quic.Request) *quic.Response {
	var listReq DeviceListRequest
	if err := quic.DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	// Convert offset/limit to page-based query
	pageSize := listReq.Limit
	if pageSize <= 0 {
		pageSize = 25
	}
	page := 1
	if listReq.Offset > 0 {
		page = (listReq.Offset / pageSize) + 1
	}

	query := datastore.PageQuery{
		Page:      page,
		PageSize:  pageSize,
		SortOrder: datastore.SortAscending,
	}

	result, err := h.deviceService.Page(ctx, query)
	if err != nil {
		h.logger.Error(err, "failed to list devices")
		return h.errorResponse(quic.StatusInternalError, ErrDeviceOperationFailed{Operation: "list", Cause: err})
	}

	devices := make([]*DeviceSummary, 0, len(result.Entities))
	for _, d := range result.Entities {
		devices = append(devices, &DeviceSummary{
			ID:     d.ID,
			Serial: d.Serial,
			Model:  d.Model,
			State:  string(d.State),
		})
	}

	resp := &DeviceListResponse{
		Devices:   devices,
		Total:     result.Total,
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

// handleDeviceUpdate modifies an existing device.
func (h *QUICServiceHandler) handleDeviceUpdate(ctx context.Context, req *quic.Request) *quic.Response {
	var updateReq DeviceUpdateRequest
	if err := quic.DecodePayload(req.Payload, &updateReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if updateReq.ID == 0 {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "id"})
	}

	device, err := h.deviceService.Get(ctx, updateReq.ID)
	if err != nil {
		h.logger.Error(err, "failed to get device for update", "id", updateReq.ID)
		return h.errorResponse(quic.StatusNotFound, ErrDeviceNotFound{DeviceID: strconv.FormatUint(updateReq.ID, 10)})
	}

	if updateReq.Serial != "" {
		device.Serial = updateReq.Serial
	}
	if updateReq.Model != "" {
		device.Model = updateReq.Model
	}
	device.UpdatedAt = time.Now()

	if err := h.deviceService.Update(ctx, device); err != nil {
		h.logger.Error(err, "failed to update device", "id", updateReq.ID)
		return h.errorResponse(quic.StatusInternalError, ErrDeviceOperationFailed{Operation: "update", Cause: err})
	}

	resp := &DeviceUpdateResponse{
		ID:        device.ID,
		Serial:    device.Serial,
		Model:     device.Model,
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

// handleDeviceGetState retrieves the current state of a device.
func (h *QUICServiceHandler) handleDeviceGetState(ctx context.Context, req *quic.Request) *quic.Response {
	var getReq DeviceGetRequest
	if err := quic.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if getReq.ID == 0 {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "id"})
	}

	device, err := h.deviceService.Get(ctx, getReq.ID)
	if err != nil {
		h.logger.Error(err, "failed to get device state", "id", getReq.ID)
		return h.errorResponse(quic.StatusNotFound, ErrDeviceNotFound{DeviceID: strconv.FormatUint(getReq.ID, 10)})
	}

	resp := &DeviceGetResponse{
		ID:        device.ID,
		Serial:    device.Serial,
		Model:     device.Model,
		State:     string(device.State),
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

// handleDeviceGetProfile retrieves a device profile by ID.
func (h *QUICServiceHandler) handleDeviceGetProfile(ctx context.Context, req *quic.Request) *quic.Response {
	if h.profileService == nil {
		return h.errorResponse(quic.StatusUnavailable, ErrDeviceProfileServiceNotAvailable{})
	}

	var getReq DeviceProfileGetRequest
	if err := quic.DecodePayload(req.Payload, &getReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if getReq.ID == 0 {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "id"})
	}

	profile, err := h.profileService.Get(ctx, getReq.ID)
	if err != nil {
		h.logger.Error(err, "failed to get device profile", "id", getReq.ID)
		return h.errorResponse(quic.StatusNotFound, ErrProfileNotFound{Profile: strconv.FormatUint(getReq.ID, 10)})
	}

	resp := &DeviceProfileGetResponse{
		ID:   profile.ID,
		Name: profile.Name,
		Role: string(profile.Role),
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

// handleDeviceListProfiles retrieves a paginated list of device profiles.
func (h *QUICServiceHandler) handleDeviceListProfiles(ctx context.Context, req *quic.Request) *quic.Response {
	if h.profileService == nil {
		return h.errorResponse(quic.StatusUnavailable, ErrDeviceProfileServiceNotAvailable{})
	}

	var listReq DeviceListRequest
	if err := quic.DecodePayload(req.Payload, &listReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	pageSize := listReq.Limit
	if pageSize <= 0 {
		pageSize = 25
	}
	page := 1
	if listReq.Offset > 0 {
		page = (listReq.Offset / pageSize) + 1
	}

	query := datastore.PageQuery{
		Page:      page,
		PageSize:  pageSize,
		SortOrder: datastore.SortAscending,
	}

	result, err := h.profileService.Page(ctx, query)
	if err != nil {
		h.logger.Error(err, "failed to list device profiles")
		return h.errorResponse(quic.StatusInternalError, ErrDeviceOperationFailed{Operation: "list_profiles", Cause: err})
	}

	profiles := make([]*DeviceProfileSummary, 0, len(result.Entities))
	for _, p := range result.Entities {
		profiles = append(profiles, &DeviceProfileSummary{
			ID:   p.ID,
			Name: p.Name,
			Role: string(p.Role),
		})
	}

	resp := &DeviceProfileListResponse{
		Profiles:  profiles,
		Total:     result.Total,
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

// handleDeviceCreateProfile creates a new device profile.
func (h *QUICServiceHandler) handleDeviceCreateProfile(ctx context.Context, req *quic.Request) *quic.Response {
	if h.profileService == nil {
		return h.errorResponse(quic.StatusUnavailable, ErrDeviceProfileServiceNotAvailable{})
	}

	var createReq DeviceProfileCreateRequest
	if err := quic.DecodePayload(req.Payload, &createReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if createReq.Name == "" {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "name"})
	}

	profile := &entities.DeviceProfile{
		Name:  createReq.Name,
		Model: createReq.Model,
		Role:  entities.DeviceRole(createReq.Role),
	}

	if err := h.profileService.Save(ctx, profile); err != nil {
		h.logger.Error(err, "failed to create device profile", "name", createReq.Name)
		return h.errorResponse(quic.StatusInternalError, ErrDeviceOperationFailed{Operation: "create_profile", Cause: err})
	}

	resp := &DeviceProfileGetResponse{
		ID:   profile.ID,
		Name: profile.Name,
		Role: string(profile.Role),
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

// handleDeviceDeleteProfile deletes a device profile by ID.
func (h *QUICServiceHandler) handleDeviceDeleteProfile(ctx context.Context, req *quic.Request) *quic.Response {
	if h.profileService == nil {
		return h.errorResponse(quic.StatusUnavailable, ErrDeviceProfileServiceNotAvailable{})
	}

	var deleteReq DeviceProfileDeleteRequest
	if err := quic.DecodePayload(req.Payload, &deleteReq); err != nil {
		return h.errorResponse(quic.StatusInvalidRequest, ErrQUICDecodingFailed{Cause: err})
	}

	if deleteReq.ID == 0 {
		return h.errorResponse(quic.StatusInvalidArgument, ErrQUICMissingField{Field: "id"})
	}

	profile, err := h.profileService.Get(ctx, deleteReq.ID)
	if err != nil {
		h.logger.Error(err, "failed to get device profile for delete", "id", deleteReq.ID)
		return h.errorResponse(quic.StatusNotFound, ErrProfileNotFound{Profile: strconv.FormatUint(deleteReq.ID, 10)})
	}

	if err := h.profileService.Delete(ctx, profile); err != nil {
		h.logger.Error(err, "failed to delete device profile", "id", deleteReq.ID)
		return h.errorResponse(quic.StatusInternalError, ErrDeviceOperationFailed{Operation: "delete_profile", Cause: err})
	}

	resp := &DeviceUnregisterResponse{
		ID:        deleteReq.ID,
		Deleted:   true,
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
