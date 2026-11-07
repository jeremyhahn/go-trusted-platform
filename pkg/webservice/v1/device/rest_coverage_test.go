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

package device

import (
	"bytes"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// TestNewCRUDHandler tests the NewCRUDHandler constructor.
func TestNewCRUDHandler(t *testing.T) {
	logger := logging.DefaultLogger()
	respWriter := &mockResponseWriter{}
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()

	handler := NewCRUDHandler(logger, respWriter, deviceSvc, profileSvc)
	require.NotNil(t, handler)

	crud, ok := handler.(*CRUDHandler)
	require.True(t, ok)
	assert.NotNil(t, crud.logger)
	assert.NotNil(t, crud.responseWriter)
	assert.NotNil(t, crud.deviceService)
	assert.NotNil(t, crud.profileService)
}

// TestCRUDHandler_CreateDevice_SaveError tests CreateDevice with a service save error.
// TestCRUDHandler_UpdateDevice_ServiceError tests UpdateDevice with a service error.
func TestCRUDHandler_UpdateDevice_ServiceError(t *testing.T) {
	handler, deviceSvc, _ := newTestHandler()
	deviceSvc.updateErr = errors.New("database unavailable")
	deviceSvc.devices[1] = &entities.Device{ID: 1}

	body := `{"model": "NewModel"}`
	req := httptest.NewRequest(http.MethodPut, "/devices/1", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.UpdateDevice(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestCRUDHandler_UpdateDevice_InvalidBody tests UpdateDevice with invalid JSON.
func TestCRUDHandler_UpdateDevice_InvalidBody(t *testing.T) {
	handler, deviceSvc, _ := newTestHandler()
	deviceSvc.devices[1] = &entities.Device{ID: 1}

	body := `{broken json`
	req := httptest.NewRequest(http.MethodPut, "/devices/1", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.UpdateDevice(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCRUDHandler_UpdateDevice_NilService tests UpdateDevice with nil device service.
func TestCRUDHandler_UpdateDevice_NilService(t *testing.T) {
	handler, _, _ := newTestHandler()
	handler.deviceService = nil

	body := `{"model": "NewModel"}`
	req := httptest.NewRequest(http.MethodPut, "/devices/1", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.UpdateDevice(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestCRUDHandler_DeleteDevice_NilService tests DeleteDevice with nil device service.
func TestCRUDHandler_DeleteDevice_NilService(t *testing.T) {
	handler, _, _ := newTestHandler()
	handler.deviceService = nil

	req := httptest.NewRequest(http.MethodDelete, "/devices/1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	w := httptest.NewRecorder()

	handler.DeleteDevice(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestCRUDHandler_DeleteDevice_GetError tests DeleteDevice when Get fails.
func TestCRUDHandler_DeleteDevice_GetError(t *testing.T) {
	handler, deviceSvc, _ := newTestHandler()
	deviceSvc.getErr = errors.New("failed to get device")

	req := httptest.NewRequest(http.MethodDelete, "/devices/1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	w := httptest.NewRecorder()

	handler.DeleteDevice(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestCRUDHandler_DeleteDevice_DeleteError tests DeleteDevice when Delete fails.
func TestCRUDHandler_DeleteDevice_DeleteError(t *testing.T) {
	handler, deviceSvc, _ := newTestHandler()
	deviceSvc.devices[1] = &entities.Device{ID: 1}
	deviceSvc.deleteErr = errors.New("database locked")

	req := httptest.NewRequest(http.MethodDelete, "/devices/1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	w := httptest.NewRecorder()

	handler.DeleteDevice(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestCRUDHandler_ListDevices_NilService tests ListDevices with nil service.
func TestCRUDHandler_ListDevices_NilService(t *testing.T) {
	handler, _, _ := newTestHandler()
	handler.deviceService = nil

	req := httptest.NewRequest(http.MethodGet, "/devices", nil)
	w := httptest.NewRecorder()

	handler.ListDevices(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestCRUDHandler_ListDevices_ServiceError tests ListDevices with a page error.
func TestCRUDHandler_ListDevices_ServiceError(t *testing.T) {
	handler, deviceSvc, _ := newTestHandler()
	deviceSvc.pageErr = errors.New("database unavailable")

	req := httptest.NewRequest(http.MethodGet, "/devices", nil)
	w := httptest.NewRecorder()

	handler.ListDevices(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestCRUDHandler_FindDeviceBySerial_NilService tests FindDeviceBySerial with nil service.
func TestCRUDHandler_FindDeviceBySerial_NilService(t *testing.T) {
	handler, _, _ := newTestHandler()
	handler.deviceService = nil

	req := httptest.NewRequest(http.MethodGet, "/devices/serial/SN001", nil)
	req = mux.SetURLVars(req, map[string]string{"serial": "SN001"})
	w := httptest.NewRecorder()

	handler.FindDeviceBySerial(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestCRUDHandler_FindDeviceBySerial_ServiceError tests FindDeviceBySerial with a service error.
func TestCRUDHandler_FindDeviceBySerial_ServiceError(t *testing.T) {
	handler, deviceSvc, _ := newTestHandler()
	deviceSvc.findBySerialErr = errors.New("database unavailable")

	req := httptest.NewRequest(http.MethodGet, "/devices/serial/SN001", nil)
	req = mux.SetURLVars(req, map[string]string{"serial": "SN001"})
	w := httptest.NewRecorder()

	handler.FindDeviceBySerial(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestCRUDHandler_CountDevices_NilService tests CountDevices with nil device service.
func TestCRUDHandler_CountDevices_NilService(t *testing.T) {
	handler, _, _ := newTestHandler()
	handler.deviceService = nil

	req := httptest.NewRequest(http.MethodGet, "/devices/count", nil)
	w := httptest.NewRecorder()

	handler.CountDevices(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestCRUDHandler_CountDevices_ServiceError tests CountDevices with a service error.
func TestCRUDHandler_CountDevices_ServiceError(t *testing.T) {
	handler, deviceSvc, _ := newTestHandler()
	deviceSvc.countErr = errors.New("database unavailable")

	req := httptest.NewRequest(http.MethodGet, "/devices/count", nil)
	w := httptest.NewRecorder()

	handler.CountDevices(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestCRUDHandler_CreateProfile_InvalidJSON tests CreateProfile with invalid JSON body.
func TestCRUDHandler_CreateProfile_InvalidJSON(t *testing.T) {
	handler, _, _ := newTestHandler()

	body := `{broken`
	req := httptest.NewRequest(http.MethodPost, "/profiles", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateProfile(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCRUDHandler_CreateProfile_SaveError tests CreateProfile with a save error.
func TestCRUDHandler_CreateProfile_SaveError(t *testing.T) {
	handler, _, profileSvc := newTestHandler()
	profileSvc.saveErr = errors.New("database locked")

	body := `{"id": 1, "name": "TestProfile"}`
	req := httptest.NewRequest(http.MethodPost, "/profiles", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateProfile(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestCRUDHandler_GetProfileByID_NilService tests GetProfileByID with nil service.
func TestCRUDHandler_GetProfileByID_NilService(t *testing.T) {
	handler, _, _ := newTestHandler()
	handler.profileService = nil

	req := httptest.NewRequest(http.MethodGet, "/profiles/1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	w := httptest.NewRecorder()

	handler.GetProfileByID(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestCRUDHandler_GetProfileByID_InvalidID tests GetProfileByID with invalid ID.
func TestCRUDHandler_GetProfileByID_InvalidID(t *testing.T) {
	handler, _, _ := newTestHandler()

	req := httptest.NewRequest(http.MethodGet, "/profiles/abc", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "abc"})
	w := httptest.NewRecorder()

	handler.GetProfileByID(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCRUDHandler_GetProfileByID_NotFound tests GetProfileByID when not found.
func TestCRUDHandler_GetProfileByID_NotFound(t *testing.T) {
	handler, _, _ := newTestHandler()

	req := httptest.NewRequest(http.MethodGet, "/profiles/999", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "999"})
	w := httptest.NewRecorder()

	handler.GetProfileByID(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestCRUDHandler_UpdateProfile_NilService tests UpdateProfile with nil profile service.
func TestCRUDHandler_UpdateProfile_NilService(t *testing.T) {
	handler, _, _ := newTestHandler()
	handler.profileService = nil

	body := `{"name": "Updated"}`
	req := httptest.NewRequest(http.MethodPut, "/profiles/1", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	w := httptest.NewRecorder()

	handler.UpdateProfile(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestCRUDHandler_UpdateProfile_InvalidID tests UpdateProfile with invalid ID.
func TestCRUDHandler_UpdateProfile_InvalidID(t *testing.T) {
	handler, _, _ := newTestHandler()

	body := `{"name": "Updated"}`
	req := httptest.NewRequest(http.MethodPut, "/profiles/abc", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "abc"})
	w := httptest.NewRecorder()

	handler.UpdateProfile(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCRUDHandler_UpdateProfile_InvalidJSON tests UpdateProfile with invalid body.
func TestCRUDHandler_UpdateProfile_InvalidJSON(t *testing.T) {
	handler, _, _ := newTestHandler()

	body := `{broken`
	req := httptest.NewRequest(http.MethodPut, "/profiles/1", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	w := httptest.NewRecorder()

	handler.UpdateProfile(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCRUDHandler_UpdateProfile_ServiceError tests UpdateProfile with a service error.
func TestCRUDHandler_UpdateProfile_ServiceError(t *testing.T) {
	handler, _, profileSvc := newTestHandler()
	profileSvc.profiles[1] = &entities.DeviceProfile{ID: 1, Name: "Old"}
	profileSvc.updateErr = errors.New("database locked")

	body := `{"name": "Updated"}`
	req := httptest.NewRequest(http.MethodPut, "/profiles/1", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.UpdateProfile(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestCRUDHandler_DeleteProfile_NilService tests DeleteProfile with nil profile service.
func TestCRUDHandler_DeleteProfile_NilService(t *testing.T) {
	handler, _, _ := newTestHandler()
	handler.profileService = nil

	req := httptest.NewRequest(http.MethodDelete, "/profiles/1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	w := httptest.NewRecorder()

	handler.DeleteProfile(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestCRUDHandler_DeleteProfile_InvalidID tests DeleteProfile with invalid ID.
func TestCRUDHandler_DeleteProfile_InvalidID(t *testing.T) {
	handler, _, _ := newTestHandler()

	req := httptest.NewRequest(http.MethodDelete, "/profiles/abc", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "abc"})
	w := httptest.NewRecorder()

	handler.DeleteProfile(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCRUDHandler_DeleteProfile_GetError tests DeleteProfile when Get fails.
func TestCRUDHandler_DeleteProfile_GetError(t *testing.T) {
	handler, _, profileSvc := newTestHandler()
	profileSvc.getErr = errors.New("not found")

	req := httptest.NewRequest(http.MethodDelete, "/profiles/1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	w := httptest.NewRecorder()

	handler.DeleteProfile(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

// TestCRUDHandler_DeleteProfile_DeleteError tests DeleteProfile when Delete fails.
func TestCRUDHandler_DeleteProfile_DeleteError(t *testing.T) {
	handler, _, profileSvc := newTestHandler()
	profileSvc.profiles[1] = &entities.DeviceProfile{ID: 1}
	profileSvc.deleteErr = errors.New("database locked")

	req := httptest.NewRequest(http.MethodDelete, "/profiles/1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	w := httptest.NewRecorder()

	handler.DeleteProfile(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestCRUDHandler_ListProfiles_NilService tests ListProfiles with nil service.
func TestCRUDHandler_ListProfiles_NilService(t *testing.T) {
	handler, _, _ := newTestHandler()
	handler.profileService = nil

	req := httptest.NewRequest(http.MethodGet, "/profiles", nil)
	w := httptest.NewRecorder()

	handler.ListProfiles(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestCRUDHandler_ListProfiles_ServiceError tests ListProfiles with a page error.
func TestCRUDHandler_ListProfiles_ServiceError(t *testing.T) {
	handler, _, profileSvc := newTestHandler()
	profileSvc.pageErr = errors.New("database unavailable")

	req := httptest.NewRequest(http.MethodGet, "/profiles", nil)
	w := httptest.NewRecorder()

	handler.ListProfiles(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestCRUDHandler_FindProfileByMAC_NilService tests FindProfileByMAC with nil service.
func TestCRUDHandler_FindProfileByMAC_NilService(t *testing.T) {
	handler, _, _ := newTestHandler()
	handler.profileService = nil

	req := httptest.NewRequest(http.MethodGet, "/profiles/mac/AA:BB:CC", nil)
	req = mux.SetURLVars(req, map[string]string{"mac": "AA:BB:CC"})
	w := httptest.NewRecorder()

	handler.FindProfileByMAC(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestCRUDHandler_FindProfileByMAC_ServiceError tests FindProfileByMAC with error.
func TestCRUDHandler_FindProfileByMAC_ServiceError(t *testing.T) {
	handler, _, profileSvc := newTestHandler()
	profileSvc.findByMACErr = errors.New("database unavailable")

	req := httptest.NewRequest(http.MethodGet, "/profiles/mac/AA:BB:CC", nil)
	req = mux.SetURLVars(req, map[string]string{"mac": "AA:BB:CC"})
	w := httptest.NewRecorder()

	handler.FindProfileByMAC(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestCRUDHandler_FindProfileBySerial_NilService tests FindProfileBySerial with nil service.
func TestCRUDHandler_FindProfileBySerial_NilService(t *testing.T) {
	handler, _, _ := newTestHandler()
	handler.profileService = nil

	req := httptest.NewRequest(http.MethodGet, "/profiles/serial/SN001", nil)
	req = mux.SetURLVars(req, map[string]string{"serial": "SN001"})
	w := httptest.NewRecorder()

	handler.FindProfileBySerial(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestCRUDHandler_FindProfileBySerial_EmptySerial tests FindProfileBySerial with empty serial.
func TestCRUDHandler_FindProfileBySerial_EmptySerial(t *testing.T) {
	handler, _, _ := newTestHandler()

	req := httptest.NewRequest(http.MethodGet, "/profiles/serial/", nil)
	req = mux.SetURLVars(req, map[string]string{"serial": ""})
	w := httptest.NewRecorder()

	handler.FindProfileBySerial(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCRUDHandler_FindMatchingProfile_NilService tests FindMatchingProfile with nil service.
func TestCRUDHandler_FindMatchingProfile_NilService(t *testing.T) {
	handler, _, _ := newTestHandler()
	handler.profileService = nil

	body := `{"mac_address":"AA:BB:CC","serial":"SN001","model":"TPM"}`
	req := httptest.NewRequest(http.MethodPost, "/profiles/match", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.FindMatchingProfile(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestCRUDHandler_FindMatchingProfile_InvalidJSON tests FindMatchingProfile with invalid body.
func TestCRUDHandler_FindMatchingProfile_InvalidJSON(t *testing.T) {
	handler, _, _ := newTestHandler()

	body := `{broken`
	req := httptest.NewRequest(http.MethodPost, "/profiles/match", bytes.NewBufferString(body))
	w := httptest.NewRecorder()

	handler.FindMatchingProfile(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCRUDHandler_FindMatchingProfile_ServiceError tests FindMatchingProfile with error.
func TestCRUDHandler_FindMatchingProfile_ServiceError(t *testing.T) {
	handler, _, profileSvc := newTestHandler()
	profileSvc.findMatchingProfileErr = errors.New("database unavailable")

	body := `{"mac_address":"AA:BB:CC","serial":"SN001","model":"TPM"}`
	req := httptest.NewRequest(http.MethodPost, "/profiles/match", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.FindMatchingProfile(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestCRUDHandler_CountProfiles_NilService tests CountProfiles with nil service.
func TestCRUDHandler_CountProfiles_NilService(t *testing.T) {
	handler, _, _ := newTestHandler()
	handler.profileService = nil

	req := httptest.NewRequest(http.MethodGet, "/profiles/count", nil)
	w := httptest.NewRecorder()

	handler.CountProfiles(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestCRUDHandler_CountProfiles_ServiceError tests CountProfiles with a service error.
func TestCRUDHandler_CountProfiles_ServiceError(t *testing.T) {
	handler, _, profileSvc := newTestHandler()
	profileSvc.countErr = errors.New("database unavailable")

	req := httptest.NewRequest(http.MethodGet, "/profiles/count", nil)
	w := httptest.NewRecorder()

	handler.CountProfiles(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestCRUDHandler_ActivateDevice_NilProfileService tests ActivateDevice with nil profile service.
func TestCRUDHandler_ActivateDevice_NilProfileService(t *testing.T) {
	handler, _, _ := newTestHandler()
	handler.profileService = nil

	body := `{"serial": "SN001"}`
	req := httptest.NewRequest(http.MethodPost, "/device/activate", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ActivateDevice(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestCRUDHandler_ActivateDevice_InvalidJSON tests ActivateDevice with invalid body.
func TestCRUDHandler_ActivateDevice_InvalidJSON(t *testing.T) {
	handler, _, _ := newTestHandler()

	body := `{broken`
	req := httptest.NewRequest(http.MethodPost, "/device/activate", bytes.NewBufferString(body))
	w := httptest.NewRecorder()

	handler.ActivateDevice(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

// TestCRUDHandler_ActivateDevice_FindDeviceError tests ActivateDevice with device lookup error.
func TestCRUDHandler_ActivateDevice_FindDeviceError(t *testing.T) {
	handler, deviceSvc, _ := newTestHandler()
	deviceSvc.findBySerialErr = errors.New("database unavailable")

	body := `{"serial": "SN001"}`
	req := httptest.NewRequest(http.MethodPost, "/device/activate", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ActivateDevice(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

// TestCRUDHandler_ActivateDevice_FindProfileError tests ActivateDevice with profile lookup error.
func TestCRUDHandler_ActivateDevice_FindProfileError(t *testing.T) {
	handler, deviceSvc, profileSvc := newTestHandler()
	deviceSvc.devices[1] = &entities.Device{ID: 1, Serial: "SN001", Model: "TPM"}
	profileSvc.findMatchingProfileErr = errors.New("no matching profile")

	body := `{"serial": "SN001", "mac_address": "AA:BB:CC"}`
	req := httptest.NewRequest(http.MethodPost, "/device/activate", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ActivateDevice(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}
