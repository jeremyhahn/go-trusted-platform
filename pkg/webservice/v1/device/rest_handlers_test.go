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
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
)

// Mock device service for testing
type mockDeviceService struct {
	devices         map[uint64]*entities.Device
	saveErr         error
	getErr          error
	deleteErr       error
	updateErr       error
	countErr        error
	pageErr         error
	findBySerialErr error
}

func newMockDeviceService() *mockDeviceService {
	return &mockDeviceService{
		devices: make(map[uint64]*entities.Device),
	}
}

func (m *mockDeviceService) Save(ctx context.Context, device *entities.Device) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.devices[device.ID] = device
	return nil
}

func (m *mockDeviceService) Get(ctx context.Context, id uint64) (*entities.Device, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	device, ok := m.devices[id]
	if !ok {
		return nil, errors.New("device not found")
	}
	return device, nil
}

func (m *mockDeviceService) Delete(ctx context.Context, device *entities.Device) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.devices, device.ID)
	return nil
}

func (m *mockDeviceService) Update(ctx context.Context, device *entities.Device) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	if _, ok := m.devices[device.ID]; !ok {
		return errors.New("failed to get device for update")
	}
	m.devices[device.ID] = device
	return nil
}

func (m *mockDeviceService) Count(ctx context.Context) (int, error) {
	if m.countErr != nil {
		return 0, m.countErr
	}
	return len(m.devices), nil
}

func (m *mockDeviceService) Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*entities.Device], error) {
	if m.pageErr != nil {
		return datastore.PageResult[*entities.Device]{}, m.pageErr
	}
	result := datastore.PageResult[*entities.Device]{
		Entities: make([]*entities.Device, 0, len(m.devices)),
		Page:     query.Page,
		PageSize: query.PageSize,
		Total:    len(m.devices),
	}
	for _, d := range m.devices {
		result.Entities = append(result.Entities, d)
	}
	return result, nil
}

func (m *mockDeviceService) FindBySerial(ctx context.Context, serial string) (*entities.Device, error) {
	if m.findBySerialErr != nil {
		return nil, m.findBySerialErr
	}
	for _, d := range m.devices {
		if d.Serial == serial {
			return d, nil
		}
	}
	return nil, errors.New("device not found")
}

// FindByHostname finds a device by its IDevID hostname.
func (m *mockDeviceService) FindByHostname(ctx context.Context, hostname string) (*entities.Device, error) {
	for _, d := range m.devices {
		if d.Hostname == hostname {
			return d, nil
		}
	}
	return nil, errors.New("device not found by hostname")
}

// Mock profile service for testing
type mockProfileService struct {
	profiles               map[uint64]*entities.DeviceProfile
	saveErr                error
	getErr                 error
	deleteErr              error
	updateErr              error
	countErr               error
	pageErr                error
	findByMACErr           error
	findBySerialErr        error
	findMatchingProfileErr error
	assignErr              error
	unassignErr            error
}

func newMockProfileService() *mockProfileService {
	return &mockProfileService{
		profiles: make(map[uint64]*entities.DeviceProfile),
	}
}

func (m *mockProfileService) Save(ctx context.Context, profile *entities.DeviceProfile) error {
	if m.saveErr != nil {
		return m.saveErr
	}
	m.profiles[profile.ID] = profile
	return nil
}

func (m *mockProfileService) Get(ctx context.Context, id uint64) (*entities.DeviceProfile, error) {
	if m.getErr != nil {
		return nil, m.getErr
	}
	profile, ok := m.profiles[id]
	if !ok {
		return nil, errors.New("profile not found")
	}
	return profile, nil
}

func (m *mockProfileService) Delete(ctx context.Context, profile *entities.DeviceProfile) error {
	if m.deleteErr != nil {
		return m.deleteErr
	}
	delete(m.profiles, profile.ID)
	return nil
}

func (m *mockProfileService) Update(ctx context.Context, profile *entities.DeviceProfile) error {
	if m.updateErr != nil {
		return m.updateErr
	}
	if _, ok := m.profiles[profile.ID]; !ok {
		return errors.New("failed to get profile for update")
	}
	m.profiles[profile.ID] = profile
	return nil
}

func (m *mockProfileService) Count(ctx context.Context) (int, error) {
	if m.countErr != nil {
		return 0, m.countErr
	}
	return len(m.profiles), nil
}

func (m *mockProfileService) Page(ctx context.Context, query datastore.PageQuery) (datastore.PageResult[*entities.DeviceProfile], error) {
	if m.pageErr != nil {
		return datastore.PageResult[*entities.DeviceProfile]{}, m.pageErr
	}
	result := datastore.PageResult[*entities.DeviceProfile]{
		Entities: make([]*entities.DeviceProfile, 0, len(m.profiles)),
		Page:     query.Page,
		PageSize: query.PageSize,
		Total:    len(m.profiles),
	}
	for _, p := range m.profiles {
		result.Entities = append(result.Entities, p)
	}
	return result, nil
}

func (m *mockProfileService) FindByMACAddress(ctx context.Context, macAddr string) (*entities.DeviceProfile, error) {
	if m.findByMACErr != nil {
		return nil, m.findByMACErr
	}
	for _, p := range m.profiles {
		if p.MatchRules != nil && p.MatchRules.MACPrefix == macAddr {
			return p, nil
		}
	}
	return nil, errors.New("profile not found")
}

func (m *mockProfileService) FindBySerial(ctx context.Context, serial string) (*entities.DeviceProfile, error) {
	if m.findBySerialErr != nil {
		return nil, m.findBySerialErr
	}
	for _, p := range m.profiles {
		if p.MatchRules != nil && p.MatchRules.SerialPrefix == serial {
			return p, nil
		}
	}
	return nil, errors.New("profile not found")
}

func (m *mockProfileService) FindMatchingProfile(ctx context.Context, macAddr, serial, model string) (*entities.DeviceProfile, error) {
	if m.findMatchingProfileErr != nil {
		return nil, m.findMatchingProfileErr
	}
	for _, p := range m.profiles {
		if p.MatchRules != nil {
			if p.MatchRules.Model == model || p.MatchRules.SerialPrefix == serial {
				return p, nil
			}
		}
	}
	return nil, errors.New("profile not found")
}

func (m *mockProfileService) AssignToDeviceWithEK(ctx context.Context, profileID uint64, ekSerial, mac, ekCertPEM string) error {
	if m.assignErr != nil {
		return m.assignErr
	}
	profile, ok := m.profiles[profileID]
	if !ok {
		return errors.New("profile not found")
	}
	if ekSerial != "" {
		profile.EKSerial = ekSerial
	}
	if mac != "" {
		profile.MACAddress = mac
	}
	if ekCertPEM != "" {
		profile.EKCert = ekCertPEM
	}
	profile.Assigned = true
	profile.AssignedAt = time.Now().UTC()
	return nil
}

func (m *mockProfileService) UnassignFromDevice(ctx context.Context, profileID uint64) error {
	if m.unassignErr != nil {
		return m.unassignErr
	}
	profile, ok := m.profiles[profileID]
	if !ok {
		return errors.New("profile not found")
	}
	profile.EKSerial = ""
	profile.MACAddress = ""
	profile.EKCert = ""
	profile.Assigned = false
	profile.AssignedAt = time.Time{}
	return nil
}

// Mock response writer for testing
type mockResponseWriter struct{}

func (m *mockResponseWriter) Success200(w http.ResponseWriter, r *http.Request, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(data)
}

func (m *mockResponseWriter) Success201(w http.ResponseWriter, r *http.Request, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(data)
}

func (m *mockResponseWriter) Error400(w http.ResponseWriter, r *http.Request, err error) {
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func (m *mockResponseWriter) Error401(w http.ResponseWriter, r *http.Request, err error) {
	w.WriteHeader(http.StatusUnauthorized)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func (m *mockResponseWriter) Error404(w http.ResponseWriter, r *http.Request, err error) {
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func (m *mockResponseWriter) Error500(w http.ResponseWriter, r *http.Request, err error) {
	w.WriteHeader(http.StatusInternalServerError)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func (m *mockResponseWriter) Write(w http.ResponseWriter, r *http.Request, status int, resp interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}

func (m *mockResponseWriter) WriteYaml(w http.ResponseWriter, status int, resp interface{}) {
	w.Header().Set("Content-Type", "application/yaml")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}

func (m *mockResponseWriter) WriteJson(w http.ResponseWriter, status int, resp interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(resp)
}

func (m *mockResponseWriter) Success404(w http.ResponseWriter, r *http.Request, payload interface{}, err error) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusNotFound)
	json.NewEncoder(w).Encode(map[string]interface{}{"payload": payload, "error": err.Error()})
}

func (m *mockResponseWriter) Error200(w http.ResponseWriter, r *http.Request, err error) {
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func (m *mockResponseWriter) Error403(w http.ResponseWriter, r *http.Request, err error, payload interface{}) {
	w.WriteHeader(http.StatusForbidden)
	json.NewEncoder(w).Encode(map[string]interface{}{"error": err.Error(), "payload": payload})
}

func (m *mockResponseWriter) WriteErrorResponse(w http.ResponseWriter, r *http.Request, code int, err error) {
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": err.Error()})
}

func (m *mockResponseWriter) WriteJSONResponse(w http.ResponseWriter, r *http.Request, code int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(data)
}

func newTestHandler() (*CRUDHandler, *mockDeviceService, *mockProfileService) {
	logger := logging.DefaultLogger()
	deviceSvc := newMockDeviceService()
	profileSvc := newMockProfileService()
	respWriter := &mockResponseWriter{}

	handler := &CRUDHandler{
		logger:         logger,
		responseWriter: respWriter,
		deviceService:  deviceSvc,
		profileService: profileSvc,
	}

	return handler, deviceSvc, profileSvc
}

func TestCRUDHandler_CreateDevice(t *testing.T) {
	handler, deviceSvc, _ := newTestHandler()

	body := `{"id": 1, "model": "TestTPM", "serial": "SN001"}`
	req := httptest.NewRequest(http.MethodPost, "/devices", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateDevice(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.NotNil(t, deviceSvc.devices[1])
	assert.Equal(t, "TestTPM", deviceSvc.devices[1].Model)
}

func TestCRUDHandler_CreateDevice_MissingID(t *testing.T) {
	// The handler auto-allocates a non-zero device ID when the client
	// omits it (the WebUI Register Device dialog can't know one up-front
	// and the platform owns identity assignment). The expected result is
	// 201 Created with a synthesised ID, not a 400.
	handler, deviceSvc, _ := newTestHandler()

	body := `{"model": "TestTPM", "serial": "SN001"}`
	req := httptest.NewRequest(http.MethodPost, "/devices", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateDevice(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	// Exactly one device should have been saved with a non-zero ID.
	require.Len(t, deviceSvc.devices, 1)
	for id, dev := range deviceSvc.devices {
		assert.NotZero(t, id)
		assert.Equal(t, "TestTPM", dev.Model)
		assert.Equal(t, "SN001", dev.Serial)
	}
}

func TestCRUDHandler_CreateDevice_InvalidJSON(t *testing.T) {
	handler, _, _ := newTestHandler()

	body := `{"invalid json`
	req := httptest.NewRequest(http.MethodPost, "/devices", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateDevice(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCRUDHandler_CreateDevice_NilService(t *testing.T) {
	handler, _, _ := newTestHandler()
	handler.deviceService = nil

	body := `{"id": 1, "model": "TestTPM", "serial": "SN001"}`
	req := httptest.NewRequest(http.MethodPost, "/devices", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateDevice(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestCRUDHandler_GetDevice(t *testing.T) {
	handler, deviceSvc, _ := newTestHandler()
	deviceSvc.devices[1] = &entities.Device{
		ID:     1,
		Model:  "TestTPM",
		Serial: "SN001",
	}

	req := httptest.NewRequest(http.MethodGet, "/devices/1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	w := httptest.NewRecorder()

	handler.GetDevice(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp DeviceResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, uint64(1), resp.ID)
	assert.Equal(t, "TestTPM", resp.Model)
}

func TestCRUDHandler_GetDevice_InvalidID(t *testing.T) {
	handler, _, _ := newTestHandler()

	req := httptest.NewRequest(http.MethodGet, "/devices/invalid", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "invalid"})
	w := httptest.NewRecorder()

	handler.GetDevice(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCRUDHandler_GetDevice_NotFound(t *testing.T) {
	handler, _, _ := newTestHandler()

	req := httptest.NewRequest(http.MethodGet, "/devices/999", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "999"})
	w := httptest.NewRecorder()

	handler.GetDevice(w, req)

	assert.Equal(t, http.StatusNotFound, w.Code)
}

func TestCRUDHandler_UpdateDevice(t *testing.T) {
	handler, deviceSvc, _ := newTestHandler()
	deviceSvc.devices[1] = &entities.Device{
		ID:     1,
		Model:  "OldModel",
		Serial: "SN001",
	}

	body := `{"model": "NewModel", "serial": "SN001"}`
	req := httptest.NewRequest(http.MethodPut, "/devices/1", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.UpdateDevice(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "NewModel", deviceSvc.devices[1].Model)
}

func TestCRUDHandler_UpdateDevice_InvalidID(t *testing.T) {
	handler, _, _ := newTestHandler()

	body := `{"model": "NewModel"}`
	req := httptest.NewRequest(http.MethodPut, "/devices/invalid", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "invalid"})
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.UpdateDevice(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCRUDHandler_DeleteDevice(t *testing.T) {
	handler, deviceSvc, _ := newTestHandler()
	deviceSvc.devices[1] = &entities.Device{ID: 1}

	req := httptest.NewRequest(http.MethodDelete, "/devices/1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	w := httptest.NewRecorder()

	handler.DeleteDevice(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	_, exists := deviceSvc.devices[1]
	assert.False(t, exists)
}

func TestCRUDHandler_DeleteDevice_InvalidID(t *testing.T) {
	handler, _, _ := newTestHandler()

	req := httptest.NewRequest(http.MethodDelete, "/devices/invalid", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "invalid"})
	w := httptest.NewRecorder()

	handler.DeleteDevice(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCRUDHandler_ListDevices(t *testing.T) {
	handler, deviceSvc, _ := newTestHandler()
	deviceSvc.devices[1] = &entities.Device{ID: 1, Model: "TPM1"}
	deviceSvc.devices[2] = &entities.Device{ID: 2, Model: "TPM2"}

	req := httptest.NewRequest(http.MethodGet, "/devices?page=1&page_size=10", nil)
	w := httptest.NewRecorder()

	handler.ListDevices(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp DeviceListResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Len(t, resp.Devices, 2)
}

func TestCRUDHandler_ListDevices_WithPagination(t *testing.T) {
	handler, deviceSvc, _ := newTestHandler()
	for i := uint64(1); i <= 20; i++ {
		deviceSvc.devices[i] = &entities.Device{ID: i}
	}

	req := httptest.NewRequest(http.MethodGet, "/devices?page=2&page_size=5&sort_order=desc", nil)
	w := httptest.NewRecorder()

	handler.ListDevices(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCRUDHandler_FindDeviceBySerial(t *testing.T) {
	handler, deviceSvc, _ := newTestHandler()
	deviceSvc.devices[1] = &entities.Device{ID: 1, Serial: "SN001"}

	req := httptest.NewRequest(http.MethodGet, "/devices/serial/SN001", nil)
	req = mux.SetURLVars(req, map[string]string{"serial": "SN001"})
	w := httptest.NewRecorder()

	handler.FindDeviceBySerial(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCRUDHandler_FindDeviceBySerial_EmptySerial(t *testing.T) {
	handler, _, _ := newTestHandler()

	req := httptest.NewRequest(http.MethodGet, "/devices/serial/", nil)
	req = mux.SetURLVars(req, map[string]string{"serial": ""})
	w := httptest.NewRecorder()

	handler.FindDeviceBySerial(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCRUDHandler_CountDevices(t *testing.T) {
	handler, deviceSvc, _ := newTestHandler()
	deviceSvc.devices[1] = &entities.Device{ID: 1}
	deviceSvc.devices[2] = &entities.Device{ID: 2}

	req := httptest.NewRequest(http.MethodGet, "/devices/count", nil)
	w := httptest.NewRecorder()

	handler.CountDevices(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp CountResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, 2, resp.Count)
}

func TestCRUDHandler_CreateProfile(t *testing.T) {
	handler, _, profileSvc := newTestHandler()

	body := `{"id": 1, "name": "TestProfile"}`
	req := httptest.NewRequest(http.MethodPost, "/device/profiles", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateProfile(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	assert.NotNil(t, profileSvc.profiles[1])
}

func TestCRUDHandler_CreateProfile_MissingID(t *testing.T) {
	// Profile create auto-allocates the ID — mirror the device-create
	// behaviour so the WebUI Create Profile dialog can submit without
	// inventing one. Expected result is 201 Created with a non-zero
	// synthesised ID.
	handler, _, profileSvc := newTestHandler()

	body := `{"name": "TestProfile"}`
	req := httptest.NewRequest(http.MethodPost, "/device/profiles", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateProfile(w, req)

	assert.Equal(t, http.StatusCreated, w.Code)
	require.Len(t, profileSvc.profiles, 1)
	for id := range profileSvc.profiles {
		assert.NotZero(t, id)
	}
}

func TestCRUDHandler_CreateProfile_NilService(t *testing.T) {
	handler, _, _ := newTestHandler()
	handler.profileService = nil

	body := `{"id": 1, "name": "TestProfile"}`
	req := httptest.NewRequest(http.MethodPost, "/device/profiles", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.CreateProfile(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestCRUDHandler_GetProfileByID(t *testing.T) {
	handler, _, profileSvc := newTestHandler()
	profileSvc.profiles[1] = &entities.DeviceProfile{ID: 1, Name: "TestProfile"}

	req := httptest.NewRequest(http.MethodGet, "/device/profiles/1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	w := httptest.NewRecorder()

	handler.GetProfileByID(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ProfileFullResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "TestProfile", resp.Name)
}

func TestCRUDHandler_UpdateProfile(t *testing.T) {
	handler, _, profileSvc := newTestHandler()
	profileSvc.profiles[1] = &entities.DeviceProfile{ID: 1, Name: "OldName"}

	body := `{"name": "NewName"}`
	req := httptest.NewRequest(http.MethodPut, "/device/profiles/1", bytes.NewBufferString(body))
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.UpdateProfile(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "NewName", profileSvc.profiles[1].Name)
}

func TestCRUDHandler_DeleteProfile(t *testing.T) {
	handler, _, profileSvc := newTestHandler()
	profileSvc.profiles[1] = &entities.DeviceProfile{ID: 1}

	req := httptest.NewRequest(http.MethodDelete, "/device/profiles/1", nil)
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	w := httptest.NewRecorder()

	handler.DeleteProfile(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	_, exists := profileSvc.profiles[1]
	assert.False(t, exists)
}

func TestCRUDHandler_ListProfiles(t *testing.T) {
	handler, _, profileSvc := newTestHandler()
	profileSvc.profiles[1] = &entities.DeviceProfile{ID: 1, Name: "P1"}
	profileSvc.profiles[2] = &entities.DeviceProfile{ID: 2, Name: "P2"}

	req := httptest.NewRequest(http.MethodGet, "/device/profiles", nil)
	w := httptest.NewRecorder()

	handler.ListProfiles(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCRUDHandler_FindProfileByMAC(t *testing.T) {
	handler, _, profileSvc := newTestHandler()
	profileSvc.profiles[1] = &entities.DeviceProfile{
		ID:   1,
		Name: "TestProfile",
		MatchRules: &entities.ProfileMatchRules{
			MACPrefix: "AA:BB:CC",
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/device/profiles/mac/AA:BB:CC", nil)
	req = mux.SetURLVars(req, map[string]string{"mac": "AA:BB:CC"})
	w := httptest.NewRecorder()

	handler.FindProfileByMAC(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCRUDHandler_FindProfileByMAC_EmptyMAC(t *testing.T) {
	handler, _, _ := newTestHandler()

	req := httptest.NewRequest(http.MethodGet, "/device/profiles/mac/", nil)
	req = mux.SetURLVars(req, map[string]string{"mac": ""})
	w := httptest.NewRecorder()

	handler.FindProfileByMAC(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCRUDHandler_FindProfileBySerial(t *testing.T) {
	handler, _, profileSvc := newTestHandler()
	profileSvc.profiles[1] = &entities.DeviceProfile{
		ID:   1,
		Name: "TestProfile",
		MatchRules: &entities.ProfileMatchRules{
			SerialPrefix: "SN001",
		},
	}

	req := httptest.NewRequest(http.MethodGet, "/device/profiles/serial/SN001", nil)
	req = mux.SetURLVars(req, map[string]string{"serial": "SN001"})
	w := httptest.NewRecorder()

	handler.FindProfileBySerial(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCRUDHandler_FindMatchingProfile(t *testing.T) {
	handler, _, profileSvc := newTestHandler()
	profileSvc.profiles[1] = &entities.DeviceProfile{
		ID:   1,
		Name: "TestProfile",
		MatchRules: &entities.ProfileMatchRules{
			Model: "TestModel",
		},
	}

	body := `{"model": "TestModel"}`
	req := httptest.NewRequest(http.MethodPost, "/device/profiles/match", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.FindMatchingProfile(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestCRUDHandler_CountProfiles(t *testing.T) {
	handler, _, profileSvc := newTestHandler()
	profileSvc.profiles[1] = &entities.DeviceProfile{ID: 1}
	profileSvc.profiles[2] = &entities.DeviceProfile{ID: 2}
	profileSvc.profiles[3] = &entities.DeviceProfile{ID: 3}

	req := httptest.NewRequest(http.MethodGet, "/device/profiles/count", nil)
	w := httptest.NewRecorder()

	handler.CountProfiles(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp CountResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, 3, resp.Count)
}

func TestCRUDHandler_ActivateDevice(t *testing.T) {
	handler, deviceSvc, profileSvc := newTestHandler()
	deviceSvc.devices[1] = &entities.Device{
		ID:     1,
		Model:  "TestModel",
		Serial: "SN001",
	}
	profileSvc.profiles[1] = &entities.DeviceProfile{
		ID:   1,
		Name: "TestProfile",
		MatchRules: &entities.ProfileMatchRules{
			Model: "TestModel",
		},
		Networks: map[string]*entities.NetworkPhaseConfig{
			entities.DefaultPostEnrollmentNetwork: {
				VLAN: 100,
			},
		},
	}

	body := `{"serial": "SN001"}`
	req := httptest.NewRequest(http.MethodPost, "/device/activate-json", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ActivateDevice(w, req)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp ActivationResponse
	err := json.NewDecoder(w.Body).Decode(&resp)
	require.NoError(t, err)
	assert.Equal(t, "activated", resp.Status)
	assert.Equal(t, uint16(100), resp.VLAN)
}

func TestCRUDHandler_ActivateDevice_MissingSerial(t *testing.T) {
	handler, _, _ := newTestHandler()

	body := `{}`
	req := httptest.NewRequest(http.MethodPost, "/device/activate-json", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ActivateDevice(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestCRUDHandler_ActivateDevice_NilDeviceService(t *testing.T) {
	handler, _, _ := newTestHandler()
	handler.deviceService = nil

	body := `{"serial": "SN001"}`
	req := httptest.NewRequest(http.MethodPost, "/device/activate-json", bytes.NewBufferString(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()

	handler.ActivateDevice(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestCRUDHandler_StringToDeviceRole(t *testing.T) {
	handler, _, _ := newTestHandler()

	assert.Equal(t, entities.DeviceRoleServer, handler.stringToDeviceRole("server"))
	assert.Equal(t, entities.DeviceRoleClient, handler.stringToDeviceRole("client"))
	assert.Equal(t, entities.DeviceRoleWorkstation, handler.stringToDeviceRole("workstation"))
	assert.Equal(t, entities.DeviceRoleEdge, handler.stringToDeviceRole("edge"))
	assert.Equal(t, entities.DeviceRoleIoT, handler.stringToDeviceRole("iot"))
	assert.Equal(t, entities.DeviceRoleGateway, handler.stringToDeviceRole("gateway"))
	assert.Equal(t, entities.DeviceRoleLoadBalancer, handler.stringToDeviceRole("load-balancer"))
	assert.Equal(t, entities.DeviceRoleLoadBalancer, handler.stringToDeviceRole("loadbalancer"))
	assert.Equal(t, entities.DeviceRoleUnknown, handler.stringToDeviceRole("unknown"))
	assert.Equal(t, entities.DeviceRoleUnknown, handler.stringToDeviceRole(""))
}

func TestCRUDHandler_StringToAuthMethod(t *testing.T) {
	handler, _, _ := newTestHandler()

	assert.Equal(t, entities.AuthMethod802_1X, handler.stringToAuthMethod("802.1x"))
	assert.Equal(t, entities.AuthMethod802_1X, handler.stringToAuthMethod("8021x"))
	assert.Equal(t, entities.AuthMethodNone, handler.stringToAuthMethod("none"))
	assert.Equal(t, entities.AuthMethodNone, handler.stringToAuthMethod(""))
}

func TestCRUDHandler_CalculateTotalPages(t *testing.T) {
	handler, _, _ := newTestHandler()

	assert.Equal(t, 0, handler.calculateTotalPages(10, 0))
	assert.Equal(t, 2, handler.calculateTotalPages(10, 5))
	assert.Equal(t, 3, handler.calculateTotalPages(11, 5))
	assert.Equal(t, 1, handler.calculateTotalPages(5, 10))
	assert.Equal(t, 1, handler.calculateTotalPages(1, 10))
}

func TestCRUDHandler_GetPaginationQuery(t *testing.T) {
	handler, _, _ := newTestHandler()

	t.Run("default values", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		query := handler.getPaginationQuery(req)
		assert.Equal(t, 1, query.Page)
		assert.Equal(t, 25, query.PageSize)
		assert.Equal(t, datastore.SortAscending, query.SortOrder)
	})

	t.Run("with custom values", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test?page=3&page_size=50&sort_order=desc", nil)
		query := handler.getPaginationQuery(req)
		assert.Equal(t, 3, query.Page)
		assert.Equal(t, 50, query.PageSize)
		assert.Equal(t, datastore.SortDescending, query.SortOrder)
	})

	t.Run("max page size limit", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test?page_size=1000", nil)
		query := handler.getPaginationQuery(req)
		assert.Equal(t, 100, query.PageSize)
	})

	t.Run("ascending sort order", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test?sort_order=ascending", nil)
		query := handler.getPaginationQuery(req)
		assert.Equal(t, datastore.SortAscending, query.SortOrder)
	})

	t.Run("descending sort order", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/test?sort_order=descending", nil)
		query := handler.getPaginationQuery(req)
		assert.Equal(t, datastore.SortDescending, query.SortOrder)
	})
}

func TestCRUDHandler_HandleServiceError(t *testing.T) {
	handler, _, _ := newTestHandler()

	t.Run("not found error", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		handler.handleServiceError(w, req, errors.New("device not found"))
		assert.Equal(t, http.StatusNotFound, w.Code)
	})

	t.Run("invalid ID error", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		handler.handleServiceError(w, req, errors.New("invalid device ID"))
		assert.Equal(t, http.StatusBadRequest, w.Code)
	})

	t.Run("generic error", func(t *testing.T) {
		w := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/test", nil)
		handler.handleServiceError(w, req, errors.New("some other error"))
		assert.Equal(t, http.StatusInternalServerError, w.Code)
	})
}

func TestErrors(t *testing.T) {
	t.Run("ErrDeviceServiceNotInitialized", func(t *testing.T) {
		err := ErrDeviceServiceNotInitialized{}
		assert.Equal(t, "device service not initialized", err.Error())
	})

	t.Run("ErrProfileServiceNotInitializedError", func(t *testing.T) {
		err := ErrProfileServiceNotInitializedError{}
		assert.Equal(t, "profile service not initialized", err.Error())
	})

	t.Run("ErrInvalidRequestBody", func(t *testing.T) {
		err := ErrInvalidRequestBody{Reason: "test reason"}
		assert.Equal(t, "invalid request body: test reason", err.Error())

		err2 := ErrInvalidRequestBody{}
		assert.Equal(t, "invalid request body", err2.Error())
	})

	t.Run("ErrMissingDeviceID", func(t *testing.T) {
		err := ErrMissingDeviceID{}
		assert.Equal(t, "device id is required", err.Error())
	})

	t.Run("ErrMissingProfileID", func(t *testing.T) {
		err := ErrMissingProfileID{}
		assert.Equal(t, "profile id is required", err.Error())
	})

	t.Run("ErrMissingSerialNumber", func(t *testing.T) {
		err := ErrMissingSerialNumber{}
		assert.Equal(t, "serial number is required", err.Error())
	})

	t.Run("ErrMissingMACAddress", func(t *testing.T) {
		err := ErrMissingMACAddress{}
		assert.Equal(t, "mac address is required", err.Error())
	})

	t.Run("ErrDeviceNotFound", func(t *testing.T) {
		err := ErrDeviceNotFound{Serial: "SN001"}
		assert.Equal(t, "device not found: serial=SN001", err.Error())

		err2 := ErrDeviceNotFound{}
		assert.Equal(t, "device not found", err2.Error())
	})

	t.Run("ErrProfileNotFoundError", func(t *testing.T) {
		err := ErrProfileNotFoundError{Serial: "SN001"}
		assert.Equal(t, "profile not found: serial=SN001", err.Error())

		err2 := ErrProfileNotFoundError{MAC: "AA:BB:CC"}
		assert.Equal(t, "profile not found: mac=AA:BB:CC", err2.Error())

		err3 := ErrProfileNotFoundError{}
		assert.Equal(t, "profile not found", err3.Error())
	})

	t.Run("ErrInvalidDeviceID", func(t *testing.T) {
		err := ErrInvalidDeviceID{}
		assert.Equal(t, "invalid device id", err.Error())
	})

	t.Run("ErrInvalidProfileID", func(t *testing.T) {
		err := ErrInvalidProfileID{}
		assert.Equal(t, "invalid profile id", err.Error())
	})

	t.Run("ErrInvalidPaginationParams", func(t *testing.T) {
		err := ErrInvalidPaginationParams{Reason: "test reason"}
		assert.Equal(t, "invalid pagination parameters: test reason", err.Error())

		err2 := ErrInvalidPaginationParams{}
		assert.Equal(t, "invalid pagination parameters", err2.Error())
	})
}

func TestNetworkPhaseConversions(t *testing.T) {
	handler, _, _ := newTestHandler()

	t.Run("networkPhaseRequestToEntity", func(t *testing.T) {
		req := &NetworkPhaseRequest{
			VLAN:     100,
			StaticIP: "192.168.1.100",
			Gateway:  "192.168.1.1",
			DNS:      []string{"8.8.8.8"},
			DHCPPool: &DHCPPoolRequest{
				Network:    "192.168.1.0/24",
				RangeStart: "192.168.1.10",
				RangeEnd:   "192.168.1.50",
				LeaseTime:  3600,
			},
			ACLs: []ACLRequest{
				{
					Priority: 100,
					Protocol: "tcp",
					DstPort:  443,
					Action:   "allow",
				},
			},
		}

		entity := handler.networkPhaseRequestToEntity(req)
		assert.Equal(t, uint16(100), entity.VLAN)
		assert.Equal(t, "192.168.1.100", entity.StaticIP)
		assert.NotNil(t, entity.DHCPPool)
		assert.Equal(t, "192.168.1.0/24", entity.DHCPPool.Network)
		assert.Len(t, entity.ACLs, 1)
	})

	t.Run("networkPhaseEntityToResponse", func(t *testing.T) {
		entity := &entities.NetworkPhaseConfig{
			VLAN:     100,
			StaticIP: "192.168.1.100",
			DHCPPool: &entities.DHCPPoolConfig{
				Network: "192.168.1.0/24",
			},
			ACLs: []entities.ACLConfig{
				{Priority: 100, Action: "allow"},
			},
		}

		resp := handler.networkPhaseEntityToResponse(entity)
		assert.Equal(t, uint16(100), resp.VLAN)
		assert.NotNil(t, resp.DHCPPool)
		assert.Len(t, resp.ACLs, 1)
	})

	t.Run("networkPhaseEntityToResponse_nil", func(t *testing.T) {
		resp := handler.networkPhaseEntityToResponse(nil)
		assert.Nil(t, resp)
	})
}

func TestProfileConversions(t *testing.T) {
	handler, _, _ := newTestHandler()

	t.Run("requestToProfile_complete", func(t *testing.T) {
		req := &ProfileRequest{
			ID:   1,
			Name: "TestProfile",
			Role: "server",
			Networks: map[string]*NetworkPhaseRequest{
				entities.DefaultEnrollmentNetwork:     {VLAN: 10},
				entities.DefaultPostEnrollmentNetwork: {VLAN: 100},
				entities.DefaultFailureNetwork:        {VLAN: 999},
			},
			PlatformdConfig: &PlatformdConfigRequest{
				ConfigType: "yaml",
				ConfigPath: "/etc/platformd/config.yaml",
			},
			MatchRules: &MatchRulesRequest{
				MACPrefix:    "AA:BB:CC",
				SerialPrefix: "SN",
			},
		}

		profile := handler.requestToProfile(req)
		assert.Equal(t, uint64(1), profile.ID)
		assert.Equal(t, "TestProfile", profile.Name)
		assert.Equal(t, entities.DeviceRoleServer, profile.Role)
		assert.NotNil(t, profile.GetEnrollmentNetworkConfig())
		assert.NotNil(t, profile.GetPostEnrollmentNetworkConfig())
		assert.NotNil(t, profile.GetFailureNetworkConfig())
		assert.NotNil(t, profile.PlatformdConfig)
		assert.NotNil(t, profile.MatchRules)
	})

	t.Run("profileToResponse_complete", func(t *testing.T) {
		profile := &entities.DeviceProfile{
			ID:   1,
			Name: "TestProfile",
			Role: entities.DeviceRoleServer,
			Networks: map[string]*entities.NetworkPhaseConfig{
				entities.DefaultEnrollmentNetwork: {
					VLAN: 10,
				},
				entities.DefaultPostEnrollmentNetwork: {
					VLAN: 100,
				},
				entities.DefaultFailureNetwork: {
					VLAN: 999,
				},
			},
			PlatformdConfig: &entities.PlatformdConfigRef{
				ConfigType: "yaml",
			},
			MatchRules: &entities.ProfileMatchRules{
				MACPrefix: "AA:BB:CC",
			},
		}

		resp := handler.profileToResponse(profile)
		assert.Equal(t, uint64(1), resp.ID)
		assert.Equal(t, "TestProfile", resp.Name)
		assert.NotNil(t, resp.Networks[entities.DefaultEnrollmentNetwork])
		assert.NotNil(t, resp.Networks[entities.DefaultPostEnrollmentNetwork])
		assert.NotNil(t, resp.Networks[entities.DefaultFailureNetwork])
		assert.NotNil(t, resp.PlatformdConfig)
		assert.NotNil(t, resp.MatchRules)
	})

	t.Run("profileToResponse_nil", func(t *testing.T) {
		resp := handler.profileToResponse(nil)
		assert.Nil(t, resp)
	})
}
