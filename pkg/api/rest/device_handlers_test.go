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

package rest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// =============================================================================
// Mock Services
// =============================================================================

type mockDeviceService struct {
	devices       map[uint64]*entities.Device
	saveErr       error
	getErr        error
	deleteErr     error
	updateErr     error
	countErr      error
	pageErr       error
	findSerialErr error
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
		HasMore:  false,
	}
	for _, d := range m.devices {
		result.Entities = append(result.Entities, d)
	}
	return result, nil
}

func (m *mockDeviceService) FindBySerial(ctx context.Context, serial string) (*entities.Device, error) {
	if m.findSerialErr != nil {
		return nil, m.findSerialErr
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

func (m *mockDeviceService) addDevice(d *entities.Device) {
	m.devices[d.ID] = d
}

type mockProfileService struct {
	profiles      map[uint64]*entities.DeviceProfile
	saveErr       error
	getErr        error
	deleteErr     error
	updateErr     error
	countErr      error
	pageErr       error
	findMACErr    error
	findSerialErr error
	findMatchErr  error
	assignErr     error
	unassignErr   error
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
		HasMore:  false,
	}
	for _, p := range m.profiles {
		result.Entities = append(result.Entities, p)
	}
	return result, nil
}

func (m *mockProfileService) FindByMACAddress(ctx context.Context, macAddr string) (*entities.DeviceProfile, error) {
	if m.findMACErr != nil {
		return nil, m.findMACErr
	}
	return nil, errors.New("profile not found")
}

func (m *mockProfileService) FindBySerial(ctx context.Context, serial string) (*entities.DeviceProfile, error) {
	if m.findSerialErr != nil {
		return nil, m.findSerialErr
	}
	return nil, errors.New("profile not found")
}

func (m *mockProfileService) FindMatchingProfile(ctx context.Context, macAddr, serial, model string) (*entities.DeviceProfile, error) {
	if m.findMatchErr != nil {
		return nil, m.findMatchErr
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

func (m *mockProfileService) addProfile(p *entities.DeviceProfile) {
	m.profiles[p.ID] = p
}

// =============================================================================
// Test Helpers
// =============================================================================

// setupDeviceTestHandlerWithInterfaces creates handlers using interface types to properly handle nil.
func setupDeviceTestHandlerWithInterfaces(deviceSvc DeviceServiceInterface, profileSvc ProfileServiceInterface) (*DeviceHandlers, *mux.Router) {
	logger := slog.Default()
	handlers := NewDeviceHandlers(deviceSvc, profileSvc, logger)
	router := mux.NewRouter()
	handlers.RegisterRoutes(router)
	return handlers, router
}

// setupDeviceTestHandler is a convenience wrapper for tests with non-nil services.
func setupDeviceTestHandler(deviceSvc *mockDeviceService, profileSvc *mockProfileService) (*DeviceHandlers, *mux.Router) {
	var dSvc DeviceServiceInterface
	var pSvc ProfileServiceInterface
	if deviceSvc != nil {
		dSvc = deviceSvc
	}
	if profileSvc != nil {
		pSvc = profileSvc
	}
	return setupDeviceTestHandlerWithInterfaces(dSvc, pSvc)
}

func decodeDeviceResponse(t *testing.T, body *bytes.Buffer, v interface{}) {
	t.Helper()
	err := json.NewDecoder(body).Decode(v)
	require.NoError(t, err)
}

// =============================================================================
// Error Type Tests
// =============================================================================

func TestDeviceHandlerErrors(t *testing.T) {
	t.Run("ErrDeviceServiceNotAvailable", func(t *testing.T) {
		err := ErrDeviceServiceNotAvailable{}
		assert.Equal(t, "device service not available", err.Error())
	})

	t.Run("ErrProfileServiceNotAvailable", func(t *testing.T) {
		err := ErrProfileServiceNotAvailable{}
		assert.Equal(t, "profile service not available", err.Error())
	})

	t.Run("ErrInvalidDeviceID with empty ID", func(t *testing.T) {
		err := ErrDeviceInvalidID{}
		assert.Equal(t, "device ID is required", err.Error())
	})

	t.Run("ErrInvalidDeviceID with ID", func(t *testing.T) {
		err := ErrDeviceInvalidID{ID: "bad-id"}
		assert.Equal(t, "invalid device ID: bad-id", err.Error())
	})

	t.Run("ErrInvalidProfileID with empty ID", func(t *testing.T) {
		err := ErrInvalidProfileID{}
		assert.Equal(t, "profile ID is required", err.Error())
	})

	t.Run("ErrInvalidProfileID with ID", func(t *testing.T) {
		err := ErrInvalidProfileID{ID: "bad-id"}
		assert.Equal(t, "invalid profile ID: bad-id", err.Error())
	})

	t.Run("ErrDeviceNotFound with ID", func(t *testing.T) {
		err := ErrDeviceNotFound{ID: 123}
		assert.Equal(t, "device not found with ID: 123", err.Error())
	})

	t.Run("ErrDeviceNotFound with serial", func(t *testing.T) {
		err := ErrDeviceNotFound{Serial: "SN123"}
		assert.Equal(t, "device not found with serial: SN123", err.Error())
	})

	t.Run("ErrProfileNotFound", func(t *testing.T) {
		err := ErrProfileNotFound{ID: 456}
		assert.Equal(t, "profile not found with ID: 456", err.Error())
	})

	t.Run("ErrDeviceSerialRequired", func(t *testing.T) {
		err := ErrDeviceSerialRequired{}
		assert.Equal(t, "device serial is required", err.Error())
	})

	t.Run("ErrDeviceAlreadyExists", func(t *testing.T) {
		err := ErrDeviceAlreadyExists{Serial: "SN123"}
		assert.Equal(t, "device already exists with serial: SN123", err.Error())
	})

	t.Run("ErrDeviceOperationFailed", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := ErrDeviceOperationFailed{Operation: "register", Cause: cause}
		assert.Equal(t, "device operation register failed: underlying error", err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("ErrProfileOperationFailed", func(t *testing.T) {
		cause := errors.New("underlying error")
		err := ErrProfileOperationFailed{Operation: "create", Cause: cause}
		assert.Equal(t, "profile operation create failed: underlying error", err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("ErrDeviceActivationFailed with cause", func(t *testing.T) {
		cause := errors.New("activation error")
		err := ErrDeviceActivationFailed{ID: 123, Cause: cause}
		assert.Equal(t, "device activation failed for ID 123: activation error", err.Error())
		assert.Equal(t, cause, err.Unwrap())
	})

	t.Run("ErrDeviceActivationFailed without cause", func(t *testing.T) {
		err := ErrDeviceActivationFailed{ID: 123}
		assert.Equal(t, "device activation failed for ID 123", err.Error())
	})
}

// =============================================================================
// Constructor Tests
// =============================================================================

func TestNewDeviceHandlers(t *testing.T) {
	t.Run("creates handlers with services and logger", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		logger := slog.Default()
		handlers := NewDeviceHandlers(deviceSvc, profileSvc, logger)
		require.NotNil(t, handlers)
		assert.NotNil(t, handlers.deviceService)
		assert.NotNil(t, handlers.profileService)
		assert.Equal(t, logger, handlers.logger)
	})

	t.Run("creates handlers with nil logger uses default", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		handlers := NewDeviceHandlers(deviceSvc, profileSvc, nil)
		require.NotNil(t, handlers)
		assert.NotNil(t, handlers.logger)
	})
}

func TestRegisterDeviceRoutes(t *testing.T) {
	t.Run("registers all device routes", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		routes := []struct {
			method string
			path   string
		}{
			{http.MethodPost, "/api/v1/devices"},
			{http.MethodGet, "/api/v1/devices"},
			{http.MethodGet, "/api/v1/devices/123"},
			{http.MethodPut, "/api/v1/devices/123"},
			{http.MethodDelete, "/api/v1/devices/123"},
			{http.MethodPost, "/api/v1/devices/123/activate"},
			{http.MethodGet, "/api/v1/devices/123/state"},
			{http.MethodGet, "/api/v1/devices/serial/SN123"},
			{http.MethodPost, "/api/v1/devices/profiles"},
			{http.MethodGet, "/api/v1/devices/profiles"},
			{http.MethodGet, "/api/v1/devices/profiles/123"},
			{http.MethodPut, "/api/v1/devices/profiles/123"},
			{http.MethodDelete, "/api/v1/devices/profiles/123"},
		}

		for _, route := range routes {
			req := httptest.NewRequest(route.method, route.path, nil)
			match := &mux.RouteMatch{}
			matched := router.Match(req, match)
			assert.True(t, matched, "Route %s %s should be registered", route.method, route.path)
		}
	})

	t.Run("registers attest only when a verifier is wired", func(t *testing.T) {
		handlers := NewDeviceHandlers(newMockDeviceService(), newMockProfileService(), slog.Default(),
			WithDeviceAttestService(&stubAttestService{resp: &platformv1.AttestDeviceResponse{}}))
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/123/attest", nil)
		assert.True(t, router.Match(req, &mux.RouteMatch{}),
			"the attest route must be registered when the verifier is present")
	})
}

// =============================================================================
// Device Registration Tests
// =============================================================================

func TestHandleRegisterDevice(t *testing.T) {
	t.Run("registers device successfully", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		reqBody := DeviceRegisterRequest{
			Serial: "SN-12345",
			Model:  "Model-A",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		var deviceResp DeviceResponse
		decodeDeviceResponse(t, w.Body, &deviceResp)
		assert.Equal(t, "SN-12345", deviceResp.Serial)
		assert.Equal(t, "Model-A", deviceResp.Model)
		assert.NotZero(t, deviceResp.ID)
	})

	t.Run("registers device with all fields", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		reqBody := DeviceRegisterRequest{
			Serial:     "SN-99999",
			Model:      "Model-B",
			AttestPub:  "attest-pub-key",
			SigningPub: "signing-pub-key",
			EKCert:     "ek-cert-data",
			EventLog:   []byte{0x01, 0x02, 0x03},
			HashAlgoID: 11,
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		var deviceResp DeviceResponse
		decodeDeviceResponse(t, w.Body, &deviceResp)
		assert.Equal(t, "SN-99999", deviceResp.Serial)
		assert.Equal(t, "Model-B", deviceResp.Model)
		assert.Equal(t, "attest-pub-key", deviceResp.AttestPub)
		assert.Equal(t, "signing-pub-key", deviceResp.SigningPub)
		assert.Equal(t, "ek-cert-data", deviceResp.EKCert)
		assert.Equal(t, []byte{0x01, 0x02, 0x03}, deviceResp.EventLog)
		assert.Equal(t, uint32(11), deviceResp.HashAlgoID)
	})

	t.Run("returns error for missing serial", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		reqBody := DeviceRegisterRequest{
			Model: "Model-A",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for invalid JSON", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices", bytes.NewReader([]byte("invalid-json")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(nil, profileSvc)

		reqBody := DeviceRegisterRequest{Serial: "SN-12345"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error when save fails", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		deviceSvc.saveErr = errors.New("database error")
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		reqBody := DeviceRegisterRequest{Serial: "SN-12345"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})
}

// =============================================================================
// Device List Tests
// =============================================================================

func TestHandleListDevices(t *testing.T) {
	t.Run("lists devices successfully", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		deviceSvc.addDevice(&entities.Device{ID: 1, Serial: "SN-001"})
		deviceSvc.addDevice(&entities.Device{ID: 2, Serial: "SN-002"})
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var listResp DeviceListResponse
		decodeDeviceResponse(t, w.Body, &listResp)
		assert.Len(t, listResp.Devices, 2)
		assert.NotNil(t, listResp.Pagination)
	})

	t.Run("lists empty devices", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var listResp DeviceListResponse
		decodeDeviceResponse(t, w.Body, &listResp)
		assert.Empty(t, listResp.Devices)
	})

	t.Run("supports pagination parameters", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/devices?page=2&page_size=10&sort_order=desc", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(nil, profileSvc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error when page fails", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		deviceSvc.pageErr = errors.New("database error")
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})
}

// =============================================================================
// Device Get Tests
// =============================================================================

func TestHandleGetDevice(t *testing.T) {
	t.Run("gets device successfully", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		device := &entities.Device{ID: 12345, Serial: "SN-12345", Model: "Model-A"}
		deviceSvc.addDevice(device)
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/devices/12345", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var deviceResp DeviceResponse
		decodeDeviceResponse(t, w.Body, &deviceResp)
		assert.Equal(t, uint64(12345), deviceResp.ID)
		assert.Equal(t, "SN-12345", deviceResp.Serial)
	})

	t.Run("returns error for invalid ID format", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/devices/invalid-id", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for not found device", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/devices/99999", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(nil, profileSvc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/devices/12345", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Device Update Tests
// =============================================================================

func TestHandleUpdateDevice(t *testing.T) {
	t.Run("updates device successfully", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		device := &entities.Device{ID: 12345, Serial: "SN-12345", Model: "Model-A"}
		deviceSvc.addDevice(device)
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		reqBody := DeviceUpdateRequest{
			Model: "Model-B",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/devices/12345", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var deviceResp DeviceResponse
		decodeDeviceResponse(t, w.Body, &deviceResp)
		assert.Equal(t, "Model-B", deviceResp.Model)
	})

	t.Run("updates device with all fields", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		device := &entities.Device{ID: 12345, Serial: "SN-12345", Model: "Model-A"}
		deviceSvc.addDevice(device)
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		reqBody := DeviceUpdateRequest{
			Serial:     "SN-UPDATED",
			Model:      "Model-C",
			AttestPub:  "new-attest-pub",
			SigningPub: "new-signing-pub",
			EKCert:     "new-ek-cert",
			EventLog:   []byte{0x04, 0x05},
			HashAlgoID: 12,
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/devices/12345", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var deviceResp DeviceResponse
		decodeDeviceResponse(t, w.Body, &deviceResp)
		assert.Equal(t, "SN-UPDATED", deviceResp.Serial)
		assert.Equal(t, "Model-C", deviceResp.Model)
		assert.Equal(t, "new-attest-pub", deviceResp.AttestPub)
		assert.Equal(t, "new-signing-pub", deviceResp.SigningPub)
		assert.Equal(t, "new-ek-cert", deviceResp.EKCert)
		assert.Equal(t, []byte{0x04, 0x05}, deviceResp.EventLog)
		assert.Equal(t, uint32(12), deviceResp.HashAlgoID)
	})

	t.Run("returns error for invalid ID format", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		reqBody := DeviceUpdateRequest{Model: "Model-B"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/devices/invalid-id", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for invalid JSON", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		device := &entities.Device{ID: 12345, Serial: "SN-12345", State: entities.DeviceStateRegistered}
		deviceSvc.addDevice(device)
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/devices/12345", bytes.NewReader([]byte("invalid-json")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for not found device", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		reqBody := DeviceUpdateRequest{Model: "Model-B"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/devices/99999", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("returns error when update fails", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		device := &entities.Device{ID: 12345, Serial: "SN-12345", State: entities.DeviceStateRegistered}
		deviceSvc.addDevice(device)
		deviceSvc.updateErr = errors.New("update error")
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		reqBody := DeviceUpdateRequest{Model: "Model-B"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/devices/12345", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(nil, profileSvc)

		reqBody := DeviceUpdateRequest{Model: "Model-B"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/devices/12345", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Device Delete Tests
// =============================================================================

func TestHandleDeleteDevice(t *testing.T) {
	t.Run("deletes device successfully", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		device := &entities.Device{ID: 12345, Serial: "SN-12345", State: entities.DeviceStateRegistered}
		deviceSvc.addDevice(device)
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/devices/12345", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var actionResp DeviceActionResponse
		decodeDeviceResponse(t, w.Body, &actionResp)
		assert.Equal(t, uint64(12345), actionResp.DeviceID)
		assert.Equal(t, "delete", actionResp.Action)
		assert.True(t, actionResp.Success)
	})

	t.Run("returns error for invalid ID format", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/devices/invalid-id", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for not found device", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/devices/99999", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("returns error when delete fails", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		device := &entities.Device{ID: 12345, Serial: "SN-12345", State: entities.DeviceStateRegistered}
		deviceSvc.addDevice(device)
		deviceSvc.deleteErr = errors.New("delete error")
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/devices/12345", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(nil, profileSvc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/devices/12345", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Device Activate Tests
// =============================================================================

func TestHandleActivateDevice(t *testing.T) {
	t.Run("activates device successfully", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		device := &entities.Device{ID: 12345, Serial: "SN-12345", State: entities.DeviceStateRegistered}
		deviceSvc.addDevice(device)
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/12345/activate", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var activateResp DeviceActivateResponse
		decodeDeviceResponse(t, w.Body, &activateResp)
		assert.Equal(t, uint64(12345), activateResp.DeviceID)
		assert.True(t, activateResp.Activated)
	})

	t.Run("activates device with request body", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		device := &entities.Device{ID: 12345, Serial: "SN-12345", State: entities.DeviceStateRegistered}
		deviceSvc.addDevice(device)
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		reqBody := DeviceActivateRequest{Nonce: []byte{0x01, 0x02, 0x03}}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/12345/activate", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)
	})

	t.Run("returns error for invalid request body", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		device := &entities.Device{ID: 12345, Serial: "SN-12345", State: entities.DeviceStateRegistered}
		deviceSvc.addDevice(device)
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/12345/activate", bytes.NewReader([]byte("invalid-json")))
		req.Header.Set("Content-Type", "application/json")
		req.ContentLength = 12
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for invalid ID format", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/invalid-id/activate", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for not found device", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/99999/activate", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(nil, profileSvc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/12345/activate", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Device Attest Tests
//
// The attest route holds no verifier of its own: it binds HTTP and delegates
// to the in-process DeviceService implementation, which is the platform's
// single device quote verifier. These tests pin the HTTP contract. That a
// forged quote is actually REFUSED on this transport is proved against the
// real verifier in pkg/api/daemon (TestRESTDeviceAttest_RefusesForgedQuote),
// because a fake service here could only prove the call was made.
// =============================================================================

// stubAttestService is a DeviceServiceServer that records the request and
// returns a canned verdict, so the handler's HTTP binding can be exercised
// without standing up the verifier.
type stubAttestService struct {
	platformv1.UnimplementedDeviceServiceServer
	gotDeviceID string
	gotEvidence []byte
	resp        *platformv1.AttestDeviceResponse
	err         error
}

func (s *stubAttestService) AttestDevice(
	_ context.Context,
	req *platformv1.AttestDeviceRequest,
) (*platformv1.AttestDeviceResponse, error) {
	s.gotDeviceID = req.GetDeviceId()
	s.gotEvidence = req.GetEvidence()
	if s.err != nil {
		return nil, s.err
	}
	return s.resp, nil
}

// setupAttestRouter mounts the device routes with an attestation service.
func setupAttestRouter(svc platformv1.DeviceServiceServer) *mux.Router {
	handlers := NewDeviceHandlers(
		newMockDeviceService(),
		newMockProfileService(),
		slog.Default(),
		WithDeviceAttestService(svc),
	)
	router := mux.NewRouter()
	handlers.RegisterRoutes(router)
	return router
}

func attestRequestBody(t *testing.T, evidence []byte) *bytes.Reader {
	t.Helper()
	body, err := json.Marshal(DeviceAttestRequest{Evidence: evidence})
	require.NoError(t, err)
	return bytes.NewReader(body)
}

func TestHandleAttestDevice(t *testing.T) {
	t.Run("reports a negative verdict as 200, not as success", func(t *testing.T) {
		svc := &stubAttestService{resp: &platformv1.AttestDeviceResponse{
			DeviceId:          12345,
			Serial:            "SN-12345",
			Verified:          false,
			SignatureValid:    false,
			NonceValid:        true,
			AttestationStatus: "failed",
			Message:           "RSA signature verification failed",
			AttestedAt:        timestamppb.New(time.Unix(1757000000, 0).UTC()),
		}}
		router := setupAttestRouter(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/12345/attest",
			attestRequestBody(t, []byte(`{"quote":"AAAA"}`)))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Result().StatusCode)

		var resp DeviceAttestResponse
		decodeDeviceResponse(t, w.Body, &resp)
		assert.False(t, resp.Verified, "a failed quote must not report verified")
		assert.False(t, resp.SignatureValid)
		assert.True(t, resp.NonceValid)
		assert.Equal(t, "failed", resp.AttestationStatus)
		assert.Equal(t, "RSA signature verification failed", resp.Message)
		assert.Equal(t, uint64(12345), resp.DeviceID)
	})

	t.Run("carries the evidence through verbatim", func(t *testing.T) {
		evidence := []byte(`{"quote":"c29tZQ==","signature":"c2ln"}`)
		svc := &stubAttestService{resp: &platformv1.AttestDeviceResponse{DeviceId: 7, Verified: true}}
		router := setupAttestRouter(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/7/attest",
			attestRequestBody(t, evidence))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Result().StatusCode)
		assert.Equal(t, "7", svc.gotDeviceID)
		assert.Equal(t, evidence, svc.gotEvidence,
			"the handler must not reshape evidence: every transport carries one encoding")
	})

	t.Run("reports the full verdict detail including the baseline", func(t *testing.T) {
		recorded := time.Unix(1756900000, 0).UTC()
		svc := &stubAttestService{resp: &platformv1.AttestDeviceResponse{
			DeviceId:              9,
			Verified:              true,
			SignatureValid:        true,
			NonceValid:            true,
			PcrsValid:             true,
			AkCertificateVerified: true,
			AttestationStatus:     "verified",
			PcrBaselineSource:     "tofu",
			PcrBaselineRecordedAt: timestamppb.New(recorded),
			PcrBaselineCaptured:   true,
		}}
		router := setupAttestRouter(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/9/attest",
			attestRequestBody(t, []byte(`{}`)))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		require.Equal(t, http.StatusOK, w.Result().StatusCode)
		var resp DeviceAttestResponse
		decodeDeviceResponse(t, w.Body, &resp)
		assert.True(t, resp.Verified)
		assert.True(t, resp.AKCertificateVerified)
		assert.True(t, resp.PCRsValid)
		assert.Equal(t, "tofu", resp.PCRBaselineSource)
		assert.True(t, resp.PCRBaselineCaptured)
		require.NotNil(t, resp.PCRBaselineRecordedAt)
		assert.Equal(t, recorded, resp.PCRBaselineRecordedAt.UTC())
	})

	t.Run("rejects a body with no evidence", func(t *testing.T) {
		svc := &stubAttestService{resp: &platformv1.AttestDeviceResponse{}}
		router := setupAttestRouter(svc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/12345/attest",
			attestRequestBody(t, nil))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
		assert.Empty(t, svc.gotDeviceID, "an empty body must not reach the verifier")
	})

	t.Run("rejects an unparseable body", func(t *testing.T) {
		router := setupAttestRouter(&stubAttestService{resp: &platformv1.AttestDeviceResponse{}})

		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/12345/attest",
			bytes.NewReader([]byte("not-json")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusBadRequest, w.Result().StatusCode)
	})

	t.Run("maps verifier errors onto HTTP status by code", func(t *testing.T) {
		cases := []struct {
			name string
			err  error
			want int
		}{
			{"unknown device", status.Error(codes.NotFound, "device not found"), http.StatusNotFound},
			{"malformed evidence", status.Error(codes.InvalidArgument, "evidence is required"), http.StatusBadRequest},
			{"no dependency", status.Error(codes.Unavailable, "device service unavailable"), http.StatusServiceUnavailable},
			{"unclassified", errors.New("boom"), http.StatusInternalServerError},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				router := setupAttestRouter(&stubAttestService{err: tc.err})

				req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/12345/attest",
					attestRequestBody(t, []byte(`{}`)))
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)

				assert.Equal(t, tc.want, w.Result().StatusCode)
			})
		}
	})

	t.Run("does not register the route without a verifier", func(t *testing.T) {
		handlers := NewDeviceHandlers(newMockDeviceService(), newMockProfileService(), slog.Default())
		router := mux.NewRouter()
		handlers.RegisterRoutes(router)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/12345/attest",
			attestRequestBody(t, []byte(`{}`)))
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusNotFound, w.Result().StatusCode,
			"an unverified attest route must not exist at all; #403 was a route that answered without verifying")
	})
}

// =============================================================================
// Device State Tests
// =============================================================================

func TestHandleGetDeviceState(t *testing.T) {
	t.Run("gets device state successfully", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		device := &entities.Device{ID: 12345, Serial: "SN-12345", State: entities.DeviceStateRegistered}
		deviceSvc.addDevice(device)
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/devices/12345/state", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var stateResp DeviceStateResponse
		decodeDeviceResponse(t, w.Body, &stateResp)
		assert.Equal(t, uint64(12345), stateResp.DeviceID)
		assert.Equal(t, "SN-12345", stateResp.Serial)
		assert.Equal(t, "registered", stateResp.State)
	})

	t.Run("returns error for invalid ID format", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/devices/invalid-id/state", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for not found device", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/devices/99999/state", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(nil, profileSvc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/devices/12345/state", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Device By Serial Tests
// =============================================================================

func TestHandleGetDeviceBySerial(t *testing.T) {
	t.Run("gets device by serial successfully", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		device := &entities.Device{ID: 12345, Serial: "SN-12345", Model: "Model-A"}
		deviceSvc.addDevice(device)
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/devices/serial/SN-12345", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var deviceResp DeviceResponse
		decodeDeviceResponse(t, w.Body, &deviceResp)
		assert.Equal(t, "SN-12345", deviceResp.Serial)
	})

	t.Run("returns error for not found device", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/devices/serial/NONEXISTENT", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(nil, profileSvc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/devices/serial/SN-12345", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Profile Create Tests
// =============================================================================

func TestHandleCreateProfile(t *testing.T) {
	t.Run("creates profile successfully", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		reqBody := ProfileCreateRequest{
			Name:  "test-profile",
			Model: "Model-A",
			Role:  "server",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/profiles", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		var profileResp ProfileResponse
		decodeDeviceResponse(t, w.Body, &profileResp)
		assert.Equal(t, "test-profile", profileResp.Name)
		assert.Equal(t, "Model-A", profileResp.Model)
		assert.Equal(t, "server", profileResp.Role)
	})

	t.Run("creates profile with network configurations", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		reqBody := ProfileCreateRequest{
			Name:  "network-profile",
			Model: "Model-B",
			Role:  "edge",
			Networks: map[string]*NetworkPhaseConfigRequest{
				"provisioning": {
					VLAN:       100,
					StaticIP:   "192.168.1.10",
					Gateway:    "192.168.1.1",
					DNS:        []string{"8.8.8.8", "8.8.4.4"},
					AuthMethod: "cert",
				},
				"trusted": {
					VLAN:       200,
					StaticIP:   "10.0.0.10",
					Gateway:    "10.0.0.1",
					DNS:        []string{"10.0.0.2"},
					AuthMethod: "mTLS",
				},
				"quarantine": {
					VLAN:       999,
					StaticIP:   "172.16.0.10",
					Gateway:    "172.16.0.1",
					DNS:        []string{"172.16.0.2"},
					AuthMethod: "none",
				},
			},
			MatchRules: &ProfileMatchRulesRequest{
				MACPrefix:    "00:11:22",
				SerialPrefix: "SN-",
				Model:        "Model-B",
			},
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/profiles", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		var profileResp ProfileResponse
		decodeDeviceResponse(t, w.Body, &profileResp)
		assert.Equal(t, "network-profile", profileResp.Name)
		assert.NotNil(t, profileResp.Networks)
		assert.NotNil(t, profileResp.Networks["provisioning"])
		assert.Equal(t, uint16(100), profileResp.Networks["provisioning"].VLAN)
		assert.NotNil(t, profileResp.Networks["trusted"])
		assert.Equal(t, uint16(200), profileResp.Networks["trusted"].VLAN)
		assert.NotNil(t, profileResp.Networks["quarantine"])
		assert.Equal(t, uint16(999), profileResp.Networks["quarantine"].VLAN)
		assert.NotNil(t, profileResp.MatchRules)
		assert.Equal(t, "00:11:22", profileResp.MatchRules.MACPrefix)
	})

	t.Run("returns error for missing name", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		reqBody := ProfileCreateRequest{
			Model: "Model-A",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/profiles", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for invalid JSON", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/profiles", bytes.NewReader([]byte("invalid-json")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		_, router := setupDeviceTestHandler(deviceSvc, nil)

		reqBody := ProfileCreateRequest{Name: "test-profile"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/profiles", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error when save fails", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		profileSvc.saveErr = errors.New("database error")
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		reqBody := ProfileCreateRequest{Name: "test-profile"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/profiles", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})
}

// =============================================================================
// Profile List Tests
// =============================================================================

func TestHandleListProfiles(t *testing.T) {
	t.Run("lists profiles successfully", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		profileSvc.addProfile(&entities.DeviceProfile{ID: 1, Name: "profile-1"})
		profileSvc.addProfile(&entities.DeviceProfile{ID: 2, Name: "profile-2"})
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/devices/profiles", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var listResp ProfileListResponse
		decodeDeviceResponse(t, w.Body, &listResp)
		assert.Len(t, listResp.Profiles, 2)
	})

	t.Run("lists profiles with network configurations", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		profileSvc.addProfile(&entities.DeviceProfile{
			ID:   1,
			Name: "profile-with-network",
			Networks: map[string]*entities.NetworkPhaseConfig{
				entities.DefaultEnrollmentNetwork: {
					VLAN:     100,
					StaticIP: "192.168.1.10",
				},
			},
			MatchRules: &entities.ProfileMatchRules{
				MACPrefix: "00:11:22",
			},
		})
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/devices/profiles", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var listResp ProfileListResponse
		decodeDeviceResponse(t, w.Body, &listResp)
		assert.Len(t, listResp.Profiles, 1)
		assert.NotNil(t, listResp.Profiles[0].Networks)
		assert.NotNil(t, listResp.Profiles[0].MatchRules)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		_, router := setupDeviceTestHandler(deviceSvc, nil)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/devices/profiles", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})

	t.Run("returns error when page fails", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		profileSvc.pageErr = errors.New("database error")
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/devices/profiles", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})
}

// =============================================================================
// Profile Get Tests
// =============================================================================

func TestHandleGetProfile(t *testing.T) {
	t.Run("gets profile successfully", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		profile := &entities.DeviceProfile{ID: 12345, Name: "test-profile", Model: "Model-A"}
		profileSvc.addProfile(profile)
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/devices/profiles/12345", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var profileResp ProfileResponse
		decodeDeviceResponse(t, w.Body, &profileResp)
		assert.Equal(t, uint64(12345), profileResp.ID)
		assert.Equal(t, "test-profile", profileResp.Name)
	})

	t.Run("returns error for invalid ID format", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/devices/profiles/invalid-id", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for not found profile", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/devices/profiles/99999", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		_, router := setupDeviceTestHandler(deviceSvc, nil)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/devices/profiles/12345", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Profile Update Tests
// =============================================================================

func TestHandleUpdateProfile(t *testing.T) {
	t.Run("updates profile successfully", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		profile := &entities.DeviceProfile{ID: 12345, Name: "test-profile"}
		profileSvc.addProfile(profile)
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		reqBody := ProfileUpdateRequest{
			Name:  "updated-profile",
			Model: "Model-B",
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/devices/profiles/12345", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var profileResp ProfileResponse
		decodeDeviceResponse(t, w.Body, &profileResp)
		assert.Equal(t, "updated-profile", profileResp.Name)
		assert.Equal(t, "Model-B", profileResp.Model)
	})

	t.Run("updates profile with network configurations", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		profile := &entities.DeviceProfile{ID: 12345, Name: "test-profile"}
		profileSvc.addProfile(profile)
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		reqBody := ProfileUpdateRequest{
			Role:     "edge",
			EventLog: []byte{0x01, 0x02},
			Networks: map[string]*NetworkPhaseConfigRequest{
				"provisioning": {
					VLAN:     100,
					StaticIP: "192.168.1.10",
				},
				"trusted": {
					VLAN:     200,
					StaticIP: "10.0.0.10",
				},
				"quarantine": {
					VLAN:     999,
					StaticIP: "172.16.0.10",
				},
			},
			MatchRules: &ProfileMatchRulesRequest{
				MACPrefix:    "00:11:22",
				SerialPrefix: "SN-",
				Model:        "Model-B",
			},
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/devices/profiles/12345", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var profileResp ProfileResponse
		decodeDeviceResponse(t, w.Body, &profileResp)
		assert.Equal(t, "edge", profileResp.Role)
		assert.NotNil(t, profileResp.Networks)
		assert.NotNil(t, profileResp.Networks["provisioning"])
		assert.NotNil(t, profileResp.Networks["trusted"])
		assert.NotNil(t, profileResp.Networks["quarantine"])
		assert.NotNil(t, profileResp.MatchRules)
	})

	t.Run("returns error for invalid ID format", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		reqBody := ProfileUpdateRequest{Name: "updated"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/devices/profiles/invalid-id", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for invalid JSON", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		profile := &entities.DeviceProfile{ID: 12345, Name: "test-profile"}
		profileSvc.addProfile(profile)
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/devices/profiles/12345", bytes.NewReader([]byte("invalid-json")))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for not found profile", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		reqBody := ProfileUpdateRequest{Name: "updated"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/devices/profiles/99999", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("returns error when update fails", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		profile := &entities.DeviceProfile{ID: 12345, Name: "test-profile"}
		profileSvc.addProfile(profile)
		profileSvc.updateErr = errors.New("update error")
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		reqBody := ProfileUpdateRequest{Name: "updated"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/devices/profiles/12345", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		_, router := setupDeviceTestHandler(deviceSvc, nil)

		reqBody := ProfileUpdateRequest{Name: "updated"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/devices/profiles/12345", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Profile Delete Tests
// =============================================================================

func TestHandleDeleteProfile(t *testing.T) {
	t.Run("deletes profile successfully", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		profile := &entities.DeviceProfile{ID: 12345, Name: "test-profile"}
		profileSvc.addProfile(profile)
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/devices/profiles/12345", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNoContent, resp.StatusCode)
	})

	t.Run("returns error for invalid ID format", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/devices/profiles/invalid-id", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})

	t.Run("returns error for not found profile", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/devices/profiles/99999", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusNotFound, resp.StatusCode)
	})

	t.Run("returns error when delete fails", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		profile := &entities.DeviceProfile{ID: 12345, Name: "test-profile"}
		profileSvc.addProfile(profile)
		profileSvc.deleteErr = errors.New("delete error")
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/devices/profiles/12345", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusInternalServerError, resp.StatusCode)
	})

	t.Run("returns error when service unavailable", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		_, router := setupDeviceTestHandler(deviceSvc, nil)

		req := httptest.NewRequest(http.MethodDelete, "/api/v1/devices/profiles/12345", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusServiceUnavailable, resp.StatusCode)
	})
}

// =============================================================================
// Utility Function Tests
// =============================================================================

func TestGenerateDeviceID(t *testing.T) {
	t.Run("generates deterministic ID from serial", func(t *testing.T) {
		id1 := generateDeviceID("SN-12345")
		id2 := generateDeviceID("SN-12345")
		assert.Equal(t, id1, id2)
		assert.NotZero(t, id1)
	})

	t.Run("generates different IDs for different serials", func(t *testing.T) {
		id1 := generateDeviceID("SN-12345")
		id2 := generateDeviceID("SN-67890")
		assert.NotEqual(t, id1, id2)
	})

	t.Run("returns zero for empty serial", func(t *testing.T) {
		id := generateDeviceID("")
		assert.Zero(t, id)
	})
}

func TestGenerateProfileID(t *testing.T) {
	t.Run("generates deterministic ID from name", func(t *testing.T) {
		id1 := generateProfileID("test-profile")
		id2 := generateProfileID("test-profile")
		assert.Equal(t, id1, id2)
		assert.NotZero(t, id1)
	})

	t.Run("generates different IDs for different names", func(t *testing.T) {
		id1 := generateProfileID("profile-1")
		id2 := generateProfileID("profile-2")
		assert.NotEqual(t, id1, id2)
	})

	t.Run("returns zero for empty name", func(t *testing.T) {
		id := generateProfileID("")
		assert.Zero(t, id)
	})
}

func TestCalculateTotalPages(t *testing.T) {
	t.Run("calculates correct pages for exact division", func(t *testing.T) {
		assert.Equal(t, 5, calculateTotalPages(50, 10))
	})

	t.Run("calculates correct pages with remainder", func(t *testing.T) {
		assert.Equal(t, 6, calculateTotalPages(51, 10))
	})

	t.Run("returns zero for zero page size", func(t *testing.T) {
		assert.Equal(t, 0, calculateTotalPages(50, 0))
	})

	t.Run("returns zero for negative page size", func(t *testing.T) {
		assert.Equal(t, 0, calculateTotalPages(50, -1))
	})
}

func TestIsNotFoundError(t *testing.T) {
	t.Run("returns true for not found error", func(t *testing.T) {
		assert.True(t, isNotFoundError(errors.New("device not found")))
		assert.True(t, isNotFoundError(errors.New("record not found")))
	})

	t.Run("returns false for other errors", func(t *testing.T) {
		assert.False(t, isNotFoundError(errors.New("database error")))
	})

	t.Run("returns false for nil error", func(t *testing.T) {
		assert.False(t, isNotFoundError(nil))
	})
}

func TestIsAlreadyExistsError(t *testing.T) {
	t.Run("returns true for already exists error", func(t *testing.T) {
		assert.True(t, isAlreadyExistsError(errors.New("device already exists")))
		assert.True(t, isAlreadyExistsError(errors.New("duplicate key")))
	})

	t.Run("returns false for other errors", func(t *testing.T) {
		assert.False(t, isAlreadyExistsError(errors.New("database error")))
	})

	t.Run("returns false for nil error", func(t *testing.T) {
		assert.False(t, isAlreadyExistsError(nil))
	})
}

func TestIsInvalidIDError(t *testing.T) {
	t.Run("returns true for invalid ID error", func(t *testing.T) {
		assert.True(t, isInvalidIDError(errors.New("invalid device ID")))
		assert.True(t, isInvalidIDError(errors.New("invalid profile ID")))
	})

	t.Run("returns false for other errors", func(t *testing.T) {
		assert.False(t, isInvalidIDError(errors.New("database error")))
	})

	t.Run("returns false for nil error", func(t *testing.T) {
		assert.False(t, isInvalidIDError(nil))
	})
}

func TestContains(t *testing.T) {
	t.Run("returns true when string contains substring", func(t *testing.T) {
		assert.True(t, contains("hello world", "world"))
		assert.True(t, contains("hello world", "hello"))
		assert.True(t, contains("HELLO WORLD", "hello"))
	})

	t.Run("returns false when string does not contain substring", func(t *testing.T) {
		assert.False(t, contains("hello", "world"))
	})

	t.Run("returns true for exact match", func(t *testing.T) {
		assert.True(t, contains("hello", "hello"))
	})
}

func TestContainsSubstring(t *testing.T) {
	t.Run("case insensitive search", func(t *testing.T) {
		assert.True(t, containsSubstring("Hello World", "world"))
		assert.True(t, containsSubstring("Hello World", "WORLD"))
		assert.True(t, containsSubstring("HELLO WORLD", "hello"))
	})

	t.Run("returns false for no match", func(t *testing.T) {
		assert.False(t, containsSubstring("hello", "xyz"))
	})
}

// =============================================================================
// Response Timestamp Tests
// =============================================================================

func TestResponseTimestamps(t *testing.T) {
	t.Run("list devices includes timestamp", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		before := time.Now().UTC()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		after := time.Now().UTC()

		var listResp DeviceListResponse
		decodeDeviceResponse(t, w.Body, &listResp)

		assert.True(t, listResp.Timestamp.After(before) || listResp.Timestamp.Equal(before))
		assert.True(t, listResp.Timestamp.Before(after) || listResp.Timestamp.Equal(after))
	})

	t.Run("list profiles includes timestamp", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		before := time.Now().UTC()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/devices/profiles", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)
		after := time.Now().UTC()

		var listResp ProfileListResponse
		decodeDeviceResponse(t, w.Body, &listResp)

		assert.True(t, listResp.Timestamp.After(before) || listResp.Timestamp.Equal(before))
		assert.True(t, listResp.Timestamp.Before(after) || listResp.Timestamp.Equal(after))
	})
}

// =============================================================================
// Error Mapping Tests
// =============================================================================

func TestWriteDeviceError(t *testing.T) {
	t.Run("maps already exists error to conflict", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		deviceSvc.saveErr = errors.New("device already exists")
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		reqBody := DeviceRegisterRequest{Serial: "SN-12345"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusConflict, resp.StatusCode)
	})

	t.Run("maps invalid ID error to bad request", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		device := &entities.Device{ID: 12345, Serial: "SN-12345", State: entities.DeviceStateRegistered}
		deviceSvc.addDevice(device)
		deviceSvc.updateErr = errors.New("invalid device ID format")
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		reqBody := DeviceUpdateRequest{Model: "Model-B"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/devices/12345", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

func TestWriteProfileError(t *testing.T) {
	t.Run("maps already exists error to conflict", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		profileSvc.saveErr = errors.New("profile already exists")
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		reqBody := ProfileCreateRequest{Name: "test-profile"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/profiles", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusConflict, resp.StatusCode)
	})

	t.Run("maps invalid ID error to bad request", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		profile := &entities.DeviceProfile{ID: 12345, Name: "test-profile"}
		profileSvc.addProfile(profile)
		profileSvc.updateErr = errors.New("invalid profile ID format")
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		reqBody := ProfileUpdateRequest{Name: "updated"}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/devices/profiles/12345", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusBadRequest, resp.StatusCode)
	})
}

// =============================================================================
// Network Configuration Conversion Tests
// =============================================================================

func TestNetworkConfigConversion(t *testing.T) {
	t.Run("networkRequestToEntity handles nil", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		h, _ := setupDeviceTestHandler(deviceSvc, profileSvc)

		result := h.networkRequestToEntity(nil)
		assert.Nil(t, result)
	})

	t.Run("networkRequestToEntity converts request", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		h, _ := setupDeviceTestHandler(deviceSvc, profileSvc)

		req := &NetworkPhaseConfigRequest{
			VLAN:       100,
			StaticIP:   "192.168.1.10",
			Gateway:    "192.168.1.1",
			DNS:        []string{"8.8.8.8"},
			AuthMethod: "cert",
		}

		result := h.networkRequestToEntity(req)
		require.NotNil(t, result)
		assert.Equal(t, uint16(100), result.VLAN)
		assert.Equal(t, "192.168.1.10", result.StaticIP)
		assert.Equal(t, "192.168.1.1", result.Gateway)
		assert.Equal(t, []string{"8.8.8.8"}, result.DNS)
		assert.Equal(t, entities.AuthMethod("cert"), result.AuthMethod)
	})

	t.Run("networkEntityToResponse handles nil", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		h, _ := setupDeviceTestHandler(deviceSvc, profileSvc)

		result := h.networkEntityToResponse(nil)
		assert.Nil(t, result)
	})

	t.Run("networkEntityToResponse converts entity", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		h, _ := setupDeviceTestHandler(deviceSvc, profileSvc)

		entity := &entities.NetworkPhaseConfig{
			VLAN:       200,
			StaticIP:   "10.0.0.10",
			Gateway:    "10.0.0.1",
			DNS:        []string{"10.0.0.2"},
			AuthMethod: "mTLS",
		}

		result := h.networkEntityToResponse(entity)
		require.NotNil(t, result)
		assert.Equal(t, uint16(200), result.VLAN)
		assert.Equal(t, "10.0.0.10", result.StaticIP)
		assert.Equal(t, "10.0.0.1", result.Gateway)
		assert.Equal(t, []string{"10.0.0.2"}, result.DNS)
		assert.Equal(t, "mTLS", result.AuthMethod)
	})
}

// =============================================================================
// Profile With Nil Network Config Tests
// =============================================================================

func TestProfileWithNilNetworkConfigs(t *testing.T) {
	t.Run("lists profile with nil network configs", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		// Profile with nil network configurations
		profileSvc.addProfile(&entities.DeviceProfile{
			ID:         1,
			Name:       "minimal-profile",
			MatchRules: nil,
		})
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/devices/profiles", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var listResp ProfileListResponse
		decodeDeviceResponse(t, w.Body, &listResp)
		assert.Len(t, listResp.Profiles, 1)
		assert.Nil(t, listResp.Profiles[0].Networks)
		assert.Nil(t, listResp.Profiles[0].MatchRules)
	})

	t.Run("gets profile with nil network configs", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		profileSvc.addProfile(&entities.DeviceProfile{
			ID:         12345,
			Name:       "minimal-profile",
			MatchRules: nil,
		})
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		req := httptest.NewRequest(http.MethodGet, "/api/v1/devices/profiles/12345", nil)
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var profileResp ProfileResponse
		decodeDeviceResponse(t, w.Body, &profileResp)
		assert.Equal(t, "minimal-profile", profileResp.Name)
		assert.Nil(t, profileResp.Networks)
		assert.Nil(t, profileResp.MatchRules)
	})

	t.Run("creates profile without network configs", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		reqBody := ProfileCreateRequest{
			Name:  "no-network-profile",
			Model: "Model-A",
			Role:  "server",
			// No network configurations
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPost, "/api/v1/devices/profiles", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusCreated, resp.StatusCode)

		var profileResp ProfileResponse
		decodeDeviceResponse(t, w.Body, &profileResp)
		assert.Equal(t, "no-network-profile", profileResp.Name)
		assert.Nil(t, profileResp.Networks)
	})

	t.Run("updates profile without network configs", func(t *testing.T) {
		deviceSvc := newMockDeviceService()
		profileSvc := newMockProfileService()
		profile := &entities.DeviceProfile{ID: 12345, Name: "test-profile"}
		profileSvc.addProfile(profile)
		_, router := setupDeviceTestHandler(deviceSvc, profileSvc)

		reqBody := ProfileUpdateRequest{
			Name:  "updated-no-network",
			Model: "Model-B",
			// No network configurations
		}
		body, _ := json.Marshal(reqBody)

		req := httptest.NewRequest(http.MethodPut, "/api/v1/devices/profiles/12345", bytes.NewReader(body))
		req.Header.Set("Content-Type", "application/json")
		w := httptest.NewRecorder()

		router.ServeHTTP(w, req)

		resp := w.Result()
		defer resp.Body.Close()

		assert.Equal(t, http.StatusOK, resp.StatusCode)

		var profileResp ProfileResponse
		decodeDeviceResponse(t, w.Body, &profileResp)
		assert.Equal(t, "updated-no-network", profileResp.Name)
		assert.Nil(t, profileResp.Networks)
	})
}
