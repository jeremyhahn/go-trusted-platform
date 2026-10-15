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

package bmc

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	bmcpkg "github.com/jeremyhahn/go-trusted-platform/pkg/bmc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/provisioning/baremetal"
)

// mockBMCService is a test double for BMCServicer.
type mockBMCService struct {
	powerOnFn           func(ctx context.Context, profileID uint64) error
	powerOffFn          func(ctx context.Context, profileID uint64) error
	powerResetFn        func(ctx context.Context, profileID uint64) error
	powerCycleFn        func(ctx context.Context, profileID uint64) error
	powerStatusFn       func(ctx context.Context, profileID uint64) (bmcpkg.PowerState, error)
	setBootDeviceFn     func(ctx context.Context, profileID uint64, device bmcpkg.BootDevice, persistent bool) error
	getBootDeviceFn     func(ctx context.Context, profileID uint64) (bmcpkg.BootDevice, error)
	mountISOFn          func(ctx context.Context, profileID uint64, isoURL string) error
	unmountISOFn        func(ctx context.Context, profileID uint64) error
	virtualMediaStatFn  func(ctx context.Context, profileID uint64) (*bmcpkg.VirtualMediaInfo, error)
	getSensorsFn        func(ctx context.Context, profileID uint64) ([]bmcpkg.SensorReading, error)
	getSystemInfoFn     func(ctx context.Context, profileID uint64) (*bmcpkg.SystemInfo, error)
	getWebCertificateFn func(ctx context.Context, profileID uint64) (*bmcpkg.CertificateInfo, error)
	replaceWebCertFn    func(ctx context.Context, profileID uint64, certPEM, keyPEM []byte) error
	listUsersFn         func(ctx context.Context, profileID uint64) ([]bmcpkg.User, error)
	createUserFn        func(ctx context.Context, profileID uint64, user bmcpkg.User, password string) error
	deleteUserFn        func(ctx context.Context, profileID uint64, slot uint8) error
	setUserPasswordFn   func(ctx context.Context, profileID uint64, slot uint8, password string) error
	setUserPrivilegeFn  func(ctx context.Context, profileID uint64, slot, channel uint8, privilege bmcpkg.Privilege) error
}

func (m *mockBMCService) PowerOn(ctx context.Context, profileID uint64) error {
	if m.powerOnFn != nil {
		return m.powerOnFn(ctx, profileID)
	}
	return nil
}

func (m *mockBMCService) PowerOff(ctx context.Context, profileID uint64) error {
	if m.powerOffFn != nil {
		return m.powerOffFn(ctx, profileID)
	}
	return nil
}

func (m *mockBMCService) PowerReset(ctx context.Context, profileID uint64) error {
	if m.powerResetFn != nil {
		return m.powerResetFn(ctx, profileID)
	}
	return nil
}

func (m *mockBMCService) PowerCycle(ctx context.Context, profileID uint64) error {
	if m.powerCycleFn != nil {
		return m.powerCycleFn(ctx, profileID)
	}
	return nil
}

func (m *mockBMCService) PowerStatus(ctx context.Context, profileID uint64) (bmcpkg.PowerState, error) {
	if m.powerStatusFn != nil {
		return m.powerStatusFn(ctx, profileID)
	}
	return bmcpkg.PowerStateOn, nil
}

func (m *mockBMCService) SetBootDevice(ctx context.Context, profileID uint64, device bmcpkg.BootDevice, persistent bool) error {
	if m.setBootDeviceFn != nil {
		return m.setBootDeviceFn(ctx, profileID, device, persistent)
	}
	return nil
}

func (m *mockBMCService) GetBootDevice(ctx context.Context, profileID uint64) (bmcpkg.BootDevice, error) {
	if m.getBootDeviceFn != nil {
		return m.getBootDeviceFn(ctx, profileID)
	}
	return bmcpkg.BootDeviceDisk, nil
}

func (m *mockBMCService) MountISO(ctx context.Context, profileID uint64, isoURL string) error {
	if m.mountISOFn != nil {
		return m.mountISOFn(ctx, profileID, isoURL)
	}
	return nil
}

func (m *mockBMCService) UnmountISO(ctx context.Context, profileID uint64) error {
	if m.unmountISOFn != nil {
		return m.unmountISOFn(ctx, profileID)
	}
	return nil
}

func (m *mockBMCService) VirtualMediaStatus(ctx context.Context, profileID uint64) (*bmcpkg.VirtualMediaInfo, error) {
	if m.virtualMediaStatFn != nil {
		return m.virtualMediaStatFn(ctx, profileID)
	}
	return &bmcpkg.VirtualMediaInfo{Mounted: false}, nil
}

func (m *mockBMCService) GetSensors(ctx context.Context, profileID uint64) ([]bmcpkg.SensorReading, error) {
	if m.getSensorsFn != nil {
		return m.getSensorsFn(ctx, profileID)
	}
	return []bmcpkg.SensorReading{}, nil
}

func (m *mockBMCService) GetSystemInfo(ctx context.Context, profileID uint64) (*bmcpkg.SystemInfo, error) {
	if m.getSystemInfoFn != nil {
		return m.getSystemInfoFn(ctx, profileID)
	}
	return &bmcpkg.SystemInfo{Manufacturer: "TestVendor"}, nil
}

func (m *mockBMCService) GetWebCertificate(ctx context.Context, profileID uint64) (*bmcpkg.CertificateInfo, error) {
	if m.getWebCertificateFn != nil {
		return m.getWebCertificateFn(ctx, profileID)
	}
	return &bmcpkg.CertificateInfo{Subject: "CN=mock-bmc"}, nil
}

func (m *mockBMCService) ReplaceWebCertificate(ctx context.Context, profileID uint64, certPEM, keyPEM []byte) error {
	if m.replaceWebCertFn != nil {
		return m.replaceWebCertFn(ctx, profileID, certPEM, keyPEM)
	}
	return nil
}

func (m *mockBMCService) ListUsers(ctx context.Context, profileID uint64) ([]bmcpkg.User, error) {
	if m.listUsersFn != nil {
		return m.listUsersFn(ctx, profileID)
	}
	return []bmcpkg.User{}, nil
}

func (m *mockBMCService) CreateUser(ctx context.Context, profileID uint64, user bmcpkg.User, password string) error {
	if m.createUserFn != nil {
		return m.createUserFn(ctx, profileID, user, password)
	}
	return nil
}

func (m *mockBMCService) DeleteUser(ctx context.Context, profileID uint64, slot uint8) error {
	if m.deleteUserFn != nil {
		return m.deleteUserFn(ctx, profileID, slot)
	}
	return nil
}

func (m *mockBMCService) SetUserPassword(ctx context.Context, profileID uint64, slot uint8, password string) error {
	if m.setUserPasswordFn != nil {
		return m.setUserPasswordFn(ctx, profileID, slot, password)
	}
	return nil
}

func (m *mockBMCService) SetUserPrivilege(ctx context.Context, profileID uint64, slot, channel uint8, privilege bmcpkg.Privilege) error {
	if m.setUserPrivilegeFn != nil {
		return m.setUserPrivilegeFn(ctx, profileID, slot, channel, privilege)
	}
	return nil
}

// mockBaremetalService is a test double for BaremetalServicer.
type mockBaremetalService struct {
	provisionFn func(ctx context.Context, req baremetal.ProvisionRequest) (*baremetal.ProvisionResult, error)
	statusFn    func(ctx context.Context, profileID uint64) (*baremetal.ProvisionResult, error)
}

func (m *mockBaremetalService) Provision(ctx context.Context, req baremetal.ProvisionRequest) (*baremetal.ProvisionResult, error) {
	if m.provisionFn != nil {
		return m.provisionFn(ctx, req)
	}
	return &baremetal.ProvisionResult{
		ProvisionID: "prov-123",
		ProfileID:   req.ProfileID,
		Status:      baremetal.StatusPending,
	}, nil
}

func (m *mockBaremetalService) Status(ctx context.Context, profileID uint64) (*baremetal.ProvisionResult, error) {
	if m.statusFn != nil {
		return m.statusFn(ctx, profileID)
	}
	return &baremetal.ProvisionResult{
		ProvisionID: "prov-123",
		ProfileID:   profileID,
		Status:      baremetal.StatusComplete,
	}, nil
}

// mockResponseWriter captures HTTP responses for assertions.
type mockResponseWriter struct {
	lastStatus int
	lastBody   interface{}
	lastErr    error
}

func (m *mockResponseWriter) Write(w http.ResponseWriter, r *http.Request, status int, response interface{}) {
	m.lastStatus = status
	m.lastBody = response
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(response)
}

func (m *mockResponseWriter) WriteYaml(w http.ResponseWriter, status int, response interface{}) {
	m.lastStatus = status
	m.lastBody = response
}

func (m *mockResponseWriter) WriteJson(w http.ResponseWriter, status int, response interface{}) {
	m.lastStatus = status
	m.lastBody = response
}

func (m *mockResponseWriter) Success200(w http.ResponseWriter, r *http.Request, payload interface{}) {
	m.lastStatus = http.StatusOK
	m.lastBody = payload
	w.WriteHeader(http.StatusOK)
	json.NewEncoder(w).Encode(payload)
}

func (m *mockResponseWriter) Success201(w http.ResponseWriter, r *http.Request, payload interface{}) {
	m.lastStatus = http.StatusCreated
	m.lastBody = payload
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(payload)
}

func (m *mockResponseWriter) Success404(w http.ResponseWriter, r *http.Request, payload interface{}, err error) {
	m.lastStatus = http.StatusNotFound
	m.lastBody = payload
	m.lastErr = err
}

func (m *mockResponseWriter) Error200(w http.ResponseWriter, r *http.Request, err error) {
	m.lastStatus = http.StatusOK
	m.lastErr = err
	w.WriteHeader(http.StatusOK)
}

func (m *mockResponseWriter) Error400(w http.ResponseWriter, r *http.Request, err error) {
	m.lastStatus = http.StatusBadRequest
	m.lastErr = err
	w.WriteHeader(http.StatusBadRequest)
}

func (m *mockResponseWriter) Error401(w http.ResponseWriter, r *http.Request, err error) {
	m.lastStatus = http.StatusUnauthorized
	m.lastErr = err
	w.WriteHeader(http.StatusUnauthorized)
}

func (m *mockResponseWriter) Error403(w http.ResponseWriter, r *http.Request, err error, payload interface{}) {
	m.lastStatus = http.StatusForbidden
	m.lastErr = err
	w.WriteHeader(http.StatusForbidden)
}

func (m *mockResponseWriter) Error404(w http.ResponseWriter, r *http.Request, err error) {
	m.lastStatus = http.StatusNotFound
	m.lastErr = err
	w.WriteHeader(http.StatusNotFound)
}

func (m *mockResponseWriter) Error500(w http.ResponseWriter, r *http.Request, err error) {
	m.lastStatus = http.StatusInternalServerError
	m.lastErr = err
	w.WriteHeader(http.StatusInternalServerError)
}

func (m *mockResponseWriter) Error503(w http.ResponseWriter, r *http.Request, err error) {
	m.lastStatus = http.StatusServiceUnavailable
	m.lastErr = err
	w.WriteHeader(http.StatusServiceUnavailable)
}

// newTestRouter creates a mux router with the given handler registered at the
// specified method and path.
func newTestRouter(method, path string, handlerFunc http.HandlerFunc) *mux.Router {
	r := mux.NewRouter()
	r.HandleFunc(path, handlerFunc).Methods(method)
	return r
}

func TestNewHandler(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		h, err := NewHandler(HandlerParams{
			Logger:         newTestLogger(),
			BMCService:     &mockBMCService{},
			ResponseWriter: &mockResponseWriter{},
		})
		if err != nil {
			t.Fatalf("expected no error, got: %v", err)
		}
		if h == nil {
			t.Fatal("expected handler, got nil")
		}
	})

	t.Run("missing_logger", func(t *testing.T) {
		_, err := NewHandler(HandlerParams{
			BMCService:     &mockBMCService{},
			ResponseWriter: &mockResponseWriter{},
		})
		if err == nil {
			t.Fatal("expected error for missing logger")
		}
	})

	t.Run("missing_bmc_service", func(t *testing.T) {
		_, err := NewHandler(HandlerParams{
			Logger:         newTestLogger(),
			ResponseWriter: &mockResponseWriter{},
		})
		if err == nil {
			t.Fatal("expected error for missing BMC service")
		}
	})

	t.Run("missing_response_writer", func(t *testing.T) {
		_, err := NewHandler(HandlerParams{
			Logger:     newTestLogger(),
			BMCService: &mockBMCService{},
		})
		if err == nil {
			t.Fatal("expected error for missing response writer")
		}
	})
}

func TestPowerAction(t *testing.T) {
	tests := []struct {
		name           string
		profileID      string
		body           interface{}
		powerOnErr     error
		expectedStatus int
	}{
		{
			name:           "power_on_success",
			profileID:      "42",
			body:           PowerActionRequest{Action: "on"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "power_off_success",
			profileID:      "42",
			body:           PowerActionRequest{Action: "off"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "power_reset_success",
			profileID:      "42",
			body:           PowerActionRequest{Action: "reset"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "power_cycle_success",
			profileID:      "42",
			body:           PowerActionRequest{Action: "cycle"},
			expectedStatus: http.StatusOK,
		},
		{
			name:           "invalid_profile_id",
			profileID:      "abc",
			body:           PowerActionRequest{Action: "on"},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "missing_action",
			profileID:      "42",
			body:           PowerActionRequest{Action: ""},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "invalid_action",
			profileID:      "42",
			body:           PowerActionRequest{Action: "destroy"},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name:           "service_error",
			profileID:      "42",
			body:           PowerActionRequest{Action: "on"},
			powerOnErr:     bmcpkg.ErrConnectionFailed{Address: "10.0.0.1"},
			expectedStatus: http.StatusInternalServerError,
		},
		{
			name:           "profile_not_found",
			profileID:      "999",
			body:           PowerActionRequest{Action: "on"},
			powerOnErr:     bmcpkg.ErrProfileNotFound{ProfileID: 999},
			expectedStatus: http.StatusNotFound,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			rw := &mockResponseWriter{}
			svc := &mockBMCService{
				powerOnFn: func(ctx context.Context, profileID uint64) error {
					return tc.powerOnErr
				},
			}
			h, err := NewHandler(HandlerParams{
				Logger:         newTestLogger(),
				BMCService:     svc,
				ResponseWriter: rw,
			})
			if err != nil {
				t.Fatalf("unexpected error creating handler: %v", err)
			}

			body, _ := json.Marshal(tc.body)
			req := httptest.NewRequest("POST", "/bmc/"+tc.profileID+"/power", bytes.NewReader(body))
			rec := httptest.NewRecorder()

			router := newTestRouter("POST", "/bmc/{profileID}/power", h.PowerAction)
			router.ServeHTTP(rec, req)

			if rw.lastStatus != tc.expectedStatus {
				t.Errorf("expected status %d, got %d", tc.expectedStatus, rw.lastStatus)
			}
		})
	}
}

func TestPowerAction_InvalidJSON(t *testing.T) {
	rw := &mockResponseWriter{}
	h, err := NewHandler(HandlerParams{
		Logger:         newTestLogger(),
		BMCService:     &mockBMCService{},
		ResponseWriter: rw,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest("POST", "/bmc/42/power", bytes.NewReader([]byte("{invalid")))
	rec := httptest.NewRecorder()

	router := newTestRouter("POST", "/bmc/{profileID}/power", h.PowerAction)
	router.ServeHTTP(rec, req)

	if rw.lastStatus != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rw.lastStatus)
	}
}

func TestPowerStatus(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		rw := &mockResponseWriter{}
		svc := &mockBMCService{
			powerStatusFn: func(ctx context.Context, profileID uint64) (bmcpkg.PowerState, error) {
				return bmcpkg.PowerStateOn, nil
			},
		}
		h, err := NewHandler(HandlerParams{
			Logger:         newTestLogger(),
			BMCService:     svc,
			ResponseWriter: rw,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		req := httptest.NewRequest("GET", "/bmc/42/power", nil)
		rec := httptest.NewRecorder()

		router := newTestRouter("GET", "/bmc/{profileID}/power", h.PowerStatus)
		router.ServeHTTP(rec, req)

		if rw.lastStatus != http.StatusOK {
			t.Errorf("expected status 200, got %d", rw.lastStatus)
		}

		resp, ok := rw.lastBody.(PowerStatusResponse)
		if !ok {
			t.Fatal("expected PowerStatusResponse in body")
		}
		if resp.State != "on" {
			t.Errorf("expected state 'on', got %q", resp.State)
		}
	})

	t.Run("invalid_profile_id", func(t *testing.T) {
		rw := &mockResponseWriter{}
		h, err := NewHandler(HandlerParams{
			Logger:         newTestLogger(),
			BMCService:     &mockBMCService{},
			ResponseWriter: rw,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		req := httptest.NewRequest("GET", "/bmc/abc/power", nil)
		rec := httptest.NewRecorder()

		router := newTestRouter("GET", "/bmc/{profileID}/power", h.PowerStatus)
		router.ServeHTTP(rec, req)

		if rw.lastStatus != http.StatusBadRequest {
			t.Errorf("expected status 400, got %d", rw.lastStatus)
		}
	})
}

func TestSetBootDevice(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		rw := &mockResponseWriter{}
		h, err := NewHandler(HandlerParams{
			Logger:         newTestLogger(),
			BMCService:     &mockBMCService{},
			ResponseWriter: rw,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		body, _ := json.Marshal(SetBootDeviceRequest{Device: "pxe", Persistent: true})
		req := httptest.NewRequest("POST", "/bmc/42/boot-device", bytes.NewReader(body))
		rec := httptest.NewRecorder()

		router := newTestRouter("POST", "/bmc/{profileID}/boot-device", h.SetBootDevice)
		router.ServeHTTP(rec, req)

		if rw.lastStatus != http.StatusOK {
			t.Errorf("expected status 200, got %d", rw.lastStatus)
		}
	})

	t.Run("missing_device", func(t *testing.T) {
		rw := &mockResponseWriter{}
		h, err := NewHandler(HandlerParams{
			Logger:         newTestLogger(),
			BMCService:     &mockBMCService{},
			ResponseWriter: rw,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		body, _ := json.Marshal(SetBootDeviceRequest{Device: ""})
		req := httptest.NewRequest("POST", "/bmc/42/boot-device", bytes.NewReader(body))
		rec := httptest.NewRecorder()

		router := newTestRouter("POST", "/bmc/{profileID}/boot-device", h.SetBootDevice)
		router.ServeHTTP(rec, req)

		if rw.lastStatus != http.StatusBadRequest {
			t.Errorf("expected status 400, got %d", rw.lastStatus)
		}
	})

	t.Run("invalid_device", func(t *testing.T) {
		rw := &mockResponseWriter{}
		h, err := NewHandler(HandlerParams{
			Logger:         newTestLogger(),
			BMCService:     &mockBMCService{},
			ResponseWriter: rw,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		body, _ := json.Marshal(SetBootDeviceRequest{Device: "floppy"})
		req := httptest.NewRequest("POST", "/bmc/42/boot-device", bytes.NewReader(body))
		rec := httptest.NewRecorder()

		router := newTestRouter("POST", "/bmc/{profileID}/boot-device", h.SetBootDevice)
		router.ServeHTTP(rec, req)

		if rw.lastStatus != http.StatusBadRequest {
			t.Errorf("expected status 400, got %d", rw.lastStatus)
		}
	})
}

func TestGetBootDevice(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		rw := &mockResponseWriter{}
		svc := &mockBMCService{
			getBootDeviceFn: func(ctx context.Context, profileID uint64) (bmcpkg.BootDevice, error) {
				return bmcpkg.BootDevicePXE, nil
			},
		}
		h, err := NewHandler(HandlerParams{
			Logger:         newTestLogger(),
			BMCService:     svc,
			ResponseWriter: rw,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		req := httptest.NewRequest("GET", "/bmc/42/boot-device", nil)
		rec := httptest.NewRecorder()

		router := newTestRouter("GET", "/bmc/{profileID}/boot-device", h.GetBootDevice)
		router.ServeHTTP(rec, req)

		if rw.lastStatus != http.StatusOK {
			t.Errorf("expected status 200, got %d", rw.lastStatus)
		}

		resp, ok := rw.lastBody.(BootDeviceResponse)
		if !ok {
			t.Fatal("expected BootDeviceResponse in body")
		}
		if resp.Device != "pxe" {
			t.Errorf("expected device 'pxe', got %q", resp.Device)
		}
	})

	t.Run("service_error", func(t *testing.T) {
		rw := &mockResponseWriter{}
		svc := &mockBMCService{
			getBootDeviceFn: func(ctx context.Context, profileID uint64) (bmcpkg.BootDevice, error) {
				return bmcpkg.BootDeviceNone, bmcpkg.ErrProfileNotFound{ProfileID: 42}
			},
		}
		h, err := NewHandler(HandlerParams{
			Logger:         newTestLogger(),
			BMCService:     svc,
			ResponseWriter: rw,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		req := httptest.NewRequest("GET", "/bmc/42/boot-device", nil)
		rec := httptest.NewRecorder()

		router := newTestRouter("GET", "/bmc/{profileID}/boot-device", h.GetBootDevice)
		router.ServeHTTP(rec, req)

		if rw.lastStatus != http.StatusNotFound {
			t.Errorf("expected status 404, got %d", rw.lastStatus)
		}
	})
}

func TestMountISO(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		rw := &mockResponseWriter{}
		h, err := NewHandler(HandlerParams{
			Logger:         newTestLogger(),
			BMCService:     &mockBMCService{},
			ResponseWriter: rw,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		body, _ := json.Marshal(MountISORequest{ISOURL: "https://iso.example.com/os.iso"})
		req := httptest.NewRequest("POST", "/bmc/42/virtual-media", bytes.NewReader(body))
		rec := httptest.NewRecorder()

		router := newTestRouter("POST", "/bmc/{profileID}/virtual-media", h.MountISO)
		router.ServeHTTP(rec, req)

		if rw.lastStatus != http.StatusOK {
			t.Errorf("expected status 200, got %d", rw.lastStatus)
		}
	})

	t.Run("missing_iso_url", func(t *testing.T) {
		rw := &mockResponseWriter{}
		h, err := NewHandler(HandlerParams{
			Logger:         newTestLogger(),
			BMCService:     &mockBMCService{},
			ResponseWriter: rw,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		body, _ := json.Marshal(MountISORequest{ISOURL: ""})
		req := httptest.NewRequest("POST", "/bmc/42/virtual-media", bytes.NewReader(body))
		rec := httptest.NewRecorder()

		router := newTestRouter("POST", "/bmc/{profileID}/virtual-media", h.MountISO)
		router.ServeHTTP(rec, req)

		if rw.lastStatus != http.StatusBadRequest {
			t.Errorf("expected status 400, got %d", rw.lastStatus)
		}
	})
}

func TestUnmountISO(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		rw := &mockResponseWriter{}
		h, err := NewHandler(HandlerParams{
			Logger:         newTestLogger(),
			BMCService:     &mockBMCService{},
			ResponseWriter: rw,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		req := httptest.NewRequest("DELETE", "/bmc/42/virtual-media", nil)
		rec := httptest.NewRecorder()

		router := newTestRouter("DELETE", "/bmc/{profileID}/virtual-media", h.UnmountISO)
		router.ServeHTTP(rec, req)

		if rw.lastStatus != http.StatusOK {
			t.Errorf("expected status 200, got %d", rw.lastStatus)
		}
	})

	t.Run("service_error", func(t *testing.T) {
		rw := &mockResponseWriter{}
		svc := &mockBMCService{
			unmountISOFn: func(ctx context.Context, profileID uint64) error {
				return bmcpkg.ErrVirtualMedia{Operation: "unmount"}
			},
		}
		h, err := NewHandler(HandlerParams{
			Logger:         newTestLogger(),
			BMCService:     svc,
			ResponseWriter: rw,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		req := httptest.NewRequest("DELETE", "/bmc/42/virtual-media", nil)
		rec := httptest.NewRecorder()

		router := newTestRouter("DELETE", "/bmc/{profileID}/virtual-media", h.UnmountISO)
		router.ServeHTTP(rec, req)

		if rw.lastStatus != http.StatusInternalServerError {
			t.Errorf("expected status 500, got %d", rw.lastStatus)
		}
	})
}

func TestVirtualMediaStatus(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		rw := &mockResponseWriter{}
		svc := &mockBMCService{
			virtualMediaStatFn: func(ctx context.Context, profileID uint64) (*bmcpkg.VirtualMediaInfo, error) {
				return &bmcpkg.VirtualMediaInfo{
					Mounted:  true,
					ImageURL: "https://iso.example.com/os.iso",
				}, nil
			},
		}
		h, err := NewHandler(HandlerParams{
			Logger:         newTestLogger(),
			BMCService:     svc,
			ResponseWriter: rw,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		req := httptest.NewRequest("GET", "/bmc/42/virtual-media", nil)
		rec := httptest.NewRecorder()

		router := newTestRouter("GET", "/bmc/{profileID}/virtual-media", h.VirtualMediaStatus)
		router.ServeHTTP(rec, req)

		if rw.lastStatus != http.StatusOK {
			t.Errorf("expected status 200, got %d", rw.lastStatus)
		}
	})

	t.Run("invalid_profile_id", func(t *testing.T) {
		rw := &mockResponseWriter{}
		h, err := NewHandler(HandlerParams{
			Logger:         newTestLogger(),
			BMCService:     &mockBMCService{},
			ResponseWriter: rw,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		req := httptest.NewRequest("GET", "/bmc/xyz/virtual-media", nil)
		rec := httptest.NewRecorder()

		router := newTestRouter("GET", "/bmc/{profileID}/virtual-media", h.VirtualMediaStatus)
		router.ServeHTTP(rec, req)

		if rw.lastStatus != http.StatusBadRequest {
			t.Errorf("expected status 400, got %d", rw.lastStatus)
		}
	})
}

func TestGetSensors(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		rw := &mockResponseWriter{}
		svc := &mockBMCService{
			getSensorsFn: func(ctx context.Context, profileID uint64) ([]bmcpkg.SensorReading, error) {
				return []bmcpkg.SensorReading{
					{Name: "CPU Temp", Value: 45.0, Units: "C", Status: "ok"},
				}, nil
			},
		}
		h, err := NewHandler(HandlerParams{
			Logger:         newTestLogger(),
			BMCService:     svc,
			ResponseWriter: rw,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		req := httptest.NewRequest("GET", "/bmc/42/sensors", nil)
		rec := httptest.NewRecorder()

		router := newTestRouter("GET", "/bmc/{profileID}/sensors", h.GetSensors)
		router.ServeHTTP(rec, req)

		if rw.lastStatus != http.StatusOK {
			t.Errorf("expected status 200, got %d", rw.lastStatus)
		}
	})

	t.Run("service_error", func(t *testing.T) {
		rw := &mockResponseWriter{}
		svc := &mockBMCService{
			getSensorsFn: func(ctx context.Context, profileID uint64) ([]bmcpkg.SensorReading, error) {
				return nil, bmcpkg.ErrInventory{Cause: bmcpkg.ErrConnectionFailed{Address: "10.0.0.1"}}
			},
		}
		h, err := NewHandler(HandlerParams{
			Logger:         newTestLogger(),
			BMCService:     svc,
			ResponseWriter: rw,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		req := httptest.NewRequest("GET", "/bmc/42/sensors", nil)
		rec := httptest.NewRecorder()

		router := newTestRouter("GET", "/bmc/{profileID}/sensors", h.GetSensors)
		router.ServeHTTP(rec, req)

		if rw.lastStatus != http.StatusInternalServerError {
			t.Errorf("expected status 500, got %d", rw.lastStatus)
		}
	})
}

func TestGetSystemInfo(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		rw := &mockResponseWriter{}
		svc := &mockBMCService{
			getSystemInfoFn: func(ctx context.Context, profileID uint64) (*bmcpkg.SystemInfo, error) {
				return &bmcpkg.SystemInfo{
					Manufacturer: "Dell",
					Product:      "PowerEdge R640",
				}, nil
			},
		}
		h, err := NewHandler(HandlerParams{
			Logger:         newTestLogger(),
			BMCService:     svc,
			ResponseWriter: rw,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		req := httptest.NewRequest("GET", "/bmc/42/system-info", nil)
		rec := httptest.NewRecorder()

		router := newTestRouter("GET", "/bmc/{profileID}/system-info", h.GetSystemInfo)
		router.ServeHTTP(rec, req)

		if rw.lastStatus != http.StatusOK {
			t.Errorf("expected status 200, got %d", rw.lastStatus)
		}
	})

	t.Run("profile_not_found", func(t *testing.T) {
		rw := &mockResponseWriter{}
		svc := &mockBMCService{
			getSystemInfoFn: func(ctx context.Context, profileID uint64) (*bmcpkg.SystemInfo, error) {
				return nil, bmcpkg.ErrProfileNotFound{ProfileID: 999}
			},
		}
		h, err := NewHandler(HandlerParams{
			Logger:         newTestLogger(),
			BMCService:     svc,
			ResponseWriter: rw,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		req := httptest.NewRequest("GET", "/bmc/999/system-info", nil)
		rec := httptest.NewRecorder()

		router := newTestRouter("GET", "/bmc/{profileID}/system-info", h.GetSystemInfo)
		router.ServeHTTP(rec, req)

		if rw.lastStatus != http.StatusNotFound {
			t.Errorf("expected status 404, got %d", rw.lastStatus)
		}
	})
}

func TestProvision(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		rw := &mockResponseWriter{}
		h, err := NewHandler(HandlerParams{
			Logger:           newTestLogger(),
			BMCService:       &mockBMCService{},
			BaremetalService: &mockBaremetalService{},
			ResponseWriter:   rw,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		body, _ := json.Marshal(ProvisionRequest{ISOURL: "https://iso.example.com/os.iso"})
		req := httptest.NewRequest("POST", "/bmc/42/provision", bytes.NewReader(body))
		rec := httptest.NewRecorder()

		router := newTestRouter("POST", "/bmc/{profileID}/provision", h.Provision)
		router.ServeHTTP(rec, req)

		if rw.lastStatus != http.StatusCreated {
			t.Errorf("expected status 201, got %d", rw.lastStatus)
		}
	})

	t.Run("no_baremetal_service", func(t *testing.T) {
		rw := &mockResponseWriter{}
		h, err := NewHandler(HandlerParams{
			Logger:         newTestLogger(),
			BMCService:     &mockBMCService{},
			ResponseWriter: rw,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		body, _ := json.Marshal(ProvisionRequest{})
		req := httptest.NewRequest("POST", "/bmc/42/provision", bytes.NewReader(body))
		rec := httptest.NewRecorder()

		router := newTestRouter("POST", "/bmc/{profileID}/provision", h.Provision)
		router.ServeHTTP(rec, req)

		if rw.lastStatus != http.StatusServiceUnavailable {
			t.Errorf("expected status 503, got %d", rw.lastStatus)
		}
		if _, ok := rw.lastErr.(ErrBaremetalServiceNotAvailable); !ok {
			t.Errorf("err = %T, want ErrBaremetalServiceNotAvailable", rw.lastErr)
		}
	})

	t.Run("already_in_progress", func(t *testing.T) {
		rw := &mockResponseWriter{}
		bmSvc := &mockBaremetalService{
			provisionFn: func(ctx context.Context, req baremetal.ProvisionRequest) (*baremetal.ProvisionResult, error) {
				return nil, baremetal.ErrProvisionInProgress{ProfileID: 42}
			},
		}
		h, err := NewHandler(HandlerParams{
			Logger:           newTestLogger(),
			BMCService:       &mockBMCService{},
			BaremetalService: bmSvc,
			ResponseWriter:   rw,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		body, _ := json.Marshal(ProvisionRequest{})
		req := httptest.NewRequest("POST", "/bmc/42/provision", bytes.NewReader(body))
		rec := httptest.NewRecorder()

		router := newTestRouter("POST", "/bmc/{profileID}/provision", h.Provision)
		router.ServeHTTP(rec, req)

		if rw.lastStatus != http.StatusConflict {
			t.Errorf("expected status 409, got %d", rw.lastStatus)
		}
	})

	t.Run("invalid_request", func(t *testing.T) {
		rw := &mockResponseWriter{}
		bmSvc := &mockBaremetalService{
			provisionFn: func(ctx context.Context, req baremetal.ProvisionRequest) (*baremetal.ProvisionResult, error) {
				return nil, baremetal.ErrInvalidProvisionRequest{Reason: "missing ISO URL"}
			},
		}
		h, err := NewHandler(HandlerParams{
			Logger:           newTestLogger(),
			BMCService:       &mockBMCService{},
			BaremetalService: bmSvc,
			ResponseWriter:   rw,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		body, _ := json.Marshal(ProvisionRequest{})
		req := httptest.NewRequest("POST", "/bmc/42/provision", bytes.NewReader(body))
		rec := httptest.NewRecorder()

		router := newTestRouter("POST", "/bmc/{profileID}/provision", h.Provision)
		router.ServeHTTP(rec, req)

		if rw.lastStatus != http.StatusBadRequest {
			t.Errorf("expected status 400, got %d", rw.lastStatus)
		}
	})
}

func TestProvisionStatus(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		rw := &mockResponseWriter{}
		h, err := NewHandler(HandlerParams{
			Logger:           newTestLogger(),
			BMCService:       &mockBMCService{},
			BaremetalService: &mockBaremetalService{},
			ResponseWriter:   rw,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		req := httptest.NewRequest("GET", "/bmc/42/provision", nil)
		rec := httptest.NewRecorder()

		router := newTestRouter("GET", "/bmc/{profileID}/provision", h.ProvisionStatus)
		router.ServeHTTP(rec, req)

		if rw.lastStatus != http.StatusOK {
			t.Errorf("expected status 200, got %d", rw.lastStatus)
		}
	})

	t.Run("not_found", func(t *testing.T) {
		rw := &mockResponseWriter{}
		bmSvc := &mockBaremetalService{
			statusFn: func(ctx context.Context, profileID uint64) (*baremetal.ProvisionResult, error) {
				return nil, baremetal.ErrProvisionNotFound{ProvisionID: "prov-42"}
			},
		}
		h, err := NewHandler(HandlerParams{
			Logger:           newTestLogger(),
			BMCService:       &mockBMCService{},
			BaremetalService: bmSvc,
			ResponseWriter:   rw,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		req := httptest.NewRequest("GET", "/bmc/42/provision", nil)
		rec := httptest.NewRecorder()

		router := newTestRouter("GET", "/bmc/{profileID}/provision", h.ProvisionStatus)
		router.ServeHTTP(rec, req)

		if rw.lastStatus != http.StatusNotFound {
			t.Errorf("expected status 404, got %d", rw.lastStatus)
		}
	})

	t.Run("no_baremetal_service", func(t *testing.T) {
		rw := &mockResponseWriter{}
		h, err := NewHandler(HandlerParams{
			Logger:         newTestLogger(),
			BMCService:     &mockBMCService{},
			ResponseWriter: rw,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		req := httptest.NewRequest("GET", "/bmc/42/provision", nil)
		rec := httptest.NewRecorder()

		router := newTestRouter("GET", "/bmc/{profileID}/provision", h.ProvisionStatus)
		router.ServeHTTP(rec, req)

		if rw.lastStatus != http.StatusServiceUnavailable {
			t.Errorf("expected status 503, got %d", rw.lastStatus)
		}
		if _, ok := rw.lastErr.(ErrBaremetalServiceNotAvailable); !ok {
			t.Errorf("err = %T, want ErrBaremetalServiceNotAvailable", rw.lastErr)
		}
	})
}

func TestProvision_ProfileNoBMC(t *testing.T) {
	rw := &mockResponseWriter{}
	bmSvc := &mockBaremetalService{
		provisionFn: func(ctx context.Context, req baremetal.ProvisionRequest) (*baremetal.ProvisionResult, error) {
			return nil, baremetal.ErrProfileNoBMC{ProfileID: 42}
		},
	}
	h, err := NewHandler(HandlerParams{
		Logger:           newTestLogger(),
		BMCService:       &mockBMCService{},
		BaremetalService: bmSvc,
		ResponseWriter:   rw,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	body, _ := json.Marshal(ProvisionRequest{})
	req := httptest.NewRequest("POST", "/bmc/42/provision", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	router := newTestRouter("POST", "/bmc/{profileID}/provision", h.Provision)
	router.ServeHTTP(rec, req)

	if rw.lastStatus != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rw.lastStatus)
	}
}

func TestProvision_GenericError(t *testing.T) {
	rw := &mockResponseWriter{}
	bmSvc := &mockBaremetalService{
		provisionFn: func(ctx context.Context, req baremetal.ProvisionRequest) (*baremetal.ProvisionResult, error) {
			return nil, bmcpkg.ErrConnectionFailed{Address: "10.0.0.1"}
		},
	}
	h, err := NewHandler(HandlerParams{
		Logger:           newTestLogger(),
		BMCService:       &mockBMCService{},
		BaremetalService: bmSvc,
		ResponseWriter:   rw,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	body, _ := json.Marshal(ProvisionRequest{ISOURL: "https://iso.example.com/os.iso"})
	req := httptest.NewRequest("POST", "/bmc/42/provision", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	router := newTestRouter("POST", "/bmc/{profileID}/provision", h.Provision)
	router.ServeHTTP(rec, req)

	if rw.lastStatus != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", rw.lastStatus)
	}
}

func TestProvision_InvalidJSON(t *testing.T) {
	rw := &mockResponseWriter{}
	h, err := NewHandler(HandlerParams{
		Logger:           newTestLogger(),
		BMCService:       &mockBMCService{},
		BaremetalService: &mockBaremetalService{},
		ResponseWriter:   rw,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest("POST", "/bmc/42/provision", bytes.NewReader([]byte("{bad")))
	rec := httptest.NewRecorder()

	router := newTestRouter("POST", "/bmc/{profileID}/provision", h.Provision)
	router.ServeHTTP(rec, req)

	if rw.lastStatus != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rw.lastStatus)
	}
}

func TestProvision_InvalidProfileID(t *testing.T) {
	rw := &mockResponseWriter{}
	h, err := NewHandler(HandlerParams{
		Logger:           newTestLogger(),
		BMCService:       &mockBMCService{},
		BaremetalService: &mockBaremetalService{},
		ResponseWriter:   rw,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	body, _ := json.Marshal(ProvisionRequest{})
	req := httptest.NewRequest("POST", "/bmc/abc/provision", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	router := newTestRouter("POST", "/bmc/{profileID}/provision", h.Provision)
	router.ServeHTTP(rec, req)

	if rw.lastStatus != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rw.lastStatus)
	}
}

func TestProvisionStatus_GenericError(t *testing.T) {
	rw := &mockResponseWriter{}
	bmSvc := &mockBaremetalService{
		statusFn: func(ctx context.Context, profileID uint64) (*baremetal.ProvisionResult, error) {
			return nil, bmcpkg.ErrConnectionFailed{Address: "10.0.0.1"}
		},
	}
	h, err := NewHandler(HandlerParams{
		Logger:           newTestLogger(),
		BMCService:       &mockBMCService{},
		BaremetalService: bmSvc,
		ResponseWriter:   rw,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest("GET", "/bmc/42/provision", nil)
	rec := httptest.NewRecorder()

	router := newTestRouter("GET", "/bmc/{profileID}/provision", h.ProvisionStatus)
	router.ServeHTTP(rec, req)

	if rw.lastStatus != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", rw.lastStatus)
	}
}

func TestProvisionStatus_InvalidProfileID(t *testing.T) {
	rw := &mockResponseWriter{}
	h, err := NewHandler(HandlerParams{
		Logger:           newTestLogger(),
		BMCService:       &mockBMCService{},
		BaremetalService: &mockBaremetalService{},
		ResponseWriter:   rw,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest("GET", "/bmc/abc/provision", nil)
	rec := httptest.NewRecorder()

	router := newTestRouter("GET", "/bmc/{profileID}/provision", h.ProvisionStatus)
	router.ServeHTTP(rec, req)

	if rw.lastStatus != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rw.lastStatus)
	}
}

func TestSetBootDevice_ServiceError(t *testing.T) {
	rw := &mockResponseWriter{}
	svc := &mockBMCService{
		setBootDeviceFn: func(ctx context.Context, profileID uint64, device bmcpkg.BootDevice, persistent bool) error {
			return bmcpkg.ErrBootDevice{Device: string(device)}
		},
	}
	h, err := NewHandler(HandlerParams{
		Logger:         newTestLogger(),
		BMCService:     svc,
		ResponseWriter: rw,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	body, _ := json.Marshal(SetBootDeviceRequest{Device: "pxe", Persistent: false})
	req := httptest.NewRequest("POST", "/bmc/42/boot-device", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	router := newTestRouter("POST", "/bmc/{profileID}/boot-device", h.SetBootDevice)
	router.ServeHTTP(rec, req)

	if rw.lastStatus != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", rw.lastStatus)
	}
}

func TestSetBootDevice_InvalidJSON(t *testing.T) {
	rw := &mockResponseWriter{}
	h, err := NewHandler(HandlerParams{
		Logger:         newTestLogger(),
		BMCService:     &mockBMCService{},
		ResponseWriter: rw,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest("POST", "/bmc/42/boot-device", bytes.NewReader([]byte("{bad")))
	rec := httptest.NewRecorder()

	router := newTestRouter("POST", "/bmc/{profileID}/boot-device", h.SetBootDevice)
	router.ServeHTTP(rec, req)

	if rw.lastStatus != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rw.lastStatus)
	}
}

func TestMountISO_ServiceError(t *testing.T) {
	rw := &mockResponseWriter{}
	svc := &mockBMCService{
		mountISOFn: func(ctx context.Context, profileID uint64, isoURL string) error {
			return bmcpkg.ErrVirtualMedia{Operation: "mount"}
		},
	}
	h, err := NewHandler(HandlerParams{
		Logger:         newTestLogger(),
		BMCService:     svc,
		ResponseWriter: rw,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	body, _ := json.Marshal(MountISORequest{ISOURL: "https://iso.example.com/os.iso"})
	req := httptest.NewRequest("POST", "/bmc/42/virtual-media", bytes.NewReader(body))
	rec := httptest.NewRecorder()

	router := newTestRouter("POST", "/bmc/{profileID}/virtual-media", h.MountISO)
	router.ServeHTTP(rec, req)

	if rw.lastStatus != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", rw.lastStatus)
	}
}

func TestMountISO_InvalidJSON(t *testing.T) {
	rw := &mockResponseWriter{}
	h, err := NewHandler(HandlerParams{
		Logger:         newTestLogger(),
		BMCService:     &mockBMCService{},
		ResponseWriter: rw,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest("POST", "/bmc/42/virtual-media", bytes.NewReader([]byte("{bad")))
	rec := httptest.NewRecorder()

	router := newTestRouter("POST", "/bmc/{profileID}/virtual-media", h.MountISO)
	router.ServeHTTP(rec, req)

	if rw.lastStatus != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rw.lastStatus)
	}
}

func TestPowerStatus_ServiceError(t *testing.T) {
	rw := &mockResponseWriter{}
	svc := &mockBMCService{
		powerStatusFn: func(ctx context.Context, profileID uint64) (bmcpkg.PowerState, error) {
			return bmcpkg.PowerStateUnknown, bmcpkg.ErrConnectionFailed{Address: "10.0.0.1"}
		},
	}
	h, err := NewHandler(HandlerParams{
		Logger:         newTestLogger(),
		BMCService:     svc,
		ResponseWriter: rw,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest("GET", "/bmc/42/power", nil)
	rec := httptest.NewRecorder()

	router := newTestRouter("GET", "/bmc/{profileID}/power", h.PowerStatus)
	router.ServeHTTP(rec, req)

	if rw.lastStatus != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", rw.lastStatus)
	}
}

func TestGetSensors_InvalidProfileID(t *testing.T) {
	rw := &mockResponseWriter{}
	h, err := NewHandler(HandlerParams{
		Logger:         newTestLogger(),
		BMCService:     &mockBMCService{},
		ResponseWriter: rw,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest("GET", "/bmc/abc/sensors", nil)
	rec := httptest.NewRecorder()

	router := newTestRouter("GET", "/bmc/{profileID}/sensors", h.GetSensors)
	router.ServeHTTP(rec, req)

	if rw.lastStatus != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rw.lastStatus)
	}
}

func TestGetSystemInfo_InvalidProfileID(t *testing.T) {
	rw := &mockResponseWriter{}
	h, err := NewHandler(HandlerParams{
		Logger:         newTestLogger(),
		BMCService:     &mockBMCService{},
		ResponseWriter: rw,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest("GET", "/bmc/abc/system-info", nil)
	rec := httptest.NewRecorder()

	router := newTestRouter("GET", "/bmc/{profileID}/system-info", h.GetSystemInfo)
	router.ServeHTTP(rec, req)

	if rw.lastStatus != http.StatusBadRequest {
		t.Errorf("expected status 400, got %d", rw.lastStatus)
	}
}

func TestVirtualMediaStatus_ServiceError(t *testing.T) {
	rw := &mockResponseWriter{}
	svc := &mockBMCService{
		virtualMediaStatFn: func(ctx context.Context, profileID uint64) (*bmcpkg.VirtualMediaInfo, error) {
			return nil, bmcpkg.ErrConnectionFailed{Address: "10.0.0.1"}
		},
	}
	h, err := NewHandler(HandlerParams{
		Logger:         newTestLogger(),
		BMCService:     svc,
		ResponseWriter: rw,
	})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	req := httptest.NewRequest("GET", "/bmc/42/virtual-media", nil)
	rec := httptest.NewRecorder()

	router := newTestRouter("GET", "/bmc/{profileID}/virtual-media", h.VirtualMediaStatus)
	router.ServeHTTP(rec, req)

	if rw.lastStatus != http.StatusInternalServerError {
		t.Errorf("expected status 500, got %d", rw.lastStatus)
	}
}
