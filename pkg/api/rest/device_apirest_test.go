package rest

import (
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"testing/iotest"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func deviceErrorMessage(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var errResp ErrorResponse
	decodeResponse(t, rec.Body, &errResp)
	return errResp.Error
}

func serveDevice(router *mux.Router, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// The router never yields an empty {id}, so the ID-scoped handlers are
// driven directly to prove they refuse before reaching a service.
func TestDeviceAPIRest_EmptyID(t *testing.T) {
	h := NewDeviceHandlers(newMockDeviceService(), newMockProfileService(), slog.Default(),
		WithDeviceAttestService(&stubAttestService{resp: &platformv1.AttestDeviceResponse{}}))
	cases := []struct {
		name   string
		handle http.HandlerFunc
		want   error
	}{
		{"get device", h.handleGetDevice, ErrDeviceInvalidID{}},
		{"update device", h.handleUpdateDevice, ErrDeviceInvalidID{}},
		{"delete device", h.handleDeleteDevice, ErrDeviceInvalidID{}},
		{"activate device", h.handleActivateDevice, ErrDeviceInvalidID{}},
		{"attest device", h.handleAttestDevice, ErrDeviceInvalidID{}},
		{"device state", h.handleGetDeviceState, ErrDeviceInvalidID{}},
		{"get profile", h.handleGetProfile, ErrInvalidProfileID{}},
		{"update profile", h.handleUpdateProfile, ErrInvalidProfileID{}},
		{"delete profile", h.handleDeleteProfile, ErrInvalidProfileID{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := mux.SetURLVars(httptest.NewRequest(http.MethodPost, "/", strings.NewReader(`{}`)), map[string]string{"id": ""})
			rec := httptest.NewRecorder()
			tc.handle(rec, req)
			require.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Equal(t, tc.want.Error(), deviceErrorMessage(t, rec))
		})
	}
}

func TestDeviceAPIRest_GetBySerialEmpty(t *testing.T) {
	h, _ := setupDeviceTestHandler(newMockDeviceService(), nil)
	req := mux.SetURLVars(httptest.NewRequest(http.MethodGet, "/", nil), map[string]string{"serial": ""})
	rec := httptest.NewRecorder()

	h.handleGetDeviceBySerial(rec, req)

	require.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Contains(t, deviceErrorMessage(t, rec), "serial")
}

func TestDeviceAPIRest_ActivateRefusals(t *testing.T) {
	t.Run("state that cannot activate", func(t *testing.T) {
		svc := newMockDeviceService()
		svc.addDevice(&entities.Device{ID: 7, Serial: "SN7", State: entities.DeviceStateRevoked})
		_, router := setupDeviceTestHandler(svc, nil)

		rec := serveDevice(router, http.MethodPost, "/api/v1/devices/7/activate", "")

		require.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, ErrDeviceActivationFailed{ID: 7, Reason: "device cannot be activated from state: revoked"}.Error(),
			deviceErrorMessage(t, rec))
		assert.Equal(t, entities.DeviceStateRevoked, svc.devices[7].State)
	})

	// CanActivate admits an unknown device but the lifecycle state machine
	// only lets it move to registered; the refusal must surface, not 500.
	t.Run("state machine refuses unknown", func(t *testing.T) {
		svc := newMockDeviceService()
		svc.addDevice(&entities.Device{ID: 8, Serial: "SN8", State: entities.DeviceStateUnknown})
		_, router := setupDeviceTestHandler(svc, nil)

		rec := serveDevice(router, http.MethodPost, "/api/v1/devices/8/activate", "")

		require.Equal(t, http.StatusBadRequest, rec.Code)
		transitionErr := entities.ErrInvalidTransition{From: entities.DeviceStateUnknown, To: entities.DeviceStateActivated}
		assert.Equal(t, ErrDeviceActivationFailed{ID: 8, Reason: transitionErr.Error()}.Error(), deviceErrorMessage(t, rec))
	})

	t.Run("persist failure", func(t *testing.T) {
		svc := newMockDeviceService()
		svc.addDevice(&entities.Device{ID: 9, Serial: "SN9", State: entities.DeviceStateRegistered})
		svc.updateErr = errors.New("disk full")
		_, router := setupDeviceTestHandler(svc, nil)

		rec := serveDevice(router, http.MethodPost, "/api/v1/devices/9/activate", `{"nonce":"AQID"}`)

		require.Equal(t, http.StatusInternalServerError, rec.Code)
		assert.Equal(t, ErrDeviceOperationFailed{Operation: "update", Cause: svc.updateErr}.Error(), deviceErrorMessage(t, rec))
	})
}

func TestDeviceAPIRest_AttestPreconditions(t *testing.T) {
	t.Run("no attestation service", func(t *testing.T) {
		h, _ := setupDeviceTestHandler(newMockDeviceService(), nil)
		req := mux.SetURLVars(httptest.NewRequest(http.MethodPost, "/", nil), map[string]string{"id": "1"})
		rec := httptest.NewRecorder()

		h.handleAttestDevice(rec, req)

		require.Equal(t, http.StatusServiceUnavailable, rec.Code)
		assert.Equal(t, "device attestation service is not available", deviceErrorMessage(t, rec))
	})

	t.Run("body read failure", func(t *testing.T) {
		h := NewDeviceHandlers(newMockDeviceService(), nil, slog.Default(),
			WithDeviceAttestService(&stubAttestService{resp: &platformv1.AttestDeviceResponse{}}))
		req := mux.SetURLVars(httptest.NewRequest(http.MethodPost, "/", iotest.ErrReader(errors.New("connection reset"))),
			map[string]string{"id": "1"})
		rec := httptest.NewRecorder()

		h.handleAttestDevice(rec, req)

		require.Equal(t, http.StatusBadRequest, rec.Code)
		assert.Equal(t, ErrInvalidRequestBody{Reason: "connection reset"}.Error(), deviceErrorMessage(t, rec))
	})
}

func TestDeviceAPIRest_DeviceState(t *testing.T) {
	attested := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	heartbeat := attested.Add(time.Hour)
	svc := newMockDeviceService()
	svc.addDevice(&entities.Device{ID: 3, Serial: "SN3", LastAttestedAt: attested, LastHeartbeatAt: heartbeat})
	_, router := setupDeviceTestHandler(svc, nil)

	rec := serveDevice(router, http.MethodGet, "/api/v1/devices/3/state", "")

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp DeviceStateResponse
	decodeResponse(t, rec.Body, &resp)
	assert.Equal(t, uint64(3), resp.DeviceID)
	assert.Equal(t, "SN3", resp.Serial)
	assert.Equal(t, "registered", resp.State, "an unset state reports registered")
	assert.True(t, attested.Equal(resp.LastAttested))
	assert.True(t, heartbeat.Equal(resp.LastHeartbeat))
}

func TestDeviceAPIRest_UpdateProfileNetworkFields(t *testing.T) {
	profiles := newMockProfileService()
	profiles.addProfile(&entities.DeviceProfile{ID: 4, Name: "edge"})
	_, router := setupDeviceTestHandler(nil, profiles)

	rec := serveDevice(router, http.MethodPut, "/api/v1/devices/profiles/4",
		`{"zone":"dmz","enrollment_network":"enroll","post_enrollment_network":"prod","failure_network":"quarantine"}`)

	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	var resp ProfileResponse
	decodeResponse(t, rec.Body, &resp)
	assert.Equal(t, "edge", resp.Name, "unset fields keep their stored value")
	assert.Equal(t, "dmz", resp.Zone)
	assert.Equal(t, "enroll", resp.EnrollmentNetwork)
	assert.Equal(t, "prod", resp.PostEnrollmentNetwork)
	assert.Equal(t, "quarantine", resp.FailureNetwork)
	assert.Equal(t, "dmz", profiles.profiles[4].Zone)
}

func TestDeviceAPIRest_ErrorMessages(t *testing.T) {
	assert.Equal(t, "device activation failed for ID 5: busy", ErrDeviceActivationFailed{ID: 5, Reason: "busy"}.Error())
	assert.Equal(t, "device attestation service is not available", ErrDeviceAttestationUnavailable{}.Error())
	assert.Equal(t, "device attestation could not be evaluated", ErrDeviceAttestationRejected{}.Error())
}

func TestDeviceAPIRest_WriteJSONEncodeFailure(t *testing.T) {
	h, _ := setupDeviceTestHandler(nil, nil)
	rec := httptest.NewRecorder()

	h.writeJSON(rec, http.StatusOK, map[string]interface{}{"ch": make(chan int)})

	assert.Equal(t, http.StatusOK, rec.Code)
	assert.Empty(t, rec.Body.String())
}
