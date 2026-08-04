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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// newTestTemplateHandler builds a TemplateHandler backed by the shared
// mock profile service (template service left nil: assignment endpoints
// only touch the profile service).
func newTestTemplateHandler() (*TemplateHandler, *mockProfileService) {
	profileSvc := newMockProfileService()
	handler := &TemplateHandler{
		logger:         logging.DefaultLogger(),
		responseWriter: &mockResponseWriter{},
		profileService: profileSvc,
	}
	return handler, profileSvc
}

// assignRequest performs a POST against the assignment handler with the
// profile ID injected as a mux var.
func assignRequest(t *testing.T, handler http.HandlerFunc, id string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, "/device/profiles/"+id+"/assign", bytes.NewReader(encoded))
	req = mux.SetURLVars(req, map[string]string{"id": id})
	rec := httptest.NewRecorder()
	handler(rec, req)
	return rec
}

// TestTemplateHandler_AssignProfileToDevice verifies the assign endpoint
// binds the EK identity and prestages the EK certificate.
func TestTemplateHandler_AssignProfileToDevice(t *testing.T) {
	handler, profileSvc := newTestTemplateHandler()
	ekCert := newEKCertPEMForWebserviceTest(t)

	profileSvc.profiles[100] = &entities.DeviceProfile{ID: 100, Name: "assign-me"}

	rec := assignRequest(t, handler.AssignProfileToDevice, "100", AssignProfileToDeviceRequest{
		EKSerial:   "EK-1001",
		MACAddress: "00:25:90:ff:aa:02",
		EKCert:     ekCert,
	})

	assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	stored := profileSvc.profiles[100]
	assert.True(t, stored.Assigned)
	assert.Equal(t, "EK-1001", stored.EKSerial)
	assert.Equal(t, "00:25:90:ff:aa:02", stored.MACAddress)
	assert.Equal(t, ekCert, stored.EKCert)
}

// TestTemplateHandler_AssignProfileToDevice_Errors verifies boundary
// validation on the assign endpoint.
func TestTemplateHandler_AssignProfileToDevice_Errors(t *testing.T) {
	handler, profileSvc := newTestTemplateHandler()
	profileSvc.profiles[101] = &entities.DeviceProfile{ID: 101}

	t.Run("MissingIdentity", func(t *testing.T) {
		rec := assignRequest(t, handler.AssignProfileToDevice, "101", AssignProfileToDeviceRequest{})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("InvalidEKCert", func(t *testing.T) {
		rec := assignRequest(t, handler.AssignProfileToDevice, "101", AssignProfileToDeviceRequest{
			EKSerial: "EK-1",
			EKCert:   "not-a-pem",
		})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("InvalidProfileID", func(t *testing.T) {
		rec := assignRequest(t, handler.AssignProfileToDevice, "not-a-number", AssignProfileToDeviceRequest{
			EKSerial: "EK-1",
		})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("ServiceUnavailable", func(t *testing.T) {
		bare := &TemplateHandler{
			logger:         logging.DefaultLogger(),
			responseWriter: &mockResponseWriter{},
		}
		rec := assignRequest(t, bare.AssignProfileToDevice, "101", AssignProfileToDeviceRequest{
			EKSerial: "EK-1",
		})
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}

// TestTemplateHandler_UnassignProfileFromDevice verifies the unassign
// endpoint clears the device binding, plus its error paths.
func TestTemplateHandler_UnassignProfileFromDevice(t *testing.T) {
	handler, profileSvc := newTestTemplateHandler()

	profileSvc.profiles[200] = &entities.DeviceProfile{
		ID:       200,
		EKSerial: "EK-2002",
		EKCert:   newEKCertPEMForWebserviceTest(t),
		Assigned: true,
	}

	rec := assignRequest(t, handler.UnassignProfileFromDevice, "200", nil)
	assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	stored := profileSvc.profiles[200]
	assert.False(t, stored.Assigned)
	assert.Empty(t, stored.EKSerial)
	assert.Empty(t, stored.EKCert)

	t.Run("InvalidProfileID", func(t *testing.T) {
		rec := assignRequest(t, handler.UnassignProfileFromDevice, "abc", nil)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("UnknownProfile", func(t *testing.T) {
		rec := assignRequest(t, handler.UnassignProfileFromDevice, "999999", nil)
		assert.NotEqual(t, http.StatusOK, rec.Code)
	})
}
