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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// newTestTemplateRouter builds a mux router with the template routes
// registered against the shared mock profile service (template service
// left nil: assignment endpoints only touch the profile service).
func newTestTemplateRouter() (*mux.Router, *mockProfileService) {
	profileSvc := newMockProfileService()
	handlers := NewTemplateHandlers(nil, profileSvc, nil)
	router := mux.NewRouter()
	handlers.RegisterRoutes(router)
	return router, profileSvc
}

// postTemplateJSON performs a POST with a JSON body through the router.
func postTemplateJSON(t *testing.T, router *mux.Router, path string, body interface{}) *httptest.ResponseRecorder {
	t.Helper()
	encoded, err := json.Marshal(body)
	require.NoError(t, err)
	req := httptest.NewRequest(http.MethodPost, path, bytes.NewReader(encoded))
	rec := httptest.NewRecorder()
	router.ServeHTTP(rec, req)
	return rec
}

// TestTemplateHandlers_AssignProfileToDevice verifies the daemon REST
// assign endpoint binds the EK identity and prestages the EK certificate.
func TestTemplateHandlers_AssignProfileToDevice(t *testing.T) {
	router, profileSvc := newTestTemplateRouter()
	ekCert := newEKCertPEMForRESTTest(t)

	profileSvc.profiles[100] = &entities.DeviceProfile{ID: 100, Name: "assign-me"}

	rec := postTemplateJSON(t, router, "/api/v1/devices/profiles/100/assign", AssignProfileRequest{
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

// TestTemplateHandlers_AssignProfileToDevice_Errors verifies boundary
// validation on the daemon REST assign endpoint.
func TestTemplateHandlers_AssignProfileToDevice_Errors(t *testing.T) {
	router, profileSvc := newTestTemplateRouter()
	profileSvc.profiles[101] = &entities.DeviceProfile{ID: 101}

	t.Run("MissingIdentity", func(t *testing.T) {
		rec := postTemplateJSON(t, router, "/api/v1/devices/profiles/101/assign", AssignProfileRequest{})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("InvalidEKCert", func(t *testing.T) {
		rec := postTemplateJSON(t, router, "/api/v1/devices/profiles/101/assign", AssignProfileRequest{
			EKSerial: "EK-1",
			EKCert:   "not-a-pem",
		})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("InvalidProfileID", func(t *testing.T) {
		rec := postTemplateJSON(t, router, "/api/v1/devices/profiles/not-a-number/assign", AssignProfileRequest{
			EKSerial: "EK-1",
		})
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("UnknownProfile", func(t *testing.T) {
		rec := postTemplateJSON(t, router, "/api/v1/devices/profiles/999999/assign", AssignProfileRequest{
			EKSerial: "EK-1",
		})
		assert.NotEqual(t, http.StatusOK, rec.Code)
	})
}

// TestTemplateHandlers_UnassignProfileFromDevice verifies the daemon REST
// unassign endpoint clears the device binding, plus its error paths.
func TestTemplateHandlers_UnassignProfileFromDevice(t *testing.T) {
	router, profileSvc := newTestTemplateRouter()

	profileSvc.profiles[200] = &entities.DeviceProfile{
		ID:       200,
		EKSerial: "EK-2002",
		EKCert:   newEKCertPEMForRESTTest(t),
		Assigned: true,
	}

	rec := postTemplateJSON(t, router, "/api/v1/devices/profiles/200/unassign", nil)
	assert.Equal(t, http.StatusOK, rec.Code, rec.Body.String())

	stored := profileSvc.profiles[200]
	assert.False(t, stored.Assigned)
	assert.Empty(t, stored.EKSerial)
	assert.Empty(t, stored.EKCert)

	t.Run("InvalidProfileID", func(t *testing.T) {
		rec := postTemplateJSON(t, router, "/api/v1/devices/profiles/abc/unassign", nil)
		assert.Equal(t, http.StatusBadRequest, rec.Code)
	})

	t.Run("UnknownProfile", func(t *testing.T) {
		rec := postTemplateJSON(t, router, "/api/v1/devices/profiles/424242/unassign", nil)
		assert.NotEqual(t, http.StatusOK, rec.Code)
	})
}
