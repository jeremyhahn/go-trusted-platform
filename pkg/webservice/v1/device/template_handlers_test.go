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
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
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

// captureTemplateService records the template handed to Save so tests can
// assert what the handler mapped; the read paths are unused by these tests.
type captureTemplateService struct {
	device.DeviceTemplateService
	saved *entities.DeviceTemplate
}

func (c *captureTemplateService) Save(_ context.Context, template *entities.DeviceTemplate) error {
	c.saved = template
	return nil
}

func newTestTemplateCreateHandler() (*TemplateHandler, *captureTemplateService) {
	templateSvc := &captureTemplateService{}
	handler := &TemplateHandler{
		logger:          logging.DefaultLogger(),
		responseWriter:  &mockResponseWriter{},
		templateService: templateSvc,
	}
	return handler, templateSvc
}

func createTemplateRequest(t *testing.T, handler *TemplateHandler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/devices/templates", bytes.NewReader([]byte(body)))
	rec := httptest.NewRecorder()
	handler.CreateTemplate(rec, req)
	return rec
}

// TestTemplateHandler_CreateTemplate_SeederBodyIsNotInterpreted verifies the
// CRUD handler does not guess at the bootstrap seeder's {role, template}
// body: that contract belongs to the seeder router's route. Here `template`
// is decoded as the envelope it is declared to be, so the configuration
// document's keys are simply not template fields and nothing is stored under
// the role's deterministic id.
func TestTemplateHandler_CreateTemplate_SeederBodyIsNotInterpreted(t *testing.T) {
	handler, templateSvc := newTestTemplateCreateHandler()
	rec := createTemplateRequest(t, handler, `{"role":"worker","template":{"domain":"example.com","network":{}}}`)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	require.NotNil(t, templateSvc.saved)
	assert.NotEqual(t, util.NewID([]byte("worker")), templateSvc.saved.ID)
	assert.Empty(t, templateSvc.saved.Name)
	assert.Empty(t, templateSvc.saved.Config)
}

// TestTemplateHandler_CreateTemplate_Envelope verifies the JS SDK's
// {template: {...}} envelope still reaches the entity mapper.
func TestTemplateHandler_CreateTemplate_Envelope(t *testing.T) {
	handler, templateSvc := newTestTemplateCreateHandler()
	rec := createTemplateRequest(t, handler, `{"template":{"name":"gw-default","role":"gateway","description":"d"}}`)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	require.NotNil(t, templateSvc.saved)
	assert.NotZero(t, templateSvc.saved.ID)
	assert.Equal(t, "gw-default", templateSvc.saved.Name)
	assert.Equal(t, entities.DeviceRoleGateway, templateSvc.saved.Role)
	assert.Equal(t, "d", templateSvc.saved.Description)
}

// TestTemplateHandler_CreateTemplate_Flat verifies the legacy flat shape.
func TestTemplateHandler_CreateTemplate_Flat(t *testing.T) {
	handler, templateSvc := newTestTemplateCreateHandler()
	rec := createTemplateRequest(t, handler, `{"id":42,"name":"flat","role":"loadbalancer"}`)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	require.NotNil(t, templateSvc.saved)
	assert.Equal(t, uint64(42), templateSvc.saved.ID)
	assert.Equal(t, "flat", templateSvc.saved.Name)
	assert.Equal(t, entities.DeviceRoleLoadBalancer, templateSvc.saved.Role)
}

// TestTemplateHandler_CreateTemplate_UnknownRole verifies a role outside the
// vocabulary is a 400 on every accepted shape and nothing is saved.
func TestTemplateHandler_CreateTemplate_UnknownRole(t *testing.T) {
	bodies := map[string]string{
		"envelope": `{"template":{"name":"x","role":"compute"}}`,
		"flat":     `{"name":"x","role":"compute"}`,
	}
	for shape, body := range bodies {
		t.Run(shape, func(t *testing.T) {
			handler, templateSvc := newTestTemplateCreateHandler()
			rec := createTemplateRequest(t, handler, body)
			assert.Equal(t, http.StatusBadRequest, rec.Code)
			assert.Contains(t, rec.Body.String(), `unknown role \"compute\"`)
			assert.Nil(t, templateSvc.saved)
		})
	}
}

// TestTemplateHandler_CreateTemplate_MalformedEnvelope verifies a `template`
// that is not an object is a 400.
func TestTemplateHandler_CreateTemplate_MalformedEnvelope(t *testing.T) {
	handler, templateSvc := newTestTemplateCreateHandler()
	rec := createTemplateRequest(t, handler, `{"template":"not-an-object"}`)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Nil(t, templateSvc.saved)
}

// TestTemplateHandler_UpdateTemplate_UnknownRole verifies update applies the
// same vocabulary check as create.
func TestTemplateHandler_UpdateTemplate_UnknownRole(t *testing.T) {
	handler, templateSvc := newTestTemplateCreateHandler()
	req := httptest.NewRequest(http.MethodPut, "/devices/templates/7", bytes.NewReader([]byte(`{"name":"x","role":"master"}`)))
	req = mux.SetURLVars(req, map[string]string{"id": "7"})
	rec := httptest.NewRecorder()
	handler.UpdateTemplate(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Nil(t, templateSvc.saved)
}

// TestTemplateHandler_CreateProfileFromTemplate_UnknownRole verifies an
// override role outside the vocabulary is rejected before ToProfile runs.
func TestTemplateHandler_CreateProfileFromTemplate_UnknownRole(t *testing.T) {
	handler, profileSvc := newTestTemplateHandler()
	handler.templateService = &captureTemplateService{}
	req := httptest.NewRequest(http.MethodPost, "/devices/templates/7/create-profile",
		bytes.NewReader([]byte(`{"overrides":{"name":"n","role":"compute"}}`)))
	req = mux.SetURLVars(req, map[string]string{"id": "7"})
	rec := httptest.NewRecorder()
	handler.CreateProfileFromTemplate(rec, req)
	assert.Equal(t, http.StatusBadRequest, rec.Code)
	assert.Empty(t, profileSvc.profiles)
}
