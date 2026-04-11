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
	"strconv"
	"testing"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"log/slog"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// mockTemplateService implements device.DeviceTemplateService for testing.
type mockTemplateService struct {
	saved     *entities.DeviceTemplate
	saveErr   error
	getResult *entities.DeviceTemplate
	getErr    error
	profile   *entities.DeviceProfile
	toErr     error
}

func (m *mockTemplateService) Save(_ context.Context, t *entities.DeviceTemplate) error {
	m.saved = t
	return m.saveErr
}

func (m *mockTemplateService) Get(_ context.Context, id uint64) (*entities.DeviceTemplate, error) {
	return m.getResult, m.getErr
}

func (m *mockTemplateService) Delete(_ context.Context, _ *entities.DeviceTemplate) error {
	return nil
}

func (m *mockTemplateService) Update(_ context.Context, _ *entities.DeviceTemplate) error {
	return nil
}

func (m *mockTemplateService) Count(_ context.Context) (int, error) {
	return 0, nil
}

func (m *mockTemplateService) Page(_ context.Context, _ datastore.PageQuery) (datastore.PageResult[*entities.DeviceTemplate], error) {
	return datastore.PageResult[*entities.DeviceTemplate]{}, nil
}

func (m *mockTemplateService) FindByName(_ context.Context, _, _ string) (*entities.DeviceTemplate, error) {
	return nil, nil
}

func (m *mockTemplateService) ToProfile(_ context.Context, _ uint64, _ *entities.DeviceProfile) (*entities.DeviceProfile, error) {
	return m.profile, m.toErr
}

// mockProfileService implements device.DeviceProfileService for testing.
type mockProfileService struct {
	saved   *entities.DeviceProfile
	saveErr error
}

func (m *mockProfileService) Save(_ context.Context, p *entities.DeviceProfile) error {
	m.saved = p
	return m.saveErr
}

func (m *mockProfileService) Get(_ context.Context, _ uint64) (*entities.DeviceProfile, error) {
	return nil, nil
}

func (m *mockProfileService) Delete(_ context.Context, _ *entities.DeviceProfile) error {
	return nil
}

func (m *mockProfileService) Update(_ context.Context, _ *entities.DeviceProfile) error {
	return nil
}

func (m *mockProfileService) Count(_ context.Context) (int, error) {
	return 0, nil
}

func (m *mockProfileService) Page(_ context.Context, _ datastore.PageQuery) (datastore.PageResult[*entities.DeviceProfile], error) {
	return datastore.PageResult[*entities.DeviceProfile]{}, nil
}

func (m *mockProfileService) FindByMACAddress(_ context.Context, _ string) (*entities.DeviceProfile, error) {
	return nil, nil
}

func (m *mockProfileService) FindBySerial(_ context.Context, _ string) (*entities.DeviceProfile, error) {
	return nil, nil
}

func (m *mockProfileService) FindMatchingProfile(_ context.Context, _, _, _ string) (*entities.DeviceProfile, error) {
	return nil, nil
}

func testLogger() *logging.Logger {
	return logging.NewLogger(slog.LevelDebug, nil)
}

func testResponseWriter() response.HttpWriter {
	return response.NewResponseWriter(testLogger(), nil)
}

// TestHandleUploadTemplate_Success verifies a valid template upload request
// is saved and returns 201 with the template ID.
func TestHandleUploadTemplate_Success(t *testing.T) {
	tmplSvc := &mockTemplateService{}
	handler := NewDeviceTemplateHandlers(testLogger(), testResponseWriter(), tmplSvc, nil)

	body := templateRequest{
		Role:     "gateway",
		Template: json.RawMessage(`{"key":"value"}`),
	}
	payload, err := json.Marshal(body)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/devices/templates", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.HandleUploadTemplate(rr, req)

	assert.Equal(t, http.StatusCreated, rr.Code)

	var resp response.WebServiceResponse
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &resp))
	assert.True(t, resp.Success)

	// Verify the saved template has the expected fields.
	require.NotNil(t, tmplSvc.saved)
	expectedID := util.NewID([]byte("gateway"))
	assert.Equal(t, expectedID, tmplSvc.saved.ID)
	assert.Equal(t, "gateway", tmplSvc.saved.Name)
	assert.Equal(t, entities.DeviceRole("gateway"), tmplSvc.saved.Role)
	assert.Equal(t, json.RawMessage(`{"key":"value"}`), json.RawMessage(tmplSvc.saved.Config))
}

// TestHandleUploadTemplate_MissingRole verifies a 400 response when role is empty.
func TestHandleUploadTemplate_MissingRole(t *testing.T) {
	tmplSvc := &mockTemplateService{}
	handler := NewDeviceTemplateHandlers(testLogger(), testResponseWriter(), tmplSvc, nil)

	body := templateRequest{
		Role:     "",
		Template: json.RawMessage(`{"key":"value"}`),
	}
	payload, err := json.Marshal(body)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/devices/templates", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.HandleUploadTemplate(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestHandleUploadTemplate_MissingTemplate verifies a 400 response when template is empty.
func TestHandleUploadTemplate_MissingTemplate(t *testing.T) {
	tmplSvc := &mockTemplateService{}
	handler := NewDeviceTemplateHandlers(testLogger(), testResponseWriter(), tmplSvc, nil)

	body := templateRequest{
		Role:     "server",
		Template: nil,
	}
	payload, err := json.Marshal(body)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/devices/templates", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.HandleUploadTemplate(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestHandleUploadTemplate_InvalidJSON verifies a 400 response for malformed JSON.
func TestHandleUploadTemplate_InvalidJSON(t *testing.T) {
	tmplSvc := &mockTemplateService{}
	handler := NewDeviceTemplateHandlers(testLogger(), testResponseWriter(), tmplSvc, nil)

	req := httptest.NewRequest(http.MethodPost, "/devices/templates", bytes.NewReader([]byte("not json")))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.HandleUploadTemplate(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestHandleUploadTemplate_SaveError verifies a 500 response when template service Save fails.
func TestHandleUploadTemplate_SaveError(t *testing.T) {
	tmplSvc := &mockTemplateService{
		saveErr: ErrTemplateSaveFailed{Cause: ErrMissingRole{}},
	}
	handler := NewDeviceTemplateHandlers(testLogger(), testResponseWriter(), tmplSvc, nil)

	body := templateRequest{
		Role:     "server",
		Template: json.RawMessage(`{"key":"value"}`),
	}
	payload, err := json.Marshal(body)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/devices/templates", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()

	handler.HandleUploadTemplate(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

// TestHandleUploadTemplate_NilTemplateService verifies a 500 response when
// the template service is nil.
func TestHandleUploadTemplate_NilTemplateService(t *testing.T) {
	handler := NewDeviceTemplateHandlers(testLogger(), testResponseWriter(), nil, nil)

	req := httptest.NewRequest(http.MethodPost, "/devices/templates", bytes.NewReader([]byte("{}")))
	rr := httptest.NewRecorder()

	handler.HandleUploadTemplate(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

// TestHandleCreateProfile_Success verifies a profile is created from a template.
func TestHandleCreateProfile_Success(t *testing.T) {
	templateID := util.NewID([]byte("gateway"))
	profile := &entities.DeviceProfile{
		ID:   util.NewID([]byte("node-01")),
		Name: "node-01",
		Role: entities.DeviceRoleGateway,
	}
	tmplSvc := &mockTemplateService{profile: profile}
	profSvc := &mockProfileService{}
	handler := NewDeviceTemplateHandlers(testLogger(), testResponseWriter(), tmplSvc, profSvc)

	body := profileRequest{
		MAC:      "aa:bb:cc:dd:ee:ff",
		Hostname: "node-01",
		Role:     "gateway",
	}
	payload, err := json.Marshal(body)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/devices/templates/"+strconv.FormatUint(templateID, 10)+"/create-profile", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req = mux.SetURLVars(req, map[string]string{"id": strconv.FormatUint(templateID, 10)})
	rr := httptest.NewRecorder()

	handler.HandleCreateProfile(rr, req)

	assert.Equal(t, http.StatusCreated, rr.Code)
	require.NotNil(t, profSvc.saved)
	assert.Equal(t, "node-01", profSvc.saved.Name)
}

// TestHandleCreateProfile_MissingHostname verifies a 400 response when hostname is empty.
func TestHandleCreateProfile_MissingHostname(t *testing.T) {
	templateID := util.NewID([]byte("gateway"))
	tmplSvc := &mockTemplateService{}
	profSvc := &mockProfileService{}
	handler := NewDeviceTemplateHandlers(testLogger(), testResponseWriter(), tmplSvc, profSvc)

	body := profileRequest{
		MAC:  "aa:bb:cc:dd:ee:ff",
		Role: "gateway",
	}
	payload, err := json.Marshal(body)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/devices/templates/"+strconv.FormatUint(templateID, 10)+"/create-profile", bytes.NewReader(payload))
	req = mux.SetURLVars(req, map[string]string{"id": strconv.FormatUint(templateID, 10)})
	rr := httptest.NewRecorder()

	handler.HandleCreateProfile(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestHandleCreateProfile_InvalidTemplateID verifies a 400 response for non-numeric template ID.
func TestHandleCreateProfile_InvalidTemplateID(t *testing.T) {
	tmplSvc := &mockTemplateService{}
	profSvc := &mockProfileService{}
	handler := NewDeviceTemplateHandlers(testLogger(), testResponseWriter(), tmplSvc, profSvc)

	req := httptest.NewRequest(http.MethodPost, "/devices/templates/abc/create-profile", bytes.NewReader([]byte("{}")))
	req = mux.SetURLVars(req, map[string]string{"id": "abc"})
	rr := httptest.NewRecorder()

	handler.HandleCreateProfile(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}

// TestHandleCreateProfile_ToProfileError verifies a 500 response when ToProfile fails.
func TestHandleCreateProfile_ToProfileError(t *testing.T) {
	templateID := util.NewID([]byte("gateway"))
	tmplSvc := &mockTemplateService{toErr: ErrProfileCreateFailed{}}
	profSvc := &mockProfileService{}
	handler := NewDeviceTemplateHandlers(testLogger(), testResponseWriter(), tmplSvc, profSvc)

	body := profileRequest{
		Hostname: "node-01",
		Role:     "gateway",
	}
	payload, err := json.Marshal(body)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/devices/templates/"+strconv.FormatUint(templateID, 10)+"/create-profile", bytes.NewReader(payload))
	req = mux.SetURLVars(req, map[string]string{"id": strconv.FormatUint(templateID, 10)})
	rr := httptest.NewRecorder()

	handler.HandleCreateProfile(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

// TestHandleCreateProfile_SaveError verifies a 500 response when profile save fails.
func TestHandleCreateProfile_SaveError(t *testing.T) {
	templateID := util.NewID([]byte("gateway"))
	profile := &entities.DeviceProfile{
		ID:   util.NewID([]byte("node-01")),
		Name: "node-01",
	}
	tmplSvc := &mockTemplateService{profile: profile}
	profSvc := &mockProfileService{saveErr: ErrProfileSaveFailed{}}
	handler := NewDeviceTemplateHandlers(testLogger(), testResponseWriter(), tmplSvc, profSvc)

	body := profileRequest{
		Hostname: "node-01",
		Role:     "gateway",
	}
	payload, err := json.Marshal(body)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/devices/templates/"+strconv.FormatUint(templateID, 10)+"/create-profile", bytes.NewReader(payload))
	req = mux.SetURLVars(req, map[string]string{"id": strconv.FormatUint(templateID, 10)})
	rr := httptest.NewRecorder()

	handler.HandleCreateProfile(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

// TestHandleCreateProfile_NilTemplateService verifies a 500 response when template service is nil.
func TestHandleCreateProfile_NilTemplateService(t *testing.T) {
	handler := NewDeviceTemplateHandlers(testLogger(), testResponseWriter(), nil, &mockProfileService{})

	req := httptest.NewRequest(http.MethodPost, "/devices/templates/123/create-profile", bytes.NewReader([]byte("{}")))
	req = mux.SetURLVars(req, map[string]string{"id": "123"})
	rr := httptest.NewRecorder()

	handler.HandleCreateProfile(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

// TestHandleCreateProfile_NilProfileService verifies a 500 response when profile service is nil.
func TestHandleCreateProfile_NilProfileService(t *testing.T) {
	tmplSvc := &mockTemplateService{}
	handler := NewDeviceTemplateHandlers(testLogger(), testResponseWriter(), tmplSvc, nil)

	req := httptest.NewRequest(http.MethodPost, "/devices/templates/123/create-profile", bytes.NewReader([]byte("{}")))
	req = mux.SetURLVars(req, map[string]string{"id": "123"})
	rr := httptest.NewRecorder()

	handler.HandleCreateProfile(rr, req)

	assert.Equal(t, http.StatusInternalServerError, rr.Code)
}

// TestHandleCreateProfile_InvalidJSON verifies a 400 response for malformed JSON body.
func TestHandleCreateProfile_InvalidJSON(t *testing.T) {
	templateID := util.NewID([]byte("gateway"))
	tmplSvc := &mockTemplateService{}
	profSvc := &mockProfileService{}
	handler := NewDeviceTemplateHandlers(testLogger(), testResponseWriter(), tmplSvc, profSvc)

	req := httptest.NewRequest(http.MethodPost, "/devices/templates/"+strconv.FormatUint(templateID, 10)+"/create-profile", bytes.NewReader([]byte("bad json")))
	req = mux.SetURLVars(req, map[string]string{"id": strconv.FormatUint(templateID, 10)})
	rr := httptest.NewRecorder()

	handler.HandleCreateProfile(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
}
