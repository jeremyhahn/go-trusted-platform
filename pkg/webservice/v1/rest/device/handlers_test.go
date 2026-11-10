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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/store/datastore"
	"github.com/jeremyhahn/go-trusted-platform/pkg/util"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/restwire"
)

// mockTemplateService implements device.DeviceTemplateService for testing.
type mockTemplateService struct {
	saved           *entities.DeviceTemplate
	saveErr         error
	getResult       *entities.DeviceTemplate
	getErr          error
	profile         *entities.DeviceProfile
	toErr           error
	configOverrides map[string]interface{}
	overrides       *entities.DeviceProfile
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

func (m *mockTemplateService) ToProfile(_ context.Context, _ uint64, overrides *entities.DeviceProfile) (*entities.DeviceProfile, error) {
	m.overrides = overrides
	return m.profile, m.toErr
}

func (m *mockTemplateService) ToProfileWithConfigOverrides(_ context.Context, _ uint64, overrides *entities.DeviceProfile, configOverrides map[string]interface{}) (*entities.DeviceProfile, error) {
	m.overrides = overrides
	m.configOverrides = configOverrides
	return m.profile, m.toErr
}

// mockProfileService implements device.DeviceProfileService for testing.
type mockProfileService struct {
	saved           *entities.DeviceProfile
	saveErr         error
	findByMAC       *entities.DeviceProfile
	findByMACErr    error
	findBySerial    *entities.DeviceProfile
	findBySerialErr error
	findMatching    *entities.DeviceProfile
	findMatchingErr error
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

func (m *mockProfileService) Update(_ context.Context, _ *entities.DeviceProfile, _ ...device.ProfileUpdateOption) error {
	return nil
}

func (m *mockProfileService) Count(_ context.Context) (int, error) {
	return 0, nil
}

func (m *mockProfileService) Page(_ context.Context, _ datastore.PageQuery) (datastore.PageResult[*entities.DeviceProfile], error) {
	return datastore.PageResult[*entities.DeviceProfile]{}, nil
}

func (m *mockProfileService) FindByMACAddress(_ context.Context, _ string) (*entities.DeviceProfile, error) {
	return m.findByMAC, m.findByMACErr
}

func (m *mockProfileService) FindBySerial(_ context.Context, _ string) (*entities.DeviceProfile, error) {
	return m.findBySerial, m.findBySerialErr
}

func (m *mockProfileService) FindMatchingProfile(_ context.Context, _, _, _ string) (*entities.DeviceProfile, error) {
	return m.findMatching, m.findMatchingErr
}

func (m *mockProfileService) FindProfileForDevice(_ context.Context, _ *entities.Device) (*entities.DeviceProfile, error) {
	return m.findMatching, m.findMatchingErr
}

func (m *mockProfileService) AssignToDeviceWithEK(_ context.Context, _ uint64, _, _, _ string) error {
	return nil
}

func (m *mockProfileService) UnassignFromDevice(_ context.Context, _ uint64) error {
	return nil
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

	var resp restwire.WebServiceResponse
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

// TestHandleUploadTemplate_Errors verifies each rejected upload maps to its
// status: a bad request is a 400, a missing or failing service a 500.
func TestHandleUploadTemplate_Errors(t *testing.T) {
	tests := []struct {
		name    string
		tmplSvc device.DeviceTemplateService
		body    string
		want    int
	}{
		{"missing role", &mockTemplateService{}, `{"role":"","template":{"key":"value"}}`, http.StatusBadRequest},
		{"missing template", &mockTemplateService{}, `{"role":"server","template":null}`, http.StatusBadRequest},
		{"invalid JSON", &mockTemplateService{}, "not json", http.StatusBadRequest},
		{"save error", &mockTemplateService{saveErr: ErrTemplateSaveFailed{Cause: ErrMissingRole{}}}, `{"role":"server","template":{"key":"value"}}`, http.StatusInternalServerError},
		{"nil template service", nil, "{}", http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewDeviceTemplateHandlers(testLogger(), testResponseWriter(), tt.tmplSvc, nil)

			req := httptest.NewRequest(http.MethodPost, "/devices/templates", bytes.NewReader([]byte(tt.body)))
			req.Header.Set("Content-Type", "application/json")
			rr := httptest.NewRecorder()

			handler.HandleUploadTemplate(rr, req)

			assert.Equal(t, tt.want, rr.Code)
		})
	}
}

// TestHandleCreateProfile_Success verifies a profile is created from a template.
func TestHandleCreateProfile_Success(t *testing.T) {
	templateID := util.NewID([]byte("gateway"))
	profileID := util.NewID([]byte("node-01"))
	profile := &entities.DeviceProfile{
		ID:         profileID,
		Name:       "node-01",
		Role:       entities.DeviceRoleGateway,
		MatchRules: &entities.ProfileMatchRules{MACPrefix: "aa:bb:cc:dd:ee:ff"},
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

	// The body carries the created profile in the standard envelope with
	// the id as a JSON string — the shape the bootstrap seeder parses.
	assert.Equal(t, "application/json", rr.Header().Get("Content-Type"))
	var envelope struct {
		Code    int             `json:"code"`
		Success bool            `json:"success"`
		Payload profileResponse `json:"payload"`
	}
	require.NoError(t, json.Unmarshal(rr.Body.Bytes(), &envelope))
	assert.Equal(t, http.StatusCreated, envelope.Code)
	assert.True(t, envelope.Success)
	// envelope.Payload.ID is a devicewire.ID; compare the numeric value so a
	// failure reports a mismatched id rather than a mismatched type.
	assert.Equal(t, profileID, envelope.Payload.ID.Uint64())
	assert.Equal(t, "node-01", envelope.Payload.Name)
	assert.Equal(t, "gateway", envelope.Payload.Role)
	require.NotNil(t, envelope.Payload.MatchRules)
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", envelope.Payload.MatchRules.MACPrefix)
	assert.False(t, envelope.Payload.Assigned)
	assert.Contains(t, rr.Body.String(), `"id":"`+strconv.FormatUint(profileID, 10)+`"`)
}

// newTestEKCertPEM generates a self-signed certificate PEM for ek_cert tests.
func newTestEKCertPEM(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-ek"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	require.NoError(t, err)
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

func createProfileRequest(t *testing.T, templateID uint64, body profileRequest) *http.Request {
	t.Helper()
	payload, err := json.Marshal(body)
	require.NoError(t, err)
	id := strconv.FormatUint(templateID, 10)
	req := httptest.NewRequest(http.MethodPost, "/devices/templates/"+id+"/create-profile", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	return mux.SetURLVars(req, map[string]string{"id": id})
}

// TestHandleCreateProfile_MergedConfig verifies the seeder's merged config
// replaces the template-derived config on the saved profile.
func TestHandleCreateProfile_MergedConfig(t *testing.T) {
	templateID := util.NewID([]byte("control-plane"))
	profile := &entities.DeviceProfile{
		ID:     util.NewID([]byte("host-02")),
		Name:   "host-02",
		Config: map[string]interface{}{"os": map[string]interface{}{"hostname": "template-placeholder"}},
		PlatformdConfig: &entities.PlatformdConfigRef{
			ConfigType: "inline",
			Inline:     map[string]interface{}{"os": map[string]interface{}{"hostname": "template-placeholder"}},
		},
	}
	tmplSvc := &mockTemplateService{profile: profile}
	profSvc := &mockProfileService{}
	handler := NewDeviceTemplateHandlers(testLogger(), testResponseWriter(), tmplSvc, profSvc)

	rr := httptest.NewRecorder()
	handler.HandleCreateProfile(rr, createProfileRequest(t, templateID, profileRequest{
		MAC:      "00:25:90:00:02:aa",
		Hostname: "host-02",
		Role:     "control-plane",
		Config:   json.RawMessage(`{"os":{"hostname":"host-02"},"platform":{"domain":"example.com"}}`),
	}))

	assert.Equal(t, http.StatusCreated, rr.Code)
	require.NotNil(t, profSvc.saved)
	want := map[string]interface{}{
		"os":       map[string]interface{}{"hostname": "host-02"},
		"platform": map[string]interface{}{"domain": "example.com"},
	}
	assert.Equal(t, want, profSvc.saved.Config)
	require.NotNil(t, profSvc.saved.PlatformdConfig)
	assert.Equal(t, "inline", profSvc.saved.PlatformdConfig.ConfigType)
	assert.Equal(t, want, profSvc.saved.PlatformdConfig.Inline)
	assert.Empty(t, profSvc.saved.EKCert)
	assert.Nil(t, tmplSvc.configOverrides)
}

// TestHandleCreateProfile_MergedConfig_NoPlatformdConfig verifies the merged
// config is delivered even when the template produced no inline config ref.
func TestHandleCreateProfile_MergedConfig_NoPlatformdConfig(t *testing.T) {
	templateID := util.NewID([]byte("worker"))
	tmplSvc := &mockTemplateService{profile: &entities.DeviceProfile{ID: util.NewID([]byte("host-03")), Name: "host-03"}}
	profSvc := &mockProfileService{}
	handler := NewDeviceTemplateHandlers(testLogger(), testResponseWriter(), tmplSvc, profSvc)

	rr := httptest.NewRecorder()
	handler.HandleCreateProfile(rr, createProfileRequest(t, templateID, profileRequest{
		Hostname: "host-03",
		Config:   json.RawMessage(`{"os":{"hostname":"host-03"}}`),
	}))

	assert.Equal(t, http.StatusCreated, rr.Code)
	require.NotNil(t, profSvc.saved)
	require.NotNil(t, profSvc.saved.PlatformdConfig)
	assert.Equal(t, "inline", profSvc.saved.PlatformdConfig.ConfigType)
	assert.Equal(t, map[string]interface{}{"os": map[string]interface{}{"hostname": "host-03"}}, profSvc.saved.PlatformdConfig.Inline)
	assert.Empty(t, profSvc.saved.EKCert)
}

// TestHandleCreateProfile_InvalidConfig verifies a config that is not a JSON
// object is rejected with 400 before anything is saved.
func TestHandleCreateProfile_InvalidConfig(t *testing.T) {
	tmplSvc := &mockTemplateService{profile: &entities.DeviceProfile{ID: 1, Name: "host-02"}}
	profSvc := &mockProfileService{}
	handler := NewDeviceTemplateHandlers(testLogger(), testResponseWriter(), tmplSvc, profSvc)

	rr := httptest.NewRecorder()
	handler.HandleCreateProfile(rr, createProfileRequest(t, 1, profileRequest{
		Hostname: "host-02",
		Config:   json.RawMessage(`["not","an","object"]`),
	}))

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "profile config must be a JSON object")
	assert.Nil(t, profSvc.saved)
}

// TestHandleCreateProfile_NullConfig verifies an explicit "config": null is
// rejected with 400 rather than silently keeping the template-derived config.
func TestHandleCreateProfile_NullConfig(t *testing.T) {
	tmplSvc := &mockTemplateService{profile: &entities.DeviceProfile{ID: 1, Name: "host-02"}}
	profSvc := &mockProfileService{}
	handler := NewDeviceTemplateHandlers(testLogger(), testResponseWriter(), tmplSvc, profSvc)

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/devices/templates/1/create-profile",
		bytes.NewReader([]byte(`{"hostname":"host-02","config":null}`)))
	req.Header.Set("Content-Type", "application/json")
	handler.HandleCreateProfile(rr, mux.SetURLVars(req, map[string]string{"id": "1"}))

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), "config is null")
	assert.Nil(t, profSvc.saved)
}

// TestHandleCreateProfile_EKCertRefused verifies that even a well-formed
// ek_cert is refused with 400 on this unauthenticated route, before anything
// is saved, so a caller cannot prestage hardware identity here.
func TestHandleCreateProfile_EKCertRefused(t *testing.T) {
	tmplSvc := &mockTemplateService{profile: &entities.DeviceProfile{ID: 1, Name: "host-02"}}
	profSvc := &mockProfileService{}
	handler := NewDeviceTemplateHandlers(testLogger(), testResponseWriter(), tmplSvc, profSvc)

	for name, ekCert := range map[string]string{
		"valid PEM": newTestEKCertPEM(t),
		"not PEM":   "not a certificate",
	} {
		t.Run(name, func(t *testing.T) {
			rr := httptest.NewRecorder()
			handler.HandleCreateProfile(rr, createProfileRequest(t, 1, profileRequest{
				Hostname: "host-02",
				EKCert:   ekCert,
			}))

			assert.Equal(t, http.StatusBadRequest, rr.Code)
			assert.Contains(t, rr.Body.String(), "ek_cert is not accepted")
			assert.Nil(t, profSvc.saved)
		})
	}
}

// TestProfileToResponse_NoMatchRules verifies a profile without match rules
// maps to a payload that omits them rather than emitting an empty object.
func TestProfileToResponse_NoMatchRules(t *testing.T) {
	profile := &entities.DeviceProfile{
		ID:         42,
		Name:       "bare",
		Role:       entities.DeviceRoleServer,
		MACAddress: "aa:bb:cc:dd:ee:01",
		Assigned:   true,
	}

	resp := profileToResponse(profile)

	assert.Equal(t, uint64(42), resp.ID.Uint64())
	assert.Equal(t, "bare", resp.Name)
	assert.Equal(t, "server", resp.Role)
	assert.Equal(t, "aa:bb:cc:dd:ee:01", resp.MACAddress)
	assert.True(t, resp.Assigned)
	assert.Nil(t, resp.MatchRules)

	encoded, err := json.Marshal(resp)
	require.NoError(t, err)
	assert.NotContains(t, string(encoded), "match_rules")
	assert.Contains(t, string(encoded), `"id":"42"`)
}

// TestHandleCreateProfile_WithConfigOverrides verifies that config overrides
// from the request are passed through to ToProfileWithConfigOverrides.
func TestHandleCreateProfile_WithConfigOverrides(t *testing.T) {
	templateID := util.NewID([]byte("worker"))
	profile := &entities.DeviceProfile{
		ID:   util.NewID([]byte("host-03")),
		Name: "host-03",
		Role: entities.DeviceRoleServer,
		Config: map[string]interface{}{
			"hostname": "host-03",
			"domain":   "compute.example.com",
		},
	}
	tmplSvc := &mockTemplateService{profile: profile}
	profSvc := &mockProfileService{}
	handler := NewDeviceTemplateHandlers(testLogger(), testResponseWriter(), tmplSvc, profSvc)

	body := profileRequest{
		MAC:      "aa:bb:cc:dd:ee:ff",
		Hostname: "host-03",
		Role:     "worker",
		Overrides: map[string]interface{}{
			"hostname": "host-03",
			"os": map[string]interface{}{
				"hostname": "host-03",
			},
		},
	}
	payload, err := json.Marshal(body)
	require.NoError(t, err)

	req := httptest.NewRequest(http.MethodPost, "/devices/templates/"+strconv.FormatUint(templateID, 10)+"/create-profile", bytes.NewReader(payload))
	req.Header.Set("Content-Type", "application/json")
	req = mux.SetURLVars(req, map[string]string{"id": strconv.FormatUint(templateID, 10)})
	rr := httptest.NewRecorder()

	handler.HandleCreateProfile(rr, req)

	assert.Equal(t, http.StatusCreated, rr.Code)

	// Verify config overrides were passed to the service
	require.NotNil(t, tmplSvc.configOverrides)
	assert.Equal(t, "host-03", tmplSvc.configOverrides["hostname"])
	osOverrides, ok := tmplSvc.configOverrides["os"].(map[string]interface{})
	require.True(t, ok)
	assert.Equal(t, "host-03", osOverrides["hostname"])
}

// TestHandleCreateProfile_Errors verifies each rejected create-profile request
// maps to its status: a bad request is a 400, a missing or failing service a 500.
func TestHandleCreateProfile_Errors(t *testing.T) {
	tests := []struct {
		name    string
		id      string
		body    string
		tmplSvc device.DeviceTemplateService
		profSvc device.DeviceProfileService
		want    int
	}{
		{"missing hostname", "1", `{"mac":"aa:bb:cc:dd:ee:ff","role":"gateway"}`, &mockTemplateService{}, &mockProfileService{}, http.StatusBadRequest},
		{"invalid template id", "abc", "{}", &mockTemplateService{}, &mockProfileService{}, http.StatusBadRequest},
		{"invalid JSON", "1", "bad json", &mockTemplateService{}, &mockProfileService{}, http.StatusBadRequest},
		{"to profile error", "1", `{"hostname":"node-01","role":"gateway"}`, &mockTemplateService{toErr: ErrProfileCreateFailed{}}, &mockProfileService{}, http.StatusInternalServerError},
		{"nil template service", "123", "{}", nil, &mockProfileService{}, http.StatusInternalServerError},
		{"nil profile service", "123", "{}", &mockTemplateService{}, nil, http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewDeviceTemplateHandlers(testLogger(), testResponseWriter(), tt.tmplSvc, tt.profSvc)

			req := httptest.NewRequest(http.MethodPost, "/devices/templates/"+tt.id+"/create-profile", bytes.NewReader([]byte(tt.body)))
			req = mux.SetURLVars(req, map[string]string{"id": tt.id})
			rr := httptest.NewRecorder()

			handler.HandleCreateProfile(rr, req)

			assert.Equal(t, tt.want, rr.Code)
		})
	}
}

// TestHandleGetConfig_ByMAC verifies that a config is returned as raw YAML
// when looking up a profile by exact MAC address.
func TestHandleGetConfig_ByMAC(t *testing.T) {
	expectedConfig := map[string]interface{}{
		"hostname": "node-01",
		"network": map[string]interface{}{
			"interface": "eth0",
		},
	}
	profile := &entities.DeviceProfile{
		ID:     42,
		Name:   "node-01",
		Config: expectedConfig,
	}
	profSvc := &mockProfileService{findByMAC: profile}
	handler := NewDeviceTemplateHandlers(testLogger(), testResponseWriter(), nil, profSvc)

	req := httptest.NewRequest(http.MethodGet, "/devices/config?mac=aa:bb:cc:dd:ee:ff", nil)
	rr := httptest.NewRecorder()

	handler.HandleGetConfig(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/x-yaml", rr.Header().Get("Content-Type"))
	assert.Contains(t, rr.Body.String(), "hostname: node-01")
	assert.Contains(t, rr.Body.String(), "interface: eth0")
}

// TestHandleGetConfig_StoredNumbersArePlainYAML pins #125: a profile read from
// the store holds its numbers as json.Number. The delivered YAML carries each
// one unquoted with its digits unchanged, so an integer above 2^53 and a
// typed int field both decode on the device.
func TestHandleGetConfig_StoredNumbersArePlainYAML(t *testing.T) {
	profile := &entities.DeviceProfile{
		ID: 42,
		PlatformdConfig: &entities.PlatformdConfigRef{
			ConfigType: "inline",
			Inline: map[string]interface{}{
				"serial-id": json.Number("9007199254740993"),
				"ratio":     json.Number("1.5"),
				"vlans":     []interface{}{json.Number("-7"), json.Number("4094")},
			},
		},
	}
	profSvc := &mockProfileService{findByMAC: profile}
	handler := NewDeviceTemplateHandlers(testLogger(), testResponseWriter(), nil, profSvc)

	req := httptest.NewRequest(http.MethodGet, "/devices/config?mac=aa:bb:cc:dd:ee:ff", nil)
	rr := httptest.NewRecorder()

	handler.HandleGetConfig(rr, req)

	require.Equal(t, http.StatusOK, rr.Code)
	body := rr.Body.String()
	assert.Contains(t, body, "serial-id: 9007199254740993\n")
	assert.Contains(t, body, "ratio: 1.5\n")
	assert.Contains(t, body, "- -7\n")
	assert.Contains(t, body, "- 4094\n")
	assert.NotContains(t, body, `"`)
}

// TestHandleGetConfig_BySerial verifies that a config is returned when
// looking up a profile by serial number (MAC not found).
func TestHandleGetConfig_BySerial(t *testing.T) {
	expectedConfig := map[string]interface{}{
		"hostname": "node-02",
	}
	profile := &entities.DeviceProfile{
		ID:     43,
		Name:   "node-02",
		Config: expectedConfig,
	}
	profSvc := &mockProfileService{
		findBySerial: profile,
	}
	handler := NewDeviceTemplateHandlers(testLogger(), testResponseWriter(), nil, profSvc)

	req := httptest.NewRequest(http.MethodGet, "/devices/config?serial=SN12345", nil)
	rr := httptest.NewRecorder()

	handler.HandleGetConfig(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/x-yaml", rr.Header().Get("Content-Type"))
	assert.Contains(t, rr.Body.String(), "hostname: node-02")
}

// TestHandleGetConfig_ByMatchRules verifies fallback to match rules when
// exact MAC and serial lookups both fail.
func TestHandleGetConfig_ByMatchRules(t *testing.T) {
	expectedConfig := map[string]interface{}{
		"hostname": "node-03",
	}
	profile := &entities.DeviceProfile{
		ID:     44,
		Name:   "node-03",
		Config: expectedConfig,
	}
	profSvc := &mockProfileService{
		findMatching: profile,
	}
	handler := NewDeviceTemplateHandlers(testLogger(), testResponseWriter(), nil, profSvc)

	req := httptest.NewRequest(http.MethodGet, "/devices/config?mac=52:54:00:aa:bb:cc&serial=SN999", nil)
	rr := httptest.NewRecorder()

	handler.HandleGetConfig(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Equal(t, "application/x-yaml", rr.Header().Get("Content-Type"))
	assert.Contains(t, rr.Body.String(), "hostname: node-03")
}

// TestHandleGetConfig_Errors verifies each failed config lookup maps to its
// status: no identifier is a 400, no profile a 404, and a missing service or
// an undeliverable stored config a 500.
func TestHandleGetConfig_Errors(t *testing.T) {
	notFound := ErrProfileNotFound{MAC: "aa:bb:cc:dd:ee:ff"}
	tests := []struct {
		name    string
		url     string
		profSvc device.DeviceProfileService
		want    int
	}{
		{"missing query params", "/devices/config", &mockProfileService{}, http.StatusBadRequest},
		{"profile not found", "/devices/config?mac=aa:bb:cc:dd:ee:ff", &mockProfileService{findByMACErr: notFound, findMatchingErr: notFound}, http.StatusNotFound},
		{"nil profile service", "/devices/config?mac=aa:bb:cc:dd:ee:ff", nil, http.StatusInternalServerError},
		{"invalid stored number", "/devices/config?mac=aa:bb:cc:dd:ee:ff", &mockProfileService{findByMAC: &entities.DeviceProfile{
			ID:     42,
			Config: map[string]interface{}{"port": json.Number("not-a-number")},
		}}, http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			handler := NewDeviceTemplateHandlers(testLogger(), testResponseWriter(), nil, tt.profSvc)

			rr := httptest.NewRecorder()
			handler.HandleGetConfig(rr, httptest.NewRequest(http.MethodGet, tt.url, nil))

			assert.Equal(t, tt.want, rr.Code)
		})
	}
}

// TestHandleGetConfig_ProfileConfigEmpty verifies a 404 response when the
// matched profile has a nil Config field.
func TestHandleGetConfig_ProfileConfigEmpty(t *testing.T) {
	profile := &entities.DeviceProfile{
		ID:     45,
		Name:   "node-empty",
		Config: nil,
	}
	profSvc := &mockProfileService{findByMAC: profile}
	handler := NewDeviceTemplateHandlers(testLogger(), testResponseWriter(), nil, profSvc)

	req := httptest.NewRequest(http.MethodGet, "/devices/config?mac=aa:bb:cc:dd:ee:ff", nil)
	rr := httptest.NewRecorder()

	handler.HandleGetConfig(rr, req)

	assert.Equal(t, http.StatusNotFound, rr.Code)
	assert.Contains(t, rr.Body.String(), "no config")
}

// TestHandleGetConfig_MACTakesPriorityOverSerial verifies that when both mac
// and serial are provided, and MAC lookup succeeds, the serial lookup is skipped.
func TestHandleGetConfig_MACTakesPriorityOverSerial(t *testing.T) {
	macProfile := &entities.DeviceProfile{
		ID:     50,
		Name:   "mac-node",
		Config: map[string]interface{}{"source": "mac"},
	}
	serialProfile := &entities.DeviceProfile{
		ID:     51,
		Name:   "serial-node",
		Config: map[string]interface{}{"source": "serial"},
	}
	profSvc := &mockProfileService{
		findByMAC:    macProfile,
		findBySerial: serialProfile,
	}
	handler := NewDeviceTemplateHandlers(testLogger(), testResponseWriter(), nil, profSvc)

	req := httptest.NewRequest(http.MethodGet, "/devices/config?mac=aa:bb:cc:dd:ee:ff&serial=SN123", nil)
	rr := httptest.NewRecorder()

	handler.HandleGetConfig(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "source: mac")
}

// TestHandleGetConfig_SerialFallbackWhenMACFails verifies that serial lookup
// is used when MAC lookup returns an error.
func TestHandleGetConfig_SerialFallbackWhenMACFails(t *testing.T) {
	serialProfile := &entities.DeviceProfile{
		ID:     52,
		Name:   "serial-node",
		Config: map[string]interface{}{"source": "serial"},
	}
	profSvc := &mockProfileService{
		findByMACErr: ErrProfileNotFound{MAC: "aa:bb:cc:dd:ee:ff"},
		findBySerial: serialProfile,
	}
	handler := NewDeviceTemplateHandlers(testLogger(), testResponseWriter(), nil, profSvc)

	req := httptest.NewRequest(http.MethodGet, "/devices/config?mac=aa:bb:cc:dd:ee:ff&serial=SN123", nil)
	rr := httptest.NewRecorder()

	handler.HandleGetConfig(rr, req)

	assert.Equal(t, http.StatusOK, rr.Code)
	assert.Contains(t, rr.Body.String(), "source: serial")
}

// TestHandleUploadTemplate_SeederRoles verifies the three role strings the
// bootstrap seeder sends are stored as first-class roles with the name set.
func TestHandleUploadTemplate_SeederRoles(t *testing.T) {
	for _, role := range []string{"control-plane", "gateway", "worker"} {
		t.Run(role, func(t *testing.T) {
			tmplSvc := &mockTemplateService{}
			handler := NewDeviceTemplateHandlers(testLogger(), testResponseWriter(), tmplSvc, nil)

			payload := []byte(`{"role":"` + role + `","template":{"domain":"example.com"}}`)
			req := httptest.NewRequest(http.MethodPost, "/devices/templates", bytes.NewReader(payload))
			rr := httptest.NewRecorder()
			handler.HandleUploadTemplate(rr, req)

			require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
			require.NotNil(t, tmplSvc.saved)
			assert.Equal(t, util.NewID([]byte(role)), tmplSvc.saved.ID)
			assert.Equal(t, role, tmplSvc.saved.Name)
			assert.Equal(t, entities.DeviceRole(role), tmplSvc.saved.Role)
			assert.True(t, tmplSvc.saved.Role.IsValid())
		})
	}
}

// TestHandleUploadTemplate_UnknownRole verifies a role outside the vocabulary
// is a typed 400 and nothing is saved.
func TestHandleUploadTemplate_UnknownRole(t *testing.T) {
	tmplSvc := &mockTemplateService{}
	handler := NewDeviceTemplateHandlers(testLogger(), testResponseWriter(), tmplSvc, nil)

	payload := []byte(`{"role":"compute","template":{"domain":"example.com"}}`)
	req := httptest.NewRequest(http.MethodPost, "/devices/templates", bytes.NewReader(payload))
	rr := httptest.NewRecorder()
	handler.HandleUploadTemplate(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Contains(t, rr.Body.String(), `unknown role \"compute\"`)
	assert.Nil(t, tmplSvc.saved)
}

// TestHandleCreateProfile_UnknownRole verifies the profile role is checked
// against the vocabulary before the template is resolved.
func TestHandleCreateProfile_UnknownRole(t *testing.T) {
	tmplSvc := &mockTemplateService{profile: &entities.DeviceProfile{ID: 1, Name: "node-01"}}
	profSvc := &mockProfileService{}
	handler := NewDeviceTemplateHandlers(testLogger(), testResponseWriter(), tmplSvc, profSvc)

	payload := []byte(`{"hostname":"node-01","role":"compute"}`)
	req := httptest.NewRequest(http.MethodPost, "/devices/templates/1/create-profile", bytes.NewReader(payload))
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	rr := httptest.NewRecorder()
	handler.HandleCreateProfile(rr, req)

	assert.Equal(t, http.StatusBadRequest, rr.Code)
	assert.Nil(t, profSvc.saved)
}

// TestHandleCreateProfile_RoleOmittedInheritsTemplateRole verifies a request
// without a role does not override the template's role with "unknown".
func TestHandleCreateProfile_RoleOmittedInheritsTemplateRole(t *testing.T) {
	tmplSvc := &mockTemplateService{profile: &entities.DeviceProfile{ID: 1, Name: "node-01", Role: entities.DeviceRoleWorker}}
	profSvc := &mockProfileService{}
	handler := NewDeviceTemplateHandlers(testLogger(), testResponseWriter(), tmplSvc, profSvc)

	payload := []byte(`{"hostname":"node-01","mac":"aa:bb:cc:dd:ee:ff"}`)
	req := httptest.NewRequest(http.MethodPost, "/devices/templates/1/create-profile", bytes.NewReader(payload))
	req = mux.SetURLVars(req, map[string]string{"id": "1"})
	rr := httptest.NewRecorder()
	handler.HandleCreateProfile(rr, req)

	require.Equal(t, http.StatusCreated, rr.Code, rr.Body.String())
	require.NotNil(t, tmplSvc.overrides)
	assert.Empty(t, tmplSvc.overrides.Role, "an omitted role must not override the template role")
}

// TestHandleCreateProfile_VLANsNotDistinctIsClientError covers the last of
// the eight profile error-mapping sites #133 names. This route reported any
// save failure as 500 unconditionally, so a caller that described a profile
// with a shared provisioning and admitted VLAN was told the server had
// broken — and, being a 5xx, it is the class a client is entitled to retry.
//
// The wrapped case is the one that matters in production: the service layer
// is free to wrap on the way out, and a bare type assertion would stop
// matching the moment it did.
func TestHandleCreateProfile_VLANsNotDistinctIsClientError(t *testing.T) {
	tests := []struct {
		name    string
		saveErr error
		want    int
	}{
		{
			name:    "typed validation failure is a 400",
			saveErr: device.ErrProfileVLANsNotDistinct{VLAN: 200},
			want:    http.StatusBadRequest,
		},
		{
			name:    "wrapped validation failure is a 400",
			saveErr: &device.WrappedError{Msg: "failed to save profile", Err: device.ErrProfileVLANsNotDistinct{VLAN: 200}},
			want:    http.StatusBadRequest,
		},
		{
			name:    "an unrelated save failure stays a 500",
			saveErr: errors.New("storage write failed"),
			want:    http.StatusInternalServerError,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			templateID := util.NewID([]byte("gateway"))
			profile := &entities.DeviceProfile{
				ID:   util.NewID([]byte("node-01")),
				Name: "node-01",
				Role: entities.DeviceRoleGateway,
			}
			tmplSvc := &mockTemplateService{profile: profile}
			profSvc := &mockProfileService{saveErr: tt.saveErr}
			handler := NewDeviceTemplateHandlers(testLogger(), testResponseWriter(), tmplSvc, profSvc)

			payload, err := json.Marshal(profileRequest{
				MAC:      "aa:bb:cc:dd:ee:ff",
				Hostname: "node-01",
				Role:     "gateway",
			})
			require.NoError(t, err)

			req := httptest.NewRequest(http.MethodPost,
				"/devices/templates/"+strconv.FormatUint(templateID, 10)+"/create-profile",
				bytes.NewReader(payload))
			req.Header.Set("Content-Type", "application/json")
			req = mux.SetURLVars(req, map[string]string{"id": strconv.FormatUint(templateID, 10)})
			rr := httptest.NewRecorder()

			handler.HandleCreateProfile(rr, req)

			assert.Equal(t, tt.want, rr.Code)
		})
	}
}
