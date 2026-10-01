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

// overridesCaptureService records the overrides entity the handler hands to
// ToProfile and returns it as the created profile, so a test can see both what
// the request mapped to and what the 201 then carries. The real merge is
// covered in pkg/device (TestTemplateService_ToProfile_*).
type overridesCaptureService struct {
	device.DeviceTemplateService
	overrides *entities.DeviceProfile
}

func (c *overridesCaptureService) ToProfile(_ context.Context, _ uint64, overrides *entities.DeviceProfile) (*entities.DeviceProfile, error) {
	c.overrides = overrides
	if overrides == nil {
		return &entities.DeviceProfile{ID: 42}, nil
	}
	profile := *overrides
	profile.ID = 42
	return &profile, nil
}

func createProfileFromTemplateRequest(t *testing.T, handler *TemplateHandler, body string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/device/templates/7/create-profile", bytes.NewReader([]byte(body)))
	req = mux.SetURLVars(req, map[string]string{"id": "7"})
	rec := httptest.NewRecorder()
	handler.CreateProfileFromTemplate(rec, req)
	return rec
}

// TestTemplateHandler_CreateProfileFromTemplate_OverridesRoundTrip is the
// #378 server-side fix: every override field the CRUD route honours survives
// request → entity → 201 on the template route too. Before this the handler
// mapped name/model/role only and answered 201 with the rest silently gone.
func TestTemplateHandler_CreateProfileFromTemplate_OverridesRoundTrip(t *testing.T) {
	handler, profileSvc := newTestTemplateHandler()
	templateSvc := &overridesCaptureService{}
	handler.templateService = templateSvc

	rec := createProfileFromTemplateRequest(t, handler, `{"overrides":{
		"name":"lab-worker","role":"worker","zone":"lab",
		"networks":{
			"provisioning":{"vlan":998,"dhcp":true},
			"lab-dmz":{"vlan":42,"static_ip":"10.42.0.7","gateway":"10.42.0.1","dns":["10.42.0.1"],
			           "auth_method":"802.1x","acls":[{"priority":100,"protocol":"tcp","dst_port":443,"action":"allow"}]}
		},
		"enrollment_network":"provisioning","post_enrollment_network":"lab-dmz","failure_network":"quarantine",
		"ek_serial":"EK-0001","mac_address":"52:54:00:aa:bb:cc",
		"platformd_config":{"config_type":"reference","reference":"/etc/platformd/worker.yaml"},
		"match_rules":{"mac_prefix":"52:54:00","serial_prefix":"LAB-"}
	}}`)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	// Request → entity: what ToProfile received.
	got := templateSvc.overrides
	require.NotNil(t, got)
	assert.Equal(t, "lab", got.Zone)
	assert.Equal(t, "EK-0001", got.EKSerial)
	assert.Equal(t, "52:54:00:aa:bb:cc", got.MACAddress)
	assert.Equal(t, "provisioning", got.EnrollmentNetwork)
	assert.Equal(t, "lab-dmz", got.PostEnrollmentNetwork)
	assert.Equal(t, "quarantine", got.FailureNetwork)
	require.Len(t, got.Networks, 2)
	require.NotNil(t, got.Networks["lab-dmz"])
	assert.Equal(t, uint16(42), got.Networks["lab-dmz"].VLAN)
	assert.Equal(t, "10.42.0.7", got.Networks["lab-dmz"].StaticIP)
	assert.Equal(t, entities.AuthMethod802_1X, got.Networks["lab-dmz"].AuthMethod)
	require.Len(t, got.Networks["lab-dmz"].ACLs, 1)
	assert.Equal(t, uint16(443), got.Networks["lab-dmz"].ACLs[0].DstPort)
	require.NotNil(t, got.PlatformdConfig)
	assert.Equal(t, "/etc/platformd/worker.yaml", got.PlatformdConfig.Reference)
	require.NotNil(t, got.MatchRules)
	assert.Equal(t, "LAB-", got.MatchRules.SerialPrefix)
	require.Len(t, profileSvc.profiles, 1)

	// Entity → 201: the operator sees what was stored, networks and selectors included.
	var resp ProfileFullResponse
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &resp))
	assert.Equal(t, uint64(42), resp.ID.Uint64())
	assert.Equal(t, "lab", resp.Zone)
	assert.Equal(t, "EK-0001", resp.EKSerial)
	assert.Equal(t, "52:54:00:aa:bb:cc", resp.MACAddress)
	assert.Equal(t, "lab-dmz", resp.PostEnrollmentNetwork)
	require.NotNil(t, resp.Networks["lab-dmz"])
	assert.Equal(t, "10.42.0.7", resp.Networks["lab-dmz"].StaticIP)
	assert.Equal(t, "802.1x", resp.Networks["lab-dmz"].AuthMethod)
	require.NotNil(t, resp.PlatformdConfig)
	assert.Equal(t, "reference", resp.PlatformdConfig.ConfigType)
	require.NotNil(t, resp.MatchRules)
	assert.Equal(t, "52:54:00", resp.MatchRules.MACPrefix)
}

// TestTemplateHandler_CreateProfileFromTemplate_MinimalOverrides is the
// negative: a body that names none of those fields yields zero values on the
// entity and omits them from the 201 — nothing is invented on the way through.
func TestTemplateHandler_CreateProfileFromTemplate_MinimalOverrides(t *testing.T) {
	handler, profileSvc := newTestTemplateHandler()
	templateSvc := &overridesCaptureService{}
	handler.templateService = templateSvc

	rec := createProfileFromTemplateRequest(t, handler, `{"overrides":{"name":"bare"}}`)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())

	got := templateSvc.overrides
	require.NotNil(t, got)
	assert.Equal(t, "bare", got.Name)
	assert.Empty(t, got.Zone)
	assert.Empty(t, got.EKSerial)
	assert.Empty(t, got.MACAddress)
	assert.Empty(t, got.EnrollmentNetwork)
	assert.Empty(t, got.PostEnrollmentNetwork)
	assert.Empty(t, got.FailureNetwork)
	assert.Empty(t, got.Networks)
	assert.Nil(t, got.PlatformdConfig)
	assert.Nil(t, got.MatchRules)
	require.Len(t, profileSvc.profiles, 1)

	var raw map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(rec.Body.Bytes(), &raw))
	for _, absent := range []string{"networks", "enrollment_network", "post_enrollment_network",
		"failure_network", "ek_serial", "mac_address", "platformd_config", "match_rules", "zone"} {
		_, present := raw[absent]
		assert.False(t, present, "%s should be omitted when unset", absent)
	}
	assert.Equal(t, `"bare"`, string(raw["name"]))
}

// TestTemplateHandler_CreateProfileFromTemplate_NoOverridesBody verifies an
// empty body still creates from the template alone: the shared mapper's nil
// guard hands ToProfile a nil overrides pointer, not a zero-valued profile.
func TestTemplateHandler_CreateProfileFromTemplate_NoOverridesBody(t *testing.T) {
	handler, profileSvc := newTestTemplateHandler()
	templateSvc := &overridesCaptureService{}
	handler.templateService = templateSvc

	rec := createProfileFromTemplateRequest(t, handler, `{}`)
	require.Equal(t, http.StatusCreated, rec.Code, rec.Body.String())
	assert.Nil(t, templateSvc.overrides)
	require.Len(t, profileSvc.profiles, 1)
}

// TestTemplateHandler_AssignProfileToDevice_ByDeviceID pins the live REST
// surface of assign-by-device (#463): the EK serial and prestaged
// certificate derive on the server from the registered device, explicit
// values win, and the failure shapes are typed.
func TestTemplateHandler_AssignProfileToDevice_ByDeviceID(t *testing.T) {
	handler, profiles := newTestTemplateHandler()
	devices := newMockDeviceService()
	handler.deviceService = devices
	certPEM := newEKCertPEMForWebserviceTest(t)
	devices.devices[1] = &entities.Device{ID: 1, EKCert: certPEM}
	devices.devices[2] = &entities.Device{ID: 2}
	profiles.profiles[100] = &entities.DeviceProfile{ID: 100, Name: "node-05"}

	rec := assignRequest(t, handler.AssignProfileToDevice, "100", map[string]interface{}{"device_id": "1"})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	wantSerial, err := entities.EKSerialFromCertPEM(certPEM)
	require.NoError(t, err)
	assert.Equal(t, wantSerial, profiles.profiles[100].EKSerial)
	assert.Equal(t, certPEM, profiles.profiles[100].EKCert)
	assert.True(t, profiles.profiles[100].Assigned)

	rec = assignRequest(t, handler.AssignProfileToDevice, "100", map[string]interface{}{"device_id": 1, "ek_serial": "EXPLICIT"})
	require.Equal(t, http.StatusOK, rec.Code, rec.Body.String())
	assert.Equal(t, "EXPLICIT", profiles.profiles[100].EKSerial, "an explicit serial wins over the derived one")

	t.Run("DeviceWithoutEKCert", func(t *testing.T) {
		profiles.profiles[101] = &entities.DeviceProfile{ID: 101, Name: "q"}
		rec := assignRequest(t, handler.AssignProfileToDevice, "101", map[string]interface{}{"device_id": 2})
		assert.Equal(t, http.StatusBadRequest, rec.Code, rec.Body.String())
		assert.False(t, profiles.profiles[101].Assigned)
	})
	t.Run("UnknownDevice", func(t *testing.T) {
		rec := assignRequest(t, handler.AssignProfileToDevice, "100", map[string]interface{}{"device_id": 404})
		assert.NotEqual(t, http.StatusOK, rec.Code)
	})
	t.Run("NoDeviceService", func(t *testing.T) {
		bare, bareProfiles := newTestTemplateHandler()
		bareProfiles.profiles[100] = &entities.DeviceProfile{ID: 100}
		rec := assignRequest(t, bare.AssignProfileToDevice, "100", map[string]interface{}{"device_id": 1})
		assert.Equal(t, http.StatusInternalServerError, rec.Code)
	})
}
