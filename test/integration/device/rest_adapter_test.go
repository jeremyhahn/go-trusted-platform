//go:build integration

package device

import (
	"errors"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	wsdevice "github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/device"
	"github.com/jeremyhahn/go-trusted-platform/pkg/webservice/v1/response"
)

// daemonBody renders payload the way the daemon's device handlers do: the
// webservice's own response writer wraps it in the envelope.
func daemonBody(t *testing.T, payload any) []byte {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil)
	response.NewResponseWriter(logging.NewLogger(slog.LevelError, nil), nil).Success200(recorder, request, payload)
	require.Equal(t, http.StatusOK, recorder.Code)
	return recorder.Body.Bytes()
}

func TestUnwrapPayload(t *testing.T) {
	payload, err := unwrapPayload("GET /api/v1/devices/3", daemonBody(t, &wsdevice.DeviceResponse{ID: 3, Serial: "SN-1"}))
	require.NoError(t, err)
	assert.JSONEq(t, `{"id":"3","serial":"SN-1"}`, string(payload))

	payload, err = unwrapPayload("DELETE /api/v1/devices/3", nil)
	require.NoError(t, err)
	assert.Nil(t, payload)
}

func TestUnwrapPayload_RejectsANonEnvelope(t *testing.T) {
	_, err := unwrapPayload("GET /api/v1/devices/3", []byte("404 page not found"))
	var adapterErr *RESTAdapterError
	require.True(t, errors.As(err, &adapterErr), "got %v", err)
	assert.Equal(t, "GET /api/v1/devices/3", adapterErr.Operation)
}

func TestDecodeDevice_AcceptsTheStringID(t *testing.T) {
	payload, err := unwrapPayload("GetDevice", daemonBody(t, &wsdevice.DeviceResponse{
		ID:     18446744073709551615,
		Serial: "SN-1",
		Model:  "r650",
	}))
	require.NoError(t, err)

	device, err := decodeDevice("GetDevice", payload)
	require.NoError(t, err)
	assert.Equal(t, uint64(18446744073709551615), device.ID)
	assert.Equal(t, "SN-1", device.Serial)
	assert.Equal(t, "r650", device.Model)

	// The CLI prints the same object with a numeric id; the shared type
	// still decodes it.
	device, err = decodeDevice("GetDevice", []byte(`{"id":3,"serial":"SN-1"}`))
	require.NoError(t, err)
	assert.Equal(t, uint64(3), device.ID)
}

func TestDecodeDevice_RejectsAMalformedPayload(t *testing.T) {
	_, err := decodeDevice("GetDevice", []byte(`{"id":"not-a-number"}`))
	var adapterErr *RESTAdapterError
	require.True(t, errors.As(err, &adapterErr), "got %v", err)
	assert.Equal(t, "GetDevice", adapterErr.Operation)
}

func TestDecodeProfile(t *testing.T) {
	payload, err := unwrapPayload("GetProfile", daemonBody(t, &wsdevice.ProfileFullResponse{
		ID:                    7,
		Name:                  "edge-node",
		Zone:                  "edge",
		Model:                 "r650",
		Role:                  string(entities.DeviceRoleLoadBalancer),
		EKSerial:              "EK-1",
		MACAddress:            "aa:bb:cc:dd:ee:ff",
		TLSServerName:         "compute.example.internal",
		PostEnrollmentNetwork: "admitted",
		PlatformdConfig:       &wsdevice.PlatformdConfigResponse{ConfigType: "reference", Reference: "base"},
		MatchRules:            &wsdevice.MatchRulesResponse{MACPrefix: "aa:bb", Model: "r650"},
		Assigned:              true,
		Networks: map[string]*wsdevice.NetworkPhaseResponse{
			"admitted": {
				VLAN:       100,
				AuthMethod: string(entities.AuthMethod802_1X),
				DNS:        []string{"10.0.0.53"},
				DHCPPool:   &wsdevice.DHCPPoolResponse{Network: "10.0.0.0/24", LeaseTime: 3600},
				ACLs:       []wsdevice.ACLResponse{{Priority: 10, Protocol: "tcp", DstPort: 443, Action: "allow"}},
				Zone:       "edge-admitted",
			},
		},
	}))
	require.NoError(t, err)

	profile, err := decodeProfile("GetProfile", payload)
	require.NoError(t, err)
	assert.Equal(t, uint64(7), profile.ID)
	assert.Equal(t, "edge-node", profile.Name)
	assert.Equal(t, "edge", profile.Zone)
	assert.Equal(t, entities.DeviceRoleLoadBalancer, profile.Role)
	assert.Equal(t, "EK-1", profile.EKSerial)
	assert.Equal(t, "aa:bb:cc:dd:ee:ff", profile.MACAddress)
	assert.Equal(t, "compute.example.internal", profile.TLSServerName)
	assert.Equal(t, "admitted", profile.PostEnrollmentNetwork)
	assert.True(t, profile.Assigned)
	require.NotNil(t, profile.PlatformdConfig)
	assert.Equal(t, "base", profile.PlatformdConfig.Reference)
	require.NotNil(t, profile.MatchRules)
	assert.Equal(t, "aa:bb", profile.MatchRules.MACPrefix)

	require.Contains(t, profile.Networks, "admitted")
	admitted := profile.Networks["admitted"]
	assert.Equal(t, uint16(100), admitted.VLAN)
	assert.Equal(t, entities.AuthMethod802_1X, admitted.AuthMethod)
	assert.Equal(t, []string{"10.0.0.53"}, admitted.DNS)
	assert.Equal(t, "edge-admitted", admitted.Zone)
	require.NotNil(t, admitted.DHCPPool)
	assert.Equal(t, 3600, admitted.DHCPPool.LeaseTime)
	require.Len(t, admitted.ACLs, 1)
	assert.Equal(t, uint16(443), admitted.ACLs[0].DstPort)
}

func TestDecodeProfile_RejectsAMalformedPayload(t *testing.T) {
	_, err := decodeProfile("GetProfile", []byte(`[]`))
	var adapterErr *RESTAdapterError
	require.True(t, errors.As(err, &adapterErr), "got %v", err)
	assert.Equal(t, "GetProfile", adapterErr.Operation)
}

func TestDecodeTemplate(t *testing.T) {
	payload, err := unwrapPayload("GetTemplate", daemonBody(t, &wsdevice.TemplateResponse{
		ID:          41,
		Name:        "edge-template",
		Description: "edge nodes",
		Role:        string(entities.DeviceRoleEdge),
		MatchRules:  &wsdevice.MatchRulesResponse{SerialPrefix: "SN-"},
	}))
	require.NoError(t, err)

	template, err := decodeTemplate("GetTemplate", payload)
	require.NoError(t, err)
	assert.Equal(t, uint64(41), template.ID)
	assert.Equal(t, "edge-template", template.Name)
	assert.Equal(t, "edge nodes", template.Description)
	assert.Equal(t, entities.DeviceRoleEdge, template.Role)
	require.NotNil(t, template.MatchRules)
	assert.Equal(t, "SN-", template.MatchRules.SerialPrefix)
}

func TestDecodeTemplate_RejectsAMalformedPayload(t *testing.T) {
	_, err := decodeTemplate("GetTemplate", []byte(`{"id":true}`))
	var adapterErr *RESTAdapterError
	require.True(t, errors.As(err, &adapterErr), "got %v", err)
	assert.Equal(t, "GetTemplate", adapterErr.Operation)
}

func TestNetworkPhaseEntity_NilPhase(t *testing.T) {
	assert.Nil(t, networkPhaseEntity(nil))
}
