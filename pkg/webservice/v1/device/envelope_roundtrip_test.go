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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/device/entities"
)

// readBackThroughTheEnvelope writes sent the way every device handler
// answers (Success200 wraps it in {code, success, payload}) and decodes the
// payload into received, as a REST client does.
func readBackThroughTheEnvelope(t *testing.T, sent, received any) {
	t.Helper()
	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodGet, "/api/v1/devices", nil)
	newTestResponseWriter().Success200(recorder, request, sent)
	require.Equal(t, http.StatusOK, recorder.Code)

	var envelope struct {
		Payload json.RawMessage `json:"payload"`
	}
	require.NoError(t, json.Unmarshal(recorder.Body.Bytes(), &envelope))
	require.NotEmpty(t, envelope.Payload, "the answer must carry the object under payload")
	require.NoError(t, json.Unmarshal(envelope.Payload, received))
}

// TestProfileResponseSurvivesTheEnvelope: every profile field a client reads,
// networks included, comes back from the wire unchanged.
func TestProfileResponseSurvivesTheEnvelope(t *testing.T) {
	sent := &ProfileFullResponse{
		ID:                    7,
		Name:                  "edge-node",
		Zone:                  "edge",
		Model:                 "r650",
		Role:                  string(entities.DeviceRoleLoadBalancer),
		EKSerial:              "EK-1",
		MACAddress:            "aa:bb:cc:dd:ee:ff",
		TLSServerName:         "compute.example.internal",
		PostEnrollmentNetwork: "admitted",
		PlatformdConfig:       &PlatformdConfigResponse{ConfigType: "reference", Reference: "base"},
		MatchRules:            &MatchRulesResponse{MACPrefix: "aa:bb", Model: "r650"},
		Assigned:              true,
		Networks: map[string]*NetworkPhaseResponse{
			"admitted": {
				VLAN:       100,
				AuthMethod: string(entities.AuthMethod802_1X),
				DNS:        []string{"10.0.0.53"},
				DHCPPool:   &DHCPPoolResponse{Network: "10.0.0.0/24", LeaseTime: 3600},
				ACLs:       []ACLResponse{{Priority: 10, Protocol: "tcp", DstPort: 443, Action: "allow"}},
				Zone:       "edge-admitted",
			},
		},
	}

	var received ProfileFullResponse
	readBackThroughTheEnvelope(t, sent, &received)
	assert.Equal(t, sent, &received)
}

// TestTemplateResponseSurvivesTheEnvelope is the same contract for templates.
func TestTemplateResponseSurvivesTheEnvelope(t *testing.T) {
	sent := &TemplateResponse{
		ID:          41,
		Name:        "edge-template",
		Description: "edge nodes",
		Role:        string(entities.DeviceRoleEdge),
		MatchRules:  &MatchRulesResponse{SerialPrefix: "SN-"},
	}

	var received TemplateResponse
	readBackThroughTheEnvelope(t, sent, &received)
	assert.Equal(t, sent, &received)
}

// TestMalformedPayloadsDoNotDecode: a profile or template payload whose shape
// is not the object is refused rather than zeroed. A malformed device id is
// TestIDRejectsWhatIsNotAnUnsignedInteger's.
func TestMalformedPayloadsDoNotDecode(t *testing.T) {
	for name, tc := range map[string]struct {
		payload string
		into    any
	}{
		"profile is an array":   {`[]`, &ProfileFullResponse{}},
		"template id is a bool": {`{"id":true}`, &TemplateResponse{}},
	} {
		t.Run(name, func(t *testing.T) {
			assert.Error(t, json.Unmarshal([]byte(tc.payload), tc.into))
		})
	}
}
