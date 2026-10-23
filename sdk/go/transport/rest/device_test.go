// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.

package rest

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// fullProfile is a DeviceProfile with every field ProfileRequest carries set.
func fullProfile() *platformv1.DeviceProfile {
	return &platformv1.DeviceProfile{
		Id:                    3,
		Name:                  "edge-node",
		Zone:                  "edge",
		Model:                 "r650",
		Role:                  platformv1.DeviceRole_DEVICE_ROLE_LOAD_BALANCER,
		EventLog:              []byte{0x01, 0x02},
		EkSerial:              "EK-1",
		MacAddress:            "aa:bb:cc:dd:ee:ff",
		Config:                []byte(`{"hostname":"edge-1"}`),
		TlsServerName:         "compute.example.internal",
		EnrollmentNetwork:     "provisioning",
		PostEnrollmentNetwork: "admitted",
		FailureNetwork:        "quarantine",
		PlatformdConfig:       &platformv1.PlatformdConfigRef{ConfigType: "reference", Reference: "base"},
		MatchRules:            &platformv1.ProfileMatchRules{MacPrefix: "aa:bb", Model: "r650"},
		Networks: map[string]*platformv1.NetworkPhaseConfig{
			"admitted": {
				Vlan:       100,
				AuthMethod: platformv1.AuthMethod_AUTH_METHOD_802_1X,
				Dns:        []string{"10.0.0.53"},
				Acls:       []*platformv1.ACLConfig{{Priority: 10, Protocol: "tcp", DstPort: 443, Action: "allow"}},
			},
		},
	}
}

func TestProfileRequestJSON_WritesTheFlatDomainShape(t *testing.T) {
	body, err := profileRequestJSON(fullProfile())
	require.NoError(t, err)

	encoded, err := json.Marshal(body)
	require.NoError(t, err)
	var got map[string]any
	require.NoError(t, json.Unmarshal(encoded, &got))

	require.NotContains(t, got, "profile", "the body must be flat")
	require.Equal(t, "edge-node", got["name"])
	require.Equal(t, "3", got["id"])
	require.Equal(t, "load-balancer", got["role"])
	require.Equal(t, map[string]any{"hostname": "edge-1"}, got["config"])
	require.Equal(t, "AQI=", got["event_log"])
	admitted := got["networks"].(map[string]any)["admitted"].(map[string]any)
	require.Equal(t, "802.1x", admitted["auth_method"])
	require.Equal(t, float64(100), admitted["vlan"])
	require.Equal(t, "aa:bb", got["match_rules"].(map[string]any)["mac_prefix"])
}

func TestProfileRequestJSON_OmitsUnspecifiedEnumsAndEmptyConfig(t *testing.T) {
	body, err := profileRequestJSON(&platformv1.DeviceProfile{
		Name:     "p",
		Networks: map[string]*platformv1.NetworkPhaseConfig{"lab": {Vlan: 5}},
	})
	require.NoError(t, err)
	require.NotContains(t, body, "role")
	require.NotContains(t, body, "config")
	require.NotContains(t, body["networks"].(map[string]any)["lab"], "auth_method")

	empty, err := profileRequestJSON(nil)
	require.NoError(t, err)
	require.Empty(t, empty)
}

func TestProfileRequestJSON_RejectsConfigThatIsNotJSON(t *testing.T) {
	_, err := profileRequestJSON(&platformv1.DeviceProfile{Config: []byte("hostname: edge-1")})
	require.ErrorIs(t, err, ErrProfileConfigNotJSON{})
}

func TestProfileBodyEncoder_RejectsARequestWithoutAProfile(t *testing.T) {
	encode := profileBodyEncoder(platformv1.DeviceService_UpdateProfile_FullMethodName)
	_, err := encode(&platformv1.GetProfileRequest{Id: 1})
	require.ErrorIs(t, err, ErrUnexpectedRequestType{Method: platformv1.DeviceService_UpdateProfile_FullMethodName})
}

func TestEncodeTemplateOverrides_NestsTheFlatProfile(t *testing.T) {
	body, err := encodeTemplateOverrides(&platformv1.CreateProfileFromTemplateRequest{
		Overrides: &platformv1.DeviceProfile{Name: "from-template", Role: platformv1.DeviceRole_DEVICE_ROLE_WORKER},
	})
	require.NoError(t, err)
	overrides := body.(map[string]any)["overrides"].(map[string]any)
	require.Equal(t, "from-template", overrides["name"])
	require.Equal(t, "worker", overrides["role"])

	body, err = encodeTemplateOverrides(&platformv1.CreateProfileFromTemplateRequest{TemplateId: 5})
	require.NoError(t, err)
	require.Empty(t, body)
}

func TestEncodeTemplateOverrides_RejectsBadInput(t *testing.T) {
	_, err := encodeTemplateOverrides(&platformv1.CreateProfileRequest{})
	require.ErrorIs(t, err, ErrUnexpectedRequestType{Method: platformv1.DeviceService_CreateProfileFromTemplate_FullMethodName})

	_, err = encodeTemplateOverrides(&platformv1.CreateProfileFromTemplateRequest{
		Overrides: &platformv1.DeviceProfile{Config: []byte("{")},
	})
	require.ErrorIs(t, err, ErrProfileConfigNotJSON{})
}

// TestProfileWrites_SendTheFlatBody drives each profile write through the
// adapter and checks the body the server receives is the flat
// ProfileRequest, with the path id left out of the update body.
func TestProfileWrites_SendTheFlatBody(t *testing.T) {
	var body map[string]any
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost && r.Method != http.MethodPut {
			w.WriteHeader(http.StatusOK)
			return
		}
		raw, err := io.ReadAll(r.Body)
		if err == nil {
			body = map[string]any{}
			err = json.Unmarshal(raw, &body)
		}
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"success":true,"payload":{"id":"3","name":"edge-node"}}`))
	})

	cases := map[string]struct {
		method string
		req    proto.Message
		resp   proto.Message
		flat   func(map[string]any) map[string]any
	}{
		"CreateProfile": {
			method: platformv1.DeviceService_CreateProfile_FullMethodName,
			req:    &platformv1.CreateProfileRequest{Profile: fullProfile()},
			resp:   &platformv1.CreateProfileResponse{},
			flat:   func(b map[string]any) map[string]any { return b },
		},
		"UpdateProfile": {
			method: platformv1.DeviceService_UpdateProfile_FullMethodName,
			req:    &platformv1.UpdateProfileRequest{Profile: fullProfile()},
			resp:   &platformv1.UpdateProfileResponse{},
			flat:   func(b map[string]any) map[string]any { return b },
		},
		"CreateProfileFromTemplate": {
			method: platformv1.DeviceService_CreateProfileFromTemplate_FullMethodName,
			req:    &platformv1.CreateProfileFromTemplateRequest{TemplateId: 5, Overrides: fullProfile()},
			resp:   &platformv1.CreateProfileResponse{},
			flat:   func(b map[string]any) map[string]any { return b["overrides"].(map[string]any) },
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			body = nil
			require.NoError(t, a.Connection().Invoke(context.Background(), tc.method, tc.req, tc.resp))
			require.NotContains(t, body, "profile")
			flat := tc.flat(body)
			require.Equal(t, "edge-node", flat["name"])
			require.Equal(t, "load-balancer", flat["role"])
			require.Equal(t, "edge-1", flat["config"].(map[string]any)["hostname"])
		})
	}
	require.NotContains(t, body, "template_id", "the template id travels in the path")
}

// TestProfileWrites_RejectConfigThatIsNotJSONBeforeTheWire covers the
// encoder error path through Invoke: InvalidArgument, and nothing is sent.
func TestProfileWrites_RejectConfigThatIsNotJSONBeforeTheWire(t *testing.T) {
	sent := false
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPost {
			sent = true
		}
		w.WriteHeader(http.StatusOK)
	})

	err := a.Connection().Invoke(context.Background(), platformv1.DeviceService_CreateProfile_FullMethodName,
		&platformv1.CreateProfileRequest{Profile: &platformv1.DeviceProfile{Name: "p", Config: []byte("not json")}},
		&platformv1.CreateProfileResponse{})
	require.Equal(t, codes.InvalidArgument, status.Code(err), "err: %v", err)
	require.False(t, sent, "a profile with non-JSON config reached the server")
}

func TestEncodeRequestBody_PassesUnencodedMethodsThrough(t *testing.T) {
	req := &platformv1.GetDeviceRequest{Id: 1}
	body, err := encodeRequestBody(platformv1.DeviceService_GetDevice_FullMethodName, req)
	require.NoError(t, err)
	require.Same(t, req, body)
}

func TestEncodeInvokeBody_ReportsEncoderFailureAsInvalidArgument(t *testing.T) {
	_, err := encodeInvokeBody(platformv1.DeviceService_UpdateProfile_FullMethodName, &platformv1.GetDeviceRequest{})
	require.Equal(t, codes.InvalidArgument, status.Code(err))
}

// TestDeviceReplies_NestTheBareDevice pins the P2 register failure: the
// server answers a bare device, and the reply must carry it under device.
func TestDeviceReplies_NestTheBareDevice(t *testing.T) {
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"code":201,"success":true,"payload":{` +
			`"id":"42","serial":"SN-1","model":"r650","state":"registered",` +
			`"created_at":"2026-10-12T09:00:00Z","last_heartbeat_addr":"10.0.0.9:443"}}`))
	})

	resp := &platformv1.CreateDeviceResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.DeviceService_CreateDevice_FullMethodName,
		&platformv1.CreateDeviceRequest{Device: &platformv1.Device{Serial: "SN-1"}}, resp)
	require.NoError(t, err)
	require.NotNil(t, resp.GetDevice())
	require.Equal(t, uint64(42), resp.GetDevice().GetId())
	require.Equal(t, "SN-1", resp.GetDevice().GetSerial())
	require.Equal(t, int64(1791795600), resp.GetDevice().GetCreatedAt().GetSeconds())
	require.True(t, resp.GetStatus().GetSuccess())

	get := &platformv1.GetDeviceResponse{}
	require.NoError(t, a.Connection().Invoke(context.Background(), platformv1.DeviceService_GetDevice_FullMethodName,
		&platformv1.GetDeviceRequest{Id: 42}, get))
	require.Equal(t, uint64(42), get.GetDevice().GetId())
}

func TestDeviceReplies_RejectMalformedPayloads(t *testing.T) {
	decode := resourceReplyDecoder(platformv1.DeviceService_CreateDevice_FullMethodName, "device", decodeDevice)

	err := decode([]byte(`{"id":"not-a-number"}`), &platformv1.CreateDeviceResponse{})
	require.True(t, errors.As(err, &ErrUnmarshalFailed{}), "err: %v", err)

	err = decode([]byte(`{"id":"1"}`), &platformv1.ListDevicesResponse{})
	require.ErrorIs(t, err, ErrUnexpectedReplyType{Method: platformv1.DeviceService_CreateDevice_FullMethodName})
}

// profileFullResponseJSON is a ProfileFullResponse as the webservice writes
// it: string id, domain role and auth method, config as JSON, hex PCR
// digests and a zero assigned_at.
const profileFullResponseJSON = `{
	"id": "18446744073709551615",
	"name": "edge-node",
	"role": "gateway",
	"networks": {"admitted": {"vlan": 100, "auth_method": "802.1x", "dhcp": true}},
	"platformd_config": {"config_type": "reference", "reference": "base"},
	"pcr_baseline": {"values": {"7": "a1b2"}, "source": "tofu",
		"recorded_at": "2026-10-12T09:00:00Z", "recorded_from_device_id": "42"},
	"config": {"hostname": "edge-1"},
	"assigned": false,
	"assigned_at": "0001-01-01T00:00:00Z",
	"tls_server_name": "compute.example.internal"
}`

func TestDecodeProfile_TranslatesTheWebserviceShape(t *testing.T) {
	msg, err := decodeProfile([]byte(profileFullResponseJSON))
	require.NoError(t, err)
	profile := msg.(*platformv1.DeviceProfile)

	require.Equal(t, uint64(18446744073709551615), profile.GetId())
	require.Equal(t, platformv1.DeviceRole_DEVICE_ROLE_GATEWAY, profile.GetRole())
	require.Equal(t, platformv1.AuthMethod_AUTH_METHOD_802_1X, profile.GetNetworks()["admitted"].GetAuthMethod())
	require.JSONEq(t, `{"hostname":"edge-1"}`, string(profile.GetConfig()))
	require.Nil(t, profile.GetAssignedAt())
	require.Equal(t, "base", profile.GetPlatformdConfig().GetReference())
	require.Equal(t, []byte{0xa1, 0xb2}, profile.GetPcrBaseline().GetValues()[7])
	require.Equal(t, uint64(42), profile.GetPcrBaseline().GetRecordedFromDeviceId())
	require.Equal(t, "compute.example.internal", profile.GetTlsServerName())
}

func TestDecodeProfile_RejectsMalformedPayloads(t *testing.T) {
	_, err := decodeProfile([]byte(`{"pcr_baseline":{"values":{"7":"zz"}}}`))
	var notHex ErrPCRDigestNotHex
	require.ErrorAs(t, err, &notHex)
	require.Equal(t, "7", notHex.Index)

	_, err = decodeProfile([]byte(`["not","an","object"]`))
	require.True(t, errors.As(err, &ErrUnmarshalFailed{}), "err: %v", err)
}

func TestProfileReplies_NestTheBareProfile(t *testing.T) {
	decode := resourceReplyDecoder(platformv1.DeviceService_UpdateProfile_FullMethodName, "profile", decodeProfile)
	resp := &platformv1.UpdateProfileResponse{}
	require.NoError(t, decode([]byte(profileFullResponseJSON), resp))
	require.Equal(t, "edge-node", resp.GetProfile().GetName())
	require.True(t, resp.GetStatus().GetSuccess())

	// A reply without a status field takes the profile alone.
	found := &platformv1.FindProfileBySerialResponse{}
	require.NoError(t, decode([]byte(profileFullResponseJSON), found))
	require.Equal(t, "edge-node", found.GetProfile().GetName())
}

func TestSetReplyResource_RejectsRepliesWithoutTheField(t *testing.T) {
	const method = "/platform.v1.DeviceService/Test"
	device := &platformv1.Device{Id: 1}

	cases := map[string]struct {
		reply interface{}
		field string
	}{
		"not a proto message":   {reply: &struct{}{}, field: "device"},
		"no such field":         {reply: &platformv1.CountDevicesResponse{}, field: "device"},
		"field of another type": {reply: &platformv1.CreateProfileResponse{}, field: "profile"},
		"repeated field":        {reply: &platformv1.ListDevicesResponse{}, field: "devices"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := setReplyResource(tc.reply, method, protoreflect.Name(tc.field), device)
			require.ErrorIs(t, err, ErrUnexpectedReplyType{Method: method})
		})
	}
}

func TestDecodeDeviceList_MapsPagination(t *testing.T) {
	out := &platformv1.ListDevicesResponse{}
	err := decodeDeviceList([]byte(`{"devices":[{"id":"1","serial":"SN-1","state":"active"}],`+
		`"pagination":{"page":2,"page_size":10,"total":11,"total_pages":2,"has_more":false}}`), out)
	require.NoError(t, err)
	require.Len(t, out.GetDevices(), 1)
	require.Equal(t, "SN-1", out.GetDevices()[0].GetSerial())
	require.Equal(t, uint64(11), out.GetPagination().GetTotalItems())
	require.Equal(t, uint32(2), out.GetPagination().GetPage())
}

func TestDecodeDeviceList_RejectsBadInput(t *testing.T) {
	err := decodeDeviceList([]byte(`{}`), &platformv1.ListProfilesResponse{})
	require.ErrorIs(t, err, ErrUnexpectedReplyType{Method: platformv1.DeviceService_ListDevices_FullMethodName})

	err = decodeDeviceList([]byte(`{"devices":`), &platformv1.ListDevicesResponse{})
	require.True(t, errors.As(err, &ErrUnmarshalFailed{}), "err: %v", err)
}

func TestDecodeProfileList_TranslatesEveryProfile(t *testing.T) {
	out := &platformv1.ListProfilesResponse{}
	err := decodeProfileList([]byte(`{"profiles":[`+profileFullResponseJSON+`],"pagination":{"total":1}}`), out)
	require.NoError(t, err)
	require.Len(t, out.GetProfiles(), 1)
	require.Equal(t, platformv1.DeviceRole_DEVICE_ROLE_GATEWAY, out.GetProfiles()[0].GetRole())
	require.Equal(t, uint64(1), out.GetPagination().GetTotalItems())
}

func TestDecodeProfileList_RejectsBadInput(t *testing.T) {
	err := decodeProfileList([]byte(`{}`), &platformv1.ListDevicesResponse{})
	require.ErrorIs(t, err, ErrUnexpectedReplyType{Method: platformv1.DeviceService_ListProfiles_FullMethodName})

	err = decodeProfileList([]byte(`{"profiles":[{"pcr_baseline":{"values":{"0":"x"}}}]}`), &platformv1.ListProfilesResponse{})
	require.ErrorAs(t, err, new(ErrPCRDigestNotHex))
}

func TestDecodeActivation_SeparatesStateFromStatus(t *testing.T) {
	out := &platformv1.ActivateDeviceResponse{}
	err := decodeActivation([]byte(`{"status":"active","vlan":200,"transitioned_at":"2026-10-12T09:00:00Z"}`), out)
	require.NoError(t, err)
	require.Equal(t, "active", out.GetActivationStatus())
	require.Equal(t, uint32(200), out.GetVlan())
	require.Equal(t, int64(1791795600), out.GetTransitionedAt().GetSeconds())
	require.True(t, out.GetStatus().GetSuccess())
}

func TestDecodeActivation_RejectsBadInput(t *testing.T) {
	err := decodeActivation([]byte(`{}`), &platformv1.ActivateDeviceRequest{})
	require.ErrorIs(t, err, ErrUnexpectedReplyType{Method: platformv1.DeviceService_ActivateDevice_FullMethodName})

	err = decodeActivation([]byte(`{"vlan":"many"}`), &platformv1.ActivateDeviceResponse{})
	require.True(t, errors.As(err, &ErrUnmarshalFailed{}), "err: %v", err)
}

func TestDecodeObject_TreatsNullAsEmptyAndKeepsLargeNumbers(t *testing.T) {
	obj := map[string]any{}
	require.NoError(t, decodeObject([]byte(`null`), &obj))
	require.NotNil(t, obj)
	require.Empty(t, obj)

	require.NoError(t, decodeObject([]byte(`{"id":18446744073709551615}`), &obj))
	require.Equal(t, json.Number("18446744073709551615"), obj["id"])
}

func TestDecodeObject_RejectsNonObjects(t *testing.T) {
	obj := map[string]any{}
	require.Error(t, decodeObject([]byte(`[1]`), &obj))
	require.Error(t, decodeObject([]byte(`{`), &obj))
}
