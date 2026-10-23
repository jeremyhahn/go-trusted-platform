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
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// phase35Request is what the test server saw for one call.
type phase35Request struct {
	method string
	target string // path plus query
	body   map[string]interface{}
}

// invokeCapturing performs one Invoke against a server that records the
// request and answers with respBody.
func invokeCapturing(t *testing.T, method string, req, reply proto.Message, respBody string) (phase35Request, error) {
	t.Helper()
	var got phase35Request
	a, _ := adapterAgainst(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health/live" {
			return
		}
		got.method = r.Method
		got.target = r.URL.RequestURI()
		raw, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(raw, &got.body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(respBody))
	})
	err := a.Connection().Invoke(context.Background(), method, req, reply)
	return got, err
}

// phase35Routes is every ceremony, PIV and FIDO2 method with the verb and URL
// the daemon serves it on (pkg/api/daemon/{ceremony,piv,fido2}_rest.go).
var phase35Routes = []struct {
	method string
	req    proto.Message
	reply  proto.Message
	verb   string
	target string
}{
	{"/platform.v1.CeremonyService/Init", &platformv1.CeremonyInitRequest{}, &platformv1.CeremonyInitResponse{}, "POST", "/api/v1/ceremony/init"},
	{"/platform.v1.CeremonyService/Status", &platformv1.CeremonyStatusRequest{}, &platformv1.CeremonyStatusResponse{}, "GET", "/api/v1/ceremony/status"},
	{"/platform.v1.CeremonyService/ClaimCertBegin", &platformv1.CeremonyClaimCertBeginRequest{}, &platformv1.CeremonyClaimCertBeginResponse{}, "POST", "/api/v1/ceremony/claim-cert/begin"},
	{"/platform.v1.CeremonyService/ClaimCertComplete", &platformv1.CeremonyClaimCertCompleteRequest{}, &platformv1.CeremonyClaimCertCompleteResponse{}, "POST", "/api/v1/ceremony/claim-cert/complete"},
	{"/platform.v1.CeremonyService/ClaimShareBegin", &platformv1.CeremonyClaimShareBeginRequest{}, &platformv1.CeremonyClaimShareBeginResponse{}, "POST", "/api/v1/ceremony/claim-share/begin"},
	{"/platform.v1.CeremonyService/ClaimShareComplete", &platformv1.CeremonyClaimShareCompleteRequest{}, &platformv1.CeremonyClaimShareCompleteResponse{}, "POST", "/api/v1/ceremony/claim-share/complete"},
	{"/platform.v1.CeremonyService/SignCSR", &platformv1.CeremonySignCSRRequest{}, &platformv1.CeremonySignCSRResponse{}, "POST", "/api/v1/ceremony/sign-csr"},

	{"/platform.v1.PIVService/ListDevices", &platformv1.PIVListDevicesRequest{}, &platformv1.PIVListDevicesResponse{}, "GET", "/api/v1/piv/devices"},
	{"/platform.v1.PIVService/ListSlots", &platformv1.PIVListSlotsRequest{Device: "yk5"}, &platformv1.PIVListSlotsResponse{}, "GET", "/api/v1/piv/devices/yk5/slots"},
	{"/platform.v1.PIVService/SlotInfo", &platformv1.PIVSlotInfoRequest{Slot: "9a", Device: "yk5"}, &platformv1.PIVSlotInfoResponse{}, "GET", "/api/v1/piv/slots/9a?device=yk5"},
	{"/platform.v1.PIVService/Generate", &platformv1.PIVGenerateRequest{Slot: "9a"}, &platformv1.PIVGenerateResponse{}, "POST", "/api/v1/piv/slots/9a/generate"},
	{"/platform.v1.PIVService/Import", &platformv1.PIVImportRequest{Slot: "9a"}, &platformv1.PIVImportResponse{}, "POST", "/api/v1/piv/slots/9a/import"},
	{"/platform.v1.PIVService/Sign", &platformv1.PIVSignRequest{Slot: "9a"}, &platformv1.PIVSignResponse{}, "POST", "/api/v1/piv/slots/9a/sign"},
	{"/platform.v1.PIVService/Attest", &platformv1.PIVAttestRequest{Slot: "9a"}, &platformv1.PIVAttestResponse{}, "POST", "/api/v1/piv/slots/9a/attest"},
	{"/platform.v1.PIVService/Reset", &platformv1.PIVResetRequest{Device: "yk5"}, &platformv1.PIVResetResponse{}, "POST", "/api/v1/piv/devices/yk5/reset"},

	{"/platform.v1.FIDO2Service/ListDevices", &platformv1.FIDO2ListDevicesRequest{}, &platformv1.FIDO2ListDevicesResponse{}, "GET", "/api/v1/fido2/devices"},
	{"/platform.v1.FIDO2Service/WaitDevice", &platformv1.FIDO2WaitDeviceRequest{TimeoutSeconds: 5}, &platformv1.FIDO2WaitDeviceResponse{}, "GET", "/api/v1/fido2/devices/wait?timeout_seconds=5"},
	{"/platform.v1.FIDO2Service/Info", &platformv1.FIDO2InfoRequest{Device: "k1"}, &platformv1.FIDO2InfoResponse{}, "GET", "/api/v1/fido2/devices/k1"},
	{"/platform.v1.FIDO2Service/Register", &platformv1.FIDO2RegisterRequest{Username: "alice"}, &platformv1.FIDO2RegisterResponse{}, "POST", "/api/v1/fido2/register"},
	{"/platform.v1.FIDO2Service/Authenticate", &platformv1.FIDO2AuthenticateRequest{CredentialId: "c1"}, &platformv1.FIDO2AuthenticateResponse{}, "POST", "/api/v1/fido2/authenticate"},
}

// TestPhase35REST_EveryMethodUsesTheServerRoute drives each method through
// the adapter and asserts the verb and URL the daemon registers. The reply
// body is `{}`, which every decoder accepts.
func TestPhase35REST_EveryMethodUsesTheServerRoute(t *testing.T) {
	for _, tc := range phase35Routes {
		t.Run(tc.method, func(t *testing.T) {
			got, err := invokeCapturing(t, tc.method, tc.req, tc.reply, `{}`)
			if err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			if got.method != tc.verb || got.target != tc.target {
				t.Errorf("sent %s %s, want %s %s", got.method, got.target, tc.verb, tc.target)
			}
		})
	}
}

// TestPhase35REST_NoUnexpectedMethodsRouted fails when one of the three
// services gains a route the table above does not cover.
func TestPhase35REST_NoUnexpectedMethodsRouted(t *testing.T) {
	listed := map[string]bool{}
	for _, tc := range phase35Routes {
		listed[tc.method] = true
	}
	prefixes := []string{"/platform.v1.CeremonyService/", "/platform.v1.PIVService/", "/platform.v1.FIDO2Service/"}
	check := func(method string) {
		for _, prefix := range prefixes {
			if strings.HasPrefix(method, prefix) && !listed[method] {
				t.Errorf("%s is routed but not covered by the table", method)
			}
		}
	}
	for method := range templatedRouteTable {
		check(method)
	}
	for method := range grpcMethodToRESTMap {
		check(method)
	}
}

func TestPhase35REST_TemplatedRoutesRefuseMissingIdentifiers(t *testing.T) {
	for _, tc := range []struct {
		method string
		req    proto.Message
	}{
		{"/platform.v1.PIVService/ListSlots", &platformv1.PIVListSlotsRequest{}},
		{"/platform.v1.PIVService/SlotInfo", &platformv1.PIVSlotInfoRequest{Device: "yk5"}},
		{"/platform.v1.PIVService/Sign", &platformv1.PIVSignRequest{}},
		{"/platform.v1.PIVService/Reset", &platformv1.PIVResetRequest{}},
		{"/platform.v1.FIDO2Service/Info", &platformv1.FIDO2InfoRequest{}},
	} {
		t.Run(tc.method, func(t *testing.T) {
			got, err := invokeCapturing(t, tc.method, tc.req, nil, `{}`)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("err = %v, want InvalidArgument", err)
			}
			if got.method != "" {
				t.Errorf("request was sent: %+v", got)
			}
		})
	}
}

func TestPhase35REST_EnumsGoOutAsWireStrings(t *testing.T) {
	for _, tc := range []struct {
		name   string
		method string
		req    proto.Message
		reply  proto.Message
		want   map[string]interface{}
	}{
		{
			"ceremony authenticator", "/platform.v1.CeremonyService/ClaimCertBegin",
			&platformv1.CeremonyClaimCertBeginRequest{
				Username: "alice", Slot: "9a", CredentialId: "c",
				AuthenticatorType: platformv1.CeremonyAuthenticatorType_CEREMONY_AUTHENTICATOR_TYPE_PIV,
			},
			&platformv1.CeremonyClaimCertBeginResponse{},
			map[string]interface{}{"username": "alice", "authenticator_type": "piv", "slot": "9a", "credential_id": "c"},
		},
		{
			"ceremony role", "/platform.v1.CeremonyService/SignCSR",
			&platformv1.CeremonySignCSRRequest{
				Username: "alice", SoPin: "so", CsrPem: "csr",
				Role: platformv1.CeremonyOfficerRole_CEREMONY_OFFICER_ROLE_ADMIN,
			},
			&platformv1.CeremonySignCSRResponse{},
			map[string]interface{}{"username": "alice", "so_pin": "so", "csr_pem": "csr", "role": "admin"},
		},
		{
			"piv algorithm", "/platform.v1.PIVService/Generate",
			&platformv1.PIVGenerateRequest{Slot: "9a", Pin: "123456", Algorithm: platformv1.PIVAlgorithm_PIV_ALGORITHM_ECDSA},
			&platformv1.PIVGenerateResponse{},
			map[string]interface{}{"algorithm": "ecdsa", "pin": "123456"},
		},
		{
			"fido2 role", "/platform.v1.FIDO2Service/Register",
			&platformv1.FIDO2RegisterRequest{
				Username: "alice", Role: platformv1.FIDO2Role_FIDO2_ROLE_SO, RequirePin: true, RpId: "rp",
			},
			&platformv1.FIDO2RegisterResponse{},
			map[string]interface{}{"username": "alice", "role": "so", "require_pin": true, "require_uv": false, "rp_id": "rp"},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := invokeCapturing(t, tc.method, tc.req, tc.reply, `{}`)
			if err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			if len(got.body) != len(tc.want) {
				t.Errorf("body = %v, want %v", got.body, tc.want)
			}
			for k, v := range tc.want {
				if got.body[k] != v {
					t.Errorf("body[%q] = %v, want %v (body %v)", k, got.body[k], v, got.body)
				}
			}
		})
	}
}

func TestPhase35REST_UnknownEnumRefusedBeforeSend(t *testing.T) {
	for _, tc := range []struct {
		method string
		req    proto.Message
	}{
		{"/platform.v1.CeremonyService/ClaimCertBegin", &platformv1.CeremonyClaimCertBeginRequest{AuthenticatorType: 99}},
		{"/platform.v1.CeremonyService/SignCSR", &platformv1.CeremonySignCSRRequest{Role: 99}},
		{"/platform.v1.PIVService/Generate", &platformv1.PIVGenerateRequest{Slot: "9a", Algorithm: 99}},
		{"/platform.v1.FIDO2Service/Register", &platformv1.FIDO2RegisterRequest{Role: 99}},
	} {
		t.Run(tc.method, func(t *testing.T) {
			got, err := invokeCapturing(t, tc.method, tc.req, nil, `{}`)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("err = %v, want InvalidArgument", err)
			}
			if got.method != "" {
				t.Errorf("request was sent: %+v", got)
			}
		})
	}
}

func TestPhase35REST_BytesTravelAsBase64(t *testing.T) {
	got, err := invokeCapturing(t, "/platform.v1.PIVService/Sign",
		&platformv1.PIVSignRequest{Slot: "9a", Payload: []byte("hello"), Pin: "1"},
		&platformv1.PIVSignResponse{}, `{}`)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if got.body["payload"] != base64.StdEncoding.EncodeToString([]byte("hello")) {
		t.Errorf("payload = %v", got.body["payload"])
	}
	if _, echoed := got.body["slot"]; echoed {
		t.Errorf("slot is in the URL and must not be in the body: %v", got.body)
	}
}

func TestPhase35REST_DecodesDaemonJSON(t *testing.T) {
	t.Run("ceremony status", func(t *testing.T) {
		reply := &platformv1.CeremonyStatusResponse{}
		_, err := invokeCapturing(t, "/platform.v1.CeremonyService/Status", &platformv1.CeremonyStatusRequest{}, reply,
			`{"ceremony_id":"c-1","state":"complete","threshold":"2-of-3","officers_enrolled":3,"officers_required":3,"initialized_at":"2026-01-02T03:04:05Z"}`)
		if err != nil {
			t.Fatalf("Invoke: %v", err)
		}
		if reply.GetState() != platformv1.CeremonyState_CEREMONY_STATE_COMPLETE || reply.GetOfficersEnrolled() != 3 ||
			reply.GetInitializedAt().AsTime().Year() != 2026 {
			t.Errorf("reply = %+v", reply)
		}
	})
	t.Run("ceremony unknown state", func(t *testing.T) {
		_, err := invokeCapturing(t, "/platform.v1.CeremonyService/Status", &platformv1.CeremonyStatusRequest{},
			&platformv1.CeremonyStatusResponse{}, `{"state":"bogus"}`)
		if status.Code(err) != codes.Internal {
			t.Errorf("err = %v, want Internal", err)
		}
	})
	t.Run("piv slot info", func(t *testing.T) {
		reply := &platformv1.PIVSlotInfoResponse{}
		_, err := invokeCapturing(t, "/platform.v1.PIVService/SlotInfo", &platformv1.PIVSlotInfoRequest{Slot: "9a"}, reply,
			`{"Slot":{"ID":"9a","Algorithm":"ed25519","HasKey":true},"PublicKeyPEM":"PUB"}`)
		if err != nil {
			t.Fatalf("Invoke: %v", err)
		}
		if reply.GetSlot().GetAlgorithm() != platformv1.PIVAlgorithm_PIV_ALGORITHM_ED25519 || reply.GetPublicKeyPem() != "PUB" {
			t.Errorf("reply = %+v", reply)
		}
	})
	t.Run("piv list slots unknown algorithm", func(t *testing.T) {
		_, err := invokeCapturing(t, "/platform.v1.PIVService/ListSlots", &platformv1.PIVListSlotsRequest{Device: "d"},
			&platformv1.PIVListSlotsResponse{}, `{"slots":[{"ID":"9a","Algorithm":"dsa"}]}`)
		if status.Code(err) != codes.Internal {
			t.Errorf("err = %v, want Internal", err)
		}
	})
	t.Run("piv sign signature", func(t *testing.T) {
		reply := &platformv1.PIVSignResponse{}
		_, err := invokeCapturing(t, "/platform.v1.PIVService/Sign", &platformv1.PIVSignRequest{Slot: "9a"}, reply,
			`{"signature":"`+base64.StdEncoding.EncodeToString([]byte{1, 2, 3})+`"}`)
		if err != nil || string(reply.GetSignature()) != string([]byte{1, 2, 3}) {
			t.Errorf("err=%v reply=%+v", err, reply)
		}
	})
	t.Run("piv reset", func(t *testing.T) {
		reply := &platformv1.PIVResetResponse{}
		_, err := invokeCapturing(t, "/platform.v1.PIVService/Reset", &platformv1.PIVResetRequest{Device: "d"}, reply, `{"reset":true}`)
		if err != nil || !reply.GetReset_() {
			t.Errorf("err=%v reply=%+v", err, reply)
		}
	})
	t.Run("fido2 info", func(t *testing.T) {
		reply := &platformv1.FIDO2InfoResponse{}
		_, err := invokeCapturing(t, "/platform.v1.FIDO2Service/Info", &platformv1.FIDO2InfoRequest{Device: "k1"}, reply,
			`{"Device":{"ID":"k1","Path":"/dev/hidraw0"},"AAGUID":"aa","MaxMsgSize":1200,"Options":{"clientPin":true}}`)
		if err != nil {
			t.Fatalf("Invoke: %v", err)
		}
		if reply.GetInfo().GetDevice().GetPath() != "/dev/hidraw0" || reply.GetInfo().GetAaguid() != "aa" ||
			!reply.GetInfo().GetOptions()["clientPin"] {
			t.Errorf("reply = %+v", reply)
		}
	})
	t.Run("fido2 authenticate", func(t *testing.T) {
		reply := &platformv1.FIDO2AuthenticateResponse{}
		_, err := invokeCapturing(t, "/platform.v1.FIDO2Service/Authenticate", &platformv1.FIDO2AuthenticateRequest{CredentialId: "c"},
			reply, `{"Authenticated":true,"Counter":7}`)
		if err != nil || !reply.GetAuthenticated() || reply.GetCounter() != 7 {
			t.Errorf("err=%v reply=%+v", err, reply)
		}
	})
}

func TestPhase35REST_EncodersAndDecodersRejectWrongTypes(t *testing.T) {
	for method, encode := range restRequestEncoders {
		var unexpected ErrUnexpectedRequestType
		if _, err := encode(&platformv1.GetEABCredentialRequest{}); !errors.As(err, &unexpected) {
			t.Errorf("%s encoder: err = %v, want ErrUnexpectedRequestType", method, err)
		}
	}
	for method, decode := range restResponseDecoders {
		if !strings.Contains(method, "Ceremony") && !strings.Contains(method, "PIV") && !strings.Contains(method, "FIDO2") {
			continue
		}
		var unexpected ErrUnexpectedReplyType
		if err := decode([]byte(`{}`), &platformv1.GetEABCredentialResponse{}); !errors.As(err, &unexpected) {
			t.Errorf("%s decoder: err = %v, want ErrUnexpectedReplyType", method, err)
		}
	}
}
