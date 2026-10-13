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

package mcp

import (
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// phase35Methods is every ceremony, PIV and FIDO2 method and the tool the
// server registers for it.
var phase35Methods = map[string]string{
	"/platform.v1.CeremonyService/Init":               "platform_ceremony_init",
	"/platform.v1.CeremonyService/Status":             "platform_ceremony_status",
	"/platform.v1.CeremonyService/ClaimCertBegin":     "platform_ceremony_claim_cert_begin",
	"/platform.v1.CeremonyService/ClaimCertComplete":  "platform_ceremony_claim_cert_complete",
	"/platform.v1.CeremonyService/ClaimShareBegin":    "platform_ceremony_claim_share_begin",
	"/platform.v1.CeremonyService/ClaimShareComplete": "platform_ceremony_claim_share_complete",
	"/platform.v1.CeremonyService/SignCSR":            "platform_ceremony_sign_csr",
	"/platform.v1.PIVService/ListDevices":             "platform_piv_list_devices",
	"/platform.v1.PIVService/ListSlots":               "platform_piv_list_slots",
	"/platform.v1.PIVService/SlotInfo":                "platform_piv_slot_info",
	"/platform.v1.PIVService/Generate":                "platform_piv_generate",
	"/platform.v1.PIVService/Import":                  "platform_piv_import",
	"/platform.v1.PIVService/Sign":                    "platform_piv_sign",
	"/platform.v1.PIVService/Attest":                  "platform_piv_attest",
	"/platform.v1.PIVService/Reset":                   "platform_piv_reset",
	"/platform.v1.FIDO2Service/ListDevices":           "platform_fido2_list_devices",
	"/platform.v1.FIDO2Service/WaitDevice":            "platform_fido2_wait_device",
	"/platform.v1.FIDO2Service/Info":                  "platform_fido2_info",
	"/platform.v1.FIDO2Service/Register":              "platform_fido2_register",
	"/platform.v1.FIDO2Service/Authenticate":          "platform_fido2_authenticate",
}

// TestPhase35MCP_EveryMethodMapsToARegisteredTool pins each method to the
// tool the server registers, so a method missing here or renamed on either
// side fails.
func TestPhase35MCP_EveryMethodMapsToItsTool(t *testing.T) {
	// That the server registers each tool is checked in pkg/api/mcp
	// against MethodTools; the SDK cannot import the server.
	for method, want := range phase35Methods {
		if got := grpcMethodToMCPToolMap[method]; got != want {
			t.Errorf("%s maps to %q, want %q", method, got, want)
		}
	}
}

// TestPhase35MCP_NoUnexpectedMethodsMapped fails when a method is mapped for
// one of the three services without being listed above.
func TestPhase35MCP_NoUnexpectedMethodsMapped(t *testing.T) {
	prefixes := []string{"/platform.v1.CeremonyService/", "/platform.v1.PIVService/", "/platform.v1.FIDO2Service/"}
	for method := range grpcMethodToMCPToolMap {
		for _, prefix := range prefixes {
			if !strings.HasPrefix(method, prefix) {
				continue
			}
			if _, listed := phase35Methods[method]; !listed {
				t.Errorf("%s is mapped but not covered by the table", method)
			}
		}
	}
}

// requireCode asserts err is a gRPC status error carrying want.
func requireCode(t *testing.T, err error, want codes.Code) {
	t.Helper()
	if got := status.Code(err); got != want {
		t.Fatalf("err = %v (code %v), want code %v", err, got, want)
	}
}

func invokePhase35(t *testing.T, results map[string]interface{}, method string, req, reply interface{}) ([]toolCall, error) {
	t.Helper()
	var calls []toolCall
	a := provisioningTestServer(t, results, &calls)
	err := a.Connection().Invoke(context.Background(), method, req, reply)
	return calls, err
}

func TestPhase35MCP_CeremonyInit_ArgsReachTool(t *testing.T) {
	calls, err := invokePhase35(t, map[string]interface{}{
		"platform_ceremony_init": map[string]interface{}{
			"ceremony_id":    "c-1",
			"state":          "in_progress",
			"initialized_at": "2026-01-02T03:04:05Z",
		},
	}, "/platform.v1.CeremonyService/Init", &platformv1.CeremonyInitRequest{
		SoPin: "so", UserPin: "user", Threshold: "2-of-3", Hostname: "host",
	}, &platformv1.CeremonyInitResponse{})
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if calls[0].Name != "platform_ceremony_init" || calls[0].Arguments["so_pin"] != "so" ||
		calls[0].Arguments["threshold"] != "2-of-3" {
		t.Errorf("call = %+v", calls[0])
	}
}

func TestPhase35MCP_CeremonyInit_ReplyDecode(t *testing.T) {
	reply := &platformv1.CeremonyInitResponse{}
	_, err := invokePhase35(t, map[string]interface{}{
		"platform_ceremony_init": map[string]interface{}{
			"ceremony_id":    "c-1",
			"state":          "in_progress",
			"initialized_at": "2026-01-02T03:04:05Z",
			"admin_cert_pem": "ADMIN-CERT",
			"admin_key_pem":  "ADMIN-KEY",
			"spki_pin":       "PIN",
		},
	}, "/platform.v1.CeremonyService/Init", &platformv1.CeremonyInitRequest{}, reply)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if reply.GetCeremonyId() != "c-1" || reply.GetState() != platformv1.CeremonyState_CEREMONY_STATE_IN_PROGRESS {
		t.Errorf("reply = %+v", reply)
	}
	if reply.GetAdminCertPem() != "ADMIN-CERT" || reply.GetAdminKeyPem() != "ADMIN-KEY" || reply.GetSpkiPin() != "PIN" {
		t.Errorf("admin bundle not decoded: %+v", reply)
	}
	if reply.GetInitializedAt().AsTime().Year() != 2026 {
		t.Errorf("initialized_at = %v", reply.GetInitializedAt())
	}
}

func TestPhase35MCP_CeremonyStatus_UnknownStateRefused(t *testing.T) {
	_, err := invokePhase35(t, map[string]interface{}{
		"platform_ceremony_status": map[string]interface{}{"state": "bogus"},
	}, "/platform.v1.CeremonyService/Status", &platformv1.CeremonyStatusRequest{}, &platformv1.CeremonyStatusResponse{})
	requireCode(t, err, codes.Internal)
}

func TestPhase35MCP_CeremonyClaimCertBegin_EnumGoesOutAsString(t *testing.T) {
	reply := &platformv1.CeremonyClaimCertBeginResponse{}
	calls, err := invokePhase35(t, map[string]interface{}{
		"platform_ceremony_claim_cert_begin": map[string]interface{}{
			"nonce": "n-1", "challenge_id": "ch-1", "expires_at": "2026-01-02T03:04:05Z",
		},
	}, "/platform.v1.CeremonyService/ClaimCertBegin", &platformv1.CeremonyClaimCertBeginRequest{
		Username:          "alice",
		AuthenticatorType: platformv1.CeremonyAuthenticatorType_CEREMONY_AUTHENTICATOR_TYPE_FIDO2,
		Slot:              "9a",
		CredentialId:      "cred",
	}, reply)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	args := calls[0].Arguments
	if args["authenticator_type"] != "fido2" || args["username"] != "alice" || args["slot"] != "9a" || args["credential_id"] != "cred" {
		t.Errorf("args = %v", args)
	}
	if reply.GetNonce() != "n-1" {
		t.Errorf("reply = %+v", reply)
	}
}

func TestPhase35MCP_CeremonyClaimCertBegin_UnknownEnumRefusedBeforeCall(t *testing.T) {
	calls, err := invokePhase35(t, nil, "/platform.v1.CeremonyService/ClaimCertBegin",
		&platformv1.CeremonyClaimCertBeginRequest{AuthenticatorType: platformv1.CeremonyAuthenticatorType(99)},
		&platformv1.CeremonyClaimCertBeginResponse{})
	requireCode(t, err, codes.InvalidArgument)
	if len(calls) != 0 {
		t.Errorf("tool was called despite the invalid request: %+v", calls)
	}
}

func TestPhase35MCP_CeremonyClaimShareComplete_SignatureIsBase64(t *testing.T) {
	calls, err := invokePhase35(t, map[string]interface{}{
		"platform_ceremony_claim_share_complete": map[string]interface{}{"share": "s"},
	}, "/platform.v1.CeremonyService/ClaimShareComplete", &platformv1.CeremonyClaimShareCompleteRequest{
		Username: "alice", Nonce: "n", Signature: []byte{0xde, 0xad, 0xbe, 0xef},
	}, &platformv1.CeremonyClaimShareCompleteResponse{})
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if got := calls[0].Arguments["signature"]; got != base64.StdEncoding.EncodeToString([]byte{0xde, 0xad, 0xbe, 0xef}) {
		t.Errorf("signature = %v", got)
	}
}

func TestPhase35MCP_CeremonySignCSR_RoleGoesOutAsString(t *testing.T) {
	calls, err := invokePhase35(t, map[string]interface{}{
		"platform_ceremony_sign_csr": map[string]interface{}{"certificate_pem": "PEM"},
	}, "/platform.v1.CeremonyService/SignCSR", &platformv1.CeremonySignCSRRequest{
		Username: "alice", SoPin: "so", CsrPem: "csr",
		Role: platformv1.CeremonyOfficerRole_CEREMONY_OFFICER_ROLE_ADMIN,
	}, &platformv1.CeremonySignCSRResponse{})
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if calls[0].Arguments["role"] != "admin" || calls[0].Arguments["csr_pem"] != "csr" {
		t.Errorf("args = %v", calls[0].Arguments)
	}
}

func TestPhase35MCP_PIVListDevices_DecodesGoNamedKeys(t *testing.T) {
	reply := &platformv1.PIVListDevicesResponse{}
	_, err := invokePhase35(t, map[string]interface{}{
		"platform_piv_list_devices": map[string]interface{}{
			"devices": []interface{}{map[string]interface{}{
				"ID": "d1", "Name": "YubiKey", "Manufacturer": "Yubico", "Serial": "123", "FirmwareVersion": "5.4.3",
			}},
		},
	}, "/platform.v1.PIVService/ListDevices", &platformv1.PIVListDevicesRequest{}, reply)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if len(reply.GetDevices()) != 1 || reply.GetDevices()[0].GetId() != "d1" ||
		reply.GetDevices()[0].GetFirmwareVersion() != "5.4.3" {
		t.Errorf("reply = %+v", reply)
	}
}

func TestPhase35MCP_PIVListSlots_UnknownAlgorithmRefused(t *testing.T) {
	_, err := invokePhase35(t, map[string]interface{}{
		"platform_piv_list_slots": map[string]interface{}{
			"slots": []interface{}{map[string]interface{}{"ID": "9a", "Algorithm": "dsa"}},
		},
	}, "/platform.v1.PIVService/ListSlots", &platformv1.PIVListSlotsRequest{Device: "d1"}, &platformv1.PIVListSlotsResponse{})
	requireCode(t, err, codes.Internal)
}

func TestPhase35MCP_PIVSlotInfo_DecodesBareStruct(t *testing.T) {
	reply := &platformv1.PIVSlotInfoResponse{}
	calls, err := invokePhase35(t, map[string]interface{}{
		"platform_piv_slot_info": map[string]interface{}{
			"Slot":         map[string]interface{}{"ID": "9a", "Algorithm": "ecdsa", "HasKey": true},
			"PublicKeyPEM": "PUB",
		},
	}, "/platform.v1.PIVService/SlotInfo", &platformv1.PIVSlotInfoRequest{Slot: "9a", Device: "d1"}, reply)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if calls[0].Arguments["slot"] != "9a" || calls[0].Arguments["device"] != "d1" {
		t.Errorf("args = %v", calls[0].Arguments)
	}
	if reply.GetSlot().GetAlgorithm() != platformv1.PIVAlgorithm_PIV_ALGORITHM_ECDSA ||
		!reply.GetSlot().GetHasKey() || reply.GetPublicKeyPem() != "PUB" {
		t.Errorf("reply = %+v", reply)
	}
}

func TestPhase35MCP_PIVGenerate_AlgorithmGoesOutAsString(t *testing.T) {
	reply := &platformv1.PIVGenerateResponse{}
	calls, err := invokePhase35(t, map[string]interface{}{
		"platform_piv_generate": map[string]interface{}{"public_key_pem": "PUB"},
	}, "/platform.v1.PIVService/Generate", &platformv1.PIVGenerateRequest{
		Slot: "9a", Algorithm: platformv1.PIVAlgorithm_PIV_ALGORITHM_ED25519, Pin: "123456",
	}, reply)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if calls[0].Arguments["algorithm"] != "ed25519" || calls[0].Arguments["pin"] != "123456" {
		t.Errorf("args = %v", calls[0].Arguments)
	}
	if reply.GetPublicKeyPem() != "PUB" {
		t.Errorf("reply = %+v", reply)
	}
}

func TestPhase35MCP_PIVGenerate_UnknownAlgorithmRefusedBeforeCall(t *testing.T) {
	calls, err := invokePhase35(t, nil, "/platform.v1.PIVService/Generate",
		&platformv1.PIVGenerateRequest{Algorithm: platformv1.PIVAlgorithm(99)}, &platformv1.PIVGenerateResponse{})
	requireCode(t, err, codes.InvalidArgument)
	if len(calls) != 0 {
		t.Errorf("tool was called despite the invalid request: %+v", calls)
	}
}

func TestPhase35MCP_PIVSign_PayloadBase64AndSignatureDecoded(t *testing.T) {
	signature := []byte{1, 2, 3, 4}
	reply := &platformv1.PIVSignResponse{}
	calls, err := invokePhase35(t, map[string]interface{}{
		"platform_piv_sign": map[string]interface{}{"signature": base64.StdEncoding.EncodeToString(signature)},
	}, "/platform.v1.PIVService/Sign", &platformv1.PIVSignRequest{Slot: "9a", Payload: []byte("hello"), Pin: "1"}, reply)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if calls[0].Arguments["payload"] != base64.StdEncoding.EncodeToString([]byte("hello")) {
		t.Errorf("payload = %v", calls[0].Arguments["payload"])
	}
	if string(reply.GetSignature()) != string(signature) {
		t.Errorf("signature = %v", reply.GetSignature())
	}
}

func TestPhase35MCP_PIVImportAttestReset_GenericRoundTrip(t *testing.T) {
	results := map[string]interface{}{
		"platform_piv_import": map[string]interface{}{"imported": true},
		"platform_piv_attest": map[string]interface{}{"attestation_cert_pem": "CERT", "attestation_chain_pem": "CHAIN"},
		"platform_piv_reset":  map[string]interface{}{"reset": true},
	}

	imp := &platformv1.PIVImportResponse{}
	calls, err := invokePhase35(t, results, "/platform.v1.PIVService/Import",
		&platformv1.PIVImportRequest{Slot: "9a", PrivateKeyPem: "KEY", Pin: "1"}, imp)
	if err != nil || !imp.GetImported() || calls[0].Arguments["private_key_pem"] != "KEY" {
		t.Errorf("import: err=%v reply=%+v args=%v", err, imp, calls)
	}

	att := &platformv1.PIVAttestResponse{}
	if _, err = invokePhase35(t, results, "/platform.v1.PIVService/Attest",
		&platformv1.PIVAttestRequest{Slot: "9a"}, att); err != nil ||
		att.GetAttestationCertPem() != "CERT" || att.GetAttestationChainPem() != "CHAIN" {
		t.Errorf("attest: err=%v reply=%+v", err, att)
	}

	rst := &platformv1.PIVResetResponse{}
	if calls, err = invokePhase35(t, results, "/platform.v1.PIVService/Reset",
		&platformv1.PIVResetRequest{Device: "d1"}, rst); err != nil || !rst.GetReset_() ||
		calls[0].Arguments["device"] != "d1" {
		t.Errorf("reset: err=%v reply=%+v args=%v", err, rst, calls)
	}
}

func TestPhase35MCP_FIDO2_ListWaitInfoDecode(t *testing.T) {
	device := map[string]interface{}{"ID": "k1", "Path": "/dev/hidraw0", "Manufacturer": "Yubico", "ProductID": 1031, "VendorID": 4176}
	results := map[string]interface{}{
		"platform_fido2_list_devices": map[string]interface{}{"devices": []interface{}{device}},
		"platform_fido2_wait_device":  device,
		"platform_fido2_info": map[string]interface{}{
			"Device": device, "AAGUID": "aa", "FirmwareVersion": "5.4", "MaxMsgSize": 1200,
			"Extensions": []interface{}{"hmac-secret"}, "Options": map[string]interface{}{"clientPin": true},
		},
	}

	list := &platformv1.FIDO2ListDevicesResponse{}
	if _, err := invokePhase35(t, results, "/platform.v1.FIDO2Service/ListDevices",
		&platformv1.FIDO2ListDevicesRequest{}, list); err != nil || len(list.GetDevices()) != 1 ||
		list.GetDevices()[0].GetId() != "k1" {
		t.Errorf("list: err=%v reply=%+v", err, list)
	}

	wait := &platformv1.FIDO2WaitDeviceResponse{}
	calls, err := invokePhase35(t, results, "/platform.v1.FIDO2Service/WaitDevice",
		&platformv1.FIDO2WaitDeviceRequest{TimeoutSeconds: 5}, wait)
	if err != nil || wait.GetDevice().GetPath() != "/dev/hidraw0" || calls[0].Arguments["timeout_seconds"].(float64) != 5 {
		t.Errorf("wait: err=%v reply=%+v args=%v", err, wait, calls)
	}

	info := &platformv1.FIDO2InfoResponse{}
	if _, err = invokePhase35(t, results, "/platform.v1.FIDO2Service/Info",
		&platformv1.FIDO2InfoRequest{Device: "k1"}, info); err != nil ||
		info.GetInfo().GetAaguid() != "aa" || info.GetInfo().GetMaxMsgSize() != 1200 ||
		!info.GetInfo().GetOptions()["clientPin"] {
		t.Errorf("info: err=%v reply=%+v", err, info)
	}
}

func TestPhase35MCP_FIDO2Register_RoleGoesOutAsString(t *testing.T) {
	reply := &platformv1.FIDO2RegisterResponse{}
	calls, err := invokePhase35(t, map[string]interface{}{
		"platform_fido2_register": map[string]interface{}{"CredentialID": "c1", "AAGUID": "aa", "PublicKeyPEM": "PUB"},
	}, "/platform.v1.FIDO2Service/Register", &platformv1.FIDO2RegisterRequest{
		Username: "alice", Role: platformv1.FIDO2Role_FIDO2_ROLE_SO, RequirePin: true, RpId: "rp",
	}, reply)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if calls[0].Arguments["role"] != "so" || calls[0].Arguments["require_pin"] != true || calls[0].Arguments["rp_id"] != "rp" {
		t.Errorf("args = %v", calls[0].Arguments)
	}
	if reply.GetCredentialId() != "c1" || reply.GetPublicKeyPem() != "PUB" {
		t.Errorf("reply = %+v", reply)
	}
}

func TestPhase35MCP_FIDO2Register_UnknownRoleRefusedBeforeCall(t *testing.T) {
	calls, err := invokePhase35(t, nil, "/platform.v1.FIDO2Service/Register",
		&platformv1.FIDO2RegisterRequest{Role: platformv1.FIDO2Role(99)}, &platformv1.FIDO2RegisterResponse{})
	requireCode(t, err, codes.InvalidArgument)
	if len(calls) != 0 {
		t.Errorf("tool was called despite the invalid request: %+v", calls)
	}
}

func TestPhase35MCP_FIDO2Authenticate_Decode(t *testing.T) {
	reply := &platformv1.FIDO2AuthenticateResponse{}
	calls, err := invokePhase35(t, map[string]interface{}{
		"platform_fido2_authenticate": map[string]interface{}{"Authenticated": true, "Counter": 7},
	}, "/platform.v1.FIDO2Service/Authenticate", &platformv1.FIDO2AuthenticateRequest{CredentialId: "c1"}, reply)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if calls[0].Arguments["credential_id"] != "c1" || !reply.GetAuthenticated() || reply.GetCounter() != 7 {
		t.Errorf("args=%v reply=%+v", calls[0].Arguments, reply)
	}
}

// TestPhase35MCP_BuildersRejectWrongTypes covers the type guards of the
// argument builders and reply decoders.
func TestPhase35MCP_BuildersRejectWrongTypes(t *testing.T) {
	for method, build := range phase35ArgBuilders {
		var unexpected ErrUnexpectedArgsType
		if _, err := build(&platformv1.GetEABCredentialRequest{}); !errors.As(err, &unexpected) {
			t.Errorf("%s builder: err = %v, want ErrUnexpectedArgsType", method, err)
		}
	}
	for method, decode := range phase35ReplyDecoders {
		var unexpected ErrUnexpectedReplyType
		if err := decode(map[string]interface{}{}, &platformv1.GetEABCredentialRequest{}); !errors.As(err, &unexpected) {
			t.Errorf("%s decoder: err = %v, want ErrUnexpectedReplyType", method, err)
		}
	}
}
