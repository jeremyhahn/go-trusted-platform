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

//go:build codec_msgpack

package quic

import (
	"context"
	"reflect"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// TestPhase35MethodsAreMapped asserts that every CeremonyService, PIVService
// and FIDO2Service method resolves to its category opcode and has a
// sub-opcode. The service descriptors are the source of truth, so a method
// added to a proto without a QUIC mapping fails here.
func TestPhase35MethodsAreMapped(t *testing.T) {
	services := []struct {
		desc   grpc.ServiceDesc
		opcode byte
	}{
		{platformv1.CeremonyService_ServiceDesc, quicwire.OpCeremonyCategory},
		{platformv1.PIVService_ServiceDesc, quicwire.OpPIVCategory},
		{platformv1.FIDO2Service_ServiceDesc, quicwire.OpFIDO2Category},
	}
	wantMethods := map[string]int{"CeremonyService": 7, "PIVService": 8, "FIDO2Service": 5}

	for _, svc := range services {
		short := svc.desc.ServiceName[len("platform.v1."):]
		if got := len(svc.desc.Methods); got != wantMethods[short] {
			t.Errorf("%s has %d methods, want %d; update the mapping and this test", short, got, wantMethods[short])
		}
		for _, m := range svc.desc.Methods {
			method := "/" + svc.desc.ServiceName + "/" + m.MethodName
			if got, ok := grpcMethodToOpcodeMap[method]; !ok || got != svc.opcode {
				t.Errorf("%s opcode = 0x%02X (mapped=%v), want 0x%02X", method, got, ok, svc.opcode)
			}
			if _, ok := categorySubOpcodeMap[method]; !ok {
				t.Errorf("%s has no sub-opcode", method)
			}
		}
	}
}

// TestPhase35SubOpcodesAreUniquePerCategory guards against two methods in
// one category sharing a sub-opcode, which would route to the wrong handler.
func TestPhase35SubOpcodesAreUniquePerCategory(t *testing.T) {
	seen := map[[2]byte]string{}
	for _, desc := range []grpc.ServiceDesc{
		platformv1.CeremonyService_ServiceDesc, platformv1.PIVService_ServiceDesc, platformv1.FIDO2Service_ServiceDesc,
	} {
		for _, m := range desc.Methods {
			method := "/" + desc.ServiceName + "/" + m.MethodName
			key := [2]byte{grpcMethodToOpcodeMap[method], categorySubOpcodeMap[method]}
			if other, dup := seen[key]; dup {
				t.Errorf("%s and %s share opcode 0x%02X sub-opcode 0x%02X", method, other, key[0], key[1])
			}
			seen[key] = method
		}
	}
}

var wireTime = time.Date(2026, 10, 9, 1, 2, 3, 0, time.UTC)

// phase35Case drives one method through Invoke: request is the pb request,
// wantWire the daemon struct it must be translated to, wireResp the daemon
// response the fake server returns, and check asserts the pb reply.
type phase35Case struct {
	method   string
	opcode   byte
	subOp    byte
	request  interface{}
	wantWire interface{}
	wireResp interface{}
	reply    interface{}
	check    func(t *testing.T, reply interface{})
}

func phase35Cases() []phase35Case {
	device := quicwire.FIDO2Device{ID: "k1", Path: "/dev/hidraw0", Manufacturer: "Yubico", Product: "Key", ProductID: 1031, VendorID: 4176}
	return []phase35Case{
		{
			method: platformv1.CeremonyService_Init_FullMethodName, opcode: quicwire.OpCeremonyCategory, subOp: quicwire.CeremonySubInit,
			request:  &platformv1.CeremonyInitRequest{SoPin: "so", UserPin: "u", Threshold: "2-of-3", Hostname: "h", Sans: []string{"a"}, CredentialSealStrategy: "tpm"},
			wantWire: &quicwire.CeremonyInitReq{SOPIN: "so", UserPIN: "u", Threshold: "2-of-3", Hostname: "h", SANs: []string{"a"}, CredentialSealStrategy: "tpm"},
			wireResp: &quicwire.CeremonyInitResp{
				CeremonyID: "c1", State: "in_progress", InitializedAt: wireTime,
				AdminCertPEM: "ADMIN-CERT", AdminKeyPEM: "ADMIN-KEY", SPKIPin: "PIN",
			},
			reply: &platformv1.CeremonyInitResponse{},
			check: func(t *testing.T, r interface{}) {
				got := r.(*platformv1.CeremonyInitResponse)
				if got.GetCeremonyId() != "c1" || got.GetState() != platformv1.CeremonyState_CEREMONY_STATE_IN_PROGRESS ||
					!got.GetInitializedAt().AsTime().Equal(wireTime) {
					t.Errorf("reply = %v", got)
				}
				if got.GetAdminCertPem() != "ADMIN-CERT" || got.GetAdminKeyPem() != "ADMIN-KEY" || got.GetSpkiPin() != "PIN" {
					t.Errorf("admin bundle not decoded: %v", got)
				}
			},
		},
		{
			method: platformv1.CeremonyService_Status_FullMethodName, opcode: quicwire.OpCeremonyCategory, subOp: quicwire.CeremonySubStatus,
			request:  &platformv1.CeremonyStatusRequest{},
			wireResp: &quicwire.CeremonyStatusResp{CeremonyID: "c1", State: "complete", Threshold: "2-of-3", OfficersEnrolled: 2, OfficersRequired: 3, InitializedAt: wireTime},
			reply:    &platformv1.CeremonyStatusResponse{},
			check: func(t *testing.T, r interface{}) {
				got := r.(*platformv1.CeremonyStatusResponse)
				if got.GetState() != platformv1.CeremonyState_CEREMONY_STATE_COMPLETE || got.GetOfficersEnrolled() != 2 ||
					got.GetOfficersRequired() != 3 || got.GetThreshold() != "2-of-3" {
					t.Errorf("reply = %v", got)
				}
			},
		},
		{
			method: platformv1.CeremonyService_ClaimCertBegin_FullMethodName, opcode: quicwire.OpCeremonyCategory, subOp: quicwire.CeremonySubClaimCertBegin,
			request:  &platformv1.CeremonyClaimCertBeginRequest{Username: "alice", AuthenticatorType: platformv1.CeremonyAuthenticatorType_CEREMONY_AUTHENTICATOR_TYPE_PIV, Slot: "9a", CredentialId: "cred"},
			wantWire: &quicwire.CeremonyClaimCertBeginReq{Username: "alice", AuthenticatorType: "piv", Slot: "9a", CredentialID: "cred"},
			wireResp: &quicwire.CeremonyClaimCertBeginResp{Nonce: "n", ChallengeID: "ch", ExpiresAt: wireTime},
			reply:    &platformv1.CeremonyClaimCertBeginResponse{},
			check: func(t *testing.T, r interface{}) {
				got := r.(*platformv1.CeremonyClaimCertBeginResponse)
				if got.GetNonce() != "n" || got.GetChallengeId() != "ch" || !got.GetExpiresAt().AsTime().Equal(wireTime) {
					t.Errorf("reply = %v", got)
				}
			},
		},
		{
			method: platformv1.CeremonyService_ClaimCertComplete_FullMethodName, opcode: quicwire.OpCeremonyCategory, subOp: quicwire.CeremonySubClaimCertComplete,
			request:  &platformv1.CeremonyClaimCertCompleteRequest{Username: "alice", Nonce: "n", Signature: "sig"},
			wantWire: &quicwire.CeremonyClaimCertCompleteReq{Username: "alice", Nonce: "n", Signature: "sig"},
			wireResp: &quicwire.CeremonyClaimCertCompleteResp{CertificatePEM: "CERT", ChainPEM: "CHAIN"},
			reply:    &platformv1.CeremonyClaimCertCompleteResponse{},
			check: func(t *testing.T, r interface{}) {
				got := r.(*platformv1.CeremonyClaimCertCompleteResponse)
				if got.GetCertificatePem() != "CERT" || got.GetChainPem() != "CHAIN" {
					t.Errorf("reply = %v", got)
				}
			},
		},
		{
			method: platformv1.CeremonyService_ClaimShareBegin_FullMethodName, opcode: quicwire.OpCeremonyCategory, subOp: quicwire.CeremonySubClaimShareBegin,
			request:  &platformv1.CeremonyClaimShareBeginRequest{Username: "alice"},
			wantWire: &quicwire.CeremonyClaimShareBeginReq{Username: "alice"},
			wireResp: &quicwire.CeremonyClaimShareBeginResp{Nonce: "n", ExpiresAt: wireTime},
			reply:    &platformv1.CeremonyClaimShareBeginResponse{},
			check: func(t *testing.T, r interface{}) {
				got := r.(*platformv1.CeremonyClaimShareBeginResponse)
				if got.GetNonce() != "n" || !got.GetExpiresAt().AsTime().Equal(wireTime) {
					t.Errorf("reply = %v", got)
				}
			},
		},
		{
			method: platformv1.CeremonyService_ClaimShareComplete_FullMethodName, opcode: quicwire.OpCeremonyCategory, subOp: quicwire.CeremonySubClaimShareComplete,
			request:  &platformv1.CeremonyClaimShareCompleteRequest{Username: "alice", Nonce: "n", Signature: []byte{1, 2, 3}},
			wantWire: &quicwire.CeremonyClaimShareCompleteReq{Username: "alice", Nonce: "n", Signature: []byte{1, 2, 3}},
			wireResp: &quicwire.CeremonyClaimShareCompleteResp{Share: "s", Index: 4},
			reply:    &platformv1.CeremonyClaimShareCompleteResponse{},
			check: func(t *testing.T, r interface{}) {
				got := r.(*platformv1.CeremonyClaimShareCompleteResponse)
				if got.GetShare() != "s" || got.GetIndex() != 4 {
					t.Errorf("reply = %v", got)
				}
			},
		},
		{
			method: platformv1.CeremonyService_SignCSR_FullMethodName, opcode: quicwire.OpCeremonyCategory, subOp: quicwire.CeremonySubSignCSR,
			request:  &platformv1.CeremonySignCSRRequest{Username: "alice", SoPin: "so", CsrPem: "CSR", Role: platformv1.CeremonyOfficerRole_CEREMONY_OFFICER_ROLE_ADMIN},
			wantWire: &quicwire.CeremonySignCSRReq{Username: "alice", SOPIN: "so", CSRPEM: "CSR", Role: "admin"},
			wireResp: &quicwire.CeremonySignCSRResp{CertificatePEM: "CERT", ChainPEM: "CHAIN"},
			reply:    &platformv1.CeremonySignCSRResponse{},
			check: func(t *testing.T, r interface{}) {
				got := r.(*platformv1.CeremonySignCSRResponse)
				if got.GetCertificatePem() != "CERT" || got.GetChainPem() != "CHAIN" {
					t.Errorf("reply = %v", got)
				}
			},
		},
		{
			method: platformv1.PIVService_ListDevices_FullMethodName, opcode: quicwire.OpPIVCategory, subOp: quicwire.PIVSubListDevices,
			request:  &platformv1.PIVListDevicesRequest{},
			wireResp: &quicwire.PIVListDevicesResp{Devices: []quicwire.PIVDevice{{ID: "d1", Name: "YubiKey", Manufacturer: "Yubico", Model: "5", Serial: "123", FirmwareVersion: "5.4.3"}}},
			reply:    &platformv1.PIVListDevicesResponse{},
			check: func(t *testing.T, r interface{}) {
				d := r.(*platformv1.PIVListDevicesResponse).GetDevices()
				if len(d) != 1 || d[0].GetId() != "d1" || d[0].GetFirmwareVersion() != "5.4.3" || d[0].GetSerial() != "123" {
					t.Errorf("devices = %v", d)
				}
			},
		},
		{
			method: platformv1.PIVService_ListSlots_FullMethodName, opcode: quicwire.OpPIVCategory, subOp: quicwire.PIVSubListSlots,
			request:  &platformv1.PIVListSlotsRequest{Device: "d1"},
			wantWire: &quicwire.PIVListSlotsReq{Device: "d1"},
			wireResp: &quicwire.PIVListSlotsResp{Slots: []quicwire.PIVSlot{{ID: "9a", Name: "auth", Algorithm: "ecdsa", HasKey: true}}},
			reply:    &platformv1.PIVListSlotsResponse{},
			check: func(t *testing.T, r interface{}) {
				s := r.(*platformv1.PIVListSlotsResponse).GetSlots()
				if len(s) != 1 || s[0].GetAlgorithm() != platformv1.PIVAlgorithm_PIV_ALGORITHM_ECDSA || !s[0].GetHasKey() || s[0].GetHasCertificate() {
					t.Errorf("slots = %v", s)
				}
			},
		},
		{
			method: platformv1.PIVService_SlotInfo_FullMethodName, opcode: quicwire.OpPIVCategory, subOp: quicwire.PIVSubSlotInfo,
			request:  &platformv1.PIVSlotInfoRequest{Slot: "9a", Device: "d1"},
			wantWire: &quicwire.PIVSlotInfoReq{Slot: "9a", Device: "d1"},
			wireResp: &quicwire.PIVSlotInfoResp{Slot: quicwire.PIVSlot{ID: "9a", Algorithm: "rsa", HasKey: true, HasCertificate: true}, PublicKeyPEM: "PUB", CertificatePEM: "CERT"},
			reply:    &platformv1.PIVSlotInfoResponse{},
			check: func(t *testing.T, r interface{}) {
				got := r.(*platformv1.PIVSlotInfoResponse)
				if got.GetSlot().GetId() != "9a" || got.GetSlot().GetAlgorithm() != platformv1.PIVAlgorithm_PIV_ALGORITHM_RSA ||
					got.GetPublicKeyPem() != "PUB" || got.GetCertificatePem() != "CERT" {
					t.Errorf("reply = %v", got)
				}
			},
		},
		{
			method: platformv1.PIVService_Generate_FullMethodName, opcode: quicwire.OpPIVCategory, subOp: quicwire.PIVSubGenerate,
			request:  &platformv1.PIVGenerateRequest{Slot: "9a", Algorithm: platformv1.PIVAlgorithm_PIV_ALGORITHM_ED25519, Pin: "123456"},
			wantWire: &quicwire.PIVGenerateReq{Slot: "9a", Algorithm: "ed25519", PIN: "123456"},
			wireResp: &quicwire.PIVGenerateResp{PublicKeyPEM: "PUB"},
			reply:    &platformv1.PIVGenerateResponse{},
			check: func(t *testing.T, r interface{}) {
				if got := r.(*platformv1.PIVGenerateResponse).GetPublicKeyPem(); got != "PUB" {
					t.Errorf("public key = %q", got)
				}
			},
		},
		{
			method: platformv1.PIVService_Import_FullMethodName, opcode: quicwire.OpPIVCategory, subOp: quicwire.PIVSubImport,
			request:  &platformv1.PIVImportRequest{Slot: "9a", PrivateKeyPem: "KEY", Pin: "123456"},
			wantWire: &quicwire.PIVImportReq{Slot: "9a", PrivateKeyPEM: "KEY", PIN: "123456"},
			wireResp: &quicwire.PIVImportResp{Imported: true},
			reply:    &platformv1.PIVImportResponse{},
			check: func(t *testing.T, r interface{}) {
				if !r.(*platformv1.PIVImportResponse).GetImported() {
					t.Error("imported = false")
				}
			},
		},
		{
			method: platformv1.PIVService_Sign_FullMethodName, opcode: quicwire.OpPIVCategory, subOp: quicwire.PIVSubSign,
			request:  &platformv1.PIVSignRequest{Slot: "9a", Payload: []byte("data"), Pin: "123456"},
			wantWire: &quicwire.PIVSignReq{Slot: "9a", Payload: []byte("data"), PIN: "123456"},
			wireResp: &quicwire.PIVSignResp{Signature: []byte("sig")},
			reply:    &platformv1.PIVSignResponse{},
			check: func(t *testing.T, r interface{}) {
				if got := string(r.(*platformv1.PIVSignResponse).GetSignature()); got != "sig" {
					t.Errorf("signature = %q", got)
				}
			},
		},
		{
			method: platformv1.PIVService_Attest_FullMethodName, opcode: quicwire.OpPIVCategory, subOp: quicwire.PIVSubAttest,
			request:  &platformv1.PIVAttestRequest{Slot: "9a"},
			wantWire: &quicwire.PIVAttestReq{Slot: "9a"},
			wireResp: &quicwire.PIVAttestResp{AttestationCertPEM: "CERT", AttestationChainPEM: "CHAIN"},
			reply:    &platformv1.PIVAttestResponse{},
			check: func(t *testing.T, r interface{}) {
				got := r.(*platformv1.PIVAttestResponse)
				if got.GetAttestationCertPem() != "CERT" || got.GetAttestationChainPem() != "CHAIN" {
					t.Errorf("reply = %v", got)
				}
			},
		},
		{
			method: platformv1.PIVService_Reset_FullMethodName, opcode: quicwire.OpPIVCategory, subOp: quicwire.PIVSubReset,
			request:  &platformv1.PIVResetRequest{Device: "d1"},
			wantWire: &quicwire.PIVResetReq{Device: "d1"},
			wireResp: &quicwire.PIVResetResp{Reset: true},
			reply:    &platformv1.PIVResetResponse{},
			check: func(t *testing.T, r interface{}) {
				if !r.(*platformv1.PIVResetResponse).GetReset_() {
					t.Error("reset = false")
				}
			},
		},
		{
			method: platformv1.FIDO2Service_ListDevices_FullMethodName, opcode: quicwire.OpFIDO2Category, subOp: quicwire.FIDO2SubListDevices,
			request:  &platformv1.FIDO2ListDevicesRequest{},
			wireResp: &quicwire.FIDO2ListDevicesResp{Devices: []quicwire.FIDO2Device{device}},
			reply:    &platformv1.FIDO2ListDevicesResponse{},
			check: func(t *testing.T, r interface{}) {
				d := r.(*platformv1.FIDO2ListDevicesResponse).GetDevices()
				if len(d) != 1 || d[0].GetId() != "k1" || d[0].GetProductId() != 1031 || d[0].GetVendorId() != 4176 {
					t.Errorf("devices = %v", d)
				}
			},
		},
		{
			method: platformv1.FIDO2Service_WaitDevice_FullMethodName, opcode: quicwire.OpFIDO2Category, subOp: quicwire.FIDO2SubWaitDevice,
			request:  &platformv1.FIDO2WaitDeviceRequest{TimeoutSeconds: 30},
			wantWire: &quicwire.FIDO2WaitDeviceReq{TimeoutSeconds: 30},
			wireResp: &quicwire.FIDO2WaitDeviceResp{Device: device},
			reply:    &platformv1.FIDO2WaitDeviceResponse{},
			check: func(t *testing.T, r interface{}) {
				if got := r.(*platformv1.FIDO2WaitDeviceResponse).GetDevice().GetPath(); got != "/dev/hidraw0" {
					t.Errorf("device path = %q", got)
				}
			},
		},
		{
			method: platformv1.FIDO2Service_Info_FullMethodName, opcode: quicwire.OpFIDO2Category, subOp: quicwire.FIDO2SubInfo,
			request:  &platformv1.FIDO2InfoRequest{Device: "k1"},
			wantWire: &quicwire.FIDO2InfoReq{Device: "k1"},
			wireResp: &quicwire.FIDO2InfoResp{Device: device, AAGUID: "aa", FirmwareVersion: "5.4", Extensions: []string{"hmac-secret"}, Options: map[string]bool{"clientPin": true}, MaxMsgSize: 1200},
			reply:    &platformv1.FIDO2InfoResponse{},
			check: func(t *testing.T, r interface{}) {
				info := r.(*platformv1.FIDO2InfoResponse).GetInfo()
				if info.GetAaguid() != "aa" || info.GetMaxMsgSize() != 1200 || !info.GetOptions()["clientPin"] ||
					info.GetDevice().GetId() != "k1" || len(info.GetExtensions()) != 1 {
					t.Errorf("info = %v", info)
				}
			},
		},
		{
			method: platformv1.FIDO2Service_Register_FullMethodName, opcode: quicwire.OpFIDO2Category, subOp: quicwire.FIDO2SubRegister,
			request:  &platformv1.FIDO2RegisterRequest{Username: "alice", Role: platformv1.FIDO2Role_FIDO2_ROLE_SO, RequirePin: true, RequireUv: true, RpId: "example.test"},
			wantWire: &quicwire.FIDO2RegisterReq{Username: "alice", Role: "so", RequirePIN: true, RequireUV: true, RPID: "example.test"},
			wireResp: &quicwire.FIDO2RegisterResp{CredentialID: "cred", AAGUID: "aa", PublicKeyPEM: "PUB"},
			reply:    &platformv1.FIDO2RegisterResponse{},
			check: func(t *testing.T, r interface{}) {
				got := r.(*platformv1.FIDO2RegisterResponse)
				if got.GetCredentialId() != "cred" || got.GetAaguid() != "aa" || got.GetPublicKeyPem() != "PUB" {
					t.Errorf("reply = %v", got)
				}
			},
		},
		{
			method: platformv1.FIDO2Service_Authenticate_FullMethodName, opcode: quicwire.OpFIDO2Category, subOp: quicwire.FIDO2SubAuthenticate,
			request:  &platformv1.FIDO2AuthenticateRequest{CredentialId: "cred"},
			wantWire: &quicwire.FIDO2AuthenticateReq{CredentialID: "cred"},
			wireResp: &quicwire.FIDO2AuthenticateResp{Authenticated: true, Counter: 9},
			reply:    &platformv1.FIDO2AuthenticateResponse{},
			check: func(t *testing.T, r interface{}) {
				got := r.(*platformv1.FIDO2AuthenticateResponse)
				if !got.GetAuthenticated() || got.GetCounter() != 9 {
					t.Errorf("reply = %v", got)
				}
			},
		},
	}
}

// TestPhase35InvokeTranslatesBothDirections drives every method through
// Invoke and asserts the opcode, the sub-opcode, the wire struct the daemon
// would decode, and the pb reply built from the daemon's response.
func TestPhase35InvokeTranslatesBothDirections(t *testing.T) {
	cases := phase35Cases()
	if len(cases) != 20 {
		t.Fatalf("table covers %d methods, want all 20", len(cases))
	}
	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			respPayload, err := quicwire.EncodePayload(tc.wireResp)
			if err != nil {
				t.Fatalf("encode response: %v", err)
			}
			sender := &recordingSender{respPayload: respPayload}
			conn := newConnWithSender(t, sender)

			if err := conn.Invoke(context.Background(), tc.method, tc.request, tc.reply); err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			if sender.rawCalls != 1 || sender.encCalls != 0 {
				t.Fatalf("SendRequest calls = %d, Send calls = %d; want 1, 0", sender.rawCalls, sender.encCalls)
			}
			if sender.rawOpcode != tc.opcode || sender.rawPayload[0] != tc.subOp {
				t.Errorf("opcode/sub-opcode = 0x%02X/0x%02X, want 0x%02X/0x%02X",
					sender.rawOpcode, sender.rawPayload[0], tc.opcode, tc.subOp)
			}
			if tc.wantWire == nil {
				if len(sender.rawPayload) != 1 {
					t.Errorf("empty-body method sent %d payload bytes, want only the sub-opcode", len(sender.rawPayload))
				}
			} else {
				gotWire := reflect.New(reflect.TypeOf(tc.wantWire).Elem()).Interface()
				if err := quicwire.DecodePayload(sender.rawPayload[1:], gotWire); err != nil {
					t.Fatalf("decode request body: %v", err)
				}
				if !reflect.DeepEqual(gotWire, tc.wantWire) {
					t.Errorf("wire request = %+v, want %+v", gotWire, tc.wantWire)
				}
			}
			tc.check(t, tc.reply)
		})
	}
}

// TestPhase35InvokeRejectsBadMessages covers the error paths: a request of
// the wrong type, an enum outside the proto, and a daemon response carrying
// a value the SDK does not recognise must each fail rather than send or
// report a silently altered message: a refused request is the caller's
// InvalidArgument and never reaches the wire, a refused response Internal.
func TestPhase35InvokeRejectsBadMessages(t *testing.T) {
	unknownSlot, err := quicwire.EncodePayload(&quicwire.PIVListSlotsResp{Slots: []quicwire.PIVSlot{{ID: "9a", Algorithm: "dsa"}}})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	unknownState, err := quicwire.EncodePayload(&quicwire.CeremonyStatusResp{State: "sealed"})
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	tests := []struct {
		name     string
		method   string
		request  interface{}
		reply    interface{}
		response []byte
		wantSent bool
	}{
		{"request of wrong type", platformv1.PIVService_Generate_FullMethodName, &platformv1.PIVAttestRequest{}, &platformv1.PIVGenerateResponse{}, nil, false},
		{"nil request", platformv1.PIVService_Generate_FullMethodName, (*platformv1.PIVGenerateRequest)(nil), &platformv1.PIVGenerateResponse{}, nil, false},
		{"unknown algorithm enum", platformv1.PIVService_Generate_FullMethodName, &platformv1.PIVGenerateRequest{Algorithm: 99}, &platformv1.PIVGenerateResponse{}, nil, false},
		{"unknown role enum", platformv1.FIDO2Service_Register_FullMethodName, &platformv1.FIDO2RegisterRequest{Role: 99}, &platformv1.FIDO2RegisterResponse{}, nil, false},
		{"unknown authenticator enum", platformv1.CeremonyService_ClaimCertBegin_FullMethodName, &platformv1.CeremonyClaimCertBeginRequest{AuthenticatorType: 99}, &platformv1.CeremonyClaimCertBeginResponse{}, nil, false},
		{"unknown officer role enum", platformv1.CeremonyService_SignCSR_FullMethodName, &platformv1.CeremonySignCSRRequest{Role: 99}, &platformv1.CeremonySignCSRResponse{}, nil, false},
		{"reply of wrong type", platformv1.PIVService_Reset_FullMethodName, &platformv1.PIVResetRequest{}, &platformv1.PIVSignResponse{}, []byte{0x80}, true},
		{"unknown slot algorithm in response", platformv1.PIVService_ListSlots_FullMethodName, &platformv1.PIVListSlotsRequest{}, &platformv1.PIVListSlotsResponse{}, unknownSlot, true},
		{"unknown ceremony state in response", platformv1.CeremonyService_Status_FullMethodName, &platformv1.CeremonyStatusRequest{}, &platformv1.CeremonyStatusResponse{}, unknownState, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sender := &recordingSender{respPayload: tt.response}
			conn := newConnWithSender(t, sender)

			err := conn.Invoke(context.Background(), tt.method, tt.request, tt.reply)
			wantCode := codes.InvalidArgument
			if tt.wantSent {
				wantCode = codes.Internal
			}
			if status.Code(err) != wantCode {
				t.Fatalf("Invoke error = %v, want code %v", err, wantCode)
			}
			if sent := sender.rawCalls > 0; sent != tt.wantSent {
				t.Errorf("request sent = %v, want %v", sent, tt.wantSent)
			}
		})
	}
}

// TestPhase35ServerErrorsPropagate checks that a daemon failure (for example
// a service that is not configured, which the dispatcher reports as
// StatusUnavailable) reaches the caller as a gRPC error instead of an empty
// success.
func TestPhase35ServerErrorsPropagate(t *testing.T) {
	sender := &recordingSender{sendRequestErr: &quicwire.ErrProtocol{Status: quicwire.StatusUnavailable, Message: "piv: not configured"}}
	conn := newConnWithSender(t, sender)

	err := conn.Invoke(context.Background(), platformv1.PIVService_ListDevices_FullMethodName,
		&platformv1.PIVListDevicesRequest{}, &platformv1.PIVListDevicesResponse{})
	if status.Code(err) != codes.Unavailable {
		t.Fatalf("Invoke error = %v, want code Unavailable", err)
	}
}
