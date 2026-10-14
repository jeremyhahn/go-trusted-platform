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
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// luksCases covers every LUKSService method the daemon serves under
// OpLUKSCategory (pkg/api/daemon/phase35_quic.go::luksQUICDispatch). They run
// through TestPhase35InvokeTranslatesBothDirections with the other categories.
func luksCases() []phase35Case {
	return []phase35Case{
		{
			method: platformv1.LUKSService_Status_FullMethodName, opcode: quicwire.OpLUKSCategory, subOp: quicwire.LUKSSubStatus,
			request:  &platformv1.LUKSStatusRequest{Device: "/dev/sda2"},
			wantWire: &quicwire.LUKSStatusReq{Device: "/dev/sda2"},
			wireResp: &quicwire.LUKSStatusResp{Device: "/dev/sda2", IsLUKS: true, Version: 2, UUID: "u-1", Label: "root", Cipher: "aes-xts-plain64", ActiveSlots: []int32{0, 2}},
			reply:    &platformv1.LUKSStatusResponse{},
			check: func(t *testing.T, r interface{}) {
				got := r.(*platformv1.LUKSStatusResponse)
				if !got.GetIsLuks() || got.GetVersion() != 2 || got.GetUuid() != "u-1" || got.GetLabel() != "root" ||
					got.GetCipher() != "aes-xts-plain64" || len(got.GetActiveSlots()) != 2 || got.GetDevice() != "/dev/sda2" {
					t.Errorf("reply = %v", got)
				}
			},
		},
		{
			method: platformv1.LUKSService_ListSlots_FullMethodName, opcode: quicwire.OpLUKSCategory, subOp: quicwire.LUKSSubListSlots,
			request:  &platformv1.LUKSListSlotsRequest{Device: "/dev/sda2"},
			wantWire: &quicwire.LUKSListSlotsReq{Device: "/dev/sda2"},
			wireResp: &quicwire.LUKSListSlotsResp{Device: "/dev/sda2", Slots: []quicwire.LUKSKeyslot{{Slot: 1, Type: "tpm", KeySize: 512, Priority: 1}}},
			reply:    &platformv1.LUKSListSlotsResponse{},
			check: func(t *testing.T, r interface{}) {
				s := r.(*platformv1.LUKSListSlotsResponse).GetSlots()
				if len(s) != 1 || s[0].GetSlot() != 1 || s[0].GetType() != platformv1.LUKSKeyType_LUKS_KEY_TYPE_TPM ||
					s[0].GetKeySize() != 512 || s[0].GetPriority() != 1 {
					t.Errorf("slots = %v", s)
				}
			},
		},
		{
			method: platformv1.LUKSService_Info_FullMethodName, opcode: quicwire.OpLUKSCategory, subOp: quicwire.LUKSSubInfo,
			request:  &platformv1.LUKSInfoRequest{Device: "/dev/sda2"},
			wantWire: &quicwire.LUKSInfoReq{Device: "/dev/sda2"},
			wireResp: &quicwire.LUKSInfoResp{
				Device: "/dev/sda2", UUID: "u-1", Label: "root", Version: 2, Cipher: "aes-xts-plain64", KeySize: 512, SectorSize: 4096,
				Slots: []quicwire.LUKSKeyslot{{Slot: 0, Type: "passphrase"}, {Slot: 3, Type: "fido2"}}, MetadataJSON: "{}",
			},
			reply: &platformv1.LUKSInfoResponse{},
			check: func(t *testing.T, r interface{}) {
				got := r.(*platformv1.LUKSInfoResponse)
				if got.GetUuid() != "u-1" || got.GetKeySize() != 512 || got.GetSectorSize() != 4096 || got.GetMetadataJson() != "{}" {
					t.Errorf("reply = %v", got)
				}
				s := got.GetSlots()
				if len(s) != 2 || s[0].GetType() != platformv1.LUKSKeyType_LUKS_KEY_TYPE_PASSPHRASE || s[1].GetType() != platformv1.LUKSKeyType_LUKS_KEY_TYPE_FIDO2 {
					t.Errorf("slots = %v", s)
				}
			},
		},
		{
			method: platformv1.LUKSService_EnrollPassphrase_FullMethodName, opcode: quicwire.OpLUKSCategory, subOp: quicwire.LUKSSubEnrollPassphrase,
			request:  &platformv1.LUKSEnrollPassphraseRequest{Device: "/dev/sda2", ExistingPassphrase: "old", NewPassphrase: "new"},
			wantWire: &quicwire.LUKSEnrollPassphraseReq{Device: "/dev/sda2", ExistingPassphrase: "old", NewPassphrase: "new"},
			wireResp: &quicwire.LUKSEnrollPassphraseResp{Slot: 3},
			reply:    &platformv1.LUKSEnrollPassphraseResponse{},
			check: func(t *testing.T, r interface{}) {
				if got := r.(*platformv1.LUKSEnrollPassphraseResponse).GetSlot(); got != 3 {
					t.Errorf("slot = %d", got)
				}
			},
		},
		{
			method: platformv1.LUKSService_EnrollFIDO2_FullMethodName, opcode: quicwire.OpLUKSCategory, subOp: quicwire.LUKSSubEnrollFIDO2,
			request:  &platformv1.LUKSEnrollFIDO2Request{Device: "/dev/sda2", ExistingPassphrase: "old", CredentialId: "cred", RequirePin: true, RequireUv: true},
			wantWire: &quicwire.LUKSEnrollFIDO2Req{Device: "/dev/sda2", ExistingPassphrase: "old", CredentialID: "cred", RequirePIN: true, RequireUV: true},
			wireResp: &quicwire.LUKSEnrollFIDO2Resp{Slot: 4, TokenID: "tok-f"},
			reply:    &platformv1.LUKSEnrollFIDO2Response{},
			check: func(t *testing.T, r interface{}) {
				got := r.(*platformv1.LUKSEnrollFIDO2Response)
				if got.GetSlot() != 4 || got.GetTokenId() != "tok-f" {
					t.Errorf("reply = %v", got)
				}
			},
		},
		{
			method: platformv1.LUKSService_EnrollTPM_FullMethodName, opcode: quicwire.OpLUKSCategory, subOp: quicwire.LUKSSubEnrollTPM,
			request:  &platformv1.LUKSEnrollTPMRequest{Device: "/dev/sda2", ExistingPassphrase: "old", Pcrs: []int32{0, 7}},
			wantWire: &quicwire.LUKSEnrollTPMReq{Device: "/dev/sda2", ExistingPassphrase: "old", PCRs: []int32{0, 7}},
			wireResp: &quicwire.LUKSEnrollTPMResp{Slot: 5, TokenID: "tok-t"},
			reply:    &platformv1.LUKSEnrollTPMResponse{},
			check: func(t *testing.T, r interface{}) {
				got := r.(*platformv1.LUKSEnrollTPMResponse)
				if got.GetSlot() != 5 || got.GetTokenId() != "tok-t" {
					t.Errorf("reply = %v", got)
				}
			},
		},
		{
			method: platformv1.LUKSService_EnrollRecovery_FullMethodName, opcode: quicwire.OpLUKSCategory, subOp: quicwire.LUKSSubEnrollRecovery,
			request:  &platformv1.LUKSEnrollRecoveryRequest{Device: "/dev/sda2", ExistingPassphrase: "old"},
			wantWire: &quicwire.LUKSEnrollRecoveryReq{Device: "/dev/sda2", ExistingPassphrase: "old"},
			wireResp: &quicwire.LUKSEnrollRecoveryResp{Slot: 6, RecoveryKey: "abcd-efgh"},
			reply:    &platformv1.LUKSEnrollRecoveryResponse{},
			check: func(t *testing.T, r interface{}) {
				got := r.(*platformv1.LUKSEnrollRecoveryResponse)
				if got.GetSlot() != 6 || got.GetRecoveryKey() != "abcd-efgh" {
					t.Errorf("reply = %v", got)
				}
			},
		},
		{
			method: platformv1.LUKSService_RemoveKey_FullMethodName, opcode: quicwire.OpLUKSCategory, subOp: quicwire.LUKSSubRemoveKey,
			request:  &platformv1.LUKSRemoveKeyRequest{Device: "/dev/sda2", Slot: 3},
			wantWire: &quicwire.LUKSRemoveKeyReq{Device: "/dev/sda2", Slot: 3},
			wireResp: &quicwire.LUKSRemoveKeyResp{Removed: true},
			reply:    &platformv1.LUKSRemoveKeyResponse{},
			check: func(t *testing.T, r interface{}) {
				if !r.(*platformv1.LUKSRemoveKeyResponse).GetRemoved() {
					t.Error("removed = false")
				}
			},
		},
		{
			method: platformv1.LUKSService_TestUnlock_FullMethodName, opcode: quicwire.OpLUKSCategory, subOp: quicwire.LUKSSubTestUnlock,
			request:  &platformv1.LUKSTestUnlockRequest{Device: "/dev/sda2", Slot: 1},
			wantWire: &quicwire.LUKSTestUnlockReq{Device: "/dev/sda2", Slot: 1},
			wireResp: &quicwire.LUKSTestUnlockResp{Unlocked: true},
			reply:    &platformv1.LUKSTestUnlockResponse{},
			check: func(t *testing.T, r interface{}) {
				if !r.(*platformv1.LUKSTestUnlockResponse).GetUnlocked() {
					t.Error("unlocked = false")
				}
			},
		},
		{
			method: platformv1.LUKSService_ChangePassphrase_FullMethodName, opcode: quicwire.OpLUKSCategory, subOp: quicwire.LUKSSubChangePassphrase,
			request:  &platformv1.LUKSChangePassphraseRequest{Device: "/dev/sda2", Slot: 0, OldPassphrase: "old", NewPassphrase: "new"},
			wantWire: &quicwire.LUKSChangePassphraseReq{Device: "/dev/sda2", Slot: 0, OldPassphrase: "old", NewPassphrase: "new"},
			wireResp: &quicwire.LUKSChangePassphraseResp{Changed: true},
			reply:    &platformv1.LUKSChangePassphraseResponse{},
			check: func(t *testing.T, r interface{}) {
				if !r.(*platformv1.LUKSChangePassphraseResponse).GetChanged() {
					t.Error("changed = false")
				}
			},
		},
	}
}

// TestLUKSServerErrorsPropagate checks every LUKS method reports the daemon's
// typed failure: the dispatcher answers ErrLUKSNotConfigured with
// StatusUnavailable and the error text, ErrLUKSRootRequired with
// StatusPermissionDenied, and both must reach the caller as that gRPC code
// with the daemon's message, never as an empty success.
func TestLUKSServerErrorsPropagate(t *testing.T) {
	serverErrors := []struct {
		status   byte
		message  string
		wantCode codes.Code
	}{
		{quicwire.StatusUnavailable, "luks: backend not configured", codes.Unavailable},
		{quicwire.StatusPermissionDenied, "luks: root privileges required", codes.PermissionDenied},
	}
	for _, tc := range luksCases() {
		for _, se := range serverErrors {
			t.Run(tc.method+"/"+se.wantCode.String(), func(t *testing.T) {
				sender := &recordingSender{sendRequestErr: &quicwire.ErrProtocol{Status: se.status, Message: se.message}}
				conn := newConnWithSender(t, sender)

				err := conn.Invoke(context.Background(), tc.method, tc.request, tc.reply)
				st, ok := status.FromError(err)
				if !ok || st.Code() != se.wantCode || st.Message() != se.message {
					t.Fatalf("Invoke error = %v, want %v %q", err, se.wantCode, se.message)
				}
			})
		}
	}
}
