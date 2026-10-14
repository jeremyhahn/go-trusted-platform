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
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"reflect"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/mcpwire"
)

// luksMCPCase drives one LUKSService method through the platform_luks_*
// tool: the arguments the server reads (pkg/api/daemon/mcp_phase35.go) and
// the result it renders, which for status, slots, info and enroll is the
// daemon's untagged domain struct with Go-named keys.
type luksMCPCase struct {
	method   string
	request  interface{}
	wantArgs map[string]interface{}
	result   interface{}
	reply    interface{}
	check    func(t *testing.T, reply interface{})
}

func luksMCPCases() []luksMCPCase {
	return []luksMCPCase{
		{
			method:   platformv1.LUKSService_Status_FullMethodName,
			request:  &platformv1.LUKSStatusRequest{Device: "/dev/sda2"},
			wantArgs: map[string]interface{}{"device": "/dev/sda2"},
			result: map[string]interface{}{"Device": "/dev/sda2", "IsLUKS": true, "Version": 2, "UUID": "u-1",
				"Label": "root", "Cipher": "aes-xts-plain64", "ActiveSlots": []interface{}{0, 2}},
			reply: &platformv1.LUKSStatusResponse{},
			check: func(t *testing.T, r interface{}) {
				got := r.(*platformv1.LUKSStatusResponse)
				if !got.GetIsLuks() || got.GetUuid() != "u-1" || got.GetVersion() != 2 || len(got.GetActiveSlots()) != 2 {
					t.Errorf("reply = %v", got)
				}
			},
		},
		{
			method:   platformv1.LUKSService_ListSlots_FullMethodName,
			request:  &platformv1.LUKSListSlotsRequest{Device: "/dev/sda2"},
			wantArgs: map[string]interface{}{"device": "/dev/sda2"},
			result: map[string]interface{}{"Device": "/dev/sda2",
				"Slots": []interface{}{map[string]interface{}{"Slot": 1, "Type": "tpm", "KeySize": 512, "Priority": 1}}},
			reply: &platformv1.LUKSListSlotsResponse{},
			check: func(t *testing.T, r interface{}) {
				s := r.(*platformv1.LUKSListSlotsResponse).GetSlots()
				if len(s) != 1 || s[0].GetSlot() != 1 || s[0].GetType() != platformv1.LUKSKeyType_LUKS_KEY_TYPE_TPM || s[0].GetKeySize() != 512 {
					t.Errorf("slots = %v", s)
				}
			},
		},
		{
			method:   platformv1.LUKSService_Info_FullMethodName,
			request:  &platformv1.LUKSInfoRequest{Device: "/dev/sda2"},
			wantArgs: map[string]interface{}{"device": "/dev/sda2"},
			result: map[string]interface{}{"Device": "/dev/sda2", "UUID": "u-1", "Version": 2, "KeySize": 512, "SectorSize": 4096,
				"Slots": []interface{}{map[string]interface{}{"Slot": 0, "Type": "recovery"}}, "MetadataJSON": "{}"},
			reply: &platformv1.LUKSInfoResponse{},
			check: func(t *testing.T, r interface{}) {
				got := r.(*platformv1.LUKSInfoResponse)
				if got.GetUuid() != "u-1" || got.GetSectorSize() != 4096 || got.GetMetadataJson() != "{}" ||
					len(got.GetSlots()) != 1 || got.GetSlots()[0].GetType() != platformv1.LUKSKeyType_LUKS_KEY_TYPE_RECOVERY {
					t.Errorf("reply = %v", got)
				}
			},
		},
		{
			method:   platformv1.LUKSService_EnrollPassphrase_FullMethodName,
			request:  &platformv1.LUKSEnrollPassphraseRequest{Device: "/dev/sda2", ExistingPassphrase: "old", NewPassphrase: "new"},
			wantArgs: map[string]interface{}{"device": "/dev/sda2", "existing_passphrase": "old", "new_passphrase": "new"},
			result:   map[string]interface{}{"Slot": 3},
			reply:    &platformv1.LUKSEnrollPassphraseResponse{},
			check: func(t *testing.T, r interface{}) {
				if got := r.(*platformv1.LUKSEnrollPassphraseResponse).GetSlot(); got != 3 {
					t.Errorf("slot = %d", got)
				}
			},
		},
		{
			method:  platformv1.LUKSService_EnrollFIDO2_FullMethodName,
			request: &platformv1.LUKSEnrollFIDO2Request{Device: "/dev/sda2", ExistingPassphrase: "old", CredentialId: "cred", RequirePin: true, RequireUv: true},
			wantArgs: map[string]interface{}{"device": "/dev/sda2", "existing_passphrase": "old", "credential_id": "cred",
				"require_pin": true, "require_uv": true},
			result: map[string]interface{}{"Slot": 4, "TokenID": "tok-f"},
			reply:  &platformv1.LUKSEnrollFIDO2Response{},
			check: func(t *testing.T, r interface{}) {
				got := r.(*platformv1.LUKSEnrollFIDO2Response)
				if got.GetSlot() != 4 || got.GetTokenId() != "tok-f" {
					t.Errorf("reply = %v", got)
				}
			},
		},
		{
			method:  platformv1.LUKSService_EnrollTPM_FullMethodName,
			request: &platformv1.LUKSEnrollTPMRequest{Device: "/dev/sda2", ExistingPassphrase: "old", Pcrs: []int32{0, 7}, Handle: "0x81000001"},
			wantArgs: map[string]interface{}{"device": "/dev/sda2", "existing_passphrase": "old",
				"pcrs": []interface{}{float64(0), float64(7)}, "handle": "0x81000001"},
			result: map[string]interface{}{"Slot": 5, "TokenID": "tok-t"},
			reply:  &platformv1.LUKSEnrollTPMResponse{},
			check: func(t *testing.T, r interface{}) {
				got := r.(*platformv1.LUKSEnrollTPMResponse)
				if got.GetSlot() != 5 || got.GetTokenId() != "tok-t" {
					t.Errorf("reply = %v", got)
				}
			},
		},
		{
			method:   platformv1.LUKSService_EnrollRecovery_FullMethodName,
			request:  &platformv1.LUKSEnrollRecoveryRequest{Device: "/dev/sda2", ExistingPassphrase: "old"},
			wantArgs: map[string]interface{}{"device": "/dev/sda2", "existing_passphrase": "old"},
			result:   map[string]interface{}{"Slot": 6, "RecoveryKey": "abcd-efgh"},
			reply:    &platformv1.LUKSEnrollRecoveryResponse{},
			check: func(t *testing.T, r interface{}) {
				got := r.(*platformv1.LUKSEnrollRecoveryResponse)
				if got.GetSlot() != 6 || got.GetRecoveryKey() != "abcd-efgh" {
					t.Errorf("reply = %v", got)
				}
			},
		},
		{
			method:   platformv1.LUKSService_RemoveKey_FullMethodName,
			request:  &platformv1.LUKSRemoveKeyRequest{Device: "/dev/sda2", Slot: 3},
			wantArgs: map[string]interface{}{"device": "/dev/sda2", "slot": float64(3)},
			result:   map[string]interface{}{"removed": true},
			reply:    &platformv1.LUKSRemoveKeyResponse{},
			check: func(t *testing.T, r interface{}) {
				if !r.(*platformv1.LUKSRemoveKeyResponse).GetRemoved() {
					t.Error("removed = false")
				}
			},
		},
		{
			method:   platformv1.LUKSService_TestUnlock_FullMethodName,
			request:  &platformv1.LUKSTestUnlockRequest{Device: "/dev/sda2", Slot: 1},
			wantArgs: map[string]interface{}{"device": "/dev/sda2", "slot": float64(1)},
			result:   map[string]interface{}{"unlocked": true},
			reply:    &platformv1.LUKSTestUnlockResponse{},
			check: func(t *testing.T, r interface{}) {
				if !r.(*platformv1.LUKSTestUnlockResponse).GetUnlocked() {
					t.Error("unlocked = false")
				}
			},
		},
		{
			method:  platformv1.LUKSService_ChangePassphrase_FullMethodName,
			request: &platformv1.LUKSChangePassphraseRequest{Device: "/dev/sda2", Slot: 2, OldPassphrase: "old", NewPassphrase: "new"},
			wantArgs: map[string]interface{}{"device": "/dev/sda2", "slot": float64(2),
				"old_passphrase": "old", "new_passphrase": "new"},
			result: map[string]interface{}{"changed": true},
			reply:  &platformv1.LUKSChangePassphraseResponse{},
			check: func(t *testing.T, r interface{}) {
				if !r.(*platformv1.LUKSChangePassphraseResponse).GetChanged() {
					t.Error("changed = false")
				}
			},
		},
	}
}

// TestLUKSMCP_InvokeTranslatesBothDirections drives every LUKS method through
// Invoke and asserts the tool called, the arguments it receives and the pb
// reply built from the server's result.
func TestLUKSMCP_InvokeTranslatesBothDirections(t *testing.T) {
	cases := luksMCPCases()
	if len(cases) != len(platformv1.LUKSService_ServiceDesc.Methods) {
		t.Fatalf("table covers %d methods, want all %d", len(cases), len(platformv1.LUKSService_ServiceDesc.Methods))
	}
	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			tool := phase35ToolMap[tc.method]
			calls, err := invokePhase35(t, map[string]interface{}{tool: tc.result}, tc.method, tc.request, tc.reply)
			if err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			if len(calls) != 1 || calls[0].Name != tool {
				t.Fatalf("calls = %+v, want one call to %s", calls, tool)
			}
			if !reflect.DeepEqual(calls[0].Arguments, tc.wantArgs) {
				t.Errorf("arguments = %v, want %v", calls[0].Arguments, tc.wantArgs)
			}
			tc.check(t, tc.reply)
		})
	}
}

// TestLUKSMCP_UnknownKeyslotTypeRefused checks a keyslot type the SDK does
// not know is refused as Internal rather than reported as UNSPECIFIED.
func TestLUKSMCP_UnknownKeyslotTypeRefused(t *testing.T) {
	slots := map[string]interface{}{"Slots": []interface{}{map[string]interface{}{"Slot": 1, "Type": "smartcard"}}}
	results := map[string]interface{}{"platform_luks_list_slots": slots, "platform_luks_info": slots}

	_, err := invokePhase35(t, results, platformv1.LUKSService_ListSlots_FullMethodName,
		&platformv1.LUKSListSlotsRequest{Device: "/dev/sda2"}, &platformv1.LUKSListSlotsResponse{})
	requireCode(t, err, codes.Internal)

	_, err = invokePhase35(t, results, platformv1.LUKSService_Info_FullMethodName,
		&platformv1.LUKSInfoRequest{Device: "/dev/sda2"}, &platformv1.LUKSInfoResponse{})
	requireCode(t, err, codes.Internal)
}

// luksFailingAdapter answers every tool call with the JSON-RPC error the
// server sends for a failed tool (pkg/api/mcp/error_class.go::toolErrorCode)
// and records the tool called. Its client does not retry, so the error
// arrives at once.
func luksFailingAdapter(t *testing.T, code int, message string, tools *[]string) *Adapter {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req mcpwire.JSONRPCRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		params, _ := req.Params.(map[string]interface{})
		name, _ := params["name"].(string)
		*tools = append(*tools, name)
		resp := mcpwire.JSONRPCResponse{JSONRPC: "2.0", ID: req.ID, Error: &mcpwire.JSONRPCError{Code: code, Message: message}}
		if err := json.NewEncoder(w).Encode(resp); err != nil {
			t.Errorf("encode response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	config := mcpwire.DefaultClientConfig(server.URL)
	config.MaxRetries = 0
	client, err := mcpwire.NewClient(config)
	if err != nil {
		t.Fatalf("NewClient: %v", err)
	}
	a := &Adapter{client: client, address: server.URL, timeout: 5 * time.Second}
	a.connected.Store(true)
	t.Cleanup(func() { _ = a.Close() })
	return a
}

// TestLUKSMCP_ServerErrorsPropagate checks every LUKS method reports the
// server's failure as its gRPC class with the server's message, never as an
// empty success: an unconfigured LUKS provider is Unavailable
// (ErrPhase35NotConfigured) and an unclassified daemon failure Internal.
func TestLUKSMCP_ServerErrorsPropagate(t *testing.T) {
	serverErrors := []struct {
		code     int
		message  string
		wantCode codes.Code
	}{
		{mcpwire.CodeForClass(codes.Unavailable), "phase35: service provider not configured", codes.Unavailable},
		{mcpwire.InternalError, "luks: cryptsetup luksAddKey failed", codes.Internal},
	}
	for _, tc := range luksMCPCases() {
		for _, se := range serverErrors {
			t.Run(tc.method+"/"+se.wantCode.String(), func(t *testing.T) {
				var tools []string
				a := luksFailingAdapter(t, se.code, se.message, &tools)

				err := a.Connection().Invoke(context.Background(), tc.method, tc.request, tc.reply)
				st, ok := status.FromError(err)
				if !ok || st.Code() != se.wantCode || st.Message() != se.message {
					t.Fatalf("Invoke error = %v, want %v %q", err, se.wantCode, se.message)
				}
				if len(tools) != 1 || tools[0] != phase35ToolMap[tc.method] {
					t.Errorf("tools called = %v, want [%s]", tools, phase35ToolMap[tc.method])
				}
			})
		}
	}
}
