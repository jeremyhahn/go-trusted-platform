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
	"reflect"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestTPMSealNVMethodsAreRouted(t *testing.T) {
	want := map[string]string{
		platformv1.TPMService_Seal_FullMethodName:          "platform_tpm_seal",
		platformv1.TPMService_Unseal_FullMethodName:        "platform_tpm_unseal",
		platformv1.TPMService_ReadNVRAM_FullMethodName:     "platform_tpm_nv_read",
		platformv1.TPMService_WriteNVRAM_FullMethodName:    "platform_tpm_nv_write",
		platformv1.TPMService_UndefineNVRAM_FullMethodName: "platform_tpm_nv_delete",
	}
	for method, tool := range want {
		if got := grpcMethodToMCPToolMap[method]; got != tool {
			t.Errorf("%s routes to %q, want %q", method, got, tool)
		}
	}
	if got, ok := grpcMethodToMCPToolMap[platformv1.TPMService_DefineNVRAM_FullMethodName]; ok {
		t.Errorf("DefineNVRAM routes to %q, want no route (the server has no define tool)", got)
	}
}

func TestInvoke_TPMSeal_SendsTheToolArguments(t *testing.T) {
	var calls []toolCall
	adapter := provisioningTestServer(t, map[string]interface{}{
		"platform_tpm_seal": map[string]interface{}{"sealed_data": base64.StdEncoding.EncodeToString([]byte("blob"))},
	}, &calls)

	reply := &platformv1.SealResponse{}
	if err := adapter.Connection().Invoke(context.Background(), platformv1.TPMService_Seal_FullMethodName,
		&platformv1.SealRequest{Data: []byte("secret"), Cn: "disk-key", Password: "pw", PcrIndices: []uint32{0, 7}}, reply); err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if len(calls) != 1 || calls[0].Name != "platform_tpm_seal" {
		t.Fatalf("calls = %v, want one platform_tpm_seal call", calls)
	}
	want := map[string]interface{}{
		"data":     base64.StdEncoding.EncodeToString([]byte("secret")),
		"cn":       "disk-key",
		"password": "pw",
		"pcrs":     []interface{}{float64(0), float64(7)},
	}
	if !reflect.DeepEqual(calls[0].Arguments, want) {
		t.Errorf("wire args = %v, want %v", calls[0].Arguments, want)
	}
	if string(reply.GetSealedData()) != "blob" {
		t.Errorf("sealed data = %q, want %q", reply.GetSealedData(), "blob")
	}
	if !reply.GetStatus().GetSuccess() {
		t.Errorf("status = %v, want success", reply.GetStatus())
	}
}

func TestInvoke_TPMSeal_RefusesAnotherParent(t *testing.T) {
	cases := map[string]*platformv1.SealRequest{
		"parent_handle":   {Data: []byte("secret"), ParentHandle: 0x81000002},
		"parent_password": {Data: []byte("secret"), ParentPassword: "p"},
		"pcr_bank":        {Data: []byte("secret"), PcrBank: platformv1.PCRBank_PCR_BANK_SHA1},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			var calls []toolCall
			adapter := provisioningTestServer(t, map[string]interface{}{}, &calls)
			err := adapter.Connection().Invoke(context.Background(), platformv1.TPMService_Seal_FullMethodName,
				req, &platformv1.SealResponse{})
			if status.Code(err) != codes.InvalidArgument {
				t.Errorf("Invoke code = %v, want InvalidArgument", status.Code(err))
			}
			if len(calls) != 0 {
				t.Errorf("calls = %v, want no tool call", calls)
			}
		})
	}
}

func TestInvoke_TPMUnseal_RefusesAnotherParent(t *testing.T) {
	cases := map[string]*platformv1.UnsealRequest{
		"parent_handle":   {Cn: "disk-key", ParentHandle: 0x81000002},
		"parent_password": {Cn: "disk-key", ParentPassword: "p"},
		"pcr_bank":        {Cn: "disk-key", PcrBank: platformv1.PCRBank_PCR_BANK_SHA1},
	}
	for name, req := range cases {
		t.Run(name, func(t *testing.T) {
			var calls []toolCall
			adapter := provisioningTestServer(t, map[string]interface{}{}, &calls)
			err := adapter.Connection().Invoke(context.Background(), platformv1.TPMService_Unseal_FullMethodName,
				req, &platformv1.UnsealResponse{})
			if status.Code(err) != codes.InvalidArgument {
				t.Errorf("Invoke code = %v, want InvalidArgument", status.Code(err))
			}
			if len(calls) != 0 {
				t.Errorf("calls = %v, want no tool call", calls)
			}
		})
	}
}

func TestInvoke_TPMUnseal_CarriesTheData(t *testing.T) {
	var calls []toolCall
	adapter := provisioningTestServer(t, map[string]interface{}{
		"platform_tpm_unseal": map[string]interface{}{"data": base64.StdEncoding.EncodeToString([]byte("secret"))},
	}, &calls)

	reply := &platformv1.UnsealResponse{}
	if err := adapter.Connection().Invoke(context.Background(), platformv1.TPMService_Unseal_FullMethodName,
		&platformv1.UnsealRequest{Cn: "disk-key", Password: "pw"}, reply); err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if len(calls) != 1 || calls[0].Name != "platform_tpm_unseal" {
		t.Fatalf("calls = %v, want one platform_tpm_unseal call", calls)
	}
	want := map[string]interface{}{"cn": "disk-key", "password": "pw"}
	if !reflect.DeepEqual(calls[0].Arguments, want) {
		t.Errorf("wire args = %v, want %v", calls[0].Arguments, want)
	}
	if string(reply.GetData()) != "secret" {
		t.Errorf("data = %q, want %q", reply.GetData(), "secret")
	}
	if !reply.GetStatus().GetSuccess() {
		t.Errorf("status = %v, want success", reply.GetStatus())
	}
}

func TestInvoke_TPMReadNVRAM_CarriesTheData(t *testing.T) {
	var calls []toolCall
	adapter := provisioningTestServer(t, map[string]interface{}{
		"platform_tpm_nv_read": map[string]interface{}{
			"index": 0x01500000,
			"data":  base64.StdEncoding.EncodeToString([]byte("abcd")),
			"size":  4,
		},
	}, &calls)

	reply := &platformv1.ReadNVRAMResponse{}
	if err := adapter.Connection().Invoke(context.Background(), platformv1.TPMService_ReadNVRAM_FullMethodName,
		&platformv1.ReadNVRAMRequest{Index: 0x01500000, Size: 4, Offset: 2, Password: "pw"}, reply); err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if len(calls) != 1 || calls[0].Name != "platform_tpm_nv_read" {
		t.Fatalf("calls = %v, want one platform_tpm_nv_read call", calls)
	}
	args := calls[0].Arguments
	if args["index"] != float64(0x01500000) || args["size"] != float64(4) ||
		args["offset"] != float64(2) || args["password"] != "pw" {
		t.Errorf("wire args = %v, want index, size, offset and password", args)
	}
	if string(reply.GetData()) != "abcd" {
		t.Errorf("data = %q, want %q", reply.GetData(), "abcd")
	}
}

func TestInvoke_TPMWriteNVRAM_CarriesTheStatus(t *testing.T) {
	var calls []toolCall
	adapter := provisioningTestServer(t, map[string]interface{}{
		"platform_tpm_nv_write": map[string]interface{}{"success": true, "message": "wrote 4 bytes"},
	}, &calls)

	reply := &platformv1.WriteNVRAMResponse{}
	if err := adapter.Connection().Invoke(context.Background(), platformv1.TPMService_WriteNVRAM_FullMethodName,
		&platformv1.WriteNVRAMRequest{Index: 0x01500000, Data: []byte("abcd")}, reply); err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if len(calls) != 1 || calls[0].Name != "platform_tpm_nv_write" {
		t.Fatalf("calls = %v, want one platform_tpm_nv_write call", calls)
	}
	args := calls[0].Arguments
	if args["index"] != float64(0x01500000) || args["data"] != base64.StdEncoding.EncodeToString([]byte("abcd")) {
		t.Errorf("wire args = %v, want index and base64 data", args)
	}
	if !reply.GetStatus().GetSuccess() || reply.GetStatus().GetMessage() != "wrote 4 bytes" {
		t.Errorf("status = %v, want the daemon's success", reply.GetStatus())
	}
}

func TestInvoke_TPMUndefineNVRAM_SendsTheOwnerAuth(t *testing.T) {
	var calls []toolCall
	adapter := provisioningTestServer(t, map[string]interface{}{
		"platform_tpm_nv_delete": map[string]interface{}{"success": true, "message": "undefined"},
	}, &calls)

	reply := &platformv1.UndefineNVRAMResponse{}
	if err := adapter.Connection().Invoke(context.Background(), platformv1.TPMService_UndefineNVRAM_FullMethodName,
		&platformv1.UndefineNVRAMRequest{Index: 0x01500000, ParentPassword: "owner"}, reply); err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if len(calls) != 1 || calls[0].Name != "platform_tpm_nv_delete" {
		t.Fatalf("calls = %v, want one platform_tpm_nv_delete call", calls)
	}
	want := map[string]interface{}{"index": float64(0x01500000), "parent_password": "owner"}
	if !reflect.DeepEqual(calls[0].Arguments, want) {
		t.Errorf("wire args = %v, want %v", calls[0].Arguments, want)
	}
	if !reply.GetStatus().GetSuccess() || reply.GetStatus().GetMessage() != "undefined" {
		t.Errorf("status = %v, want the daemon's success", reply.GetStatus())
	}

	calls = nil
	err := adapter.Connection().Invoke(context.Background(), platformv1.TPMService_UndefineNVRAM_FullMethodName,
		&platformv1.UndefineNVRAMRequest{Index: 0x01500000, Password: "x"}, &platformv1.UndefineNVRAMResponse{})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("Invoke code = %v, want InvalidArgument for an index password", status.Code(err))
	}
	if len(calls) != 0 {
		t.Errorf("calls = %v, want no tool call", calls)
	}
}

func TestTPMSealNVDecoders_RejectWrongTypes(t *testing.T) {
	wrongReq := &platformv1.QuoteRequest{}
	builders := map[string]mcpArgBuilder{
		"seal":     buildTPMSealNVSealArgs,
		"unseal":   buildTPMSealNVUnsealArgs,
		"undefine": buildTPMSealNVUndefineArgs,
	}
	for name, build := range builders {
		var wrongArgs ErrUnexpectedArgsType
		if _, err := build(wrongReq); !errors.As(err, &wrongArgs) {
			t.Errorf("%s args: got %v, want ErrUnexpectedArgsType", name, err)
		}
	}

	wrongReply := &platformv1.QuoteResponse{}
	decoders := map[string]mcpReplyDecoder{
		"seal":     decodeTPMSealNVSealResult,
		"unseal":   decodeTPMSealNVUnsealResult,
		"write":    decodeTPMSealNVWriteResult,
		"undefine": decodeTPMSealNVUndefineResult,
	}
	for name, decode := range decoders {
		var wrong ErrUnexpectedReplyType
		if err := decode(map[string]interface{}{}, wrongReply); !errors.As(err, &wrong) {
			t.Errorf("%s reply: got %v, want ErrUnexpectedReplyType", name, err)
		}
	}
}

func TestTPMSealNVFieldUnsupported_Message(t *testing.T) {
	err := ErrTPMSealNVFieldUnsupported{Method: "Seal", Field: "parent_handle"}
	if got, want := err.Error(), "Seal: parent_handle is not supported over MCP"; got != want {
		t.Errorf("Error() = %q, want %q", got, want)
	}
}
