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
	"errors"
	"reflect"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func TestInvoke_TPMGetCapabilities_CarriesTheToolsLists(t *testing.T) {
	var calls []toolCall
	adapter := provisioningTestServer(t, map[string]interface{}{
		"platform_tpm_capabilities": map[string]interface{}{
			"algorithms": []string{"RSA", "ECC"},
			"commands":   []string{"TPM2_Quote"},
			"ecc_curves": []string{"P256"},
		},
	}, &calls)

	reply := &platformv1.TPMCapabilitiesResponse{}
	if err := adapter.Connection().Invoke(context.Background(), platformv1.TPMService_GetCapabilities_FullMethodName,
		&platformv1.TPMCapabilitiesRequest{}, reply); err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if len(calls) != 1 || calls[0].Name != "platform_tpm_capabilities" {
		t.Fatalf("calls = %v, want one platform_tpm_capabilities call", calls)
	}
	if !reflect.DeepEqual(reply.GetAlgorithms(), []string{"RSA", "ECC"}) ||
		!reflect.DeepEqual(reply.GetCommands(), []string{"TPM2_Quote"}) ||
		!reflect.DeepEqual(reply.GetEccCurves(), []string{"P256"}) {
		t.Errorf("reply = %v, want every capability list carried", reply)
	}
}

func TestInvoke_TPMGetPlatformAttributes_FoldsTheKeyFields(t *testing.T) {
	var calls []toolCall
	adapter := provisioningTestServer(t, map[string]interface{}{
		"platform_tpm_platform": map[string]interface{}{
			"available":     true,
			"device":        "/dev/tpmrm0",
			"is_fips":       true,
			"pcr_extended":  true,
			"can_seal":      true,
			"is_simulator":  true,
			"manufacturer":  "IBM",
			"ek_handle":     0x81010001,
			"ek_algorithm":  "RSA",
			"srk_handle":    0,
			"srk_algorithm": "ECC",
		},
	}, &calls)

	reply := &platformv1.TPMPlatformAttributesResponse{}
	if err := adapter.Connection().Invoke(context.Background(), platformv1.TPMService_GetPlatformAttributes_FullMethodName,
		&platformv1.TPMPlatformAttributesRequest{}, reply); err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if len(calls) != 1 || calls[0].Name != "platform_tpm_platform" {
		t.Fatalf("calls = %v, want one platform_tpm_platform call", calls)
	}
	if reply.GetDevice() != "/dev/tpmrm0" || !reply.GetIsFips() || !reply.GetPcrExtended() ||
		!reply.GetCanSeal() || !reply.GetIsSimulator() || reply.GetManufacturer() != "IBM" {
		t.Errorf("reply = %v, want every attribute carried", reply)
	}
	if reply.GetEk().GetHandle() != 0x81010001 || reply.GetEk().GetAlgorithm() != "RSA" {
		t.Errorf("ek = %v, want 0x81010001 RSA", reply.GetEk())
	}
	// Handle 0 is a real key reference, not an absent one.
	if reply.GetSrk() == nil || reply.GetSrk().GetHandle() != 0 || reply.GetSrk().GetAlgorithm() != "ECC" {
		t.Errorf("srk = %v, want handle 0 ECC", reply.GetSrk())
	}
	if reply.GetIak() != nil {
		t.Errorf("iak = %v, want absent for an unprovisioned key", reply.GetIak())
	}
}

func TestInvoke_TPMExtendPCR_SendsTheToolsArgumentsAndReturnsItsStatus(t *testing.T) {
	var calls []toolCall
	adapter := provisioningTestServer(t, map[string]interface{}{
		"platform_tpm_pcr_extend": map[string]interface{}{"success": true, "message": "PCR 16 extended"},
	}, &calls)

	reply := &platformv1.ExtendPCRResponse{}
	if err := adapter.Connection().Invoke(context.Background(), platformv1.TPMService_ExtendPCR_FullMethodName,
		&platformv1.ExtendPCRRequest{Index: 16, HashAlg: "sha256", Data: []byte("measure")}, reply); err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if len(calls) != 1 || calls[0].Name != "platform_tpm_pcr_extend" {
		t.Fatalf("calls = %v, want one platform_tpm_pcr_extend call", calls)
	}
	want := map[string]interface{}{"pcr_index": float64(16), "hash_alg": "sha256", "data": "bWVhc3VyZQ=="}
	if !reflect.DeepEqual(calls[0].Arguments, want) {
		t.Errorf("wire args = %v, want %v", calls[0].Arguments, want)
	}
	if !reply.GetStatus().GetSuccess() || reply.GetStatus().GetMessage() != "PCR 16 extended" {
		t.Errorf("status = %v, want the daemon's success", reply.GetStatus())
	}
}

func TestInvoke_TPMAttrs_UndecodableResultIsInternal(t *testing.T) {
	cases := []struct {
		method string
		tool   string
		req    interface{}
		reply  interface{}
	}{
		{platformv1.TPMService_GetPlatformAttributes_FullMethodName, "platform_tpm_platform",
			&platformv1.TPMPlatformAttributesRequest{}, &platformv1.TPMPlatformAttributesResponse{}},
		{platformv1.TPMService_ExtendPCR_FullMethodName, "platform_tpm_pcr_extend",
			&platformv1.ExtendPCRRequest{Index: 16}, &platformv1.ExtendPCRResponse{}},
	}
	for _, tc := range cases {
		t.Run(tc.tool, func(t *testing.T) {
			var calls []toolCall
			adapter := provisioningTestServer(t, map[string]interface{}{
				tc.tool: map[string]interface{}{"device": 7, "success": "yes", "ek_handle": -1},
			}, &calls)
			err := adapter.Connection().Invoke(context.Background(), tc.method, tc.req, tc.reply)
			if status.Code(err) != codes.Internal {
				t.Errorf("Invoke code = %v, want Internal for a result of the wrong shape", status.Code(err))
			}
		})
	}
}

func TestTPMAttrsMapping_RefusesTheWrongTypes(t *testing.T) {
	var wrongArgs ErrUnexpectedArgsType
	if _, err := buildTPMExtendPCRArgs(&platformv1.QuoteRequest{}); !errors.As(err, &wrongArgs) {
		t.Errorf("extend args: got %v, want ErrUnexpectedArgsType", err)
	}
	var wrongReply ErrUnexpectedReplyType
	if err := decodeTPMExtendPCRResult(map[string]interface{}{}, &platformv1.QuoteResponse{}); !errors.As(err, &wrongReply) {
		t.Errorf("extend reply: got %v, want ErrUnexpectedReplyType", err)
	}
	if err := decodeTPMPlatformResult(map[string]interface{}{}, &platformv1.QuoteResponse{}); !errors.As(err, &wrongReply) {
		t.Errorf("platform reply: got %v, want ErrUnexpectedReplyType", err)
	}
}
