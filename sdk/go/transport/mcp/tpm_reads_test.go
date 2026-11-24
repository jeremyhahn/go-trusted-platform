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
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"reflect"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

func tpmReadB64(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }

func TestTPMReadMethodsAreRouted(t *testing.T) {
	want := map[string]string{
		platformv1.TPMService_GetEK_FullMethodName:            "platform_tpm_ek",
		platformv1.TPMService_GetEKCertificate_FullMethodName: "platform_tpm_ek_cert",
		platformv1.TPMService_GetSRK_FullMethodName:           "platform_tpm_srk",
		platformv1.TPMService_GetPCRs_FullMethodName:          "platform_tpm_pcrs",
		platformv1.TPMService_GetEventLog_FullMethodName:      "platform_tpm_eventlog",
		platformv1.TPMService_GetRandom_FullMethodName:        "platform_tpm_random",
		platformv1.TPMService_GetAK_FullMethodName:            "platform_tpm_iak",
	}
	for method, tool := range want {
		if got := grpcMethodToMCPToolMap[method]; got != tool {
			t.Errorf("%s routes to %q, want %q", method, got, tool)
		}
	}
}

func TestInvoke_TPMGetEK_DecodesTheKey(t *testing.T) {
	var calls []toolCall
	adapter := provisioningTestServer(t, map[string]interface{}{
		"platform_tpm_ek": map[string]interface{}{
			"handle":     0x81010001,
			"public_key": tpmReadB64("ek-pub"),
			"algorithm":  "RSA",
		},
	}, &calls)

	reply := &platformv1.GetEKResponse{}
	if err := adapter.Connection().Invoke(context.Background(), platformv1.TPMService_GetEK_FullMethodName,
		&platformv1.GetEKRequest{}, reply); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if len(calls) != 1 || calls[0].Name != "platform_tpm_ek" {
		t.Fatalf("calls = %v, want one platform_tpm_ek call", calls)
	}
	if len(calls[0].Arguments) != 0 {
		t.Errorf("arguments = %v, want none", calls[0].Arguments)
	}
	if reply.GetHandle() != 0x81010001 || string(reply.GetPublicKey()) != "ek-pub" {
		t.Errorf("reply = %v, want handle 0x81010001 and the public key", reply)
	}
	if reply.GetAlgorithm() != platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED {
		t.Errorf("algorithm = %v, want unset (the tool reports the family only)", reply.GetAlgorithm())
	}
}

// TestInvoke_TPMGetAK_DecodesTheKeyAndName reads the platform AK (the
// IAK) through platform_tpm_iak and carries its TPM name, which the
// credential flow needs.
func TestInvoke_TPMGetAK_DecodesTheKeyAndName(t *testing.T) {
	var calls []toolCall
	adapter := provisioningTestServer(t, map[string]interface{}{
		"platform_tpm_iak": map[string]interface{}{
			"handle":     0x81010002,
			"public_key": tpmReadB64("ak-pub"),
			"algorithm":  "ECDSA",
			"name":       tpmReadB64("ak-name"),
		},
	}, &calls)

	reply := &platformv1.GetAKResponse{}
	if err := adapter.Connection().Invoke(context.Background(), platformv1.TPMService_GetAK_FullMethodName,
		&platformv1.GetAKRequest{}, reply); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if len(calls) != 1 || calls[0].Name != "platform_tpm_iak" {
		t.Fatalf("calls = %v, want one platform_tpm_iak call", calls)
	}
	if len(calls[0].Arguments) != 0 {
		t.Errorf("arguments = %v, want none", calls[0].Arguments)
	}
	if reply.GetHandle() != 0x81010002 || string(reply.GetPublicKey()) != "ak-pub" {
		t.Errorf("reply = %v, want handle 0x81010002 and the public key", reply)
	}
	if string(reply.GetName()) != "ak-name" {
		t.Errorf("name = %q, want the AK name", reply.GetName())
	}
	if reply.GetAlgorithm() != platformv1.KeyAlgorithm_KEY_ALGORITHM_UNSPECIFIED {
		t.Errorf("algorithm = %v, want unset (the tool reports the family only)", reply.GetAlgorithm())
	}
}

// TestInvoke_TPMGetAK_RefusesAHandle refuses an AK handle the tool cannot
// select, before any call is sent.
func TestInvoke_TPMGetAK_RefusesAHandle(t *testing.T) {
	var calls []toolCall
	adapter := provisioningTestServer(t, map[string]interface{}{}, &calls)
	err := adapter.Connection().Invoke(context.Background(), platformv1.TPMService_GetAK_FullMethodName,
		&platformv1.GetAKRequest{Handle: 5}, &platformv1.GetAKResponse{})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("err = %v, want InvalidArgument (ErrTPMReadFieldUnsupported)", err)
	}
	if len(calls) != 0 {
		t.Errorf("calls = %v, want none", calls)
	}
}

func TestInvoke_TPMGetEK_RefusesAnotherKey(t *testing.T) {
	for name, req := range map[string]*platformv1.GetEKRequest{
		"handle":    {Handle: 0x81010002},
		"algorithm": {Algorithm: platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256},
	} {
		t.Run(name, func(t *testing.T) {
			var calls []toolCall
			adapter := provisioningTestServer(t, map[string]interface{}{}, &calls)
			err := adapter.Connection().Invoke(context.Background(), platformv1.TPMService_GetEK_FullMethodName,
				req, &platformv1.GetEKResponse{})
			if status.Code(err) != codes.InvalidArgument {
				t.Errorf("err = %v, want InvalidArgument", err)
			}
			if len(calls) != 0 {
				t.Errorf("calls = %v, want none", calls)
			}
		})
	}
}

func TestInvoke_TPMGetEKCertificate_CarriesTheDER(t *testing.T) {
	var calls []toolCall
	adapter := provisioningTestServer(t, map[string]interface{}{
		"platform_tpm_ek_cert": map[string]interface{}{
			"certificate": tpmReadB64("der-bytes"),
		},
	}, &calls)

	reply := &platformv1.GetEKCertificateResponse{}
	if err := adapter.Connection().Invoke(context.Background(), platformv1.TPMService_GetEKCertificate_FullMethodName,
		&platformv1.GetEKCertificateRequest{}, reply); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if len(calls) != 1 || calls[0].Name != "platform_tpm_ek_cert" || len(calls[0].Arguments) != 0 {
		t.Fatalf("calls = %v, want one platform_tpm_ek_cert call with no arguments", calls)
	}
	if string(reply.GetCertificate()) != "der-bytes" || reply.GetFormat() != "DER" {
		t.Errorf("reply = %v, want the DER bytes and format DER", reply)
	}
}

func TestInvoke_TPMGetSRK_SendsTheHandle(t *testing.T) {
	var calls []toolCall
	adapter := provisioningTestServer(t, map[string]interface{}{
		"platform_tpm_srk": map[string]interface{}{
			"handle":     0x81000002,
			"public_key": tpmReadB64("srk-pub"),
			"algorithm":  "ECDSA",
		},
	}, &calls)

	reply := &platformv1.GetSRKResponse{}
	if err := adapter.Connection().Invoke(context.Background(), platformv1.TPMService_GetSRK_FullMethodName,
		&platformv1.GetSRKRequest{Handle: 0x81000002}, reply); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if len(calls) != 1 || calls[0].Name != "platform_tpm_srk" {
		t.Fatalf("calls = %v, want one platform_tpm_srk call", calls)
	}
	if got := calls[0].Arguments["handle"]; got != float64(0x81000002) {
		t.Errorf("handle argument = %v, want 0x81000002", got)
	}
	if reply.GetHandle() != 0x81000002 || string(reply.GetPublicKey()) != "srk-pub" {
		t.Errorf("reply = %v, want handle 0x81000002 and the public key", reply)
	}

	if err := adapter.Connection().Invoke(context.Background(), platformv1.TPMService_GetSRK_FullMethodName,
		&platformv1.GetSRKRequest{}, &platformv1.GetSRKResponse{}); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if len(calls) != 2 {
		t.Fatalf("calls = %v, want two", calls)
	}
	if got, ok := calls[1].Arguments["handle"]; !ok || got != float64(0) {
		t.Errorf("handle argument = %v (sent %v), want 0", got, ok)
	}

	err := adapter.Connection().Invoke(context.Background(), platformv1.TPMService_GetSRK_FullMethodName,
		&platformv1.GetSRKRequest{Algorithm: platformv1.KeyAlgorithm_KEY_ALGORITHM_ECDSA_P256}, &platformv1.GetSRKResponse{})
	if status.Code(err) != codes.InvalidArgument || len(calls) != 2 {
		t.Errorf("err = %v, calls = %d, want InvalidArgument and no call", err, len(calls))
	}
}

func TestInvoke_TPMGetPCRs_FlattensTheBanks(t *testing.T) {
	var calls []toolCall
	adapter := provisioningTestServer(t, map[string]interface{}{
		"platform_tpm_pcrs": map[string]interface{}{
			"banks": []interface{}{
				map[string]interface{}{"algorithm": "sha1", "pcrs": []interface{}{
					map[string]interface{}{"index": 0, "value": tpmReadB64("s1-0")},
					map[string]interface{}{"index": 7, "value": tpmReadB64("s1-7")},
				}},
				map[string]interface{}{"algorithm": "SHA256", "pcrs": []interface{}{
					map[string]interface{}{"index": 0, "value": tpmReadB64("s2-0")},
					map[string]interface{}{"index": 7, "value": tpmReadB64("s2-7")},
				}},
			},
		},
	}, &calls)

	reply := &platformv1.GetPCRsResponse{}
	if err := adapter.Connection().Invoke(context.Background(), platformv1.TPMService_GetPCRs_FullMethodName,
		&platformv1.GetPCRsRequest{Indices: []uint32{0, 7}}, reply); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if len(calls) != 1 || calls[0].Name != "platform_tpm_pcrs" {
		t.Fatalf("calls = %v, want one platform_tpm_pcrs call", calls)
	}
	if got := calls[0].Arguments["indices"]; !reflect.DeepEqual(got, []interface{}{float64(0), float64(7)}) {
		t.Errorf("indices argument = %v, want [0 7]", got)
	}
	type pcr struct {
		index uint32
		bank  platformv1.PCRBank
		value string
	}
	want := []pcr{
		{0, platformv1.PCRBank_PCR_BANK_SHA1, "s1-0"},
		{7, platformv1.PCRBank_PCR_BANK_SHA1, "s1-7"},
		{0, platformv1.PCRBank_PCR_BANK_SHA256, "s2-0"},
		{7, platformv1.PCRBank_PCR_BANK_SHA256, "s2-7"},
	}
	var got []pcr
	for _, v := range reply.GetPcrValues() {
		got = append(got, pcr{v.GetIndex(), v.GetBank(), string(v.GetValue())})
	}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("pcr values = %v, want %v", got, want)
	}

	reply = &platformv1.GetPCRsResponse{}
	if err := adapter.Connection().Invoke(context.Background(), platformv1.TPMService_GetPCRs_FullMethodName,
		&platformv1.GetPCRsRequest{Bank: platformv1.PCRBank_PCR_BANK_SHA256}, reply); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	got = nil
	for _, v := range reply.GetPcrValues() {
		got = append(got, pcr{v.GetIndex(), v.GetBank(), string(v.GetValue())})
	}
	if !reflect.DeepEqual(got, want[2:]) {
		t.Errorf("sha256 pcr values = %v, want %v", got, want[2:])
	}
}

func TestTPMReadDecoders_PCRBankNames(t *testing.T) {
	for _, tc := range []struct {
		in   interface{}
		want platformv1.PCRBank
	}{
		{"sha1", platformv1.PCRBank_PCR_BANK_SHA1},
		{"SHA-256", platformv1.PCRBank_PCR_BANK_SHA256},
		{"sha_384", platformv1.PCRBank_PCR_BANK_SHA384},
		{"sha512", platformv1.PCRBank_PCR_BANK_SHA512},
		{"sm3_256", platformv1.PCRBank_PCR_BANK_SM3_256},
		{float64(0x000B), platformv1.PCRBank_PCR_BANK_SHA256},
		{float64(0x0012), platformv1.PCRBank_PCR_BANK_SM3_256},
		{"md5", platformv1.PCRBank_PCR_BANK_UNSPECIFIED},
		{nil, platformv1.PCRBank_PCR_BANK_UNSPECIFIED},
	} {
		if got := tpmReadPCRBank(tc.in); got != tc.want {
			t.Errorf("tpmReadPCRBank(%v) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestInvoke_TPMGetEventLog_CarriesTheLog(t *testing.T) {
	var calls []toolCall
	adapter := provisioningTestServer(t, map[string]interface{}{
		"platform_tpm_eventlog": map[string]interface{}{
			"event_log":   tpmReadB64("log"),
			"format":      "tcg2",
			"event_count": 2,
			"entries": []map[string]interface{}{
				{
					"event_num": 0, "pcr_index": 0, "event_type": "EV_S_CRTM_VERSION", "digest_count": 1,
					"digests":    []map[string]interface{}{{"algorithm_id": "sha256", "digest": "ab01"}},
					"event_size": 16, "event_string": "crtm",
				},
				{
					"event_num": 1, "pcr_index": 7, "event_type": "EV_EFI_VARIABLE_DRIVER_CONFIG", "digest_count": 1,
					"digests":    []map[string]interface{}{{"algorithm_id": "sha256", "digest": "cd02"}},
					"event_size": 32, "event_string": "SecureBoot",
				},
			},
		},
	}, &calls)

	reply := &platformv1.GetEventLogResponse{}
	if err := adapter.Connection().Invoke(context.Background(), platformv1.TPMService_GetEventLog_FullMethodName,
		&platformv1.GetEventLogRequest{Format: "json"}, reply); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if len(calls) != 1 || calls[0].Name != "platform_tpm_eventlog" || len(calls[0].Arguments) != 0 {
		t.Fatalf("calls = %v, want one platform_tpm_eventlog call with no arguments", calls)
	}
	if string(reply.GetEventLog()) != "log" || reply.GetFormat() != "tcg2" || reply.GetEventCount() != 2 {
		t.Errorf("reply = %v, want the log, format tcg2 and 2 events", reply)
	}
	want := []*platformv1.EventLogEntry{
		{EventNum: 0, PcrIndex: 0, EventType: "EV_S_CRTM_VERSION", DigestCount: 1,
			Digests: []*platformv1.EventDigest{{AlgorithmId: "sha256", Digest: "ab01"}}, EventSize: 16, EventString: "crtm"},
		{EventNum: 1, PcrIndex: 7, EventType: "EV_EFI_VARIABLE_DRIVER_CONFIG", DigestCount: 1,
			Digests: []*platformv1.EventDigest{{AlgorithmId: "sha256", Digest: "cd02"}}, EventSize: 32, EventString: "SecureBoot"},
	}
	got := reply.GetEntries()
	if len(got) != len(want) {
		t.Fatalf("entries = %v, want %d entries (#2069)", got, len(want))
	}
	for i, w := range want {
		g := got[i]
		if g.GetEventNum() != w.GetEventNum() || g.GetPcrIndex() != w.GetPcrIndex() ||
			g.GetEventType() != w.GetEventType() || g.GetDigestCount() != w.GetDigestCount() ||
			g.GetEventSize() != w.GetEventSize() || g.GetEventString() != w.GetEventString() {
			t.Errorf("entry %d = %v, want %v", i, g, w)
		}
		if len(g.GetDigests()) != 1 || g.GetDigests()[0].GetAlgorithmId() != w.GetDigests()[0].GetAlgorithmId() ||
			g.GetDigests()[0].GetDigest() != w.GetDigests()[0].GetDigest() {
			t.Errorf("entry %d digests = %v, want %v", i, g.GetDigests(), w.GetDigests())
		}
	}
}

func TestInvoke_TPMGetRandom_CarriesTheBytes(t *testing.T) {
	random := []byte("0123456789abcdef")
	var calls []toolCall
	adapter := provisioningTestServer(t, map[string]interface{}{
		"platform_tpm_random": map[string]interface{}{
			"random_bytes": base64.StdEncoding.EncodeToString(random),
			"num_bytes":    16,
		},
	}, &calls)

	reply := &platformv1.GetRandomResponse{}
	if err := adapter.Connection().Invoke(context.Background(), platformv1.TPMService_GetRandom_FullMethodName,
		&platformv1.GetRandomRequest{NumBytes: 16}, reply); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if len(calls) != 1 || calls[0].Name != "platform_tpm_random" {
		t.Fatalf("calls = %v, want one platform_tpm_random call", calls)
	}
	if got := calls[0].Arguments["num_bytes"]; got != float64(16) {
		t.Errorf("num_bytes argument = %v, want 16", got)
	}
	if !bytes.Equal(reply.GetRandomBytes(), random) {
		t.Errorf("random bytes = %q, want %q", reply.GetRandomBytes(), random)
	}
}

func TestTPMReadDecoders_RejectWrongTypes(t *testing.T) {
	wrongReq := &platformv1.QuoteRequest{}
	wrongReply := &platformv1.QuoteResponse{}
	builders := map[string]mcpArgBuilder{
		"ek":      buildTPMReadEKArgs,
		"ek_cert": buildTPMReadEKCertificateArgs,
		"srk":     buildTPMReadSRKArgs,
		"pcrs":    buildTPMReadPCRsArgs,
		"log":     buildTPMReadEventLogArgs,
	}
	for name, build := range builders {
		var target ErrUnexpectedArgsType
		if _, err := build(wrongReq); !errors.As(err, &target) {
			t.Errorf("%s args: got %v, want ErrUnexpectedArgsType", name, err)
		}
	}
	replyDecoders := map[string]mcpReplyDecoder{
		"ek":  decodeTPMReadEKResult,
		"srk": decodeTPMReadSRKResult,
		"log": decodeTPMReadEventLogResult,
	}
	for name, decode := range replyDecoders {
		var target ErrUnexpectedReplyType
		if err := decode(map[string]interface{}{}, wrongReply); !errors.As(err, &target) {
			t.Errorf("%s reply: got %v, want ErrUnexpectedReplyType", name, err)
		}
	}
	requestReplyDecoders := map[string]mcpRequestReplyDecoder{
		"ek_cert": decodeTPMReadEKCertificateResult,
		"pcrs":    decodeTPMReadPCRsResult,
	}
	for name, decode := range requestReplyDecoders {
		var target ErrUnexpectedReplyType
		if err := decode(wrongReq, map[string]interface{}{}, wrongReply); !errors.As(err, &target) {
			t.Errorf("%s reply: got %v, want ErrUnexpectedReplyType", name, err)
		}
	}
}
