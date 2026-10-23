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
	"bytes"
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// replyPayload encodes a daemon reply for the recording sender to return.
func replyPayload(t *testing.T, reply interface{}) []byte {
	t.Helper()
	payload, err := quicwire.EncodePayload(reply)
	if err != nil {
		t.Fatalf("encode reply: %v", err)
	}
	return payload
}

// assertTPM2SubOpcode checks the call went out on the TPM2 category with the
// given sub-opcode first.
func assertTPM2SubOpcode(t *testing.T, sender *recordingSender, sub byte) {
	t.Helper()
	if sender.rawOpcode != quicwire.OpTPM2Category {
		t.Errorf("opcode = 0x%02X, want OpTPM2Category (0x%02X)", sender.rawOpcode, quicwire.OpTPM2Category)
	}
	if len(sender.rawPayload) == 0 || sender.rawPayload[0] != sub {
		t.Fatalf("payload = %x, want sub-opcode 0x%02X first", sender.rawPayload, sub)
	}
}

func TestInvoke_TPMGetCapabilities_ReachesHandleCapabilities(t *testing.T) {
	sender := &recordingSender{respPayload: replyPayload(t, &quicwire.TPM2CapabilitiesResponse{
		Algorithms: []string{"RSA", "ECC"},
		Commands:   []string{"TPM2_Quote"},
		ECCCurves:  []string{"P256"},
	})}
	conn := newConnWithSender(t, sender)

	reply := &platformv1.TPMCapabilitiesResponse{}
	if err := conn.Invoke(context.Background(), platformv1.TPMService_GetCapabilities_FullMethodName,
		&platformv1.TPMCapabilitiesRequest{}, reply); err != nil {
		t.Fatalf("Invoke() unexpected error: %v", err)
	}

	assertTPM2SubOpcode(t, sender, quicwire.SubOpTPM2Capabilities)
	if len(sender.rawPayload) != 1 {
		t.Errorf("payload = %x, want the sub-opcode only (empty body)", sender.rawPayload)
	}
	if len(reply.GetAlgorithms()) != 2 || reply.GetCommands()[0] != "TPM2_Quote" || reply.GetEccCurves()[0] != "P256" {
		t.Errorf("reply = %v, want every capability list carried", reply)
	}
}

func TestInvoke_TPMGetPlatformAttributes_CarriesTheKeyRefs(t *testing.T) {
	sender := &recordingSender{respPayload: replyPayload(t, &quicwire.TPM2PlatformAttributesResponse{
		Device:       "/dev/tpmrm0",
		IsFIPS:       true,
		PCRExtended:  true,
		CanSeal:      true,
		IsSimulator:  true,
		Manufacturer: "IBM",
		EK:           &quicwire.TPM2KeyRef{Handle: 0x81010001, Algorithm: "RSA"},
		SRK:          &quicwire.TPM2KeyRef{Handle: 0x81000001, Algorithm: "ECC"},
	})}
	conn := newConnWithSender(t, sender)

	reply := &platformv1.TPMPlatformAttributesResponse{}
	if err := conn.Invoke(context.Background(), platformv1.TPMService_GetPlatformAttributes_FullMethodName,
		&platformv1.TPMPlatformAttributesRequest{}, reply); err != nil {
		t.Fatalf("Invoke() unexpected error: %v", err)
	}

	assertTPM2SubOpcode(t, sender, quicwire.SubOpTPM2PlatformAttrs)
	if reply.GetDevice() != "/dev/tpmrm0" || !reply.GetIsFips() || !reply.GetPcrExtended() ||
		!reply.GetCanSeal() || !reply.GetIsSimulator() || reply.GetManufacturer() != "IBM" {
		t.Errorf("reply = %v, want every attribute carried", reply)
	}
	if reply.GetEk().GetHandle() != 0x81010001 || reply.GetEk().GetAlgorithm() != "RSA" {
		t.Errorf("ek = %v, want 0x81010001 RSA", reply.GetEk())
	}
	if reply.GetSrk().GetHandle() != 0x81000001 || reply.GetSrk().GetAlgorithm() != "ECC" {
		t.Errorf("srk = %v, want 0x81000001 ECC", reply.GetSrk())
	}
	if reply.GetIak() != nil {
		t.Errorf("iak = %v, want absent for an unprovisioned key", reply.GetIak())
	}
}

func TestInvoke_TPMExtendPCR_SendsTheExtendAndReturnsItsStatus(t *testing.T) {
	sender := &recordingSender{respPayload: replyPayload(t, &quicwire.TPM2StatusResponse{
		Success: true, Message: "PCR 16 extended",
	})}
	conn := newConnWithSender(t, sender)

	reply := &platformv1.ExtendPCRResponse{}
	if err := conn.Invoke(context.Background(), platformv1.TPMService_ExtendPCR_FullMethodName,
		&platformv1.ExtendPCRRequest{Index: 16, HashAlg: "sha256", Data: []byte("measure")}, reply); err != nil {
		t.Fatalf("Invoke() unexpected error: %v", err)
	}

	assertTPM2SubOpcode(t, sender, quicwire.SubOpTPM2ExtendPCR)
	var got quicwire.TPM2ExtendPCRRequest
	if err := quicwire.DecodePayload(sender.rawPayload[1:], &got); err != nil {
		t.Fatalf("payload[1:] decode failed: %v", err)
	}
	if got.PCRIndex != 16 || got.HashAlg != "sha256" || !bytes.Equal(got.Data, []byte("measure")) {
		t.Errorf("server request = %+v, want PCR 16 sha256 \"measure\"", got)
	}
	if !reply.GetStatus().GetSuccess() || reply.GetStatus().GetMessage() != "PCR 16 extended" {
		t.Errorf("status = %v, want the daemon's success", reply.GetStatus())
	}
}

func TestInvoke_TPMExtendPCR_RefusesTheWrongRequestType(t *testing.T) {
	sender := &recordingSender{}
	conn := newConnWithSender(t, sender)

	err := conn.Invoke(context.Background(), platformv1.TPMService_ExtendPCR_FullMethodName,
		&platformv1.QuoteRequest{}, &platformv1.ExtendPCRResponse{})
	if status.Code(err) != codes.InvalidArgument {
		t.Errorf("Invoke() code = %v, want InvalidArgument", status.Code(err))
	}
	if sender.rawCalls != 0 {
		t.Errorf("SendRequest calls = %d, want none for a refused request", sender.rawCalls)
	}
}

func TestInvoke_TPMAttrs_GarbageReplyIsInternal(t *testing.T) {
	cases := map[string]interface{}{
		platformv1.TPMService_GetCapabilities_FullMethodName:       &platformv1.TPMCapabilitiesResponse{},
		platformv1.TPMService_GetPlatformAttributes_FullMethodName: &platformv1.TPMPlatformAttributesResponse{},
		platformv1.TPMService_ExtendPCR_FullMethodName:             &platformv1.ExtendPCRResponse{},
	}
	requests := map[string]interface{}{
		platformv1.TPMService_GetCapabilities_FullMethodName:       &platformv1.TPMCapabilitiesRequest{},
		platformv1.TPMService_GetPlatformAttributes_FullMethodName: &platformv1.TPMPlatformAttributesRequest{},
		platformv1.TPMService_ExtendPCR_FullMethodName:             &platformv1.ExtendPCRRequest{Index: 16},
	}
	for method, reply := range cases {
		t.Run(method, func(t *testing.T) {
			conn := newConnWithSender(t, &recordingSender{respPayload: []byte{0xFF}})
			err := conn.Invoke(context.Background(), method, requests[method], reply)
			if status.Code(err) != codes.Internal {
				t.Errorf("Invoke() code = %v, want Internal for an undecodable reply", status.Code(err))
			}
		})
	}
}
