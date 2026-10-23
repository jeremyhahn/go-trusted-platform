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

package quic

import (
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// TestLDevIDQUICMapping verifies the LDevID create RPC routes onto the
// physical-TPM category opcode with the LDevID sub-opcode, and that the
// category invariant (every category-routed method has a sub-opcode) holds.
func TestLDevIDQUICMapping(t *testing.T) {
	method := platformv1.IDevIDService_CreateLDevID_FullMethodName

	opcode, ok := grpcMethodToOpcodeMap[method]
	if !ok {
		t.Fatalf("CreateLDevID not mapped to a QUIC opcode")
	}
	if opcode != quicwire.OpTPM2Category {
		t.Fatalf("CreateLDevID opcode = 0x%02X, want OpTPM2Category (0x%02X)", opcode, quicwire.OpTPM2Category)
	}

	if !isCategoryOpcode(opcode) {
		t.Fatalf("OpTPM2Category not registered as a category opcode")
	}

	sub, ok := categorySubOpcodeMap[method]
	if !ok {
		t.Fatalf("CreateLDevID has no category sub-opcode mapping")
	}
	if sub != quicwire.SubOpTPM2LDevIDCSR {
		t.Fatalf("CreateLDevID sub-opcode = 0x%02X, want SubOpTPM2LDevIDCSR (0x%02X)", sub, quicwire.SubOpTPM2LDevIDCSR)
	}
}

// TestLDevIDQUICWireCompat proves the pb request/response round-trip through
// the QUIC protocol codec by their Go field names, which is the exact framing
// the SDK adapter (client) and daemon interception (server) rely on.
func TestLDevIDQUICWireCompat(t *testing.T) {
	req := &platformv1.CreateLDevIDRequest{
		Template: &platformv1.CSRTemplate{
			CommonName: "ldevid.example",
			DnsNames:   []string{"a.example", "b.example"},
		},
		Algorithm:    platformv1.DeviceKeyAlgorithm_DEVICE_KEY_ALGORITHM_ECDSA_P384,
		Handle:       0x81010102,
		Profile:      "tls-client",
		ValidityDays: 90,
		Overwrite:    true,
	}

	data, err := quicwire.EncodePayload(req)
	if err != nil {
		t.Fatalf("encode request: %v", err)
	}
	var gotReq platformv1.CreateLDevIDRequest
	if err := quicwire.DecodePayload(data, &gotReq); err != nil {
		t.Fatalf("decode request: %v", err)
	}
	if gotReq.GetHandle() != req.GetHandle() || gotReq.GetProfile() != req.GetProfile() ||
		gotReq.GetValidityDays() != req.GetValidityDays() || gotReq.GetOverwrite() != req.GetOverwrite() ||
		gotReq.GetAlgorithm() != req.GetAlgorithm() {
		t.Fatalf("request scalar mismatch: got %+v", &gotReq)
	}
	if gotReq.GetTemplate().GetCommonName() != "ldevid.example" || len(gotReq.GetTemplate().GetDnsNames()) != 2 {
		t.Fatalf("request template mismatch: %+v", gotReq.GetTemplate())
	}

	resp := &platformv1.CreateLDevIDResponse{
		Status:         &platformv1.Status{Success: true, Message: "issued"},
		CsrPem:         []byte("CSR"),
		CertificatePem: []byte("CERT"),
	}
	rd, err := quicwire.EncodePayload(resp)
	if err != nil {
		t.Fatalf("encode response: %v", err)
	}
	var gotResp platformv1.CreateLDevIDResponse
	if err := quicwire.DecodePayload(rd, &gotResp); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if !gotResp.GetStatus().GetSuccess() || string(gotResp.GetCsrPem()) != "CSR" ||
		string(gotResp.GetCertificatePem()) != "CERT" {
		t.Fatalf("response mismatch: %+v", &gotResp)
	}
}
