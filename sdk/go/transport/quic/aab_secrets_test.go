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

	kmspb "github.com/jeremyhahn/go-quicbaas/api/proto"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// TestSecretsVersionMethodsRouteToTheCategoryOpcode pins the QUIC wire
// contract the daemon's secrets dispatcher serves.
func TestSecretsVersionMethodsRouteToTheCategoryOpcode(t *testing.T) {
	want := map[string]byte{
		kmspb.SecretsManagement_GetSecretVersion_FullMethodName:   0x07,
		kmspb.SecretsManagement_ListSecretVersions_FullMethodName: 0x08,
		kmspb.SecretsManagement_RotateSecret_FullMethodName:       0x09,
		kmspb.SecretsManagement_RollbackSecret_FullMethodName:     0x0A,
		kmspb.SecretsManagement_UpdateSecretStatus_FullMethodName: 0x0B,
	}
	if _, isCategory := categoryOpcodes[quicwire.OpSecretsCategory]; !isCategory {
		t.Fatal("OpSecretsCategory is not registered as a category opcode")
	}
	for method, wantSub := range want {
		t.Run(method, func(t *testing.T) {
			if opcode := grpcMethodToOpcodeMap[method]; opcode != quicwire.OpSecretsCategory {
				t.Fatalf("opcode = 0x%02x, want 0x%02x", opcode, quicwire.OpSecretsCategory)
			}
			sub, ok := categorySubOpcodeMap[method]
			if !ok || sub != wantSub {
				t.Fatalf("sub-opcode = 0x%02x (mapped %v), want 0x%02x", sub, ok, wantSub)
			}
		})
	}
}

// TestSecretsWireStructMethodsAreNotRouted keeps the store/get/list/delete
// methods off the name routing: their sub-opcodes carry platform wire
// structs, so a generated quicbaas.kms.v1 request would not decode there.
func TestSecretsWireStructMethodsAreNotRouted(t *testing.T) {
	for _, method := range []string{
		kmspb.SecretsManagement_StoreSecret_FullMethodName,
		kmspb.SecretsManagement_GetSecret_FullMethodName,
		kmspb.SecretsManagement_ListSecrets_FullMethodName,
		kmspb.SecretsManagement_DeleteSecret_FullMethodName,
	} {
		if opcode, routed := grpcMethodToOpcodeMap[method]; routed {
			t.Errorf("%s routed to 0x%02x; its sub-opcode does not take the quicbaas message", method, opcode)
		}
	}
}

// TestSecretsCategoryPayloadCarriesTheQuicbaasMessage verifies the bytes on
// the wire decode back into the generated request the daemon expects.
func TestSecretsCategoryPayloadCarriesTheQuicbaasMessage(t *testing.T) {
	in := &kmspb.RotateSecretRequest{SecretId: "db/pw", NewData: []byte("v2"), Metadata: map[string]string{"by": "ops"}}
	payload, err := buildCategoryPayload(quicwire.SecretsSubRotate, in)
	if err != nil {
		t.Fatalf("buildCategoryPayload() error = %v", err)
	}
	if payload[0] != quicwire.SecretsSubRotate {
		t.Fatalf("payload[0] = 0x%02x, want 0x%02x", payload[0], quicwire.SecretsSubRotate)
	}
	var out kmspb.RotateSecretRequest
	if err := quicwire.DecodePayload(payload[1:], &out); err != nil {
		t.Fatalf("DecodePayload() error = %v", err)
	}
	if out.GetSecretId() != "db/pw" || string(out.GetNewData()) != "v2" || out.GetMetadata()["by"] != "ops" {
		t.Fatalf("decoded request = %+v, want the request sent", &out)
	}
}
