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
	"strings"
	"testing"

	quicapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestInvoke_CategoryPrefix_AllEABMethods verifies every EABService
// method emits OpProvisioningCategory (0xCF) with the correct EAB
// sub-opcode in payload[0], matching the server dispatcher in
// pkg/api/daemon/quic_eab.go.
func TestInvoke_CategoryPrefix_AllEABMethods(t *testing.T) {
	tests := []struct {
		method        string
		args          interface{}
		expectedSubOp byte
	}{
		{"/platform.v1.EABService/CreateCredential", &platformv1.CreateEABCredentialRequest{ProfileId: 1, TenantId: "t"}, quicapi.EABSubCreateCredential},
		{"/platform.v1.EABService/GetCredential", &platformv1.GetEABCredentialRequest{CredentialId: 1}, quicapi.EABSubGetCredential},
		{"/platform.v1.EABService/GetCredentialByKeyID", &platformv1.GetEABCredentialByKeyIDRequest{KeyId: "k"}, quicapi.EABSubGetCredentialByKeyID},
		{"/platform.v1.EABService/ListCredentials", &platformv1.ListEABCredentialsRequest{TenantId: "t"}, quicapi.EABSubListCredentials},
		{"/platform.v1.EABService/RevokeCredential", &platformv1.RevokeEABCredentialRequest{CredentialId: 1}, quicapi.EABSubRevokeCredential},
		{"/platform.v1.EABService/ValidateCredential", &platformv1.ValidateEABCredentialRequest{KeyId: "k", HmacKey: "h"}, quicapi.EABSubValidateCredential},
		{"/platform.v1.EABService/DeleteCredential", &platformv1.DeleteEABCredentialRequest{CredentialId: 1}, quicapi.EABSubDeleteCredential},
		{"/platform.v1.EABService/GetCredentialQRCode", &platformv1.GetEABCredentialQRCodeRequest{CredentialId: 1}, quicapi.EABSubGetCredentialQRCode},
		{"/platform.v1.EABService/GetEnrollmentURL", &platformv1.GetEABEnrollmentURLRequest{CredentialId: 1}, quicapi.EABSubGetEnrollmentURL},
		{"/platform.v1.EABService/MarkCredentialUsed", &platformv1.MarkEABCredentialUsedRequest{CredentialId: 1}, quicapi.EABSubMarkCredentialUsed},
		{"/platform.v1.EABService/CleanupExpiredCredentials", &platformv1.CleanupExpiredEABCredentialsRequest{}, quicapi.EABSubCleanupExpiredCredentials},
	}

	for _, tt := range tests {
		t.Run(tt.method, func(t *testing.T) {
			sender := &recordingSender{}
			conn := newConnWithSender(t, sender)

			if err := conn.Invoke(context.Background(), tt.method, tt.args, nil); err != nil {
				t.Fatalf("Invoke() unexpected error: %v", err)
			}
			if sender.rawCalls != 1 {
				t.Fatalf("expected exactly 1 SendRequest call, got %d", sender.rawCalls)
			}
			if sender.rawOpcode != quicapi.OpProvisioningCategory {
				t.Errorf("opcode = 0x%02X, want 0x%02X (OpProvisioningCategory)",
					sender.rawOpcode, quicapi.OpProvisioningCategory)
			}
			if len(sender.rawPayload) == 0 {
				t.Fatal("payload must contain at least the sub-opcode prefix")
			}
			if sender.rawPayload[0] != tt.expectedSubOp {
				t.Errorf("payload[0] sub-opcode = 0x%02X, want 0x%02X",
					sender.rawPayload[0], tt.expectedSubOp)
			}
		})
	}
}

// TestInvoke_EABRequestEncodesPBFieldNames pins the request wire
// contract: payload[1:] keys on the exact pb Go field names the daemon
// decodes into (quic.DecodePayload into the pb request struct).
func TestInvoke_EABRequestEncodesPBFieldNames(t *testing.T) {
	sender := &recordingSender{}
	conn := newConnWithSender(t, sender)

	args := &platformv1.CreateEABCredentialRequest{
		ProfileId:        7,
		TenantId:         "tenant-1",
		ExpiresInSeconds: 3600,
		HmacKeyLength:    64,
	}
	if err := conn.Invoke(context.Background(),
		"/platform.v1.EABService/CreateCredential", args, nil); err != nil {
		t.Fatalf("Invoke() unexpected error: %v", err)
	}

	// The daemon decodes payload[1:] into the identical pb struct, so a
	// decode round-trip through the shared codec must reproduce the args.
	var decoded platformv1.CreateEABCredentialRequest
	if err := quicapi.DecodePayload(sender.rawPayload[1:], &decoded); err != nil {
		t.Fatalf("daemon-side decode failed: %v", err)
	}
	if decoded.GetProfileId() != 7 || decoded.GetTenantId() != "tenant-1" ||
		decoded.GetExpiresInSeconds() != 3600 || decoded.GetHmacKeyLength() != 64 {
		t.Errorf("request did not round-trip: %+v", &decoded)
	}
}

// TestInvoke_EABResponseDecodesDirectly verifies EAB responses (oneof
// free) decode straight into the pb reply by Go field name — no custom
// decoder needed.
func TestInvoke_EABResponseDecodesDirectly(t *testing.T) {
	wire := &platformv1.GetEABCredentialResponse{
		Credential: &platformv1.EABCredential{
			Id:        42,
			KeyId:     "key-a",
			ProfileId: 7,
			TenantId:  "tenant-1",
			Status:    platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_ACTIVE,
		},
	}
	encoded, err := quicapi.EncodePayload(wire)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}

	sender := &recordingSender{respPayload: encoded}
	conn := newConnWithSender(t, sender)

	var reply platformv1.GetEABCredentialResponse
	if err := conn.Invoke(context.Background(),
		"/platform.v1.EABService/GetCredential",
		&platformv1.GetEABCredentialRequest{CredentialId: 42}, &reply); err != nil {
		t.Fatalf("Invoke() unexpected error: %v", err)
	}
	cred := reply.GetCredential()
	if cred.GetId() != 42 || cred.GetKeyId() != "key-a" || cred.GetProfileId() != 7 ||
		cred.GetStatus() != platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_ACTIVE {
		t.Errorf("response did not round-trip: %+v", cred)
	}
}

// TestEABMethodsHaveNoCustomDecoders pins the design decision that EAB
// responses use the default decode path (they carry no oneofs).
func TestEABMethodsHaveNoCustomDecoders(t *testing.T) {
	for method := range grpcMethodToOpcodeMap {
		if !strings.HasPrefix(method, "/platform.v1.EABService/") {
			continue
		}
		if _, has := categoryResponseDecoders[method]; has {
			t.Errorf("%s must not have a custom response decoder", method)
		}
		if _, has := categoryEmptyBodyMethods[method]; has {
			t.Errorf("%s must not be an empty-body method (all EAB requests carry a body)", method)
		}
	}
}

// TestEABSubOpcodeMapComplete verifies every EABService method routed to
// the provisioning category has a sub-opcode mapping (the init invariant
// panics on violation, but this test documents the expected set).
func TestEABSubOpcodeMapComplete(t *testing.T) {
	count := 0
	for method, opcode := range grpcMethodToOpcodeMap {
		if !strings.HasPrefix(method, "/platform.v1.EABService/") {
			continue
		}
		count++
		if opcode != quicapi.OpProvisioningCategory {
			t.Errorf("%s opcode = 0x%02X, want OpProvisioningCategory", method, opcode)
		}
		if _, has := categorySubOpcodeMap[method]; !has {
			t.Errorf("%s missing sub-opcode mapping", method)
		}
	}
	if count != 11 {
		t.Errorf("expected 11 EABService methods mapped, got %d", count)
	}
}
