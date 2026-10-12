// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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
	"errors"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

func TestLookupOperationPermission_DirectOpcodes(t *testing.T) {
	cases := []struct {
		name   string
		opcode byte
		want   OpcodePermission
	}{
		{"kms delete", quicwire.OpKMSDeleteKey, OpcodePermission{Resource: "kms", Action: "delete"}},
		{"kms decrypt", quicwire.OpKMSDecrypt, OpcodePermission{Resource: "kms", Action: "read"}},
		{"dns add record", quicwire.OpDNSAddRecord, OpcodePermission{Resource: "dns", Action: "write"}},
		{"vtpm unseal", quicwire.OpVTPMUnseal, OpcodePermission{Resource: "vtpm", Action: "read"}},
		// OpTenant* dispatch to the platform TenantService (quotas, DEKs,
		// sync), so they carry the tenant scopes gRPC TenantService uses.
		{"tenant create", quicwire.OpTenantCreate, OpcodePermission{Resource: "tenant", Action: "write"}},
		{"tenant get", quicwire.OpTenantGet, OpcodePermission{Resource: "tenant", Action: "read"}},
		{"tenant delete", quicwire.OpTenantDelete, OpcodePermission{Resource: "tenant", Action: "delete"}},
		{"tenant rotate dek", quicwire.OpTenantRotateDEK, OpcodePermission{Resource: "tenant", Action: "write"}},
		{"iam token verify", quicwire.OpIAMTokenVerify, OpcodePermission{Resource: "iam", Action: "read"}},
		{"pxe remove device", quicwire.OpPXERemoveDevice, OpcodePermission{Resource: "pxe", Action: "delete"}},
		// A quote makes the node TPM sign a caller-supplied nonce: it collects
		// fresh evidence, like OpAttestCollectHost, so it needs write.
		{"attestation quote", quicwire.OpAttestQuote, OpcodePermission{Resource: "attestation", Action: "write"}},
		{"attestation collect host", quicwire.OpAttestCollectHost, OpcodePermission{Resource: "attestation", Action: "write"}},
		{"attestation verify", quicwire.OpAttestVerify, OpcodePermission{Resource: "attestation", Action: "read"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, preAuth, err := LookupOperationPermission(tc.opcode, nil)
			if err != nil {
				t.Fatalf("opcode 0x%02X: unexpected error %v", tc.opcode, err)
			}
			if preAuth {
				t.Fatalf("opcode 0x%02X: classified as pre-auth", tc.opcode)
			}
			if got != tc.want {
				t.Fatalf("opcode 0x%02X: got %+v, want %+v", tc.opcode, got, tc.want)
			}
		})
	}
}

func TestLookupOperationPermission_CategorySubOpcodes(t *testing.T) {
	cases := []struct {
		name     string
		category byte
		sub      byte
		want     OpcodePermission
	}{
		{"proxy route delete", quicwire.OpGatewayCategory, quicwire.ProxySubRouteDelete, OpcodePermission{Resource: "proxy", Action: "delete"}},
		{"gateway lb add vip", quicwire.OpGatewayCategory, quicwire.OpGatewayLBAddVIP, OpcodePermission{Resource: "sdn", Action: "write"}},
		{"ntp step", quicwire.OpNTPCategory, quicwire.NTPSubStep, OpcodePermission{Resource: "ntp", Action: "write"}},
		{"ntp status", quicwire.OpNTPCategory, quicwire.NTPSubGetStatus, OpcodePermission{Resource: "ntp", Action: "read"}},
		{"iam tenant create", quicwire.OpIAMCategory, quicwire.IAMSubTenantCreate, OpcodePermission{Resource: "iam", Action: "write"}},
		{"iam tenant list", quicwire.OpIAMCategory, quicwire.IAMSubTenantList, OpcodePermission{Resource: "iam", Action: "read"}},
		{"iam tenant delete", quicwire.OpIAMCategory, quicwire.IAMSubTenantDelete, OpcodePermission{Resource: "iam", Action: "delete"}},
		{"ipam release", quicwire.OpIPAMCategory, quicwire.OpGatewayReleaseIP, OpcodePermission{Resource: "sdn", Action: "write"}},
		{"container remove", quicwire.OpVMExtendedCategory, quicwire.OpContainerRemove, OpcodePermission{Resource: "container", Action: "delete"}},
		{"vm snapshot delete", quicwire.OpVMExtendedCategory, quicwire.OpVMSnapshotDelete, OpcodePermission{Resource: "vm", Action: "delete"}},
		{"eab revoke", quicwire.OpProvisioningCategory, quicwire.EABSubRevokeCredential, OpcodePermission{Resource: "eab", Action: "write"}},
		{"device profile assign", quicwire.OpProvisioningCategory, quicwire.DeviceProfileSubAssign, OpcodePermission{Resource: "device", Action: "write"}},
		{"bmc enroll", quicwire.OpBMCCategory, quicwire.BMCSubEnroll, OpcodePermission{Resource: "bmc", Action: "admin"}},
		{"tenant barrier unseal", quicwire.OpTenantBarrierCategory, quicwire.TenantBarrierSubUnseal, OpcodePermission{Resource: "tenant", Action: "write"}},
		{"tenant barrier status", quicwire.OpTenantBarrierCategory, quicwire.TenantBarrierSubStatus, OpcodePermission{Resource: "tenant", Action: "read"}},
		{"tpm2 clear", quicwire.OpTPM2Category, quicwire.SubOpTPM2Clear, OpcodePermission{Resource: "tpm", Action: "delete"}},
		{"secrets delete", quicwire.OpSecretsCategory, quicwire.SecretsSubDelete, OpcodePermission{Resource: "secrets", Action: "delete"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, preAuth, err := LookupOperationPermission(tc.category, []byte{tc.sub, 0xAA})
			if err != nil {
				t.Fatalf("0x%02X/0x%02X: unexpected error %v", tc.category, tc.sub, err)
			}
			if preAuth {
				t.Fatalf("0x%02X/0x%02X: classified as pre-auth", tc.category, tc.sub)
			}
			if got != tc.want {
				t.Fatalf("0x%02X/0x%02X: got %+v, want %+v", tc.category, tc.sub, got, tc.want)
			}
		})
	}
}

func TestLookupOperationPermission_PreAuth(t *testing.T) {
	for _, opcode := range []byte{quicwire.OpHealth, quicwire.OpLiveness, quicwire.OpReadiness, quicwire.OpIAMAuthenticate} {
		perm, preAuth, err := LookupOperationPermission(opcode, nil)
		if err != nil {
			t.Fatalf("opcode 0x%02X: unexpected error %v", opcode, err)
		}
		if !preAuth {
			t.Fatalf("opcode 0x%02X: expected pre-auth", opcode)
		}
		if perm != (OpcodePermission{}) {
			t.Fatalf("opcode 0x%02X: pre-auth entry carries a permission %+v", opcode, perm)
		}
	}
}

func TestLookupOperationPermission_UnclassifiedIsDenied(t *testing.T) {
	cases := []struct {
		name    string
		opcode  byte
		payload []byte
	}{
		{"reserved jwt byte", quicwire.OpJWTCreate, nil},
		{"reserved dek byte", quicwire.OpDEKCreate, nil},
		{"retired tenant byte", 0xE7, nil},
		{"reserved byte after the iam category", 0x52, nil},
		{"unknown iam category sub", quicwire.OpIAMCategory, []byte{0x7F}},
		{"unknown gateway sub", quicwire.OpGatewayCategory, []byte{0x7F}},
		{"ipam category rejects non-ipam gateway sub", quicwire.OpIPAMCategory, []byte{quicwire.OpGatewaySetMode}},
		{"unknown ceremony sub", quicwire.OpCeremonyCategory, []byte{0xEE}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, preAuth, err := LookupOperationPermission(tc.opcode, tc.payload)
			if preAuth {
				t.Fatal("unclassified operation reported as pre-auth")
			}
			var notClassified ErrOperationNotClassified
			if !errors.As(err, &notClassified) {
				t.Fatalf("expected ErrOperationNotClassified, got %v", err)
			}
			if notClassified.Opcode != tc.opcode {
				t.Fatalf("error carries opcode 0x%02X, want 0x%02X", notClassified.Opcode, tc.opcode)
			}
		})
	}
}

func TestLookupOperationPermission_CategoryWithoutSubOpcode(t *testing.T) {
	for _, category := range []byte{quicwire.OpGatewayCategory, quicwire.OpNTPCategory, quicwire.OpVMExtendedCategory, quicwire.OpProvisioningCategory} {
		_, preAuth, err := LookupOperationPermission(category, nil)
		if preAuth {
			t.Fatalf("category 0x%02X: empty payload reported as pre-auth", category)
		}
		var missing ErrSubOpcodeMissing
		if !errors.As(err, &missing) {
			t.Fatalf("category 0x%02X: expected ErrSubOpcodeMissing, got %v", category, err)
		}
		if missing.Opcode != category {
			t.Fatalf("error carries opcode 0x%02X, want 0x%02X", missing.Opcode, category)
		}
	}
}

func TestLookupOperationPermission_VMDirectOpcodesStayDirect(t *testing.T) {
	// 0x69 is a category, but the neighbouring VM opcodes are direct: their
	// payload must not be read as a sub-opcode.
	got, _, err := LookupOperationPermission(quicwire.OpVMDelete, []byte{quicwire.OpContainerGet})
	if err != nil {
		t.Fatalf("unexpected error %v", err)
	}
	if want := (OpcodePermission{Resource: "vm", Action: "delete"}); got != want {
		t.Fatalf("got %+v, want %+v", got, want)
	}
}

func TestOperationCatalog_EntriesAreWellFormed(t *testing.T) {
	actions := map[string]bool{actionRead: true, actionWrite: true, actionDelete: true, actionAdmin: true}
	check := func(where string, perm OpcodePermission) {
		if perm.Resource == "" || !actions[perm.Action] {
			t.Errorf("%s: malformed permission %+v", where, perm)
		}
	}
	for opcode, perm := range opcodePermissions {
		check(hexByte(opcode), perm)
		if _, ok := categoryPermissions[opcode]; ok {
			t.Errorf("opcode %s is both direct and a category; the direct entry is unreachable", hexByte(opcode))
		}
	}
	for category, subs := range categoryPermissions {
		if len(subs) == 0 {
			t.Errorf("category %s has no sub-opcodes", hexByte(category))
		}
		for sub, perm := range subs {
			check(hexByte(category)+"/"+hexByte(sub), perm)
		}
	}
	for opcode, reason := range preAuthOpcodes {
		if reason == "" {
			t.Errorf("pre-auth opcode %s carries no reason", hexByte(opcode))
		}
		if _, ok := opcodePermissions[opcode]; ok {
			t.Errorf("pre-auth opcode %s also has a permission that is never enforced", hexByte(opcode))
		}
		if _, ok := categoryPermissions[opcode]; ok {
			t.Errorf("pre-auth opcode %s is a category", hexByte(opcode))
		}
	}
}

func TestOperationErrors_Messages(t *testing.T) {
	direct := ErrOperationNotClassified{Opcode: 0x90}
	if got, want := direct.Error(), "QUIC operation not classified for authorization: opcode 0x90"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	sub := ErrOperationNotClassified{Opcode: 0x2F, Sub: 0x7F, HasSub: true}
	if got, want := sub.Error(), "QUIC operation not classified for authorization: opcode 0x2F sub-opcode 0x7F"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
	missing := ErrSubOpcodeMissing{Opcode: 0x50}
	if got, want := missing.Error(), "QUIC category opcode 0x50 requires a sub-opcode in payload[0]"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestOpcodePermission_Scope(t *testing.T) {
	if got := (OpcodePermission{Resource: "kms", Action: "write"}).Scope(); got != "kms:write" {
		t.Fatalf("got %q, want kms:write", got)
	}
	if got := (OpcodePermission{}).Scope(); got != "" {
		t.Fatalf("empty permission scope = %q, want empty", got)
	}
}
