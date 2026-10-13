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
	"context"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/platformtoken"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

func scopedContext(scopes ...string) context.Context {
	return ContextWithAuthorizedContext(context.Background(), &platformtoken.AuthorizedContext{Scopes: scopes})
}

func TestAuthorizeSubOpcode_AllowsHeldScope(t *testing.T) {
	ctx := scopedContext("piv:read")
	if resp := AuthorizeSubOpcode(ctx, PIVSubOpcodePermissions, quicwire.PIVSubListDevices); resp != nil {
		t.Fatalf("read sub-opcode refused for a piv:read token: status=%d", resp.Status)
	}
}

func TestAuthorizeSubOpcode_DeniesMissingScope(t *testing.T) {
	cases := []struct {
		name  string
		perms map[byte]OpcodePermission
		sub   byte
		held  string
		want  string
	}{
		{"piv write with read", PIVSubOpcodePermissions, quicwire.PIVSubGenerate, "piv:read", "write on piv"},
		{"fido2 write with read", FIDO2SubOpcodePermissions, quicwire.FIDO2SubRegister, "fido2:read", "write on fido2"},
		{"ceremony init with read", CeremonySubOpcodePermissions, quicwire.CeremonySubInit, "ceremony:read", "write on ceremony"},
		{"ceremony status with other scope", CeremonySubOpcodePermissions, quicwire.CeremonySubStatus, "piv:read", "read on ceremony"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := AuthorizeSubOpcode(scopedContext(tc.held), tc.perms, tc.sub)
			if resp == nil || resp.Status != quicwire.StatusPermissionDenied {
				t.Fatalf("resp = %+v, want PermissionDenied", resp)
			}
			if !strings.Contains(string(resp.Payload), tc.want) {
				t.Errorf("payload = %q, want it to name %q", resp.Payload, tc.want)
			}
		})
	}
}

// A request with no AuthorizedContext has no scopes to check, and an unknown
// sub-opcode is left to the handler's NotImplemented answer.
func TestAuthorizeSubOpcode_MissingContextDeniesScopedSubOpcode(t *testing.T) {
	cases := []struct {
		name  string
		perms map[byte]OpcodePermission
		sub   byte
		want  string
	}{
		{"anonymous caller on a server without auth middleware", CeremonySubOpcodePermissions, quicwire.CeremonySubInit, "write on ceremony"},
		{"legacy token caller without scoped authorization context", FIDO2SubOpcodePermissions, quicwire.FIDO2SubRegister, "write on fido2"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			resp := AuthorizeSubOpcode(context.Background(), tc.perms, tc.sub)
			if resp == nil || resp.Status != quicwire.StatusPermissionDenied {
				t.Fatalf("resp = %+v, want PermissionDenied", resp)
			}
			if !strings.Contains(string(resp.Payload), tc.want) {
				t.Errorf("payload = %q, want it to name %q", resp.Payload, tc.want)
			}
		})
	}
}

func TestAuthorizeSubOpcode_UnknownSubOpcodeIsLeftToHandler(t *testing.T) {
	if resp := AuthorizeSubOpcode(scopedContext(), PIVSubOpcodePermissions, 0xFF); resp != nil {
		t.Errorf("unknown sub-opcode: status=%d, want nil", resp.Status)
	}
}

// TestOperationCatalog_Phase35CategoriesScopedToTheirResource proves every
// ceremony, PIV and FIDO2 sub-operation the catalog classifies requires a
// scope on its own resource, so no category operation is reachable with an
// unrelated scope or with none.
func TestOperationCatalog_Phase35CategoriesScopedToTheirResource(t *testing.T) {
	resources := map[byte]string{quicwire.OpCeremonyCategory: "ceremony", quicwire.OpPIVCategory: "piv", quicwire.OpFIDO2Category: "fido2"}
	for opcode, resource := range resources {
		subs := categoryPermissions[opcode]
		if len(subs) == 0 {
			t.Errorf("opcode 0x%02x: no sub-operations classified", opcode)
		}
		for sub := range subs {
			perm, preAuth, err := LookupOperationPermission(opcode, []byte{sub})
			if err != nil || preAuth || perm.Resource != resource || perm.Action == "" {
				t.Errorf("opcode 0x%02x sub 0x%02x = %+v preAuth=%v err=%v, want a %s scope",
					opcode, sub, perm, preAuth, err, resource)
			}
		}
	}
}
