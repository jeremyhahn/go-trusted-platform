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
		{"invitation create", quicwire.OpIAMCategory, quicwire.InvitationSubCreate, OpcodePermission{Resource: "invitation", Action: "write"}},
		{"invitation get", quicwire.OpIAMCategory, quicwire.InvitationSubGet, OpcodePermission{Resource: "invitation", Action: "read"}},
		{"invitation list", quicwire.OpIAMCategory, quicwire.InvitationSubList, OpcodePermission{Resource: "invitation", Action: "read"}},
		{"invitation revoke", quicwire.OpIAMCategory, quicwire.InvitationSubRevoke, OpcodePermission{Resource: "invitation", Action: "write"}},
		{"invitation delete", quicwire.OpIAMCategory, quicwire.InvitationSubDelete, OpcodePermission{Resource: "invitation", Action: "delete"}},
		{"ipam release", quicwire.OpIPAMCategory, quicwire.OpGatewayReleaseIP, OpcodePermission{Resource: "sdn", Action: "write"}},
		{"container remove", quicwire.OpVMExtendedCategory, quicwire.OpContainerRemove, OpcodePermission{Resource: "container", Action: "delete"}},
		{"vm create", quicwire.OpVMExtendedCategory, quicwire.OpVMCreate, OpcodePermission{Resource: "vm", Action: "write"}},
		{"vm delete", quicwire.OpVMExtendedCategory, quicwire.OpVMDelete, OpcodePermission{Resource: "vm", Action: "delete"}},
		{"vm list", quicwire.OpVMExtendedCategory, quicwire.OpVMList, OpcodePermission{Resource: "vm", Action: "read"}},
		{"vm snapshot create", quicwire.OpVMExtendedCategory, quicwire.OpVMSnapshotCreate, OpcodePermission{Resource: "vm", Action: "write"}},
		{"vm snapshot restore", quicwire.OpVMExtendedCategory, quicwire.OpVMSnapshotRestore, OpcodePermission{Resource: "vm", Action: "write"}},
		{"vm snapshot delete", quicwire.OpVMExtendedCategory, quicwire.OpVMSnapshotDelete, OpcodePermission{Resource: "vm", Action: "delete"}},
		{"vm snapshot list", quicwire.OpVMExtendedCategory, quicwire.OpVMSnapshotList, OpcodePermission{Resource: "vm", Action: "read"}},
		{"vm snapshot get", quicwire.OpVMExtendedCategory, quicwire.OpVMSnapshotGet, OpcodePermission{Resource: "vm", Action: "read"}},
		{"vm prepare migration", quicwire.OpVMExtendedCategory, quicwire.OpVMPrepareMigration, OpcodePermission{Resource: "vm", Action: "write"}},
		{"vm finalize migration", quicwire.OpVMExtendedCategory, quicwire.OpVMFinalizeMigration, OpcodePermission{Resource: "vm", Action: "write"}},
		{"vm attest", quicwire.OpVMExtendedCategory, quicwire.OpVMAttest, OpcodePermission{Resource: "vm", Action: "read"}},
		{"vm verify attest", quicwire.OpVMExtendedCategory, quicwire.OpVMVerifyAttest, OpcodePermission{Resource: "vm", Action: "read"}},
		{"eab revoke", quicwire.OpProvisioningCategory, quicwire.EABSubRevokeCredential, OpcodePermission{Resource: "eab", Action: "write"}},
		{"device profile assign", quicwire.OpProvisioningCategory, quicwire.DeviceProfileSubAssign, OpcodePermission{Resource: "device", Action: "write"}},
		{"device disable", quicwire.OpProvisioningCategory, quicwire.DeviceSubDisable, OpcodePermission{Resource: "device", Action: "write"}},
		{"device enable", quicwire.OpProvisioningCategory, quicwire.DeviceSubEnable, OpcodePermission{Resource: "device", Action: "write"}},
		{"device profile match", quicwire.OpProvisioningCategory, quicwire.DeviceSubFindMatchingProfile, OpcodePermission{Resource: "device", Action: "read"}},
		{"device find config", quicwire.OpProvisioningCategory, quicwire.DeviceSubFindConfigForDevice, OpcodePermission{Resource: "device", Action: "read"}},
		{"pxe get device by mac", quicwire.OpProvisioningCategory, quicwire.PXESubGetDeviceByMAC, OpcodePermission{Resource: "pxe", Action: "read"}},
		{"pxe set device enrolled", quicwire.OpProvisioningCategory, quicwire.PXESubSetDeviceEnrolled, OpcodePermission{Resource: "pxe", Action: "write"}},
		{"pxe get events", quicwire.OpProvisioningCategory, quicwire.PXESubGetEvents, OpcodePermission{Resource: "pxe", Action: "read"}},
		{"pxe get status", quicwire.OpProvisioningCategory, quicwire.PXESubGetStatus, OpcodePermission{Resource: "pxe", Action: "read"}},
		{"pxe start service", quicwire.OpProvisioningCategory, quicwire.PXESubStartService, OpcodePermission{Resource: "pxe", Action: "write"}},
		{"pxe stop service", quicwire.OpProvisioningCategory, quicwire.PXESubStopService, OpcodePermission{Resource: "pxe", Action: "write"}},
		{"pxe webhook complete", quicwire.OpProvisioningCategory, quicwire.PXESubWebhookComplete, OpcodePermission{Resource: "pxe", Action: "write"}},
		{"bmc enroll", quicwire.OpBMCCategory, quicwire.BMCSubEnroll, OpcodePermission{Resource: "bmc", Action: "admin"}},
		{"bmc power status", quicwire.OpBMCCategory, quicwire.BMCSubPowerStatus, OpcodePermission{Resource: "bmc", Action: "read"}},
		{"bmc power on", quicwire.OpBMCCategory, quicwire.BMCSubPowerOn, OpcodePermission{Resource: "bmc", Action: "write"}},
		{"bmc power cycle", quicwire.OpBMCCategory, quicwire.BMCSubPowerCycle, OpcodePermission{Resource: "bmc", Action: "power"}},
		{"bmc mount iso", quicwire.OpBMCCategory, quicwire.BMCSubMountISO, OpcodePermission{Resource: "bmc", Action: "media"}},
		{"cluster bootstrap", quicwire.OpClusterCategory, quicwire.ClusterSubBootstrap, OpcodePermission{Resource: "cluster", Action: "write"}},
		{"cluster join", quicwire.OpClusterCategory, quicwire.ClusterSubJoin, OpcodePermission{Resource: "cluster", Action: "write"}},
		{"cluster leave", quicwire.OpClusterCategory, quicwire.ClusterSubLeave, OpcodePermission{Resource: "cluster", Action: "write"}},
		{"cluster status", quicwire.OpClusterCategory, quicwire.ClusterSubGetStatus, OpcodePermission{Resource: "cluster", Action: "read"}},
		{"cluster list nodes", quicwire.OpClusterCategory, quicwire.ClusterSubListNodes, OpcodePermission{Resource: "cluster", Action: "read"}},
		{"tenant barrier unseal", quicwire.OpTenantBarrierCategory, quicwire.TenantBarrierSubUnseal, OpcodePermission{Resource: "tenant", Action: "write"}},
		{"tenant barrier status", quicwire.OpTenantBarrierCategory, quicwire.TenantBarrierSubStatus, OpcodePermission{Resource: "tenant", Action: "read"}},
		{"tpm2 clear", quicwire.OpTPM2Category, quicwire.SubOpTPM2Clear, OpcodePermission{Resource: "tpm", Action: "delete"}},
		{"tpm2 certify", quicwire.OpTPM2Category, quicwire.SubOpTPM2Certify, OpcodePermission{Resource: "tpm", Action: "read"}},
		{"secrets delete", quicwire.OpSecretsCategory, quicwire.SecretsSubDelete, OpcodePermission{Resource: "secrets", Action: "delete"}},
		// The list subs need secrets:list, as ListSecrets and
		// ListSecretVersions do on gRPC and secret_list* on MCP.
		{"secrets list", quicwire.OpSecretsCategory, quicwire.SecretsSubList, OpcodePermission{Resource: "secrets", Action: "list"}},
		{"secrets list versions", quicwire.OpSecretsCategory, quicwire.SecretsSubListVersions, OpcodePermission{Resource: "secrets", Action: "list"}},
		{"secrets get version", quicwire.OpSecretsCategory, quicwire.SecretsSubGetVersion, OpcodePermission{Resource: "secrets", Action: "read"}},
		{"secrets rotate", quicwire.OpSecretsCategory, quicwire.SecretsSubRotate, OpcodePermission{Resource: "secrets", Action: "write"}},
		{"secrets rollback", quicwire.OpSecretsCategory, quicwire.SecretsSubRollback, OpcodePermission{Resource: "secrets", Action: "write"}},
		{"secrets update status", quicwire.OpSecretsCategory, quicwire.SecretsSubUpdateStatus, OpcodePermission{Resource: "secrets", Action: "write"}},
		// The DEK subs carry their gRPC DEKManagement method's scope.
		{"dek create", quicwire.OpKMSExtendedCategory, quicwire.KMSSubCreateDEK, OpcodePermission{Resource: "kms", Action: "write"}},
		{"dek list", quicwire.OpKMSExtendedCategory, quicwire.KMSSubListDEKs, OpcodePermission{Resource: "kms", Action: "read"}},
		{"dek get", quicwire.OpKMSExtendedCategory, quicwire.KMSSubGetDEK, OpcodePermission{Resource: "kms", Action: "read"}},
		{"dek status", quicwire.OpKMSExtendedCategory, quicwire.KMSSubGetDEKStatus, OpcodePermission{Resource: "kms", Action: "read"}},
		{"dek rotate", quicwire.OpKMSExtendedCategory, quicwire.KMSSubRotateDEK, OpcodePermission{Resource: "kms", Action: "write"}},
		{"dek delete", quicwire.OpKMSExtendedCategory, quicwire.KMSSubDeleteDEK, OpcodePermission{Resource: "kms", Action: "delete"}},
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

func TestLookupOperationPermission_PreAuthSubOpcodes(t *testing.T) {
	type op struct{ category, sub byte }
	openOps := []op{
		{quicwire.OpProvisioningCategory, quicwire.DeviceSubBootCertificate},
		{quicwire.OpProvisioningCategory, quicwire.DeviceSubBootDelivery},
		// Device-side config delivery is open as on gRPC and MCP (#304).
		{quicwire.OpProvisioningCategory, quicwire.ProvisioningSubGetNonce},
		{quicwire.OpProvisioningCategory, quicwire.ProvisioningSubFetchConfig},
		{quicwire.OpProvisioningCategory, quicwire.ProvisioningSubSignDigest},
		{quicwire.OpProvisioningCategory, quicwire.ProvisioningSubPollSession},
		// The invitee half of the invitation flow is open as on gRPC and MCP (#704).
		{quicwire.OpIAMCategory, quicwire.InvitationSubGetByToken},
		{quicwire.OpIAMCategory, quicwire.InvitationSubAccept},
	}
	for _, o := range openOps {
		perm, preAuth, err := LookupOperationPermission(o.category, []byte{o.sub, 0xAA})
		if err != nil {
			t.Fatalf("0x%02X/0x%02X: unexpected error %v", o.category, o.sub, err)
		}
		if !preAuth {
			t.Fatalf("0x%02X/0x%02X: expected pre-auth", o.category, o.sub)
		}
		if perm != (OpcodePermission{}) {
			t.Fatalf("0x%02X/0x%02X: pre-auth entry carries a permission %+v", o.category, o.sub, perm)
		}
	}

	// Sibling sub-opcodes of the same category still need their permission,
	// including the operator half of config delivery and of invitations.
	scoped := []op{
		{quicwire.OpProvisioningCategory, quicwire.DeviceSubRecordAttestCert},
		{quicwire.OpProvisioningCategory, quicwire.ProvisioningSubFulfillSession},
		{quicwire.OpProvisioningCategory, quicwire.ProvisioningSubListSessions},
		{quicwire.OpProvisioningCategory, quicwire.ProvisioningSubGetSession},
		{quicwire.OpIAMCategory, quicwire.InvitationSubCreate},
		{quicwire.OpIAMCategory, quicwire.InvitationSubGet},
		{quicwire.OpIAMCategory, quicwire.InvitationSubList},
		{quicwire.OpIAMCategory, quicwire.InvitationSubRevoke},
		{quicwire.OpIAMCategory, quicwire.InvitationSubDelete},
		{quicwire.OpIAMCategory, quicwire.IAMSubTenantGet},
	}
	for _, o := range scoped {
		_, preAuth, err := LookupOperationPermission(o.category, []byte{o.sub})
		if err != nil || preAuth {
			t.Fatalf("0x%02X/0x%02X: preAuth=%v err=%v, want a classified, authenticated operation", o.category, o.sub, preAuth, err)
		}
	}
}

func TestLookupOperationPermission_UnclassifiedIsDenied(t *testing.T) {
	cases := []struct {
		name    string
		opcode  byte
		payload []byte
	}{
		{"reserved jwt byte", quicwire.OpJWTVerify, nil},
		{"reserved dek byte", quicwire.OpDEKCreate, nil},
		{"retired tenant byte", 0xE7, nil},
		{"unknown iam category sub", quicwire.OpIAMCategory, []byte{0x7F}},
		{"unknown vpn category sub", quicwire.OpVPNCategory, []byte{0x7F}},
		{"unknown cache category sub", quicwire.OpCacheCategory, []byte{0x7F}},
		{"unknown scheduler category sub", quicwire.OpSchedulerCategory, []byte{0x7F}},
		{"unknown messaging category sub", quicwire.OpMessagingCategory, []byte{0x7F}},
		{"unknown object storage category sub", quicwire.OpObjectStorageCategory, []byte{0x7F}},
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

func TestLookupOperationPermission_RetiredVMBytesAreUnclassified(t *testing.T) {
	// The VM verbs moved under 0x69; their old top-level bytes must not
	// grant a permission on their own.
	_, _, err := LookupOperationPermission(quicwire.OpVMDelete, []byte{quicwire.OpContainerGet})
	var unclassified ErrOperationNotClassified
	if !errors.As(err, &unclassified) {
		t.Fatalf("err = %v, want ErrOperationNotClassified", err)
	}
	if unclassified.HasSub {
		t.Fatalf("err = %+v, want a top-level refusal", unclassified)
	}
}

func TestOperationCatalog_EntriesAreWellFormed(t *testing.T) {
	actions := map[string]bool{
		actionRead: true, actionWrite: true, actionDelete: true, actionAdmin: true, actionSignCSR: true,
		actionGenerate: true, actionRevoke: true, actionList: true, actionPower: true, actionMedia: true,
	}
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
	for category, subs := range preAuthSubOpcodes {
		classified, ok := categoryPermissions[category]
		if !ok {
			t.Errorf("pre-auth sub-opcodes under %s, which is not a category", hexByte(category))
		}
		for sub, reason := range subs {
			if reason == "" {
				t.Errorf("pre-auth sub-opcode %s/%s carries no reason", hexByte(category), hexByte(sub))
			}
			if _, ok := classified[sub]; ok {
				t.Errorf("pre-auth sub-opcode %s/%s also has a permission that is never enforced", hexByte(category), hexByte(sub))
			}
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
