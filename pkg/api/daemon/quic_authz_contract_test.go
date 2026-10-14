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

package daemon

import (
	"errors"
	"fmt"
	"strings"
	"testing"

	grpccreds "github.com/jeremyhahn/go-trusted-platform/pkg/api/grpc"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
)

// This file is the authorization contract of the QUIC dispatcher (#767):
// every routable opcode and every declared sub-opcode is either classified in
// the operation catalog (quic.LookupOperationPermission) or on its pre-auth
// list. Adding an opcode or sub-opcode without a catalog entry fails here,
// because the guard in HandleRequest would refuse it.

// quicSubOpcodePrefixes maps the name prefix of each sub-opcode constant
// family that is not Op-prefixed to the category opcode carrying it. A new
// sub-opcode family must be added here; an unknown prefix fails the contract.
var quicSubOpcodePrefixes = map[string]byte{
	"SubOpTPM2":        quicwire.OpTPM2Category,
	"NTPSub":           quicwire.OpNTPCategory,
	"IAMSub":           quicwire.OpIAMCategory,
	"VPNSub":           quicwire.OpVPNCategory,
	"ProxySub":         quicwire.OpGatewayCategory,
	"ProvisioningSub":  quicwire.OpProvisioningCategory,
	"EABSub":           quicwire.OpProvisioningCategory,
	"DeviceProfileSub": quicwire.OpProvisioningCategory,
	"DeviceSub":        quicwire.OpProvisioningCategory,
	"SwitchSub":        quicwire.OpSwitchCategory,
	"TenantBarrierSub": quicwire.OpTenantBarrierCategory,
	"CeremonySub":      quicwire.OpCeremonyCategory,
	"PIVSub":           quicwire.OpPIVCategory,
	"LUKSSub":          quicwire.OpLUKSCategory,
	"FIDO2Sub":         quicwire.OpFIDO2Category,
	"BMCSub":           quicwire.OpBMCCategory,
	"KMSSub":           quicwire.OpKMSExtendedCategory,
	"SecretsSub":       quicwire.OpSecretsCategory,
	"CacheSub":         quicwire.OpCacheCategory,
	"SchedulerSub":     quicwire.OpSchedulerCategory,
	"MessagingSub":     quicwire.OpMessagingCategory,
}

// assertOperationClassified fails unless the operation is in the catalog or
// on the pre-auth list.
func assertOperationClassified(t *testing.T, opcode byte, payload []byte) {
	t.Helper()
	if _, _, err := quic.LookupOperationPermission(opcode, payload); err != nil {
		t.Errorf("opcode 0x%02X payload %X has no permission entry: %v", opcode, payload, err)
	}
}

func TestQUICAuthzContract_EveryRoutableOpcodeIsClassified(t *testing.T) {
	t.Parallel()

	for _, r := range quicWireOwners {
		for op := int(r.lo); op <= int(r.hi); op++ {
			opcode := byte(op)
			payload := dispatchProbePayload(opcode, r.family)
			if r.family != "reserved" {
				assertOperationClassified(t, opcode, payload)
				continue
			}
			var unclassified quic.ErrOperationNotClassified
			if _, _, err := quic.LookupOperationPermission(opcode, payload); !errors.As(err, &unclassified) {
				t.Errorf("reserved opcode 0x%02X must be unclassified, got %v", opcode, err)
			}
		}
	}
}

func TestQUICAuthzContract_EveryOpPrefixedSubOpcodeIsClassified(t *testing.T) {
	t.Parallel()

	for name, intent := range quicDispatchOpcodeIntents {
		if intent.mode != categorySub {
			continue
		}
		t.Run(name, func(t *testing.T) {
			assertOperationClassified(t, intent.category, []byte{intent.value})
		})
	}
}

func TestQUICAuthzContract_EverySubOpcodeConstantIsClassified(t *testing.T) {
	t.Parallel()

	declared := parseQUICByteConstants(t, func(name string) bool {
		return strings.Contains(name, "Sub") && !strings.HasPrefix(name, "Op")
	})
	if len(declared) == 0 {
		t.Fatal("no sub-opcode byte constants found in pkg/api/quic")
	}

	for name, value := range declared {
		t.Run(name, func(t *testing.T) {
			category, err := subOpcodeCategory(name)
			if err != nil {
				t.Fatal(err)
			}
			assertOperationClassified(t, category, []byte{value})
		})
	}
}

// TestQUICAuthzContract_ScopesMatchGRPC pins the QUIC catalog to the gRPC
// method catalog (which mirrors the MCP tool map): the same capability needs
// the same scope on every transport. One mutating and one reading operation
// per service family.
func TestQUICAuthzContract_ScopesMatchGRPC(t *testing.T) {
	t.Parallel()

	cases := []struct {
		grpcMethod string
		opcode     byte
		payload    []byte
	}{
		{"/platform.v1.VTPMService/DeleteTemplate", quicwire.OpVTPMDeleteTemplate, nil},
		{"/platform.v1.DNSService/DeleteRecord", quicwire.OpDNSDeleteRecord, nil},
		{"/platform.v1.DNSService/DeleteZone", quicwire.OpDNSDeleteZone, nil},
		{"/platform.v1.DeviceService/DeleteProfile", quicwire.OpDeviceDeleteProfile, nil},
		{"/platform.v1.SDNService/DeleteBridge", quicwire.OpSDNDeleteBridge, nil},
		{"/platform.v1.SDNService/DeletePolicy", quicwire.OpSDNDeletePolicy, nil},
		{"/platform.v1.KeyManagementService/DeleteKey", quicwire.OpKMSDeleteKey, nil},
		{"/platform.v1.KeyManagementService/GetKey", quicwire.OpKMSGetKey, nil},
		{"/platform.v1.PlatformIAMService/DeleteUser", quicwire.OpIAMUserDelete, nil},
		{"/platform.v1.PlatformIAMService/DeleteRole", quicwire.OpIAMRoleDelete, nil},
		{"/platform.v1.CAService/RevokeCertificate", quicwire.OpCARevoke, nil},
		{"/platform.v1.NTPService/Step", quicwire.OpNTPCategory, []byte{quicwire.NTPSubStep}},
		{"/platform.v1.NTPService/GetStatus", quicwire.OpNTPCategory, []byte{quicwire.NTPSubGetStatus}},
		{"/platform.v1.VPNService/EnrolPeer", quicwire.OpVPNCategory, []byte{quicwire.VPNSubEnrolPeer}},
		{"/platform.v1.VPNService/ListPeers", quicwire.OpVPNCategory, []byte{quicwire.VPNSubListPeers}},
		{"/platform.v1.VPNService/RevokePeer", quicwire.OpVPNCategory, []byte{quicwire.VPNSubRevokePeer}},
		{"/platform.v1.VPNService/GetStatus", quicwire.OpVPNCategory, []byte{quicwire.VPNSubGetStatus}},
		{"/platform.v1.VPNService/GetPosturePolicy", quicwire.OpVPNCategory, []byte{quicwire.VPNSubGetPosturePolicy}},
		{"/platform.v1.VPNService/SetPosturePolicy", quicwire.OpVPNCategory, []byte{quicwire.VPNSubSetPosturePolicy}},
		{"/platform.v1.VPNService/DeletePosturePolicy", quicwire.OpVPNCategory, []byte{quicwire.VPNSubDeletePosturePolicy}},
		{"/platform.v1.VPNService/ListPosturePolicies", quicwire.OpVPNCategory, []byte{quicwire.VPNSubListPosturePolicies}},
		{"/platform.v1.ProxyService/DeleteRoute", quicwire.OpGatewayCategory, []byte{quicwire.ProxySubRouteDelete}},
		{"/platform.v1.ProxyService/ListRoutes", quicwire.OpGatewayCategory, []byte{quicwire.ProxySubRouteList}},
		{"/platform.v1.GatewayService/RemoveVIP", quicwire.OpGatewayCategory, []byte{quicwire.OpGatewayLBRemoveVIP}},
		{"/platform.v1.GatewayService/GetPerfFlows", quicwire.OpGatewayCategory, []byte{quicwire.OpGatewayPerfFlows}},
		{"/platform.v1.CacheService/GetStats", quicwire.OpCacheCategory, []byte{quicwire.CacheSubGetStats}},
		{"/platform.v1.CacheService/Clear", quicwire.OpCacheCategory, []byte{quicwire.CacheSubClear}},
		{"/platform.v1.CacheService/GetConfig", quicwire.OpCacheCategory, []byte{quicwire.CacheSubGetConfig}},
		{"/platform.v1.CacheService/UpdateConfig", quicwire.OpCacheCategory, []byte{quicwire.CacheSubUpdateConfig}},
		{"/platform.v1.SchedulerService/CreateJob", quicwire.OpSchedulerCategory, []byte{quicwire.SchedulerSubCreateJob}},
		{"/platform.v1.SchedulerService/GetJob", quicwire.OpSchedulerCategory, []byte{quicwire.SchedulerSubGetJob}},
		{"/platform.v1.SchedulerService/UpdateJob", quicwire.OpSchedulerCategory, []byte{quicwire.SchedulerSubUpdateJob}},
		{"/platform.v1.SchedulerService/DeleteJob", quicwire.OpSchedulerCategory, []byte{quicwire.SchedulerSubDeleteJob}},
		{"/platform.v1.SchedulerService/ListJobs", quicwire.OpSchedulerCategory, []byte{quicwire.SchedulerSubListJobs}},
		{"/platform.v1.SchedulerService/TriggerJob", quicwire.OpSchedulerCategory, []byte{quicwire.SchedulerSubTriggerJob}},
		{"/platform.v1.SchedulerService/PauseJob", quicwire.OpSchedulerCategory, []byte{quicwire.SchedulerSubPauseJob}},
		{"/platform.v1.SchedulerService/ResumeJob", quicwire.OpSchedulerCategory, []byte{quicwire.SchedulerSubResumeJob}},
		{"/platform.v1.SchedulerService/CancelJob", quicwire.OpSchedulerCategory, []byte{quicwire.SchedulerSubCancelJob}},
		{"/platform.v1.SchedulerService/GetJobHistory", quicwire.OpSchedulerCategory, []byte{quicwire.SchedulerSubGetJobHistory}},
		{"/platform.v1.SchedulerService/GetStatus", quicwire.OpSchedulerCategory, []byte{quicwire.SchedulerSubGetStatus}},
		{"/platform.v1.MessagingService/CreateChannel", quicwire.OpMessagingCategory, []byte{quicwire.MessagingSubCreateChannel}},
		{"/platform.v1.MessagingService/DeleteChannel", quicwire.OpMessagingCategory, []byte{quicwire.MessagingSubDeleteChannel}},
		{"/platform.v1.MessagingService/GetChannel", quicwire.OpMessagingCategory, []byte{quicwire.MessagingSubGetChannel}},
		{"/platform.v1.MessagingService/ListChannels", quicwire.OpMessagingCategory, []byte{quicwire.MessagingSubListChannels}},
		{"/platform.v1.MessagingService/Publish", quicwire.OpMessagingCategory, []byte{quicwire.MessagingSubPublish}},
		{"/platform.v1.MessagingService/GetStats", quicwire.OpMessagingCategory, []byte{quicwire.MessagingSubGetStats}},
		{"/platform.v1.MessagingService/GetDedupStats", quicwire.OpMessagingCategory, []byte{quicwire.MessagingSubGetDedupStats}},
		{"/platform.v1.MessagingService/GetChannelStats", quicwire.OpMessagingCategory, []byte{quicwire.MessagingSubGetChannelStats}},
	}
	for _, tc := range cases {
		t.Run(tc.grpcMethod, func(t *testing.T) {
			want := grpccreds.ScopeForMethod(tc.grpcMethod)
			if want == "" {
				t.Fatalf("%s is not in the gRPC catalog", tc.grpcMethod)
			}
			perm, _, err := quic.LookupOperationPermission(tc.opcode, tc.payload)
			if err != nil {
				t.Fatalf("QUIC lookup: %v", err)
			}
			if got := perm.Scope(); got != want {
				t.Errorf("QUIC scope %q, gRPC scope %q", got, want)
			}
		})
	}
}

func TestSubOpcodeCategory(t *testing.T) {
	t.Parallel()

	category, err := subOpcodeCategory("DeviceProfileSubAssign")
	if err != nil || category != quicwire.OpProvisioningCategory {
		t.Fatalf("DeviceProfileSubAssign: category 0x%02X, err %v", category, err)
	}
	if _, err := subOpcodeCategory("WidgetSubFrob"); err == nil {
		t.Fatal("an unknown sub-opcode family must be rejected")
	}
}

// errUnknownSubOpcodeFamily reports a sub-opcode constant whose family is not
// in quicSubOpcodePrefixes.
type errUnknownSubOpcodeFamily struct {
	name string
}

func (e errUnknownSubOpcodeFamily) Error() string {
	return fmt.Sprintf("sub-opcode constant %s has no category in quicSubOpcodePrefixes — "+
		"add its family and a catalog entry for it", e.name)
}

// subOpcodeCategory returns the category opcode carrying the named
// sub-opcode constant.
func subOpcodeCategory(name string) (byte, error) {
	for prefix, category := range quicSubOpcodePrefixes {
		if strings.HasPrefix(name, prefix) {
			return category, nil
		}
	}
	return 0, errUnknownSubOpcodeFamily{name: name}
}
