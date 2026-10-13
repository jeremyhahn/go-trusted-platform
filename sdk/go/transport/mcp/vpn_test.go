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
	"errors"
	"reflect"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestVPNMethodsMapToTheDaemonTools pins every VPNService method to the tool
// the daemon registers.
func TestVPNMethodsMapToTheDaemonTools(t *testing.T) {
	want := map[string]string{
		platformv1.VPNService_EnrolPeer_FullMethodName:           "vpn_peer_enrol",
		platformv1.VPNService_ListPeers_FullMethodName:           "vpn_peer_list",
		platformv1.VPNService_RevokePeer_FullMethodName:          "vpn_peer_revoke",
		platformv1.VPNService_GetStatus_FullMethodName:           "vpn_status",
		platformv1.VPNService_GetPosturePolicy_FullMethodName:    "vpn_posture_policy_get",
		platformv1.VPNService_SetPosturePolicy_FullMethodName:    "vpn_posture_policy_set",
		platformv1.VPNService_DeletePosturePolicy_FullMethodName: "vpn_posture_policy_delete",
		platformv1.VPNService_ListPosturePolicies_FullMethodName: "vpn_posture_policy_list",
	}
	if len(platformv1.VPNService_ServiceDesc.Methods) != len(want) {
		t.Fatalf("VPNService has %d methods, the test pins %d", len(platformv1.VPNService_ServiceDesc.Methods), len(want))
	}
	for method, tool := range want {
		if got := grpcMethodToMCPToolMap[method]; got != tool {
			t.Errorf("%s maps to %q, want %q", method, got, tool)
		}
	}
}

// TestVPNToolArguments checks the arguments each tool receives: the nested
// peer and policy are flattened, and the flat requests keep their names.
func TestVPNToolArguments(t *testing.T) {
	enrol, err := buildVPNEnrolPeerArgs(&platformv1.EnrolVPNPeerRequest{
		Peer: &platformv1.VPNPeer{TenantId: "acme", DeviceId: "laptop-1", Zones: []string{"management"}},
	})
	if err != nil {
		t.Fatalf("buildVPNEnrolPeerArgs() error = %v", err)
	}
	wantEnrol := map[string]interface{}{"tenant_id": "acme", "device_id": "laptop-1", "zones": []string{"management"}}
	if !reflect.DeepEqual(enrol, wantEnrol) {
		t.Errorf("enrol arguments = %v, want %v", enrol, wantEnrol)
	}

	set, err := buildVPNSetPosturePolicyArgs(&platformv1.SetVPNPosturePolicyRequest{
		Policy: &platformv1.VPNPosturePolicy{TenantId: "acme", Name: "corp", Module: "package vpn.posture"},
	})
	if err != nil {
		t.Fatalf("buildVPNSetPosturePolicyArgs() error = %v", err)
	}
	wantSet := map[string]interface{}{"tenant_id": "acme", "name": "corp", "module": "package vpn.posture"}
	if !reflect.DeepEqual(set, wantSet) {
		t.Errorf("set arguments = %v, want %v", set, wantSet)
	}

	revoke, err := structToMap(&platformv1.RevokeVPNPeerRequest{TenantId: "acme", DeviceId: "laptop-1"})
	if err != nil {
		t.Fatalf("structToMap() error = %v", err)
	}
	if revoke["tenant_id"] != "acme" || revoke["device_id"] != "laptop-1" {
		t.Errorf("revoke arguments = %v, want tenant_id and device_id", revoke)
	}
}

func TestVPNToolArgumentsRefuseTheWrongRequestType(t *testing.T) {
	var wrongType ErrUnexpectedArgsType
	if _, err := buildVPNEnrolPeerArgs(&platformv1.ListVPNPeersRequest{}); !errors.As(err, &wrongType) {
		t.Errorf("buildVPNEnrolPeerArgs(wrong type) error = %v, want ErrUnexpectedArgsType", err)
	}
	if _, err := buildVPNSetPosturePolicyArgs(&platformv1.ListVPNPeersRequest{}); !errors.As(err, &wrongType) {
		t.Errorf("buildVPNSetPosturePolicyArgs(wrong type) error = %v, want ErrUnexpectedArgsType", err)
	}
}
