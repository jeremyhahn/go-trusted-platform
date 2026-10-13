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

package rest

import (
	"encoding/json"
	"errors"
	"net/http"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// TestVPNRoutesMatchTheDaemonHandlers pins every VPNService method to the
// path, verb and body the daemon REST handlers serve.
func TestVPNRoutesMatchTheDaemonHandlers(t *testing.T) {
	cases := []struct {
		method   string
		args     proto.Message
		verb     string
		path     string
		wantBody proto.Message
	}{
		{
			method: platformv1.VPNService_EnrolPeer_FullMethodName,
			args:   &platformv1.EnrolVPNPeerRequest{Peer: &platformv1.VPNPeer{TenantId: "acme", DeviceId: "laptop-1", Zones: []string{"management"}}},
			verb:   http.MethodPost, path: "/api/v1/vpn/peers",
			wantBody: &platformv1.VPNPeer{TenantId: "acme", DeviceId: "laptop-1", Zones: []string{"management"}},
		},
		{
			method: platformv1.VPNService_ListPeers_FullMethodName,
			args:   &platformv1.ListVPNPeersRequest{TenantId: "acme"},
			verb:   http.MethodGet, path: "/api/v1/vpn/peers?tenant_id=acme",
		},
		{
			method: platformv1.VPNService_RevokePeer_FullMethodName,
			args:   &platformv1.RevokeVPNPeerRequest{TenantId: "acme", DeviceId: "laptop-1"},
			verb:   http.MethodDelete, path: "/api/v1/vpn/peers/laptop-1?tenant_id=acme",
		},
		{
			method: platformv1.VPNService_GetStatus_FullMethodName,
			args:   &platformv1.GetVPNStatusRequest{},
			verb:   http.MethodGet, path: "/api/v1/vpn/status",
		},
		{
			method: platformv1.VPNService_ListPosturePolicies_FullMethodName,
			args:   &platformv1.ListVPNPosturePoliciesRequest{TenantId: "acme"},
			verb:   http.MethodGet, path: "/api/v1/vpn/posture-policies?tenant_id=acme",
		},
		{
			method: platformv1.VPNService_GetPosturePolicy_FullMethodName,
			args:   &platformv1.GetVPNPosturePolicyRequest{TenantId: "acme", Name: "corp"},
			verb:   http.MethodGet, path: "/api/v1/vpn/posture-policies/corp?tenant_id=acme",
		},
		{
			method: platformv1.VPNService_SetPosturePolicy_FullMethodName,
			args:   &platformv1.SetVPNPosturePolicyRequest{Policy: &platformv1.VPNPosturePolicy{TenantId: "acme", Name: "corp", Module: "package vpn.posture"}},
			verb:   http.MethodPut, path: "/api/v1/vpn/posture-policies/corp",
			wantBody: &platformv1.VPNPosturePolicy{TenantId: "acme", Module: "package vpn.posture"},
		},
		{
			method: platformv1.VPNService_DeletePosturePolicy_FullMethodName,
			args:   &platformv1.DeleteVPNPosturePolicyRequest{TenantId: "acme", Name: "corp"},
			verb:   http.MethodDelete, path: "/api/v1/vpn/posture-policies/corp?tenant_id=acme",
		},
	}
	if len(platformv1.VPNService_ServiceDesc.Methods) != len(cases) {
		t.Fatalf("VPNService has %d methods, the test pins %d", len(platformv1.VPNService_ServiceDesc.Methods), len(cases))
	}

	for _, tc := range cases {
		t.Run(tc.method, func(t *testing.T) {
			verb, path, body, err := route(tc.method, tc.args)
			if err != nil {
				t.Fatalf("route() error = %v", err)
			}
			if verb != tc.verb || path != tc.path {
				t.Fatalf("route() = %s %s, want %s %s", verb, path, tc.verb, tc.path)
			}
			if tc.wantBody == nil {
				return
			}

			// The daemon decodes the body with protojson into the bare
			// peer or policy.
			encoded, err := json.Marshal(body)
			if err != nil {
				t.Fatalf("json.Marshal() error = %v", err)
			}
			got := tc.wantBody.ProtoReflect().New().Interface()
			if err := protojson.Unmarshal(encoded, got); err != nil {
				t.Fatalf("the daemon cannot decode body %s: %v", encoded, err)
			}
			if !proto.Equal(tc.wantBody, got) {
				t.Fatalf("body = %v, want %v", got, tc.wantBody)
			}
		})
	}
}

// TestVPNRoutesRefuseIncompleteRequests checks that a request missing its
// path identity never reaches the wire.
func TestVPNRoutesRefuseIncompleteRequests(t *testing.T) {
	cases := map[string]proto.Message{
		platformv1.VPNService_RevokePeer_FullMethodName:       &platformv1.RevokeVPNPeerRequest{TenantId: "acme"},
		platformv1.VPNService_SetPosturePolicy_FullMethodName: &platformv1.SetVPNPosturePolicyRequest{},
		platformv1.VPNService_GetPosturePolicy_FullMethodName: &platformv1.GetVPNPosturePolicyRequest{TenantId: "acme"},
	}
	for method, args := range cases {
		if _, _, _, err := route(method, args); status.Code(err) != codes.InvalidArgument {
			t.Errorf("%s: route() error = %v, want InvalidArgument", method, err)
		}
	}
}

func TestVPNRequestEncoders(t *testing.T) {
	peer, err := encodeEnrolVPNPeer(&platformv1.EnrolVPNPeerRequest{})
	if err != nil || !proto.Equal(peer.(proto.Message), &platformv1.VPNPeer{}) {
		t.Fatalf("encodeEnrolVPNPeer(empty) = %v, %v; want an empty peer", peer, err)
	}

	var wrongType ErrUnexpectedRequestType
	if _, err := encodeEnrolVPNPeer(&platformv1.ListVPNPeersRequest{}); !errors.As(err, &wrongType) {
		t.Errorf("encodeEnrolVPNPeer(wrong type) error = %v, want ErrUnexpectedRequestType", err)
	}
	if _, err := encodeSetVPNPosturePolicy(&platformv1.ListVPNPeersRequest{}); !errors.As(err, &wrongType) {
		t.Errorf("encodeSetVPNPosturePolicy(wrong type) error = %v, want ErrUnexpectedRequestType", err)
	}
}
