// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
//
// This file is part of go-trusted-platform.
//
// go-trusted-platform is dual-licensed:
//
//  1. GNU Affero General Public License v3.0 (AGPL-3.0)
//     See LICENSE file or visit https://www.gnu.org/licenses/agpl-3.0.html
//
//  2. Commercial License
//     Contact licensing@automatethethings.com for commercial licensing options.
package mcp

import (
	"context"
	"fmt"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// The server's manifest tools answer the gRPC reply as protojson in the
// proto's own field names (pkg/api/daemon/mcp_attestation_manifests.go).

func TestAttestationManifestsMCP_List_ArgsAndDecode(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"attestation_list_manifests": map[string]interface{}{
			"manifests": []interface{}{map[string]interface{}{"id": "m-11", "host_id": "h1"}},
			"total":     30,
		},
	}, &calls)

	resp := &platformv1.ListManifestsResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.AttestationService_ListManifests_FullMethodName,
		&platformv1.ListManifestsRequest{HostId: "h1", Limit: 10, Offset: 10}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if len(calls) != 1 || calls[0].Name != "attestation_list_manifests" {
		t.Fatalf("calls = %+v, want attestation_list_manifests", calls)
	}
	if fmt.Sprint(calls[0].Arguments["limit"]) != "10" || fmt.Sprint(calls[0].Arguments["offset"]) != "10" {
		t.Fatalf("arguments = %+v, want limit 10 and offset 10", calls[0].Arguments)
	}
	if calls[0].Arguments["host_id"] != "h1" {
		t.Fatalf("arguments = %+v, want host_id h1", calls[0].Arguments)
	}
	if resp.GetTotal() != 30 || len(resp.GetManifests()) != 1 || resp.GetManifests()[0].GetHostId() != "h1" {
		t.Fatalf("resp = %+v", resp)
	}
}

func TestAttestationManifestsMCP_Get_ArgsAndDecode(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"attestation_get_manifest": map[string]interface{}{
			"manifest": map[string]interface{}{"id": "m-1", "nonce": "AQI=", "signature": "AwQ="},
		},
	}, &calls)

	resp := &platformv1.GetManifestResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.AttestationService_GetManifest_FullMethodName,
		&platformv1.GetManifestRequest{Id: "m-1"}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if len(calls) != 1 || calls[0].Name != "attestation_get_manifest" || calls[0].Arguments["id"] != "m-1" {
		t.Fatalf("calls = %+v, want attestation_get_manifest with id m-1", calls)
	}
	m := resp.GetManifest()
	if m.GetId() != "m-1" || string(m.GetNonce()) != "\x01\x02" || string(m.GetSignature()) != "\x03\x04" {
		t.Fatalf("manifest = %+v", m)
	}
}

func TestAttestationManifestsMCP_Delete_Args(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"attestation_delete_manifest": map[string]interface{}{},
	}, &calls)

	resp := &platformv1.DeleteManifestResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.AttestationService_DeleteManifest_FullMethodName,
		&platformv1.DeleteManifestRequest{Id: "m-1"}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if len(calls) != 1 || calls[0].Name != "attestation_delete_manifest" || calls[0].Arguments["id"] != "m-1" {
		t.Fatalf("calls = %+v, want attestation_delete_manifest with id m-1", calls)
	}
}
