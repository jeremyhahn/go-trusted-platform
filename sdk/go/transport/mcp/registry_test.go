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
	"bytes"
	"context"
	"errors"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

var registryMethods = map[string]string{
	platformv1.RegistryService_List_FullMethodName:    "platform_registry_list",
	platformv1.RegistryService_Inspect_FullMethodName: "platform_registry_inspect",
	platformv1.RegistryService_Delete_FullMethodName:  "platform_registry_delete",
	platformv1.RegistryService_Status_FullMethodName:  "platform_registry_status",
}

// registryTestMillis is 2025-01-02T03:04:05.006Z in Unix milliseconds.
const registryTestMillis = int64(1735787045006)

func TestRegistryMCP_EveryMethodHasToolBuilderAndDecoder(t *testing.T) {
	for method, tool := range registryMethods {
		if got := grpcMethodToMCPToolMap[method]; got != tool {
			t.Errorf("%s routes to %q, want %q", method, got, tool)
		}
		if _, has := mcpArgBuilders[method]; !has {
			t.Errorf("%s missing argument builder", method)
		}
		if _, has := mcpReplyDecoders[method]; !has {
			t.Errorf("%s missing reply decoder", method)
		}
	}
	for _, streaming := range []string{
		platformv1.RegistryService_Push_FullMethodName,
		platformv1.RegistryService_Pull_FullMethodName,
	} {
		if tool, has := grpcMethodToMCPToolMap[streaming]; has {
			t.Errorf("streaming %s maps to %q; an MCP tool call cannot carry a stream", streaming, tool)
		}
	}
}

func TestRegistryMCP_ListRoundTrip(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"platform_registry_list": map[string]interface{}{
			"total": float64(1), "has_more": true, "next_cursor": "c2",
			"artifacts": []interface{}{map[string]interface{}{
				"id": "a1", "repository": "library/alpine", "tag": "3.20", "digest": "sha256:aa",
				"type": "container_image", "state": "available", "size": float64(4096),
				"labels": map[string]interface{}{"team": "infra"}, "os": "linux", "architecture": "arm64",
				"created_at": float64(registryTestMillis), "updated_at": float64(0), "pull_count": float64(9),
				"manifest": map[string]interface{}{
					"digest": "sha256:mm", "media_type": "application/vnd.oci.image.manifest.v1+json",
					"size": float64(512), "config_digest": "sha256:cc",
					"layers": []interface{}{map[string]interface{}{
						"digest": "sha256:ll", "size": float64(3584), "media_type": "tar", "compression": "zstd",
					}},
				},
			}},
			"pagination": map[string]interface{}{
				"page": float64(2), "page_size": float64(1), "total_pages": float64(3), "total_items": float64(3),
			},
		},
	}, &calls)

	resp := &platformv1.ListArtifactsResponse{}
	req := &platformv1.ListArtifactsRequest{
		Repository: "library/alpine", Type: platformv1.ArtifactType_ARTIFACT_TYPE_CONTAINER_IMAGE, Limit: 1, Offset: 1,
	}
	if err := a.Connection().Invoke(context.Background(), platformv1.RegistryService_List_FullMethodName, req, resp); err != nil {
		t.Fatalf("List: %v", err)
	}

	if len(calls) != 1 || calls[0].Name != "platform_registry_list" {
		t.Fatalf("calls = %+v", calls)
	}
	args := calls[0].Arguments
	if args["repository"] != "library/alpine" || args["artifact_type"] != float64(1) ||
		args["limit"] != float64(1) || args["offset"] != float64(1) {
		t.Errorf("list sent %v, want the repository, type and page", args)
	}
	if _, sent := args["match_labels"]; sent {
		t.Errorf("list without a selector sent match_labels: %v", args)
	}

	if resp.GetTotal() != 1 || !resp.GetHasMore() || resp.GetNextCursor() != "c2" {
		t.Errorf("page = %+v", resp)
	}
	if p := resp.GetPagination(); p.GetPage() != 2 || p.GetPageSize() != 1 || p.GetTotalPages() != 3 || p.GetTotalItems() != 3 {
		t.Errorf("pagination = %+v", p)
	}
	if len(resp.GetArtifacts()) != 1 {
		t.Fatalf("artifacts = %d, want 1", len(resp.GetArtifacts()))
	}
	art := resp.GetArtifacts()[0]
	if art.GetId() != "a1" || art.GetTag() != "3.20" || art.GetSize() != 4096 || art.GetPullCount() != 9 ||
		art.GetOs() != "linux" || art.GetArchitecture() != "arm64" || art.GetLabels()["team"] != "infra" {
		t.Errorf("artifact = %+v", art)
	}
	if art.GetType() != platformv1.ArtifactType_ARTIFACT_TYPE_CONTAINER_IMAGE ||
		art.GetState() != platformv1.ArtifactState_ARTIFACT_STATE_AVAILABLE {
		t.Errorf("type/state = %v/%v", art.GetType(), art.GetState())
	}
	if got := art.GetCreatedAt().AsTime().UnixMilli(); got != registryTestMillis {
		t.Errorf("created_at = %d, want %d", got, registryTestMillis)
	}
	if art.GetUpdatedAt() != nil {
		t.Errorf("updated_at = %v, want unset for 0", art.GetUpdatedAt())
	}
	layers := art.GetManifest().GetLayers()
	if art.GetManifest().GetConfigDigest() != "sha256:cc" || len(layers) != 1 ||
		layers[0].GetCompression() != platformv1.CompressionType_COMPRESSION_TYPE_ZSTD || layers[0].GetSize() != 3584 {
		t.Errorf("manifest = %+v", art.GetManifest())
	}
}

func TestRegistryMCP_ListCarriesCursorSortAndSelector(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"platform_registry_list": map[string]interface{}{"total": float64(0)},
	}, &calls)

	req := &platformv1.ListArtifactsRequest{
		Cursor: "c1", SortBy: "size", Ascending: true,
		Selector: &platformv1.LabelSelector{
			MatchLabels:      map[string]string{"env": "prod"},
			MatchExpressions: []string{"tier in (edge)"},
		},
	}
	resp := &platformv1.ListArtifactsResponse{}
	if err := a.Connection().Invoke(context.Background(), platformv1.RegistryService_List_FullMethodName, req, resp); err != nil {
		t.Fatalf("List: %v", err)
	}
	if len(calls) != 1 {
		t.Fatalf("calls = %+v", calls)
	}
	args := calls[0].Arguments
	if args["cursor"] != "c1" || args["sort_by"] != "size" || args["ascending"] != true {
		t.Errorf("list sent %v, want the cursor and sort order", args)
	}
	labels, ok := args["match_labels"].(map[string]interface{})
	if !ok || labels["env"] != "prod" {
		t.Errorf("match_labels = %v, want env=prod", args["match_labels"])
	}
	exprs, ok := args["match_expressions"].([]interface{})
	if !ok || len(exprs) != 1 || exprs[0] != "tier in (edge)" {
		t.Errorf("match_expressions = %v, want [tier in (edge)]", args["match_expressions"])
	}
}

func TestRegistryMCP_InspectRoundTrip(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"platform_registry_inspect": map[string]interface{}{
			"artifact": map[string]interface{}{"id": "a1", "repository": "library/alpine", "type": "helm_chart"},
			"tags":     []interface{}{"3.20", "latest"},
			"signatures": []interface{}{map[string]interface{}{
				"key_id": "k1", "algorithm": "ES256", "signature": "c2ln", "signed_at": float64(registryTestMillis), "signer": "ci",
			}},
			"scan_result": map[string]interface{}{
				"scanner": "trivy", "scanned_at": float64(registryTestMillis), "high_count": float64(1),
				"vulnerabilities": []interface{}{map[string]interface{}{
					"id": "CVE-2025-0001", "severity": "high", "package_name": "musl", "fixed_version": "1.2.6",
				}},
			},
		},
	}, &calls)

	resp := &platformv1.InspectArtifactResponse{}
	req := &platformv1.InspectArtifactRequest{
		Repository: "library/alpine", Reference: "3.20", IncludeSignatures: true, IncludeScanResult: true,
	}
	if err := a.Connection().Invoke(context.Background(), platformv1.RegistryService_Inspect_FullMethodName, req, resp); err != nil {
		t.Fatalf("Inspect: %v", err)
	}

	args := calls[0].Arguments
	if calls[0].Name != "platform_registry_inspect" || args["repository"] != "library/alpine" || args["reference"] != "3.20" ||
		args["digest"] != "" || args["include_signatures"] != true || args["include_scan_result"] != true {
		t.Errorf("inspect sent %s %v", calls[0].Name, args)
	}

	detail := resp.GetDetail()
	if detail.GetArtifact().GetType() != platformv1.ArtifactType_ARTIFACT_TYPE_HELM_CHART || len(detail.GetTags()) != 2 {
		t.Errorf("detail = %+v", detail)
	}
	sig := detail.GetSignatures()
	if len(sig) != 1 || sig[0].GetKeyId() != "k1" || !bytes.Equal(sig[0].GetSignature(), []byte("sig")) ||
		sig[0].GetSignedAt().AsTime().UnixMilli() != registryTestMillis {
		t.Errorf("signatures = %+v", sig)
	}
	scan := detail.GetScanResult()
	vulns := scan.GetVulnerabilities()
	if scan.GetScanner() != "trivy" || scan.GetHighCount() != 1 || len(vulns) != 1 ||
		vulns[0].GetSeverity() != platformv1.VulnerabilitySeverity_VULNERABILITY_SEVERITY_HIGH || vulns[0].GetFixedVersion() != "1.2.6" {
		t.Errorf("scan = %+v", scan)
	}
}

func TestRegistryMCP_InspectWithoutDetailMapsToNoDetail(t *testing.T) {
	resp := &platformv1.InspectArtifactResponse{Detail: &platformv1.ArtifactDetail{}}
	_, err := invokePhase35(t, map[string]interface{}{
		"platform_registry_inspect": map[string]interface{}{"repository": "r", "reference": "t", "digest": ""},
	}, platformv1.RegistryService_Inspect_FullMethodName, &platformv1.InspectArtifactRequest{Repository: "r", Reference: "t"}, resp)
	if err != nil {
		t.Fatalf("Inspect: %v", err)
	}
	if resp.GetDetail() != nil {
		t.Errorf("detail = %+v, want none", resp.GetDetail())
	}
}

func TestRegistryMCP_DeleteAndStatusRoundTrip(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"platform_registry_delete": map[string]interface{}{
			"repository": "library/alpine", "reference": "3.20", "digest": "sha256:aa",
			"bytes_freed": float64(4096), "timestamp": float64(registryTestMillis),
		},
		"platform_registry_status": map[string]interface{}{
			"health": "degraded", "version": "1.4.0", "read_only": true,
			"started_at": float64(registryTestMillis), "timestamp": float64(0),
			"storage": map[string]interface{}{"total_bytes": float64(100), "used_bytes": float64(40), "repository_count": float64(2)},
			"components": []interface{}{map[string]interface{}{
				"name": "blobstore", "status": "unhealthy", "message": "disk", "details": map[string]interface{}{"path": "/var"},
			}},
		},
	}, &calls)
	conn := a.Connection()
	ctx := context.Background()

	deleteResp := &platformv1.DeleteArtifactResponse{}
	if err := conn.Invoke(ctx, platformv1.RegistryService_Delete_FullMethodName,
		&platformv1.DeleteArtifactRequest{Repository: "library/alpine", Reference: "3.20", Force: true}, deleteResp); err != nil {
		t.Fatalf("Delete: %v", err)
	}
	if deleteResp.GetDigest() != "sha256:aa" || deleteResp.GetBytesFreed() != 4096 ||
		deleteResp.GetTimestamp().AsTime().UnixMilli() != registryTestMillis {
		t.Errorf("delete = %+v", deleteResp)
	}
	if args := calls[0].Arguments; args["repository"] != "library/alpine" || args["reference"] != "3.20" || args["force"] != true {
		t.Errorf("delete sent %v", args)
	}

	statusResp := &platformv1.RegistryStatusResponse{}
	if err := conn.Invoke(ctx, platformv1.RegistryService_Status_FullMethodName, &platformv1.RegistryStatusRequest{}, statusResp); err != nil {
		t.Fatalf("Status: %v", err)
	}
	if statusResp.GetHealth() != platformv1.HealthStatus_HEALTH_STATUS_DEGRADED || statusResp.GetVersion() != "1.4.0" ||
		!statusResp.GetReadOnly() || statusResp.GetTimestamp() != nil ||
		statusResp.GetStorage().GetUsedBytes() != 40 || statusResp.GetStorage().GetRepositoryCount() != 2 {
		t.Errorf("status = %+v", statusResp)
	}
	comps := statusResp.GetComponents()
	if len(comps) != 1 || comps[0].GetStatus() != platformv1.HealthStatus_HEALTH_STATUS_UNHEALTHY || comps[0].GetDetails()["path"] != "/var" {
		t.Errorf("components = %+v", comps)
	}
	if len(calls[1].Arguments) != 0 {
		t.Errorf("status sent %v, want no arguments", calls[1].Arguments)
	}
}

func TestRegistryMCP_BuildersRefuseTheWrongRequestType(t *testing.T) {
	for method := range registryMethods {
		var wrongType ErrUnexpectedArgsType
		if _, err := mcpArgBuilders[method](&platformv1.GetNAT64StatusRequest{}); !errors.As(err, &wrongType) ||
			wrongType.Method != method {
			t.Errorf("%s: wrong request gave %v, want ErrUnexpectedArgsType naming the method", method, err)
		}
	}
}

func TestRegistryMCP_DecodersRefuseTheWrongReplyAndMalformedResults(t *testing.T) {
	replies := map[string]interface{}{
		platformv1.RegistryService_List_FullMethodName:    &platformv1.ListArtifactsResponse{},
		platformv1.RegistryService_Inspect_FullMethodName: &platformv1.InspectArtifactResponse{},
		platformv1.RegistryService_Delete_FullMethodName:  &platformv1.DeleteArtifactResponse{},
		platformv1.RegistryService_Status_FullMethodName:  &platformv1.RegistryStatusResponse{},
	}
	for method, reply := range replies {
		decode := mcpReplyDecoders[method]

		var wrongType ErrUnexpectedReplyType
		if err := decode(map[string]interface{}{}, &platformv1.GetNAT64StatusResponse{}); !errors.As(err, &wrongType) ||
			wrongType.Method != method {
			t.Errorf("%s: wrong reply gave %v, want ErrUnexpectedReplyType naming the method", method, err)
		}
		var unmarshal ErrUnmarshalFailed
		if err := decode("not an object", reply); !errors.As(err, &unmarshal) {
			t.Errorf("%s: wrong shape gave %v, want ErrUnmarshalFailed", method, err)
		}
		var marshal ErrMarshalFailed
		if err := decode(make(chan int), reply); !errors.As(err, &marshal) {
			t.Errorf("%s: unencodable result gave %v, want ErrMarshalFailed", method, err)
		}
	}
}

func TestRegistryMCP_DecodersRefuseUnknownEnumNames(t *testing.T) {
	tests := []struct {
		name   string
		method string
		result map[string]interface{}
		reply  interface{}
		field  string
	}{
		{"artifact type", platformv1.RegistryService_List_FullMethodName,
			map[string]interface{}{"artifacts": []interface{}{map[string]interface{}{"type": "tarball"}}},
			&platformv1.ListArtifactsResponse{}, "artifact type"},
		{"artifact state", platformv1.RegistryService_List_FullMethodName,
			map[string]interface{}{"artifacts": []interface{}{map[string]interface{}{"state": "lost"}}},
			&platformv1.ListArtifactsResponse{}, "artifact state"},
		{"layer compression", platformv1.RegistryService_List_FullMethodName,
			map[string]interface{}{"artifacts": []interface{}{map[string]interface{}{
				"manifest": map[string]interface{}{"layers": []interface{}{map[string]interface{}{"compression": "lz4"}}},
			}}},
			&platformv1.ListArtifactsResponse{}, "compression"},
		{"vulnerability severity", platformv1.RegistryService_Inspect_FullMethodName,
			map[string]interface{}{"artifact": map[string]interface{}{}, "scan_result": map[string]interface{}{
				"vulnerabilities": []interface{}{map[string]interface{}{"severity": "dire"}},
			}},
			&platformv1.InspectArtifactResponse{}, "vulnerability severity"},
		{"registry health", platformv1.RegistryService_Status_FullMethodName,
			map[string]interface{}{"health": "fine"}, &platformv1.RegistryStatusResponse{}, "health"},
		{"component health", platformv1.RegistryService_Status_FullMethodName,
			map[string]interface{}{"components": []interface{}{map[string]interface{}{"status": "fine"}}},
			&platformv1.RegistryStatusResponse{}, "health"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var unknown ErrUnknownRegistryEnum
			if err := mcpReplyDecoders[tt.method](tt.result, tt.reply); !errors.As(err, &unknown) || unknown.Field != tt.field {
				t.Errorf("err = %v, want ErrUnknownRegistryEnum for %s", err, tt.field)
			}
		})
	}
}
