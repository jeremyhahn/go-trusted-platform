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
	"context"
	"errors"
	"path"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

const tenantTestMoment = "2026-10-15T01:02:03Z"

// tenantWireResult is a tenant as the daemon's tenant tools display it.
func tenantWireResult(state string) map[string]interface{} {
	return map[string]interface{}{
		"id":            "t-1",
		"name":          "acme",
		"display_name":  "Acme",
		"state":         state,
		"compute_quota": map[string]interface{}{"max_vms": 4},
		"created_at":    tenantTestMoment,
		"updated_at":    "",
	}
}

func TestTenantMCP_EveryMethodHasATool(t *testing.T) {
	for _, desc := range platformv1.TenantService_ServiceDesc.Methods {
		method := path.Join("/", platformv1.TenantService_ServiceDesc.ServiceName, desc.MethodName)
		if _, ok := grpcMethodToMCPToolMap[method]; !ok {
			t.Errorf("%s has no MCP tool", method)
		}
	}
}

func TestTenantMCP_CreateTenant_FlattensQuotasAndDecodes(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"tenant_create": map[string]interface{}{
			"success": true,
			"message": "created",
			"tenant":  tenantWireResult("created"),
		},
	}, &calls)

	resp := &platformv1.CreateTenantResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.TenantService_CreateTenant_FullMethodName,
		&platformv1.CreateTenantRequest{Name: "acme", ComputeQuota: &platformv1.ComputeQuota{MaxVms: 4}}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	args := calls[0].Arguments
	if args["name"] != "acme" || args["max_vms"].(float64) != 4 {
		t.Errorf("args = %v", args)
	}
	// Only the quotas the request sets travel; an unset one is not zeroed.
	if _, ok := args["max_bridges"]; ok {
		t.Errorf("unset network quota sent: %v", args)
	}

	if !resp.GetStatus().GetSuccess() || resp.GetStatus().GetMessage() != "created" {
		t.Errorf("status = %+v", resp.GetStatus())
	}
	tenant := resp.GetTenant()
	if tenant.GetState() != platformv1.TenantState_TENANT_STATE_PENDING {
		t.Errorf("state = %v, want PENDING", tenant.GetState())
	}
	if tenant.GetComputeQuota().GetMaxVms() != 4 {
		t.Errorf("compute quota = %+v", tenant.GetComputeQuota())
	}
	if got := tenant.GetCreatedAt().AsTime().Format(time.RFC3339); got != tenantTestMoment {
		t.Errorf("created_at = %s", got)
	}
	if tenant.GetUpdatedAt() != nil {
		t.Errorf("an empty updated_at decoded to %v", tenant.GetUpdatedAt())
	}
}

func TestTenantMCP_UnknownStateIsInternal(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"tenant_get": tenantWireResult("haunted"),
	}, &calls)

	err := a.Connection().Invoke(context.Background(), platformv1.TenantService_GetTenant_FullMethodName,
		&platformv1.GetTenantRequest{TenantId: "t-1"}, &platformv1.GetTenantResponse{})
	if status.Code(err) != codes.Internal {
		t.Errorf("code = %v (%v), want Internal", status.Code(err), err)
	}
}

func TestTenantMCP_StateFromName(t *testing.T) {
	cases := map[string]platformv1.TenantState{
		"created":                  platformv1.TenantState_TENANT_STATE_PENDING,
		"suspended":                platformv1.TenantState_TENANT_STATE_SUSPENDED,
		"TENANT_STATE_UNSPECIFIED": platformv1.TenantState_TENANT_STATE_UNSPECIFIED,
	}
	for name, want := range cases {
		got, err := tenantStateFromName(name)
		if err != nil || got != want {
			t.Errorf("%q = %v, %v; want %v", name, got, err, want)
		}
	}

	_, err := tenantStateFromName("haunted")
	var unknown ErrUnknownTenantState
	if !errors.As(err, &unknown) || unknown.State != "haunted" {
		t.Errorf("err = %v, want ErrUnknownTenantState{haunted}", err)
	}
}

func TestTenantMCP_CheckQuota_ResourceTypeArg(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"tenant_check_quota": map[string]interface{}{
			"tenant_id": "t-1", "resource_type": "vms", "amount": 2, "available": true,
		},
	}, &calls)

	resp := &platformv1.CheckQuotaResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.TenantService_CheckQuota_FullMethodName,
		&platformv1.CheckQuotaRequest{TenantId: "t-1", Resource: "vms", Amount: 2}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if calls[0].Arguments["resource_type"] != "vms" {
		t.Errorf("args = %v", calls[0].Arguments)
	}
	if resp.GetResource() != "vms" || resp.GetAmount() != 2 || !resp.GetAvailable() {
		t.Errorf("resp = %+v", resp)
	}
}

func TestTenantMCP_DEKStatus_DecodesMomentsAndProgress(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"tenant_get_dek_status": map[string]interface{}{
			"tenant_id":  "t-1",
			"version":    3,
			"algorithm":  "AES-256-GCM",
			"created_at": tenantTestMoment,
			"rotated_at": "",
			"reencrypt_progress": map[string]interface{}{
				"in_progress": true, "total_keys": 10, "processed_keys": 4,
				"started_at": tenantTestMoment,
			},
		},
	}, &calls)

	resp := &platformv1.GetTenantDEKStatusResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.TenantService_GetTenantDEKStatus_FullMethodName,
		&platformv1.GetTenantDEKStatusRequest{TenantId: "t-1"}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	dek := resp.GetDekStatus()
	if dek.GetVersion() != 3 || dek.GetCreatedAt() == nil || dek.GetRotatedAt() != nil {
		t.Errorf("dek = %+v", dek)
	}
	progress := dek.GetReencryptProgress()
	if !progress.GetInProgress() || progress.GetProcessedKeys() != 4 || progress.GetStartedAt() == nil {
		t.Errorf("progress = %+v", progress)
	}
}

func TestTenantMCP_StatusOnlyReply(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"tenant_sync": map[string]interface{}{"success": true, "message": "synced 3"},
	}, &calls)

	resp := &platformv1.SyncTenantsResponse{}
	err := a.Connection().Invoke(context.Background(), platformv1.TenantService_Sync_FullMethodName,
		&platformv1.SyncTenantsRequest{}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if !resp.GetStatus().GetSuccess() || resp.GetStatus().GetMessage() != "synced 3" {
		t.Errorf("status = %+v", resp.GetStatus())
	}
}

func TestTenantMCP_ArgBuilders_WrongType(t *testing.T) {
	for _, method := range []string{
		platformv1.TenantService_CreateTenant_FullMethodName,
		platformv1.TenantService_UpdateQuotas_FullMethodName,
		platformv1.TenantService_CheckQuota_FullMethodName,
	} {
		if _, err := mcpArgBuilders[method]("not-a-proto"); err == nil {
			t.Errorf("%s: expected typed error for wrong args type", method)
		}
	}
}

func TestTenantMCP_ReplyDecoders_WrongType(t *testing.T) {
	for _, desc := range platformv1.TenantService_ServiceDesc.Methods {
		method := path.Join("/", platformv1.TenantService_ServiceDesc.ServiceName, desc.MethodName)
		decode, ok := mcpReplyDecoders[method]
		if !ok {
			continue
		}
		if err := decode(map[string]interface{}{}, "not-a-proto"); err == nil {
			t.Errorf("%s: expected typed error for wrong reply type", method)
		}
	}
}
