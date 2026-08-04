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
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	mcpapi "github.com/jeremyhahn/go-trusted-platform/pkg/api/mcp"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// eabWireCredential is a canonical daemon-shaped credential JSON payload
// (pkg/api/daemon/mcp_eab.go::eabCredentialJSON): uint64 ids as decimal
// strings, status as the domain name, RFC3339 timestamps.
func eabWireCredential() map[string]interface{} {
	return map[string]interface{}{
		"id":         "42",
		"key_id":     "key-a",
		"profile_id": "7",
		"tenant_id":  "tenant-1",
		"status":     "active",
		"created_at": "2026-01-02T03:04:05Z",
		"expires_at": "2026-01-03T03:04:05Z",
	}
}

// TestEABMCP_ToolMappingParity pins the adapter tool names against the
// server-side ToolRegistry registrations — the kms_sign bug class where
// a tool is mapped on one side only.
func TestEABMCP_ToolMappingParity(t *testing.T) {
	registry := mcpapi.NewToolRegistry(nil, logging.DefaultLogger())
	registered := map[string]bool{}
	for _, td := range registry.ListTools() {
		registered[td.Name] = true
	}

	count := 0
	for method, tool := range grpcMethodToMCPToolMap {
		if len(method) < len("/platform.v1.EABService/") ||
			method[:len("/platform.v1.EABService/")] != "/platform.v1.EABService/" {
			continue
		}
		count++
		if !registered[tool] {
			t.Errorf("adapter maps %s -> %q but the server does not register that tool", method, tool)
		}
		if _, has := mcpArgBuilders[method]; !has {
			t.Errorf("%s missing argument builder", method)
		}
		if _, has := mcpReplyDecoders[method]; !has {
			t.Errorf("%s missing reply decoder", method)
		}
	}
	if count != 11 {
		t.Errorf("expected 11 EABService methods mapped, got %d", count)
	}
}

func TestEABMCP_CreateCredential_ArgsAndDecode(t *testing.T) {
	var calls []toolCall
	result := eabWireCredential()
	result["hmac_key"] = "aGVsbG8"
	a := provisioningTestServer(t, map[string]interface{}{
		"platform_eab_create_credential": result,
	}, &calls)

	conn := a.Connection()
	resp := &platformv1.CreateEABCredentialResponse{}
	err := conn.Invoke(context.Background(), "/platform.v1.EABService/CreateCredential",
		&platformv1.CreateEABCredentialRequest{
			ProfileId:        7,
			TenantId:         "tenant-1",
			ExpiresInSeconds: 3600,
			HmacKeyLength:    64,
		}, resp)
	if err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	if len(calls) != 1 || calls[0].Name != "platform_eab_create_credential" {
		t.Fatalf("calls = %+v", calls)
	}
	args := calls[0].Arguments
	// uint64 profile_id travels as a decimal string.
	if args["profile_id"] != "7" || args["tenant_id"] != "tenant-1" {
		t.Errorf("args = %v", args)
	}
	if args["expires_in_seconds"].(float64) != 3600 || args["hmac_key_length"].(float64) != 64 {
		t.Errorf("numeric args = %v", args)
	}

	cred := resp.GetCredential()
	if cred.GetId() != 42 || cred.GetProfileId() != 7 || cred.GetHmacKey() != "aGVsbG8" {
		t.Errorf("decode mismatch: %+v", cred)
	}
	if cred.GetStatus() != platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_ACTIVE {
		t.Errorf("status = %v", cred.GetStatus())
	}
	if cred.GetCreatedAt() == nil || cred.GetExpiresAt() == nil {
		t.Error("timestamps not decoded")
	}
}

func TestEABMCP_GetCredential_StringIDArg(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"platform_eab_get_credential": eabWireCredential(),
	}, &calls)

	conn := a.Connection()
	resp := &platformv1.GetEABCredentialResponse{}
	if err := conn.Invoke(context.Background(), "/platform.v1.EABService/GetCredential",
		&platformv1.GetEABCredentialRequest{CredentialId: 18446744073709551615}, resp); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if calls[0].Arguments["credential_id"] != "18446744073709551615" {
		t.Errorf("credential_id arg = %v, want full-precision decimal string",
			calls[0].Arguments["credential_id"])
	}
	if resp.GetCredential().GetId() != 42 {
		t.Errorf("id = %d", resp.GetCredential().GetId())
	}
}

func TestEABMCP_GetCredentialByKeyID(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"platform_eab_get_credential_by_key_id": eabWireCredential(),
	}, &calls)

	conn := a.Connection()
	resp := &platformv1.GetEABCredentialResponse{}
	if err := conn.Invoke(context.Background(), "/platform.v1.EABService/GetCredentialByKeyID",
		&platformv1.GetEABCredentialByKeyIDRequest{KeyId: "key-a"}, resp); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if calls[0].Arguments["key_id"] != "key-a" {
		t.Errorf("key_id arg = %v", calls[0].Arguments["key_id"])
	}
	if resp.GetCredential().GetKeyId() != "key-a" {
		t.Errorf("key_id = %q", resp.GetCredential().GetKeyId())
	}
}

func TestEABMCP_ListCredentials_FiltersAndDecode(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"platform_eab_list_credentials": map[string]interface{}{
			"credentials": []interface{}{eabWireCredential()},
			"total":       3,
			"page":        2,
			"page_size":   1,
		},
	}, &calls)

	conn := a.Connection()
	resp := &platformv1.ListEABCredentialsResponse{}
	if err := conn.Invoke(context.Background(), "/platform.v1.EABService/ListCredentials",
		&platformv1.ListEABCredentialsRequest{
			TenantId:     "tenant-1",
			ProfileId:    7,
			ActiveOnly:   true,
			StatusFilter: platformv1.EABCredentialStatus_EAB_CREDENTIAL_STATUS_ACTIVE,
			Pagination:   &platformv1.PaginationRequest{Page: 2, PageSize: 1},
		}, resp); err != nil {
		t.Fatalf("Invoke: %v", err)
	}

	args := calls[0].Arguments
	if args["tenant_id"] != "tenant-1" || args["profile_id"] != "7" ||
		args["active_only"] != true || args["status"] != "active" {
		t.Errorf("filter args = %v", args)
	}
	if args["page"].(float64) != 2 || args["page_size"].(float64) != 1 {
		t.Errorf("pagination args = %v", args)
	}

	if len(resp.GetCredentials()) != 1 || resp.GetTotal() != 3 {
		t.Errorf("decode: creds=%d total=%d", len(resp.GetCredentials()), resp.GetTotal())
	}
	pg := resp.GetPagination()
	if pg.GetPage() != 2 || pg.GetPageSize() != 1 || pg.GetTotalItems() != 3 || pg.GetTotalPages() != 3 {
		t.Errorf("pagination = %+v", pg)
	}
}

func TestEABMCP_RevokeDeleteMarkUsed(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"platform_eab_revoke_credential":    map[string]interface{}{"credential_id": "5", "revoker_id": "9", "status": "revoked"},
		"platform_eab_delete_credential":    map[string]interface{}{"credential_id": "5", "status": "deleted"},
		"platform_eab_mark_credential_used": map[string]interface{}{"credential_id": "5", "status": "used"},
	}, &calls)
	conn := a.Connection()

	revoke := &platformv1.RevokeEABCredentialResponse{}
	if err := conn.Invoke(context.Background(), "/platform.v1.EABService/RevokeCredential",
		&platformv1.RevokeEABCredentialRequest{CredentialId: 5, RevokerId: 9}, revoke); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if !revoke.GetStatus().GetSuccess() {
		t.Error("revoke: expected success")
	}
	if calls[0].Arguments["credential_id"] != "5" || calls[0].Arguments["revoker_id"] != "9" {
		t.Errorf("revoke args = %v", calls[0].Arguments)
	}

	del := &platformv1.DeleteEABCredentialResponse{}
	if err := conn.Invoke(context.Background(), "/platform.v1.EABService/DeleteCredential",
		&platformv1.DeleteEABCredentialRequest{CredentialId: 5}, del); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if !del.GetStatus().GetSuccess() {
		t.Error("delete: expected success")
	}

	used := &platformv1.MarkEABCredentialUsedResponse{}
	if err := conn.Invoke(context.Background(), "/platform.v1.EABService/MarkCredentialUsed",
		&platformv1.MarkEABCredentialUsedRequest{CredentialId: 5}, used); err != nil {
		t.Fatalf("mark used: %v", err)
	}
	if !used.GetStatus().GetSuccess() {
		t.Error("mark used: expected success")
	}
}

func TestEABMCP_ValidateCredential(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"platform_eab_validate_credential": map[string]interface{}{
			"valid":      true,
			"credential": eabWireCredential(),
		},
	}, &calls)

	conn := a.Connection()
	resp := &platformv1.ValidateEABCredentialResponse{}
	if err := conn.Invoke(context.Background(), "/platform.v1.EABService/ValidateCredential",
		&platformv1.ValidateEABCredentialRequest{KeyId: "key-a", HmacKey: "aGVsbG8"}, resp); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if calls[0].Arguments["key_id"] != "key-a" || calls[0].Arguments["hmac_key"] != "aGVsbG8" {
		t.Errorf("args = %v", calls[0].Arguments)
	}
	if !resp.GetValid() || resp.GetCredential().GetId() != 42 {
		t.Errorf("decode mismatch: valid=%v cred=%+v", resp.GetValid(), resp.GetCredential())
	}
}

func TestEABMCP_ValidateCredential_InvalidResult(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"platform_eab_validate_credential": map[string]interface{}{
			"valid":         false,
			"key_id":        "k",
			"error_message": "eab: credential not found: keyID=k",
		},
	}, &calls)

	conn := a.Connection()
	resp := &platformv1.ValidateEABCredentialResponse{}
	if err := conn.Invoke(context.Background(), "/platform.v1.EABService/ValidateCredential",
		&platformv1.ValidateEABCredentialRequest{KeyId: "k", HmacKey: "aGVsbG8"}, resp); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if resp.GetValid() || resp.GetErrorMessage() == "" {
		t.Errorf("expected in-band failure, got %+v", resp)
	}
}

func TestEABMCP_QRCodeAndURL(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"platform_eab_get_credential_qr_code": map[string]interface{}{
			"credential_id": "5",
			"content_type":  "image/png",
			"size":          256,
			// []byte round-trips as std base64 in JSON ("PNG!" -> UE5HIQ==).
			"qr_code": "UE5HIQ==",
		},
		"platform_eab_get_enrollment_url": map[string]interface{}{
			"credential_id": "5",
			"url":           "https://acme.example/enroll?kid=x",
		},
	}, &calls)
	conn := a.Connection()

	qr := &platformv1.GetEABCredentialQRCodeResponse{}
	if err := conn.Invoke(context.Background(), "/platform.v1.EABService/GetCredentialQRCode",
		&platformv1.GetEABCredentialQRCodeRequest{CredentialId: 5, Size: 256}, qr); err != nil {
		t.Fatalf("qr: %v", err)
	}
	if calls[0].Arguments["size"].(float64) != 256 {
		t.Errorf("size arg = %v", calls[0].Arguments["size"])
	}
	if string(qr.GetQrCode()) != "PNG!" || qr.GetContentType() != "image/png" {
		t.Errorf("qr decode: %q %q", qr.GetQrCode(), qr.GetContentType())
	}

	urlResp := &platformv1.GetEABEnrollmentURLResponse{}
	if err := conn.Invoke(context.Background(), "/platform.v1.EABService/GetEnrollmentURL",
		&platformv1.GetEABEnrollmentURLRequest{CredentialId: 5, Path: "/enroll"}, urlResp); err != nil {
		t.Fatalf("url: %v", err)
	}
	if calls[1].Arguments["path"] != "/enroll" {
		t.Errorf("path arg = %v", calls[1].Arguments["path"])
	}
	if urlResp.GetUrl() != "https://acme.example/enroll?kid=x" {
		t.Errorf("url = %q", urlResp.GetUrl())
	}
}

func TestEABMCP_CleanupExpired(t *testing.T) {
	var calls []toolCall
	a := provisioningTestServer(t, map[string]interface{}{
		"platform_eab_cleanup_expired_credentials": map[string]interface{}{
			"deleted_count": 3,
			"tenant_id":     "t1",
			"status":        "ok",
		},
	}, &calls)

	conn := a.Connection()
	resp := &platformv1.CleanupExpiredEABCredentialsResponse{}
	if err := conn.Invoke(context.Background(), "/platform.v1.EABService/CleanupExpiredCredentials",
		&platformv1.CleanupExpiredEABCredentialsRequest{TenantId: "t1"}, resp); err != nil {
		t.Fatalf("Invoke: %v", err)
	}
	if calls[0].Arguments["tenant_id"] != "t1" {
		t.Errorf("tenant_id arg = %v", calls[0].Arguments["tenant_id"])
	}
	if resp.GetDeletedCount() != 3 || !resp.GetStatus().GetSuccess() {
		t.Errorf("decode: %+v", resp)
	}
}

// TestEABMCP_ArgBuilders_WrongType covers the typed error path when a
// builder receives an unexpected request type.
func TestEABMCP_ArgBuilders_WrongType(t *testing.T) {
	builders := map[string]mcpArgBuilder{
		"CreateCredential":          buildEABCreateCredentialArgs,
		"GetCredential":             buildEABGetCredentialArgs,
		"GetCredentialByKeyID":      buildEABGetCredentialByKeyIDArgs,
		"ListCredentials":           buildEABListCredentialsArgs,
		"RevokeCredential":          buildEABRevokeCredentialArgs,
		"ValidateCredential":        buildEABValidateCredentialArgs,
		"DeleteCredential":          buildEABDeleteCredentialArgs,
		"GetCredentialQRCode":       buildEABGetCredentialQRCodeArgs,
		"GetEnrollmentURL":          buildEABGetEnrollmentURLArgs,
		"MarkCredentialUsed":        buildEABMarkCredentialUsedArgs,
		"CleanupExpiredCredentials": buildEABCleanupExpiredCredentialsArgs,
	}
	for name, build := range builders {
		if _, err := build("not-a-proto"); err == nil {
			t.Errorf("%s: expected typed error for wrong args type", name)
		}
	}
}

// TestEABMCP_ReplyDecoders_WrongType covers the typed error path when a
// decoder receives an unexpected reply type.
func TestEABMCP_ReplyDecoders_WrongType(t *testing.T) {
	decoders := map[string]mcpReplyDecoder{
		"CreateCredential":          decodeEABCreateCredentialResult,
		"GetCredential":             decodeEABGetCredentialResult,
		"ListCredentials":           decodeEABListCredentialsResult,
		"RevokeCredential":          decodeEABRevokeCredentialResult,
		"ValidateCredential":        decodeEABValidateCredentialResult,
		"DeleteCredential":          decodeEABDeleteCredentialResult,
		"GetCredentialQRCode":       decodeEABGetCredentialQRCodeResult,
		"GetEnrollmentURL":          decodeEABGetEnrollmentURLResult,
		"MarkCredentialUsed":        decodeEABMarkCredentialUsedResult,
		"CleanupExpiredCredentials": decodeEABCleanupExpiredCredentialsResult,
	}
	for name, decode := range decoders {
		if err := decode(map[string]interface{}{}, "not-a-proto"); err == nil {
			t.Errorf("%s: expected typed error for wrong reply type", name)
		}
	}
}

// TestEABMCP_FlexUint64 covers both wire forms for uint64 identifiers.
func TestEABMCP_FlexUint64(t *testing.T) {
	var u eabFlexUint64
	if err := u.UnmarshalJSON([]byte(`"42"`)); err != nil || uint64(u) != 42 {
		t.Errorf("string form: %v %d", err, u)
	}
	if err := u.UnmarshalJSON([]byte(`7`)); err != nil || uint64(u) != 7 {
		t.Errorf("number form: %v %d", err, u)
	}
	if err := u.UnmarshalJSON([]byte(`"not-a-number"`)); err == nil {
		t.Error("expected error for non-numeric string")
	}
	if err := u.UnmarshalJSON([]byte(`true`)); err == nil {
		t.Error("expected error for boolean")
	}
}

// TestEABMCP_ErrorTranslation verifies MCP error codes surface as gRPC
// statuses for EAB methods (unavailable server path).
func TestEABMCP_ErrorTranslation(t *testing.T) {
	a := &Adapter{}
	a.closed.Store(true)
	conn := &mcpClientConn{adapter: a}
	err := conn.Invoke(context.Background(), "/platform.v1.EABService/GetCredential",
		&platformv1.GetEABCredentialRequest{CredentialId: 1},
		&platformv1.GetEABCredentialResponse{})
	if status.Code(err) != codes.Unavailable {
		t.Errorf("expected Unavailable on closed adapter, got %v", err)
	}
}
