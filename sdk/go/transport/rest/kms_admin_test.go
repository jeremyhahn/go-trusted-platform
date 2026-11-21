package rest

import (
	"context"
	"net/http"
	"reflect"
	"testing"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

// TestKMSAdmin_RoutesAndBodies pins ImportKey, UpdateKeyStatus,
// GetKeyVersions and BackendStatus to the webservice KMS router's routes
// (pkg/webservice/v1/rest/kms/router.go) and their bodies to its wire names.
func TestKMSAdmin_RoutesAndBodies(t *testing.T) {
	cases := []struct {
		name       string
		grpcMethod string
		req        proto.Message
		resp       proto.Message
		wantMethod string
		wantPath   string
		wantBody   map[string]interface{}
	}{
		{
			name:       "ImportKey",
			grpcMethod: platformv1.KeyManagementService_ImportKey_FullMethodName,
			req: &platformv1.ImportKeyRequest{
				Name:          "kek",
				Description:   "imported",
				Tags:          map[string]string{"env": "prod"},
				KeyMaterial:   []byte("wrapped"),
				WrappingKeyId: "wrap",
				KeySpec: &platformv1.KMSKeySpec{
					Algorithm: platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256,
					Usage:     []platformv1.KeyUsage{platformv1.KeyUsage_KEY_USAGE_ENCRYPT, platformv1.KeyUsage_KEY_USAGE_DECRYPT},
				},
			},
			resp:       &platformv1.ImportKeyResponse{},
			wantMethod: http.MethodPost,
			wantPath:   "/api/v1/kms/keys/import",
			wantBody: map[string]interface{}{
				"name": "kek", "description": "imported", "tags": map[string]interface{}{"env": "prod"},
				"key_material": b64("wrapped"), "wrapping_key_id": "wrap",
				"algorithm": "AES-256-GCM", "usage": []interface{}{"ENCRYPT", "DECRYPT"},
			},
		},
		{
			name:       "UpdateKeyStatusDestroyedIsDeleted",
			grpcMethod: platformv1.KeyManagementService_UpdateKeyStatus_FullMethodName,
			req: &platformv1.UpdateKeyStatusRequest{KeyId: "kek",
				Status: platformv1.KeyStatus_KEY_STATUS_DESTROYED},
			resp:       &platformv1.UpdateKeyStatusResponse{},
			wantMethod: http.MethodPut,
			wantPath:   "/api/v1/kms/keys/kek/status",
			wantBody:   map[string]interface{}{"status": "DELETED"},
		},
		{
			name:       "UpdateKeyStatusWithVersion",
			grpcMethod: platformv1.KeyManagementService_UpdateKeyStatus_FullMethodName,
			req: &platformv1.UpdateKeyStatusRequest{KeyId: "kek", Version: 2,
				Status: platformv1.KeyStatus_KEY_STATUS_DISABLED},
			resp:       &platformv1.UpdateKeyStatusResponse{},
			wantMethod: http.MethodPut,
			wantPath:   "/api/v1/kms/keys/kek/status",
			wantBody:   map[string]interface{}{"status": "DISABLED", "version": float64(2)},
		},
		{
			name:       "GetKeyVersions",
			grpcMethod: platformv1.KeyManagementService_GetKeyVersions_FullMethodName,
			req:        &platformv1.GetKeyVersionsRequest{KeyId: "kek"},
			resp:       &platformv1.GetKeyVersionsResponse{},
			wantMethod: http.MethodGet,
			wantPath:   "/api/v1/kms/keys/kek/versions",
		},
		{
			name:       "BackendStatus",
			grpcMethod: platformv1.KeyManagementService_BackendStatus_FullMethodName,
			req:        &platformv1.BackendStatusRequest{},
			resp:       &platformv1.BackendStatusResponse{},
			wantMethod: http.MethodGet,
			wantPath:   "/api/v1/kms/backend/status",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, captured := kmsAdapter(t, `{}`)
			if err := a.Connection().Invoke(context.Background(), tc.grpcMethod, tc.req, tc.resp); err != nil {
				t.Fatalf("Invoke: %v", err)
			}
			if captured.method != tc.wantMethod || captured.path != tc.wantPath {
				t.Fatalf("route = %s %s, want %s %s", captured.method, captured.path, tc.wantMethod, tc.wantPath)
			}
			if tc.wantBody != nil && !reflect.DeepEqual(captured.body, tc.wantBody) {
				t.Fatalf("body = %v, want %v", captured.body, tc.wantBody)
			}
		})
	}
}

// TestKMSAdmin_StatusMapping covers every proto status on encode and every
// server status on decode (parseKeyStatus, handlers.go).
func TestKMSAdmin_StatusMapping(t *testing.T) {
	encode := map[platformv1.KeyStatus]string{
		platformv1.KeyStatus_KEY_STATUS_ENABLED:          "ENABLED",
		platformv1.KeyStatus_KEY_STATUS_DISABLED:         "DISABLED",
		platformv1.KeyStatus_KEY_STATUS_PENDING_DELETION: "PENDING_DELETION",
		platformv1.KeyStatus_KEY_STATUS_DESTROYED:        "DELETED",
	}
	for st, want := range encode {
		body, err := encodeKMSUpdateKeyStatus(&platformv1.UpdateKeyStatusRequest{Status: st})
		if err != nil {
			t.Fatalf("encode %v: %v", st, err)
		}
		if body["status"] != want {
			t.Fatalf("encode %v = %v, want %s", st, body["status"], want)
		}
	}

	decode := map[string]platformv1.KeyStatus{
		"ENABLED":          platformv1.KeyStatus_KEY_STATUS_ENABLED,
		"DISABLED":         platformv1.KeyStatus_KEY_STATUS_DISABLED,
		"PENDING_DELETION": platformv1.KeyStatus_KEY_STATUS_PENDING_DELETION,
		"DELETED":          platformv1.KeyStatus_KEY_STATUS_DESTROYED,
		"ROTATING":         platformv1.KeyStatus_KEY_STATUS_ENABLED,
		"COMPROMISED":      platformv1.KeyStatus_KEY_STATUS_DISABLED,
		"SOMETHING_ELSE":   platformv1.KeyStatus_KEY_STATUS_UNSPECIFIED,
	}
	for name, want := range decode {
		resp, err := decodeKMSUpdateKeyStatus([]byte(`{"key_id":"kek","version":3,"status":"` + name + `"}`))
		if err != nil {
			t.Fatalf("decode %s: %v", name, err)
		}
		if resp.GetKeyStatus() != want || resp.GetKeyId() != "kek" || resp.GetVersion() != 3 {
			t.Fatalf("decode %s = %v, want status %v", name, resp, want)
		}
	}
}

// TestKMSAdmin_RefusedBeforeTheWire: requests the routes cannot carry are
// InvalidArgument and never reach the server.
func TestKMSAdmin_RefusedBeforeTheWire(t *testing.T) {
	cases := []struct {
		name       string
		grpcMethod string
		req        proto.Message
		resp       proto.Message
	}{
		{"PendingImport", platformv1.KeyManagementService_UpdateKeyStatus_FullMethodName,
			&platformv1.UpdateKeyStatusRequest{KeyId: "kek", Status: platformv1.KeyStatus_KEY_STATUS_PENDING_IMPORT},
			&platformv1.UpdateKeyStatusResponse{}},
		{"UnspecifiedStatus", platformv1.KeyManagementService_UpdateKeyStatus_FullMethodName,
			&platformv1.UpdateKeyStatusRequest{KeyId: "kek"},
			&platformv1.UpdateKeyStatusResponse{}},
		{"ImportUnknownAlgorithm", platformv1.KeyManagementService_ImportKey_FullMethodName,
			&platformv1.ImportKeyRequest{Name: "k",
				KeySpec: &platformv1.KMSKeySpec{Algorithm: platformv1.KMSKeyAlgorithm(99)}},
			&platformv1.ImportKeyResponse{}},
		{"ImportUnknownUsage", platformv1.KeyManagementService_ImportKey_FullMethodName,
			&platformv1.ImportKeyRequest{Name: "k",
				KeySpec: &platformv1.KMSKeySpec{Usage: []platformv1.KeyUsage{platformv1.KeyUsage_KEY_USAGE_DERIVE}}},
			&platformv1.ImportKeyResponse{}},
		{"VersionsLimit", platformv1.KeyManagementService_GetKeyVersions_FullMethodName,
			&platformv1.GetKeyVersionsRequest{KeyId: "kek", Limit: 10},
			&platformv1.GetKeyVersionsResponse{}},
		{"VersionsCursor", platformv1.KeyManagementService_GetKeyVersions_FullMethodName,
			&platformv1.GetKeyVersionsRequest{KeyId: "kek", Cursor: "next"},
			&platformv1.GetKeyVersionsResponse{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			a, captured := kmsAdapter(t, `{}`)
			err := a.Connection().Invoke(context.Background(), tc.grpcMethod, tc.req, tc.resp)
			if status.Code(err) != codes.InvalidArgument {
				t.Fatalf("code = %v, want InvalidArgument (err %v)", status.Code(err), err)
			}
			if captured.method != "" {
				t.Fatalf("request reached the server: %s %s", captured.method, captured.path)
			}
		})
	}
}

// TestKMSAdmin_VersionsAndBackendDecode checks the reply fields of
// GetKeyVersions, BackendStatus and ImportKey.
func TestKMSAdmin_VersionsAndBackendDecode(t *testing.T) {
	t.Run("GetKeyVersions", func(t *testing.T) {
		a, _ := kmsAdapter(t, `{"versions":[`+
			`{"version":1,"status":"DELETED","algorithm":"AES-256-GCM","created_at":"2026-01-02T03:04:05Z","disabled_at":"2026-02-02T03:04:05Z"},`+
			`{"version":2,"status":"ROTATING","algorithm":"ECDSA-P384","created_at":"2026-03-02T03:04:05Z","disabled_at":"0001-01-01T00:00:00Z"}]}`)
		resp := &platformv1.GetKeyVersionsResponse{}
		if err := a.Connection().Invoke(context.Background(), platformv1.KeyManagementService_GetKeyVersions_FullMethodName,
			&platformv1.GetKeyVersionsRequest{KeyId: "kek"}, resp); err != nil {
			t.Fatalf("Invoke: %v", err)
		}
		got := resp.GetVersions()
		if len(got) != 2 || resp.GetKeyId() != "kek" {
			t.Fatalf("reply = %v", resp)
		}
		if got[0].GetVersion() != 1 || got[0].GetStatus() != platformv1.KeyStatus_KEY_STATUS_DESTROYED ||
			got[0].GetAlgorithm() != platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256 ||
			got[0].GetCreatedAt() != 1767323045 || got[0].GetDisabledAt() != 1770001445 {
			t.Fatalf("version 1 = %v", got[0])
		}
		if got[1].GetVersion() != 2 || got[1].GetStatus() != platformv1.KeyStatus_KEY_STATUS_ENABLED ||
			got[1].GetAlgorithm() != platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P384 ||
			got[1].GetCreatedAt() != 1772420645 || got[1].GetDisabledAt() != 0 {
			t.Fatalf("version 2 = %v", got[1])
		}
	})

	t.Run("BackendStatus", func(t *testing.T) {
		a, _ := kmsAdapter(t, `{"backend_type":"tpm2","status":"healthy","device":"tpm0","region":"r1",`+
			`"key_id":"srk","pcr_banks":["sha256"],"pcr_registers":[0,7],"capabilities":{"seal":true}}`)
		resp := &platformv1.BackendStatusResponse{}
		if err := a.Connection().Invoke(context.Background(), platformv1.KeyManagementService_BackendStatus_FullMethodName,
			&platformv1.BackendStatusRequest{}, resp); err != nil {
			t.Fatalf("Invoke: %v", err)
		}
		if resp.GetBackendType() != "tpm2" || resp.GetBackendStatus() != "healthy" || resp.GetDevice() != "tpm0" ||
			resp.GetRegion() != "r1" || resp.GetKeyId() != "srk" ||
			!reflect.DeepEqual(resp.GetPcrBanks(), []string{"sha256"}) ||
			!reflect.DeepEqual(resp.GetPcrRegisters(), []int32{0, 7}) ||
			!resp.GetCapabilities()["seal"] || !resp.GetStatus().GetSuccess() {
			t.Fatalf("reply = %v", resp)
		}
	})

	t.Run("ImportKey", func(t *testing.T) {
		a, _ := kmsAdapter(t, `{"key_id":"kek","version":1,"algorithm":"AES-256-GCM"}`)
		resp := &platformv1.ImportKeyResponse{}
		if err := a.Connection().Invoke(context.Background(), platformv1.KeyManagementService_ImportKey_FullMethodName,
			&platformv1.ImportKeyRequest{Name: "kek"}, resp); err != nil {
			t.Fatalf("Invoke: %v", err)
		}
		alg := platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256
		if resp.GetKey().GetKeyId() != "kek" || resp.GetKey().GetVersion() != 1 || resp.GetKey().GetAlgorithm() != alg ||
			resp.GetMetadata().GetKeyId() != "kek" || resp.GetMetadata().GetVersion() != 1 ||
			resp.GetMetadata().GetAlgorithm() != alg || !resp.GetStatus().GetSuccess() {
			t.Fatalf("reply = %v", resp)
		}
	})
}
