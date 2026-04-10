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

package kms

import (
	"encoding/json"
	"testing"
	"time"
)

func TestPaginationParamsJSON(t *testing.T) {
	t.Run("marshal", func(t *testing.T) {
		params := PaginationParams{
			Limit:  50,
			Cursor: "abc123",
		}

		data, err := json.Marshal(params)
		if err != nil {
			t.Fatalf("failed to marshal: %v", err)
		}

		var result map[string]interface{}
		if err := json.Unmarshal(data, &result); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}

		if result["limit"] != float64(50) {
			t.Errorf("expected limit 50, got %v", result["limit"])
		}
		if result["cursor"] != "abc123" {
			t.Errorf("expected cursor abc123, got %v", result["cursor"])
		}
	})

	t.Run("unmarshal", func(t *testing.T) {
		data := []byte(`{"limit":100,"cursor":"xyz789"}`)
		var params PaginationParams
		if err := json.Unmarshal(data, &params); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}

		if params.Limit != 100 {
			t.Errorf("expected limit 100, got %d", params.Limit)
		}
		if params.Cursor != "xyz789" {
			t.Errorf("expected cursor xyz789, got %s", params.Cursor)
		}
	})
}

func TestPaginatedResponseJSON(t *testing.T) {
	t.Run("marshal", func(t *testing.T) {
		resp := PaginatedResponse{
			NextCursor: "next123",
			HasMore:    true,
			TotalCount: 100,
		}

		data, err := json.Marshal(resp)
		if err != nil {
			t.Fatalf("failed to marshal: %v", err)
		}

		var result map[string]interface{}
		if err := json.Unmarshal(data, &result); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}

		if result["next_cursor"] != "next123" {
			t.Errorf("expected next_cursor next123, got %v", result["next_cursor"])
		}
		if result["has_more"] != true {
			t.Errorf("expected has_more true, got %v", result["has_more"])
		}
		if result["total_count"] != float64(100) {
			t.Errorf("expected total_count 100, got %v", result["total_count"])
		}
	})
}

func TestSuccessResponseJSON(t *testing.T) {
	resp := SuccessResponse{
		Success:   true,
		Message:   "operation completed",
		Timestamp: 1234567890,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var result map[string]interface{}
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result["success"] != true {
		t.Errorf("expected success true, got %v", result["success"])
	}
	if result["message"] != "operation completed" {
		t.Errorf("expected message 'operation completed', got %v", result["message"])
	}
}

func TestKeySpecRequestJSON(t *testing.T) {
	t.Run("full spec", func(t *testing.T) {
		spec := KeySpecRequest{
			Algorithm:          "AES-256-GCM",
			KeySize:            256,
			Usage:              []string{"ENCRYPT", "DECRYPT"},
			Exportable:         true,
			DeletionProtection: true,
		}

		data, err := json.Marshal(spec)
		if err != nil {
			t.Fatalf("failed to marshal: %v", err)
		}

		var result KeySpecRequest
		if err := json.Unmarshal(data, &result); err != nil {
			t.Fatalf("failed to unmarshal: %v", err)
		}

		if result.Algorithm != "AES-256-GCM" {
			t.Errorf("expected algorithm AES-256-GCM, got %s", result.Algorithm)
		}
		if result.KeySize != 256 {
			t.Errorf("expected key size 256, got %d", result.KeySize)
		}
		if len(result.Usage) != 2 {
			t.Errorf("expected 2 usage items, got %d", len(result.Usage))
		}
	})
}

func TestGenerateKeyRequestJSON(t *testing.T) {
	req := GenerateKeyRequest{
		KeySpec: KeySpecRequest{
			Algorithm: "AES-256-GCM",
		},
		Name:        "my-key",
		Description: "Test key",
		Tags:        map[string]string{"env": "test"},
		Owner:       "user@example.com",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var result GenerateKeyRequest
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result.Name != "my-key" {
		t.Errorf("expected name 'my-key', got %s", result.Name)
	}
	if result.Description != "Test key" {
		t.Errorf("expected description 'Test key', got %s", result.Description)
	}
	if result.Tags["env"] != "test" {
		t.Errorf("expected tag env=test, got %v", result.Tags)
	}
}

func TestImportKeyRequestJSON(t *testing.T) {
	req := ImportKeyRequest{
		KeyMaterial:   []byte("secret-key-material"),
		WrappingKeyID: "wrap-key-1",
		KeySpec: KeySpecRequest{
			Algorithm: "AES-256-GCM",
		},
		Name:        "imported-key",
		Description: "Imported key",
		Tags:        map[string]string{"source": "external"},
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var result ImportKeyRequest
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result.Name != "imported-key" {
		t.Errorf("expected name 'imported-key', got %s", result.Name)
	}
	if result.WrappingKeyID != "wrap-key-1" {
		t.Errorf("expected wrapping key ID 'wrap-key-1', got %s", result.WrappingKeyID)
	}
}

func TestKeyHandleResponseJSON(t *testing.T) {
	resp := KeyHandleResponse{
		KeyID:     "key-123",
		Version:   5,
		Algorithm: "AES-256-GCM",
		Status:    "ENABLED",
		CreatedAt: 1234567890,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var result KeyHandleResponse
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result.KeyID != "key-123" {
		t.Errorf("expected key ID 'key-123', got %s", result.KeyID)
	}
	if result.Version != 5 {
		t.Errorf("expected version 5, got %d", result.Version)
	}
}

func TestRotationPolicyResponseJSON(t *testing.T) {
	resp := RotationPolicyResponse{
		Enabled:         true,
		IntervalSeconds: 86400,
		NextRotation:    1234567890,
		RetainVersions:  5,
		AutoRotate:      true,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var result RotationPolicyResponse
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if !result.Enabled {
		t.Error("expected enabled to be true")
	}
	if result.IntervalSeconds != 86400 {
		t.Errorf("expected interval 86400, got %d", result.IntervalSeconds)
	}
}

func TestKeyMetadataResponseJSON(t *testing.T) {
	resp := KeyMetadataResponse{
		KeyID:              "key-123",
		Name:               "my-key",
		Description:        "Test key",
		Algorithm:          "AES-256-GCM",
		Status:             "ENABLED",
		Usage:              []string{"ENCRYPT", "DECRYPT"},
		Version:            3,
		Exportable:         true,
		DeletionProtection: false,
		CreatedAt:          1234567890,
		UpdatedAt:          1234567900,
		RotationPolicy: &RotationPolicyResponse{
			Enabled: true,
		},
		Tags:  map[string]string{"env": "prod"},
		Owner: "admin",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var result KeyMetadataResponse
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result.KeyID != "key-123" {
		t.Errorf("expected key ID 'key-123', got %s", result.KeyID)
	}
	if result.RotationPolicy == nil {
		t.Error("expected rotation policy to be set")
	}
}

func TestEncryptRequestJSON(t *testing.T) {
	req := EncryptRequest{
		Plaintext: []byte("secret data"),
		Context:   []byte("additional context"),
		Nonce:     []byte("custom-nonce"),
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var result EncryptRequest
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if string(result.Plaintext) != "secret data" {
		t.Errorf("expected plaintext 'secret data', got %s", string(result.Plaintext))
	}
}

func TestEncryptResponseJSON(t *testing.T) {
	resp := EncryptResponse{
		KeyID:      "key-123",
		KeyVersion: 2,
		Ciphertext: []byte("encrypted-data"),
		Nonce:      []byte("generated-nonce"),
		Timestamp:  1234567890,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var result EncryptResponse
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result.KeyID != "key-123" {
		t.Errorf("expected key ID 'key-123', got %s", result.KeyID)
	}
}

func TestDecryptRequestJSON(t *testing.T) {
	req := DecryptRequest{
		Ciphertext: []byte("encrypted-data"),
		Context:    []byte("additional context"),
		Nonce:      []byte("nonce"),
		KeyVersion: 2,
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var result DecryptRequest
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result.KeyVersion != 2 {
		t.Errorf("expected key version 2, got %d", result.KeyVersion)
	}
}

func TestDecryptResponseJSON(t *testing.T) {
	resp := DecryptResponse{
		KeyID:      "key-123",
		KeyVersion: 2,
		Plaintext:  []byte("decrypted-data"),
		Timestamp:  1234567890,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var result DecryptResponse
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if string(result.Plaintext) != "decrypted-data" {
		t.Errorf("expected plaintext 'decrypted-data', got %s", string(result.Plaintext))
	}
}

func TestDEKMetadataResponseJSON(t *testing.T) {
	resp := DEKMetadataResponse{
		Path:           "/tenant/app",
		Algorithm:      "AES-256-GCM",
		Version:        1,
		Status:         "active",
		IsDefault:      true,
		CreatedAt:      1234567890,
		RotatedAt:      1234567900,
		UsageCount:     100,
		BytesUsed:      10240,
		MaxUsageCount:  1000000,
		MaxBytesUsed:   1073741824,
		WarningPercent: 80,
		Description:    "Application DEK",
		BackendType:    "tpm2",
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var result DEKMetadataResponse
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result.Path != "/tenant/app" {
		t.Errorf("expected path '/tenant/app', got %s", result.Path)
	}
	if result.IsDefault != true {
		t.Error("expected is_default to be true")
	}
}

func TestCreateDEKRequestJSON(t *testing.T) {
	req := CreateDEKRequest{
		Path:           "/tenant/app/key",
		Algorithm:      "AES-256-GCM",
		Description:    "New DEK",
		MaxOperations:  1000000,
		MaxBytes:       1073741824,
		WarningPercent: 80,
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var result CreateDEKRequest
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result.Path != "/tenant/app/key" {
		t.Errorf("expected path '/tenant/app/key', got %s", result.Path)
	}
	if result.MaxOperations != 1000000 {
		t.Errorf("expected max_operations 1000000, got %d", result.MaxOperations)
	}
}

func TestRotateDEKRequestJSON(t *testing.T) {
	req := RotateDEKRequest{
		Background: true,
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var result RotateDEKRequest
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if !result.Background {
		t.Error("expected background to be true")
	}
}

func TestDeleteDEKRequestJSON(t *testing.T) {
	req := DeleteDEKRequest{
		Force:     true,
		MigrateTo: "/tenant/app/key2",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var result DeleteDEKRequest
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if !result.Force {
		t.Error("expected force to be true")
	}
	if result.MigrateTo != "/tenant/app/key2" {
		t.Errorf("expected migrate_to '/tenant/app/key2', got %s", result.MigrateTo)
	}
}

func TestReencryptionProgressResponseJSON(t *testing.T) {
	resp := ReencryptionProgressResponse{
		InProgress:          true,
		TotalKeys:           100,
		ProcessedKeys:       50,
		FailedKeys:          2,
		StartedAt:           1234567890,
		EstimatedCompletion: 1234568890,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var result ReencryptionProgressResponse
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if !result.InProgress {
		t.Error("expected in_progress to be true")
	}
	if result.ProcessedKeys != 50 {
		t.Errorf("expected processed_keys 50, got %d", result.ProcessedKeys)
	}
}

func TestGetDEKStatusResponseJSON(t *testing.T) {
	resp := GetDEKStatusResponse{
		DEK: &DEKMetadataResponse{
			Path:    "/tenant/app",
			Version: 2,
		},
		ReencryptionProgress: &ReencryptionProgressResponse{
			InProgress: true,
		},
		Timestamp: 1234567890,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var result GetDEKStatusResponse
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result.DEK == nil {
		t.Error("expected DEK to be set")
	}
	if result.ReencryptionProgress == nil {
		t.Error("expected reencryption_progress to be set")
	}
}

func TestBackendStatusResponseJSON(t *testing.T) {
	resp := BackendStatusResponse{
		BackendType:  "tpm2",
		Status:       "healthy",
		Device:       "/dev/tpm0",
		Region:       "",
		KeyID:        "srk-key",
		PCRBanks:     []string{"sha256", "sha384"},
		PCRRegisters: []int32{0, 1, 7},
		Capabilities: map[string]bool{"seal": true, "unseal": true},
		Timestamp:    1234567890,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var result BackendStatusResponse
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result.BackendType != "tpm2" {
		t.Errorf("expected backend_type 'tpm2', got %s", result.BackendType)
	}
	if len(result.PCRBanks) != 2 {
		t.Errorf("expected 2 PCR banks, got %d", len(result.PCRBanks))
	}
}

func TestBackendTestResponseJSON(t *testing.T) {
	resp := BackendTestResponse{
		Success:    true,
		DurationMs: 150,
		Message:    "Test completed successfully",
		Timestamp:  1234567890,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var result BackendTestResponse
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if !result.Success {
		t.Error("expected success to be true")
	}
	if result.DurationMs != 150 {
		t.Errorf("expected duration_ms 150, got %d", result.DurationMs)
	}
}

func TestTimeToUnix(t *testing.T) {
	t.Run("nil time", func(t *testing.T) {
		result := timeToUnix(nil)
		if result != 0 {
			t.Errorf("expected 0 for nil time, got %d", result)
		}
	})

	t.Run("valid time", func(t *testing.T) {
		tm := time.Unix(1234567890, 0)
		result := timeToUnix(&tm)
		if result != 1234567890 {
			t.Errorf("expected 1234567890, got %d", result)
		}
	})
}

func TestListKeysResponseJSON(t *testing.T) {
	resp := ListKeysResponse{
		PaginatedResponse: PaginatedResponse{
			NextCursor: "next",
			HasMore:    true,
			TotalCount: 100,
		},
		Keys: []KeyHandleResponse{
			{KeyID: "key-1", Version: 1, Algorithm: "AES-256-GCM", Status: "ENABLED"},
			{KeyID: "key-2", Version: 2, Algorithm: "RSA-2048", Status: "DISABLED"},
		},
		Timestamp: 1234567890,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var result ListKeysResponse
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if len(result.Keys) != 2 {
		t.Errorf("expected 2 keys, got %d", len(result.Keys))
	}
	if !result.HasMore {
		t.Error("expected has_more to be true")
	}
}

func TestRotateKeyRequestJSON(t *testing.T) {
	req := RotateKeyRequest{
		RetainOldVersion: true,
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var result RotateKeyRequest
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if !result.RetainOldVersion {
		t.Error("expected retain_old_version to be true")
	}
}

func TestRotateKeyResponseJSON(t *testing.T) {
	resp := RotateKeyResponse{
		KeyID:      "key-123",
		OldVersion: 1,
		NewVersion: 2,
		Timestamp:  1234567890,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var result RotateKeyResponse
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result.OldVersion != 1 {
		t.Errorf("expected old_version 1, got %d", result.OldVersion)
	}
	if result.NewVersion != 2 {
		t.Errorf("expected new_version 2, got %d", result.NewVersion)
	}
}

func TestDeleteKeyRequestJSON(t *testing.T) {
	req := DeleteKeyRequest{
		PendingWindowDays: 7,
		Force:             true,
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var result DeleteKeyRequest
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result.PendingWindowDays != 7 {
		t.Errorf("expected pending_window_days 7, got %d", result.PendingWindowDays)
	}
}

func TestDeleteKeyResponseJSON(t *testing.T) {
	resp := DeleteKeyResponse{
		KeyID:        "key-123",
		Status:       "PENDING_DELETION",
		DeletionDate: 1234567890,
		Timestamp:    1234567800,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var result DeleteKeyResponse
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result.Status != "PENDING_DELETION" {
		t.Errorf("expected status 'PENDING_DELETION', got %s", result.Status)
	}
}

func TestUpdateKeyStatusRequestJSON(t *testing.T) {
	req := UpdateKeyStatusRequest{
		Version: 2,
		Status:  "DISABLED",
	}

	data, err := json.Marshal(req)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var result UpdateKeyStatusRequest
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if result.Status != "DISABLED" {
		t.Errorf("expected status 'DISABLED', got %s", result.Status)
	}
}

func TestListKeyVersionsResponseJSON(t *testing.T) {
	resp := ListKeyVersionsResponse{
		PaginatedResponse: PaginatedResponse{
			NextCursor: "next",
			HasMore:    false,
		},
		KeyID: "key-123",
		Versions: []KeyVersionInfoResponse{
			{Version: 1, Status: "DISABLED", Algorithm: "AES-256-GCM", CreatedAt: 1234567800},
			{Version: 2, Status: "ENABLED", Algorithm: "AES-256-GCM", CreatedAt: 1234567890},
		},
		Timestamp: 1234567890,
	}

	data, err := json.Marshal(resp)
	if err != nil {
		t.Fatalf("failed to marshal: %v", err)
	}

	var result ListKeyVersionsResponse
	if err := json.Unmarshal(data, &result); err != nil {
		t.Fatalf("failed to unmarshal: %v", err)
	}

	if len(result.Versions) != 2 {
		t.Errorf("expected 2 versions, got %d", len(result.Versions))
	}
}
