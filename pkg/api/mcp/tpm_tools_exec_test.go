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
	"encoding/base64"
	"testing"
)

func TestTPMToolExecution(t *testing.T) {
	ctx := context.Background()
	log := newTestLogger()

	t.Run("executeTPMInfo success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_tpm_info", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeTPMProvision success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_tpm_provision", map[string]interface{}{
			"owner_password": "test-password",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeTPMClear success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_tpm_clear", map[string]interface{}{
			"owner_password": "test-password",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeTPMGetEK success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_tpm_ek", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeTPMGetEKCert success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_tpm_ek_cert", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeTPMImportEKCert success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		certDER := []byte("fake-cert-der")
		result, err := registry.ExecuteTool(ctx, "platform_tpm_ek_import_cert", map[string]interface{}{
			"certificate": base64.StdEncoding.EncodeToString(certDER),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeTPMImportEKCert missing certificate", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "platform_tpm_ek_import_cert", map[string]interface{}{})
		if err == nil {
			t.Fatal("expected error for missing certificate")
		}
		if err != ErrTPMCertificateRequired {
			t.Fatalf("expected ErrTPMCertificateRequired, got %v", err)
		}
	})

	t.Run("executeTPMImportEKCert invalid base64", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "platform_tpm_ek_import_cert", map[string]interface{}{
			"certificate": "not-valid-base64!!!",
		})
		if err == nil {
			t.Fatal("expected error for invalid base64")
		}
		if err != ErrTPMInvalidCertificate {
			t.Fatalf("expected ErrTPMInvalidCertificate, got %v", err)
		}
	})

	t.Run("executeTPMCreateEK success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_tpm_ek_create", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeTPMDeleteEK success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_tpm_ek_delete", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeTPMGetSRK success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_tpm_srk", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeTPMCreateSRK success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_tpm_srk_create", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeTPMDeleteSRK success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_tpm_srk_delete", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeTPMGetIAK success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_tpm_iak", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeTPMCreateIAK success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_tpm_iak_create", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeTPMDeleteIAK success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_tpm_iak_delete", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeTPMQuote success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		nonce := []byte("test-nonce-value")
		result, err := registry.ExecuteTool(ctx, "platform_tpm_quote", map[string]interface{}{
			"nonce": base64.StdEncoding.EncodeToString(nonce),
			"pcrs":  []interface{}{float64(0), float64(1), float64(7)},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeTPMQuote missing nonce", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "platform_tpm_quote", map[string]interface{}{})
		if err == nil {
			t.Fatal("expected error for missing nonce")
		}
		if err != ErrTPMNonceRequired {
			t.Fatalf("expected ErrTPMNonceRequired, got %v", err)
		}
	})

	t.Run("executeTPMQuote invalid nonce", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "platform_tpm_quote", map[string]interface{}{
			"nonce": "not-valid-base64!!!",
		})
		if err == nil {
			t.Fatal("expected error for invalid nonce")
		}
		if err != ErrTPMInvalidNonce {
			t.Fatalf("expected ErrTPMInvalidNonce, got %v", err)
		}
	})

	t.Run("executeTPMVerifyQuote success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_tpm_verify_quote", map[string]interface{}{
			"quote":               base64.StdEncoding.EncodeToString([]byte("quote-data")),
			"signature":           base64.StdEncoding.EncodeToString([]byte("sig-data")),
			"nonce":               base64.StdEncoding.EncodeToString([]byte("nonce-data")),
			"signature_algorithm": "SHA256-RSAPSS",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		out, ok := result.(map[string]interface{})
		if !ok {
			t.Fatalf("result = %T, want a map", result)
		}
		if got := out["signature_algorithm"]; got != "SHA256-RSAPSS" {
			t.Errorf("service received signature_algorithm %v, want SHA256-RSAPSS", got)
		}
	})

	t.Run("executeTPMVerifyQuote without a scheme passes none", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_tpm_verify_quote", map[string]interface{}{
			"quote":     base64.StdEncoding.EncodeToString([]byte("quote-data")),
			"signature": base64.StdEncoding.EncodeToString([]byte("sig-data")),
			"nonce":     base64.StdEncoding.EncodeToString([]byte("nonce-data")),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		out, ok := result.(map[string]interface{})
		if !ok {
			t.Fatalf("result = %T, want a map", result)
		}
		if got := out["signature_algorithm"]; got != "" {
			t.Errorf("service received signature_algorithm %q, want none for the verifier to refuse", got)
		}
		if got := out["ak_public"]; got != "" {
			t.Errorf("service received ak_public %q, want none so the platform IAK verifies", got)
		}
	})

	t.Run("executeTPMVerifyQuote passes ak_public", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_tpm_verify_quote", map[string]interface{}{
			"quote":               base64.StdEncoding.EncodeToString([]byte("quote-data")),
			"signature":           base64.StdEncoding.EncodeToString([]byte("sig-data")),
			"nonce":               base64.StdEncoding.EncodeToString([]byte("nonce-data")),
			"ak_public":           base64.StdEncoding.EncodeToString([]byte("ak-der")),
			"signature_algorithm": "SHA256-RSAPSS",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		out, ok := result.(map[string]interface{})
		if !ok {
			t.Fatalf("result = %T, want a map", result)
		}
		if got := out["ak_public"]; got != "ak-der" {
			t.Errorf("service received ak_public %v, want the decoded key", got)
		}
	})

	t.Run("executeTPMVerifyQuote invalid ak_public base64", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "platform_tpm_verify_quote", map[string]interface{}{
			"quote":               base64.StdEncoding.EncodeToString([]byte("quote-data")),
			"signature":           base64.StdEncoding.EncodeToString([]byte("sig-data")),
			"nonce":               base64.StdEncoding.EncodeToString([]byte("nonce-data")),
			"ak_public":           "!!!not-base64!!!",
			"signature_algorithm": "SHA256-RSAPSS",
		})
		if err != ErrTPMInvalidData {
			t.Fatalf("expected ErrTPMInvalidData, got %v", err)
		}
	})

	t.Run("executeTPMVerifyQuote missing nonce", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "platform_tpm_verify_quote", map[string]interface{}{
			"quote":     base64.StdEncoding.EncodeToString([]byte("quote-data")),
			"signature": base64.StdEncoding.EncodeToString([]byte("sig-data")),
		})
		if err == nil {
			t.Fatal("expected error for missing nonce")
		}
		if err != ErrTPMNonceRequired {
			t.Fatalf("expected ErrTPMNonceRequired, got %v", err)
		}
	})

	t.Run("executeTPMVerifyQuote invalid quote base64", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "platform_tpm_verify_quote", map[string]interface{}{
			"quote":     "not-valid-base64!!!",
			"signature": base64.StdEncoding.EncodeToString([]byte("sig-data")),
			"nonce":     base64.StdEncoding.EncodeToString([]byte("nonce-data")),
		})
		if err == nil {
			t.Fatal("expected error for invalid quote base64")
		}
		if err != ErrTPMInvalidData {
			t.Fatalf("expected ErrTPMInvalidData, got %v", err)
		}
	})

	t.Run("executeTPMVerifyQuote invalid signature base64", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "platform_tpm_verify_quote", map[string]interface{}{
			"quote":     base64.StdEncoding.EncodeToString([]byte("quote-data")),
			"signature": "not-valid-base64!!!",
			"nonce":     base64.StdEncoding.EncodeToString([]byte("nonce-data")),
		})
		if err == nil {
			t.Fatal("expected error for invalid signature base64")
		}
		if err != ErrTPMInvalidData {
			t.Fatalf("expected ErrTPMInvalidData, got %v", err)
		}
	})

	t.Run("executeTPMVerifyQuote invalid nonce base64", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "platform_tpm_verify_quote", map[string]interface{}{
			"quote":     base64.StdEncoding.EncodeToString([]byte("quote-data")),
			"signature": base64.StdEncoding.EncodeToString([]byte("sig-data")),
			"nonce":     "not-valid-base64!!!",
		})
		if err == nil {
			t.Fatal("expected error for invalid nonce base64")
		}
		if err != ErrTPMInvalidNonce {
			t.Fatalf("expected ErrTPMInvalidNonce, got %v", err)
		}
	})

	t.Run("executeTPMReadPCRs success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_tpm_pcrs", map[string]interface{}{
			"indices": []interface{}{float64(0), float64(1), float64(7)},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeTPMExtendPCR success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_tpm_pcr_extend", map[string]interface{}{
			"pcr_index": float64(7),
			"data":      base64.StdEncoding.EncodeToString([]byte("measurement-data")),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeTPMExtendPCR invalid data base64", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "platform_tpm_pcr_extend", map[string]interface{}{
			"pcr_index": float64(7),
			"data":      "not-valid-base64!!!",
		})
		if err == nil {
			t.Fatal("expected error for invalid data base64")
		}
		if err != ErrTPMInvalidData {
			t.Fatalf("expected ErrTPMInvalidData, got %v", err)
		}
	})

	t.Run("executeTPMEventLog success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_tpm_eventlog", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeTPMCapabilities success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_tpm_capabilities", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeTPMRandom success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_tpm_random", map[string]interface{}{
			"num_bytes": float64(16),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result should be a map")
		}
		if resultMap["num_bytes"] != 16 {
			t.Fatalf("expected num_bytes=16, got %v", resultMap["num_bytes"])
		}
	})

	t.Run("executeTPMRandom default bytes", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_tpm_random", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result should be a map")
		}
		if resultMap["num_bytes"] != 32 {
			t.Fatalf("expected default num_bytes=32, got %v", resultMap["num_bytes"])
		}
	})

	t.Run("executeTPMSeal success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_tpm_seal", map[string]interface{}{
			"data": base64.StdEncoding.EncodeToString([]byte("secret-data")),
			"pcrs": []interface{}{float64(0), float64(7)},
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result should be a map")
		}
		if _, exists := resultMap["sealed_data"]; !exists {
			t.Fatal("result should contain 'sealed_data' key")
		}
	})

	t.Run("executeTPMSeal missing data", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "platform_tpm_seal", map[string]interface{}{})
		if err == nil {
			t.Fatal("expected error for missing data")
		}
		if err != ErrTPMDataRequired {
			t.Fatalf("expected ErrTPMDataRequired, got %v", err)
		}
	})

	t.Run("executeTPMSeal invalid data base64", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "platform_tpm_seal", map[string]interface{}{
			"data": "not-valid-base64!!!",
		})
		if err == nil {
			t.Fatal("expected error for invalid data base64")
		}
		if err != ErrTPMInvalidData {
			t.Fatalf("expected ErrTPMInvalidData, got %v", err)
		}
	})

	t.Run("executeTPMUnseal success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_tpm_unseal", map[string]interface{}{
			"cn": "test.example.com",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result should be a map")
		}
		if _, exists := resultMap["data"]; !exists {
			t.Fatal("result should contain 'data' key")
		}
	})

	t.Run("executeTPMUnseal missing cn", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "platform_tpm_unseal", map[string]interface{}{})
		if err == nil {
			t.Fatal("expected error for missing cn")
		}
		if err != ErrTPMCNRequired {
			t.Fatalf("expected ErrTPMCNRequired, got %v", err)
		}
	})

	t.Run("executeTPMCertify success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_tpm_certify", map[string]interface{}{
			"key_handle": float64(0x81000001),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeTPMNVList success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_tpm_nv_list", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeTPMNVRead success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_tpm_nv_read", map[string]interface{}{
			"index": float64(0x01500000),
			"size":  float64(32),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result should be a map")
		}
		if _, exists := resultMap["data"]; !exists {
			t.Fatal("result should contain 'data' key")
		}
	})

	t.Run("executeTPMNVWrite success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_tpm_nv_write", map[string]interface{}{
			"index": float64(0x01500000),
			"data":  base64.StdEncoding.EncodeToString([]byte("nv-data")),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeTPMNVWrite invalid data base64", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "platform_tpm_nv_write", map[string]interface{}{
			"index": float64(0x01500000),
			"data":  "not-valid-base64!!!",
		})
		if err == nil {
			t.Fatal("expected error for invalid data base64")
		}
		if err != ErrTPMInvalidData {
			t.Fatalf("expected ErrTPMInvalidData, got %v", err)
		}
	})

	t.Run("executeTPMNVDelete success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_tpm_nv_delete", map[string]interface{}{
			"index": float64(0x01500000),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeTPMPlatform success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "platform_tpm_platform", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})
}

func TestTPMErrorTypes(t *testing.T) {
	t.Run("TPMError format", func(t *testing.T) {
		err := &TPMError{Code: "TEST_CODE", Message: "test message"}
		expected := "TEST_CODE: test message"
		if err.Error() != expected {
			t.Errorf("expected %q, got %q", expected, err.Error())
		}
	})
}
