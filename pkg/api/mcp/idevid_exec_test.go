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

func TestIDevIDToolExecution(t *testing.T) {
	ctx := context.Background()
	log := newTestLogger()

	t.Run("executeIDevIDGenerate success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "idevid_generate", map[string]interface{}{
			"algorithm": "ECC",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeIDevIDGenerate default algorithm", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.idevidGenerateFunc = func(ctx context.Context, req *IDevIDGenerateMCPRequest) (interface{}, error) {
			if req.Algorithm != "ECC" {
				t.Errorf("expected default algorithm ECC, got %s", req.Algorithm)
			}
			return map[string]interface{}{"handle": "0x81010002"}, nil
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "idevid_generate", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("executeIDevIDGenerate service error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.idevidGenerateFunc = func(ctx context.Context, req *IDevIDGenerateMCPRequest) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "idevid_generate", map[string]interface{}{})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("executeIDevIDInfo success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "idevid_info", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeIDevIDInfo service error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.idevidInfoFunc = func(ctx context.Context) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "idevid_info", map[string]interface{}{})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("executeIDevIDDelete success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "idevid_delete", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result should be a map")
		}
		if resultMap["success"] != true {
			t.Fatal("expected success=true")
		}
	})

	t.Run("executeIDevIDDelete service error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.idevidDeleteFunc = func(ctx context.Context) error {
			return ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "idevid_delete", map[string]interface{}{})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("executeIDevIDCSR success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "idevid_csr", map[string]interface{}{
			"common_name":  "device.example.com",
			"organization": "Test Org",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeIDevIDCSR with include_tcg_attrs false", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.idevidCSRFunc = func(ctx context.Context, req *IDevIDCSRMCPRequest) (interface{}, error) {
			if req.IncludeTCGAttrs != false {
				t.Error("expected IncludeTCGAttrs=false")
			}
			return map[string]interface{}{"csr_pem": "test"}, nil
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "idevid_csr", map[string]interface{}{
			"common_name":       "device.example.com",
			"include_tcg_attrs": false,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("executeIDevIDInstallCert success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "idevid_install_cert", map[string]interface{}{
			"certificate_pem": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeIDevIDInstallCert missing certificate_pem", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "idevid_install_cert", map[string]interface{}{})
		if err == nil {
			t.Fatal("expected error for missing certificate_pem")
		}
		if err != ErrIDevIDCertificatePEMRequired {
			t.Fatalf("expected ErrIDevIDCertificatePEMRequired, got %v", err)
		}
	})

	t.Run("executeIDevIDGetCert success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "idevid_get_cert", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeIDevIDGetCert include_pem false", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.idevidGetCertFunc = func(ctx context.Context, includePEM bool) (interface{}, error) {
			if includePEM != false {
				t.Error("expected includePEM=false")
			}
			return map[string]interface{}{"serial": "abc123"}, nil
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "idevid_get_cert", map[string]interface{}{
			"include_pem": false,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("executeIDevIDDeleteCert success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "idevid_delete_cert", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result should be a map")
		}
		if resultMap["success"] != true {
			t.Fatal("expected success=true")
		}
	})

	t.Run("executeIDevIDDeleteCert service error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.idevidDeleteCertFunc = func(ctx context.Context) error {
			return ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "idevid_delete_cert", map[string]interface{}{})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("executeIDevIDExists success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "idevid_exists", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result should be a map")
		}
		if resultMap["exists"] != true {
			t.Fatal("expected exists=true")
		}
	})

	t.Run("executeIDevIDExists service error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.idevidExistsFunc = func(ctx context.Context) (bool, error) {
			return false, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "idevid_exists", map[string]interface{}{})
		if err == nil {
			t.Fatal("expected error")
		}
	})
}

func TestIAKToolExecution(t *testing.T) {
	ctx := context.Background()
	log := newTestLogger()

	t.Run("executeIAKGenerate success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "iak_generate", map[string]interface{}{
			"algorithm": "ECC",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeIAKGenerate default algorithm", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.iakGenerateFunc = func(ctx context.Context, req *IDevIDGenerateMCPRequest) (interface{}, error) {
			if req.Algorithm != "ECC" {
				t.Errorf("expected default algorithm ECC, got %s", req.Algorithm)
			}
			return map[string]interface{}{"handle": "0x81010003"}, nil
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "iak_generate", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("executeIAKInfo success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "iak_info", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeIAKDelete success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "iak_delete", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result should be a map")
		}
		if resultMap["success"] != true {
			t.Fatal("expected success=true")
		}
	})

	t.Run("executeIAKCSR success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "iak_csr", map[string]interface{}{
			"common_name":  "device-iak.example.com",
			"organization": "Test Org",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeIAKCSR with include_tcg_attrs false", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.iakCSRFunc = func(ctx context.Context, req *IDevIDCSRMCPRequest) (interface{}, error) {
			if req.IncludeTCGAttrs != false {
				t.Error("expected IncludeTCGAttrs=false")
			}
			return map[string]interface{}{"csr_pem": "test"}, nil
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "iak_csr", map[string]interface{}{
			"common_name":       "device-iak.example.com",
			"include_tcg_attrs": false,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("executeIAKInstallCert success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "iak_install_cert", map[string]interface{}{
			"certificate_pem": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeIAKInstallCert missing certificate_pem", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "iak_install_cert", map[string]interface{}{})
		if err == nil {
			t.Fatal("expected error for missing certificate_pem")
		}
		if err != ErrIDevIDCertificatePEMRequired {
			t.Fatalf("expected ErrIDevIDCertificatePEMRequired, got %v", err)
		}
	})

	t.Run("executeIAKGetCert success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "iak_get_cert", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeIAKGetCert include_pem false", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.iakGetCertFunc = func(ctx context.Context, includePEM bool) (interface{}, error) {
			if includePEM != false {
				t.Error("expected includePEM=false")
			}
			return map[string]interface{}{"serial": "iak123"}, nil
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "iak_get_cert", map[string]interface{}{
			"include_pem": false,
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
	})

	t.Run("executeIAKDeleteCert success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "iak_delete_cert", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result should be a map")
		}
		if resultMap["success"] != true {
			t.Fatal("expected success=true")
		}
	})

	t.Run("executeIAKExists success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "iak_exists", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result should be a map")
		}
		if resultMap["exists"] != true {
			t.Fatal("expected exists=true")
		}
	})

	t.Run("executeDeviceAttributes success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "device_attributes", map[string]interface{}{})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if result == nil {
			t.Fatal("result should not be nil")
		}
	})

	t.Run("executeDeviceAttributes service error", func(t *testing.T) {
		svc := newMockServiceProvider()
		svc.deviceAttributesFunc = func(ctx context.Context) (interface{}, error) {
			return nil, ErrMockServiceError
		}
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "device_attributes", map[string]interface{}{})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("executeActivateCredential success", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		result, err := registry.ExecuteTool(ctx, "activate_credential", map[string]interface{}{
			"credential_blob": base64.StdEncoding.EncodeToString([]byte("credential-blob")),
			"secret":          base64.StdEncoding.EncodeToString([]byte("secret-value")),
		})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		resultMap, ok := result.(map[string]interface{})
		if !ok {
			t.Fatal("result should be a map")
		}
		if _, exists := resultMap["decrypted"]; !exists {
			t.Fatal("result should contain 'decrypted' key")
		}
	})

	t.Run("executeActivateCredential missing credential_blob", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "activate_credential", map[string]interface{}{
			"secret": base64.StdEncoding.EncodeToString([]byte("secret-value")),
		})
		if err == nil {
			t.Fatal("expected error for missing credential_blob")
		}
		if err != ErrIDevIDCredentialBlobRequired {
			t.Fatalf("expected ErrIDevIDCredentialBlobRequired, got %v", err)
		}
	})

	t.Run("executeActivateCredential missing secret", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "activate_credential", map[string]interface{}{
			"credential_blob": base64.StdEncoding.EncodeToString([]byte("credential-blob")),
		})
		if err == nil {
			t.Fatal("expected error for missing secret")
		}
		if err != ErrIDevIDSecretRequired {
			t.Fatalf("expected ErrIDevIDSecretRequired, got %v", err)
		}
	})

	t.Run("executeActivateCredential invalid credential_blob base64", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "activate_credential", map[string]interface{}{
			"credential_blob": "not-valid-base64!!!",
			"secret":          base64.StdEncoding.EncodeToString([]byte("secret-value")),
		})
		if err == nil {
			t.Fatal("expected error for invalid credential_blob base64")
		}
	})

	t.Run("executeActivateCredential invalid secret base64", func(t *testing.T) {
		svc := newMockServiceProvider()
		registry := NewToolRegistry(svc, log)

		_, err := registry.ExecuteTool(ctx, "activate_credential", map[string]interface{}{
			"credential_blob": base64.StdEncoding.EncodeToString([]byte("credential-blob")),
			"secret":          "not-valid-base64!!!",
		})
		if err == nil {
			t.Fatal("expected error for invalid secret base64")
		}
	})
}
