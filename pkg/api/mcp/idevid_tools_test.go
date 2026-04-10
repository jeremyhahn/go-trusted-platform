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

//go:build iam && codec_msgpack && codec_cbor && codec_json

package mcp

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"
)

// =============================================================================
// IDevID Error Tests
// =============================================================================

func TestIDevIDErrorMessages(t *testing.T) {
	tests := []struct {
		name     string
		err      *IDevIDError
		expected string
	}{
		{
			name:     "ErrIDevIDServiceUnavailable",
			err:      ErrIDevIDServiceUnavailable,
			expected: "IDEVID_SERVICE_UNAVAILABLE: IDevID service is not available",
		},
		{
			name:     "ErrIDevIDNotFound",
			err:      ErrIDevIDNotFound,
			expected: "IDEVID_NOT_FOUND: IDevID key not found",
		},
		{
			name:     "ErrIAKNotFound",
			err:      ErrIAKNotFound,
			expected: "IAK_NOT_FOUND: IAK key not found",
		},
		{
			name:     "ErrIDevIDCertificateNotFound",
			err:      ErrIDevIDCertificateNotFound,
			expected: "IDEVID_CERTIFICATE_NOT_FOUND: IDevID certificate not found",
		},
		{
			name:     "ErrIAKCertificateNotFound",
			err:      ErrIAKCertificateNotFound,
			expected: "IAK_CERTIFICATE_NOT_FOUND: IAK certificate not found",
		},
		{
			name:     "ErrIDevIDCertificatePEMRequired",
			err:      ErrIDevIDCertificatePEMRequired,
			expected: "IDEVID_CERTIFICATE_PEM_REQUIRED: certificate_pem is required",
		},
		{
			name:     "ErrIDevIDInvalidCertificatePEM",
			err:      ErrIDevIDInvalidCertificatePEM,
			expected: "IDEVID_INVALID_CERTIFICATE_PEM: invalid certificate PEM encoding",
		},
		{
			name:     "ErrIDevIDCredentialBlobRequired",
			err:      ErrIDevIDCredentialBlobRequired,
			expected: "IDEVID_CREDENTIAL_BLOB_REQUIRED: credential_blob is required",
		},
		{
			name:     "ErrIDevIDSecretRequired",
			err:      ErrIDevIDSecretRequired,
			expected: "IDEVID_SECRET_REQUIRED: secret is required",
		},
		{
			name:     "ErrIDevIDInvalidBase64",
			err:      ErrIDevIDInvalidBase64,
			expected: "IDEVID_INVALID_BASE64: invalid base64 encoding",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.err.Error()
			if got != tt.expected {
				t.Errorf("Error() = %q, want %q", got, tt.expected)
			}
		})
	}
}

func TestIDevIDError_CustomError(t *testing.T) {
	err := &IDevIDError{
		Code:    "TEST_ERROR",
		Message: "test error message",
	}
	expected := "TEST_ERROR: test error message"
	if err.Error() != expected {
		t.Errorf("Error() = %q, want %q", err.Error(), expected)
	}
}

// =============================================================================
// IDevID Tool Execution Tests
// =============================================================================

func TestExecuteIDevIDGenerate_Success(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.idevidGenerateFunc = func(ctx context.Context, req *IDevIDGenerateMCPRequest) (interface{}, error) {
		if req.Algorithm != "RSA" {
			t.Errorf("Algorithm = %s, want RSA", req.Algorithm)
		}
		if !req.Overwrite {
			t.Error("Overwrite should be true")
		}
		return map[string]interface{}{
			"handle":    "0x81010002",
			"algorithm": req.Algorithm,
			"status":    "created",
		}, nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"algorithm": "RSA",
		"overwrite": true,
	}

	result, err := registry.executeIDevIDGenerate(ctx, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}
	if resultMap["algorithm"] != "RSA" {
		t.Errorf("algorithm = %v, want RSA", resultMap["algorithm"])
	}
}

func TestExecuteIDevIDGenerate_DefaultAlgorithm(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.idevidGenerateFunc = func(ctx context.Context, req *IDevIDGenerateMCPRequest) (interface{}, error) {
		if req.Algorithm != "ECC" {
			t.Errorf("Algorithm = %s, want ECC (default)", req.Algorithm)
		}
		return map[string]interface{}{"status": "created"}, nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	result, err := registry.executeIDevIDGenerate(ctx, map[string]interface{}{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Error("result should not be nil")
	}
}

func TestExecuteIDevIDGenerate_Error(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.idevidGenerateFunc = func(ctx context.Context, req *IDevIDGenerateMCPRequest) (interface{}, error) {
		return nil, errors.New("TPM not available")
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.executeIDevIDGenerate(ctx, map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestExecuteIDevIDInfo_Success(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.idevidInfoFunc = func(ctx context.Context) (interface{}, error) {
		return map[string]interface{}{
			"handle":          "0x81010002",
			"algorithm":       "ECC",
			"has_certificate": true,
		}, nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	result, err := registry.executeIDevIDInfo(ctx, map[string]interface{}{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}
	if resultMap["handle"] != "0x81010002" {
		t.Errorf("handle = %v, want 0x81010002", resultMap["handle"])
	}
}

func TestExecuteIDevIDInfo_Error(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.idevidInfoFunc = func(ctx context.Context) (interface{}, error) {
		return nil, ErrIDevIDNotFound
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.executeIDevIDInfo(ctx, map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestExecuteIDevIDDelete_Success(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.idevidDeleteFunc = func(ctx context.Context) error {
		return nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	result, err := registry.executeIDevIDDelete(ctx, map[string]interface{}{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}
	if resultMap["success"] != true {
		t.Error("expected success = true")
	}
	if resultMap["message"] != "IDevID key deleted" {
		t.Errorf("message = %v, want 'IDevID key deleted'", resultMap["message"])
	}
}

func TestExecuteIDevIDDelete_Error(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.idevidDeleteFunc = func(ctx context.Context) error {
		return errors.New("key not found")
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.executeIDevIDDelete(ctx, map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestExecuteIDevIDCSR_Success(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.idevidCSRFunc = func(ctx context.Context, req *IDevIDCSRMCPRequest) (interface{}, error) {
		if req.CommonName != "device.example.com" {
			t.Errorf("CommonName = %s, want device.example.com", req.CommonName)
		}
		if req.Organization != "Test Org" {
			t.Errorf("Organization = %s, want Test Org", req.Organization)
		}
		if !req.IncludeTCGAttrs {
			t.Error("IncludeTCGAttrs should be true by default")
		}
		return map[string]interface{}{
			"csr_pem": "-----BEGIN CERTIFICATE REQUEST-----\nMIIB...\n-----END CERTIFICATE REQUEST-----",
		}, nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"common_name":  "device.example.com",
		"organization": "Test Org",
		"country":      "US",
	}

	result, err := registry.executeIDevIDCSR(ctx, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}
	if _, ok := resultMap["csr_pem"]; !ok {
		t.Error("expected csr_pem in result")
	}
}

func TestExecuteIDevIDCSR_WithIncludeTCGAttrsFalse(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.idevidCSRFunc = func(ctx context.Context, req *IDevIDCSRMCPRequest) (interface{}, error) {
		if req.IncludeTCGAttrs {
			t.Error("IncludeTCGAttrs should be false")
		}
		return map[string]interface{}{"csr_pem": "..."}, nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"common_name":       "test",
		"include_tcg_attrs": false,
	}

	_, err := registry.executeIDevIDCSR(ctx, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecuteIDevIDCSR_Error(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.idevidCSRFunc = func(ctx context.Context, req *IDevIDCSRMCPRequest) (interface{}, error) {
		return nil, errors.New("CSR generation failed")
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.executeIDevIDCSR(ctx, map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestExecuteIDevIDInstallCert_Success(t *testing.T) {
	ctx := context.Background()
	certPEM := "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"
	svc := newMockServiceProvider()
	svc.idevidInstallCertFunc = func(ctx context.Context, cert string) (interface{}, error) {
		if cert != certPEM {
			t.Errorf("cert = %s, want %s", cert, certPEM)
		}
		return map[string]interface{}{"installed": true}, nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"certificate_pem": certPEM,
	}

	result, err := registry.executeIDevIDInstallCert(ctx, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}
	if resultMap["installed"] != true {
		t.Error("expected installed = true")
	}
}

func TestExecuteIDevIDInstallCert_MissingCertPEM(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.executeIDevIDInstallCert(ctx, map[string]interface{}{})
	if err != ErrIDevIDCertificatePEMRequired {
		t.Errorf("expected ErrIDevIDCertificatePEMRequired, got %v", err)
	}
}

func TestExecuteIDevIDInstallCert_Error(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.idevidInstallCertFunc = func(ctx context.Context, cert string) (interface{}, error) {
		return nil, errors.New("installation failed")
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"certificate_pem": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
	}

	_, err := registry.executeIDevIDInstallCert(ctx, args)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestExecuteIDevIDGetCert_Success(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.idevidGetCertFunc = func(ctx context.Context, includePEM bool) (interface{}, error) {
		result := map[string]interface{}{
			"serial":      "abc123",
			"common_name": "device.example.com",
		}
		if includePEM {
			result["pem"] = "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----"
		}
		return result, nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	result, err := registry.executeIDevIDGetCert(ctx, map[string]interface{}{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}
	if resultMap["serial"] != "abc123" {
		t.Errorf("serial = %v, want abc123", resultMap["serial"])
	}
}

func TestExecuteIDevIDGetCert_WithIncludePEMFalse(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.idevidGetCertFunc = func(ctx context.Context, includePEM bool) (interface{}, error) {
		if includePEM {
			t.Error("includePEM should be false")
		}
		return map[string]interface{}{"serial": "abc123"}, nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"include_pem": false,
	}

	_, err := registry.executeIDevIDGetCert(ctx, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecuteIDevIDGetCert_Error(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.idevidGetCertFunc = func(ctx context.Context, includePEM bool) (interface{}, error) {
		return nil, ErrIDevIDCertificateNotFound
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.executeIDevIDGetCert(ctx, map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestExecuteIDevIDDeleteCert_Success(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.idevidDeleteCertFunc = func(ctx context.Context) error {
		return nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	result, err := registry.executeIDevIDDeleteCert(ctx, map[string]interface{}{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}
	if resultMap["success"] != true {
		t.Error("expected success = true")
	}
}

func TestExecuteIDevIDDeleteCert_Error(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.idevidDeleteCertFunc = func(ctx context.Context) error {
		return errors.New("cert not found")
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.executeIDevIDDeleteCert(ctx, map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestExecuteIDevIDExists_Success(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.idevidExistsFunc = func(ctx context.Context) (bool, error) {
		return true, nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	result, err := registry.executeIDevIDExists(ctx, map[string]interface{}{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}
	if resultMap["exists"] != true {
		t.Error("expected exists = true")
	}
}

func TestExecuteIDevIDExists_NotExists(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.idevidExistsFunc = func(ctx context.Context) (bool, error) {
		return false, nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	result, err := registry.executeIDevIDExists(ctx, map[string]interface{}{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}
	if resultMap["exists"] != false {
		t.Error("expected exists = false")
	}
}

func TestExecuteIDevIDExists_Error(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.idevidExistsFunc = func(ctx context.Context) (bool, error) {
		return false, errors.New("TPM error")
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.executeIDevIDExists(ctx, map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error")
	}
}

// =============================================================================
// IAK Tool Execution Tests
// =============================================================================

func TestExecuteIAKGenerate_Success(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iakGenerateFunc = func(ctx context.Context, req *IDevIDGenerateMCPRequest) (interface{}, error) {
		if req.Algorithm != "RSA" {
			t.Errorf("Algorithm = %s, want RSA", req.Algorithm)
		}
		return map[string]interface{}{
			"handle":    "0x81010003",
			"algorithm": req.Algorithm,
		}, nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"algorithm": "RSA",
	}

	result, err := registry.executeIAKGenerate(ctx, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Error("result should not be nil")
	}
}

func TestExecuteIAKGenerate_DefaultAlgorithm(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iakGenerateFunc = func(ctx context.Context, req *IDevIDGenerateMCPRequest) (interface{}, error) {
		if req.Algorithm != "ECC" {
			t.Errorf("Algorithm = %s, want ECC (default)", req.Algorithm)
		}
		return map[string]interface{}{"status": "created"}, nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.executeIAKGenerate(ctx, map[string]interface{}{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecuteIAKGenerate_Error(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iakGenerateFunc = func(ctx context.Context, req *IDevIDGenerateMCPRequest) (interface{}, error) {
		return nil, errors.New("generation failed")
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.executeIAKGenerate(ctx, map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestExecuteIAKInfo_Success(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iakInfoFunc = func(ctx context.Context) (interface{}, error) {
		return map[string]interface{}{
			"handle":    "0x81010003",
			"algorithm": "ECC",
		}, nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	result, err := registry.executeIAKInfo(ctx, map[string]interface{}{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Error("result should not be nil")
	}
}

func TestExecuteIAKInfo_Error(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iakInfoFunc = func(ctx context.Context) (interface{}, error) {
		return nil, ErrIAKNotFound
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.executeIAKInfo(ctx, map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestExecuteIAKDelete_Success(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iakDeleteFunc = func(ctx context.Context) error {
		return nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	result, err := registry.executeIAKDelete(ctx, map[string]interface{}{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}
	if resultMap["success"] != true {
		t.Error("expected success = true")
	}
	if resultMap["message"] != "IAK key deleted" {
		t.Errorf("message = %v, want 'IAK key deleted'", resultMap["message"])
	}
}

func TestExecuteIAKDelete_Error(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iakDeleteFunc = func(ctx context.Context) error {
		return errors.New("key not found")
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.executeIAKDelete(ctx, map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestExecuteIAKCSR_Success(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iakCSRFunc = func(ctx context.Context, req *IDevIDCSRMCPRequest) (interface{}, error) {
		if req.CommonName != "device-iak.example.com" {
			t.Errorf("CommonName = %s, want device-iak.example.com", req.CommonName)
		}
		return map[string]interface{}{"csr_pem": "..."}, nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"common_name": "device-iak.example.com",
	}

	_, err := registry.executeIAKCSR(ctx, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecuteIAKCSR_WithIncludeTCGAttrsFalse(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iakCSRFunc = func(ctx context.Context, req *IDevIDCSRMCPRequest) (interface{}, error) {
		if req.IncludeTCGAttrs {
			t.Error("IncludeTCGAttrs should be false")
		}
		return map[string]interface{}{"csr_pem": "..."}, nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"include_tcg_attrs": false,
	}

	_, err := registry.executeIAKCSR(ctx, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecuteIAKCSR_Error(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iakCSRFunc = func(ctx context.Context, req *IDevIDCSRMCPRequest) (interface{}, error) {
		return nil, errors.New("CSR generation failed")
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.executeIAKCSR(ctx, map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestExecuteIAKInstallCert_Success(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iakInstallCertFunc = func(ctx context.Context, cert string) (interface{}, error) {
		return map[string]interface{}{"installed": true}, nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"certificate_pem": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
	}

	result, err := registry.executeIAKInstallCert(ctx, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}
	if resultMap["installed"] != true {
		t.Error("expected installed = true")
	}
}

func TestExecuteIAKInstallCert_MissingCertPEM(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.executeIAKInstallCert(ctx, map[string]interface{}{})
	if err != ErrIDevIDCertificatePEMRequired {
		t.Errorf("expected ErrIDevIDCertificatePEMRequired, got %v", err)
	}
}

func TestExecuteIAKInstallCert_Error(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iakInstallCertFunc = func(ctx context.Context, cert string) (interface{}, error) {
		return nil, errors.New("installation failed")
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"certificate_pem": "-----BEGIN CERTIFICATE-----\nMIIB...\n-----END CERTIFICATE-----",
	}

	_, err := registry.executeIAKInstallCert(ctx, args)
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestExecuteIAKGetCert_Success(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iakGetCertFunc = func(ctx context.Context, includePEM bool) (interface{}, error) {
		return map[string]interface{}{"serial": "iak123"}, nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	result, err := registry.executeIAKGetCert(ctx, map[string]interface{}{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if result == nil {
		t.Error("result should not be nil")
	}
}

func TestExecuteIAKGetCert_WithIncludePEMFalse(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iakGetCertFunc = func(ctx context.Context, includePEM bool) (interface{}, error) {
		if includePEM {
			t.Error("includePEM should be false")
		}
		return map[string]interface{}{"serial": "iak123"}, nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"include_pem": false,
	}

	_, err := registry.executeIAKGetCert(ctx, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestExecuteIAKGetCert_Error(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iakGetCertFunc = func(ctx context.Context, includePEM bool) (interface{}, error) {
		return nil, ErrIAKCertificateNotFound
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.executeIAKGetCert(ctx, map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestExecuteIAKDeleteCert_Success(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iakDeleteCertFunc = func(ctx context.Context) error {
		return nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	result, err := registry.executeIAKDeleteCert(ctx, map[string]interface{}{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}
	if resultMap["success"] != true {
		t.Error("expected success = true")
	}
}

func TestExecuteIAKDeleteCert_Error(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iakDeleteCertFunc = func(ctx context.Context) error {
		return errors.New("cert not found")
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.executeIAKDeleteCert(ctx, map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestExecuteIAKExists_Success(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iakExistsFunc = func(ctx context.Context) (bool, error) {
		return true, nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	result, err := registry.executeIAKExists(ctx, map[string]interface{}{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}
	if resultMap["exists"] != true {
		t.Error("expected exists = true")
	}
}

func TestExecuteIAKExists_Error(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.iakExistsFunc = func(ctx context.Context) (bool, error) {
		return false, errors.New("TPM error")
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.executeIAKExists(ctx, map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error")
	}
}

// =============================================================================
// Device Attributes and Activate Credential Tests
// =============================================================================

func TestExecuteDeviceAttributes_Success(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.deviceAttributesFunc = func(ctx context.Context) (interface{}, error) {
		return map[string]interface{}{
			"manufacturer":     "Test TPM Manufacturer",
			"model":            "vTPM 2.0",
			"firmware_version": "1.2.3",
		}, nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	result, err := registry.executeDeviceAttributes(ctx, map[string]interface{}{})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}
	if resultMap["manufacturer"] != "Test TPM Manufacturer" {
		t.Errorf("manufacturer = %v, want 'Test TPM Manufacturer'", resultMap["manufacturer"])
	}
}

func TestExecuteDeviceAttributes_Error(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.deviceAttributesFunc = func(ctx context.Context) (interface{}, error) {
		return nil, errors.New("TPM not available")
	}
	registry := NewToolRegistry(svc, newTestLogger())

	_, err := registry.executeDeviceAttributes(ctx, map[string]interface{}{})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestExecuteActivateCredential_Success(t *testing.T) {
	ctx := context.Background()
	credentialBlob := []byte("credential-blob-data")
	secret := []byte("encrypted-secret")

	svc := newMockServiceProvider()
	svc.activateCredentialFunc = func(ctx context.Context, blob []byte, sec []byte) ([]byte, error) {
		if string(blob) != string(credentialBlob) {
			t.Errorf("credentialBlob mismatch")
		}
		if string(sec) != string(secret) {
			t.Errorf("secret mismatch")
		}
		return []byte("decrypted-credential"), nil
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"credential_blob": base64.StdEncoding.EncodeToString(credentialBlob),
		"secret":          base64.StdEncoding.EncodeToString(secret),
	}

	result, err := registry.executeActivateCredential(ctx, args)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	resultMap, ok := result.(map[string]interface{})
	if !ok {
		t.Fatal("expected map result")
	}

	decrypted, ok := resultMap["decrypted"].(string)
	if !ok {
		t.Fatal("expected decrypted to be string")
	}

	decoded, err := base64.StdEncoding.DecodeString(decrypted)
	if err != nil {
		t.Fatalf("failed to decode result: %v", err)
	}
	if string(decoded) != "decrypted-credential" {
		t.Errorf("decoded = %s, want decrypted-credential", string(decoded))
	}
}

func TestExecuteActivateCredential_MissingCredentialBlob(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"secret": base64.StdEncoding.EncodeToString([]byte("secret")),
	}

	_, err := registry.executeActivateCredential(ctx, args)
	if err != ErrIDevIDCredentialBlobRequired {
		t.Errorf("expected ErrIDevIDCredentialBlobRequired, got %v", err)
	}
}

func TestExecuteActivateCredential_MissingSecret(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"credential_blob": base64.StdEncoding.EncodeToString([]byte("blob")),
	}

	_, err := registry.executeActivateCredential(ctx, args)
	if err != ErrIDevIDSecretRequired {
		t.Errorf("expected ErrIDevIDSecretRequired, got %v", err)
	}
}

func TestExecuteActivateCredential_InvalidCredentialBlobBase64(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"credential_blob": "not-valid-base64!!!",
		"secret":          base64.StdEncoding.EncodeToString([]byte("secret")),
	}

	_, err := registry.executeActivateCredential(ctx, args)
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
	if !errors.Is(err, ErrIDevIDInvalidBase64) {
		t.Errorf("expected error to wrap ErrIDevIDInvalidBase64, got %v", err)
	}
}

func TestExecuteActivateCredential_InvalidSecretBase64(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"credential_blob": base64.StdEncoding.EncodeToString([]byte("blob")),
		"secret":          "not-valid-base64!!!",
	}

	_, err := registry.executeActivateCredential(ctx, args)
	if err == nil {
		t.Fatal("expected error for invalid base64")
	}
	if !errors.Is(err, ErrIDevIDInvalidBase64) {
		t.Errorf("expected error to wrap ErrIDevIDInvalidBase64, got %v", err)
	}
}

func TestExecuteActivateCredential_ServiceError(t *testing.T) {
	ctx := context.Background()
	svc := newMockServiceProvider()
	svc.activateCredentialFunc = func(ctx context.Context, blob []byte, sec []byte) ([]byte, error) {
		return nil, errors.New("TPM error")
	}
	registry := NewToolRegistry(svc, newTestLogger())

	args := map[string]interface{}{
		"credential_blob": base64.StdEncoding.EncodeToString([]byte("blob")),
		"secret":          base64.StdEncoding.EncodeToString([]byte("secret")),
	}

	_, err := registry.executeActivateCredential(ctx, args)
	if err == nil {
		t.Fatal("expected error")
	}
}

// =============================================================================
// IDevID Tool Registration Tests
// =============================================================================

func TestRegisterIDevIDTools(t *testing.T) {
	svc := newMockServiceProvider()
	registry := NewToolRegistry(svc, newTestLogger())

	expectedTools := []string{
		"idevid_generate",
		"idevid_info",
		"idevid_delete",
		"idevid_csr",
		"idevid_install_cert",
		"idevid_get_cert",
		"idevid_delete_cert",
		"idevid_exists",
		"iak_generate",
		"iak_info",
		"iak_delete",
		"iak_csr",
		"iak_install_cert",
		"iak_get_cert",
		"iak_delete_cert",
		"iak_exists",
		"device_attributes",
		"activate_credential",
	}

	tools := registry.ListTools()
	toolNames := make(map[string]bool)
	for _, tool := range tools {
		toolNames[tool.Name] = true
	}

	for _, name := range expectedTools {
		if !toolNames[name] {
			t.Errorf("missing expected tool: %s", name)
		}
	}
}
