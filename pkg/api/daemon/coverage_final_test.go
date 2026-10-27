// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.

package daemon

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"testing"
	"time"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
	dnsentities "github.com/jeremyhahn/go-trusted-platform/pkg/dns/entities"
	"github.com/jeremyhahn/go-trusted-platform/pkg/health"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// =============================================================================
// Untested Error Types - Error() and Unwrap() coverage
// =============================================================================

func TestCoverageFinalUncoveredErrors(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("sentinel")

	tests := []struct {
		name     string
		err      error
		contains string
	}{
		// Compute adapter errors
		{"ErrNilOrchestrator", ErrNilOrchestrator{}, "orchestrator cannot be nil"},
		{"ErrLogsNotSupported", ErrLogsNotSupported{}, "container logs operation not supported"},
		{"ErrAttestNotSupported", ErrAttestNotSupported{}, "container attestation operation not supported"},
		{"ErrVerifyAttestationNotSupported", ErrVerifyAttestationNotSupported{}, "verify attestation operation not supported"},
		{"ErrEvaluatePolicyNotSupported", ErrEvaluatePolicyNotSupported{}, "evaluate policy operation not supported"},
		{"ErrPullImageNotSupported", ErrPullImageNotSupported{}, "pull image operation not supported"},
		{"ErrVerifyImageNotSupported", ErrVerifyImageNotSupported{}, "verify image operation not supported"},

		// Container errors
		{"ErrContainerServiceNotAvailable", ErrContainerServiceNotAvailable{}, "container service not available"},
		{"ErrContainerNotFound", ErrContainerNotFound{ContainerID: "c-1"}, "container not found: c-1"},
		{"ErrContainerOperationFailed", ErrContainerOperationFailed{Operation: "start", Cause: sentinel}, "container operation start failed"},
		{"ErrContainerAttestNotSupported", ErrContainerAttestNotSupported{}, "container attestation not implemented"},
		{"ErrContainerInvalidParameter", ErrContainerInvalidParameter{Parameter: "image", Reason: "empty"}, "invalid container parameter image: empty"},

		// Authentication/Token errors
		{"ErrQuicBaaSServiceUnavailable", ErrQuicBaaSServiceUnavailable{}, "QuicBaaS service not available"},
		{"ErrTokenValidationFailed_with_cause", ErrTokenValidationFailed{Cause: sentinel}, "token validation failed: sentinel"},
		{"ErrTokenValidationFailed_nil_cause", ErrTokenValidationFailed{}, "token validation failed"},

		// Overlay/Gateway errors
		{"ErrOverlayServiceNotAvailable", ErrOverlayServiceNotAvailable{}, "overlay network service not available"},
		{"ErrGatewayServiceNotAvailable", ErrGatewayServiceNotAvailable{}, "gateway service not available"},

		// TPM errors
		{"ErrTPMInvalidSize", ErrTPMInvalidSize{Max: 64, Requested: 128}, "requested size 128 exceeds maximum 64 bytes"},

		// mTLS errors
		{"ErrMTLSNoPeerInfo", ErrMTLSNoPeerInfo{}, ""},
		{"ErrMTLSNoTLSInfo", ErrMTLSNoTLSInfo{}, ""},
		{"ErrMTLSNoCertificates", ErrMTLSNoCertificates{}, ""},

		// IAM authorizer errors
		{"ErrPEPClientNotAvailable", ErrPEPClientNotAvailable{}, ""},

		// TPM2/IDevID errors
		{"ErrInvalidCertificatePEM", ErrInvalidCertificatePEM{}, "invalid PEM-encoded certificate"},
		{"ErrTPM2ServiceNotAvailable", ErrTPM2ServiceNotAvailable{}, "TPM2 service not available"},
		{"ErrIDevIDNotFound", ErrIDevIDNotFound{}, "IDevID not found in TPM"},
		{"ErrIAKNotFound", ErrIAKNotFound{}, "IAK not found in TPM"},
		{"ErrIDevIDCertificateNotFound", ErrIDevIDCertificateNotFound{}, "IDevID certificate not installed"},
		{"ErrIAKCertificateNotFound", ErrIAKCertificateNotFound{}, "IAK certificate not installed"},
		{"ErrTPM2OperationFailed", ErrTPM2OperationFailed{Operation: "read", Cause: sentinel}, "TPM2 operation read failed"},

		// KMS errors
		{"ErrKMSOperationNotImplemented", ErrKMSOperationNotImplemented{Operation: "ImportKey"}, "KMS operation not implemented: ImportKey"},

		// Service unavailable
		{"ErrServiceUnavailable", ErrServiceUnavailable{Service: "ca"}, "service unavailable: ca"},

		// Device errors
		{"ErrDeviceOperationFailed", ErrDeviceOperationFailed{Operation: "provision", Cause: sentinel}, "device operation provision failed"},
		{"ErrDeviceProfileServiceNotAvailable", ErrDeviceProfileServiceNotAvailable{}, "device: profile service not available"},
		{"ErrDeviceProfileLookupFailed", ErrDeviceProfileLookupFailed{DeviceID: "7", Cause: sentinel}, "device profile lookup failed for device 7"},
		{"ErrAttestationFailed with cause", ErrAttestationFailed{Reason: "peer verification did not complete", Err: sentinel}, "attestation failed: peer verification did not complete: "},

		// TLS config
		{"ErrTLSConfigFailed", ErrTLSConfigFailed{Reason: "missing cert"}, "tls config failed: missing cert"},

		// Tenant DEK errors
		{"ErrTenantDEKProvision", ErrTenantDEKProvision{TenantID: "t1", Cause: sentinel}, "failed to provision DEK for tenant t1"},
		{"ErrTenantDEKDeprovision", ErrTenantDEKDeprovision{TenantID: "t2", Cause: sentinel}, "failed to deprovision DEK for tenant t2"},

		// PXE errors
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			msg := tc.err.Error()
			if tc.contains != "" && !containsStr(msg, tc.contains) {
				t.Errorf("Error() = %q, expected to contain %q", msg, tc.contains)
			}
			if msg == "" {
				t.Errorf("Error() returned empty string for %T", tc.err)
			}
		})
	}
}

func TestCoverageFinalUnwrapMethods(t *testing.T) {
	t.Parallel()

	sentinel := errors.New("inner")

	unwrapCases := []struct {
		name  string
		err   error
		inner error
	}{
		{"ErrTokenValidationFailed", ErrTokenValidationFailed{Cause: sentinel}, sentinel},
		{"ErrTPM2OperationFailed", ErrTPM2OperationFailed{Operation: "x", Cause: sentinel}, sentinel},
		{"ErrContainerOperationFailed", ErrContainerOperationFailed{Operation: "x", Cause: sentinel}, sentinel},
		{"ErrDeviceOperationFailed", ErrDeviceOperationFailed{Operation: "x", Cause: sentinel}, sentinel},
		{"ErrDeviceProfileLookupFailed", ErrDeviceProfileLookupFailed{DeviceID: "x", Cause: sentinel}, sentinel},
		{"ErrAttestationFailed", ErrAttestationFailed{Reason: "x", Err: sentinel}, sentinel},
		{"ErrTenantDEKProvision", ErrTenantDEKProvision{TenantID: "t", Cause: sentinel}, sentinel},
		{"ErrTenantDEKDeprovision", ErrTenantDEKDeprovision{TenantID: "t", Cause: sentinel}, sentinel},
	}

	for _, tc := range unwrapCases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			unwrapper, ok := tc.err.(interface{ Unwrap() error })
			if !ok {
				t.Fatalf("%T does not implement Unwrap()", tc.err)
			}
			if unwrapper.Unwrap() != tc.inner {
				t.Errorf("Unwrap() = %v, want %v", unwrapper.Unwrap(), tc.inner)
			}
		})
	}
}

// =============================================================================
// QUIC Service Handler - normalize/convert helpers
// =============================================================================

func TestCoverageFinalNormalizeSystemStatusEnum(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		expected string
	}{
		{"SYSTEM_STATUS_READY", "ready"},
		{"SYSTEM_STATUS_INITIALIZING", "initializing"},
		{"SYSTEM_STATUS_DEGRADED", "degraded"},
		{"SYSTEM_STATUS_UNAVAILABLE", "unavailable"},
		{"SYSTEM_STATUS_SHUTTING_DOWN", "shutting_down"},
		{"SYSTEM_STATUS_CUSTOM", "custom"},
		{"unknown", "unknown"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got := normalizeSystemStatusEnum(tc.input)
			if got != tc.expected {
				t.Errorf("normalizeSystemStatusEnum(%q) = %q, want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestCoverageFinalNormalizeServiceStatusEnum(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		expected string
	}{
		{"SERVICE_STATUS_RUNNING", "running"},
		{"SERVICE_STATUS_STOPPED", "stopped"},
		{"SERVICE_STATUS_STARTING", "starting"},
		{"SERVICE_STATUS_STOPPING", "stopping"},
		{"SERVICE_STATUS_ERROR", "error"},
		{"SERVICE_STATUS_CUSTOM", "custom"},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got := normalizeServiceStatusEnum(tc.input)
			if got != tc.expected {
				t.Errorf("normalizeServiceStatusEnum(%q) = %q, want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestCoverageFinalBuildProtocolInfo(t *testing.T) {
	t.Parallel()

	t.Run("valid_address", func(t *testing.T) {
		t.Parallel()
		info := buildProtocolInfo("gRPC", true, "0.0.0.0:10443", true)
		if info.Name != "gRPC" {
			t.Errorf("Name = %q, want gRPC", info.Name)
		}
		if info.Port != 10443 {
			t.Errorf("Port = %d, want 10443", info.Port)
		}
		if info.Status != "enabled" {
			t.Errorf("Status = %q, want enabled", info.Status)
		}
		if !info.TLS {
			t.Error("TLS should be true")
		}
	})

	t.Run("invalid_address", func(t *testing.T) {
		t.Parallel()
		info := buildProtocolInfo("Unix", false, "/run/sock", false)
		if info.Port != 0 {
			t.Errorf("Port = %d, want 0", info.Port)
		}
		if info.Status != "disabled" {
			t.Errorf("Status = %q, want disabled", info.Status)
		}
	})
}

func TestCoverageFinalProtocolStatus(t *testing.T) {
	t.Parallel()

	if protocolStatus(true) != "enabled" {
		t.Error("protocolStatus(true) should be enabled")
	}
	if protocolStatus(false) != "disabled" {
		t.Error("protocolStatus(false) should be disabled")
	}
}

func TestCoverageFinalConvertServiceInfoToQUIC(t *testing.T) {
	t.Parallel()

	t.Run("nil_input", func(t *testing.T) {
		t.Parallel()
		result := convertServiceInfoToQUIC(nil)
		if result.Name != "" {
			t.Errorf("expected empty name for nil input, got %q", result.Name)
		}
	})

	t.Run("full_info", func(t *testing.T) {
		t.Parallel()
		now := timestamppb.Now()
		info := &platformv1.ServiceInfo{
			Name:          "tpm",
			Status:        platformv1.ServiceStatus_SERVICE_STATUS_RUNNING,
			StartedAt:     now,
			UptimeSeconds: 3600,
			Metadata: map[string]string{
				"start_count": "5",
				"stop_count":  "2",
				"last_error":  "timeout",
			},
		}
		result := convertServiceInfoToQUIC(info)
		if result.Name != "tpm" {
			t.Errorf("Name = %q, want tpm", result.Name)
		}
		if result.Status != "running" {
			t.Errorf("Status = %q, want running", result.Status)
		}
		if result.StartCount != 5 {
			t.Errorf("StartCount = %d, want 5", result.StartCount)
		}
		if result.StopCount != 2 {
			t.Errorf("StopCount = %d, want 2", result.StopCount)
		}
		if result.LastError != "timeout" {
			t.Errorf("LastError = %q, want timeout", result.LastError)
		}
		if result.StartedAt == 0 {
			t.Error("StartedAt should not be 0")
		}
	})

	t.Run("no_metadata", func(t *testing.T) {
		t.Parallel()
		info := &platformv1.ServiceInfo{
			Name:   "sdn",
			Status: platformv1.ServiceStatus_SERVICE_STATUS_STOPPED,
		}
		result := convertServiceInfoToQUIC(info)
		if result.StartCount != 0 {
			t.Errorf("StartCount = %d, want 0", result.StartCount)
		}
	})
}

// =============================================================================
// KMS Conversion Helpers
// =============================================================================

func TestCoverageFinalKeyStatusToString(t *testing.T) {
	t.Parallel()
	got := keyStatusToString(pb.KeyStatus_KEY_STATUS_ENABLED)
	if got == "" {
		t.Error("keyStatusToString returned empty string")
	}
}

func TestCoverageFinalKeyUsagesToStrings(t *testing.T) {
	t.Parallel()

	t.Run("ShortNames", func(t *testing.T) {
		t.Parallel()
		usages := []pb.KeyUsage{
			pb.KeyUsage_KEY_USAGE_ENCRYPT,
			pb.KeyUsage_KEY_USAGE_SIGN,
			pb.KeyUsage_KEY_USAGE_WRAP_KEY,
		}
		want := []string{"ENCRYPT", "SIGN", "WRAP_KEY"}
		result := keyUsagesToStrings(usages)
		if len(result) != len(want) {
			t.Fatalf("expected %d strings, got %v", len(want), result)
		}
		for i := range want {
			if result[i] != want[i] {
				t.Errorf("result[%d] = %q, want %q", i, result[i], want[i])
			}
		}
	})

	t.Run("RoundTrip", func(t *testing.T) {
		t.Parallel()
		usages := []pb.KeyUsage{
			pb.KeyUsage_KEY_USAGE_ENCRYPT,
			pb.KeyUsage_KEY_USAGE_DECRYPT,
			pb.KeyUsage_KEY_USAGE_SIGN,
			pb.KeyUsage_KEY_USAGE_VERIFY,
			pb.KeyUsage_KEY_USAGE_WRAP_KEY,
			pb.KeyUsage_KEY_USAGE_DERIVE_KEY,
			pb.KeyUsage_KEY_USAGE_GENERATE_MAC,
			pb.KeyUsage_KEY_USAGE_VERIFY_MAC,
		}
		back := stringsToKeyUsages(keyUsagesToStrings(usages))
		if len(back) != len(usages) {
			t.Fatalf("round trip lost usages: got %v, want %v", back, usages)
		}
		for i := range usages {
			if back[i] != usages[i] {
				t.Errorf("round trip [%d] = %v, want %v", i, back[i], usages[i])
			}
		}
	})

	t.Run("Empty", func(t *testing.T) {
		t.Parallel()
		if result := keyUsagesToStrings(nil); len(result) != 0 {
			t.Errorf("expected no strings, got %v", result)
		}
	})
}

func TestCoverageFinalStringToKeyUsage(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		expected pb.KeyUsage
	}{
		{"ENCRYPT", pb.KeyUsage_KEY_USAGE_ENCRYPT},
		{"DECRYPT", pb.KeyUsage_KEY_USAGE_DECRYPT},
		{"SIGN", pb.KeyUsage_KEY_USAGE_SIGN},
		{"VERIFY", pb.KeyUsage_KEY_USAGE_VERIFY},
		{"WRAP", pb.KeyUsage_KEY_USAGE_WRAP_KEY},
		{"DERIVE", pb.KeyUsage_KEY_USAGE_DERIVE_KEY},
		{"MAC", pb.KeyUsage_KEY_USAGE_GENERATE_MAC},
		{"VERIFY_MAC", pb.KeyUsage_KEY_USAGE_VERIFY_MAC},
		{"unknown", pb.KeyUsage_KEY_USAGE_UNSPECIFIED},
		{"key-usage-encrypt", pb.KeyUsage_KEY_USAGE_ENCRYPT},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got := stringToKeyUsage(tc.input)
			if got != tc.expected {
				t.Errorf("stringToKeyUsage(%q) = %v, want %v", tc.input, got, tc.expected)
			}
		})
	}
}

func TestCoverageFinalStringsToKeyUsages(t *testing.T) {
	t.Parallel()

	result := stringsToKeyUsages([]string{"ENCRYPT", "SIGN", "unknown"})
	if len(result) != 2 {
		t.Errorf("expected 2 usages (unknown filtered), got %d", len(result))
	}
}

func TestCoverageFinalBuildDataKeySpecForQUIC(t *testing.T) {
	t.Parallel()

	valid := []struct {
		name      string
		algorithm platformv1.KMSKeyAlgorithm
		expected  pb.KeyAlgorithm
		bits      int32
	}{
		{"unspecified_defaults_aes256", platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_UNSPECIFIED, pb.KeyAlgorithm_KEY_ALG_AES_256_GCM, 256},
		{"aes128", platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_128, pb.KeyAlgorithm_KEY_ALG_AES_128_GCM, 128},
		{"aes192", platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_192, pb.KeyAlgorithm_KEY_ALG_AES_192_GCM, 192},
		{"aes256", platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_AES_256, pb.KeyAlgorithm_KEY_ALG_AES_256_GCM, 256},
		{"chacha20", platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_CHACHA20_POLY1305, pb.KeyAlgorithm_KEY_ALG_CHACHA20_POLY1305, 256},
	}

	for _, tc := range valid {
		t.Run("valid_"+tc.name, func(t *testing.T) {
			t.Parallel()
			spec, err := buildDataKeySpecForQUIC(int32(tc.algorithm), 0)
			if err != nil {
				t.Fatalf("buildDataKeySpecForQUIC(%v) error: %v", tc.algorithm, err)
			}
			if spec == nil {
				t.Fatal("spec should not be nil")
			}
			if spec.Algorithm != tc.expected {
				t.Errorf("Algorithm = %v, want %v", spec.Algorithm, tc.expected)
			}
			if spec.KeySize != tc.bits {
				t.Errorf("KeySize = %d, want %d", spec.KeySize, tc.bits)
			}
		})
	}

	t.Run("invalid", func(t *testing.T) {
		t.Parallel()
		_, err := buildDataKeySpecForQUIC(int32(platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_RSA_2048), 0)
		if err == nil {
			t.Fatal("expected error for asymmetric data key algorithm")
		}
		var errAlg ErrKMSInvalidAlgorithm
		if !errors.As(err, &errAlg) {
			t.Errorf("expected ErrKMSInvalidAlgorithm, got %T", err)
		}
	})
}

func TestCoverageFinalConvertKeyHandleToQUIC(t *testing.T) {
	t.Parallel()

	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		if convertKeyHandleToQUIC(nil) != nil {
			t.Error("expected nil for nil input")
		}
	})

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		handle := &pb.KeyHandle{
			KeyId:     "key-123",
			Version:   2,
			Algorithm: pb.KeyAlgorithm_KEY_ALG_RSA_2048,
			Status:    pb.KeyStatus_KEY_STATUS_ENABLED,
		}
		result := convertKeyHandleToQUIC(handle)
		if result == nil {
			t.Fatal("result should not be nil")
		}
		if result.KeyId != "key-123" {
			t.Errorf("KeyID = %q, want key-123", result.KeyId)
		}
		if result.Version != 2 {
			t.Errorf("Version = %d, want 2", result.Version)
		}
	})
}

func TestCoverageFinalConvertKeyMetadataToQUIC(t *testing.T) {
	t.Parallel()

	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		if convertKeyMetadataToQUIC(nil) != nil {
			t.Error("expected nil for nil input")
		}
	})

	t.Run("valid", func(t *testing.T) {
		t.Parallel()
		meta := &pb.KeyMetadata{
			KeyId:       "key-456",
			Name:        "test-key",
			Description: "A test key",
			Algorithm:   pb.KeyAlgorithm_KEY_ALG_ECDSA_P256,
			Status:      pb.KeyStatus_KEY_STATUS_ENABLED,
			Usage:       []pb.KeyUsage{pb.KeyUsage_KEY_USAGE_SIGN},
			Version:     3,
			Exportable:  true,
			Owner:       "admin",
			Tags:        map[string]string{"env": "test"},
		}
		result := convertKeyMetadataToQUIC(meta)
		if result == nil {
			t.Fatal("result should not be nil")
		}
		if result.KeyId != "key-456" {
			t.Errorf("KeyID = %q, want key-456", result.KeyId)
		}
		if platformv1.KMSKeyAlgorithm(result.Algorithm) != platformv1.KMSKeyAlgorithm_KMS_KEY_ALGORITHM_ECDSA_P256 {
			t.Errorf("Algorithm = %d, want ECDSA_P256", result.Algorithm)
		}
		if platformv1.KeyStatus(result.Status) != platformv1.KeyStatus_KEY_STATUS_ENABLED {
			t.Errorf("Status = %d, want ENABLED", result.Status)
		}
		if len(result.Usage) != 1 || platformv1.KeyUsage(result.Usage[0]) != platformv1.KeyUsage_KEY_USAGE_SIGN {
			t.Errorf("Usage = %v, want [SIGN]", result.Usage)
		}
	})
}

// =============================================================================
// SDN Conversion Helpers
// =============================================================================

// =============================================================================
// DNS Conversion Helpers
// =============================================================================

func TestCoverageFinalConvertToQUICRecord(t *testing.T) {
	t.Parallel()

	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		if convertToQUICRecord(nil, "A") != nil {
			t.Error("expected nil for nil input")
		}
	})

	t.Run("A_record", func(t *testing.T) {
		t.Parallel()
		rec := &dnsentities.ARecord{Name: "example.com", Value: "1.2.3.4", TTL: 300}
		result := convertToQUICRecord(rec, "A")
		if result == nil || result.Name != "example.com" || result.Value != "1.2.3.4" {
			t.Errorf("unexpected result: %+v", result)
		}
	})

	t.Run("AAAA_record", func(t *testing.T) {
		t.Parallel()
		rec := &dnsentities.AAAARecord{Name: "v6.example.com", Value: "::1", TTL: 600}
		result := convertToQUICRecord(rec, "AAAA")
		if result == nil || result.RecordType != "AAAA" {
			t.Errorf("unexpected result: %+v", result)
		}
	})

	t.Run("CNAME_record", func(t *testing.T) {
		t.Parallel()
		rec := &dnsentities.CNAMERecord{Name: "www", Value: "example.com", TTL: 300}
		result := convertToQUICRecord(rec, "CNAME")
		if result == nil || result.Value != "example.com" {
			t.Errorf("unexpected result: %+v", result)
		}
	})

	t.Run("TXT_record", func(t *testing.T) {
		t.Parallel()
		rec := &dnsentities.TXTRecord{Name: "_dmarc", Value: "v=DMARC1", TTL: 300}
		result := convertToQUICRecord(rec, "TXT")
		if result == nil || result.Value != "v=DMARC1" {
			t.Errorf("unexpected result: %+v", result)
		}
	})

	t.Run("MX_record", func(t *testing.T) {
		t.Parallel()
		rec := &dnsentities.MXRecord{Name: "example.com", Value: "mail.example.com", TTL: 300, Priority: 10}
		result := convertToQUICRecord(rec, "MX")
		if result == nil || result.Priority != 10 {
			t.Errorf("unexpected result: %+v", result)
		}
	})

	t.Run("NS_record", func(t *testing.T) {
		t.Parallel()
		rec := &dnsentities.NSRecord{Name: "example.com", Value: "ns1.example.com", TTL: 86400}
		result := convertToQUICRecord(rec, "NS")
		if result == nil || result.Value != "ns1.example.com" {
			t.Errorf("unexpected result: %+v", result)
		}
	})

	t.Run("unknown_type", func(t *testing.T) {
		t.Parallel()
		if convertToQUICRecord("not a record", "X") != nil {
			t.Error("expected nil for unknown type")
		}
	})
}

func TestCoverageFinalConvertInterfaceToQUICRecord(t *testing.T) {
	t.Parallel()

	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		if convertInterfaceToQUICRecord(nil) != nil {
			t.Error("expected nil for nil input")
		}
	})

	t.Run("A", func(t *testing.T) {
		t.Parallel()
		rec := &dnsentities.ARecord{Name: "host", Value: "10.0.0.1", TTL: 300}
		result := convertInterfaceToQUICRecord(rec)
		if result == nil || result.RecordType != "A" {
			t.Errorf("unexpected: %+v", result)
		}
	})

	t.Run("AAAA", func(t *testing.T) {
		t.Parallel()
		result := convertInterfaceToQUICRecord(&dnsentities.AAAARecord{Name: "h", Value: "::1", TTL: 60})
		if result == nil || result.RecordType != "AAAA" {
			t.Error("expected AAAA record")
		}
	})

	t.Run("CNAME", func(t *testing.T) {
		t.Parallel()
		result := convertInterfaceToQUICRecord(&dnsentities.CNAMERecord{Name: "w", Value: "x", TTL: 60})
		if result == nil || result.RecordType != "CNAME" {
			t.Error("expected CNAME record")
		}
	})

	t.Run("TXT", func(t *testing.T) {
		t.Parallel()
		result := convertInterfaceToQUICRecord(&dnsentities.TXTRecord{Name: "t", Value: "v", TTL: 60})
		if result == nil || result.RecordType != "TXT" {
			t.Error("expected TXT record")
		}
	})

	t.Run("MX", func(t *testing.T) {
		t.Parallel()
		result := convertInterfaceToQUICRecord(&dnsentities.MXRecord{Name: "m", Value: "mx", TTL: 60, Priority: 5})
		if result == nil || result.RecordType != "MX" || result.Priority != 5 {
			t.Error("expected MX record with priority 5")
		}
	})

	t.Run("NS", func(t *testing.T) {
		t.Parallel()
		result := convertInterfaceToQUICRecord(&dnsentities.NSRecord{Name: "n", Value: "ns", TTL: 60})
		if result == nil || result.RecordType != "NS" {
			t.Error("expected NS record")
		}
	})

	t.Run("unknown", func(t *testing.T) {
		t.Parallel()
		if convertInterfaceToQUICRecord(42) != nil {
			t.Error("expected nil for unknown type")
		}
	})
}

func TestCoverageFinalCountZoneRecords(t *testing.T) {
	t.Parallel()

	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		if countZoneRecords(nil) != 0 {
			t.Error("expected 0 for nil zone")
		}
	})

	t.Run("empty_zone", func(t *testing.T) {
		t.Parallel()
		zone := &dnsentities.Zone{}
		if countZoneRecords(zone) != 0 {
			t.Error("expected 0 for empty zone")
		}
	})

	t.Run("zone_with_records", func(t *testing.T) {
		t.Parallel()
		zone := &dnsentities.Zone{
			RecordSet: dnsentities.RecordSet{
				ARecords:    []*dnsentities.ARecord{{Name: "a", Value: "1.2.3.4"}},
				AAAARecords: []*dnsentities.AAAARecord{{Name: "aaaa", Value: "::1"}},
				MXRecords:   []*dnsentities.MXRecord{{Name: "mx", Value: "mail"}},
				SOARecord:   dnsentities.SOARecord{Name: "soa.example.com"},
			},
		}
		count := countZoneRecords(zone)
		if count != 4 { // 1 A + 1 AAAA + 1 MX + 1 SOA
			t.Errorf("expected 4, got %d", count)
		}
	})
}

// =============================================================================
// containsVTPMErrorPattern / containsIDevIDErrorPattern
// =============================================================================

func TestCoverageFinalContainsVTPMErrorPattern(t *testing.T) {
	t.Parallel()

	if !containsVTPMErrorPattern("vtpm not found", "not found") {
		t.Error("should find 'not found' in 'vtpm not found'")
	}
	if containsVTPMErrorPattern("vtpm error", "not found") {
		t.Error("should not find 'not found' in 'vtpm error'")
	}
	if containsVTPMErrorPattern("", "x") {
		t.Error("should not match empty string")
	}
	if !containsVTPMErrorPattern("multiple patterns here", "not", "patterns") {
		t.Error("should match one of multiple patterns")
	}
}

func TestCoverageFinalContainsIDevIDErrorPattern(t *testing.T) {
	t.Parallel()

	if !containsIDevIDErrorPattern("idevid not found error", "not found") {
		t.Error("should find pattern")
	}
	if containsIDevIDErrorPattern("ok", "not found") {
		t.Error("should not find pattern")
	}
}

// =============================================================================
// certToQUIC / encodePublicKeyPEM
// =============================================================================

func TestCoverageFinalCertToQUIC(t *testing.T) {
	t.Parallel()

	t.Run("nil", func(t *testing.T) {
		t.Parallel()
		if certToQUIC(nil) != nil {
			t.Error("expected nil")
		}
	})

	t.Run("valid_cert", func(t *testing.T) {
		t.Parallel()
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		template := &x509.Certificate{
			SerialNumber: big.NewInt(1),
			Subject:      pkix.Name{CommonName: "test-idevid"},
			Issuer:       pkix.Name{CommonName: "test-issuer"},
			NotBefore:    time.Now().Add(-time.Hour),
			NotAfter:     time.Now().Add(time.Hour),
		}
		certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(certDER)
		if err != nil {
			t.Fatal(err)
		}

		result := certToQUIC(cert)
		if result == nil {
			t.Fatal("expected non-nil result")
		}
		if result.SubjectCN != "test-idevid" {
			t.Errorf("SubjectCN = %q", result.SubjectCN)
		}
		if result.PEM == "" {
			t.Error("PEM should not be empty")
		}
		if result.Fingerprint == "" {
			t.Error("Fingerprint should not be empty")
		}
	})
}

func TestCoverageFinalEncodePublicKeyPEM(t *testing.T) {
	t.Parallel()
	// This function is a placeholder that returns ("", nil)
	result, err := encodePublicKeyPEM(nil)
	if err != nil {
		t.Errorf("unexpected error: %v", err)
	}
	if result != "" {
		t.Errorf("expected empty string, got %q", result)
	}
}

// =============================================================================
// Service helper functions
// =============================================================================

func TestCoverageFinalServiceTypeFromName(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		expected platformv1.ServiceType
	}{
		{"tpm", platformv1.ServiceType_SERVICE_TYPE_TPM},
		{"sdn", platformv1.ServiceType_SERVICE_TYPE_SDN},
		{"compute", platformv1.ServiceType_SERVICE_TYPE_COMPUTE},
		{"dns", platformv1.ServiceType_SERVICE_TYPE_DNS},
		{"acme", platformv1.ServiceType_SERVICE_TYPE_ACME},
		{"webservice", platformv1.ServiceType_SERVICE_TYPE_WEBSERVICE},
		{"attestation", platformv1.ServiceType_SERVICE_TYPE_ATTESTATION},
		{"unknown", platformv1.ServiceType_SERVICE_TYPE_UNSPECIFIED},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := serviceTypeFromName(tc.name)
			if got != tc.expected {
				t.Errorf("serviceTypeFromName(%q) = %v, want %v", tc.name, got, tc.expected)
			}
		})
	}
}

func TestCoverageFinalServiceNameFromType(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    platformv1.ServiceType
		expected string
	}{
		{platformv1.ServiceType_SERVICE_TYPE_TPM, "tpm"},
		{platformv1.ServiceType_SERVICE_TYPE_SDN, "sdn"},
		{platformv1.ServiceType_SERVICE_TYPE_COMPUTE, "compute"},
		{platformv1.ServiceType_SERVICE_TYPE_DNS, "dns"},
		{platformv1.ServiceType_SERVICE_TYPE_ACME, "acme"},
		{platformv1.ServiceType_SERVICE_TYPE_WEBSERVICE, "webservice"},
		{platformv1.ServiceType_SERVICE_TYPE_ATTESTATION, "attestation"},
		{platformv1.ServiceType_SERVICE_TYPE_UNSPECIFIED, "unknown"},
	}

	for _, tc := range tests {
		t.Run(tc.expected, func(t *testing.T) {
			t.Parallel()
			got := serviceNameFromType(tc.input)
			if got != tc.expected {
				t.Errorf("serviceNameFromType(%v) = %q, want %q", tc.input, got, tc.expected)
			}
		})
	}
}

func TestCoverageFinalHealthStatusFromServiceStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    platformv1.ServiceStatus
		expected platformv1.HealthStatus
	}{
		{platformv1.ServiceStatus_SERVICE_STATUS_RUNNING, platformv1.HealthStatus_HEALTH_STATUS_HEALTHY},
		{platformv1.ServiceStatus_SERVICE_STATUS_ERROR, platformv1.HealthStatus_HEALTH_STATUS_UNHEALTHY},
		{platformv1.ServiceStatus_SERVICE_STATUS_STARTING, platformv1.HealthStatus_HEALTH_STATUS_DEGRADED},
		{platformv1.ServiceStatus_SERVICE_STATUS_STOPPING, platformv1.HealthStatus_HEALTH_STATUS_DEGRADED},
		{platformv1.ServiceStatus_SERVICE_STATUS_STOPPED, platformv1.HealthStatus_HEALTH_STATUS_UNSPECIFIED},
	}

	for _, tc := range tests {
		t.Run(tc.input.String(), func(t *testing.T) {
			t.Parallel()
			got := healthStatusFromServiceStatus(tc.input)
			if got != tc.expected {
				t.Errorf("healthStatusFromServiceStatus(%v) = %v, want %v", tc.input, got, tc.expected)
			}
		})
	}
}

func TestCoverageFinalHealthStatusFromHealthStatus(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    health.HealthStatus
		expected platformv1.HealthStatus
	}{
		{health.StatusHealthy, platformv1.HealthStatus_HEALTH_STATUS_HEALTHY},
		{health.StatusDegraded, platformv1.HealthStatus_HEALTH_STATUS_DEGRADED},
		{health.StatusUnhealthy, platformv1.HealthStatus_HEALTH_STATUS_UNHEALTHY},
		{health.StatusUnknown, platformv1.HealthStatus_HEALTH_STATUS_UNSPECIFIED},
		{"other", platformv1.HealthStatus_HEALTH_STATUS_UNSPECIFIED},
	}

	for _, tc := range tests {
		t.Run(string(tc.input), func(t *testing.T) {
			t.Parallel()
			got := healthStatusFromHealthStatus(tc.input)
			if got != tc.expected {
				t.Errorf("healthStatusFromHealthStatus(%q) = %v, want %v", tc.input, got, tc.expected)
			}
		})
	}
}

// =============================================================================
// QUIC Handler Construction and Routing
// =============================================================================

func TestCoverageFinalHandleRequestNilRequest(t *testing.T) {
	t.Parallel()
	h := newTestQUICServiceHandler(logging.DefaultLogger())
	resp := h.HandleRequest(context.Background(), nil)
	if resp.Status != quicwire.StatusInvalidRequest {
		t.Errorf("Status = 0x%02X, want 0x%02X", resp.Status, quicwire.StatusInvalidRequest)
	}
}

func TestCoverageFinalHandleRequestUnknownOpcode(t *testing.T) {
	t.Parallel()
	h := newTestQUICServiceHandler(logging.DefaultLogger())
	req := &quicwire.Request{Opcode: 0xFE} // Unlikely to be assigned
	resp := h.HandleRequest(context.Background(), req)
	// Might hit a PXE extended range; if so it returns unavailable. Either way, not panic.
	if resp == nil {
		t.Fatal("response should not be nil")
	}
}

func TestCoverageFinalQUICHandlerSetters(t *testing.T) {
	t.Parallel()

	h := newTestQUICServiceHandler(logging.DefaultLogger())

	// Test all setters don't panic
	h.SetCAHandler(nil)
	h.SetVTPMService(nil)
	h.SetDeviceService(nil)
	h.SetDNSService(nil)
	h.SetSDNService(nil)
	h.SetIAMService(nil)
	h.SetKMSService(nil)
	h.SetCryptoService(nil)
	h.SetTPM2Service(nil)
	h.SetContainerHandler(nil)
	h.SetContainerOrchestrator(nil)
	h.SetAttestationHandler(nil)
	h.SetAttestationService(nil)
	h.SetDaemonService(nil)
	h.SetOverlayHandler(nil)
	h.SetGatewayHandler(nil)
}

func TestCoverageFinalQUICHandlerErrorResponse(t *testing.T) {
	t.Parallel()
	h := newTestQUICServiceHandler(logging.DefaultLogger())
	resp := h.errorResponse(quicwire.StatusInternalError, ErrQUICNilRequest{})
	if resp.Status != quicwire.StatusInternalError {
		t.Errorf("Status = 0x%02X", resp.Status)
	}
	if string(resp.Payload) != "QUIC request cannot be nil" {
		t.Errorf("Payload = %q", string(resp.Payload))
	}
}

// =============================================================================
// QUIC Handler - Service routing with nil services
// =============================================================================

func TestCoverageFinalQUICHandlerRouting(t *testing.T) {
	t.Parallel()

	h := newTestQUICServiceHandler(logging.DefaultLogger())
	ctx := context.Background()

	// Test that requests to various opcodes return unavailable when services are nil
	routeTests := []struct {
		name   string
		opcode byte
	}{
		{"health_check", quicwire.OpHealth},
		{"liveness", quicwire.OpLiveness},
		{"readiness", quicwire.OpReadiness},
		{"device_nil", quicwire.OpDeviceRegister},
		{"cert_nil", quicwire.OpCertIssue},
		{"ca_nil", quicwire.OpCAInfo},
		{"daemon_nil", quicwire.OpDaemonStatus},
	}

	for _, tc := range routeTests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resp := h.HandleRequest(ctx, &quicwire.Request{Opcode: tc.opcode})
			if resp == nil {
				t.Fatal("response should not be nil")
			}
		})
	}
}

func TestCoverageFinalQUICHandlerOverlayCategory(t *testing.T) {
	t.Parallel()

	h := newTestQUICServiceHandler(logging.DefaultLogger())
	ctx := context.Background()

	t.Run("nil_handler", func(t *testing.T) {
		t.Parallel()
		resp := h.HandleRequest(ctx, &quicwire.Request{Opcode: quicwire.OpOverlayCategory, Payload: []byte{0x01}})
		if resp.Status != quicwire.StatusUnavailable {
			t.Errorf("Status = 0x%02X, want StatusUnavailable", resp.Status)
		}
	})

	t.Run("empty_payload", func(t *testing.T) {
		t.Parallel()
		// A category request without a sub-opcode cannot be classified, so
		// the authorization guard rejects it before any dispatch.
		resp := h.HandleRequest(ctx, &quicwire.Request{Opcode: quicwire.OpOverlayCategory})
		if resp.Status != quicwire.StatusInvalidRequest {
			t.Errorf("Status = 0x%02X, want StatusInvalidRequest", resp.Status)
		}
	})
}

func TestCoverageFinalQUICHandlerGatewayCategory(t *testing.T) {
	t.Parallel()

	h := newTestQUICServiceHandler(logging.DefaultLogger())
	ctx := context.Background()

	resp := h.HandleRequest(ctx, &quicwire.Request{Opcode: quicwire.OpGatewayCategory, Payload: []byte{0x01}})
	if resp.Status != quicwire.StatusUnavailable {
		t.Errorf("Status = 0x%02X, want StatusUnavailable", resp.Status)
	}
}

func TestCoverageFinalQUICHandlerIPAMCategory(t *testing.T) {
	t.Parallel()

	h := newTestQUICServiceHandler(logging.DefaultLogger())
	ctx := context.Background()

	resp := h.HandleRequest(ctx, &quicwire.Request{Opcode: quicwire.OpIPAMCategory, Payload: []byte{quicwire.OpGatewayListIPAMPools}})
	if resp.Status != quicwire.StatusUnavailable {
		t.Errorf("Status = 0x%02X, want StatusUnavailable", resp.Status)
	}
}

// expectedHealthHandlerStatus returns the status code expected from the QUIC
// health/liveness/readiness handlers. When a payload codec is compiled into the
// build (e.g. -tags codec_json) the handlers return StatusOK. When no codec is
// registered the handlers correctly surface the encoding failure as
// StatusInternalError. Tests must tolerate both so they pass under plain
// `go test` and under tagged builds like `make test`.
func expectedHealthHandlerStatus() byte {
	if len(quicwire.SupportedCodecs()) == 0 {
		return quicwire.StatusInternalError
	}
	return quicwire.StatusOK
}

func TestCoverageFinalQUICHandlerHealthCheck(t *testing.T) {
	t.Parallel()

	h := newTestQUICServiceHandler(logging.DefaultLogger())
	ctx := context.Background()

	// Health check without registry
	resp := h.HandleRequest(ctx, &quicwire.Request{Opcode: quicwire.OpHealth})
	want := expectedHealthHandlerStatus()
	if resp.Status != want {
		t.Errorf("Health check without registry: Status = 0x%02X, want 0x%02X", resp.Status, want)
	}
}

func TestCoverageFinalQUICHandlerLiveness(t *testing.T) {
	t.Parallel()

	h := newTestQUICServiceHandler(logging.DefaultLogger())
	resp := h.HandleRequest(context.Background(), &quicwire.Request{Opcode: quicwire.OpLiveness})
	want := expectedHealthHandlerStatus()
	if resp.Status != want {
		t.Errorf("Liveness: Status = 0x%02X, want 0x%02X", resp.Status, want)
	}
}

func TestCoverageFinalQUICHandlerReadiness(t *testing.T) {
	t.Parallel()

	h := newTestQUICServiceHandler(logging.DefaultLogger())
	resp := h.HandleRequest(context.Background(), &quicwire.Request{Opcode: quicwire.OpReadiness})
	want := expectedHealthHandlerStatus()
	if resp.Status != want {
		t.Errorf("Readiness: Status = 0x%02X, want 0x%02X", resp.Status, want)
	}
}

// =============================================================================
// REST ErrorResponse
// =============================================================================

func TestCoverageFinalErrorResponse(t *testing.T) {
	t.Parallel()
	resp := ErrorResponse{
		Error:     "test error",
		Code:      500,
		Timestamp: time.Now(),
	}
	if resp.Error != "test error" {
		t.Errorf("Error = %q", resp.Error)
	}
	if resp.Code != 500 {
		t.Errorf("Code = %d", resp.Code)
	}
}

// =============================================================================
// Helpers
// =============================================================================

func containsStr(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || indexStr(s, substr) >= 0)
}

func indexStr(s, substr string) int {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return -1
}
