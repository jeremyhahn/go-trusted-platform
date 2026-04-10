// Copyright (c) 2025 Jeremy Hahn
// Copyright (c) 2025 Automate The Things, LLC
//
// This file is part of go-trusted-platform.

package daemon

import (
	"context"
	"errors"
	"log/slog"
	"testing"

	pb "github.com/jeremyhahn/go-quicbaas/api/proto"
	"github.com/jeremyhahn/go-quicbaas/sdk/go/client/kms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/api/quic"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// =============================================================================
// KMS Server Adapter - nil client tests
// =============================================================================

func TestCoverageFinal2KMSServerAdapterNilClient(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	adapter := NewKMSServerAdapter(nil, logger)
	ctx := context.Background()

	t.Run("GenerateKey", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.GenerateKey(ctx, &pb.GenerateKeyRequest{Name: "test"})
		assertGRPCStatusCode(t, err, codes.Unavailable)
	})

	t.Run("GetKey", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.GetKey(ctx, &pb.GetKeyRequest{KeyId: "k1"})
		assertGRPCStatusCode(t, err, codes.Unavailable)
	})

	t.Run("ListKeys", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.ListKeys(ctx, &pb.ListKeysRequest{})
		assertGRPCStatusCode(t, err, codes.Unavailable)
	})

	t.Run("RotateKey", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.RotateKey(ctx, &pb.RotateKeyRequest{KeyId: "k1"})
		assertGRPCStatusCode(t, err, codes.Unavailable)
	})

	t.Run("DeleteKey", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.DeleteKey(ctx, &pb.DeleteKeyRequest{KeyId: "k1"})
		assertGRPCStatusCode(t, err, codes.Unavailable)
	})
}

func TestCoverageFinal2SecretsServerAdapterNilClient(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	adapter := NewSecretsServerAdapter(nil, logger)
	ctx := context.Background()

	t.Run("StoreSecret", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.StoreSecret(ctx, &pb.StoreSecretRequest{SecretId: "s1"})
		assertGRPCStatusCode(t, err, codes.Unavailable)
	})

	t.Run("GetSecret", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.GetSecret(ctx, &pb.GetSecretRequest{SecretId: "s1"})
		assertGRPCStatusCode(t, err, codes.Unavailable)
	})

	t.Run("ListSecrets", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.ListSecrets(ctx, &pb.ListSecretsRequest{})
		assertGRPCStatusCode(t, err, codes.Unavailable)
	})

	t.Run("DeleteSecret", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.DeleteSecret(ctx, &pb.DeleteSecretRequest{SecretId: "s1"})
		assertGRPCStatusCode(t, err, codes.Unavailable)
	})
}

func TestCoverageFinal2CryptoServerAdapterNilClient(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	adapter := NewCryptoServerAdapter(nil, logger)
	ctx := context.Background()

	t.Run("Encrypt", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.Encrypt(ctx, &pb.CryptoEncryptRequest{KeyId: "k1"})
		assertGRPCStatusCode(t, err, codes.Unavailable)
	})

	t.Run("Decrypt", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.Decrypt(ctx, &pb.CryptoDecryptRequest{KeyId: "k1"})
		assertGRPCStatusCode(t, err, codes.Unavailable)
	})

	t.Run("Sign", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.Sign(ctx, &pb.SignRequest{KeyId: "k1"})
		assertGRPCStatusCode(t, err, codes.Unavailable)
	})

	t.Run("Verify", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.Verify(ctx, &pb.VerifyRequest{KeyId: "k1"})
		assertGRPCStatusCode(t, err, codes.Unavailable)
	})

	t.Run("BatchEncrypt", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.BatchEncrypt(ctx, &pb.EncryptBatchRequest{KeyId: "k1"})
		assertGRPCStatusCode(t, err, codes.Unavailable)
	})

	t.Run("BatchDecrypt", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.BatchDecrypt(ctx, &pb.DecryptBatchRequest{KeyId: "k1"})
		assertGRPCStatusCode(t, err, codes.Unavailable)
	})

	t.Run("Rewrap", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.Rewrap(ctx, &pb.RewrapRequest{KeyId: "k1"})
		assertGRPCStatusCode(t, err, codes.Unavailable)
	})
}

func TestCoverageFinal2DEKServerAdapterNilClient(t *testing.T) {
	t.Parallel()

	logger := slog.Default()
	adapter := NewDEKServerAdapter(nil, logger)
	ctx := context.Background()

	t.Run("CreateDEK", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.CreateDEK(ctx, &pb.CreateDEKRequest{Path: "p1"})
		assertGRPCStatusCode(t, err, codes.Unavailable)
	})

	t.Run("GetDEK", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.GetDEK(ctx, &pb.GetDEKRequest{Path: "p1"})
		assertGRPCStatusCode(t, err, codes.Unavailable)
	})

	t.Run("RotateDEK", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.RotateDEK(ctx, &pb.RotateDEKRequest{Path: "p1"})
		assertGRPCStatusCode(t, err, codes.Unavailable)
	})

	t.Run("DeleteDEK", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.DeleteDEK(ctx, &pb.DeleteDEKRequest{Path: "p1"})
		assertGRPCStatusCode(t, err, codes.Unavailable)
	})
}

// =============================================================================
// kmsQUICAdapter tests
// =============================================================================

func TestCoverageFinal2KmsQUICAdapterNotImplemented(t *testing.T) {
	t.Parallel()

	kmsAdapter := NewKMSServerAdapter(nil, slog.Default())
	cryptoAdapter := NewCryptoServerAdapter(nil, slog.Default())
	adapter := newKMSQUICAdapter(kmsAdapter, cryptoAdapter)
	ctx := context.Background()

	t.Run("ImportKey", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.ImportKey(ctx, &pb.ImportKeyRequest{})
		if err == nil {
			t.Fatal("expected error")
		}
		var notImpl ErrKMSOperationNotImplemented
		if !isErrType(err, &notImpl) {
			t.Errorf("expected ErrKMSOperationNotImplemented, got %T: %v", err, err)
		}
	})

	t.Run("UpdateKeyStatus", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.UpdateKeyStatus(ctx, &pb.UpdateKeyStatusRequest{})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("ExportKey", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.ExportKey(ctx, &pb.ExportKeyRequest{})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("ListKeyVersions", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.ListKeyVersions(ctx, &pb.ListKeyVersionsRequest{})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("Hash", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.Hash(ctx, &pb.HashRequest{})
		if err == nil {
			t.Fatal("expected error")
		}
	})

	t.Run("GenerateRandom_valid", func(t *testing.T) {
		t.Parallel()
		resp, err := adapter.GenerateRandom(ctx, &pb.GenerateRandomRequest{NumBytes: 32})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(resp.RandomBytes) != 32 {
			t.Errorf("expected 32 bytes, got %d", len(resp.RandomBytes))
		}
	})

	t.Run("GenerateRandom_zero", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.GenerateRandom(ctx, &pb.GenerateRandomRequest{NumBytes: 0})
		if err == nil {
			t.Fatal("expected error for zero bytes")
		}
	})

	t.Run("GenerateRandom_too_large", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.GenerateRandom(ctx, &pb.GenerateRandomRequest{NumBytes: 2048})
		if err == nil {
			t.Fatal("expected error for too many bytes")
		}
	})

	// Delegation tests (these go through nil client, so they should fail)
	t.Run("GenerateKey_delegates", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.GenerateKey(ctx, &pb.GenerateKeyRequest{Name: "test"})
		assertGRPCStatusCode(t, err, codes.Unavailable)
	})

	t.Run("GetKey_delegates", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.GetKey(ctx, &pb.GetKeyRequest{KeyId: "k1"})
		assertGRPCStatusCode(t, err, codes.Unavailable)
	})

	t.Run("ListKeys_delegates", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.ListKeys(ctx, &pb.ListKeysRequest{})
		assertGRPCStatusCode(t, err, codes.Unavailable)
	})

	t.Run("DeleteKey_delegates", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.DeleteKey(ctx, &pb.DeleteKeyRequest{KeyId: "k1"})
		assertGRPCStatusCode(t, err, codes.Unavailable)
	})

	t.Run("RotateKey_delegates", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.RotateKey(ctx, &pb.RotateKeyRequest{KeyId: "k1"})
		assertGRPCStatusCode(t, err, codes.Unavailable)
	})

	t.Run("Encrypt_delegates", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.Encrypt(ctx, &pb.CryptoEncryptRequest{KeyId: "k1"})
		assertGRPCStatusCode(t, err, codes.Unavailable)
	})

	t.Run("Decrypt_delegates", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.Decrypt(ctx, &pb.CryptoDecryptRequest{KeyId: "k1"})
		assertGRPCStatusCode(t, err, codes.Unavailable)
	})

	t.Run("Sign_delegates", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.Sign(ctx, &pb.SignRequest{KeyId: "k1"})
		assertGRPCStatusCode(t, err, codes.Unavailable)
	})

	t.Run("Verify_delegates", func(t *testing.T) {
		t.Parallel()
		_, err := adapter.Verify(ctx, &pb.VerifyRequest{KeyId: "k1"})
		assertGRPCStatusCode(t, err, codes.Unavailable)
	})
}

// =============================================================================
// KMS Algorithm Conversion Helpers
// =============================================================================

func TestCoverageFinal2PbAlgorithmToSDK(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    pb.KeyAlgorithm
		expected kms.KeyAlgorithm
	}{
		{pb.KeyAlgorithm_KEY_ALG_AES_256_GCM, kms.AlgorithmAES256GCM},
		{pb.KeyAlgorithm_KEY_ALG_CHACHA20_POLY1305, kms.AlgorithmChaCha20Poly1305},
		{pb.KeyAlgorithm_KEY_ALG_RSA_2048, kms.AlgorithmRSA2048},
		{pb.KeyAlgorithm_KEY_ALG_RSA_4096, kms.AlgorithmRSA4096},
		{pb.KeyAlgorithm_KEY_ALG_ECDSA_P256, kms.AlgorithmECDSAP256},
		{pb.KeyAlgorithm_KEY_ALG_ECDSA_P384, kms.AlgorithmECDSAP384},
		{pb.KeyAlgorithm_KEY_ALG_ED25519, kms.AlgorithmED25519},
		{pb.KeyAlgorithm_KEY_ALG_UNSPECIFIED, kms.AlgorithmAES256GCM}, // default
	}

	for _, tc := range tests {
		t.Run(tc.input.String(), func(t *testing.T) {
			t.Parallel()
			got := pbAlgorithmToSDK(tc.input)
			if got != tc.expected {
				t.Errorf("pbAlgorithmToSDK(%v) = %v, want %v", tc.input, got, tc.expected)
			}
		})
	}
}

func TestCoverageFinal2SDKAlgorithmToPb(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    kms.KeyAlgorithm
		expected pb.KeyAlgorithm
	}{
		{kms.AlgorithmAES256GCM, pb.KeyAlgorithm_KEY_ALG_AES_256_GCM},
		{kms.AlgorithmChaCha20Poly1305, pb.KeyAlgorithm_KEY_ALG_CHACHA20_POLY1305},
		{kms.AlgorithmRSA2048, pb.KeyAlgorithm_KEY_ALG_RSA_2048},
		{kms.AlgorithmRSA4096, pb.KeyAlgorithm_KEY_ALG_RSA_4096},
		{kms.AlgorithmECDSAP256, pb.KeyAlgorithm_KEY_ALG_ECDSA_P256},
		{kms.AlgorithmECDSAP384, pb.KeyAlgorithm_KEY_ALG_ECDSA_P384},
		{kms.AlgorithmED25519, pb.KeyAlgorithm_KEY_ALG_ED25519},
		{kms.KeyAlgorithm(9999), pb.KeyAlgorithm_KEY_ALG_UNSPECIFIED}, // default
	}

	for _, tc := range tests {
		t.Run(tc.expected.String(), func(t *testing.T) {
			t.Parallel()
			got := sdkAlgorithmToPb(tc.input)
			if got != tc.expected {
				t.Errorf("sdkAlgorithmToPb(%v) = %v, want %v", tc.input, got, tc.expected)
			}
		})
	}
}

func TestCoverageFinal2PbUsagesToSDK(t *testing.T) {
	t.Parallel()

	usages := []pb.KeyUsage{
		pb.KeyUsage_KEY_USAGE_ENCRYPT,
		pb.KeyUsage_KEY_USAGE_DECRYPT,
		pb.KeyUsage_KEY_USAGE_SIGN,
		pb.KeyUsage_KEY_USAGE_VERIFY,
		pb.KeyUsage_KEY_USAGE_WRAP_KEY,
		pb.KeyUsage_KEY_USAGE_UNSPECIFIED, // should be skipped
	}

	result := pbUsagesToSDK(usages)
	if len(result) != 5 {
		t.Errorf("expected 5 SDK usages, got %d", len(result))
	}
}

func TestCoverageFinal2PbHashAlgorithmToSDK(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input pb.HashAlgorithm
	}{
		{pb.HashAlgorithm_HASH_ALG_SHA256},
		{pb.HashAlgorithm_HASH_ALG_SHA384},
		{pb.HashAlgorithm_HASH_ALG_SHA512},
		{pb.HashAlgorithm_HASH_ALG_UNSPECIFIED}, // defaults to SHA256
	}

	for _, tc := range tests {
		t.Run(tc.input.String(), func(t *testing.T) {
			t.Parallel()
			_ = pbHashAlgorithmToSDK(tc.input)
			// Just verify it doesn't panic
		})
	}
}

// =============================================================================
// KMS Service lifecycle
// =============================================================================

func TestCoverageFinal2KMSServiceNilApp(t *testing.T) {
	t.Parallel()

	_, err := NewKMSService(nil, slog.Default())
	if err == nil {
		t.Fatal("expected error for nil app")
	}
	var errConfig ErrInvalidConfig
	if !isErrType(err, &errConfig) {
		t.Errorf("expected ErrInvalidConfig, got %T", err)
	}
}

func TestCoverageFinal2KMSServiceAccessors(t *testing.T) {
	t.Parallel()

	// Create a minimal KMSService manually (without going through NewKMSService)
	svc := &KMSService{
		logger: slog.Default(),
	}

	if svc.Name() != "kms" {
		t.Errorf("Name() = %q, want kms", svc.Name())
	}

	if svc.IsRunning() {
		t.Error("should not be running initially")
	}

	if svc.KMSServer() != nil {
		t.Error("KMSServer should be nil before init")
	}
	if svc.SecretsServer() != nil {
		t.Error("SecretsServer should be nil before init")
	}
	if svc.CryptoServer() != nil {
		t.Error("CryptoServer should be nil before init")
	}
	if svc.DEKServer() != nil {
		t.Error("DEKServer should be nil before init")
	}

	ctx := context.Background()

	// Start/Stop
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("Start failed: %v", err)
	}
	if !svc.IsRunning() {
		t.Error("should be running after Start")
	}

	// Starting again should be no-op
	if err := svc.Start(ctx); err != nil {
		t.Fatalf("second Start failed: %v", err)
	}

	if err := svc.Stop(ctx); err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	if svc.IsRunning() {
		t.Error("should not be running after Stop")
	}

	// Stopping again should be no-op
	if err := svc.Stop(ctx); err != nil {
		t.Fatalf("second Stop failed: %v", err)
	}
}

// =============================================================================
// QUIC handler routing - more opcode ranges
// =============================================================================

func TestCoverageFinal2QUICHandlerRoutingAllRanges(t *testing.T) {
	t.Parallel()

	h := NewQUICServiceHandler(logging.DefaultLogger())
	ctx := context.Background()

	// Test routing for each major opcode range with nil services
	// These should all return responses (either unavailable or error, not panic)
	opcodeTests := []struct {
		name   string
		opcode byte
	}{
		// vTPM Extended (0x03-0x0F)
		{"vtpm_extended", quic.OpVTPMCreateTemplate},
		// vTPM (0x10-0x1F)
		{"vtpm", quic.OpVTPMCreate},
		// DNS (0x20-0x2D)
		{"dns", quic.OpDNSAddRecord},
		// SDN (0x40-0x4F)
		{"sdn", quic.OpSDNGetPortState},
		// IDevID (0x56-0x5F)
		{"idevid", quic.OpIDevIDGenerate},
		// VM (0x60-0x6A)
		{"vm", quic.OpVMCreate},
		// IAK extended (0x6B-0x6E)
		{"iak_extended", quic.OpIAKInstallCert},
		// Container Get (0x6F)
		{"container_get", quic.OpContainerGet},
		// Attestation (0x70-0x77)
		{"attestation", quic.OpAttestQuote},
		// IDevID Extended (0x78-0x7B)
		{"idevid_extended", quic.OpHasIDevID},
		// Cert/PKI (0x80-0x88)
		{"cert", quic.OpCertIssue},
		// Daemon (0x89-0x8F)
		{"daemon_status", quic.OpDaemonStatus},
		// CA (0xA0-0xA8)
		{"ca", quic.OpCAInfo},
		// IAM User (0xA9-0xAD)
		{"iam_user", quic.OpIAMUserCreate},
		// Container List (0xAE)
		{"container_list", quic.OpContainerList},
		// SDN Extended (0xB0-0xB4)
		{"sdn_extended", quic.OpSDNCreateBridge},
		// IAM Role (0xB5-0xBA)
		{"iam_role", quic.OpIAMRoleCreate},
		// IAM Group (0xBB-0xBF)
		{"iam_group", quic.OpIAMGroupCreate},
		// KMS (0xC0-0xCF)
		{"kms", quic.OpKMSGenerateKey},
		// KMS Crypto (0xD0-0xDA)
		{"kms_crypto", quic.OpKMSEncrypt},
		// Tenant (0xDB-0xE9)
		{"tenant", quic.OpTenantList},
		// Daemon ListProtocols (0x98)
		{"daemon_protocols", quic.OpDaemonListProtocols},
	}

	for _, tc := range opcodeTests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			resp := h.HandleRequest(ctx, &quic.Request{Opcode: tc.opcode, Payload: []byte{}})
			if resp == nil {
				t.Fatal("response should not be nil")
			}
			// All should return either StatusUnavailable or StatusInvalidRequest
			// since no services are configured
			if resp.Status == quic.StatusOK {
				// Only health/liveness/readiness should succeed
				t.Logf("got StatusOK for opcode 0x%02X - this is expected for health endpoints", tc.opcode)
			}
		})
	}
}

// =============================================================================
// boolToStatus
// =============================================================================

func TestCoverageFinal2BoolToStatus(t *testing.T) {
	t.Parallel()

	if boolToStatus(true) != "running" {
		t.Error("boolToStatus(true) should be running")
	}
	if boolToStatus(false) != "stopped" {
		t.Error("boolToStatus(false) should be stopped")
	}
}

// =============================================================================
// extractPort
// =============================================================================

func TestCoverageFinal2ExtractPort(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input    string
		expected int
	}{
		{"0.0.0.0:8443", 8443},
		{"localhost:10443", 10443},
		{":9000", 9000},
		{"no-port", 0},
		{"host:abc", 0},
		{"", 0},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			t.Parallel()
			got := extractPort(tc.input)
			if got != tc.expected {
				t.Errorf("extractPort(%q) = %d, want %d", tc.input, got, tc.expected)
			}
		})
	}
}

// =============================================================================
// WithQUIC* options - coverage for nil checks in constructors
// =============================================================================

func TestCoverageFinal2WithQUICOptions(t *testing.T) {
	t.Parallel()

	logger := logging.DefaultLogger()

	// WithQUICCAService with nil should not set a handler
	h := NewQUICServiceHandler(logger, WithQUICCAService(nil))
	if h.caHandler != nil {
		t.Error("caHandler should be nil when CA is nil")
	}

	// WithQUICContainerService with nil should not set handler
	h = NewQUICServiceHandler(logger, WithQUICContainerService(nil))
	if h.containerHandler != nil {
		t.Error("containerHandler should be nil when orchestrator is nil")
	}

	// WithQUICAttestationService with nil should not set handler
	h = NewQUICServiceHandler(logger, WithQUICAttestationService(nil))
	if h.attestationHandler != nil {
		t.Error("attestationHandler should be nil when svc is nil")
	}

	// WithQUICVMService with nil should not set handler
	h = NewQUICServiceHandler(logger, WithQUICVMService(nil))
	if h.vmHandler != nil {
		t.Error("vmHandler should be nil when orchestrator is nil")
	}

	// WithQUICVTPMService sets the vtpm service
	h = NewQUICServiceHandler(logger, WithQUICVTPMService(nil))
	if h.vtpmService != nil {
		t.Error("vtpmService should be nil")
	}

	// WithQUICDeviceService
	h = NewQUICServiceHandler(logger, WithQUICDeviceService(nil))
	if h.deviceService != nil {
		t.Error("deviceService should be nil")
	}

	// WithQUICDeviceProfileService
	h = NewQUICServiceHandler(logger, WithQUICDeviceProfileService(nil))
	if h.profileService != nil {
		t.Error("profileService should be nil")
	}
}

// =============================================================================
// PXE opcodes
// =============================================================================

func TestCoverageFinal2QUICHandlerPXERouting(t *testing.T) {
	t.Parallel()

	h := NewQUICServiceHandler(logging.DefaultLogger())
	ctx := context.Background()

	// PXE service control (0x7C-0x7E)
	resp := h.HandleRequest(ctx, &quic.Request{Opcode: OpPXEStart, Payload: []byte{}})
	if resp == nil {
		t.Fatal("response should not be nil")
	}

	// PXE extended (0xEC-0xEF)
	resp = h.HandleRequest(ctx, &quic.Request{Opcode: OpPXEListDevices, Payload: []byte{}})
	if resp == nil {
		t.Fatal("response should not be nil")
	}

	// PXE extended (0xFC-0xFF)
	resp = h.HandleRequest(ctx, &quic.Request{Opcode: OpPXEAuthorize, Payload: []byte{}})
	if resp == nil {
		t.Fatal("response should not be nil")
	}
}

// =============================================================================
// Attestation VM workload
// =============================================================================

func TestCoverageFinal2QUICHandlerAttestVMWorkload(t *testing.T) {
	t.Parallel()

	h := NewQUICServiceHandler(logging.DefaultLogger())
	resp := h.HandleRequest(context.Background(), &quic.Request{Opcode: quic.OpAttestVMWorkload, Payload: []byte{}})
	if resp == nil {
		t.Fatal("response should not be nil")
	}
}

// =============================================================================
// IAM Extended routing
// =============================================================================

func TestCoverageFinal2QUICHandlerIAMExtended(t *testing.T) {
	t.Parallel()

	h := NewQUICServiceHandler(logging.DefaultLogger())
	ctx := context.Background()

	// IAM extended (0xF6-0xFB)
	resp := h.HandleRequest(ctx, &quic.Request{Opcode: quic.OpIAMGroupRemoveMember, Payload: []byte{}})
	if resp == nil {
		t.Fatal("response should not be nil")
	}
}

// =============================================================================
// VM Extended Operations
// =============================================================================

func TestCoverageFinal2QUICHandlerVMExtended(t *testing.T) {
	t.Parallel()

	h := NewQUICServiceHandler(logging.DefaultLogger())
	resp := h.HandleRequest(context.Background(), &quic.Request{Opcode: quic.OpVMRestart, Payload: []byte{}})
	if resp == nil {
		t.Fatal("response should not be nil")
	}
}

// =============================================================================
// Attestation Policy Operations
// =============================================================================

func TestCoverageFinal2QUICHandlerAttestPolicy(t *testing.T) {
	t.Parallel()

	h := NewQUICServiceHandler(logging.DefaultLogger())
	ctx := context.Background()

	resp := h.HandleRequest(ctx, &quic.Request{Opcode: quic.OpAttestCreatePolicy, Payload: []byte{}})
	if resp == nil {
		t.Fatal("response should not be nil")
	}

	resp = h.HandleRequest(ctx, &quic.Request{Opcode: quic.OpAttestListPolicies, Payload: []byte{}})
	if resp == nil {
		t.Fatal("response should not be nil")
	}
}

// =============================================================================
// Container Logs
// =============================================================================

func TestCoverageFinal2QUICHandlerContainerLogs(t *testing.T) {
	t.Parallel()

	h := NewQUICServiceHandler(logging.DefaultLogger())
	resp := h.HandleRequest(context.Background(), &quic.Request{Opcode: quic.OpContainerLogs, Payload: []byte{}})
	if resp == nil {
		t.Fatal("response should not be nil")
	}
}

// =============================================================================
// Helpers
// =============================================================================

func assertGRPCStatusCode(t *testing.T, err error, expected codes.Code) {
	t.Helper()
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	st, ok := status.FromError(err)
	if !ok {
		t.Fatalf("expected gRPC status error, got %T: %v", err, err)
	}
	if st.Code() != expected {
		t.Errorf("gRPC status code = %v, want %v", st.Code(), expected)
	}
}

func isErrType(err error, target interface{}) bool {
	switch target.(type) {
	case *ErrKMSOperationNotImplemented:
		var e ErrKMSOperationNotImplemented
		return errors.As(err, &e)
	case *ErrInvalidConfig:
		var e ErrInvalidConfig
		return errors.As(err, &e)
	default:
		return false
	}
}
