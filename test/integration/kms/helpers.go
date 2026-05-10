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

// Package kms provides integration test helpers for KMS services.
// These helpers provide reusable functions for creating test keys,
// generating test data, and performing assertions in integration tests.

//go:build integration

package kms

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-quicbaas/sdk/go/service"
	"github.com/jeremyhahn/go-trusted-platform/pkg/storage/quicbaas"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// =============================================================================
// Environment Variable Constants
// =============================================================================

const (
	// EnvIntegrationTest is the environment variable that must be set to run
	// integration tests. Set INTEGRATION_TEST=1 to enable.
	EnvIntegrationTest = "INTEGRATION_TEST"

	// EnvQuicBaaSEndpoint is the environment variable for QuicBaaS service endpoint.
	// Default: 127.0.0.1:63000
	EnvQuicBaaSEndpoint = "QUICBAAS_ENDPOINT"

	// EnvQuicBaaSGRPCEndpoint is the environment variable for QuicBaaS gRPC endpoint.
	// Default: 127.0.0.1:63001
	EnvQuicBaaSGRPCEndpoint = "QUICBAAS_GRPC_ENDPOINT"

	// EnvQuicBaaSRESTEndpoint is the environment variable for QuicBaaS REST endpoint.
	// Default: 127.0.0.1:63002
	EnvQuicBaaSRESTEndpoint = "QUICBAAS_REST_ENDPOINT"

	// EnvPlatformdGRPCEndpoint is the environment variable for platformd gRPC endpoint.
	// Default: 127.0.0.1:8443
	EnvPlatformdGRPCEndpoint = "PLATFORMD_GRPC_ENDPOINT"

	// EnvPlatformAPIEndpoint is the environment variable for platform-api REST endpoint.
	// Default: 127.0.0.1:8080
	EnvPlatformAPIEndpoint = "PLATFORM_API_ENDPOINT"
)

// =============================================================================
// Default Endpoints
// =============================================================================

const (
	// DefaultQuicBaaSEndpoint is the default QuicBaaS Raft/service endpoint.
	DefaultQuicBaaSEndpoint = "127.0.0.1:63000"

	// DefaultQuicBaaSGRPCEndpoint is the default QuicBaaS gRPC endpoint.
	DefaultQuicBaaSGRPCEndpoint = "127.0.0.1:63001"

	// DefaultQuicBaaSRESTEndpoint is the default QuicBaaS REST endpoint.
	DefaultQuicBaaSRESTEndpoint = "127.0.0.1:63002"

	// DefaultPlatformdGRPCEndpoint is the default platformd gRPC endpoint.
	DefaultPlatformdGRPCEndpoint = "127.0.0.1:10443"

	// DefaultPlatformAPIEndpoint is the default platform-api REST endpoint.
	DefaultPlatformAPIEndpoint = "127.0.0.1:8443"
)

// =============================================================================
// Skip Helpers
// =============================================================================

// SkipIfNotIntegration skips the test if the INTEGRATION_TEST environment
// variable is not set. This ensures integration tests only run when explicitly
// requested, preventing accidental execution during normal unit testing.
// This is an exported version for use by other test packages.
func SkipIfNotIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv(EnvIntegrationTest) == "" {
		t.Skip("Skipping integration test. Set INTEGRATION_TEST=1 to run.")
	}
}

// SkipIfKMSUnavailable skips the test if the KMS service is not responding
// to health checks. This prevents tests from failing due to infrastructure
// issues rather than actual test failures.
func SkipIfKMSUnavailable(t *testing.T, client *quicbaas.Client, ctx context.Context) {
	t.Helper()

	if client == nil || !client.IsStarted() {
		t.Skip("Skipping test: QuicBaaS client not started")
		return
	}

	dbSvc := client.Service()
	if dbSvc == nil {
		t.Skip("Skipping test: QuicBaaS service not available")
		return
	}

	kms := dbSvc.KMS()
	if kms == nil {
		t.Skip("Skipping test: KMS service not available")
		return
	}

	// Perform a backend status check to verify KMS is responding
	status, err := kms.BackendStatus(ctx)
	if err != nil {
		t.Skipf("Skipping test: KMS backend not responding: %v", err)
		return
	}

	if status == nil || status.Status != "healthy" {
		t.Skipf("Skipping test: KMS backend not healthy: %v", status)
	}
}

// =============================================================================
// Key Attribute Helpers
// =============================================================================

// AES128GCMKeyAttributes creates KeyAttributes for an AES-128-GCM symmetric key.
// This provides 128-bit security with authenticated encryption.
func AES128GCMKeyAttributes(name string) *xkmssdk.KeyAttributes {
	return &xkmssdk.KeyAttributes{
		CN:                 name,
		SymmetricAlgorithm: xkmssdk.SymmetricAES128GCM,
		KeyType:            xkmssdk.KeyTypeEncryption,
	}
}

// AES256GCMKeyAttributes creates KeyAttributes for an AES-256-GCM symmetric key.
// This provides 256-bit security with authenticated encryption and is the
// recommended default for new symmetric encryption keys.
func AES256GCMKeyAttributes(name string) *xkmssdk.KeyAttributes {
	return &xkmssdk.KeyAttributes{
		CN:                 name,
		SymmetricAlgorithm: xkmssdk.SymmetricAES256GCM,
		KeyType:            xkmssdk.KeyTypeEncryption,
	}
}

// ChaCha20Poly1305KeyAttributes creates KeyAttributes for a ChaCha20-Poly1305 key.
// This algorithm provides 256-bit security and is faster than AES-GCM on platforms
// without hardware AES acceleration (e.g., older ARM devices).
func ChaCha20Poly1305KeyAttributes(name string) *xkmssdk.KeyAttributes {
	return &xkmssdk.KeyAttributes{
		CN:                 name,
		SymmetricAlgorithm: xkmssdk.SymmetricChaCha20Poly1305,
		KeyType:            xkmssdk.KeyTypeEncryption,
	}
}

// XChaCha20Poly1305KeyAttributes creates KeyAttributes for an XChaCha20-Poly1305 key.
// This algorithm extends ChaCha20-Poly1305 with a 192-bit nonce, reducing the
// risk of nonce reuse in high-volume encryption scenarios.
func XChaCha20Poly1305KeyAttributes(name string) *xkmssdk.KeyAttributes {
	return &xkmssdk.KeyAttributes{
		CN:                 name,
		SymmetricAlgorithm: xkmssdk.SymmetricXChaCha20Poly1305,
		KeyType:            xkmssdk.KeyTypeEncryption,
	}
}

// RSA2048KeyAttributes creates KeyAttributes for an RSA-2048 asymmetric key.
// RSA-2048 provides approximately 112-bit security and is suitable for
// digital signatures and key exchange.
func RSA2048KeyAttributes(name string) *xkmssdk.KeyAttributes {
	return &xkmssdk.KeyAttributes{
		CN:           name,
		KeyAlgorithm: x509.RSA,
		KeyType:      xkmssdk.KeyTypeSigning,
		RSAAttributes: &xkmssdk.RSAAttributes{
			KeySize: 2048,
		},
	}
}

// RSA3072KeyAttributes creates KeyAttributes for an RSA-3072 asymmetric key.
// RSA-3072 provides approximately 128-bit security and is recommended by
// NIST for protection through 2031.
func RSA3072KeyAttributes(name string) *xkmssdk.KeyAttributes {
	return &xkmssdk.KeyAttributes{
		CN:           name,
		KeyAlgorithm: x509.RSA,
		KeyType:      xkmssdk.KeyTypeSigning,
		RSAAttributes: &xkmssdk.RSAAttributes{
			KeySize: 3072,
		},
	}
}

// RSA4096KeyAttributes creates KeyAttributes for an RSA-4096 asymmetric key.
// RSA-4096 provides the highest security for RSA keys but is slower
// than smaller key sizes.
func RSA4096KeyAttributes(name string) *xkmssdk.KeyAttributes {
	return &xkmssdk.KeyAttributes{
		CN:           name,
		KeyAlgorithm: x509.RSA,
		KeyType:      xkmssdk.KeyTypeSigning,
		RSAAttributes: &xkmssdk.RSAAttributes{
			KeySize: 4096,
		},
	}
}

// ECDSAP256KeyAttributes creates KeyAttributes for an ECDSA P-256 asymmetric key.
// ECDSA P-256 (secp256r1) provides 128-bit security and is widely supported
// in TLS and code signing applications.
func ECDSAP256KeyAttributes(name string) *xkmssdk.KeyAttributes {
	return &xkmssdk.KeyAttributes{
		CN:           name,
		KeyAlgorithm: x509.ECDSA,
		KeyType:      xkmssdk.KeyTypeSigning,
		ECCAttributes: &xkmssdk.ECCAttributes{
			Curve: elliptic.P256(),
		},
	}
}

// ECDSAP384KeyAttributes creates KeyAttributes for an ECDSA P-384 asymmetric key.
// ECDSA P-384 (secp384r1) provides 192-bit security and is commonly used
// for high-security government and enterprise applications.
func ECDSAP384KeyAttributes(name string) *xkmssdk.KeyAttributes {
	return &xkmssdk.KeyAttributes{
		CN:           name,
		KeyAlgorithm: x509.ECDSA,
		KeyType:      xkmssdk.KeyTypeSigning,
		ECCAttributes: &xkmssdk.ECCAttributes{
			Curve: elliptic.P384(),
		},
	}
}

// ECDSAP521KeyAttributes creates KeyAttributes for an ECDSA P-521 asymmetric key.
// ECDSA P-521 (secp521r1) provides 256-bit security and offers the highest
// security level for NIST curves.
func ECDSAP521KeyAttributes(name string) *xkmssdk.KeyAttributes {
	return &xkmssdk.KeyAttributes{
		CN:           name,
		KeyAlgorithm: x509.ECDSA,
		KeyType:      xkmssdk.KeyTypeSigning,
		ECCAttributes: &xkmssdk.ECCAttributes{
			Curve: elliptic.P521(),
		},
	}
}

// Ed25519KeyAttributes creates KeyAttributes for an Ed25519 asymmetric key.
// Ed25519 provides 128-bit security with fast signature operations and
// deterministic signatures, making it ideal for modern applications.
func Ed25519KeyAttributes(name string) *xkmssdk.KeyAttributes {
	return &xkmssdk.KeyAttributes{
		CN:           name,
		KeyAlgorithm: x509.Ed25519,
		KeyType:      xkmssdk.KeyTypeSigning,
	}
}

// =============================================================================
// Generate Key Request Helpers
// =============================================================================

// GenerateSymmetricKeyRequest creates a GenerateKeyRequest for symmetric encryption.
func GenerateSymmetricKeyRequest(name string, attrs *xkmssdk.KeyAttributes, description string) *service.GenerateKeyRequest {
	return &service.GenerateKeyRequest{
		Name:          name,
		KeyAttributes: attrs,
		Usage: []service.KeyUsage{
			service.KeyUsageEncrypt,
			service.KeyUsageDecrypt,
		},
		Description: description,
	}
}

// GenerateSigningKeyRequest creates a GenerateKeyRequest for digital signatures.
func GenerateSigningKeyRequest(name string, attrs *xkmssdk.KeyAttributes, description string) *service.GenerateKeyRequest {
	return &service.GenerateKeyRequest{
		Name:          name,
		KeyAttributes: attrs,
		Usage: []service.KeyUsage{
			service.KeyUsageSign,
			service.KeyUsageVerify,
		},
		Description: description,
	}
}

// GenerateHMACKeyRequest creates a GenerateKeyRequest for HMAC operations.
func GenerateHMACKeyRequest(name string, attrs *xkmssdk.KeyAttributes, description string) *service.GenerateKeyRequest {
	return &service.GenerateKeyRequest{
		Name:          name,
		KeyAttributes: attrs,
		Usage: []service.KeyUsage{
			service.KeyUsageGenerateMAC,
			service.KeyUsageVerifyMAC,
		},
		Description: description,
	}
}

// =============================================================================
// Test Data Generators
// =============================================================================

// GenerateUniqueKeyName generates a unique key name with the given prefix.
// The name includes a timestamp to ensure uniqueness across test runs.
// Format: prefix-YYYYMMDDHHMMSS-nanoseconds
func GenerateUniqueKeyName(prefix string) string {
	now := time.Now()
	return fmt.Sprintf("%s-%s-%09d", prefix, now.Format("20060102150405"), now.Nanosecond())
}

// GenerateTestPlaintext generates deterministic test data of the specified size.
// The data is derived from a hash of the size, making it reproducible across
// test runs for the same size parameter.
func GenerateTestPlaintext(size int) []byte {
	if size <= 0 {
		return nil
	}

	data := make([]byte, size)

	// Use SHA-256 to generate deterministic bytes based on size
	hash := sha256.Sum256([]byte(fmt.Sprintf("test-plaintext-%d", size)))

	for i := 0; i < size; i++ {
		// Cycle through hash bytes for pattern generation
		data[i] = hash[i%len(hash)]
	}

	return data
}

// GenerateRandomBytes generates cryptographically secure random bytes.
// This is useful for testing with truly random data where reproducibility
// is not required.
func GenerateRandomBytes(size int) ([]byte, error) {
	if size <= 0 {
		return nil, nil
	}

	data := make([]byte, size)
	if _, err := rand.Read(data); err != nil {
		return nil, fmt.Errorf("failed to generate random bytes: %w", err)
	}

	return data, nil
}

// MustGenerateRandomBytes generates random bytes and panics on error.
// This is useful in test code where error handling would be verbose.
func MustGenerateRandomBytes(size int) []byte {
	data, err := GenerateRandomBytes(size)
	if err != nil {
		panic(err)
	}
	return data
}

// GenerateTestSecret generates a test secret with a deterministic pattern.
// Useful for testing secrets management operations.
func GenerateTestSecret(name string) []byte {
	hash := sha256.Sum256([]byte("test-secret-" + name))
	return hash[:]
}

// =============================================================================
// Endpoint Configuration
// =============================================================================

// ServiceEndpoints contains all configured service endpoints.
type ServiceEndpoints struct {
	QuicBaaS      string
	QuicBaaSGRPC  string
	QuicBaaSREST  string
	PlatformdGRPC string
	PlatformAPI   string
}

// GetServiceEndpoints returns QuicBaaS service endpoints from environment
// variables with sensible defaults.
func GetServiceEndpoints() ServiceEndpoints {
	return ServiceEndpoints{
		QuicBaaS:      getEnvOrDefault(EnvQuicBaaSEndpoint, DefaultQuicBaaSEndpoint),
		QuicBaaSGRPC:  getEnvOrDefault(EnvQuicBaaSGRPCEndpoint, DefaultQuicBaaSGRPCEndpoint),
		QuicBaaSREST:  getEnvOrDefault(EnvQuicBaaSRESTEndpoint, DefaultQuicBaaSRESTEndpoint),
		PlatformdGRPC: getEnvOrDefault(EnvPlatformdGRPCEndpoint, DefaultPlatformdGRPCEndpoint),
		PlatformAPI:   getEnvOrDefault(EnvPlatformAPIEndpoint, DefaultPlatformAPIEndpoint),
	}
}

// GetGRPCEndpoints returns all gRPC endpoints (platformd and QuicBaaS gRPC).
func GetGRPCEndpoints() map[string]string {
	endpoints := GetServiceEndpoints()
	return map[string]string{
		"platformd": endpoints.PlatformdGRPC,
		"quicbaas":  endpoints.QuicBaaSGRPC,
	}
}

// GetRESTEndpoints returns all REST endpoints (platform-api and QuicBaaS REST).
func GetRESTEndpoints() map[string]string {
	endpoints := GetServiceEndpoints()
	return map[string]string{
		"platform-api": endpoints.PlatformAPI,
		"quicbaas":     endpoints.QuicBaaSREST,
	}
}

// getEnvOrDefault returns the environment variable value or the default if not set.
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// =============================================================================
// Assertion Helpers
// =============================================================================

// AssertKeyExists asserts that a key with the given ID exists in the KMS.
func AssertKeyExists(t *testing.T, kms service.KMSService, ctx context.Context, keyID string) {
	t.Helper()

	resp, err := kms.GetKey(ctx, &service.GetKeyRequest{
		KeyID: keyID,
	})
	require.NoError(t, err, "GetKey should succeed for existing key")
	require.NotNil(t, resp, "GetKey response should not be nil")
	require.NotNil(t, resp.Key, "Key handle should not be nil")
	assert.Equal(t, keyID, resp.Key.KeyID, "KeyID should match")
}

// AssertKeyNotFound asserts that a key with the given ID does not exist in the KMS.
func AssertKeyNotFound(t *testing.T, kms service.KMSService, ctx context.Context, keyID string) {
	t.Helper()

	_, err := kms.GetKey(ctx, &service.GetKeyRequest{
		KeyID: keyID,
	})
	require.Error(t, err, "GetKey should fail for non-existent key")
}

// AssertEncryptDecryptRoundTrip asserts that encryption and decryption round-trip
// correctly returns the original plaintext.
func AssertEncryptDecryptRoundTrip(
	t *testing.T,
	crypto service.CryptoService,
	ctx context.Context,
	keyID string,
	plaintext []byte,
) {
	t.Helper()

	// Encrypt
	encResp, err := crypto.Encrypt(ctx, &service.EncryptRequest{
		KeyID:     keyID,
		Plaintext: plaintext,
	})
	require.NoError(t, err, "Encrypt should succeed")
	require.NotNil(t, encResp, "Encrypt response should not be nil")
	require.NotEmpty(t, encResp.Ciphertext, "Ciphertext should not be empty")

	// Verify ciphertext differs from plaintext
	assert.False(t, bytes.Equal(plaintext, encResp.Ciphertext),
		"Ciphertext should differ from plaintext")

	// Decrypt
	decResp, err := crypto.Decrypt(ctx, &service.DecryptRequest{
		KeyID:      keyID,
		Ciphertext: encResp.Ciphertext,
		Nonce:      encResp.Nonce,
		KeyVersion: encResp.KeyVersion,
	})
	require.NoError(t, err, "Decrypt should succeed")
	require.NotNil(t, decResp, "Decrypt response should not be nil")

	// Verify plaintext matches original
	assert.True(t, bytes.Equal(plaintext, decResp.Plaintext),
		"Decrypted plaintext should match original")
}

// AssertEncryptDecryptWithAAD asserts that encryption and decryption round-trip
// correctly with additional authenticated data (AAD).
func AssertEncryptDecryptWithAAD(
	t *testing.T,
	crypto service.CryptoService,
	ctx context.Context,
	keyID string,
	plaintext []byte,
	aad []byte,
) {
	t.Helper()

	// Encrypt with AAD
	encResp, err := crypto.Encrypt(ctx, &service.EncryptRequest{
		KeyID:     keyID,
		Plaintext: plaintext,
		Context:   aad,
	})
	require.NoError(t, err, "Encrypt with AAD should succeed")
	require.NotNil(t, encResp, "Encrypt response should not be nil")

	// Decrypt with same AAD
	decResp, err := crypto.Decrypt(ctx, &service.DecryptRequest{
		KeyID:      keyID,
		Ciphertext: encResp.Ciphertext,
		Nonce:      encResp.Nonce,
		Context:    aad,
		KeyVersion: encResp.KeyVersion,
	})
	require.NoError(t, err, "Decrypt with AAD should succeed")
	require.NotNil(t, decResp, "Decrypt response should not be nil")

	assert.True(t, bytes.Equal(plaintext, decResp.Plaintext),
		"Decrypted plaintext should match original")
}

// AssertDecryptFailsWithWrongAAD asserts that decryption fails when the wrong
// AAD is provided.
func AssertDecryptFailsWithWrongAAD(
	t *testing.T,
	crypto service.CryptoService,
	ctx context.Context,
	keyID string,
	plaintext []byte,
	correctAAD []byte,
	wrongAAD []byte,
) {
	t.Helper()

	// Encrypt with correct AAD
	encResp, err := crypto.Encrypt(ctx, &service.EncryptRequest{
		KeyID:     keyID,
		Plaintext: plaintext,
		Context:   correctAAD,
	})
	require.NoError(t, err, "Encrypt should succeed")

	// Decrypt with wrong AAD should fail
	_, err = crypto.Decrypt(ctx, &service.DecryptRequest{
		KeyID:      keyID,
		Ciphertext: encResp.Ciphertext,
		Nonce:      encResp.Nonce,
		Context:    wrongAAD,
		KeyVersion: encResp.KeyVersion,
	})
	require.Error(t, err, "Decrypt with wrong AAD should fail")
}

// AssertSignVerifyRoundTrip asserts that signing and verification round-trip
// correctly validates the signature.
func AssertSignVerifyRoundTrip(
	t *testing.T,
	crypto service.CryptoService,
	ctx context.Context,
	keyID string,
	message []byte,
	hashAlg service.HashAlgorithm,
) {
	t.Helper()

	// Sign
	signResp, err := crypto.Sign(ctx, &service.SignRequest{
		KeyID:         keyID,
		Message:       message,
		HashAlgorithm: hashAlg,
	})
	require.NoError(t, err, "Sign should succeed")
	require.NotNil(t, signResp, "Sign response should not be nil")
	require.NotEmpty(t, signResp.Signature, "Signature should not be empty")

	// Verify
	verifyResp, err := crypto.Verify(ctx, &service.VerifyRequest{
		KeyID:         keyID,
		Message:       message,
		Signature:     signResp.Signature,
		HashAlgorithm: hashAlg,
	})
	require.NoError(t, err, "Verify should succeed")
	require.NotNil(t, verifyResp, "Verify response should not be nil")
	assert.True(t, verifyResp.Valid, "Signature should be valid")
}

// AssertKeyStatus asserts that a key has the expected status.
func AssertKeyStatus(
	t *testing.T,
	kms service.KMSService,
	ctx context.Context,
	keyID string,
	expectedStatus service.KeyStatus,
) {
	t.Helper()

	resp, err := kms.GetKey(ctx, &service.GetKeyRequest{
		KeyID: keyID,
	})
	require.NoError(t, err, "GetKey should succeed")
	require.NotNil(t, resp, "GetKey response should not be nil")
	require.NotNil(t, resp.Key, "Key handle should not be nil")
	assert.Equal(t, expectedStatus, resp.Key.Status, "Key status should match expected")
}

// =============================================================================
// Test Context Helpers
// =============================================================================

// DefaultTestContext returns a context with a reasonable timeout for integration tests.
func DefaultTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 60*time.Second)
}

// LongRunningTestContext returns a context with a longer timeout for tests
// that may take more time (e.g., key rotation, batch operations).
func LongRunningTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Minute)
}

// ShortTestContext returns a context with a short timeout for quick operations.
func ShortTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}
