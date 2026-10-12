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

// Package registry provides integration test helpers for Registry services.
// These helpers provide reusable functions for creating test images,
// generating test data, and performing assertions in integration tests.

//go:build integration

package registry

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"testing"
	"time"

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

	// EnvPlatformdGRPCEndpoint is the environment variable for platformd gRPC endpoint.
	// Default: 127.0.0.1:10443
	EnvPlatformdGRPCEndpoint = "PLATFORMD_GRPC_ENDPOINT"

	// EnvPlatformAPIEndpoint is the environment variable for the platformd REST endpoint.
	// Default: 127.0.0.1:8443
	EnvPlatformAPIEndpoint = "PLATFORM_API_ENDPOINT"

	// EnvPlatformdQUICEndpoint is the environment variable for platformd QUIC endpoint.
	// Default: 127.0.0.1:9444
	EnvPlatformdQUICEndpoint = "PLATFORMD_QUIC_ENDPOINT"

	// EnvPlatformdMCPEndpoint is the environment variable for platformd MCP endpoint.
	// Default: 127.0.0.1:9445
	EnvPlatformdMCPEndpoint = "PLATFORMD_MCP_ENDPOINT"

	// EnvPlatformdUnixSocket is the environment variable for platformd Unix socket.
	// Default: /run/platformd.sock
	EnvPlatformdUnixSocket = "PLATFORMD_UNIX_SOCKET"

	// EnvRegistryEndpoint is the environment variable for registry endpoint.
	// Default: 127.0.0.1:5000
	EnvRegistryEndpoint = "REGISTRY_ENDPOINT"
)

// =============================================================================
// Default Endpoints
// =============================================================================

const (
	// DefaultPlatformdGRPCEndpoint is the default platformd gRPC endpoint.
	DefaultPlatformdGRPCEndpoint = "127.0.0.1:10443"

	// DefaultPlatformAPIEndpoint is the default platformd REST endpoint.
	DefaultPlatformAPIEndpoint = "127.0.0.1:8443"

	// DefaultPlatformdQUICEndpoint is the default platformd QUIC endpoint.
	DefaultPlatformdQUICEndpoint = "127.0.0.1:9444"

	// DefaultPlatformdMCPEndpoint is the default platformd MCP endpoint.
	DefaultPlatformdMCPEndpoint = "127.0.0.1:9445"

	// DefaultPlatformdUnixSocket is the default platformd Unix socket path.
	DefaultPlatformdUnixSocket = "/run/platformd.sock"

	// DefaultRegistryEndpoint is the default registry endpoint.
	DefaultRegistryEndpoint = "127.0.0.1:5000"
)

// =============================================================================
// OCI Media Types
// =============================================================================

const (
	// MediaTypeImageManifest is the OCI image manifest media type.
	MediaTypeImageManifest = "application/vnd.oci.image.manifest.v1+json"

	// MediaTypeImageConfig is the OCI image config media type.
	MediaTypeImageConfig = "application/vnd.oci.image.config.v1+json"

	// MediaTypeImageLayerGzip is the OCI gzip-compressed layer media type.
	MediaTypeImageLayerGzip = "application/vnd.oci.image.layer.v1.tar+gzip"

	// MediaTypeImageLayer is the OCI uncompressed layer media type.
	MediaTypeImageLayer = "application/vnd.oci.image.layer.v1.tar"
)

// =============================================================================
// Skip Helpers
// =============================================================================

// SkipIfNotIntegration skips the test if the INTEGRATION_TEST environment
// variable is not set. This ensures integration tests only run when explicitly
// requested, preventing accidental execution during normal unit testing.
func SkipIfNotIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv(EnvIntegrationTest) == "" {
		t.Skip("Skipping integration test. Set INTEGRATION_TEST=1 to run.")
	}
}

// =============================================================================
// Endpoint Configuration
// =============================================================================

// ServiceEndpoints contains all configured service endpoints.
type ServiceEndpoints struct {
	PlatformdGRPC string
	PlatformAPI   string
	PlatformdQUIC string
	PlatformdMCP  string
	PlatformdUnix string
	RegistryAddr  string
}

// GetServiceEndpoints returns service endpoints from environment
// variables with sensible defaults.
func GetServiceEndpoints() ServiceEndpoints {
	return ServiceEndpoints{
		PlatformdGRPC: getEnvOrDefault(EnvPlatformdGRPCEndpoint, DefaultPlatformdGRPCEndpoint),
		PlatformAPI:   getEnvOrDefault(EnvPlatformAPIEndpoint, DefaultPlatformAPIEndpoint),
		PlatformdQUIC: getEnvOrDefault(EnvPlatformdQUICEndpoint, DefaultPlatformdQUICEndpoint),
		PlatformdMCP:  getEnvOrDefault(EnvPlatformdMCPEndpoint, DefaultPlatformdMCPEndpoint),
		PlatformdUnix: getEnvOrDefault(EnvPlatformdUnixSocket, DefaultPlatformdUnixSocket),
		RegistryAddr:  getEnvOrDefault(EnvRegistryEndpoint, DefaultRegistryEndpoint),
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
// Test Data Generators
// =============================================================================

// GenerateUniqueImageRef generates a unique image reference with the given prefix.
// The name includes a timestamp to ensure uniqueness across test runs.
// Format: prefix-YYYYMMDDHHMMSS-nanoseconds:tag
func GenerateUniqueImageRef(prefix, tag string) string {
	now := time.Now()
	if tag == "" {
		tag = "latest"
	}
	return fmt.Sprintf("%s-%s-%09d:%s", prefix, now.Format("20060102150405"), now.Nanosecond(), tag)
}

// GenerateTestLayer generates a test layer with deterministic content.
// The content is derived from a hash of the size and index.
func GenerateTestLayer(size int, index int) LayerData {
	if size <= 0 {
		size = 1024
	}

	content := make([]byte, size)
	hash := sha256.Sum256([]byte(fmt.Sprintf("test-layer-%d-%d", size, index)))

	for i := 0; i < size; i++ {
		content[i] = hash[i%len(hash)]
	}

	digest := computeDigest(content)

	return LayerData{
		MediaType: MediaTypeImageLayerGzip,
		Content:   content,
		Annotations: map[string]string{
			"test.layer.index":  fmt.Sprintf("%d", index),
			"test.layer.digest": digest,
		},
	}
}

// GenerateTestImage generates a complete test image with the specified number of layers.
func GenerateTestImage(layerCount int, layerSize int) ([]LayerData, []byte) {
	if layerCount <= 0 {
		layerCount = 1
	}
	if layerSize <= 0 {
		layerSize = 1024
	}

	layers := make([]LayerData, layerCount)
	for i := 0; i < layerCount; i++ {
		layers[i] = GenerateTestLayer(layerSize, i)
	}

	config := GenerateTestConfig()

	return layers, config
}

// GenerateTestConfig generates a minimal test image configuration.
func GenerateTestConfig() []byte {
	now := time.Now().UTC().Format(time.RFC3339)
	return []byte(fmt.Sprintf(`{
  "created": "%s",
  "architecture": "amd64",
  "os": "linux",
  "config": {
    "Env": ["PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"],
    "Cmd": ["/bin/sh"],
    "WorkingDir": "/"
  },
  "rootfs": {
    "type": "layers",
    "diff_ids": []
  }
}`, now))
}

// GenerateRandomBytes generates cryptographically secure random bytes.
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
func MustGenerateRandomBytes(size int) []byte {
	data, err := GenerateRandomBytes(size)
	if err != nil {
		panic(err)
	}
	return data
}

// computeDigest computes the SHA256 digest of the content.
func computeDigest(content []byte) string {
	hash := sha256.Sum256(content)
	return "sha256:" + hex.EncodeToString(hash[:])
}

// =============================================================================
// Mock Attestation Data Generators
// =============================================================================

// GenerateMockAttestationEvidence generates mock attestation evidence for testing.
func GenerateMockAttestationEvidence(clientID string) VerifyClientOptions {
	nonce := MustGenerateRandomBytes(32)
	aik := MustGenerateRandomBytes(256)
	quote := MustGenerateRandomBytes(128)
	signature := MustGenerateRandomBytes(256)

	// Generate mock PCR values (SHA256 zeros for each PCR)
	pcrs := make(map[int][]byte)
	for i := 0; i < 24; i++ {
		pcrs[i] = make([]byte, 32)
	}

	return VerifyClientOptions{
		ClientID:  clientID,
		AIK:       aik,
		Quote:     quote,
		Signature: signature,
		Nonce:     nonce,
		PCRs:      pcrs,
		EventLog:  MustGenerateRandomBytes(1024),
		Timestamp: time.Now(),
	}
}

// GenerateMockPCRs generates mock PCR values for testing.
func GenerateMockPCRs(pcrIndices []int) map[int][]byte {
	pcrs := make(map[int][]byte)
	for _, idx := range pcrIndices {
		hash := sha256.Sum256([]byte(fmt.Sprintf("pcr-%d-value", idx)))
		pcrs[idx] = hash[:]
	}
	return pcrs
}

// =============================================================================
// Test Context Helpers
// =============================================================================

// DefaultTestContext returns a context with a reasonable timeout for integration tests.
func DefaultTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 60*time.Second)
}

// LongRunningTestContext returns a context with a longer timeout for tests
// that may take more time (e.g., large image push/pull).
func LongRunningTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Minute)
}

// ShortTestContext returns a context with a short timeout for quick operations.
func ShortTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

// =============================================================================
// Assertion Helpers
// =============================================================================

// AssertImageExists asserts that an image with the given reference exists.
func AssertImageExists(t *testing.T, adapter RegistryCommands, ctx context.Context, ref string) {
	t.Helper()

	result, err := adapter.Inspect(ctx, ref)
	require.NoError(t, err, "Inspect should succeed for existing image")
	require.NotNil(t, result, "Inspect result should not be nil")
	assert.Equal(t, ref, result.Reference, "Reference should match")
}

// AssertImageNotFound asserts that an image with the given reference does not exist.
func AssertImageNotFound(t *testing.T, adapter RegistryCommands, ctx context.Context, ref string) {
	t.Helper()

	_, err := adapter.Inspect(ctx, ref)
	require.Error(t, err, "Inspect should fail for non-existent image")
}

// AssertPushPullRoundTrip asserts that push and pull round-trip correctly.
func AssertPushPullRoundTrip(
	t *testing.T,
	adapter RegistryCommands,
	ctx context.Context,
	ref string,
	layers []LayerData,
	config []byte,
) {
	t.Helper()

	// Push image
	pushOpts := PushOptions{
		Layers:         layers,
		Config:         config,
		AllowOverwrite: true,
	}
	pushResult, err := adapter.Push(ctx, ref, pushOpts)
	require.NoError(t, err, "Push should succeed")
	require.NotNil(t, pushResult, "Push result should not be nil")
	require.NotEmpty(t, pushResult.Digest, "Push digest should not be empty")

	// Pull image
	pullOpts := PullOptions{}
	pullResult, err := adapter.Pull(ctx, ref, pullOpts)
	require.NoError(t, err, "Pull should succeed")
	require.NotNil(t, pullResult, "Pull result should not be nil")
	require.Equal(t, len(layers), len(pullResult.Layers), "Layer count should match")

	// Verify layer contents match
	for i, layer := range layers {
		assert.Equal(t, layer.Content, pullResult.Layers[i].Content,
			"Layer %d content should match", i)
	}
}

// AssertEncryptedImage asserts that an image is encrypted.
func AssertEncryptedImage(t *testing.T, adapter RegistryCommands, ctx context.Context, ref string) {
	t.Helper()

	result, err := adapter.Inspect(ctx, ref)
	require.NoError(t, err, "Inspect should succeed")
	assert.True(t, result.Encrypted, "Image should be encrypted")
	assert.NotEmpty(t, result.EncryptionKeyID, "Encryption key ID should be set")
}

// AssertRegistryHealthy asserts that the registry is healthy.
func AssertRegistryHealthy(t *testing.T, adapter RegistryCommands, ctx context.Context) {
	t.Helper()

	result, err := adapter.Status(ctx)
	require.NoError(t, err, "Status should succeed")
	require.NotNil(t, result, "Status result should not be nil")
	assert.True(t, result.Healthy, "Registry should be healthy")
	assert.Equal(t, "running", result.Status, "Registry should be running")
}

// AssertSessionValid asserts that a session is valid and not expired.
func AssertSessionValid(t *testing.T, adapter RegistryCommands, ctx context.Context, clientID string) {
	t.Helper()

	result, err := adapter.GetSession(ctx, clientID)
	require.NoError(t, err, "GetSession should succeed for valid session")
	require.NotNil(t, result, "Session result should not be nil")
	assert.Equal(t, clientID, result.ClientID, "Client ID should match")
	assert.True(t, time.Now().Before(result.ValidUntil), "Session should not be expired")
}

// AssertSessionNotFound asserts that a session does not exist.
func AssertSessionNotFound(t *testing.T, adapter RegistryCommands, ctx context.Context, clientID string) {
	t.Helper()

	_, err := adapter.GetSession(ctx, clientID)
	require.Error(t, err, "GetSession should fail for non-existent session")
}
