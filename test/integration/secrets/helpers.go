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

// Package secrets provides integration test helpers for Secrets services.
// These helpers provide reusable functions for creating test secrets,
// generating test data, and performing assertions in integration tests.

//go:build integration

package secrets

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/sha256"
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

	// EnvPlatformAPIEndpoint is the environment variable for the platformd REST endpoint.
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

	// DefaultPlatformAPIEndpoint is the default platformd REST endpoint.
	DefaultPlatformAPIEndpoint = "127.0.0.1:8443"
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

// GenerateUniqueSecretName generates a unique secret name with the given prefix.
// The name includes a timestamp to ensure uniqueness across test runs.
// Format: prefix-YYYYMMDDHHMMSS-nanoseconds
func GenerateUniqueSecretName(prefix string) string {
	now := time.Now()
	return fmt.Sprintf("%s-%s-%09d", prefix, now.Format("20060102150405"), now.Nanosecond())
}

// GenerateTestSecretData generates deterministic test data of the specified size.
// The data is derived from a hash of the size, making it reproducible across
// test runs for the same size parameter.
func GenerateTestSecretData(size int) []byte {
	if size <= 0 {
		return nil
	}

	data := make([]byte, size)

	// Use SHA-256 to generate deterministic bytes based on size
	hash := sha256.Sum256([]byte(fmt.Sprintf("test-secret-data-%d", size)))

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
// Store Options Helpers
// =============================================================================

// DefaultStoreOptions creates default StoreOptions for a simple secret.
func DefaultStoreOptions(name string, data []byte) StoreOptions {
	return StoreOptions{
		Name:        name,
		Data:        data,
		Description: fmt.Sprintf("Test secret: %s", name),
	}
}

// StoreOptionsWithMetadata creates StoreOptions with metadata.
func StoreOptionsWithMetadata(name string, data []byte, metadata map[string]string) StoreOptions {
	opts := DefaultStoreOptions(name, data)
	opts.Metadata = metadata
	return opts
}

// StoreOptionsWithTags creates StoreOptions with tags.
func StoreOptionsWithTags(name string, data []byte, tags map[string]string) StoreOptions {
	opts := DefaultStoreOptions(name, data)
	opts.Tags = tags
	return opts
}

// StoreOptionsWithExpiry creates StoreOptions with expiration.
func StoreOptionsWithExpiry(name string, data []byte, expiresAt time.Time) StoreOptions {
	opts := DefaultStoreOptions(name, data)
	opts.ExpiresAt = expiresAt
	return opts
}

// =============================================================================
// Assertion Helpers
// =============================================================================

// AssertSecretExists asserts that a secret with the given name exists.
func AssertSecretExists(t *testing.T, cmd SecretsCommands, ctx context.Context, name string) {
	t.Helper()

	result, err := cmd.Get(ctx, name)
	require.NoError(t, err, "Get should succeed for existing secret")
	require.NotNil(t, result, "Get result should not be nil")
	assert.NotEmpty(t, result.SecretID, "SecretID should not be empty")
}

// AssertSecretNotFound asserts that a secret with the given name does not exist.
func AssertSecretNotFound(t *testing.T, cmd SecretsCommands, ctx context.Context, name string) {
	t.Helper()

	_, err := cmd.Get(ctx, name)
	require.Error(t, err, "Get should fail for non-existent secret")
}

// AssertSecretDataMatches asserts that the secret data matches expected.
func AssertSecretDataMatches(t *testing.T, cmd SecretsCommands, ctx context.Context, name string, expected []byte) {
	t.Helper()

	result, err := cmd.Get(ctx, name)
	require.NoError(t, err, "Get should succeed")
	require.NotNil(t, result, "Get result should not be nil")
	assert.True(t, bytes.Equal(expected, result.Data), "Secret data should match expected")
}

// AssertSecretVersion asserts that a secret has the expected version.
func AssertSecretVersion(t *testing.T, cmd SecretsCommands, ctx context.Context, name string, expectedVersion uint64) {
	t.Helper()

	result, err := cmd.Get(ctx, name)
	require.NoError(t, err, "Get should succeed")
	require.NotNil(t, result, "Get result should not be nil")
	assert.Equal(t, expectedVersion, result.Version, "Secret version should match expected")
}

// AssertStoreRotateRoundTrip asserts that storing and rotating a secret
// correctly maintains version history.
func AssertStoreRotateRoundTrip(
	t *testing.T,
	cmd SecretsCommands,
	ctx context.Context,
	name string,
	initialData []byte,
	rotatedData []byte,
) {
	t.Helper()

	// Store
	storeResult, err := cmd.Store(ctx, DefaultStoreOptions(name, initialData))
	require.NoError(t, err, "Store should succeed")
	require.NotNil(t, storeResult, "Store result should not be nil")
	require.Equal(t, uint64(1), storeResult.Version, "Initial version should be 1")

	// Verify initial data
	getResult, err := cmd.Get(ctx, name)
	require.NoError(t, err, "Get should succeed")
	assert.True(t, bytes.Equal(initialData, getResult.Data), "Initial data should match")

	// Rotate
	rotateResult, err := cmd.Rotate(ctx, name, rotatedData)
	require.NoError(t, err, "Rotate should succeed")
	require.NotNil(t, rotateResult, "Rotate result should not be nil")
	require.Equal(t, uint64(1), rotateResult.OldVersion, "OldVersion should be 1")
	require.Equal(t, uint64(2), rotateResult.NewVersion, "NewVersion should be 2")

	// Verify rotated data
	getResult, err = cmd.Get(ctx, name)
	require.NoError(t, err, "Get should succeed after rotation")
	assert.True(t, bytes.Equal(rotatedData, getResult.Data), "Rotated data should match")
	assert.Equal(t, uint64(2), getResult.Version, "Version should be 2 after rotation")
}

// AssertVersionHistoryMaintained asserts that version history is properly maintained.
func AssertVersionHistoryMaintained(
	t *testing.T,
	cmd SecretsCommands,
	ctx context.Context,
	name string,
	expectedVersionCount int,
) {
	t.Helper()

	result, err := cmd.Versions(ctx, name)
	require.NoError(t, err, "Versions should succeed")
	require.NotNil(t, result, "Versions result should not be nil")
	assert.Len(t, result.Versions, expectedVersionCount, "Should have expected number of versions")
}

// =============================================================================
// Test Context Helpers
// =============================================================================

// DefaultTestContext returns a context with a reasonable timeout for integration tests.
func DefaultTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 60*time.Second)
}

// LongRunningTestContext returns a context with a longer timeout for tests
// that may take more time (e.g., many rotations, batch operations).
func LongRunningTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Minute)
}

// ShortTestContext returns a context with a short timeout for quick operations.
func ShortTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

// =============================================================================
// Cleanup Helpers
// =============================================================================

// CleanupSecret attempts to delete a secret, ignoring errors.
// Useful in test cleanup to ensure secrets are removed even if the test failed.
func CleanupSecret(cmd SecretsCommands, ctx context.Context, name string) {
	_, _ = cmd.Delete(ctx, name, true)
}

// CleanupSecrets attempts to delete multiple secrets, ignoring errors.
func CleanupSecrets(cmd SecretsCommands, ctx context.Context, names []string) {
	for _, name := range names {
		CleanupSecret(cmd, ctx, name)
	}
}

// TestSecretCleaner is a helper that tracks created secrets and cleans them up.
type TestSecretCleaner struct {
	cmd     SecretsCommands
	ctx     context.Context
	secrets []string
}

// NewTestSecretCleaner creates a new test secret cleaner.
func NewTestSecretCleaner(cmd SecretsCommands, ctx context.Context) *TestSecretCleaner {
	return &TestSecretCleaner{
		cmd:     cmd,
		ctx:     ctx,
		secrets: make([]string, 0),
	}
}

// Track adds a secret name to be cleaned up.
func (c *TestSecretCleaner) Track(name string) {
	c.secrets = append(c.secrets, name)
}

// Cleanup deletes all tracked secrets.
func (c *TestSecretCleaner) Cleanup() {
	CleanupSecrets(c.cmd, c.ctx, c.secrets)
}
