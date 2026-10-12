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

//go:build integration

// Package vtpm provides integration test helpers for vTPM services.
// These helpers provide reusable functions for creating test vTPM instances,
// generating test data, managing test contexts, and performing assertions
// in multi-protocol integration tests.
package vtpm

import (
	"context"
	"fmt"
	"os"
	"time"
)

// =============================================================================
// Default Values and Timeouts
// =============================================================================

const (
	// DefaultTestTimeout is the default timeout for test operations.
	DefaultTestTimeout = 60 * time.Second

	// LongRunningTestTimeout is the timeout for long-running test operations.
	LongRunningTestTimeout = 5 * time.Minute

	// ShortTestTimeout is the timeout for quick test operations.
	ShortTestTimeout = 10 * time.Second

	// DefaultSwtpmPath is the default path to the swtpm binary.
	DefaultSwtpmPath = "/usr/bin/swtpm"
)

// =============================================================================
// Skip Helpers
// =============================================================================

// SkipIfNotIntegration skips the test if not running in integration mode.
func SkipIfNotIntegration(t interface{ Skip(...interface{}) }) {
	if os.Getenv("INTEGRATION_TEST") == "" {
		t.Skip("Skipping integration test. Set INTEGRATION_TEST=1 to run.")
	}
}

// SkipIfNoSwtpm skips the test if swtpm is not available on the system.
func SkipIfNoSwtpm(t interface{ Skip(...interface{}) }) {
	swtpmPath := GetSwtpmPath()
	if _, err := os.Stat(swtpmPath); os.IsNotExist(err) {
		t.Skip("Skipping test: swtpm not available at", swtpmPath)
	}
}

// SkipIfNoTPMDevice skips the test if no TPM device is available.
func SkipIfNoTPMDevice(t interface{ Skip(...interface{}) }) {
	if _, err := os.Stat("/dev/tpm0"); os.IsNotExist(err) {
		if _, err := os.Stat("/dev/tpmrm0"); os.IsNotExist(err) {
			t.Skip("Skipping test: no TPM device available (/dev/tpm0 or /dev/tpmrm0)")
		}
	}
}

// =============================================================================
// ID Generators
// =============================================================================

// GenerateUniqueBundleID generates a unique bundle ID with the given prefix.
// The ID includes a timestamp to ensure uniqueness across test runs.
// Format: prefix-YYYYMMDDHHMMSS-nanoseconds
func GenerateUniqueBundleID(prefix string) string {
	now := time.Now()
	return fmt.Sprintf("%s-%s-%09d", prefix, now.Format("20060102150405"), now.Nanosecond())
}

// GenerateUniqueTemplateID generates a unique template ID with the given prefix.
// The ID includes a timestamp to ensure uniqueness across test runs.
// Format: prefix-YYYYMMDDHHMMSS-nanoseconds
func GenerateUniqueTemplateID(prefix string) string {
	now := time.Now()
	return fmt.Sprintf("%s-%s-%09d", prefix, now.Format("20060102150405"), now.Nanosecond())
}

// GenerateUniqueVTPMID generates a unique vTPM ID with the given prefix.
// The ID includes a timestamp to ensure uniqueness across test runs.
// Format: prefix-YYYYMMDDHHMMSS-nanoseconds
func GenerateUniqueVTPMID(prefix string) string {
	now := time.Now()
	return fmt.Sprintf("%s-%s-%09d", prefix, now.Format("20060102150405"), now.Nanosecond())
}

// GenerateTestSerial generates a unique serial number for testing.
// Format: TEST-SERIAL-suffix
func GenerateTestSerial(suffix string) string {
	return "TEST-SERIAL-" + suffix
}

// GenerateTestHostname generates a unique hostname for testing.
func GenerateTestHostname(suffix string) string {
	return "test-vtpm-" + suffix + ".example.com"
}

// GenerateTestTemplateID generates a unique template ID for testing.
func GenerateTestTemplateID(suffix string) string {
	return "test-template-" + suffix
}

// =============================================================================
// Test Context Helpers
// =============================================================================

// DefaultTestContext returns a context with a reasonable timeout for
// standard integration tests (60 seconds).
func DefaultTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), DefaultTestTimeout)
}

// LongRunningTestContext returns a context with a longer timeout for tests
// that may take more time (e.g., vTPM provisioning, EK certificate operations).
// Timeout: 5 minutes.
func LongRunningTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), LongRunningTestTimeout)
}

// ShortTestContext returns a context with a short timeout for quick operations.
// Timeout: 10 seconds.
func ShortTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), ShortTestTimeout)
}

// TestContextWithTimeout returns a context with a custom timeout.
func TestContextWithTimeout(timeout time.Duration) (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), timeout)
}

// =============================================================================
// Endpoint Configuration
// =============================================================================

// ServiceEndpoints contains all configured service endpoints for testing.
type ServiceEndpoints struct {
	REST   string
	GRPC   string
	QUIC   string
	MCP    string
	Socket string
}

// GetServiceEndpoints returns service endpoints from environment variables
// with sensible defaults.
func GetServiceEndpoints() ServiceEndpoints {
	return ServiceEndpoints{
		REST:   GetRESTEndpoint(),
		GRPC:   GetGRPCEndpoint(),
		QUIC:   GetQUICEndpoint(),
		MCP:    GetMCPEndpoint(),
		Socket: GetSocketPath(),
	}
}

// GetCLIPath returns the path to the platformctl CLI.
func GetCLIPath() string {
	if path := os.Getenv("PLATFORMCTL_PATH"); path != "" {
		return path
	}
	return "platformctl"
}

// DefaultTenantID returns the default tenant ID for tests.
func DefaultTenantID() string {
	if id := os.Getenv("VTPM_TENANT_ID"); id != "" {
		return id
	}
	return "test-tenant"
}

// GetRESTEndpoint returns the REST API endpoint.
func GetRESTEndpoint() string {
	if endpoint := os.Getenv("VTPM_REST_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return "https://localhost:8443"
}

// GetGRPCEndpoint returns the gRPC API endpoint.
func GetGRPCEndpoint() string {
	if endpoint := os.Getenv("VTPM_GRPC_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return "localhost:10443"
}

// GetQUICEndpoint returns the QUIC API endpoint.
func GetQUICEndpoint() string {
	if endpoint := os.Getenv("VTPM_QUIC_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return "localhost:9444"
}

// GetMCPEndpoint returns the MCP API endpoint.
func GetMCPEndpoint() string {
	if endpoint := os.Getenv("VTPM_MCP_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return "https://localhost:9445"
}

// GetSocketPath returns the Unix socket path.
func GetSocketPath() string {
	if path := os.Getenv("VTPM_SOCKET_PATH"); path != "" {
		return path
	}
	return "/run/platformd.sock"
}

// GetSwtpmPath returns the path to the swtpm binary.
func GetSwtpmPath() string {
	if path := os.Getenv("SWTPM_PATH"); path != "" {
		return path
	}
	return DefaultSwtpmPath
}

// =============================================================================
// vTPM Test Configuration
// =============================================================================

// VTPMTestConfig holds configuration for vTPM integration tests.
type VTPMTestConfig struct {
	TenantID   string
	BundleID   string
	TemplateID string
	VTPMID     string
	StateDir   string
	SocketPath string
	PCRBanks   []string
}

// DefaultVTPMTestConfig returns a default configuration for vTPM tests.
func DefaultVTPMTestConfig(prefix string) VTPMTestConfig {
	return VTPMTestConfig{
		TenantID:   DefaultTenantID(),
		BundleID:   GenerateUniqueBundleID(prefix + "-bundle"),
		TemplateID: GenerateUniqueTemplateID(prefix + "-template"),
		VTPMID:     GenerateUniqueVTPMID(prefix + "-vtpm"),
		PCRBanks:   []string{"sha256"},
	}
}

// =============================================================================
// Wait and Retry Helpers
// =============================================================================

// WaitForCondition waits for a condition to become true within the given timeout.
// It polls the condition function every 100ms.
func WaitForCondition(ctx context.Context, timeout time.Duration, condition func() bool) error {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	ticker := time.NewTicker(100 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-ticker.C:
			if condition() {
				return nil
			}
		}
	}
}

// WaitForFile waits for a file to exist within the given timeout.
func WaitForFile(ctx context.Context, path string, timeout time.Duration) error {
	return WaitForCondition(ctx, timeout, func() bool {
		_, err := os.Stat(path)
		return err == nil
	})
}

// WaitForSocket waits for a Unix socket to exist within the given timeout.
func WaitForSocket(ctx context.Context, socketPath string, timeout time.Duration) error {
	return WaitForFile(ctx, socketPath, timeout)
}

// RetryConfig configures retry behavior for operations.
type RetryConfig struct {
	MaxAttempts int
	InitialWait time.Duration
	MaxWait     time.Duration
	Multiplier  float64
}

// DefaultRetryConfig returns sensible defaults for retry operations.
func DefaultRetryConfig() RetryConfig {
	return RetryConfig{
		MaxAttempts: 10,
		InitialWait: 500 * time.Millisecond,
		MaxWait:     5 * time.Second,
		Multiplier:  1.5,
	}
}

// Retry executes an operation with exponential backoff retry.
func Retry(ctx context.Context, cfg RetryConfig, operation func() error) error {
	var lastErr error
	wait := cfg.InitialWait

	for attempt := 1; attempt <= cfg.MaxAttempts; attempt++ {
		lastErr = operation()
		if lastErr == nil {
			return nil
		}

		if ctx.Err() != nil {
			return ctx.Err()
		}

		if attempt < cfg.MaxAttempts {
			select {
			case <-time.After(wait):
			case <-ctx.Done():
				return ctx.Err()
			}

			wait = time.Duration(float64(wait) * cfg.Multiplier)
			if wait > cfg.MaxWait {
				wait = cfg.MaxWait
			}
		}
	}

	return fmt.Errorf("operation failed after %d attempts: %w", cfg.MaxAttempts, lastErr)
}

// =============================================================================
// EK Algorithm Constants
// =============================================================================

// EKAlgorithm represents the algorithm used for the Endorsement Key.
type EKAlgorithm string

const (
	// EKAlgorithmRSA represents RSA-based EK.
	EKAlgorithmRSA EKAlgorithm = "RSA"

	// EKAlgorithmECC represents ECC-based EK.
	EKAlgorithmECC EKAlgorithm = "ECC"
)

// =============================================================================
// PCR Bank Constants
// =============================================================================

// PCRBankSHA1 is the SHA-1 PCR bank identifier.
const PCRBankSHA1 = "sha1"

// PCRBankSHA256 is the SHA-256 PCR bank identifier.
const PCRBankSHA256 = "sha256"

// PCRBankSHA384 is the SHA-384 PCR bank identifier.
const PCRBankSHA384 = "sha384"

// PCRBankSHA512 is the SHA-512 PCR bank identifier.
const PCRBankSHA512 = "sha512"

// DefaultPCRBanks returns the default PCR banks for testing.
func DefaultPCRBanks() []string {
	return []string{PCRBankSHA256}
}

// AllPCRBanks returns all supported PCR banks.
func AllPCRBanks() []string {
	return []string{PCRBankSHA1, PCRBankSHA256, PCRBankSHA384, PCRBankSHA512}
}
