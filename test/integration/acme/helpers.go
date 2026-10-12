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

// Package acme provides integration test helpers for ACME certificate services.
// These helpers provide reusable functions for creating test accounts, orders,
// and performing assertions in integration tests.

//go:build integration

package acme

import (
	"context"
	"fmt"
	"os"
	"testing"
	"time"
)

// =============================================================================
// Environment Variable Constants
// =============================================================================

const (
	// EnvIntegrationTest is the environment variable that must be set to run
	// integration tests. Set INTEGRATION_TEST=1 to enable.
	EnvIntegrationTest = "INTEGRATION_TEST"

	// EnvPlatformdSocket is the Unix socket path for platformd.
	EnvPlatformdSocket = "PLATFORMD_SOCKET"

	// EnvPlatformAPIEndpoint is the environment variable for the platformd REST endpoint.
	EnvPlatformAPIEndpoint = "PLATFORM_API_ENDPOINT"

	// EnvPlatformGRPCEndpoint is the environment variable for platformd gRPC endpoint.
	EnvPlatformGRPCEndpoint = "PLATFORM_GRPC_ENDPOINT"

	// EnvPlatformQUICEndpoint is the environment variable for platformd QUIC endpoint.
	EnvPlatformQUICEndpoint = "PLATFORM_QUIC_ENDPOINT"

	// EnvPlatformMCPEndpoint is the environment variable for platformd MCP endpoint.
	EnvPlatformMCPEndpoint = "PLATFORM_MCP_ENDPOINT"

	// EnvPlatformctlBinary is the path to the platformctl binary.
	EnvPlatformctlBinary = "PLATFORMCTL_BINARY"

	// EnvACMEDirectoryURL is the ACME directory URL for testing.
	EnvACMEDirectoryURL = "ACME_DIRECTORY_URL"

	// EnvACMECACert is the path to the ACME CA certificate.
	EnvACMECACert = "ACME_CA_CERT"
)

// =============================================================================
// Default Endpoints
// =============================================================================

const (
	// DefaultPlatformdSocket is the default Unix socket path.
	DefaultPlatformdSocket = "/run/platformd.sock"

	// DefaultPlatformAPIEndpoint is the default platformd REST endpoint.
	DefaultPlatformAPIEndpoint = "127.0.0.1:8443"

	// DefaultPlatformGRPCEndpoint is the default platformd gRPC endpoint.
	DefaultPlatformGRPCEndpoint = "127.0.0.1:10443"

	// DefaultPlatformQUICEndpoint is the default platformd QUIC endpoint.
	DefaultPlatformQUICEndpoint = "127.0.0.1:9444"

	// DefaultPlatformMCPEndpoint is the default platformd MCP endpoint.
	DefaultPlatformMCPEndpoint = "127.0.0.1:9445"

	// DefaultPlatformctlBinary is the default binary name when not specified.
	DefaultPlatformctlBinary = "platformctl"

	// DefaultACMEDirectoryURL is the default ACME directory URL.
	DefaultACMEDirectoryURL = "https://localhost:8443/api/v1/acme/directory"

	// DefaultACMECACert is the default ACME CA certificate path.
	DefaultACMECACert = "ca-bundle.pem"

	// DefaultCommandTimeout is the default timeout for CLI commands.
	DefaultCommandTimeout = 30 * time.Second
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
	PlatformdSocket string
	PlatformAPI     string
	PlatformGRPC    string
	PlatformQUIC    string
	PlatformMCP     string
	ACMEDirectory   string
	ACMECACert      string
}

// GetServiceEndpoints returns service endpoints from environment
// variables with sensible defaults.
func GetServiceEndpoints() ServiceEndpoints {
	return ServiceEndpoints{
		PlatformdSocket: getEnvOrDefault(EnvPlatformdSocket, DefaultPlatformdSocket),
		PlatformAPI:     getEnvOrDefault(EnvPlatformAPIEndpoint, DefaultPlatformAPIEndpoint),
		PlatformGRPC:    getEnvOrDefault(EnvPlatformGRPCEndpoint, DefaultPlatformGRPCEndpoint),
		PlatformQUIC:    getEnvOrDefault(EnvPlatformQUICEndpoint, DefaultPlatformQUICEndpoint),
		PlatformMCP:     getEnvOrDefault(EnvPlatformMCPEndpoint, DefaultPlatformMCPEndpoint),
		ACMEDirectory:   getEnvOrDefault(EnvACMEDirectoryURL, DefaultACMEDirectoryURL),
		ACMECACert:      getEnvOrDefault(EnvACMECACert, DefaultACMECACert),
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

// GenerateUniqueEmail generates a unique email address for testing.
// Format: test-YYYYMMDDHHMMSS-nanoseconds@test.example.com
func GenerateUniqueEmail(prefix string) string {
	now := time.Now()
	return fmt.Sprintf("%s-%s-%d@test.example.com", prefix, now.Format("20060102150405"), now.UnixNano()%1000000)
}

// GenerateUniqueCommonName generates a unique common name for certificates.
// Format: prefix-YYYYMMDDHHMMSS.test.local
func GenerateUniqueCommonName(prefix string) string {
	now := time.Now()
	return fmt.Sprintf("%s-%s.test.local", prefix, now.Format("20060102150405"))
}

// GenerateUniqueDeviceSerial generates a unique device serial number for testing.
// Format: PREFIX-YYYYMMDDHHMMSS-nanoseconds
func GenerateUniqueDeviceSerial(prefix string) string {
	now := time.Now()
	return fmt.Sprintf("%s-%s-%d", prefix, now.Format("20060102150405"), now.UnixNano()%1000000)
}

// GenerateTestSANs generates a list of test Subject Alternative Names.
func GenerateTestSANs(baseDomain string, count int) []string {
	sans := make([]string, count)
	for i := 0; i < count; i++ {
		sans[i] = fmt.Sprintf("san%d.%s", i+1, baseDomain)
	}
	return sans
}

// =============================================================================
// Test Context Helpers
// =============================================================================

// DefaultTestContext returns a context with a reasonable timeout for integration tests.
func DefaultTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 60*time.Second)
}

// LongRunningTestContext returns a context with a longer timeout for tests
// that may take more time (e.g., certificate issuance, attestation).
func LongRunningTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 5*time.Minute)
}

// ShortTestContext returns a context with a short timeout for quick operations.
func ShortTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

// =============================================================================
// Default Options Helpers
// =============================================================================

// DefaultAccountCreateOptions returns default account creation options.
func DefaultAccountCreateOptions(email string) AccountCreateOptions {
	endpoints := GetServiceEndpoints()
	return AccountCreateOptions{
		Email:          email,
		DirectoryURL:   endpoints.ACMEDirectory,
		TermsOfService: true,
	}
}

// DefaultCertificateRequestOptions returns default certificate request options.
func DefaultCertificateRequestOptions(cn string, email string) CertificateRequestOptions {
	endpoints := GetServiceEndpoints()
	return CertificateRequestOptions{
		CommonName:        cn,
		AuthorizationType: "dns",
		ChallengeType:     "http-01",
		DirectoryURL:      endpoints.ACMEDirectory,
		CACert:            endpoints.ACMECACert,
		Email:             email,
	}
}

// DefaultCertificateRenewOptions returns default certificate renewal options.
func DefaultCertificateRenewOptions(cn string, email string) CertificateRenewOptions {
	endpoints := GetServiceEndpoints()
	return CertificateRenewOptions{
		CommonName:        cn,
		AuthorizationType: "dns",
		ChallengeType:     "http-01",
		DirectoryURL:      endpoints.ACMEDirectory,
		CACert:            endpoints.ACMECACert,
		Email:             email,
	}
}

// DefaultOrderIdentifier returns a default DNS order identifier.
func DefaultOrderIdentifier(domain string) OrderIdentifier {
	return OrderIdentifier{
		Type:  "dns",
		Value: domain,
	}
}

// =============================================================================
// Error Types
// =============================================================================

// ErrConnectionFailed indicates a connection failure.
type ErrConnectionFailed struct {
	Protocol string
	Endpoint string
	Err      error
}

func (e ErrConnectionFailed) Error() string {
	return fmt.Sprintf("%s connection failed to %s: %v", e.Protocol, e.Endpoint, e.Err)
}

func (e ErrConnectionFailed) Unwrap() error {
	return e.Err
}

// ErrCallFailed indicates a protocol call failure.
type ErrCallFailed struct {
	Protocol string
	Method   string
	Err      error
}

func (e ErrCallFailed) Error() string {
	return fmt.Sprintf("%s call %s failed: %v", e.Protocol, e.Method, e.Err)
}

func (e ErrCallFailed) Unwrap() error {
	return e.Err
}

// ErrCLIBinaryNotFound is returned when the platformctl binary cannot be found.
type ErrCLIBinaryNotFound struct {
	Path string
}

func (e ErrCLIBinaryNotFound) Error() string {
	return fmt.Sprintf("platformctl binary not found at path: %s", e.Path)
}

// ErrCLIOutputParseFailed is returned when CLI output cannot be parsed.
type ErrCLIOutputParseFailed struct {
	Operation string
	Output    string
	Err       error
}

func (e ErrCLIOutputParseFailed) Error() string {
	return fmt.Sprintf("failed to parse CLI output for %s: %v (output: %s)", e.Operation, e.Err, e.Output)
}

// ErrAccountNotFound indicates an ACME account was not found.
type ErrAccountNotFound struct {
	AccountID string
}

func (e ErrAccountNotFound) Error() string {
	return fmt.Sprintf("ACME account not found: %s", e.AccountID)
}

// ErrOrderNotFound indicates an ACME order was not found.
type ErrOrderNotFound struct {
	OrderID string
}

func (e ErrOrderNotFound) Error() string {
	return fmt.Sprintf("ACME order not found: %s", e.OrderID)
}

// ErrCertificateNotFound indicates a certificate was not found.
type ErrCertificateNotFound struct {
	Identifier string
}

func (e ErrCertificateNotFound) Error() string {
	return fmt.Sprintf("certificate not found: %s", e.Identifier)
}

// ErrChallengeFailed indicates an ACME challenge failed.
type ErrChallengeFailed struct {
	ChallengeType string
	Reason        string
}

func (e ErrChallengeFailed) Error() string {
	return fmt.Sprintf("challenge %s failed: %s", e.ChallengeType, e.Reason)
}

// ErrAttestationFailed indicates TPM attestation failed.
type ErrAttestationFailed struct {
	DeviceSerial string
	Reason       string
}

func (e ErrAttestationFailed) Error() string {
	return fmt.Sprintf("attestation failed for device %s: %s", e.DeviceSerial, e.Reason)
}
