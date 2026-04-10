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

package ca

import (
	"fmt"
	"os"
	"testing"
)

// Environment variable names for service endpoints
const (
	EnvPlatformGRPCEndpoint = "PLATFORM_GRPC_ENDPOINT"
	EnvPlatformRESTEndpoint = "PLATFORM_REST_ENDPOINT"
	EnvPlatformQUICEndpoint = "PLATFORM_QUIC_ENDPOINT"
	EnvPlatformMCPEndpoint  = "PLATFORM_MCP_ENDPOINT"
	EnvPlatformUnixSocket   = "PLATFORM_UNIX_SOCKET"
	EnvPlatformCTL          = "PLATFORMCTL_PATH"
)

// ServiceEndpoints contains default endpoints for all protocols.
type ServiceEndpoints struct {
	PlatformGRPC string
	PlatformREST string
	PlatformQUIC string
	PlatformMCP  string
	PlatformUnix string
	PlatformCTL  string
}

// GetServiceEndpoints returns the default service endpoints.
func GetServiceEndpoints() *ServiceEndpoints {
	return &ServiceEndpoints{
		PlatformGRPC: "localhost:10443",
		PlatformREST: "http://localhost:8443",
		PlatformQUIC: "localhost:9444",
		PlatformMCP:  "localhost:9445",
		PlatformUnix: "/run/platformd.sock",
		PlatformCTL:  "platformctl",
	}
}

// SkipIfNotIntegration skips the test if not running integration tests.
func SkipIfNotIntegration(t *testing.T) {
	if os.Getenv("INTEGRATION_TEST") == "" {
		t.Skip("Skipping integration test: INTEGRATION_TEST not set")
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

// ErrCANotInitialized indicates the CA is not initialized.
type ErrCANotInitialized struct{}

func (e ErrCANotInitialized) Error() string {
	return "CA not initialized"
}

// ErrCANotAvailable indicates the CA is not available.
type ErrCANotAvailable struct {
	Reason string
}

func (e ErrCANotAvailable) Error() string {
	return fmt.Sprintf("CA not available: %s", e.Reason)
}

// ErrCertificateNotFound indicates a certificate was not found.
type ErrCertificateNotFound struct {
	Identifier string
}

func (e ErrCertificateNotFound) Error() string {
	return fmt.Sprintf("certificate not found: %s", e.Identifier)
}

// ErrCertificateExpired indicates a certificate has expired.
type ErrCertificateExpired struct {
	Subject   string
	ExpiredAt string
}

func (e ErrCertificateExpired) Error() string {
	return fmt.Sprintf("certificate %s expired at %s", e.Subject, e.ExpiredAt)
}

// ErrCertificateRevoked indicates a certificate has been revoked.
type ErrCertificateRevoked struct {
	Subject string
	Serial  string
}

func (e ErrCertificateRevoked) Error() string {
	return fmt.Sprintf("certificate %s (serial: %s) is revoked", e.Subject, e.Serial)
}

// ErrCertificateVerificationFailed indicates certificate verification failed.
type ErrCertificateVerificationFailed struct {
	Subject string
	Reason  string
}

func (e ErrCertificateVerificationFailed) Error() string {
	return fmt.Sprintf("certificate verification failed for %s: %s", e.Subject, e.Reason)
}

// ErrInvalidSerial indicates an invalid serial number.
type ErrInvalidSerial struct {
	Serial string
}

func (e ErrInvalidSerial) Error() string {
	return fmt.Sprintf("invalid serial number: %s", e.Serial)
}

// ErrInvalidStoreType indicates an invalid store type.
type ErrInvalidStoreType struct {
	Store string
}

func (e ErrInvalidStoreType) Error() string {
	return fmt.Sprintf("invalid store type: %s", e.Store)
}

// ErrInvalidKeyAlgorithm indicates an invalid key algorithm.
type ErrInvalidKeyAlgorithm struct {
	Algorithm string
}

func (e ErrInvalidKeyAlgorithm) Error() string {
	return fmt.Sprintf("invalid key algorithm: %s", e.Algorithm)
}

// ErrCRLNotFound indicates a CRL was not found.
type ErrCRLNotFound struct {
	Issuer string
}

func (e ErrCRLNotFound) Error() string {
	return fmt.Sprintf("CRL not found for issuer: %s", e.Issuer)
}

// ErrCRLGenerationFailed indicates CRL generation failed.
type ErrCRLGenerationFailed struct {
	Reason string
}

func (e ErrCRLGenerationFailed) Error() string {
	return fmt.Sprintf("CRL generation failed: %s", e.Reason)
}

// ErrExportFailed indicates an export operation failed.
type ErrExportFailed struct {
	Type   string
	Path   string
	Reason string
}

func (e ErrExportFailed) Error() string {
	return fmt.Sprintf("%s export to %s failed: %s", e.Type, e.Path, e.Reason)
}

// ErrInstallFailed indicates CA certificate installation failed.
type ErrInstallFailed struct {
	Reason string
}

func (e ErrInstallFailed) Error() string {
	return fmt.Sprintf("CA certificate installation failed: %s", e.Reason)
}

// ErrUninstallFailed indicates CA certificate uninstallation failed.
type ErrUninstallFailed struct {
	Reason string
}

func (e ErrUninstallFailed) Error() string {
	return fmt.Sprintf("CA certificate uninstallation failed: %s", e.Reason)
}

// ErrNotImplemented indicates a feature is not implemented.
type ErrNotImplemented struct {
	Feature string
}

func (e ErrNotImplemented) Error() string {
	return fmt.Sprintf("not implemented: %s", e.Feature)
}

// ErrCLIConfigCreationFailed indicates failure to create the temporary CLI config file.
type ErrCLIConfigCreationFailed struct {
	Cause error
}

func (e ErrCLIConfigCreationFailed) Error() string {
	return fmt.Sprintf("CLI config creation failed: %v", e.Cause)
}

func (e ErrCLIConfigCreationFailed) Unwrap() error {
	return e.Cause
}
