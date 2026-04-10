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

// Package network provides integration test helpers for network authentication services.
// These helpers provide reusable functions for certificate generation, OVS management,
// OPA policy loading, and performing assertions in integration tests.
package network

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"strings"
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

	// EnvPlatformdGRPCEndpoint is the environment variable for platformd gRPC endpoint.
	// Default: 127.0.0.1:8443
	EnvPlatformdGRPCEndpoint = "PLATFORMD_GRPC_ENDPOINT"

	// EnvPlatformAPIEndpoint is the environment variable for platform-api REST endpoint.
	// Default: 127.0.0.1:8080
	EnvPlatformAPIEndpoint = "PLATFORM_API_ENDPOINT"

	// EnvPlatformQUICEndpoint is the environment variable for platform QUIC endpoint.
	// Default: 127.0.0.1:9444
	EnvPlatformQUICEndpoint = "PLATFORM_QUIC_ENDPOINT"

	// EnvPlatformMCPEndpoint is the environment variable for platform MCP endpoint.
	// Default: 127.0.0.1:9445
	EnvPlatformMCPEndpoint = "PLATFORM_MCP_ENDPOINT"

	// EnvPlatformdSocket is the environment variable for platformd Unix socket.
	// Default: /var/run/platformd/platformd.sock
	EnvPlatformdSocket = "PLATFORMD_SOCKET"

	// EnvNetworkAuthEndpoint is the environment variable for network auth endpoint.
	// Default: 127.0.0.1:8443
	EnvNetworkAuthEndpoint = "NETWORK_AUTH_ENDPOINT"

	// EnvOPAEndpoint is the environment variable for OPA policy engine endpoint.
	// Default: 127.0.0.1:8181
	EnvOPAEndpoint = "OPA_ENDPOINT"
)

// =============================================================================
// Default Endpoints
// =============================================================================

const (
	// DefaultPlatformdGRPCEndpoint is the default platformd gRPC endpoint.
	DefaultPlatformdGRPCEndpoint = "127.0.0.1:10443"

	// DefaultPlatformAPIEndpoint is the default platform-api REST endpoint.
	DefaultPlatformAPIEndpoint = "127.0.0.1:8443"

	// DefaultPlatformQUICEndpoint is the default platform QUIC endpoint.
	DefaultPlatformQUICEndpoint = "127.0.0.1:9444"

	// DefaultPlatformMCPEndpoint is the default platform MCP endpoint.
	DefaultPlatformMCPEndpoint = "127.0.0.1:9445"

	// DefaultPlatformdSocket is the default platformd Unix socket.
	DefaultPlatformdSocket = "/run/platformd.sock"

	// DefaultNetworkAuthEndpoint is the default network authentication endpoint.
	DefaultNetworkAuthEndpoint = "127.0.0.1:8443"

	// DefaultOPAEndpoint is the default OPA policy engine endpoint.
	DefaultOPAEndpoint = "127.0.0.1:8181"
)

// =============================================================================
// Timeout Constants
// =============================================================================

const (
	// DefaultTestTimeout is the default timeout for integration tests.
	DefaultTestTimeout = 30 * time.Second

	// LongRunningTestTimeout is the timeout for long-running tests.
	LongRunningTestTimeout = 5 * time.Minute

	// HTTPClientTimeout is the timeout for HTTP client operations.
	HTTPClientTimeout = 5 * time.Second

	// NonceSize is the size of generated test nonces in bytes.
	NonceSize = 32
)

// =============================================================================
// Endpoint Configuration
// =============================================================================

// ServiceEndpoints contains all configured service endpoints.
type ServiceEndpoints struct {
	PlatformdGRPC string
	PlatformAPI   string
	PlatformQUIC  string
	PlatformMCP   string
	PlatformdSock string
	NetworkAuth   string
	OPA           string
}

// GetServiceEndpoints returns service endpoints from environment
// variables with sensible defaults.
func GetServiceEndpoints() ServiceEndpoints {
	return ServiceEndpoints{
		PlatformdGRPC: getEnvOrDefault(EnvPlatformdGRPCEndpoint, DefaultPlatformdGRPCEndpoint),
		PlatformAPI:   getEnvOrDefault(EnvPlatformAPIEndpoint, DefaultPlatformAPIEndpoint),
		PlatformQUIC:  getEnvOrDefault(EnvPlatformQUICEndpoint, DefaultPlatformQUICEndpoint),
		PlatformMCP:   getEnvOrDefault(EnvPlatformMCPEndpoint, DefaultPlatformMCPEndpoint),
		PlatformdSock: getEnvOrDefault(EnvPlatformdSocket, DefaultPlatformdSocket),
		NetworkAuth:   getEnvOrDefault(EnvNetworkAuthEndpoint, DefaultNetworkAuthEndpoint),
		OPA:           getEnvOrDefault(EnvOPAEndpoint, DefaultOPAEndpoint),
	}
}

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

// SkipIfNoOVS skips the test if Open vSwitch is not available.
// It checks for both the ovs-vsctl command and the OVS database socket.
func SkipIfNoOVS(t *testing.T) {
	t.Helper()
	if !CheckOVSAvailable() {
		t.Skip("Skipping test: Open vSwitch not available")
	}
}

// SkipIfNoOPA skips the test if OPA is not running.
// It checks if the OPA endpoint is reachable and responding.
func SkipIfNoOPA(t *testing.T) {
	t.Helper()
	endpoint := getEnvOrDefault(EnvOPAEndpoint, DefaultOPAEndpoint)
	if !CheckOPAAvailable(endpoint) {
		t.Skip("Skipping test: OPA not available at " + endpoint)
	}
}

// =============================================================================
// Test Data Generators
// =============================================================================

// GenerateUniquePortID generates a unique port identifier with the given prefix.
// The ID includes a timestamp to ensure uniqueness across test runs.
// Format: prefix-YYYYMMDDHHMMSS-nanoseconds
func GenerateUniquePortID(prefix string) string {
	now := time.Now()
	return fmt.Sprintf("%s-%s-%09d", prefix, now.Format("20060102150405"), now.Nanosecond())
}

// GenerateTestNonce generates a cryptographically random nonce for testing.
// Returns a 32-byte random nonce suitable for authentication challenges.
func GenerateTestNonce() []byte {
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		// Fall back to timestamp-based nonce if crypto/rand fails
		timestamp := time.Now().UnixNano()
		for i := 0; i < NonceSize; i++ {
			nonce[i] = byte(timestamp >> (i % 8 * 8))
		}
	}
	return nonce
}

// GenerateTestCertificate generates a self-signed X.509 certificate for testing.
// The certificate is valid for 24 hours and uses ECDSA P-256.
func GenerateTestCertificate(cn string) (certPEM, keyPEM []byte, err error) {
	return GenerateTestCertificateWithOIDs(cn, nil)
}

// GenerateTestCertificateWithOIDs generates a self-signed X.509 certificate
// with custom OID extensions for testing network authentication scenarios.
// The certificate is valid for 24 hours and uses ECDSA P-256.
func GenerateTestCertificateWithOIDs(cn string, oids []string) (certPEM, keyPEM []byte, err error) {
	// Generate ECDSA private key
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate private key: %w", err)
	}

	// Generate serial number
	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	// Create certificate template
	now := time.Now()
	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName:   cn,
			Organization: []string{"Test Organization"},
		},
		NotBefore:             now,
		NotAfter:              now.Add(24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
	}

	// Add custom OID extensions if provided
	for _, oidStr := range oids {
		oid, parseErr := parseOID(oidStr)
		if parseErr != nil {
			return nil, nil, fmt.Errorf("failed to parse OID %s: %w", oidStr, parseErr)
		}

		ext := pkix.Extension{
			Id:       oid,
			Critical: false,
			Value:    []byte(oidStr), // Store OID string as value for testing
		}
		template.ExtraExtensions = append(template.ExtraExtensions, ext)
	}

	// Create self-signed certificate
	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	// Encode certificate to PEM
	certBuf := new(bytes.Buffer)
	if err := pem.Encode(certBuf, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		return nil, nil, fmt.Errorf("failed to encode certificate PEM: %w", err)
	}

	// Encode private key to PEM
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to marshal private key: %w", err)
	}

	keyBuf := new(bytes.Buffer)
	if err := pem.Encode(keyBuf, &pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}); err != nil {
		return nil, nil, fmt.Errorf("failed to encode key PEM: %w", err)
	}

	return certBuf.Bytes(), keyBuf.Bytes(), nil
}

// parseOID parses a dotted-decimal OID string into an asn1.ObjectIdentifier.
func parseOID(oidStr string) (asn1.ObjectIdentifier, error) {
	parts := strings.Split(oidStr, ".")
	if len(parts) < 2 {
		return nil, fmt.Errorf("invalid OID format: %s", oidStr)
	}

	oid := make(asn1.ObjectIdentifier, len(parts))
	for i, part := range parts {
		var n int
		if _, err := fmt.Sscanf(part, "%d", &n); err != nil {
			return nil, fmt.Errorf("invalid OID component %s: %w", part, err)
		}
		oid[i] = n
	}
	return oid, nil
}

// =============================================================================
// Context Helpers
// =============================================================================

// DefaultTestContext returns a context with a 30-second timeout for integration tests.
func DefaultTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), DefaultTestTimeout)
}

// LongRunningTestContext returns a context with a 5-minute timeout for tests
// that may take more time (e.g., certificate operations, policy evaluation).
func LongRunningTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), LongRunningTestTimeout)
}

// ShortTestContext returns a context with a 10-second timeout for quick operations.
func ShortTestContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

// =============================================================================
// OVS Helpers
// =============================================================================

// CheckOVSAvailable checks if Open vSwitch is available on the system.
// Returns true if ovs-vsctl command exists and the OVS database socket is accessible.
func CheckOVSAvailable() bool {
	// Check if ovs-vsctl command exists
	_, err := exec.LookPath("ovs-vsctl")
	if err != nil {
		return false
	}

	// Check if OVS database socket exists
	socketPath := os.Getenv("OVS_DB_SOCKET")
	if socketPath == "" {
		socketPath = "/var/run/openvswitch/db.sock"
	}

	if _, err := os.Stat(socketPath); os.IsNotExist(err) {
		return false
	}

	return true
}

// CreateTestBridge creates an OVS bridge for testing.
// The bridge name should be unique to avoid conflicts with other tests.
func CreateTestBridge(name string) error {
	cmd := exec.Command("ovs-vsctl", "--may-exist", "add-br", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create bridge %s: %w, output: %s", name, err, string(output))
	}
	return nil
}

// DeleteTestBridge deletes an OVS bridge.
// Silently succeeds if the bridge does not exist.
func DeleteTestBridge(name string) error {
	cmd := exec.Command("ovs-vsctl", "--if-exists", "del-br", name)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to delete bridge %s: %w, output: %s", name, err, string(output))
	}
	return nil
}

// CreateTestPort creates an internal port on the specified OVS bridge.
// The port name should be unique within the bridge.
func CreateTestPort(bridge, portName string) error {
	cmd := exec.Command("ovs-vsctl", "--may-exist", "add-port", bridge, portName, "--", "set", "interface", portName, "type=internal")
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("failed to create port %s on bridge %s: %w, output: %s", portName, bridge, err, string(output))
	}
	return nil
}

// =============================================================================
// OPA Helpers
// =============================================================================

// CheckOPAAvailable checks if OPA is available at the specified endpoint.
// Returns true if OPA responds to a health check request.
func CheckOPAAvailable(endpoint string) bool {
	url := fmt.Sprintf("http://%s/health", endpoint)

	client := &http.Client{Timeout: HTTPClientTimeout}
	resp, err := client.Get(url)
	if err != nil {
		return false
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK
}

// LoadTestPolicy loads a Rego policy into OPA for testing.
// The policyPath specifies the OPA policy path (e.g., "network/auth").
// The regoContent contains the Rego policy source code.
func LoadTestPolicy(endpoint, policyPath, regoContent string) error {
	url := fmt.Sprintf("http://%s/v1/policies/%s", endpoint, policyPath)

	req, err := http.NewRequest(http.MethodPut, url, strings.NewReader(regoContent))
	if err != nil {
		return fmt.Errorf("failed to create policy request: %w", err)
	}
	req.Header.Set("Content-Type", "text/plain")

	client := &http.Client{Timeout: HTTPClientTimeout}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to load policy: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK && resp.StatusCode != http.StatusCreated {
		return fmt.Errorf("failed to load policy: status %d", resp.StatusCode)
	}

	return nil
}

// =============================================================================
// Certificate Helpers
// =============================================================================

// ParseCertificatePEM parses a PEM-encoded certificate and returns the x509.Certificate.
func ParseCertificatePEM(pemData []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemData)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block")
	}

	if block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("unexpected PEM block type: %s", block.Type)
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

// ExtractOIDsFromCert extracts custom OID extensions from a certificate.
// Returns a slice of OID strings in dotted-decimal format.
func ExtractOIDsFromCert(cert *x509.Certificate) []string {
	var oids []string

	for _, ext := range cert.Extensions {
		// Skip well-known extensions
		if isWellKnownOID(ext.Id) {
			continue
		}
		oids = append(oids, ext.Id.String())
	}

	return oids
}

// isWellKnownOID returns true if the OID is a standard X.509 extension OID.
func isWellKnownOID(oid asn1.ObjectIdentifier) bool {
	// Well-known X.509 extension OID prefixes
	wellKnown := []asn1.ObjectIdentifier{
		{2, 5, 29},              // id-ce (X.509 certificate extensions)
		{1, 3, 6, 1, 5, 5},      // id-pkix
		{2, 16, 840, 1, 113730}, // Netscape
	}

	for _, prefix := range wellKnown {
		if hasPrefix(oid, prefix) {
			return true
		}
	}

	return false
}

// hasPrefix checks if an OID has the specified prefix.
func hasPrefix(oid, prefix asn1.ObjectIdentifier) bool {
	if len(oid) < len(prefix) {
		return false
	}

	for i := range prefix {
		if oid[i] != prefix[i] {
			return false
		}
	}

	return true
}

// =============================================================================
// Utility Functions
// =============================================================================

// getEnvOrDefault returns the environment variable value or the default if not set.
func getEnvOrDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

// GetNetworkAuthEndpoint returns the network authentication endpoint from
// environment variables or the default.
func GetNetworkAuthEndpoint() string {
	return getEnvOrDefault(EnvNetworkAuthEndpoint, DefaultNetworkAuthEndpoint)
}

// GetOPAEndpoint returns the OPA endpoint from environment variables or the default.
func GetOPAEndpoint() string {
	return getEnvOrDefault(EnvOPAEndpoint, DefaultOPAEndpoint)
}
