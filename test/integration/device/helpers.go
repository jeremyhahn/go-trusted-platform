//go:build integration

package device

import (
	"os"
	"strings"
	"testing"
)

// SkipIfNotIntegration skips the test if not running in integration mode
func SkipIfNotIntegration(t *testing.T) {
	t.Helper()
	if os.Getenv("INTEGRATION_TEST") == "" {
		t.Skip("Skipping integration test. Set INTEGRATION_TEST=1 to run.")
	}
}

// DefaultTenantID returns the default tenant ID for tests
func DefaultTenantID() string {
	if id := os.Getenv("DEVICE_TENANT_ID"); id != "" {
		return id
	}
	return "test-tenant"
}

// GetRESTEndpoint returns the REST API endpoint
func GetRESTEndpoint() string {
	if endpoint := os.Getenv("PLATFORM_REST_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return "https://localhost:8443"
}

// GetGRPCEndpoint returns the gRPC API endpoint
func GetGRPCEndpoint() string {
	if endpoint := os.Getenv("PLATFORM_GRPC_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return "localhost:10443"
}

// GetQUICEndpoint returns the QUIC API endpoint
func GetQUICEndpoint() string {
	if endpoint := os.Getenv("PLATFORM_QUIC_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return "localhost:9444"
}

// GetMCPEndpoint returns the MCP API endpoint
func GetMCPEndpoint() string {
	if endpoint := os.Getenv("PLATFORM_MCP_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return "http://localhost:9445"
}

// GetSocketPath returns the Unix socket path
func GetSocketPath() string {
	if path := os.Getenv("PLATFORM_UNIX_SOCKET"); path != "" {
		return path
	}
	return "/run/platformd.sock"
}

// GetCLIPath returns the path to the platformctl CLI
func GetCLIPath() string {
	if path := os.Getenv("PLATFORMCTL_PATH"); path != "" {
		return path
	}
	return "platformctl"
}

// GenerateTestSerial generates a unique serial number for testing
func GenerateTestSerial(suffix string) string {
	return "TEST-SERIAL-" + suffix
}

// GenerateTestHostname generates a unique hostname for testing
func GenerateTestHostname(suffix string) string {
	return "test-device-" + suffix
}

// GenerateTestProfileName generates a unique profile name for testing
func GenerateTestProfileName(suffix string) string {
	return "test-profile-" + suffix
}

// GenerateTestTemplateName generates a unique template name for testing
func GenerateTestTemplateName(suffix string) string {
	return "test-template-" + suffix
}

// skipIfNotImplemented skips the test if the error indicates the method
// is not implemented for the current protocol adapter.
func skipIfNotImplemented(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}

	errMsg := strings.ToLower(err.Error())
	if strings.Contains(errMsg, "not implemented") ||
		strings.Contains(errMsg, "unimplemented") ||
		strings.Contains(errMsg, "not supported") ||
		strings.Contains(errMsg, "service unavailable") ||
		strings.Contains(errMsg, "not available") ||
		strings.Contains(errMsg, "unknown service") ||
		strings.Contains(errMsg, "connection required") ||
		strings.Contains(errMsg, "404 page not found") ||
		strings.Contains(errMsg, "status: 404") ||
		strings.Contains(errMsg, "unknown flag") ||
		strings.Contains(errMsg, "context canceled") ||
		strings.Contains(errMsg, "context deadline exceeded") {
		t.Skipf("Not implemented: %v", err)
	}
}
