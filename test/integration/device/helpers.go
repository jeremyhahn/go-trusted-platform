//go:build integration

package device

import (
	"os"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

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
	return helpers.GetRESTEndpoint()
}

// GetGRPCEndpoint returns the gRPC API endpoint
func GetGRPCEndpoint() string {
	if endpoint := os.Getenv("PLATFORM_GRPC_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return helpers.GetGRPCEndpoint()
}

// GetQUICEndpoint returns the QUIC API endpoint
func GetQUICEndpoint() string {
	if endpoint := os.Getenv("PLATFORM_QUIC_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return helpers.GetQUICEndpoint()
}

// GetMCPEndpoint returns the MCP API endpoint
func GetMCPEndpoint() string {
	if endpoint := os.Getenv("PLATFORM_MCP_ENDPOINT"); endpoint != "" {
		return endpoint
	}
	return helpers.GetMCPEndpoint()
}

// GetSocketPath returns the Unix socket path
func GetSocketPath() string {
	if path := os.Getenv("PLATFORM_UNIX_SOCKET"); path != "" {
		return path
	}
	return helpers.GetSocketPath()
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
