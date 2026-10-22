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

// This file carries no build tag so endpoints_test.go can check, in the unit
// suite, that it reads the names the integration runner exports (#502).

package helpers

import "os"

// Endpoint environment variables. The integration runner
// (build/docker/devcontainer/run-integration-tests.sh) exports every one of
// them, built from the same port variable it passes to `platformd serve`.
// These are also the names the suites that read the environment directly use.
const (
	envRESTEndpoint = "PLATFORM_REST_ENDPOINT"
	envGRPCEndpoint = "PLATFORM_GRPC_ENDPOINT"
	envQUICEndpoint = "PLATFORM_QUIC_ENDPOINT"
	envMCPEndpoint  = "PLATFORM_MCP_ENDPOINT"
	envSocketPath   = "PLATFORM_SOCKET_PATH"
)

// Defaults for running a suite by hand, outside the runner, against a
// platformd on its standard ports. Under the runner they never apply: it sets
// every variable above. REST and MCP serve TLS only (#844).
const (
	defaultRESTEndpoint = "https://localhost:8443"
	defaultGRPCEndpoint = "localhost:10443"
	defaultQUICEndpoint = "localhost:9444"
	defaultMCPEndpoint  = "https://localhost:9445"
	defaultSocketPath   = "/run/platformd.sock"
)

// The harness webservice listener (test/integration/config.yaml
// webservices[0]) serves the control plane's webservice router, which the
// daemon REST server does not: the gateway-facing routes such as
// POST /api/v1/gateway/telemetry (docs/gateway/api.md). Its port comes from
// that config, not a serve flag; the runner exports the endpoint built from
// the same port.
const (
	envWebServiceEndpoint     = "PLATFORM_WEBSERVICE_ENDPOINT"
	defaultWebServiceEndpoint = "https://localhost:8444"
)

// envOrDefault returns the value of the environment variable name, or
// fallback when it is unset or empty.
func envOrDefault(name, fallback string) string {
	if value := os.Getenv(name); value != "" {
		return value
	}
	return fallback
}

// GetRESTEndpoint returns the REST API endpoint for testing
func GetRESTEndpoint() string {
	return envOrDefault(envRESTEndpoint, defaultRESTEndpoint)
}

// GetGRPCEndpoint returns the gRPC endpoint for testing
func GetGRPCEndpoint() string {
	return envOrDefault(envGRPCEndpoint, defaultGRPCEndpoint)
}

// GetQUICEndpoint returns the QUIC endpoint for testing
func GetQUICEndpoint() string {
	return envOrDefault(envQUICEndpoint, defaultQUICEndpoint)
}

// GetMCPEndpoint returns the MCP endpoint for testing
func GetMCPEndpoint() string {
	return envOrDefault(envMCPEndpoint, defaultMCPEndpoint)
}

// GetSocketPath returns the Unix socket path for testing
func GetSocketPath() string {
	return envOrDefault(envSocketPath, defaultSocketPath)
}

// GetWebServiceEndpoint returns the harness webservice listener's endpoint.
func GetWebServiceEndpoint() string {
	return envOrDefault(envWebServiceEndpoint, defaultWebServiceEndpoint)
}

// EndpointConfig holds all protocol endpoints for testing
type EndpointConfig struct {
	REST   string
	GRPC   string
	QUIC   string
	MCP    string
	Socket string
}

// GetEndpointConfig returns all configured endpoints
func GetEndpointConfig() *EndpointConfig {
	return &EndpointConfig{
		REST:   GetRESTEndpoint(),
		GRPC:   GetGRPCEndpoint(),
		QUIC:   GetQUICEndpoint(),
		MCP:    GetMCPEndpoint(),
		Socket: GetSocketPath(),
	}
}

// GetCertPath returns the path to the test client certificate
func GetCertPath() string {
	path := os.Getenv("PLATFORM_TEST_CERT")
	if path == "" {
		path = "/etc/trusted-platform/certs/client.pem"
	}
	return path
}

// GetKeyPath returns the path to the test client key
func GetKeyPath() string {
	path := os.Getenv("PLATFORM_TEST_KEY")
	if path == "" {
		path = "/etc/trusted-platform/certs/client-key.pem"
	}
	return path
}

// GetCAPath returns the path to the CA certificate
func GetCAPath() string {
	path := os.Getenv("PLATFORM_CA_CERT")
	if path == "" {
		path = "/etc/trusted-platform/certs/ca.pem"
	}
	return path
}
