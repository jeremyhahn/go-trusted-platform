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

import (
	"net"
	"os"
	"strconv"
	"strings"
)

// Endpoint environment variables. The integration runner
// (build/docker/devcontainer/run-integration-tests.sh) exports every one of
// them, built from the same port variable it passes to `platformd serve`.
// These are also the names the suites that read the environment directly use.
const (
	envRESTEndpoint = EnvRESTEndpoint
	envGRPCEndpoint = EnvGRPCEndpoint
	envQUICEndpoint = EnvQUICEndpoint
	envMCPEndpoint  = EnvMCPEndpoint
	envSocketPath   = "PLATFORM_SOCKET_PATH"
)

// The runner's exported endpoint variables, for suites that resolve them
// through RequireEndpoint. PLATFORM_API_ENDPOINT carries the same REST URL
// as PLATFORM_REST_ENDPOINT; older suites read it.
const (
	EnvRESTEndpoint = "PLATFORM_REST_ENDPOINT"
	EnvAPIEndpoint  = "PLATFORM_API_ENDPOINT"
	EnvGRPCEndpoint = "PLATFORM_GRPC_ENDPOINT"
	EnvQUICEndpoint = "PLATFORM_QUIC_ENDPOINT"
	EnvMCPEndpoint  = "PLATFORM_MCP_ENDPOINT"
)

// EndpointUnsetError reports an endpoint variable the environment does not
// carry. The runner picks platformd's ports at run time (#997), so there is
// no fixed port to fall back to.
type EndpointUnsetError struct {
	Variable string
}

func (e *EndpointUnsetError) Error() string {
	return e.Variable + " is not set: the integration runner exports it with the port platformd was started on (#997)"
}

// EndpointInvalidError reports an endpoint variable whose value has no
// usable host:port.
type EndpointInvalidError struct {
	Variable string
	Value    string
	Reason   string
}

func (e *EndpointInvalidError) Error() string {
	return e.Variable + "=" + strconv.Quote(e.Value) + " is not an endpoint: " + e.Reason
}

// RequireEndpoint returns the value of the endpoint variable, as the runner
// exported it ("host:port", or a URL with a scheme for REST and MCP). An
// unset variable is an *EndpointUnsetError and a value without a host and a
// port in 1..65535 is an *EndpointInvalidError: a suite never dials a port
// the runner did not choose.
func RequireEndpoint(variable string) (string, error) {
	value := os.Getenv(variable)
	if value == "" {
		return "", &EndpointUnsetError{Variable: variable}
	}
	hostPort := value
	if _, rest, found := strings.Cut(value, "://"); found {
		hostPort, _, _ = strings.Cut(rest, "/")
	}
	host, port, err := net.SplitHostPort(hostPort)
	if err != nil {
		return "", &EndpointInvalidError{Variable: variable, Value: value, Reason: err.Error()}
	}
	if host == "" {
		return "", &EndpointInvalidError{Variable: variable, Value: value, Reason: "no host"}
	}
	number, err := strconv.Atoi(port)
	if err != nil || number < 1 || number > 65535 {
		return "", &EndpointInvalidError{Variable: variable, Value: value, Reason: "port " + strconv.Quote(port) + " is not in 1..65535"}
	}
	return value, nil
}

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
