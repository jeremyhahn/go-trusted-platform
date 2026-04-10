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

package helpers

import "os"

// GetRESTEndpoint returns the REST API endpoint for testing
func GetRESTEndpoint() string {
	endpoint := os.Getenv("PLATFORM_REST_URL")
	if endpoint == "" {
		port := os.Getenv("PLATFORM_REST_PORT")
		if port == "" {
			port = "8443"
		}
		endpoint = "http://localhost:" + port
	}
	return endpoint
}

// GetGRPCEndpoint returns the gRPC endpoint for testing
func GetGRPCEndpoint() string {
	endpoint := os.Getenv("PLATFORM_GRPC_URL")
	if endpoint == "" {
		port := os.Getenv("PLATFORM_GRPC_PORT")
		if port == "" {
			port = "10443"
		}
		endpoint = "localhost:" + port
	}
	return endpoint
}

// GetQUICEndpoint returns the QUIC endpoint for testing
func GetQUICEndpoint() string {
	endpoint := os.Getenv("PLATFORM_QUIC_URL")
	if endpoint == "" {
		port := os.Getenv("PLATFORM_QUIC_PORT")
		if port == "" {
			port = "9444"
		}
		endpoint = "localhost:" + port
	}
	return endpoint
}

// GetMCPEndpoint returns the MCP endpoint for testing
func GetMCPEndpoint() string {
	endpoint := os.Getenv("PLATFORM_MCP_URL")
	if endpoint == "" {
		port := os.Getenv("PLATFORM_MCP_PORT")
		if port == "" {
			port = "9445"
		}
		endpoint = "http://localhost:" + port
	}
	return endpoint
}

// GetSocketPath returns the Unix socket path for testing
func GetSocketPath() string {
	path := os.Getenv("PLATFORM_SOCKET_PATH")
	if path == "" {
		path = "/run/platformd.sock"
	}
	return path
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
