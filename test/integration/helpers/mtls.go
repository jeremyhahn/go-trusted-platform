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

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"os"
	"strings"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/credentials/insecure"
)

// Environment variable names for mTLS client certificate configuration.
const (
	EnvClientCert = "PLATFORM_CLIENT_CERT"
	EnvClientKey  = "PLATFORM_CLIENT_KEY"
	EnvCACert     = "PLATFORM_CA_CERT"
)

// LoadMTLSConfig loads mTLS client certificates from environment variables.
// Returns nil if the mTLS environment variables are not set.
func LoadMTLSConfig() *tls.Config {
	certFile := os.Getenv(EnvClientCert)
	keyFile := os.Getenv(EnvClientKey)
	caFile := os.Getenv(EnvCACert)

	if certFile == "" || keyFile == "" || caFile == "" {
		return nil
	}

	cert, err := tls.LoadX509KeyPair(certFile, keyFile)
	if err != nil {
		return nil
	}

	caCert, err := os.ReadFile(caFile)
	if err != nil {
		return nil
	}

	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(caCert) {
		return nil
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		RootCAs:      caPool,
	}
}

// MTLSEnabled returns true if mTLS environment variables are configured.
func MTLSEnabled() bool {
	return LoadMTLSConfig() != nil
}

// TLSConfigOrInsecure returns the mTLS config loaded from environment variables.
// mTLS is mandatory for integration tests; this function panics if the
// required environment variables are not configured.
func TLSConfigOrInsecure() *tls.Config {
	tlsConfig := LoadMTLSConfig()
	if tlsConfig == nil {
		panic("mtls: mTLS environment variables not configured; set PLATFORM_CLIENT_CERT, PLATFORM_CLIENT_KEY, and PLATFORM_CA_CERT")
	}
	tlsConfig.MinVersion = tls.VersionTLS13
	return tlsConfig
}

// QUICTLSConfig returns a TLS config suitable for QUIC connections with mTLS
// certificates if available. It sets the required NextProtos and MinVersion
// fields for the QUIC protocol.
func QUICTLSConfig(nextProtos []string) *tls.Config {
	tlsConfig := TLSConfigOrInsecure()
	tlsConfig.NextProtos = nextProtos
	tlsConfig.MinVersion = tls.VersionTLS13
	return tlsConfig
}

// NewHTTPClient creates an HTTP client configured with mTLS certificates.
// mTLS is mandatory for integration tests.
func NewHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: TLSConfigOrInsecure(),
		},
	}
}

// NewPlainHTTPClient creates an HTTP client without TLS configuration,
// suitable for connecting to plain HTTP endpoints such as the MCP server.
func NewPlainHTTPClient(timeout time.Duration) *http.Client {
	return &http.Client{
		Timeout:   timeout,
		Transport: &http.Transport{},
	}
}

// GRPCTransportCredentials returns gRPC transport credentials configured with
// mTLS. mTLS is mandatory for integration tests; this function panics if the
// required environment variables are not configured.
func GRPCTransportCredentials() grpc.DialOption {
	tlsConfig := LoadMTLSConfig()
	if tlsConfig == nil {
		panic("mtls: mTLS environment variables not configured; set PLATFORM_CLIENT_CERT, PLATFORM_CLIENT_KEY, and PLATFORM_CA_CERT")
	}
	tlsConfig.MinVersion = tls.VersionTLS13
	return grpc.WithTransportCredentials(credentials.NewTLS(tlsConfig))
}

// GRPCUnixCredentials returns insecure gRPC transport credentials for use
// with Unix domain sockets. Unix sockets do not use TLS since they provide
// kernel-level access control through file system permissions.
func GRPCUnixCredentials() grpc.DialOption {
	return grpc.WithTransportCredentials(insecure.NewCredentials())
}

// MCPEndpointURL constructs the full MCP endpoint URL. The MCP server always
// serves plain HTTP (not HTTPS), so this function always uses the http scheme.
// Even when mTLS is enabled for other protocols, the MCP server operates over
// plain HTTP on its dedicated port.
func MCPEndpointURL(endpoint string) string {
	// If the endpoint already has a scheme, return it with /mcp appended
	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		return endpoint + "/mcp"
	}
	return "http://" + endpoint + "/mcp"
}
