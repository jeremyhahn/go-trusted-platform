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
	"google.golang.org/grpc/credentials/local"

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/wire/quicwire"
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

// QUICTLSConfig returns a TLS config for QUIC connections with mTLS
// certificates if available, defaulting NextProtos to the ALPN protocol the
// daemon actually advertises.
//
// Called with no arguments it offers quicwire.ALPNProtocol -- the single protocol
// pkg/api/quic/config.go advertises -- so an adapter cannot offer a wrong one
// by writing a string. Four adapters did exactly that (attestation-quic,
// device-quic, iam-quic, tenant-quic) and failed the handshake with
// no_application_protocol BEFORE opening a stream, so their request framing
// never executed and every call failed in a way that looked like a refusal
// (#486, #480). Taking the protocol from the server's own constant makes the
// wrong value unconstructible rather than merely detectable.
//
// An explicit override is still accepted, because a negative test must be
// able to offer a deliberately wrong protocol: a helper that makes the bug
// unconstructible must not also make the test for the bug unwritable.
func QUICTLSConfig(overrideALPN ...string) *tls.Config {
	tlsConfig := TLSConfigOrInsecure()
	tlsConfig.NextProtos = []string{quicwire.ALPNProtocol}
	if len(overrideALPN) > 0 {
		tlsConfig.NextProtos = overrideALPN
	}
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

// GRPCUnixCredentials returns the gRPC transport credentials for platformd's
// Unix domain socket. The UDS is the daemon's one sanctioned non-TLS transport:
// it authenticates the caller by SO_PEERCRED and is scoped by file-system
// permissions (docs/daemon/architecture.md), so a TLS dial fails its handshake
// against it (#532). Local credentials send no handshake bytes, like insecure
// ones, but refuse to carry a dial that is not to a local address, so a
// misrouted adapter fails instead of speaking plaintext over the network.
func GRPCUnixCredentials() grpc.DialOption {
	return grpc.WithTransportCredentials(local.NewCredentials())
}

// MCPBaseURL returns the MCP server base URL for endpoint. platformd serves
// MCP over TLS 1.3 only (#844), so an endpoint without a scheme gets https://.
// An explicit scheme is kept as given, so a negative test can still dial
// http:// and assert the refusal.
func MCPBaseURL(endpoint string) string {
	if strings.HasPrefix(endpoint, "http://") || strings.HasPrefix(endpoint, "https://") {
		return endpoint
	}
	return "https://" + endpoint
}

// MCPEndpointURL returns the full MCP JSON-RPC URL for endpoint; see
// MCPBaseURL for the scheme rules. Pair it with NewHTTPClient.
func MCPEndpointURL(endpoint string) string {
	return MCPBaseURL(endpoint) + "/mcp"
}
