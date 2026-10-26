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

	// EnvTenantClientCert and EnvTenantClientKey name the harness
	// credential bound to ForeignTenantID (tenant-client-bundle.pem). It
	// chains to the same CA as the admin credential.
	EnvTenantClientCert = "PLATFORM_TENANT_CLIENT_CERT"
	EnvTenantClientKey  = "PLATFORM_TENANT_CLIENT_KEY"
)

// HarnessTenantID is the tenant of the harness admin credential
// (PLATFORM_CLIENT_CERT): platformd issues it with the root admin request
// (pkg/app/backends.AdminCertificateRequest), whose subject O is the system
// tenant (app.SystemTenantID), and the mTLS transports bind the caller to
// the tenant its subject O names. A request that names any other tenant on a
// tenant-bound service is refused, so tests name this one.
const HarnessTenantID = "system"

// ForeignTenantID is the tenant of the second harness credential
// (PLATFORM_TENANT_CLIENT_CERT). platformd issues it with the same admin
// request, its subject O replaced by this tenant, so a test can prove what
// a caller outside the system tenant is refused.
const ForeignTenantID = "harness-tenant"

// LoadMTLSConfig loads the harness admin mTLS client certificate from
// environment variables. Returns nil if the variables are not set.
func LoadMTLSConfig() *tls.Config {
	return loadMTLSConfig(EnvClientCert, EnvClientKey)
}

// LoadTenantMTLSConfig loads the ForeignTenantID mTLS client certificate
// from environment variables. Returns nil if the variables are not set.
func LoadTenantMTLSConfig() *tls.Config {
	return loadMTLSConfig(EnvTenantClientCert, EnvTenantClientKey)
}

// loadMTLSConfig builds a client TLS config from the certificate and key
// files named by certEnv and keyEnv, trusting the CA named by EnvCACert.
// Returns nil if any variable is unset or any file fails to load.
func loadMTLSConfig(certEnv, keyEnv string) *tls.Config {
	certFile := os.Getenv(certEnv)
	keyFile := os.Getenv(keyEnv)
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

// requireTLS13 returns tlsConfig pinned to TLS 1.3. mTLS is mandatory for
// integration tests, so a nil config (variables unset) panics naming them.
func requireTLS13(tlsConfig *tls.Config, certEnv, keyEnv string) *tls.Config {
	if tlsConfig == nil {
		panic("mtls: mTLS environment variables not configured; set " + certEnv + ", " + keyEnv + ", and " + EnvCACert)
	}
	tlsConfig.MinVersion = tls.VersionTLS13
	return tlsConfig
}

// MTLSEnabled returns true if mTLS environment variables are configured.
func MTLSEnabled() bool {
	return LoadMTLSConfig() != nil
}

// TLSConfigOrInsecure returns the mTLS config loaded from environment variables.
// mTLS is mandatory for integration tests; this function panics if the
// required environment variables are not configured.
func TLSConfigOrInsecure() *tls.Config {
	return requireTLS13(LoadMTLSConfig(), EnvClientCert, EnvClientKey)
}

// TenantTLSConfig returns the ForeignTenantID mTLS config pinned to TLS 1.3;
// it panics if the tenant credential variables are not configured.
func TenantTLSConfig() *tls.Config {
	return requireTLS13(LoadTenantMTLSConfig(), EnvTenantClientCert, EnvTenantClientKey)
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
// wrong value unconstructible rather than merely detectable. The server's
// refusal of a wrong protocol is TestServerRefusesAWrongALPNAtTheHandshake in
// pkg/api/quic.
func QUICTLSConfig() *tls.Config {
	return withQUICALPN(TLSConfigOrInsecure())
}

// TenantQUICTLSConfig is QUICTLSConfig for the ForeignTenantID credential.
func TenantQUICTLSConfig() *tls.Config {
	return withQUICALPN(TenantTLSConfig())
}

// withQUICALPN offers quicwire.ALPNProtocol on tlsConfig.
func withQUICALPN(tlsConfig *tls.Config) *tls.Config {
	tlsConfig.NextProtos = []string{quicwire.ALPNProtocol}
	return tlsConfig
}

// NewHTTPClient creates an HTTP client configured with mTLS certificates.
// mTLS is mandatory for integration tests.
func NewHTTPClient(timeout time.Duration) *http.Client {
	return newHTTPClient(timeout, TLSConfigOrInsecure())
}

// NewTenantHTTPClient is NewHTTPClient for the ForeignTenantID credential.
func NewTenantHTTPClient(timeout time.Duration) *http.Client {
	return newHTTPClient(timeout, TenantTLSConfig())
}

func newHTTPClient(timeout time.Duration, tlsConfig *tls.Config) *http.Client {
	return &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}
}

// GRPCTransportCredentials returns gRPC transport credentials configured with
// mTLS. mTLS is mandatory for integration tests; this function panics if the
// required environment variables are not configured.
func GRPCTransportCredentials() grpc.DialOption {
	return grpc.WithTransportCredentials(credentials.NewTLS(TLSConfigOrInsecure()))
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
	return httpsBaseURL(endpoint)
}

// RESTBaseURL returns the REST API base URL for endpoint. platformd serves
// REST over mTLS, and the harness exports PLATFORM_REST_ENDPOINT with its
// https:// scheme, so an endpoint is taken with or without one: a bare
// host:port gets https://, an explicit scheme is kept as given. Prepending a
// scheme to the exported value dialled http://https://localhost:8443 and left
// every REST subtest unreachable. A trailing slash is dropped so callers can
// append paths that start with one.
func RESTBaseURL(endpoint string) string {
	return strings.TrimRight(httpsBaseURL(endpoint), "/")
}

// httpsBaseURL keeps an explicit http:// or https:// scheme on endpoint and
// gives https:// to one without a scheme.
func httpsBaseURL(endpoint string) string {
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
