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

// Package bootstrap provides integration tests for the trust bootstrap
// subsystem. Tests verify the CA bundle REST endpoint, DANE TLSA record
// publication, and end-to-end DANE bootstrapping against a running platformd
// instance in the devcontainer.
package bootstrap

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/test/integration/helpers"
)

// =============================================================================
// Environment Variable Constants
// =============================================================================

const (
	// EnvIntegrationTest is the environment variable that must be set to run
	// integration tests. Set INTEGRATION_TEST=1 to enable.
	EnvIntegrationTest = "INTEGRATION_TEST"

	// EnvDNSServer overrides the DNS server address used by DANE tests.
	// Defaults to 127.0.0.1:8053 (public DNS port) in the devcontainer.
	EnvDNSServer = "PLATFORM_DNS_SERVER"

	// EnvDNSHostname overrides the hostname used to construct TLSA record
	// lookups. Defaults to "localhost".
	EnvDNSHostname = "PLATFORM_DNS_HOSTNAME"

	// DefaultDNSServer is the default DNS server address in the devcontainer.
	DefaultDNSServer = "127.0.0.1:8053"

	// DefaultDNSHostname is the default hostname for TLSA record queries.
	DefaultDNSHostname = "localhost"

	// DefaultRESTPort is the default REST API port.
	DefaultRESTPort = "8443"

	// BootstrapPath is the REST API path for the CA bootstrap endpoint.
	BootstrapPath = "/api/v1/ca/bootstrap"

	// CanonicalBootstrapPath is the host-root path the go-xkms trust fetcher
	// uses by default (its DefaultBundlePath) and the path
	// `xkey trust import-platform <host:port>` fetches. The platform serves
	// the same bundle here as at BootstrapPath.
	CanonicalBootstrapPath = "/v1/ca/bootstrap"

	// ContentTypePEM is the expected Content-Type for PEM bundle responses.
	ContentTypePEM = "application/pem-certificate-chain"

	// DefaultTestTimeout is the default timeout for test contexts.
	DefaultTestTimeout = 30 * time.Second
)

// =============================================================================
// Error Types
// =============================================================================

// ErrNoCertificates is returned when PEM data contains no valid certificates.
type ErrNoCertificates struct{}

func (e ErrNoCertificates) Error() string {
	return "bootstrap: PEM data contains no valid certificates"
}

// ErrInvalidPEMBlock is returned when PEM data contains an invalid block.
type ErrInvalidPEMBlock struct {
	Offset int
}

func (e ErrInvalidPEMBlock) Error() string {
	return fmt.Sprintf("bootstrap: invalid PEM block at offset %d", e.Offset)
}

// ErrCertParseFailed is returned when a certificate cannot be parsed from DER.
type ErrCertParseFailed struct {
	Cause error
}

func (e ErrCertParseFailed) Error() string {
	return fmt.Sprintf("bootstrap: certificate parse failed: %v", e.Cause)
}

func (e ErrCertParseFailed) Unwrap() error {
	return e.Cause
}

// =============================================================================
// Endpoint Helpers
// =============================================================================

// serverAddr returns the REST API base URL from environment variables or
// defaults. Uses the helpers package for consistent endpoint resolution.
func serverAddr() string {
	return helpers.GetRESTEndpoint()
}

// dnsAddr returns the DNS server address from environment variables or defaults.
func dnsAddr() string {
	if addr := os.Getenv(EnvDNSServer); addr != "" {
		return addr
	}
	return DefaultDNSServer
}

// dnsHostname returns the hostname used for DANE TLSA record lookups.
func dnsHostname() string {
	if hostname := os.Getenv(EnvDNSHostname); hostname != "" {
		return hostname
	}
	return DefaultDNSHostname
}

// bootstrapURL returns the full URL for the bootstrap endpoint with optional
// query parameters.
func bootstrapURL(queryParams string) string {
	return pathURL(BootstrapPath, queryParams)
}

// canonicalBootstrapURL returns the full URL for the host-root trust-bootstrap
// endpoint with optional query parameters.
func canonicalBootstrapURL(queryParams string) string {
	return pathURL(CanonicalBootstrapPath, queryParams)
}

// pathURL joins the server base URL, a path and optional query parameters.
func pathURL(path, queryParams string) string {
	base := serverAddr() + path
	if queryParams != "" {
		return base + "?" + queryParams
	}
	return base
}

// =============================================================================
// TLS Client Helper
// =============================================================================

// tlsClient creates an HTTPS client configured with mTLS credentials from the
// devcontainer environment. This uses the shared helpers package which reads
// PLATFORM_CLIENT_CERT, PLATFORM_CLIENT_KEY, and PLATFORM_CA_CERT.
func tlsClient() *http.Client {
	return helpers.NewHTTPClient(DefaultTestTimeout)
}

// =============================================================================
// PEM Parsing Helpers
// =============================================================================

// parsePEMBundle parses PEM-encoded data into a slice of x509.Certificate.
// Returns an error if the PEM data is empty, contains no valid certificate
// blocks, or any certificate fails to parse.
func parsePEMBundle(data []byte) ([]*x509.Certificate, error) {
	var certs []*x509.Certificate
	rest := data
	offset := 0

	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			offset += len(block.Bytes)
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, ErrCertParseFailed{Cause: err}
		}
		certs = append(certs, cert)
		offset += len(block.Bytes)
	}

	if len(certs) == 0 {
		return nil, ErrNoCertificates{}
	}

	return certs, nil
}

// =============================================================================
// Test Context Helpers
// =============================================================================

// testContext returns a context with the default test timeout.
func testContext() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), DefaultTestTimeout)
}

// fetchBootstrapBundle performs a GET request to the bootstrap endpoint and
// returns the raw PEM response body. This is a shared helper used by multiple
// test functions to avoid duplicating HTTP request logic.
func fetchBootstrapBundle(t *testing.T, queryParams string) []byte {
	t.Helper()

	ctx, cancel := testContext()
	t.Cleanup(cancel)

	url := bootstrapURL(queryParams)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		t.Fatalf("failed to create request: %v", err)
	}

	client := tlsClient()
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("bootstrap request failed: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Fatalf("unexpected status code: got %d, want %d", resp.StatusCode, http.StatusOK)
	}

	body := make([]byte, 0, 4096)
	buf := make([]byte, 1024)
	for {
		n, err := resp.Body.Read(buf)
		if n > 0 {
			body = append(body, buf[:n]...)
		}
		if err != nil {
			break
		}
	}

	return body
}
