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

package bootstrap

import (
	"bytes"
	"crypto/x509"
	"io"
	"log/slog"
	"net/http"
	"os"
	"testing"
	"time"

	mdns "github.com/miekg/dns"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/trust"
)

// TestBootstrapEndpoint_REST verifies the CA bootstrap REST endpoint returns
// a valid PEM certificate chain with the correct content type.
func TestBootstrapEndpoint_REST(t *testing.T) {
	ctx, cancel := testContext()
	t.Cleanup(cancel)

	url := bootstrapURL("")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	require.NoError(t, err)

	client := tlsClient()
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// Verify HTTP 200 status.
	assert.Equal(t, http.StatusOK, resp.StatusCode)

	// Verify Content-Type header.
	assert.Equal(t, ContentTypePEM, resp.Header.Get("Content-Type"))

	// Read the full response body.
	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// Verify response contains PEM certificate data.
	assert.True(t, bytes.Contains(body, []byte("-----BEGIN CERTIFICATE-----")),
		"response body must contain PEM certificate header")

	// Verify all PEM blocks parse into valid X.509 certificates.
	certs, err := parsePEMBundle(body)
	require.NoError(t, err)
	assert.NotEmpty(t, certs, "bundle must contain at least one certificate")

	// Verify each certificate has valid fields.
	for i, cert := range certs {
		assert.False(t, cert.NotAfter.Before(time.Now()),
			"certificate %d has expired (NotAfter: %s)", i, cert.NotAfter)
		assert.NotEmpty(t, cert.Subject.CommonName,
			"certificate %d must have a CommonName", i)
	}
}

// TestBootstrapEndpoint_CanonicalPath verifies the canonical host-root path
// serves the identical bundle. This is the path the go-xkms trust fetcher
// builds by default, so `xkey trust import-platform <host:port>` reaches it
// without being told the platform's API prefix (issue #201).
func TestBootstrapEndpoint_CanonicalPath(t *testing.T) {
	ctx, cancel := testContext()
	t.Cleanup(cancel)

	req, err := http.NewRequestWithContext(
		ctx, http.MethodGet, canonicalBootstrapURL(""), nil)
	require.NoError(t, err)

	client := tlsClient()
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, ContentTypePEM, resp.Header.Get("Content-Type"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	certs, err := parsePEMBundle(body)
	require.NoError(t, err)
	assert.NotEmpty(t, certs, "bundle must contain at least one certificate")

	// Both paths must serve the same bundle; a canonical path that drifts
	// from the prefixed one would hand first-contact clients a different
	// trust anchor than every other consumer sees.
	assert.Equal(t, string(fetchBootstrapBundle(t, "")), string(body))
}

// TestUnclaimedAPIPath_Returns404 verifies that a path under a namespace the
// API routers own, but which no route claims, returns a JSON 404 instead of
// the SPA shell. Answering an API client with 200 text/html turns a missing
// route into a parse error further downstream that names neither the route
// nor the cause (issue #201).
func TestUnclaimedAPIPath_Returns404(t *testing.T) {
	unclaimed := []string{
		"/v1/ca/nonexistent",
		"/v1/nonexistent",
		"/api/v1/ca/nonexistent",
	}

	for _, path := range unclaimed {
		t.Run(path, func(t *testing.T) {
			ctx, cancel := testContext()
			t.Cleanup(cancel)

			req, err := http.NewRequestWithContext(
				ctx, http.MethodGet, pathURL(path, ""), nil)
			require.NoError(t, err)

			client := tlsClient()
			resp, err := client.Do(req)
			require.NoError(t, err)
			defer resp.Body.Close()

			body, err := io.ReadAll(resp.Body)
			require.NoError(t, err)

			assert.Equal(t, http.StatusNotFound, resp.StatusCode)
			assert.NotContains(t, resp.Header.Get("Content-Type"), "text/html")
			assert.False(t, bytes.Contains(body, []byte("<html")),
				"unclaimed API path must not return the console HTML")
		})
	}
}

// TestBootstrapEndpoint_REST_InvalidMethod verifies the bootstrap endpoint
// rejects non-GET requests.
func TestBootstrapEndpoint_REST_InvalidMethod(t *testing.T) {
	ctx, cancel := testContext()
	t.Cleanup(cancel)

	url := bootstrapURL("")
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, nil)
	require.NoError(t, err)

	client := tlsClient()
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	// POST should return 405 Method Not Allowed.
	assert.Equal(t, http.StatusMethodNotAllowed, resp.StatusCode)
}

// TestBootstrapEndpoint_WithStoreTypeFilter verifies the bootstrap endpoint
// accepts a store_type query parameter and returns a filtered CA bundle.
func TestBootstrapEndpoint_WithStoreTypeFilter(t *testing.T) {
	ctx, cancel := testContext()
	t.Cleanup(cancel)

	// Fetch the unfiltered bundle for comparison.
	unfilteredBody := fetchBootstrapBundle(t, "")

	// Fetch the software-filtered bundle.
	url := bootstrapURL("store_type=software")
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	require.NoError(t, err)

	client := tlsClient()
	resp, err := client.Do(req)
	require.NoError(t, err)
	defer resp.Body.Close()

	assert.Equal(t, http.StatusOK, resp.StatusCode)
	assert.Equal(t, ContentTypePEM, resp.Header.Get("Content-Type"))

	body, err := io.ReadAll(resp.Body)
	require.NoError(t, err)

	// The filtered bundle must contain valid certificates.
	filteredCerts, err := parsePEMBundle(body)
	require.NoError(t, err)
	assert.NotEmpty(t, filteredCerts)

	// The filtered bundle should be a subset of (or equal to) the unfiltered bundle.
	unfilteredCerts, err := parsePEMBundle(unfilteredBody)
	require.NoError(t, err)
	assert.LessOrEqual(t, len(filteredCerts), len(unfilteredCerts),
		"filtered bundle should not contain more certificates than unfiltered")
}

// TestDANERecords_Published queries the platform's DNS server for TLSA records
// at _8443._tcp.<hostname> and verifies they were published correctly.
func TestDANERecords_Published(t *testing.T) {
	dns := dnsAddr()
	hostname := dnsHostname()

	// Construct the TLSA record name per RFC 6698.
	tlsaName := "_8443._tcp." + hostname + "."

	client := new(mdns.Client)
	client.Timeout = 10 * time.Second

	msg := new(mdns.Msg)
	msg.SetQuestion(tlsaName, mdns.TypeTLSA)
	msg.RecursionDesired = true

	resp, _, err := client.Exchange(msg, dns)
	require.NoError(t, err, "DNS query for TLSA records failed")
	require.NotNil(t, resp, "DNS response is nil")

	// Verify we received TLSA records.
	var tlsaRecords []*mdns.TLSA
	for _, rr := range resp.Answer {
		if tlsa, ok := rr.(*mdns.TLSA); ok {
			tlsaRecords = append(tlsaRecords, tlsa)
		}
	}

	require.NotEmpty(t, tlsaRecords, "no TLSA records found at %s", tlsaName)

	// Check for DANE-TA (Usage=2) record, which is always published.
	var hasDANETA bool
	for _, tlsa := range tlsaRecords {
		if tlsa.Usage == 2 {
			hasDANETA = true
			// Verify the selector and matching type are valid values.
			assert.True(t, tlsa.Selector <= 1,
				"DANE-TA selector must be 0 (Full) or 1 (SPKI), got %d", tlsa.Selector)
			assert.True(t, tlsa.MatchingType <= 2,
				"DANE-TA matching type must be 0-2, got %d", tlsa.MatchingType)
			assert.NotEmpty(t, tlsa.Certificate,
				"DANE-TA certificate data must not be empty")
		}
	}
	assert.True(t, hasDANETA, "no DANE-TA (Usage=2) TLSA record found")

	// If DANE-EE (Usage=3) records are present, validate them too.
	for _, tlsa := range tlsaRecords {
		if tlsa.Usage == 3 {
			assert.True(t, tlsa.Selector <= 1,
				"DANE-EE selector must be 0 or 1, got %d", tlsa.Selector)
			assert.True(t, tlsa.MatchingType <= 2,
				"DANE-EE matching type must be 0-2, got %d", tlsa.MatchingType)
			assert.NotEmpty(t, tlsa.Certificate,
				"DANE-EE certificate data must not be empty")
		}
	}
}

// TestDANEBootstrap_EndToEnd uses the go-truststrap DANEBootstrapper to fetch
// the CA bundle via DANE and verifies it matches the REST endpoint response.
// This is the full trust bootstrap flow: DNS TLSA lookup -> verify -> fetch PEM.
func TestDANEBootstrap_EndToEnd(t *testing.T) {
	ctx, cancel := testContext()
	t.Cleanup(cancel)

	logger := logging.NewLogger(slog.LevelInfo, os.Stderr)

	trustConfig := &trust.Config{
		Bootstrap: &trust.ScopeConfig{
			Strategies:       []trust.Strategy{trust.StrategyDANE},
			ServerURL:        serverAddr() + BootstrapPath,
			DANE:             &trust.DANEConfig{DNSServer: dnsAddr()},
			BundlePath:       BootstrapPath,
			PerMethodTimeout: 15 * time.Second,
		},
	}

	resolver, err := trust.NewResolver(trustConfig, logger)
	require.NoError(t, err, "failed to create trust resolver")

	bundlePEM, err := resolver.CABundlePEM(ctx, trust.ClassBootstrap)
	require.NoError(t, err, "DANE bootstrap fetch failed")
	require.NotEmpty(t, bundlePEM, "DANE bootstrap returned empty bundle")

	// Parse the DANE-fetched bundle.
	daneCerts, err := parsePEMBundle(bundlePEM)
	require.NoError(t, err, "failed to parse DANE bundle PEM")
	assert.NotEmpty(t, daneCerts, "DANE bundle must contain certificates")

	// Fetch the bundle from the REST endpoint for comparison.
	restBody := fetchBootstrapBundle(t, "")
	restCerts, err := parsePEMBundle(restBody)
	require.NoError(t, err, "failed to parse REST bundle PEM")

	// The DANE bundle should contain the same certificate chain as the REST endpoint.
	assert.Equal(t, len(restCerts), len(daneCerts),
		"DANE and REST bundles should contain the same number of certificates")

	// Verify certificate fingerprints match.
	for i := range daneCerts {
		if i < len(restCerts) {
			assert.True(t, daneCerts[i].Equal(restCerts[i]),
				"certificate %d differs between DANE and REST bundles", i)
		}
	}
}

// TestTrustResolver_DANE verifies the platform's trust resolver with the DANE
// strategy fetches a valid CA bundle and the certificates can be used to build
// a trust chain.
func TestTrustResolver_DANE(t *testing.T) {
	ctx, cancel := testContext()
	t.Cleanup(cancel)

	logger := logging.NewLogger(slog.LevelInfo, os.Stderr)

	trustConfig := &trust.Config{
		Bootstrap: &trust.ScopeConfig{
			Strategies:       []trust.Strategy{trust.StrategyDANE},
			ServerURL:        serverAddr() + BootstrapPath,
			DANE:             &trust.DANEConfig{DNSServer: dnsAddr()},
			BundlePath:       BootstrapPath,
			PerMethodTimeout: 15 * time.Second,
		},
	}

	resolver, err := trust.NewResolver(trustConfig, logger)
	require.NoError(t, err, "failed to create trust resolver")

	bundlePEM, err := resolver.CABundlePEM(ctx, trust.ClassBootstrap)
	require.NoError(t, err, "trust resolver DANE fetch failed")
	require.NotEmpty(t, bundlePEM, "trust resolver returned empty bundle")

	certs, err := parsePEMBundle(bundlePEM)
	require.NoError(t, err, "failed to parse trust resolver bundle")
	assert.NotEmpty(t, certs, "trust resolver bundle must contain certificates")

	// Verify the bundle contains at least a root CA certificate.
	var hasCA bool
	for _, cert := range certs {
		if cert.IsCA {
			hasCA = true
			break
		}
	}
	assert.True(t, hasCA, "bootstrap bundle must contain at least one CA certificate")

	// Verify the certificates form a valid chain: each non-root cert should
	// have an issuer present in the bundle.
	certPool := buildCertPool(certs)
	for _, cert := range certs {
		if cert.IsCA && bytes.Equal(cert.RawIssuer, cert.RawSubject) {
			// Self-signed root, skip chain verification.
			continue
		}
		opts := x509.VerifyOptions{
			Roots:         certPool,
			Intermediates: certPool,
		}
		_, err := cert.Verify(opts)
		assert.NoError(t, err,
			"certificate %q failed chain verification", cert.Subject.CommonName)
	}
}

// buildCertPool creates an x509.CertPool from a slice of certificates.
func buildCertPool(certs []*x509.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	for _, cert := range certs {
		pool.AddCert(cert)
	}
	return pool
}
