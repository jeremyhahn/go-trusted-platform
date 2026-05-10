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

package ca

// testCACertPath returns the path to the self-signed CA fixture used by
// remote-transport configuration tests. The fixture is a minimal ECDSA
// CA certificate (testdata/ca.pem) whose presence satisfies the Config
// validation contract for remote transports (tls.ca_cert required).
//
// The file is not opened by Validate()/NewAdapter() — only its non-empty
// path is checked — so any test that exercises those two entry points is
// safe to use this helper without further mocking of the TLS layer.
const testCACertPath = "testdata/ca.pem"

// testTLSConfig returns a TLSConfig suitable for tests that need to pass
// Config.Validate() for remote transports (grpc/rest/quic/mcp). It points
// at the fixture CA at testCACertPath and leaves ClientCert/ClientKey empty
// (only the CA cert is validated by Config.Validate()).
func testTLSConfig() *TLSConfig {
	return &TLSConfig{
		CACert: testCACertPath,
	}
}
