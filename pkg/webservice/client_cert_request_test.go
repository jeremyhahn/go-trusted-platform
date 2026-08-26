// Copyright (c) 2026 Jeremy Hahn
// Copyright (c) 2026 Automate The Things, LLC
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

package webservice

import (
	"crypto/tls"
	"crypto/x509"
	"testing"
)

// TestRequestOptionalClientCert_AsksForCertificate is the behavior every
// mTLS-gated surface on this listener depends on. With ClientAuth left at
// NoClientCert the server sends no CertificateRequest, so no handler ever
// sees a peer certificate — the device routes could only answer 401 and
// the gateway control plane had no identity to bind telemetry to.
func TestRequestOptionalClientCert_AsksForCertificate(t *testing.T) {
	cfg := &tls.Config{ClientCAs: x509.NewCertPool()}

	got := requestOptionalClientCert(cfg)

	if got.ClientAuth != tls.VerifyClientCertIfGiven {
		t.Fatalf("ClientAuth = %v, want tls.VerifyClientCertIfGiven", got.ClientAuth)
	}
}

// TestRequestOptionalClientCert_DoesNotRequire pins the "if given" half.
// Requiring a certificate would lock every browser out of the WebUI and
// every JWT-authenticated client out of the API, since they share this
// listener and present no certificate.
func TestRequestOptionalClientCert_DoesNotRequire(t *testing.T) {
	cfg := requestOptionalClientCert(&tls.Config{ClientCAs: x509.NewCertPool()})

	if cfg.ClientAuth == tls.RequireAndVerifyClientCert || cfg.ClientAuth == tls.RequireAnyClientCert {
		t.Fatalf("ClientAuth = %v; a shared listener must not require a client certificate", cfg.ClientAuth)
	}
}

// TestRequestOptionalClientCert_PreservesStricterSetting ensures the
// normalization never weakens a configuration that already requires and
// verifies a client certificate.
func TestRequestOptionalClientCert_PreservesStricterSetting(t *testing.T) {
	cfg := &tls.Config{
		ClientCAs:  x509.NewCertPool(),
		ClientAuth: tls.RequireAndVerifyClientCert,
	}

	if got := requestOptionalClientCert(cfg); got.ClientAuth != tls.RequireAndVerifyClientCert {
		t.Fatalf("ClientAuth = %v, want the stricter RequireAndVerifyClientCert preserved", got.ClientAuth)
	}
}

// TestRequestOptionalClientCert_WithoutClientCAs covers the case with no
// pool to verify against: asking for a certificate that can never be
// verified would only produce unverifiable peer certificates, so the
// config is left alone and the cert-bound handlers fail closed instead.
func TestRequestOptionalClientCert_WithoutClientCAs(t *testing.T) {
	cfg := requestOptionalClientCert(&tls.Config{})

	if cfg.ClientAuth != tls.NoClientCert {
		t.Fatalf("ClientAuth = %v, want tls.NoClientCert with no ClientCAs", cfg.ClientAuth)
	}
}

// TestRequestOptionalClientCert_NilConfig covers the nil input rather
// than panicking inside the TLS build path.
func TestRequestOptionalClientCert_NilConfig(t *testing.T) {
	if got := requestOptionalClientCert(nil); got != nil {
		t.Fatalf("got = %v, want nil", got)
	}
}
