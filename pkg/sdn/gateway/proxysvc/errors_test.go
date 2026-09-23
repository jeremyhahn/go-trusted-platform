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

package proxysvc

import (
	"errors"
	"strings"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/proxy"
)

// TestErrorMessages pins the operator-facing message of every typed error so
// a wording regression (or a lost field interpolation) fails loudly.
func TestErrorMessages(t *testing.T) {
	cause := errors.New("boom")
	tests := []struct {
		err  error
		want string
	}{
		{&ErrNilEngine{}, "nil proxy engine"},
		{&ErrNilClient{}, "nil control-plane client"},
		{&ErrNilReloader{}, "nil reloader"},
		{&ErrNilResolver{}, "neither a trust resolver nor a platform anchor"},
		{&ErrUnknownTrustClass{Class: "bogus"}, `unknown trust class "bogus" (known: platform, bmc)`},
		{&ErrTrustSourceMissing{Class: "platform", Source: "platform-ca-file:"}, `trust class "platform" needs platform-ca-file:`},
		{&ErrProxyDisabled{}, "proxy service is disabled"},
		{&ErrServerTLSRequired{}, "tls.cert-file"},
		{&ErrClientCARequired{}, "tls.client-ca-file"},
		{&ErrConfigInvalid{Field: "f", Reason: "r"}, "invalid configuration field f: r"},
		{&ErrCertificateLoadFailed{CertFile: "/c.pem", Cause: cause}, "/c.pem"},
		{&ErrClientCALoadFailed{Path: "/ca.pem", Cause: cause}, "/ca.pem"},
		{&ErrClientCALoadFailed{Path: "/ca.pem"}, "no certificates"},
		{&ErrDialFailed{Cause: cause}, "dialing platformd"},
		{&ErrNilDialFunc{}, "nil dial function"},
		{&ErrNilAttestationClient{}, "nil attestation client"},
		{&ErrDeviceIDRequired{}, "device id is required"},
		{&ErrDeviceNotAttested{DeviceID: "lab-node-2", Detail: "too old"}, `device "lab-node-2" not freshly attested: too old`},
		{&ErrAttestationQueryFailed{DeviceID: "lab-node-2", Cause: cause}, `attestation query for device "lab-node-2" failed: boom`},
		{&ErrTokenAuthConfig{Field: "issuer", Reason: "required"}, "token-auth configuration invalid: issuer: required"},
		{&ErrNilTokenRequest{}, "nil token auth request"},
		{&ErrBearerNotAllowed{}, "DPoP proof required"},
		{&ErrScopeDenied{Scope: "proxy:admin"}, `missing required scope "proxy:admin"`},
		{&ErrOPADisabled{}, "opa section is disabled"},
	}
	for _, tc := range tests {
		if got := tc.err.Error(); !strings.Contains(got, tc.want) {
			t.Errorf("%T.Error() = %q, want it to contain %q", tc.err, got, tc.want)
		}
	}
}

// TestErrorUnwrapping pins the errors.Is/As classification contracts the
// auth chain and the assembly rely on.
func TestErrorUnwrapping(t *testing.T) {
	cause := errors.New("boom")
	if !errors.Is(&ErrDeviceNotAttested{DeviceID: "d"}, proxy.ErrAttestationStale) {
		t.Error("ErrDeviceNotAttested must classify as proxy.ErrAttestationStale")
	}
	if !errors.Is(&ErrScopeDenied{Scope: "s"}, proxy.ErrTokenScopeDenied) {
		t.Error("ErrScopeDenied must classify as proxy.ErrTokenScopeDenied")
	}
	if !errors.Is(&ErrAttestationQueryFailed{Cause: cause}, cause) {
		t.Error("ErrAttestationQueryFailed must unwrap its cause")
	}
	if errors.Is(&ErrAttestationQueryFailed{Cause: cause}, proxy.ErrAttestationStale) {
		t.Error("ErrAttestationQueryFailed must NOT classify as stale")
	}
	if !errors.Is(&ErrDialFailed{Cause: cause}, cause) {
		t.Error("ErrDialFailed must unwrap its cause")
	}
	if !errors.Is(&ErrCertificateLoadFailed{Cause: cause}, cause) {
		t.Error("ErrCertificateLoadFailed must unwrap its cause")
	}
	if !errors.Is(&ErrClientCALoadFailed{Cause: cause}, cause) {
		t.Error("ErrClientCALoadFailed must unwrap its cause")
	}
}
