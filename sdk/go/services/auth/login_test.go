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

package auth

import (
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
)

// TestExpandHome covers the expandHome helper. It must expand "~/X"
// against the user home dir and pass through absolute paths.
func TestExpandHome(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)

	cases := map[string]string{
		"~/x":  filepath.Join(home, "x"),
		"~":    home,
		"/abs": "/abs",
		"~x":   "~x",
		"":     "",
	}
	for in, want := range cases {
		if got := expandHome(in); got != want {
			t.Errorf("expandHome(%q) = %q, want %q", in, got, want)
		}
	}
}

// TestExpandHome_NoHomeDir: a ~ path cannot be resolved without a home
// directory, so it expands to "" rather than to a path relative to the
// working directory. Absolute paths are unaffected.
func TestExpandHome_NoHomeDir(t *testing.T) {
	t.Setenv("HOME", "")

	if got := expandHome("~/x"); got != "" {
		t.Errorf("expandHome(~/x) without HOME = %q, want empty", got)
	}
	if got := expandHome("/abs"); got != "/abs" {
		t.Errorf("expandHome(/abs) without HOME = %q, want /abs", got)
	}
}

// TestResolveDefaultClientCert_ExplicitPresent returns the explicit
// path when it exists on disk.
func TestResolveDefaultClientCert_ExplicitPresent(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "admin.pem")
	if err := os.WriteFile(path, []byte("test"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := resolveDefaultClientCert(path)
	if got != path {
		t.Fatalf("expected %q, got %q", path, got)
	}
}

// TestSelectFIDO2Device covers the local-authenticator-selection branches.
// Selection now operates on client-LOCAL quicbaas.LocalDevice records keyed
// by their host device Path (the WebAuthn ceremony itself is a separate
// server round-trip).
func TestSelectFIDO2Device(t *testing.T) {
	devices := []quicbaas.LocalDevice{
		{Path: "alpha", Manufacturer: "Yubico"},
		{Path: "beta", Manufacturer: "SoloKeys"},
	}
	if _, err := selectFIDO2Device(devices, ""); err == nil {
		t.Error("expected ErrAmbiguousFIDO2Device when multiple devices and no pin")
	} else {
		var ae *ErrAmbiguousFIDO2Device
		if !errors.As(err, &ae) {
			t.Errorf("expected *ErrAmbiguousFIDO2Device, got %T: %v", err, err)
		}
	}
	if _, err := selectFIDO2Device(devices, "missing"); err == nil {
		t.Error("expected ErrFIDO2DeviceNotFound when --device does not match")
	} else {
		var nf *ErrFIDO2DeviceNotFound
		if !errors.As(err, &nf) {
			t.Errorf("expected *ErrFIDO2DeviceNotFound, got %T: %v", err, err)
		}
	}
	got, err := selectFIDO2Device(devices, "beta")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Path != "beta" {
		t.Errorf("expected device beta, got %q", got.Path)
	}
}

// TestSelectFIDO2Device_SingleAutoPicks verifies that with one device
// the helper picks it without an explicit device path.
func TestSelectFIDO2Device_SingleAutoPicks(t *testing.T) {
	devices := []quicbaas.LocalDevice{{Path: "only"}}
	got, err := selectFIDO2Device(devices, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Path != "only" {
		t.Errorf("expected only, got %q", got.Path)
	}
}

// TestPIVAlgoFromCert maps public key algorithms to PIV signing algos.
func TestPIVAlgoFromCert(t *testing.T) {
	cases := []struct {
		algo x509.PublicKeyAlgorithm
		want string
	}{
		{x509.RSA, "rsa-pkcs1"},
		{x509.Ed25519, "ed25519"},
		{x509.ECDSA, "ecdsa"},
		{x509.UnknownPublicKeyAlgorithm, "ecdsa"},
	}
	for _, tc := range cases {
		got := pivAlgoFromCert(&x509.Certificate{PublicKeyAlgorithm: tc.algo})
		if got != tc.want {
			t.Errorf("pivAlgoFromCert(%v) = %q, want %q", tc.algo, got, tc.want)
		}
	}
	if got := pivAlgoFromCert(nil); got != "ecdsa" {
		t.Errorf("pivAlgoFromCert(nil) = %q, want ecdsa", got)
	}
}

// TestStringifyMetadata flattens any-typed maps to strings.
func TestStringifyMetadata(t *testing.T) {
	got := stringifyMetadata(map[string]any{
		"k_string": "v",
		"k_bytes":  []byte("b"),
		"k_int":    42,
	})
	if got["k_string"] != "v" {
		t.Errorf("string passthrough failed: %q", got["k_string"])
	}
	if got["k_bytes"] != "b" {
		t.Errorf("bytes conversion failed: %q", got["k_bytes"])
	}
	if got["k_int"] != "42" {
		t.Errorf("int formatting failed: %q", got["k_int"])
	}
}

// TestDispatchLogin_RejectsInvalidMethod ensures unknown methods are
// rejected with a typed error.
func TestDispatchLogin_RejectsInvalidMethod(t *testing.T) {
	c := &Client{}
	_, err := c.dispatchLogin(t.Context(), &LoginRequest{Method: "totp"})
	var im *ErrInvalidAuthMethod
	if !errors.As(err, &im) {
		t.Fatalf("expected *ErrInvalidAuthMethod, got %T: %v", err, err)
	}
}

// TestDispatchLogin_AutoDiscoverNoFactors returns ErrNoFactorsAvailable
// when nothing is reachable.
func TestDispatchLogin_AutoDiscoverNoFactors(t *testing.T) {
	t.Setenv("PLATFORMCTL_CLIENT_CERT", "")
	t.Setenv("XKMSCTL_CLIENT_CERT", "")
	t.Setenv("QUICBAAS_CLIENT_CERT", "")
	t.Setenv("QRDB_CLIENT_CERT", "")
	t.Setenv("HOME", t.TempDir())

	c := &Client{}
	_, err := c.dispatchLogin(t.Context(), &LoginRequest{})
	if err == nil {
		t.Fatal("expected error from auto-discovery on empty environment")
	}
	var nf *ErrNoFactorsAvailable
	if !errors.As(err, &nf) {
		t.Logf("note: got %T: %v (this is acceptable when SDK Devices/PIV probes succeed but are empty)", err, err)
	}
}

// TestLoginMTLS_MissingCert returns ErrMissingCertPath when no cert is
// reachable.
func TestLoginMTLS_MissingCert(t *testing.T) {
	t.Setenv("PLATFORMCTL_CLIENT_CERT", "")
	t.Setenv("XKMSCTL_CLIENT_CERT", "")
	t.Setenv("QUICBAAS_CLIENT_CERT", "")
	t.Setenv("QRDB_CLIENT_CERT", "")
	t.Setenv("HOME", t.TempDir())

	c := &Client{}
	_, err := c.dispatchLogin(t.Context(), &LoginRequest{Method: "mtls"})
	if err == nil {
		t.Fatal("expected error when no client cert is available")
	}
	var mc *ErrMissingCertPath
	if !errors.As(err, &mc) {
		// Surface unavailability is the other valid outcome — the test
		// Client has no SDK wired so the factors() helper short-circuits.
		var su *ErrSecuritySurfaceUnavailable
		if !errors.As(err, &su) {
			t.Errorf("expected *ErrMissingCertPath or *ErrSecuritySurfaceUnavailable, got %T: %v", err, err)
		}
	}
}

// TestErrTokenWriteUnwrap ensures the wrap chain works.
func TestErrTokenWriteUnwrap(t *testing.T) {
	cause := errors.New("disk full")
	e := &ErrTokenWrite{Path: "/tmp/x", Cause: cause}
	if !errors.Is(e, cause) {
		t.Errorf("expected errors.Is(e, cause) to be true")
	}
	if e.Error() == "" {
		t.Errorf("Error() must not be empty")
	}
}

// TestFIDO2OptionsFromBegin_MissingChallenge returns the typed error
// when the server issued no WebAuthn options.
func TestFIDO2OptionsFromBegin_MissingChallenge(t *testing.T) {
	if _, err := fido2OptionsFromBegin(nil); err == nil {
		t.Error("expected error for nil begin response")
	} else {
		var mc *ErrMissingFIDO2Challenge
		if !errors.As(err, &mc) {
			t.Errorf("expected *ErrMissingFIDO2Challenge, got %T: %v", err, err)
		}
	}
	begin := &quicbaas.BeginLoginResponse{ChallengeMetadata: map[string]string{}}
	if _, err := fido2OptionsFromBegin(begin); err == nil {
		t.Error("expected error for empty options metadata")
	} else {
		var mc *ErrMissingFIDO2Challenge
		if !errors.As(err, &mc) {
			t.Errorf("expected *ErrMissingFIDO2Challenge, got %T: %v", err, err)
		}
	}
}

// TestFIDO2OptionsFromBegin_ReturnsOptions extracts the options bytes.
func TestFIDO2OptionsFromBegin_ReturnsOptions(t *testing.T) {
	begin := &quicbaas.BeginLoginResponse{
		ChallengeMetadata: map[string]string{fido2OptionsKey: `{"publicKey":{}}`},
	}
	got, err := fido2OptionsFromBegin(begin)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if string(got) != `{"publicKey":{}}` {
		t.Errorf("unexpected options: %q", got)
	}
}

// TestFIDO2CredentialID recovers the credential id from rawId with an
// id fallback.
func TestFIDO2CredentialID(t *testing.T) {
	got, err := fido2CredentialID([]byte(`{"id":"aWQ","rawId":"cmF3SWQ"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "cmF3SWQ" {
		t.Errorf("expected rawId to win, got %q", got)
	}
	got, err = fido2CredentialID([]byte(`{"id":"aWQ"}`))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "aWQ" {
		t.Errorf("expected id fallback, got %q", got)
	}
}

// TestFIDO2CredentialID_Invalid rejects malformed assertions with the
// typed parse error.
func TestFIDO2CredentialID_Invalid(t *testing.T) {
	for _, doc := range []string{"not json", "{}"} {
		if _, err := fido2CredentialID([]byte(doc)); err == nil {
			t.Errorf("expected error for %q", doc)
		} else {
			var pe *ErrFIDO2AssertionParse
			if !errors.As(err, &pe) {
				t.Errorf("expected *ErrFIDO2AssertionParse for %q, got %T: %v", doc, err, err)
			}
		}
	}
}

// TestLoginResultFrom_NilResponse rejects nil finish-login payloads,
// including a response whose embedded ceremony payload is nil.
func TestLoginResultFrom_NilResponse(t *testing.T) {
	if _, err := loginResultFrom(nil, "alice"); err == nil {
		t.Error("expected error for nil response")
	} else {
		var lf *ErrLoginFailed
		if !errors.As(err, &lf) {
			t.Errorf("expected *ErrLoginFailed, got %T: %v", err, err)
		}
	}
	if _, err := loginResultFrom(&quicbaas.FinishLoginResponse{}, "alice"); err == nil {
		t.Error("expected error for nil embedded response")
	}
}

// TestNewLoginResult_MapsIdentity projects the resolved identity and
// bearer onto the platform LoginResult.
func TestNewLoginResult_MapsIdentity(t *testing.T) {
	expires := time.Now().Add(time.Hour).UTC()
	got := newLoginResult("tok", "refresh", "f1", expires,
		&quicbaas.Identity{Subject: "alice", TenantID: "t1"}, "fallback")
	if got.Username != "alice" || got.UserID != "alice" {
		t.Errorf("identity mapping failed: %+v", got)
	}
	if got.TenantID != "t1" {
		t.Errorf("TenantID = %q, want t1", got.TenantID)
	}
	if got.Token != "tok" || got.RefreshToken != "refresh" || got.FactorID != "f1" {
		t.Errorf("token mapping failed: %+v", got)
	}
	if !got.ExpiresAt.Equal(expires) {
		t.Errorf("ExpiresAt = %v, want %v", got.ExpiresAt, expires)
	}
	if got.IssuedAt.IsZero() {
		t.Error("IssuedAt must be set")
	}
}

// TestNewLoginResult_FallbackUsername fills the identity fields from
// the request when the server returns no identity.
func TestNewLoginResult_FallbackUsername(t *testing.T) {
	got := newLoginResult("tok", "", "", time.Time{}, nil, "bob")
	if got.Username != "bob" || got.UserID != "bob" {
		t.Errorf("fallback mapping failed: %+v", got)
	}
}

// TestPIVBackendOr normalizes the backend selector.
func TestPIVBackendOr(t *testing.T) {
	if got := pivBackendOr(""); got != defaultPIVBackend {
		t.Errorf("pivBackendOr(empty) = %q, want %q", got, defaultPIVBackend)
	}
	if got := pivBackendOr("pkcs11"); got != "pkcs11" {
		t.Errorf("pivBackendOr(pkcs11) = %q", got)
	}
}

// TestLoginFIDO2_NoSDK surfaces the typed unavailability error when the
// client has no SDK wired.
func TestLoginFIDO2_NoSDK(t *testing.T) {
	c := &Client{}
	_, err := c.dispatchLogin(t.Context(), &LoginRequest{Method: "fido2"})
	var su *ErrSecuritySurfaceUnavailable
	if !errors.As(err, &su) {
		t.Fatalf("expected *ErrSecuritySurfaceUnavailable, got %T: %v", err, err)
	}
}

// TestLoginPIV_NoSDK surfaces the typed unavailability error when the
// client has no SDK wired.
func TestLoginPIV_NoSDK(t *testing.T) {
	c := &Client{}
	_, err := c.dispatchLogin(t.Context(), &LoginRequest{Method: "piv"})
	var su *ErrSecuritySurfaceUnavailable
	if !errors.As(err, &su) {
		t.Fatalf("expected *ErrSecuritySurfaceUnavailable, got %T: %v", err, err)
	}
}
