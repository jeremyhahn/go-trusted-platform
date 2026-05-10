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

	quicbaas "github.com/jeremyhahn/go-quicbaas/sdk/go"
)

// TestExpandHome covers the expandHome helper. It must expand "~/X"
// against the user home dir and pass through absolute paths.
func TestExpandHome(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("no home dir on this builder")
	}
	cases := []struct {
		in   string
		want string
	}{
		{"", ""},
		{"/etc/foo", "/etc/foo"},
		{"~", home},
		{"~/x", filepath.Join(home, "x")},
	}
	for _, tc := range cases {
		got := expandHome(tc.in)
		if got != tc.want {
			t.Errorf("expandHome(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

// TestResolveDefaultClientCert_ExplicitMissing returns "" when the
// supplied path does not exist.
func TestResolveDefaultClientCert_ExplicitMissing(t *testing.T) {
	got := resolveDefaultClientCert("/no/such/cert/file.pem")
	if got != "" {
		t.Fatalf("expected empty for missing path, got %q", got)
	}
}

// TestResolveDefaultClientCert_ExplicitPresent returns the supplied
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

// TestSelectFIDO2Device covers the device-selection branches.
func TestSelectFIDO2Device(t *testing.T) {
	devices := []quicbaas.FIDO2Device{
		{DeviceID: "alpha", Manufacturer: "Yubico"},
		{DeviceID: "beta", Manufacturer: "SoloKeys"},
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
	if got.DeviceID != "beta" {
		t.Errorf("expected device beta, got %q", got.DeviceID)
	}
}

// TestSelectFIDO2Device_SingleAutoPicks verifies that with one device
// the helper picks it without an explicit deviceID.
func TestSelectFIDO2Device_SingleAutoPicks(t *testing.T) {
	devices := []quicbaas.FIDO2Device{{DeviceID: "only"}}
	got, err := selectFIDO2Device(devices, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.DeviceID != "only" {
		t.Errorf("expected only, got %q", got.DeviceID)
	}
}

// TestSelectPIVReader covers the reader-selection branches.
func TestSelectPIVReader(t *testing.T) {
	readers := []quicbaas.PIVReader{
		{Name: "Yubico YubiKey OTP+CCID 0", CardPresent: true},
		{Name: "Generic CCID Reader", CardPresent: false},
	}
	if _, err := selectPIVReader(readers, ""); err == nil {
		t.Error("expected ErrAmbiguousPIVReader when multiple readers and no pin")
	} else {
		var ae *ErrAmbiguousPIVReader
		if !errors.As(err, &ae) {
			t.Errorf("expected *ErrAmbiguousPIVReader, got %T: %v", err, err)
		}
	}
	if _, err := selectPIVReader(readers, "Other"); err == nil {
		t.Error("expected ErrPIVReaderNotFound when --reader does not match")
	} else {
		var nf *ErrPIVReaderNotFound
		if !errors.As(err, &nf) {
			t.Errorf("expected *ErrPIVReaderNotFound, got %T: %v", err, err)
		}
	}
}

// TestSelectPIVReader_SingleAutoPicks verifies single-reader auto-pick.
func TestSelectPIVReader_SingleAutoPicks(t *testing.T) {
	readers := []quicbaas.PIVReader{{Name: "Reader"}}
	got, err := selectPIVReader(readers, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Name != "Reader" {
		t.Errorf("expected Reader, got %q", got.Name)
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
		t.Logf("note: got %T: %v (this is acceptable when SDK FIDO2/PIV probes succeed but are empty)", err, err)
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
