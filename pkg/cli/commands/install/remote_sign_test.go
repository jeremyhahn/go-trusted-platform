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

package install

import (
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/http"
	"os"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/installer"
)

func remoteSB() *installer.SecureBootConfig {
	return &installer.SecureBootConfig{
		Enabled:    true,
		ResignMode: installer.SecureBootResignModeRemote,
		DB:         installer.SecureBootKeyRef{KeyURI: "kms://platform/secureboot/db"},
	}
}

// TestRemoteSignInstallerOptions verifies the option is produced only for
// resign-mode remote WITH a control-plane URL, and is a no-op otherwise.
func TestRemoteSignInstallerOptions(t *testing.T) {
	t.Run("remote + server url => one option", func(t *testing.T) {
		cfg := &installer.Config{SecureBoot: remoteSB()}
		flags := &systemFlags{provisionServerURL: "https://cp:8443", eabKID: "k", eabHMAC: "h", ekSerial: "e"}
		opts, err := remoteSignInstallerOptions(cfg, flags)
		if err != nil {
			t.Fatalf("remoteSignInstallerOptions: %v", err)
		}
		if len(opts) != 1 {
			t.Fatalf("opts = %d, want 1", len(opts))
		}
	})

	t.Run("no server url => no options", func(t *testing.T) {
		cfg := &installer.Config{SecureBoot: remoteSB()}
		opts, err := remoteSignInstallerOptions(cfg, &systemFlags{})
		if err != nil || opts != nil {
			t.Fatalf("expected (nil, nil), got opts=%v err=%v", opts, err)
		}
	})

	t.Run("resign-mode local => no options", func(t *testing.T) {
		sb := remoteSB()
		sb.ResignMode = installer.SecureBootResignModeLocal
		cfg := &installer.Config{SecureBoot: sb}
		opts, err := remoteSignInstallerOptions(cfg, &systemFlags{provisionServerURL: "https://cp"})
		if err != nil || opts != nil {
			t.Fatalf("expected (nil, nil) for local, got opts=%v err=%v", opts, err)
		}
	})

	t.Run("secure boot disabled => no options", func(t *testing.T) {
		opts, err := remoteSignInstallerOptions(&installer.Config{}, &systemFlags{provisionServerURL: "https://cp"})
		if err != nil || opts != nil {
			t.Fatalf("expected (nil, nil) when secure boot is absent, got opts=%v err=%v", opts, err)
		}
	})

	t.Run("bad ca bundle => error", func(t *testing.T) {
		cfg := &installer.Config{SecureBoot: remoteSB()}
		flags := &systemFlags{provisionServerURL: "https://cp", eabKID: "k", eabHMAC: "h", ekSerial: "e", caBundle: "/nonexistent/ca.pem"}
		if _, err := remoteSignInstallerOptions(cfg, flags); err == nil {
			t.Fatal("expected an error for a missing CA bundle")
		}
	})
}

// TestBuildVerifiedHTTPClient verifies a CA-bundle-backed client is built without
// InsecureSkipVerify, an empty path yields nil, and bad input is typed.
func TestBuildVerifiedHTTPClient(t *testing.T) {
	t.Run("empty path => nil client", func(t *testing.T) {
		client, err := buildVerifiedHTTPClient("")
		if err != nil || client != nil {
			t.Fatalf("expected (nil, nil), got client=%v err=%v", client, err)
		}
	})

	t.Run("valid bundle => verified client", func(t *testing.T) {
		_, certPEM := genSignerCert(t, "ca")
		path := filepath.Join(t.TempDir(), "ca.pem")
		if err := os.WriteFile(path, certPEM, 0o644); err != nil {
			t.Fatalf("write ca: %v", err)
		}
		client, err := buildVerifiedHTTPClient(path)
		if err != nil {
			t.Fatalf("buildVerifiedHTTPClient: %v", err)
		}
		if client == nil {
			t.Fatal("expected a non-nil client")
		}
		// Verified, never insecure.
		tr, ok := client.Transport.(*http.Transport)
		if !ok {
			t.Fatalf("transport = %T, want *http.Transport", client.Transport)
		}
		if tr.TLSClientConfig.InsecureSkipVerify {
			t.Fatal("InsecureSkipVerify must never be set")
		}
		if tr.TLSClientConfig.RootCAs == nil {
			t.Fatal("expected RootCAs to be populated from the CA bundle")
		}
	})

	t.Run("missing file => typed error", func(t *testing.T) {
		_, err := buildVerifiedHTTPClient(filepath.Join(t.TempDir(), "absent.pem"))
		var e ErrCABundleRead
		if !errors.As(err, &e) {
			t.Fatalf("expected ErrCABundleRead, got %T: %v", err, err)
		}
	})

	t.Run("non-pem content => typed error", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bad.pem")
		if err := os.WriteFile(path, []byte("not a cert"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		_, err := buildVerifiedHTTPClient(path)
		var e ErrCABundleParse
		if !errors.As(err, &e) {
			t.Fatalf("expected ErrCABundleParse, got %T: %v", err, err)
		}
	})
}

// TestReadEKCertBase64 verifies PEM and DER EK certs are normalised to base64
// DER, empty paths yield "", and malformed input is typed.
func TestReadEKCertBase64(t *testing.T) {
	_, certPEM := genSignerCert(t, "ek")
	block, _ := pem.Decode(certPEM)
	wantB64 := base64.StdEncoding.EncodeToString(block.Bytes)

	t.Run("empty path => empty string", func(t *testing.T) {
		got, err := readEKCertBase64("")
		if err != nil || got != "" {
			t.Fatalf("expected (\"\", nil), got %q err=%v", got, err)
		}
	})

	t.Run("pem file => base64 der", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ek.pem")
		if err := os.WriteFile(path, certPEM, 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		got, err := readEKCertBase64(path)
		if err != nil {
			t.Fatalf("readEKCertBase64: %v", err)
		}
		if got != wantB64 {
			t.Errorf("base64 mismatch for PEM EK cert")
		}
	})

	t.Run("der file => base64 der", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ek.der")
		if err := os.WriteFile(path, block.Bytes, 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		got, err := readEKCertBase64(path)
		if err != nil {
			t.Fatalf("readEKCertBase64: %v", err)
		}
		if got != wantB64 {
			t.Errorf("base64 mismatch for DER EK cert")
		}
	})

	t.Run("missing file => typed error", func(t *testing.T) {
		_, err := readEKCertBase64(filepath.Join(t.TempDir(), "absent"))
		var e ErrEKCertRead
		if !errors.As(err, &e) {
			t.Fatalf("expected ErrEKCertRead, got %T: %v", err, err)
		}
	})

	t.Run("non-cert content => typed error", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "junk")
		if err := os.WriteFile(path, []byte("junk"), 0o644); err != nil {
			t.Fatalf("write: %v", err)
		}
		_, err := readEKCertBase64(path)
		var e ErrEKCertParse
		if !errors.As(err, &e) {
			t.Fatalf("expected ErrEKCertParse, got %T: %v", err, err)
		}
	})
}
