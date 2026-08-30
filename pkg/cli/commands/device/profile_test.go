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

package device

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	platformv1 "github.com/jeremyhahn/go-trusted-platform/sdk/go/gen"
)

// newCLITestEKCertPEM generates a self-signed ECDSA certificate PEM for
// the --ek-cert flag tests.
func newCLITestEKCertPEM(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()),
		Subject:      pkix.Name{CommonName: "test-ek"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create certificate: %v", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))
}

// TestResolveEKCertPEM verifies the --ek-cert flag resolution: empty,
// inline PEM, file path, and the malformed error paths.
func TestResolveEKCertPEM(t *testing.T) {
	certPEM := newCLITestEKCertPEM(t)

	t.Run("empty resolves to no prestage", func(t *testing.T) {
		resolved, err := resolveEKCertPEM("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resolved != "" {
			t.Fatalf("resolved = %q, want empty", resolved)
		}
	})

	t.Run("inline PEM is used verbatim", func(t *testing.T) {
		resolved, err := resolveEKCertPEM(certPEM)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resolved != certPEM {
			t.Fatal("inline PEM must be returned verbatim")
		}
	})

	t.Run("file path is read and validated", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "ek-cert.pem")
		if err := os.WriteFile(path, []byte(certPEM), 0o600); err != nil {
			t.Fatalf("write cert: %v", err)
		}
		resolved, err := resolveEKCertPEM(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if resolved != certPEM {
			t.Fatal("file PEM must round-trip")
		}
	})

	t.Run("missing file is a typed read error", func(t *testing.T) {
		_, err := resolveEKCertPEM(filepath.Join(t.TempDir(), "missing.pem"))
		var readErr ErrProfileEKCertReadFailed
		if !errors.As(err, &readErr) {
			t.Fatalf("err = %v, want ErrProfileEKCertReadFailed", err)
		}
	})

	t.Run("file without PEM is a typed validation error", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bogus.pem")
		if err := os.WriteFile(path, []byte("not pem"), 0o600); err != nil {
			t.Fatalf("write file: %v", err)
		}
		_, err := resolveEKCertPEM(path)
		var invalid ErrProfileEKCertInvalid
		if !errors.As(err, &invalid) {
			t.Fatalf("err = %v, want ErrProfileEKCertInvalid", err)
		}
	})

	t.Run("inline PEM with bad DER is rejected", func(t *testing.T) {
		bogus := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte("junk")}))
		_, err := resolveEKCertPEM(bogus)
		var invalid ErrProfileEKCertInvalid
		if !errors.As(err, &invalid) {
			t.Fatalf("err = %v, want ErrProfileEKCertInvalid", err)
		}
	})
}

// TestLoadProfileConfig verifies the --config-file flag: YAML and JSON
// inputs convert to JSON bytes, and the error paths are typed.
func TestLoadProfileConfig(t *testing.T) {
	t.Run("empty path resolves to nil", func(t *testing.T) {
		configJSON, err := loadProfileConfig("")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if configJSON != nil {
			t.Fatal("expected nil config for empty path")
		}
	})

	t.Run("yaml converts to JSON bytes", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "config.yaml")
		if err := os.WriteFile(path, []byte("hostname: lab-node-2\nsecure-boot:\n  enabled: true\n"), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		configJSON, err := loadProfileConfig(path)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		var decoded map[string]any
		if err := json.Unmarshal(configJSON, &decoded); err != nil {
			t.Fatalf("config is not JSON: %v", err)
		}
		if decoded["hostname"] != "lab-node-2" {
			t.Fatalf("decoded = %v", decoded)
		}
	})

	t.Run("missing file is a typed read error", func(t *testing.T) {
		_, err := loadProfileConfig(filepath.Join(t.TempDir(), "missing.yaml"))
		var readErr ErrProfileConfigReadFailed
		if !errors.As(err, &readErr) {
			t.Fatalf("err = %v, want ErrProfileConfigReadFailed", err)
		}
	})

	t.Run("malformed yaml is a typed parse error", func(t *testing.T) {
		path := filepath.Join(t.TempDir(), "bad.yaml")
		if err := os.WriteFile(path, []byte(":\n\t- ["), 0o600); err != nil {
			t.Fatalf("write config: %v", err)
		}
		_, err := loadProfileConfig(path)
		var parseErr ErrProfileConfigParseFailed
		if !errors.As(err, &parseErr) {
			t.Fatalf("err = %v, want ErrProfileConfigParseFailed", err)
		}
	})
}

// TestResolveProfileRole verifies role label mapping and the invalid-role
// error path.
func TestResolveProfileRole(t *testing.T) {
	tests := []struct {
		role    string
		want    platformv1.DeviceRole
		wantErr bool
	}{
		{role: "", want: platformv1.DeviceRole_DEVICE_ROLE_UNSPECIFIED},
		{role: "server", want: platformv1.DeviceRole_DEVICE_ROLE_SERVER},
		{role: "gateway", want: platformv1.DeviceRole_DEVICE_ROLE_GATEWAY},
		{role: "load-balancer", want: platformv1.DeviceRole_DEVICE_ROLE_LOAD_BALANCER},
		{role: "control-plane", want: platformv1.DeviceRole_DEVICE_ROLE_CONTROL_PLANE},
		{role: "worker", want: platformv1.DeviceRole_DEVICE_ROLE_WORKER},
		{role: "bogus", wantErr: true},
	}
	for _, tc := range tests {
		t.Run("role "+tc.role, func(t *testing.T) {
			got, err := resolveProfileRole(tc.role)
			if tc.wantErr {
				var invalid ErrProfileInvalidRole
				if !errors.As(err, &invalid) {
					t.Fatalf("err = %v, want ErrProfileInvalidRole", err)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.want {
				t.Fatalf("role = %v, want %v", got, tc.want)
			}
		})
	}
}

// TestBuildProfileOutput verifies the output map: the uint64 ID is a
// decimal string and the prestage fields surface when set.
func TestBuildProfileOutput(t *testing.T) {
	certPEM := newCLITestEKCertPEM(t)
	output := buildProfileOutput(&platformv1.DeviceProfile{
		Id:         18446744073709551615,
		Name:       "lab-node-2",
		Role:       platformv1.DeviceRole_DEVICE_ROLE_SERVER,
		EkSerial:   "EK-CLI-1",
		MacAddress: "aa:bb:cc:dd:ee:51",
		EkCert:     certPEM,
		Config:     []byte(`{"hostname":"lab-node-2"}`),
	})

	if output["id"] != "18446744073709551615" {
		t.Fatalf("id = %v, want max-uint64 decimal string", output["id"])
	}
	if output["ek_serial"] != "EK-CLI-1" || output["mac_address"] != "aa:bb:cc:dd:ee:51" {
		t.Fatalf("identity fields = %v", output)
	}
	if output["ek_cert"] != certPEM {
		t.Fatal("ek_cert missing from output")
	}
	if output["role"] != "server" {
		t.Fatalf("role = %v", output["role"])
	}
}

// TestNewProfileCommand verifies the command tree exposes create and
// update with the prestage flags registered.
func TestNewProfileCommand(t *testing.T) {
	cmd := newProfileCommand(nil)
	subs := map[string]bool{}
	for _, sub := range cmd.Commands() {
		subs[sub.Name()] = true
	}
	if !subs["create"] || !subs["update"] || !subs["assign"] || !subs["unassign"] {
		t.Fatalf("profile command must expose create, update, assign, and unassign, got %v", subs)
	}

	for _, sub := range cmd.Commands() {
		if sub.Name() != "create" && sub.Name() != "update" {
			continue
		}
		for _, flag := range []string{"name", "model", "role", "zone", "ek-serial", "mac", "ek-cert", "config-file"} {
			if sub.Flags().Lookup(flag) == nil {
				t.Errorf("%s missing flag --%s", sub.Name(), flag)
			}
		}
	}
}
