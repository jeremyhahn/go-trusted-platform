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

package commands

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	ceremonysvc "github.com/jeremyhahn/go-trusted-platform/sdk/go/services/ceremony"
)

const (
	testAdminCert = "-----BEGIN CERTIFICATE-----\nMIIBcert\n-----END CERTIFICATE-----"
	testAdminKey  = "-----BEGIN PRIVATE KEY-----\nMIIBkey\n-----END PRIVATE KEY-----"
	testSPKIPin   = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
)

// TestPersistAdminBundle_StdoutWritesBundle verifies that "-" routes the
// admin bundle to the supplied stdout writer with deterministic order:
// certificate first, then private key.
func TestPersistAdminBundle_StdoutWritesBundle(t *testing.T) {
	resp := &ceremonysvc.InitResponse{
		AdminCertPEM: testAdminCert,
		AdminKeyPEM:  testAdminKey,
		SPKIPin:      testSPKIPin,
	}
	var buf bytes.Buffer
	if err := persistAdminBundle(&buf, resp, "-", false); err != nil {
		t.Fatalf("persistAdminBundle: %v", err)
	}
	out := buf.String()
	certIdx := strings.Index(out, "BEGIN CERTIFICATE")
	keyIdx := strings.Index(out, "BEGIN PRIVATE KEY")
	if certIdx < 0 || keyIdx < 0 || certIdx > keyIdx {
		t.Fatalf("bundle ordering broken: cert=%d key=%d body=%q", certIdx, keyIdx, out)
	}
	if !strings.Contains(out, testSPKIPin) {
		t.Errorf("SPKI pin not included in bundle output: %q", out)
	}
}

// TestPersistAdminBundle_FileCreatedWith0600 verifies that targeting a
// fresh path on disk creates the file with mode 0600 and writes the
// bundle.
func TestPersistAdminBundle_FileCreatedWith0600(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "admin.pem")
	resp := &ceremonysvc.InitResponse{
		AdminCertPEM: testAdminCert,
		AdminKeyPEM:  testAdminKey,
	}
	if err := persistAdminBundle(&bytes.Buffer{}, resp, path, false); err != nil {
		t.Fatalf("persistAdminBundle: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Errorf("bundle perms: want 0600, got %o", got)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if !strings.Contains(string(body), testAdminCert) || !strings.Contains(string(body), testAdminKey) {
		t.Errorf("bundle body missing PEM blocks: %q", string(body))
	}
}

// TestPersistAdminBundle_ExistingFileRefused verifies the safety guard:
// if the file already exists, we refuse to overwrite without --force.
func TestPersistAdminBundle_ExistingFileRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "admin.pem")
	if err := os.WriteFile(path, []byte("existing"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	resp := &ceremonysvc.InitResponse{
		AdminCertPEM: testAdminCert,
		AdminKeyPEM:  testAdminKey,
	}
	err := persistAdminBundle(&bytes.Buffer{}, resp, path, false)
	var exists *ErrAdminBundleExists
	if !errors.As(err, &exists) {
		t.Fatalf("want ErrAdminBundleExists, got %T: %v", err, err)
	}
	if exists.Path != path {
		t.Errorf("Path: want %q, got %q", path, exists.Path)
	}
	body, _ := os.ReadFile(path)
	if string(body) != "existing" {
		t.Errorf("existing file was overwritten: %q", string(body))
	}
}

// TestPersistAdminBundle_ForceOverwrites verifies --force overrides the
// existing-file guard.
func TestPersistAdminBundle_ForceOverwrites(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "admin.pem")
	if err := os.WriteFile(path, []byte("existing"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	resp := &ceremonysvc.InitResponse{
		AdminCertPEM: testAdminCert,
		AdminKeyPEM:  testAdminKey,
	}
	if err := persistAdminBundle(&bytes.Buffer{}, resp, path, true); err != nil {
		t.Fatalf("persistAdminBundle force: %v", err)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(body) == "existing" {
		t.Error("file was not overwritten with --force")
	}
	if !strings.Contains(string(body), testAdminCert) {
		t.Errorf("bundle body missing cert PEM: %q", string(body))
	}
}

// TestPersistAdminBundle_EmptyResponseErrors verifies the contract that
// dropping an empty bundle on the floor is an error: the operator
// cannot authenticate without it.
func TestPersistAdminBundle_EmptyResponseErrors(t *testing.T) {
	cases := []struct {
		name string
		resp *ceremonysvc.InitResponse
	}{
		{"nil", nil},
		{"missing-cert", &ceremonysvc.InitResponse{AdminKeyPEM: testAdminKey}},
		{"missing-key", &ceremonysvc.InitResponse{AdminCertPEM: testAdminCert}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := persistAdminBundle(&bytes.Buffer{}, tc.resp, "-", false)
			var empty *ErrAdminBundleEmpty
			if !errors.As(err, &empty) {
				t.Fatalf("want ErrAdminBundleEmpty, got %T: %v", err, err)
			}
		})
	}
}

// TestErrAdminBundleExists_Message verifies the error string includes the
// bundle path so operators see the conflict location.
func TestErrAdminBundleExists_Message(t *testing.T) {
	e := &ErrAdminBundleExists{Path: "/etc/admin.pem"}
	if got := e.Error(); !strings.Contains(got, "/etc/admin.pem") || !strings.Contains(got, "--force") {
		t.Errorf("error message missing path or --force hint: %q", got)
	}
}

// TestErrAdminBundleEmpty_Message verifies the error string is non-empty
// and identifies the platform did not return a bundle.
func TestErrAdminBundleEmpty_Message(t *testing.T) {
	e := &ErrAdminBundleEmpty{}
	if got := e.Error(); got == "" || !strings.Contains(got, "admin") {
		t.Errorf("error message broken: %q", got)
	}
}

// TestCanonicalInit_ForceFlagExposed verifies the --force flag is
// registered alongside the canonical flag set.
func TestCanonicalInit_ForceFlagExposed(t *testing.T) {
	cmd, _, err := rootCmd.Find([]string{"init"})
	if err != nil {
		t.Fatalf("init not found: %v", err)
	}
	if cmd.Flags().Lookup("force") == nil {
		t.Error("expected --force flag on platformctl init")
	}
}
