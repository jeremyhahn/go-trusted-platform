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

	"github.com/jeremyhahn/go-trusted-platform/sdk/go/services/gate"
)

const (
	testAdminCert = "-----BEGIN CERTIFICATE-----\nMIIBcert\n-----END CERTIFICATE-----"
	testAdminKey  = "-----BEGIN PRIVATE KEY-----\nMIIBkey\n-----END PRIVATE KEY-----"
	testSPKIPin   = "sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA="
)

func testBundleResponse() *gate.InitResponse {
	return &gate.InitResponse{
		CeremonyID:   "ceremony-1",
		State:        gate.StateUnsealed,
		SPKIPin:      testSPKIPin,
		AdminCertPEM: testAdminCert,
		AdminKeyPEM:  testAdminKey,
	}
}

// dirEntries lists dir so a test can assert no temporary file is left.
func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir: %v", err)
	}
	names := make([]string, 0, len(entries))
	for _, e := range entries {
		names = append(names, e.Name())
	}
	return names
}

// TestAssembleAdminBundle_Order verifies the bundle is certificate, then
// key, then the SPKI pin comment: the layout tls.LoadX509KeyPair accepts.
func TestAssembleAdminBundle_Order(t *testing.T) {
	out := assembleAdminBundle(testBundleResponse())
	certIdx := strings.Index(out, "BEGIN CERTIFICATE")
	keyIdx := strings.Index(out, "BEGIN PRIVATE KEY")
	pinIdx := strings.Index(out, "# SPKI-Pin: "+testSPKIPin)
	if certIdx < 0 || keyIdx < certIdx || pinIdx < keyIdx {
		t.Fatalf("bundle ordering broken: cert=%d key=%d pin=%d body=%q", certIdx, keyIdx, pinIdx, out)
	}
}

func TestAssembleAdminBundle_NoPinNoComment(t *testing.T) {
	resp := testBundleResponse()
	resp.SPKIPin = ""
	if out := assembleAdminBundle(resp); strings.Contains(out, "SPKI-Pin") {
		t.Errorf("empty pin rendered a comment: %q", out)
	}
}

func TestBundleSink_StdoutWritesBundle(t *testing.T) {
	var stdout bytes.Buffer
	sink, err := openBundleSink(&stdout, "-", false)
	if err != nil {
		t.Fatalf("openBundleSink: %v", err)
	}
	if !sink.toStdout() || sink.name() != "stdout" {
		t.Fatalf("\"-\" is not the stdout sink: %+v", sink)
	}
	if err := sink.commit("BUNDLE"); err != nil {
		t.Fatalf("commit: %v", err)
	}
	if stdout.String() != "BUNDLE" {
		t.Errorf("stdout = %q", stdout.String())
	}
	if err := sink.abort(); err != nil {
		t.Errorf("abort of a stdout sink: %v", err)
	}
}

// TestBundleSink_FileIs0600AndRenamedIntoPlace verifies the bundle lands
// at the path with mode 0600 and no temporary file is left behind.
func TestBundleSink_FileIs0600AndRenamedIntoPlace(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "admin.pem")
	sink, err := openBundleSink(&bytes.Buffer{}, path, false)
	if err != nil {
		t.Fatalf("openBundleSink: %v", err)
	}
	if err := sink.commit("BUNDLE"); err != nil {
		t.Fatalf("commit: %v", err)
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
	if string(body) != "BUNDLE" {
		t.Errorf("bundle body = %q", body)
	}
	if names := dirEntries(t, dir); len(names) != 1 {
		t.Errorf("temporary file left behind: %v", names)
	}
}

// TestBundleSink_ExistingFileRefused verifies the guard against
// clobbering an already-deployed bundle without --force.
func TestBundleSink_ExistingFileRefused(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "admin.pem")
	if err := os.WriteFile(path, []byte("existing"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	_, err := openBundleSink(&bytes.Buffer{}, path, false)
	var exists *ErrAdminBundleExists
	if !errors.As(err, &exists) || exists.Path != path {
		t.Fatalf("want ErrAdminBundleExists{%q}, got %T: %v", path, err, err)
	}
	if names := dirEntries(t, dir); len(names) != 1 {
		t.Errorf("refusal created a file: %v", names)
	}
}

// TestBundleSink_ForceOverwritesWith0600 verifies --force replaces an
// existing file and the result is 0600 whatever the old mode was.
func TestBundleSink_ForceOverwritesWith0600(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.pem")
	if err := os.WriteFile(path, []byte("existing"), 0o644); err != nil {
		t.Fatalf("seed: %v", err)
	}
	sink, err := openBundleSink(&bytes.Buffer{}, path, true)
	if err != nil {
		t.Fatalf("openBundleSink force: %v", err)
	}
	if err := sink.commit("BUNDLE"); err != nil {
		t.Fatalf("commit: %v", err)
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
	if string(body) != "BUNDLE" {
		t.Errorf("file was not overwritten: %q", body)
	}
}

// TestBundleSink_AbortRemovesTemporaryFile verifies a failed init leaves
// nothing behind, and an existing file under --force is untouched.
func TestBundleSink_AbortRemovesTemporaryFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "admin.pem")
	if err := os.WriteFile(path, []byte("existing"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	sink, err := openBundleSink(&bytes.Buffer{}, path, true)
	if err != nil {
		t.Fatalf("openBundleSink: %v", err)
	}
	if err := sink.abort(); err != nil {
		t.Fatalf("abort: %v", err)
	}
	if names := dirEntries(t, dir); len(names) != 1 || names[0] != "admin.pem" {
		t.Errorf("abort left %v", names)
	}
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if string(body) != "existing" {
		t.Errorf("abort touched the existing bundle: %q", body)
	}
}

// TestBundleSink_UnwritableDirectoryFailsUpFront verifies the sink is
// rejected before init when the bundle cannot be created.
func TestBundleSink_UnwritableDirectoryFailsUpFront(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing", "admin.pem")
	_, err := openBundleSink(&bytes.Buffer{}, path, false)
	var wrapped *WrappedError
	if !errors.As(err, &wrapped) || !strings.Contains(wrapped.Msg, path) {
		t.Fatalf("want WrappedError naming %q, got %T: %v", path, err, err)
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

// TestBundleSink_DirectoryRefused verifies a directory destination is
// refused before the sink creates anything, with or without --force.
func TestBundleSink_DirectoryRefused(t *testing.T) {
	for _, force := range []bool{false, true} {
		path := t.TempDir()
		_, err := openBundleSink(&bytes.Buffer{}, path, force)
		var isDir *ErrAdminBundleIsDirectory
		if !errors.As(err, &isDir) || isDir.Path != path {
			t.Fatalf("force=%v: want ErrAdminBundleIsDirectory{%q}, got %T: %v", force, path, err, err)
		}
		if names := dirEntries(t, path); len(names) != 0 {
			t.Errorf("force=%v: refusal created a file: %v", force, names)
		}
	}
}

// TestBundleSink_ParentNotADirectoryFailsUpFront verifies a parent the
// temporary file cannot be created in fails before init.
func TestBundleSink_ParentNotADirectoryFailsUpFront(t *testing.T) {
	parent := filepath.Join(t.TempDir(), "file")
	if err := os.WriteFile(parent, []byte("x"), 0o600); err != nil {
		t.Fatalf("seed: %v", err)
	}
	path := filepath.Join(parent, "admin.pem")
	_, err := openBundleSink(&bytes.Buffer{}, path, false)
	var wrapped *WrappedError
	if !errors.As(err, &wrapped) || !strings.Contains(wrapped.Msg, path) {
		t.Fatalf("want WrappedError naming %q, got %T: %v", path, err, err)
	}
}

// TestBundleSink_RenameFailureKeepsTheBundle verifies the written bundle
// survives a failed final rename, and the error names where it is.
func TestBundleSink_RenameFailureKeepsTheBundle(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "admin.pem")
	sink, err := openBundleSink(&bytes.Buffer{}, path, false)
	if err != nil {
		t.Fatalf("openBundleSink: %v", err)
	}
	// A non-empty directory appearing at path makes the rename fail.
	if err := os.MkdirAll(filepath.Join(path, "occupied"), 0o700); err != nil {
		t.Fatalf("seed: %v", err)
	}

	err = sink.commit("BUNDLE")

	var notInPlace *ErrAdminBundleNotInPlace
	if !errors.As(err, &notInPlace) {
		t.Fatalf("want ErrAdminBundleNotInPlace, got %T: %v", err, err)
	}
	if notInPlace.Path != path || notInPlace.Err == nil {
		t.Errorf("error fields: %+v", notInPlace)
	}
	if !strings.Contains(err.Error(), notInPlace.TempPath) {
		t.Errorf("message does not name the kept file %q: %v", notInPlace.TempPath, err)
	}
	body, err := os.ReadFile(notInPlace.TempPath)
	if err != nil {
		t.Fatalf("kept bundle: %v", err)
	}
	if string(body) != "BUNDLE" {
		t.Errorf("kept bundle body = %q", body)
	}
}

func TestErrAdminBundleIsDirectory_Message(t *testing.T) {
	e := &ErrAdminBundleIsDirectory{Path: "/tmp/admin"}
	if got := e.Error(); !strings.Contains(got, "/tmp/admin") || !strings.Contains(got, "directory") {
		t.Errorf("error message broken: %q", got)
	}
}

func TestErrAdminBundleNotInPlace_MessageAndUnwrap(t *testing.T) {
	cause := errors.New("rename failed")
	e := &ErrAdminBundleNotInPlace{Path: "/tmp/admin.pem", TempPath: "/tmp/.admin.pem.123", Err: cause}
	got := e.Error()
	for _, want := range []string{"/tmp/admin.pem", "/tmp/.admin.pem.123", "rename failed"} {
		if !strings.Contains(got, want) {
			t.Errorf("message %q lacks %q", got, want)
		}
	}
	if !errors.Is(e, cause) {
		t.Error("Unwrap does not return the cause")
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
