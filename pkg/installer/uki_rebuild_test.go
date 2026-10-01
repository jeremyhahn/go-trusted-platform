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

package installer

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"io"
	"os"
	"path/filepath"
	"testing"

	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"
	"github.com/jeremyhahn/go-trusted-platform/pkg/authenticode"
	"github.com/jeremyhahn/go-trusted-platform/pkg/common"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
)

// fakeUKIBuilder records the UKIConfig it was asked to build and writes canned
// bytes to the output, standing in for the dracut builder so the rebuild
// pipeline is testable without dracut or a real kernel.
type fakeUKIBuilder struct {
	content       []byte
	buildErr      error
	gotKernelPath string
	gotCmdline    string
	calls         int
}

func (b *fakeUKIBuilder) BuildUKI(_ context.Context, config *UKIConfig, out io.Writer) error {
	b.calls++
	b.gotKernelPath = config.KernelPath
	b.gotCmdline = config.Cmdline
	if b.buildErr != nil {
		return b.buildErr
	}
	_, err := out.Write(b.content)
	return err
}

// fakeAuthenticode is an injectable authenticode.Authenticode. SignFile copies
// input to output (so the staged UKI exists), and Verify/Extract behaviour is
// controlled per test to exercise the verify-before-swap brick guard.
type fakeAuthenticode struct {
	cert        *x509.Certificate // captured DB cert; returned by ExtractCertificateFile
	signErr     error
	verifyErr   error
	extractErr  error
	extractCert *x509.Certificate // override; nil -> return cert
}

func (f *fakeAuthenticode) Sign(in io.Reader, out io.Writer) error {
	if f.signErr != nil {
		return f.signErr
	}
	_, err := io.Copy(out, in)
	return err
}

func (f *fakeAuthenticode) SignFile(inputPath, outputPath string) error {
	if f.signErr != nil {
		return f.signErr
	}
	data, err := os.ReadFile(inputPath)
	if err != nil {
		return err
	}
	return os.WriteFile(outputPath, data, 0o755)
}

func (f *fakeAuthenticode) Verify(_ io.Reader) error  { return f.verifyErr }
func (f *fakeAuthenticode) VerifyFile(_ string) error { return f.verifyErr }

func (f *fakeAuthenticode) ExtractCertificate(_ io.Reader) (*x509.Certificate, error) {
	return f.extractCertificate()
}

func (f *fakeAuthenticode) ExtractCertificateFile(_ string) (*x509.Certificate, error) {
	return f.extractCertificate()
}

func (f *fakeAuthenticode) extractCertificate() (*x509.Certificate, error) {
	if f.extractErr != nil {
		return nil, f.extractErr
	}
	if f.extractCert != nil {
		return f.extractCert, nil
	}
	return f.cert, nil
}

// rebuildFixture wires a UKIRebuilder against temp dirs and fakes so a test
// never touches the host /boot, /lib/modules, or ESP.
type rebuildFixture struct {
	rebuilder *UKIRebuilder
	builder   *fakeUKIBuilder
	signer    *fakeAuthenticode
	espUKI    string // live UKI path inside the temp ESP
	bootDir   string
	modules   string
	kver      string
}

// newRebuildFixture builds a fixture with a real file:// DB keypair, a signed
// fake module, the persisted cmdline, the kernel image, and an EXISTING live UKI
// (so .prev behaviour can be asserted).
func newRebuildFixture(t *testing.T) *rebuildFixture {
	t.Helper()
	root := t.TempDir()
	kver := "6.6.67-0-lts"

	// A file:// DB keypair on the "encrypted root".
	keyDir := filepath.Join(root, "secure-boot")
	if err := os.MkdirAll(keyDir, 0o755); err != nil {
		t.Fatalf("mkdir keyDir: %v", err)
	}
	keyPath := filepath.Join(keyDir, "DB.key")
	certPath := filepath.Join(keyDir, "DB.crt")
	writeTestKeypairPEM(t, keyPath, certPath, "rebuild-db")

	// boot dir with the kernel image.
	bootDir := filepath.Join(root, "boot")
	if err := os.MkdirAll(bootDir, 0o755); err != nil {
		t.Fatalf("mkdir bootDir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(bootDir, "vmlinuz-"+kver), []byte("kernel"), 0o644); err != nil {
		t.Fatalf("write kernel: %v", err)
	}

	// modules dir with a SIGNED fake module so the spot check passes.
	modDir := filepath.Join(root, "lib", "modules", kver)
	if err := os.MkdirAll(modDir, 0o755); err != nil {
		t.Fatalf("mkdir modDir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(modDir, "dummy.ko"), []byte("ELF...module-body"+moduleSignatureMagic), 0o644); err != nil {
		t.Fatalf("write module: %v", err)
	}

	// persisted kernel cmdline.
	cmdlinePath := filepath.Join(root, "cmdline")
	if err := os.WriteFile(cmdlinePath, []byte("root=/dev/mapper/cryptroot ro\n"), 0o644); err != nil {
		t.Fatalf("write cmdline: %v", err)
	}

	// temp ESP with an EXISTING live UKI.
	espDir := filepath.Join(root, "boot", "efi", "EFI", "BOOT")
	if err := os.MkdirAll(espDir, 0o755); err != nil {
		t.Fatalf("mkdir espDir: %v", err)
	}
	espUKI := filepath.Join(espDir, "BOOTX64.EFI")
	if err := os.WriteFile(espUKI, []byte("OLD-UKI"), 0o755); err != nil {
		t.Fatalf("write old uki: %v", err)
	}

	builder := &fakeUKIBuilder{content: []byte("NEW-UNSIGNED-UKI")}
	signer := &fakeAuthenticode{}
	signerFactory := func(_ context.Context, _ crypto.PrivateKey, cert *x509.Certificate, _ *logging.Logger) (authenticode.Authenticode, error) {
		signer.cert = cert // capture resolved DB cert so VerifySignedUKI cert-match passes
		return signer, nil
	}

	config := &Config{
		OS: &OSConfig{},
		SecureBoot: &SecureBootConfig{
			Enabled:    true,
			ResignMode: SecureBootResignModeLocal,
			DB: SecureBootKeyRef{
				KeyURI:  "file://" + keyPath,
				CertURI: "file://" + certPath,
			},
		},
	}

	rb := NewUKIRebuilder(logging.DefaultLogger(), config,
		WithUKIBuilder(builder),
		WithAuthenticodeSigner(signerFactory),
		WithESPUKIPath(espUKI),
		WithModulesDir(filepath.Join(root, "lib", "modules")),
		WithBootDir(bootDir),
		WithKernelCmdlinePath(cmdlinePath),
	)

	return &rebuildFixture{
		rebuilder: rb,
		builder:   builder,
		signer:    signer,
		espUKI:    espUKI,
		bootDir:   bootDir,
		modules:   filepath.Join(root, "lib", "modules"),
		kver:      kver,
	}
}

// TestUKIRebuild_HappyPath verifies the full pipeline: build -> sign to staging
// -> verify -> atomic swap, leaving the new UKI live and the previous one as
// .prev with no staging file lingering.
func TestUKIRebuild_HappyPath(t *testing.T) {
	f := newRebuildFixture(t)

	if err := f.rebuilder.Rebuild(context.Background(), f.kver); err != nil {
		t.Fatalf("Rebuild returned error: %v", err)
	}

	// The live UKI now holds the rebuilt+signed bytes.
	got, err := os.ReadFile(f.espUKI)
	if err != nil {
		t.Fatalf("read swapped uki: %v", err)
	}
	if string(got) != "NEW-UNSIGNED-UKI" {
		t.Errorf("live UKI = %q, want the rebuilt bytes", string(got))
	}

	// The previous UKI is preserved as .prev.
	prev, err := os.ReadFile(f.espUKI + ".prev")
	if err != nil {
		t.Fatalf("read .prev: %v", err)
	}
	if string(prev) != "OLD-UKI" {
		t.Errorf(".prev = %q, want the previous UKI", string(prev))
	}

	// No staging file lingers.
	if _, err := os.Stat(f.espUKI + ".new"); !os.IsNotExist(err) {
		t.Errorf("staging .new should not exist after a successful swap, stat err = %v", err)
	}

	// The builder was asked to build the right kernel + cmdline.
	if f.builder.gotKernelPath != filepath.Join(f.bootDir, "vmlinuz-"+f.kver) {
		t.Errorf("builder kernel path = %q", f.builder.gotKernelPath)
	}
	if f.builder.gotCmdline != "root=/dev/mapper/cryptroot ro" {
		t.Errorf("builder cmdline = %q", f.builder.gotCmdline)
	}
}

// TestUKIRebuild_VerifyFailureKeepsOldUKI verifies the brick guard: when the
// rebuilt UKI fails verification, NO swap happens, the old UKI is intact, the
// staging file is removed, and a typed error is returned.
func TestUKIRebuild_VerifyFailureKeepsOldUKI(t *testing.T) {
	f := newRebuildFixture(t)
	f.signer.verifyErr = errors.New("authenticode: bad signature")

	err := f.rebuilder.Rebuild(context.Background(), f.kver)
	if err == nil {
		t.Fatal("expected a verification error, got nil")
	}
	var verifyErr *ErrUKIRebuildVerify
	if !errors.As(err, &verifyErr) {
		t.Fatalf("expected *ErrUKIRebuildVerify, got %T: %v", err, err)
	}

	// The OLD UKI must still be in place, unchanged.
	got, err := os.ReadFile(f.espUKI)
	if err != nil {
		t.Fatalf("read uki: %v", err)
	}
	if string(got) != "OLD-UKI" {
		t.Errorf("live UKI = %q, want the original OLD-UKI (no swap on verify failure)", string(got))
	}

	// The staging file must be cleaned up.
	if _, err := os.Stat(f.espUKI + ".new"); !os.IsNotExist(err) {
		t.Errorf("staging .new should be removed after verify failure, stat err = %v", err)
	}
}

// TestUKIRebuild_CertMismatchKeepsOldUKI verifies that a signature whose embedded
// certificate is not the DB certificate is rejected (no swap).
func TestUKIRebuild_CertMismatchKeepsOldUKI(t *testing.T) {
	f := newRebuildFixture(t)
	// Return a DIFFERENT certificate from the signed image than the DB cert.
	otherDir := t.TempDir()
	otherCert := writeTestKeypairPEM(t, filepath.Join(otherDir, "k"), filepath.Join(otherDir, "c"), "intruder")
	f.signer.extractCert = otherCert

	err := f.rebuilder.Rebuild(context.Background(), f.kver)
	if err == nil {
		t.Fatal("expected a cert-mismatch verification error, got nil")
	}

	got, _ := os.ReadFile(f.espUKI)
	if string(got) != "OLD-UKI" {
		t.Errorf("live UKI = %q, want OLD-UKI (no swap on cert mismatch)", string(got))
	}
}

// TestUKIRebuild_UnsignedModulesKeepsOldUKI verifies the module-signature spot
// check aborts the swap when the freshly installed modules are unsigned.
func TestUKIRebuild_UnsignedModulesKeepsOldUKI(t *testing.T) {
	f := newRebuildFixture(t)
	// Overwrite the module with an UNSIGNED body (no trailer).
	if err := os.WriteFile(filepath.Join(f.modules, f.kver, "dummy.ko"), []byte("unsigned-module-body"), 0o644); err != nil {
		t.Fatalf("rewrite module: %v", err)
	}

	err := f.rebuilder.Rebuild(context.Background(), f.kver)
	if err == nil {
		t.Fatal("expected an unsigned-modules error, got nil")
	}
	var modErr *ErrModulesUnsigned
	if !errors.As(err, &modErr) {
		t.Fatalf("expected *ErrModulesUnsigned, got %T: %v", err, err)
	}

	got, _ := os.ReadFile(f.espUKI)
	if string(got) != "OLD-UKI" {
		t.Errorf("live UKI = %q, want OLD-UKI (no swap on unsigned modules)", string(got))
	}
}

// TestUKIRebuild_DefaultsKverToNewest verifies an empty kver selects the newest
// installed kernel (numeric-aware, so .67 beats .9).
func TestUKIRebuild_DefaultsKverToNewest(t *testing.T) {
	f := newRebuildFixture(t)
	// Add an OLDER kernel; the existing fixture kver (6.6.67) must stay newest.
	older := "6.6.9-0-lts"
	if err := os.MkdirAll(filepath.Join(f.modules, older), 0o755); err != nil {
		t.Fatalf("mkdir older modules: %v", err)
	}
	if err := os.WriteFile(filepath.Join(f.modules, older, "dummy.ko"), []byte("x"+moduleSignatureMagic), 0o644); err != nil {
		t.Fatalf("write older module: %v", err)
	}
	if err := os.WriteFile(filepath.Join(f.bootDir, "vmlinuz-"+older), []byte("k"), 0o644); err != nil {
		t.Fatalf("write older kernel: %v", err)
	}

	if err := f.rebuilder.Rebuild(context.Background(), ""); err != nil {
		t.Fatalf("Rebuild with default kver: %v", err)
	}
	if f.builder.gotKernelPath != filepath.Join(f.bootDir, "vmlinuz-"+f.kver) {
		t.Errorf("default kver selected kernel %q, want newest vmlinuz-%s", f.builder.gotKernelPath, f.kver)
	}
}

// TestUKIRebuild_NeverGeneratesKey verifies that with resign-mode local, no
// file:// DB key, and no remote seam, the rebuild refuses (it must not generate a
// fresh, unenrolled DB key) and leaves the old UKI in place.
func TestUKIRebuild_NeverGeneratesKey(t *testing.T) {
	f := newRebuildFixture(t)
	// Strip the file:// DB key so neither branch (a) nor (b) can resolve.
	f.rebuilder.config.SecureBoot.DB.KeyURI = ""
	f.rebuilder.config.SecureBoot.DB.CertURI = ""

	err := f.rebuilder.Rebuild(context.Background(), f.kver)
	if err == nil {
		t.Fatal("expected a no-signer error, got nil (must never generate a DB key)")
	}

	got, _ := os.ReadFile(f.espUKI)
	if string(got) != "OLD-UKI" {
		t.Errorf("live UKI = %q, want OLD-UKI (no swap when no signer)", string(got))
	}
	if f.builder.calls != 0 {
		t.Errorf("builder should not run when no signer is resolvable, calls = %d", f.builder.calls)
	}
}

// TestUKIRebuild_DisabledSecureBoot verifies the rebuild is a hard error when
// Secure Boot is not enabled (there is no DB key to re-sign with).
func TestUKIRebuild_DisabledSecureBoot(t *testing.T) {
	f := newRebuildFixture(t)
	f.rebuilder.config.SecureBoot.Enabled = false

	if err := f.rebuilder.Rebuild(context.Background(), f.kver); err == nil {
		t.Fatal("expected an error when secure boot is disabled")
	}
}

// TestUKIRebuild_MissingKernelCmdline verifies a missing persisted cmdline aborts
// the rebuild (rebuilding without root=/rd.luks.* would be unbootable).
func TestUKIRebuild_MissingKernelCmdline(t *testing.T) {
	f := newRebuildFixture(t)
	f.rebuilder.kernelCmdline = filepath.Join(t.TempDir(), "does-not-exist")

	err := f.rebuilder.Rebuild(context.Background(), f.kver)
	if err == nil {
		t.Fatal("expected an error for a missing cmdline")
	}
	var cmdErr *ErrKernelCmdlineUnavailable
	if !errors.As(err, &cmdErr) {
		t.Fatalf("expected *ErrKernelCmdlineUnavailable, got %T: %v", err, err)
	}

	got, _ := os.ReadFile(f.espUKI)
	if string(got) != "OLD-UKI" {
		t.Errorf("live UKI changed despite cmdline failure: %q", string(got))
	}
}

// TestUKIRebuild_MissingKernelImage verifies a missing kernel image aborts.
func TestUKIRebuild_MissingKernelImage(t *testing.T) {
	f := newRebuildFixture(t)
	if err := os.Remove(filepath.Join(f.bootDir, "vmlinuz-"+f.kver)); err != nil {
		t.Fatalf("remove kernel: %v", err)
	}

	err := f.rebuilder.Rebuild(context.Background(), f.kver)
	if err == nil {
		t.Fatal("expected an error for a missing kernel image")
	}
	var kErr *ErrKernelImageNotFound
	if !errors.As(err, &kErr) {
		t.Fatalf("expected *ErrKernelImageNotFound, got %T: %v", err, err)
	}
}

// TestUKIRebuild_RemoteSeam verifies resign-mode remote routes through the
// injected RemoteSignerResolver seam and completes the swap.
func TestUKIRebuild_RemoteSeam(t *testing.T) {
	f := newRebuildFixture(t)
	// Switch to remote mode: drop the file:// key so branch (b) is taken.
	f.rebuilder.config.SecureBoot.ResignMode = SecureBootResignModeRemote
	f.rebuilder.config.SecureBoot.DB = SecureBootKeyRef{
		KeyConfig: common.KeyConfig{CN: "platform-secureboot-db", StoreType: "software"},
		KeyURI:    "kms://platform/secureboot/db",
	}

	// Build a real signer + cert to hand back from the seam.
	dir := t.TempDir()
	keyPath := filepath.Join(dir, "remote.key")
	certPath := filepath.Join(dir, "remote.crt")
	cert := writeTestKeypairPEM(t, keyPath, certPath, "remote-db")
	rawKey, err := authenticode.LoadPrivateKeyPEM(keyPath)
	if err != nil {
		t.Fatalf("parse remote key: %v", err)
	}

	var seamCalled bool
	var gotCN string
	f.rebuilder.remoteSigner = func(_ context.Context, attrs *xkmssdk.KeyAttributes) (crypto.Signer, *x509.Certificate, error) {
		seamCalled = true
		gotCN = attrs.CN
		return rawKey.(crypto.Signer), cert, nil
	}

	if err := f.rebuilder.Rebuild(context.Background(), f.kver); err != nil {
		t.Fatalf("Rebuild (remote): %v", err)
	}
	if !seamCalled {
		t.Fatal("expected the remote signer seam to be invoked")
	}
	if gotCN != "platform-secureboot-db" {
		t.Errorf("seam received attrs.CN = %q, want platform-secureboot-db", gotCN)
	}
	got, _ := os.ReadFile(f.espUKI)
	if string(got) != "NEW-UNSIGNED-UKI" {
		t.Errorf("live UKI = %q, want the rebuilt bytes after remote re-sign", string(got))
	}
}

// --- focused unit tests for the helpers ---

func TestLatestKernelVersion(t *testing.T) {
	dir := t.TempDir()
	for _, v := range []string{"6.6.9-0-lts", "6.6.67-0-lts", "6.12.3-0-lts"} {
		if err := os.MkdirAll(filepath.Join(dir, v), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", v, err)
		}
	}
	got, err := latestKernelVersion(dir)
	if err != nil {
		t.Fatalf("latestKernelVersion: %v", err)
	}
	if got != "6.12.3-0-lts" {
		t.Errorf("latestKernelVersion = %q, want 6.12.3-0-lts", got)
	}
}

func TestLatestKernelVersion_Empty(t *testing.T) {
	if _, err := latestKernelVersion(t.TempDir()); err == nil {
		t.Fatal("expected an error for an empty modules dir")
	}
	var nmErr *ErrNoKernelModules
	if _, err := latestKernelVersion(filepath.Join(t.TempDir(), "missing")); !errors.As(err, &nmErr) {
		t.Fatalf("expected *ErrNoKernelModules for a missing dir, got %v", err)
	}
}

func TestKernelVersionLess(t *testing.T) {
	cases := []struct {
		a, b string
		less bool
	}{
		{"6.6.9-0-lts", "6.6.67-0-lts", true},
		{"6.6.67-0-lts", "6.6.9-0-lts", false},
		{"6.6.10-0-lts", "6.12.3-0-lts", true},
		{"6.6.67-0-lts", "6.6.67-0-lts", false},
	}
	for _, c := range cases {
		if got := kernelVersionLess(c.a, c.b); got != c.less {
			t.Errorf("kernelVersionLess(%q,%q) = %v, want %v", c.a, c.b, got, c.less)
		}
	}
}

func TestSpotCheckModuleSignatures(t *testing.T) {
	logger := logging.DefaultLogger()

	// Signed module -> pass.
	signedDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(signedDir, "a.ko"), []byte("body"+moduleSignatureMagic), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := spotCheckModuleSignatures(signedDir, logger); err != nil {
		t.Errorf("expected signed modules to pass, got %v", err)
	}

	// Unsigned module -> error.
	unsignedDir := t.TempDir()
	if err := os.WriteFile(filepath.Join(unsignedDir, "a.ko"), []byte("body-no-trailer"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := spotCheckModuleSignatures(unsignedDir, logger); err == nil {
		t.Error("expected unsigned modules to fail the spot check")
	}

	// Missing dir -> skip (no error).
	if err := spotCheckModuleSignatures(filepath.Join(t.TempDir(), "missing"), logger); err != nil {
		t.Errorf("expected a missing modules dir to be skipped, got %v", err)
	}

	// No .ko files -> skip (no error).
	if err := spotCheckModuleSignatures(t.TempDir(), logger); err != nil {
		t.Errorf("expected an empty modules dir to be skipped, got %v", err)
	}
}

func TestFileHasTrailer(t *testing.T) {
	dir := t.TempDir()
	with := filepath.Join(dir, "with")
	without := filepath.Join(dir, "without")
	short := filepath.Join(dir, "short")
	if err := os.WriteFile(with, []byte("xxx"+moduleSignatureMagic), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(without, []byte("xxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}
	if err := os.WriteFile(short, []byte("x"), 0o644); err != nil {
		t.Fatalf("write: %v", err)
	}

	if ok, err := fileHasTrailer(with, moduleSignatureMagic); err != nil || !ok {
		t.Errorf("fileHasTrailer(with) = %v, %v; want true, nil", ok, err)
	}
	if ok, err := fileHasTrailer(without, moduleSignatureMagic); err != nil || ok {
		t.Errorf("fileHasTrailer(without) = %v, %v; want false, nil", ok, err)
	}
	if ok, err := fileHasTrailer(short, moduleSignatureMagic); err != nil || ok {
		t.Errorf("fileHasTrailer(short) = %v, %v; want false, nil", ok, err)
	}
}

func TestResolveRebuildSigner_NoSigner(t *testing.T) {
	sb := &SecureBootConfig{Enabled: true, ResignMode: SecureBootResignModeLocal}
	if _, _, err := resolveRebuildSigner(context.Background(), sb, nil); err == nil {
		t.Fatal("expected an error when no DB signer is resolvable")
	}
}

func TestResolveRebuildSigner_Disabled(t *testing.T) {
	if _, _, err := resolveRebuildSigner(context.Background(), nil, nil); err == nil {
		t.Fatal("expected an error when secure boot config is nil")
	}
	if _, _, err := resolveRebuildSigner(context.Background(), &SecureBootConfig{Enabled: false}, nil); err == nil {
		t.Fatal("expected an error when secure boot is disabled")
	}
}

func TestCopyFile(t *testing.T) {
	dir := t.TempDir()
	src := filepath.Join(dir, "src")
	dst := filepath.Join(dir, "dst")
	if err := os.WriteFile(src, []byte("payload"), 0o644); err != nil {
		t.Fatalf("write src: %v", err)
	}
	if err := copyFile(src, dst); err != nil {
		t.Fatalf("copyFile: %v", err)
	}
	got, err := os.ReadFile(dst)
	if err != nil {
		t.Fatalf("read dst: %v", err)
	}
	if string(got) != "payload" {
		t.Errorf("copyFile content = %q, want payload", string(got))
	}
	if err := copyFile(filepath.Join(dir, "missing"), dst); err == nil {
		t.Error("expected copyFile to error on a missing source")
	}
}
