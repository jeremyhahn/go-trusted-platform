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

//go:build integration

package secureboot

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/jeremyhahn/go-trusted-platform/pkg/modulesign"
	pkgsecureboot "github.com/jeremyhahn/go-trusted-platform/pkg/secureboot"
)

// opensslTimeout bounds each OpenSSL invocation.
const opensslTimeout = 30 * time.Second

// signFixtureModule generates a module-signing keypair with the platform
// generator, builds the ELF .ko fixture, signs it with pkg/modulesign and
// returns (original bytes, signed bytes, cert PEM path).
func signFixtureModule(t *testing.T, ctx context.Context) (original, signed []byte, certPEM string) {
	t.Helper()

	dir := t.TempDir()

	msk, err := pkgsecureboot.GenerateModuleSigningKey(ctx, &pkgsecureboot.ModuleSigningKeyConfig{
		Path:    filepath.Join(dir, "module-signing-key.pem"),
		KeyBits: 2048,
	})
	if err != nil {
		t.Fatalf("generate module-signing key: %v", err)
	}

	original = buildTestKernelModule()
	koPath := filepath.Join(dir, "tp_sbtest.ko")
	if err := os.WriteFile(koPath, original, 0644); err != nil {
		t.Fatalf("write module fixture: %v", err)
	}

	if err := modulesign.SignModule(koPath, msk.Signer, msk.Certificate); err != nil {
		t.Fatalf("SignModule: %v", err)
	}

	signed, err = os.ReadFile(koPath)
	if err != nil {
		t.Fatalf("read signed module: %v", err)
	}

	certPEM = filepath.Join(dir, "module-signing-cert.pem")
	writeCertPEM(t, certPEM, msk.Certificate)
	return original, signed, certPEM
}

// opensslCMSVerify runs OpenSSL's independent CMS verifier against a detached
// module signature: content bytes + DER CMS + trusted signer certificate.
func opensslCMSVerify(t *testing.T, ctx context.Context, content, cmsDER []byte, certPEM string) error {
	t.Helper()
	requireTool(t, "openssl", "independently verify kernel-module CMS signatures")

	dir := t.TempDir()
	contentPath := filepath.Join(dir, "content.bin")
	sigPath := filepath.Join(dir, "sig.der")
	if err := os.WriteFile(contentPath, content, 0644); err != nil {
		t.Fatalf("write content: %v", err)
	}
	if err := os.WriteFile(sigPath, cmsDER, 0644); err != nil {
		t.Fatalf("write signature: %v", err)
	}

	vctx, cancel := context.WithTimeout(ctx, opensslTimeout)
	defer cancel()
	// The CMS carries no embedded certificates (the kernel matches the signer
	// by issuer+serial against its keyring), so the signer certificate is
	// supplied via -certfile and trusted directly via -CAfile -partial_chain.
	_, err := runCommand(t, vctx, false, "openssl", "cms", "-verify",
		"-binary", "-inform", "DER",
		"-in", sigPath,
		"-content", contentPath,
		"-certfile", certPEM,
		"-CAfile", certPEM,
		"-partial_chain", "-purpose", "any",
		"-out", os.DevNull)
	return err
}

// TestModuleSignOpenSSLInterop proves a pkg/modulesign signature is a valid
// detached CMS over the exact module bytes, verified by OpenSSL (an
// independent implementation of the format the kernel consumes), and that the
// appended trailer follows the kernel contract.
func TestModuleSignOpenSSLInterop(t *testing.T) {
	ctx := context.Background()
	original, signed, certPEM := signFixtureModule(t, ctx)

	if !hasModuleSignature(signed) {
		t.Fatal("signed module does not end with the kernel signature magic")
	}

	stripped := stripModuleSignature(t, signed)
	if !bytes.Equal(stripped, original) {
		t.Fatal("stripping the signature does not recover the original module bytes")
	}

	cmsDER := extractModuleSignature(t, signed)
	if err := opensslCMSVerify(t, ctx, original, cmsDER, certPEM); err != nil {
		t.Fatalf("OpenSSL rejected a pkg/modulesign signature: %v", err)
	}
}
