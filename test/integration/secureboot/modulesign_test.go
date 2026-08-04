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

// Package secureboot proves the platform's Secure Boot chain against real
// external verifiers and real firmware:
//
//   - pkg/modulesign signatures verify with OpenSSL's independent CMS
//     implementation and follow the kernel's appended-signature contract
//     (TestModuleSign*).
//   - pkg/secureboot + pkg/uefi + pkg/authenticode produce a key set,
//     OVMF-file enrollment and an Authenticode-signed EFI payload that real
//     OVMF firmware BOOTS, while unsigned / wrongly-signed payloads are
//     REJECTED by the firmware (TestOVMFSecureBootEnforcement).
//   - The FIPS kernel (CONFIG_MODULE_SIG_FORCE) rejects unsigned modules at
//     insmod and loads pkg/modulesign-signed modules
//     (TestFIPSKernelModuleSignatureEnforcement — requires prebuilt
//     artifacts via FIPS_KERNEL_IMAGE / FIPS_MODULES_TAR /
//     FIPS_MODULE_SIGNING_KEY).
//
// Run via:
//
//	make integration-test-secureboot
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
func opensslCMSVerify(t *testing.T, ctx context.Context, allowFailure bool, content, cmsDER []byte, certPEM string) error {
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
	_, err := runCommand(t, vctx, allowFailure, "openssl", "cms", "-verify",
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
	if err := opensslCMSVerify(t, ctx, false, original, cmsDER, certPEM); err != nil {
		t.Fatalf("OpenSSL rejected a pkg/modulesign signature: %v", err)
	}
}

// TestModuleSignCorruptedSignatureFailsVerify proves a flipped byte inside
// the CMS envelope makes OpenSSL reject the signature.
func TestModuleSignCorruptedSignatureFailsVerify(t *testing.T) {
	ctx := context.Background()
	original, signed, certPEM := signFixtureModule(t, ctx)

	cmsDER := extractModuleSignature(t, signed)
	corrupted := append([]byte{}, cmsDER...)
	// Flip a byte in the back half of the envelope (inside the signature
	// value, past the ASN.1 framing) so the DER still parses.
	corrupted[len(corrupted)-10] ^= 0xFF

	if err := opensslCMSVerify(t, ctx, true, original, corrupted, certPEM); err == nil {
		t.Fatal("OpenSSL verified a corrupted CMS signature")
	}
}

// TestModuleSignTamperedContentFailsVerify proves the signature is bound to
// the module content: modifying one module byte invalidates verification.
func TestModuleSignTamperedContentFailsVerify(t *testing.T) {
	ctx := context.Background()
	original, signed, certPEM := signFixtureModule(t, ctx)

	tampered := append([]byte{}, original...)
	tampered[len(tampered)/2] ^= 0x01

	cmsDER := extractModuleSignature(t, signed)
	if err := opensslCMSVerify(t, ctx, true, tampered, cmsDER, certPEM); err == nil {
		t.Fatal("OpenSSL verified a signature over tampered module content")
	}
}

// TestUnsignedModuleLacksTrailer proves an unsigned module carries no
// appended-signature trailer — the exact condition CONFIG_MODULE_SIG_FORCE
// rejects at load time.
func TestUnsignedModuleLacksTrailer(t *testing.T) {
	unsigned := buildTestKernelModule()
	if hasModuleSignature(unsigned) {
		t.Fatal("unsigned module fixture unexpectedly carries a signature trailer")
	}
	if !bytes.HasPrefix(unsigned, []byte{0x7F, 'E', 'L', 'F'}) {
		t.Fatal("module fixture is not a valid ELF object")
	}
}
