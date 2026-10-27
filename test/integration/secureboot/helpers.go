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
// external verifiers, real firmware and a real kernel:
//
//   - pkg/modulesign signatures verify with OpenSSL's independent CMS
//     implementation and follow the kernel's appended-signature contract
//     (TestModuleSignOpenSSLInterop).
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
// The pkg/modulesign signer lookup and its rejection of corrupted
// signatures and tampered content are unit tests in pkg/modulesign.
//
// Run via:
//
//	make integration-test-secureboot
package secureboot

import (
	"context"
	"crypto"
	"crypto/x509"
	"encoding/pem"
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/jeremyhahn/go-trusted-platform/pkg/authenticode"
	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	pkgsecureboot "github.com/jeremyhahn/go-trusted-platform/pkg/secureboot"
)

// Environment variables for the FIPS kernel insmod cycle. The kernel build
// takes hours and runs out-of-band in build/docker/fips-kernel-builder; the
// suite consumes the prebuilt artifacts.
const (
	// EnvFIPSKernelImage points at the prebuilt vmlinuz-fips image.
	EnvFIPSKernelImage = "FIPS_KERNEL_IMAGE"

	// EnvFIPSModulesTar points at the matching modules-fips-<kver>.tar.gz.
	EnvFIPSModulesTar = "FIPS_MODULES_TAR"

	// EnvFIPSModuleSigningKey points at the stable module-signing key PEM
	// bundle the kernel was built with (CONFIG_MODULE_SIG_KEY), so the suite
	// can re-sign modules that the running kernel trusts.
	EnvFIPSModuleSigningKey = "FIPS_MODULE_SIGNING_KEY"
)

// requireTool fails the test with a typed error when a required host tool is
// absent. It returns the resolved path.
func requireTool(t *testing.T, tool, purpose string) string {
	t.Helper()
	path, err := exec.LookPath(tool)
	if err != nil {
		t.Fatal(ErrMissingTool{Tool: tool, Purpose: purpose})
	}
	return path
}

// requireArtifact fails the test with a typed error when the env var is unset
// or its file does not exist. It returns the artifact path.
func requireArtifact(t *testing.T, envVar, purpose string) string {
	t.Helper()
	path := os.Getenv(envVar)
	if path == "" {
		t.Fatal(ErrMissingArtifact{EnvVar: envVar, Purpose: purpose})
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatal(ErrMissingArtifact{EnvVar: envVar, Purpose: purpose + " (" + err.Error() + ")"})
	}
	return path
}

// generateSecureBootKeys generates a full PK/KEK/DB Secure Boot key set with
// exported PEM material in keysDir using the platform's own generator
// (pkg/secureboot XKMSManager, file backend) and returns the key paths.
func generateSecureBootKeys(t *testing.T, ctx context.Context, keysDir string) pkgsecureboot.KeyPaths {
	t.Helper()

	km, err := pkgsecureboot.NewXKMSManager(&pkgsecureboot.XKMSConfig{
		KeysDir:      keysDir,
		Backend:      pkgsecureboot.BackendFile,
		CommonName:   "Trusted Platform Integration",
		Country:      "US",
		Organization: "Automate The Things",
		KeySize:      2048,
		ValidYears:   1,
		ExportKeys:   true,
	}, logging.DefaultLogger())
	if err != nil {
		t.Fatalf("create XKMS manager: %v", err)
	}
	t.Cleanup(func() {
		if closeErr := km.Close(); closeErr != nil {
			t.Logf("close XKMS manager: %v", closeErr)
		}
	})

	if err := km.GenerateAll(ctx); err != nil {
		t.Fatalf("generate Secure Boot keys: %v", err)
	}
	return km.GetKeyPaths()
}

// loadPEMKeypair loads the DB key pair from disk through the same loader the
// installer and the ISO build use (authenticode.LoadSigningPair).
func loadPEMKeypair(t *testing.T, keyPath, certPath string) (crypto.Signer, *x509.Certificate) {
	t.Helper()
	signer, cert, err := authenticode.LoadSigningPair(keyPath, certPath)
	if err != nil {
		t.Fatalf("load DB pair %s / %s: %v", keyPath, certPath, err)
	}
	return signer, cert
}

// authenticodeSign signs the PE file at inPath with the DB keypair using the
// platform's native Authenticode signer (the same signer the installer uses
// for UKIs) and writes the result to outPath.
func authenticodeSign(t *testing.T, ctx context.Context, inPath, outPath string, signer crypto.Signer, cert *x509.Certificate) {
	t.Helper()

	acSigner, err := authenticode.NewCryptoSigner(ctx, signer, cert, logging.DefaultLogger())
	if err != nil {
		t.Fatalf("create authenticode signer: %v", err)
	}
	if err := acSigner.SignFile(inPath, outPath); err != nil {
		t.Fatalf("authenticode sign %s: %v", inPath, err)
	}
}

// runCommand runs a host tool and returns its combined output, failing the
// test on error unless allowFailure is set (in which case the error is
// returned for assertion).
func runCommand(t *testing.T, ctx context.Context, allowFailure bool, name string, args ...string) (string, error) {
	t.Helper()
	cmd := exec.CommandContext(ctx, name, args...)
	out, err := cmd.CombinedOutput()
	if err != nil && !allowFailure {
		t.Fatal(ErrCommandFailed{Command: name + " " + filepath.Base(args[len(args)-1]), Output: string(out), Err: err})
	}
	return string(out), err
}

// writeCertPEM writes an x509 certificate as PEM for host-tool consumption.
func writeCertPEM(t *testing.T, path string, cert *x509.Certificate) {
	t.Helper()
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Raw})
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("write cert PEM %s: %v", path, err)
	}
}
