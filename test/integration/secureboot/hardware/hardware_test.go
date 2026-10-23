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

// Package hardware is the REAL-HARDWARE tier of the Secure Boot integration
// suite. It runs ON the target node (e.g. a Supermicro X10), never in the
// devcontainer, and is opt-in via environment variables:
//
//	TP_HW_TPM=1        run the /dev/tpmrm0 attestation quote + verify cycle
//	TP_HW_TPM_DEVICE   override the hardware TPM device (default /dev/tpmrm0)
//	TP_HW_EFIVARS=1    run the read-only efivarfs Secure Boot state checks
//
// Gating is skip-free and honest: when a tier variable is set but its
// hardware precondition is missing, the test FAILS with a typed error — it
// never skips and never fakes success. When the variable is unset the
// tier is disabled (the default virtual/OVMF tier in the parent package
// remains the CI default).
//
// The efivars tier is strictly READ-ONLY: writing PK in CI would take the
// node's firmware out of Setup Mode (potentially bricking its boot chain).
// The efivars WRITE path is validated by the operator on a real node via
// `platformctl secure-boot enroll` (dry-run first, then --commit); see
// docs/firmware/secure-boot.md.
package hardware

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"os"
	"testing"

	tpm2 "github.com/google/go-tpm/tpm2"
	xkmssdk "github.com/jeremyhahn/go-quicbaas/sdk/go/xkms"

	"github.com/jeremyhahn/go-trusted-platform/pkg/logging"
	"github.com/jeremyhahn/go-trusted-platform/pkg/uefi"
	"github.com/jeremyhahn/go-trusted-platform/pkg/vtpm"
)

// Environment variables gating the hardware tier.
const (
	// EnvHWTPM enables the hardware TPM attestation test when set to "1".
	EnvHWTPM = "TP_HW_TPM"

	// EnvHWTPMDevice overrides the hardware TPM device path.
	EnvHWTPMDevice = "TP_HW_TPM_DEVICE"

	// EnvHWEfivars enables the read-only efivarfs checks when set to "1".
	EnvHWEfivars = "TP_HW_EFIVARS"
)

// defaultHWDevice is the kernel TPM resource-manager device.
const defaultHWDevice = "/dev/tpmrm0"

// attestationPCRs are the PCRs quoted by the attestation cycle: firmware
// measurements (0) and Secure Boot state (7).
var attestationPCRs = []uint{0, 7}

// tierEnabled reports whether the env-gated tier is requested. When disabled
// it logs how to enable the tier; the test then returns without asserting
// anything (opt-in tier, not a skip of a broken environment).
func tierEnabled(t *testing.T, envVar string) bool {
	t.Helper()
	if os.Getenv(envVar) != "1" {
		t.Logf("%s != 1 — hardware tier disabled; run `make integration-test-secureboot-hw` ON the target node to enable it", envVar)
		return false
	}
	return true
}

// TestHardwareTPMAttestation exercises the full bare-metal attestation path
// against the host TPM character device through the SAME production seams the
// platform uses: vtpm.ResolveTPMTarget (explicit hardware target, fail
// closed) and vtpm.TPMProvider.GetTPMForTarget (hardware dispatch). It reads
// PCRs 0 and 7, generates an IAK quote over them with a fresh nonce, and
// verifies the TPMS_ATTEST magic, the embedded nonce, and the quote signature
// against the IAK public key.
func TestHardwareTPMAttestation(t *testing.T) {
	if !tierEnabled(t, EnvHWTPM) {
		return
	}

	device := os.Getenv(EnvHWTPMDevice)
	if device == "" {
		device = defaultHWDevice
	}

	logger := logging.DefaultLogger()
	resolved, err := vtpm.ResolveTPMTarget(&xkmssdk.TPMConfig{Device: device}, logger)
	if err != nil {
		t.Fatal(ErrHardwareTPMUnavailable{Device: device, Cause: err})
	}
	if resolved.Target != vtpm.TPMTargetHardware {
		t.Fatal(ErrHardwareTPMUnavailable{Device: device,
			Cause: vtpm.ErrNotCharDevice{Path: device}})
	}

	provider := vtpm.NewTPMProvider(logger)
	tpm, err := provider.GetTPMForTarget(resolved)
	if err != nil {
		t.Fatal(ErrHardwareTPMUnavailable{Device: device, Cause: err})
	}
	t.Cleanup(func() {
		if closeErr := provider.CloseTPM(resolved.Device); closeErr != nil {
			t.Logf("close hardware TPM: %v", closeErr)
		}
	})

	// Read-only PCR sanity: the SHA-256 bank must exist and hold 32-byte
	// values for the quoted PCRs.
	banks, err := tpm.ReadPCRs(attestationPCRs)
	if err != nil {
		t.Fatal(ErrQuoteInvalid{Reason: "read PCRs", Cause: err})
	}
	sha256Bank := false
	for _, bank := range banks {
		if bank.Algorithm != "SHA256" {
			continue
		}
		sha256Bank = true
		for _, pcr := range bank.PCRs {
			if len(pcr.Value) != sha256.Size {
				t.Fatalf("PCR %d SHA-256 value has %d bytes, want %d", pcr.ID, len(pcr.Value), sha256.Size)
			}
			t.Logf("PCR %2d = %x", pcr.ID, pcr.Value)
		}
	}
	if !sha256Bank {
		t.Fatal(ErrQuoteInvalid{Reason: "no SHA-256 PCR bank", Cause: nil})
	}

	// The quote is signed by the IAK: the platform must be provisioned.
	iakPub, err := tpm.IAK()
	if err != nil {
		t.Fatal(ErrHardwareTPMNotProvisioned{Cause: err})
	}
	iakAttrs, err := tpm.IAKAttributes()
	if err != nil {
		t.Fatal(ErrHardwareTPMNotProvisioned{Cause: err})
	}

	nonce := make([]byte, 32)
	if _, err := rand.Read(nonce); err != nil {
		t.Fatalf("generate nonce: %v", err)
	}

	quote, err := tpm.Quote(attestationPCRs, nonce)
	if err != nil {
		t.Fatal(ErrQuoteInvalid{Reason: "quote generation", Cause: err})
	}

	// Structural verification: TPMS_ATTEST magic and anti-replay nonce.
	attest, err := tpm2.Unmarshal[tpm2.TPMSAttest](quote.Quoted)
	if err != nil {
		t.Fatal(ErrQuoteInvalid{Reason: "parse TPMS_ATTEST", Cause: err})
	}
	if attest.Magic != tpm2.TPMGeneratedValue {
		t.Fatalf("TPMS_ATTEST magic = 0x%x, want TPM_GENERATED_VALUE 0x%x",
			attest.Magic, tpm2.TPMGeneratedValue)
	}
	if !bytes.Equal(attest.ExtraData.Buffer, nonce) {
		t.Fatal(ErrQuoteInvalid{Reason: "quote extraData does not match nonce (replay?)", Cause: nil})
	}

	// Cryptographic verification against the IAK public key.
	if err := verifyQuoteSignature(iakPub, iakAttrs.SignatureAlgorithm, quote.Quoted, quote.Signature); err != nil {
		t.Fatal(err)
	}
	t.Logf("hardware TPM quote verified: device=%s iak_alg=%s", resolved.Device, iakAttrs.SignatureAlgorithm)
}

// verifyQuoteSignature verifies a go-xkms quote signature (raw RSA bytes or
// ASN.1 ECDSA) over the TPMS_ATTEST content using the IAK public key.
func verifyQuoteSignature(pub crypto.PublicKey, sigAlg x509.SignatureAlgorithm, quoted, signature []byte) error {
	digest := sha256.Sum256(quoted)

	switch key := pub.(type) {
	case *rsa.PublicKey:
		switch sigAlg {
		case x509.SHA256WithRSAPSS, x509.SHA384WithRSAPSS, x509.SHA512WithRSAPSS:
			opts := &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto, Hash: crypto.SHA256}
			if err := rsa.VerifyPSS(key, crypto.SHA256, digest[:], signature, opts); err != nil {
				return ErrQuoteInvalid{Reason: "RSA-PSS signature", Cause: err}
			}
		default:
			if err := rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], signature); err != nil {
				return ErrQuoteInvalid{Reason: "RSA PKCS#1v1.5 signature", Cause: err}
			}
		}
		return nil
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, digest[:], signature) {
			return ErrQuoteInvalid{Reason: "ECDSA signature", Cause: nil}
		}
		return nil
	default:
		return ErrUnsupportedIAKAlgorithm{Algorithm: sigAlg.String()}
	}
}

// TestHardwareEfivarsSecureBootStatus performs the READ-ONLY efivarfs checks
// on a UEFI-booted node: the SecureBoot / SetupMode variables must parse and
// the reported state must be internally consistent (enforced Secure Boot
// implies an enrolled PK and db and no Setup Mode; Setup Mode implies Secure
// Boot is not enforced). It never writes an EFI variable.
func TestHardwareEfivarsSecureBootStatus(t *testing.T) {
	if !tierEnabled(t, EnvHWEfivars) {
		return
	}

	status, err := uefi.ReadSecureBootStatus()
	if err != nil {
		t.Fatal(ErrEfivarsRequired{Cause: err})
	}

	t.Logf("SetupMode=%v SecureBoot=%v UserMode=%v", status.SetupMode, status.SecureBoot, status.UserMode)
	for _, db := range []uefi.SignatureDatabase{status.PK, status.KEK, status.DB, status.DBX} {
		t.Logf("%-3s present=%v certs=%d hashes=%d subjects=%v",
			db.Name, db.Present, db.Certificates, db.Hashes, db.Subjects)
	}

	// Firmware state invariants.
	if status.SecureBoot {
		if status.SetupMode {
			t.Fatal("firmware reports Secure Boot enforced while in Setup Mode — inconsistent state")
		}
		if !status.PK.Present {
			t.Fatal("firmware reports Secure Boot enforced without an enrolled Platform Key")
		}
		if !status.DB.Present {
			t.Fatal("firmware reports Secure Boot enforced without an authorized signature database (db)")
		}
	}
	if status.SetupMode && status.UserMode {
		t.Fatal("firmware reports Setup Mode and User Mode simultaneously — inconsistent state")
	}
}
